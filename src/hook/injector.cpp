#include "hook/injector.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "psapi.lib")

// ============================================================================
// Constructor / Destructor
// ============================================================================

Injector::Injector(ProxyList& proxies, RulesEngine& rules)
    : proxies_(proxies), rules_(rules) {
    // DLL should be next to the exe
    char path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string exe_path(path);
    auto slash = exe_path.find_last_of("\\/");
    if (slash != std::string::npos)
        dll_path_ = exe_path.substr(0, slash + 1) + "proxy_hook.dll";
    else
        dll_path_ = "proxy_hook.dll";
}

Injector::~Injector() {
    stop();
}

// ============================================================================
// Start / Stop
// ============================================================================

void Injector::start() {
    if (running_) return;
    running_ = true;
    refresh_needed_ = true;
    monitor_thread_ = std::thread(&Injector::monitor_loop, this);
}

void Injector::stop() {
    running_ = false;
    if (monitor_thread_.joinable())
        monitor_thread_.join();

    // Eject from all processes
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [pid, info] : injected_) {
        eject_dll(pid);
        if (info.shared_mem) {
            CloseHandle(info.shared_mem);
        }
    }
    injected_.clear();
}

void Injector::refresh() {
    refresh_needed_ = true;
}

size_t Injector::injected_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return injected_.size();
}

// ============================================================================
// Monitor loop - runs in background thread
// ============================================================================

void Injector::monitor_loop() {
    while (running_) {
        if (refresh_needed_) {
            refresh_needed_ = false;
            apply_rules();
        }

        // Check every 2 seconds for new/exited processes
        for (int i = 0; i < 20 && running_; ++i)
            Sleep(100);

        // Periodic re-apply (catches new process launches)
        apply_rules();
    }
}

// ============================================================================
// Apply rules - inject/eject based on current rules
// ============================================================================

void Injector::apply_rules() {
    std::lock_guard<std::mutex> lock(mutex_);

    // First, check if already-injected processes are still alive
    std::vector<DWORD> dead_pids;
    for (auto& [pid, info] : injected_) {
        HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!proc) {
            dead_pids.push_back(pid);
            continue;
        }
        DWORD exit_code = 0;
        GetExitCodeProcess(proc, &exit_code);
        CloseHandle(proc);
        if (exit_code != STILL_ACTIVE) {
            dead_pids.push_back(pid);
        }
    }
    for (DWORD pid : dead_pids) {
        if (injected_[pid].shared_mem)
            CloseHandle(injected_[pid].shared_mem);
        injected_.erase(pid);
    }

    // Get our own PID to avoid self-injection
    DWORD self_pid = GetCurrentProcessId();

    // For each Application rule, find matching processes and inject
    auto& rules = rules_.rules();
    std::set<DWORD> should_be_injected;

    for (const auto& rule : rules) {
        if (!rule.enabled) continue;
        if (rule.target != RuleTarget::Application) continue;
        if (rule.action == RuleAction::Direct) continue; // Direct = no proxy needed

        // Find all processes matching this pattern
        auto pids = find_processes(rule.pattern);

        Proxy proxy;
        bool have_proxy = get_proxy_for_rule(rule, proxy);
        if (!have_proxy && rule.action != RuleAction::Block) continue;

        for (DWORD pid : pids) {
            if (pid == self_pid) continue;
            should_be_injected.insert(pid);

            // Already injected?
            if (injected_.count(pid)) continue;

            // Setup shared memory with proxy config
            if (rule.action == RuleAction::Block) {
                // Block = active but no valid proxy, DLL will refuse connections
                // For now, skip block rules (could implement later)
                continue;
            }

            if (!setup_shared_memory(pid, proxy)) continue;
            if (!inject_dll(pid)) {
                cleanup_shared_memory(pid);
                continue;
            }

            injected_[pid] = { nullptr, rule.name };
            // Note: shared_mem handle is stored via setup_shared_memory
        }
    }

    // Eject from processes that no longer match any rule
    std::vector<DWORD> to_eject;
    for (auto& [pid, info] : injected_) {
        if (should_be_injected.find(pid) == should_be_injected.end()) {
            to_eject.push_back(pid);
        }
    }
    for (DWORD pid : to_eject) {
        eject_dll(pid);
        cleanup_shared_memory(pid);
        if (injected_[pid].shared_mem)
            CloseHandle(injected_[pid].shared_mem);
        injected_.erase(pid);
    }
}

// ============================================================================
// DLL Injection via CreateRemoteThread + LoadLibraryA
// ============================================================================

bool Injector::inject_dll(DWORD pid) {
    // Check DLL exists
    DWORD attr = GetFileAttributesA(dll_path_.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return false;

    HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!proc) return false;

    // Allocate memory in target for DLL path string
    size_t path_len = dll_path_.size() + 1;
    void* remote_str = VirtualAllocEx(proc, nullptr, path_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_str) {
        CloseHandle(proc);
        return false;
    }

    // Write DLL path to target
    if (!WriteProcessMemory(proc, remote_str, dll_path_.c_str(), path_len, nullptr)) {
        VirtualFreeEx(proc, remote_str, 0, MEM_RELEASE);
        CloseHandle(proc);
        return false;
    }

    // Get LoadLibraryA address (same in all processes)
    auto load_lib = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    // Create remote thread calling LoadLibraryA(dll_path)
    HANDLE thread = CreateRemoteThread(proc, nullptr, 0,
        load_lib, remote_str, 0, nullptr);
    if (!thread) {
        VirtualFreeEx(proc, remote_str, 0, MEM_RELEASE);
        CloseHandle(proc);
        return false;
    }

    // Wait for injection to complete (5 second timeout)
    WaitForSingleObject(thread, 5000);
    CloseHandle(thread);

    // Clean up remote string (DLL is loaded now, string no longer needed)
    VirtualFreeEx(proc, remote_str, 0, MEM_RELEASE);
    CloseHandle(proc);

    return true;
}

bool Injector::eject_dll(DWORD pid) {
    HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!proc) return false;

    // Find proxy_hook.dll module in the target process
    HMODULE modules[1024];
    DWORD needed;
    if (!EnumProcessModulesEx(proc, modules, sizeof(modules), &needed, LIST_MODULES_ALL)) {
        CloseHandle(proc);
        return false;
    }

    HMODULE target_module = nullptr;
    for (DWORD i = 0; i < needed / sizeof(HMODULE); ++i) {
        char name[MAX_PATH];
        if (GetModuleFileNameExA(proc, modules[i], name, MAX_PATH)) {
            std::string mod_name(name);
            auto slash = mod_name.find_last_of("\\/");
            std::string base = (slash != std::string::npos) ? mod_name.substr(slash + 1) : mod_name;
            for (auto& c : base) c = (char)tolower(c);
            if (base == "proxy_hook.dll") {
                target_module = modules[i];
                break;
            }
        }
    }

    if (!target_module) {
        CloseHandle(proc);
        return false;
    }

    // Call FreeLibrary in remote process
    auto free_lib = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "FreeLibrary");

    HANDLE thread = CreateRemoteThread(proc, nullptr, 0,
        free_lib, target_module, 0, nullptr);
    if (thread) {
        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
    }

    CloseHandle(proc);
    return true;
}

// ============================================================================
// Shared memory management
// ============================================================================

bool Injector::setup_shared_memory(DWORD pid, const Proxy& proxy) {
    char name[64];
    snprintf(name, sizeof(name), "FlowProxy_%lu", (unsigned long)pid);

    HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr,
        PAGE_READWRITE, 0, sizeof(ProxyHookConfig), name);
    if (!hMap) return false;

    auto* cfg = (ProxyHookConfig*)MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, sizeof(ProxyHookConfig));
    if (!cfg) {
        CloseHandle(hMap);
        return false;
    }

    memset(cfg, 0, sizeof(ProxyHookConfig));
    cfg->magic = HOOK_CONFIG_MAGIC;
    cfg->active = true;

    switch (proxy.type) {
    case ProxyType::HTTP:   cfg->proxy_type = 0; break;
    case ProxyType::HTTPS:  cfg->proxy_type = 1; break;
    case ProxyType::SOCKS4: cfg->proxy_type = 2; break;
    case ProxyType::SOCKS5: cfg->proxy_type = 3; break;
    }

    strncpy(cfg->proxy_host, proxy.host.c_str(), sizeof(cfg->proxy_host) - 1);
    cfg->proxy_port = proxy.port;
    strncpy(cfg->username, proxy.username.c_str(), sizeof(cfg->username) - 1);
    strncpy(cfg->password, proxy.password.c_str(), sizeof(cfg->password) - 1);

    UnmapViewOfFile(cfg);

    // Store the handle so it stays alive while the DLL needs it
    // (The named mapping stays accessible as long as at least one handle exists)
    if (injected_.count(pid)) {
        if (injected_[pid].shared_mem) CloseHandle(injected_[pid].shared_mem);
        injected_[pid].shared_mem = hMap;
    } else {
        // Will be stored after inject succeeds
        // For now, keep it in a temp - caller will add to injected_
        // Actually, we need to keep this handle alive. Let's store it directly.
        injected_[pid].shared_mem = hMap;
    }

    return true;
}

void Injector::cleanup_shared_memory(DWORD pid) {
    // The shared memory is cleaned up when we close the handle
    // (done in stop() or when ejecting)
}

// ============================================================================
// Process enumeration
// ============================================================================

std::vector<DWORD> Injector::find_processes(const std::string& exe_pattern) const {
    std::vector<DWORD> result;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            // Convert wide name to narrow
            char name[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, MAX_PATH, nullptr, nullptr);

            // Case-insensitive glob match
            std::string lower_name(name);
            std::string lower_pat(exe_pattern);
            for (auto& c : lower_name) c = (char)tolower(c);
            for (auto& c : lower_pat) c = (char)tolower(c);

            // Simple glob: support * and ? and exact match
            bool match = false;
            if (lower_pat.find('*') != std::string::npos || lower_pat.find('?') != std::string::npos) {
                // Glob match
                size_t ti = 0, pi = 0;
                size_t star_pi = std::string::npos, star_ti = 0;
                while (ti < lower_name.size()) {
                    if (pi < lower_pat.size() && (lower_pat[pi] == '?' || lower_pat[pi] == lower_name[ti])) {
                        ++ti; ++pi;
                    } else if (pi < lower_pat.size() && lower_pat[pi] == '*') {
                        star_pi = pi++; star_ti = ti;
                    } else if (star_pi != std::string::npos) {
                        pi = star_pi + 1; ti = ++star_ti;
                    } else {
                        break;
                    }
                }
                while (pi < lower_pat.size() && lower_pat[pi] == '*') ++pi;
                match = (ti == lower_name.size() && pi == lower_pat.size());
            } else {
                match = (lower_name == lower_pat);
            }

            if (match) {
                result.push_back(pe.th32ProcessID);
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return result;
}

// ============================================================================
// Get proxy for a rule
// ============================================================================

bool Injector::get_proxy_for_rule(const ProxyRule& rule, Proxy& out_proxy) {
    if (rule.action == RuleAction::UseProxy) {
        if (rule.proxy_index >= 0) {
            std::lock_guard<std::mutex> lock(proxies_.mutex());
            if ((size_t)rule.proxy_index < proxies_.size()) {
                out_proxy = proxies_.at(rule.proxy_index);
                return true;
            }
        }
        // Use rotation
        std::lock_guard<std::mutex> lock(proxies_.mutex());
        Proxy* p = proxies_.next_proxy(RotationMode::RoundRobin);
        if (p) { out_proxy = *p; return true; }
    }
    else if (rule.action == RuleAction::UseChain) {
        // For chains, use the first proxy in the chain
        // (Full chain support would need the DLL to do multi-hop, complex)
        // For now, use the first alive proxy
        std::lock_guard<std::mutex> lock(proxies_.mutex());
        Proxy* p = proxies_.next_proxy(RotationMode::RoundRobin);
        if (p) { out_proxy = *p; return true; }
    }
    return false;
}
