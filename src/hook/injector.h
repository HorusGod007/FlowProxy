#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "hook/shared_config.h"
#include "core/proxy.h"
#include "core/proxy_list.h"
#include "core/rules_engine.h"

#include <string>
#include <vector>
#include <set>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>

// Manages DLL injection into target processes for transparent proxying.
// When a rule targets an application (e.g. firefox.exe), we:
//   1. Create shared memory with proxy config for that PID
//   2. Inject proxy_hook.dll into the process
//   3. The DLL hooks connect() and routes through the proxy
//   4. The app never knows it's being proxied
class Injector {
public:
    Injector(ProxyList& proxies, RulesEngine& rules);
    ~Injector();

    // Start/stop the background process monitor
    void start();
    void stop();
    bool is_running() const { return running_; }

    // Force re-scan: called when rules or proxies change
    void refresh();

    // Get the DLL path (next to exe)
    std::string dll_path() const { return dll_path_; }

    // Stats
    size_t injected_count() const;

private:
    // Scan for processes matching rules and inject/eject as needed
    void monitor_loop();
    void apply_rules();

    // Inject/eject DLL from a process
    bool inject_dll(DWORD pid);
    bool eject_dll(DWORD pid);

    // Create shared memory with proxy config for a process
    bool setup_shared_memory(DWORD pid, const Proxy& proxy);
    void cleanup_shared_memory(DWORD pid);

    // Find all PIDs for a given exe name
    std::vector<DWORD> find_processes(const std::string& exe_name) const;

    // Get the proxy to use for a rule
    bool get_proxy_for_rule(const ProxyRule& rule, Proxy& out_proxy);

    ProxyList& proxies_;
    RulesEngine& rules_;
    std::string dll_path_;

    std::thread monitor_thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> refresh_needed_{false};

    // Track what we've injected: PID -> shared memory handle
    struct InjectedProcess {
        HANDLE shared_mem;
        std::string rule_name;
    };
    std::map<DWORD, InjectedProcess> injected_;
    mutable std::mutex mutex_;
};
