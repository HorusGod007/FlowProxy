#include "utils/system_proxy.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <iphlpapi.h>

static const char* INTERNET_SETTINGS_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

bool SystemProxy::set_registry_proxy(const std::string& proxy_str, bool enable) {
    if (!set_registry_value("ProxyServer", proxy_str)) return false;
    if (!set_registry_dword("ProxyEnable", enable ? 1 : 0)) return false;
    return true;
}

bool SystemProxy::set_registry_value(const std::string& value_name, const std::string& data) {
    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS)
        return false;
    LONG result = RegSetValueExA(key, value_name.c_str(), 0, REG_SZ,
                                 (const BYTE*)data.c_str(), (DWORD)data.size() + 1);
    RegCloseKey(key);
    return result == ERROR_SUCCESS;
}

bool SystemProxy::set_registry_dword(const std::string& value_name, uint32_t data) {
    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS)
        return false;
    LONG result = RegSetValueExA(key, value_name.c_str(), 0, REG_DWORD,
                                 (const BYTE*)&data, sizeof(data));
    RegCloseKey(key);
    return result == ERROR_SUCCESS;
}

std::string SystemProxy::get_registry_value(const std::string& value_name) {
    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return "";
    char buf[1024] = {};
    DWORD size = sizeof(buf), type = 0;
    RegQueryValueExA(key, value_name.c_str(), nullptr, &type, (BYTE*)buf, &size);
    RegCloseKey(key);
    return std::string(buf);
}

uint32_t SystemProxy::get_registry_dword(const std::string& value_name) {
    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return 0;
    DWORD value = 0, size = sizeof(value), type = 0;
    RegQueryValueExA(key, value_name.c_str(), nullptr, &type, (BYTE*)&value, &size);
    RegCloseKey(key);
    return value;
}

void SystemProxy::notify_system_proxy_changed() {
    InternetSetOptionA(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionA(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
    SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                        (LPARAM)"InternetSettings", SMTO_ABORTIFHUNG, 1000, nullptr);
}

bool SystemProxy::set_system_proxy(const std::string& host, uint16_t port) {
    std::string proxy_str = host + ":" + std::to_string(port);

    // Set bypass list so local/private traffic never hits the interceptor
    std::string bypass = "localhost;127.0.0.1;10.*;172.16.*;172.17.*;172.18.*;"
                         "172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;"
                         "172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;"
                         "172.29.*;172.30.*;172.31.*;192.168.*;<local>";
    set_registry_value("ProxyOverride", bypass);

    if (!set_registry_proxy(proxy_str, true)) return false;

    // Also use WinINET per-connection option (wide strings for UNICODE build)
    std::wstring proxy_w(proxy_str.begin(), proxy_str.end());
    std::wstring bypass_w(bypass.begin(), bypass.end());

    INTERNET_PER_CONN_OPTIONW options[3] = {};
    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[0].Value.dwValue = PROXY_TYPE_PROXY;
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[1].Value.pszValue = (LPWSTR)proxy_w.c_str();
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    options[2].Value.pszValue = (LPWSTR)bypass_w.c_str();

    INTERNET_PER_CONN_OPTION_LISTW list = {};
    list.dwSize = sizeof(list);
    list.pszConnection = nullptr;
    list.dwOptionCount = 3;
    list.pOptions = options;

    InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list));

    notify_system_proxy_changed();
    return true;
}

bool SystemProxy::clear_system_proxy() {
    if (!set_registry_proxy("", false)) return false;

    INTERNET_PER_CONN_OPTIONW options[1] = {};
    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[0].Value.dwValue = PROXY_TYPE_DIRECT;

    INTERNET_PER_CONN_OPTION_LISTW list = {};
    list.dwSize = sizeof(list);
    list.pszConnection = nullptr;
    list.dwOptionCount = 1;
    list.pOptions = options;

    InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list));

    notify_system_proxy_changed();
    return true;
}

bool SystemProxy::get_system_proxy(std::string& host, uint16_t& port, bool& enabled) {
    enabled = get_registry_dword("ProxyEnable") != 0;
    std::string proxy_str = get_registry_value("ProxyServer");

    if (proxy_str.empty()) { host = ""; port = 0; return true; }

    auto colon = proxy_str.rfind(':');
    if (colon != std::string::npos) {
        host = proxy_str.substr(0, colon);
        try { port = (uint16_t)std::stoi(proxy_str.substr(colon + 1)); } catch (...) { port = 0; }
    } else {
        host = proxy_str; port = 0;
    }
    return true;
}

bool SystemProxy::set_pac_url(const std::string& pac_url) {
    std::wstring url_w(pac_url.begin(), pac_url.end());

    INTERNET_PER_CONN_OPTIONW options[2] = {};
    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[0].Value.dwValue = PROXY_TYPE_AUTO_PROXY_URL;
    options[1].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    options[1].Value.pszValue = (LPWSTR)url_w.c_str();

    INTERNET_PER_CONN_OPTION_LISTW list = {};
    list.dwSize = sizeof(list);
    list.pszConnection = nullptr;
    list.dwOptionCount = 2;
    list.pOptions = options;

    bool ok = InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list)) != FALSE;
    notify_system_proxy_changed();
    return ok;
}

bool SystemProxy::set_bypass_list(const std::string& bypass) {
    return set_registry_value("ProxyOverride", bypass);
}

// ============================================================================
// WFP / System driver functions
// MinGW's fwpmu headers may be incomplete, so we use runtime loading.
// ============================================================================

typedef DWORD (WINAPI *PFN_FwpmEngineOpen0)(const wchar_t*, UINT32, void*, void*, HANDLE*);
typedef DWORD (WINAPI *PFN_FwpmEngineClose0)(HANDLE);

static HMODULE get_fwpuclnt() {
    static HMODULE mod = LoadLibraryA("fwpuclnt.dll");
    return mod;
}

bool SystemProxy::install_system_driver() {
    HMODULE fwp = get_fwpuclnt();
    if (!fwp) return false;

    auto pOpen = (PFN_FwpmEngineOpen0)GetProcAddress(fwp, "FwpmEngineOpen0");
    auto pClose = (PFN_FwpmEngineClose0)GetProcAddress(fwp, "FwpmEngineClose0");
    if (!pOpen || !pClose) return false;

    HANDLE engine = nullptr;
    // FWPM_SESSION0 layout: GUID(16) + displayData(2 pointers=16) + flags(4) + timeout(4)
    // We only need flags = FWPM_SESSION_FLAG_DYNAMIC (0x1)
    char session[128] = {};
    // flags offset = 16 (GUID) + 16 (FWPM_DISPLAY_DATA0 = 2 pointers) = 32
    *(UINT32*)(session + 32) = 0x00000001; // FWPM_SESSION_FLAG_DYNAMIC

    DWORD result = pOpen(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session, &engine);
    if (result != ERROR_SUCCESS) return false;

    pClose(engine);
    return true;
}

bool SystemProxy::uninstall_system_driver() {
    // Dynamic sessions clean up automatically
    return true;
}

bool SystemProxy::is_driver_installed() {
    return get_fwpuclnt() != nullptr;
}

bool SystemProxy::enable_transparent_proxy(const std::string& proxy_addr, uint16_t proxy_port) {
    if (!set_system_proxy(proxy_addr, proxy_port)) return false;
    install_system_driver(); // Best-effort
    return true;
}

bool SystemProxy::disable_transparent_proxy() {
    clear_system_proxy();
    return true;
}

bool SystemProxy::add_proxy_route(const std::string& proxy_ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, proxy_ip.c_str(), &addr) != 1) return false;

    MIB_IPFORWARDROW route = {};
    route.dwForwardDest = addr.s_addr;
    route.dwForwardMask = 0xFFFFFFFF;
    route.dwForwardType = MIB_IPROUTE_TYPE_DIRECT;
    route.dwForwardProto = MIB_IPPROTO_NETMGMT;
    route.dwForwardMetric1 = 1;

    DWORD size = 0;
    GetIpForwardTable(nullptr, &size, FALSE);
    auto* table = (MIB_IPFORWARDTABLE*)malloc(size);
    if (!table) return false;

    if (GetIpForwardTable(table, &size, FALSE) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            if (table->table[i].dwForwardDest == 0) {
                route.dwForwardNextHop = table->table[i].dwForwardNextHop;
                route.dwForwardIfIndex = table->table[i].dwForwardIfIndex;
                break;
            }
        }
    }
    free(table);

    return CreateIpForwardEntry(&route) == NO_ERROR;
}

bool SystemProxy::remove_proxy_route(const std::string& proxy_ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, proxy_ip.c_str(), &addr) != 1) return false;

    MIB_IPFORWARDROW route = {};
    route.dwForwardDest = addr.s_addr;
    route.dwForwardMask = 0xFFFFFFFF;
    return DeleteIpForwardEntry(&route) == NO_ERROR;
}
