#pragma once

#include <string>
#include <cstdint>

// Manages Windows system-level proxy settings via registry and WinINET
// This acts as a system-level driver for proxy configuration
class SystemProxy {
public:
    // Set system proxy (affects all applications using WinINET/WinHTTP)
    static bool set_system_proxy(const std::string& host, uint16_t port);

    // Clear/disable system proxy
    static bool clear_system_proxy();

    // Get current system proxy setting
    static bool get_system_proxy(std::string& host, uint16_t& port, bool& enabled);

    // Set PAC (Proxy Auto-Config) script URL
    static bool set_pac_url(const std::string& pac_url);

    // Set proxy bypass list (semicolon-separated, e.g. "localhost;127.0.0.1;*.local")
    static bool set_bypass_list(const std::string& bypass);

    // Notify the system that proxy settings changed (forces refresh)
    static void notify_system_proxy_changed();

    // Install/manage WinDivert or WFP driver for transparent proxying (system-level)
    // This uses Windows Filtering Platform (WFP) for packet-level interception
    static bool install_system_driver();
    static bool uninstall_system_driver();
    static bool is_driver_installed();

    // TUN/TAP-based transparent proxy (system-level network driver)
    static bool enable_transparent_proxy(const std::string& proxy_addr, uint16_t proxy_port);
    static bool disable_transparent_proxy();

private:
    // Registry helpers
    static bool set_registry_proxy(const std::string& proxy_str, bool enable);
    static bool set_registry_value(const std::string& value_name, const std::string& data);
    static bool set_registry_dword(const std::string& value_name, uint32_t data);
    static std::string get_registry_value(const std::string& value_name);
    static uint32_t get_registry_dword(const std::string& value_name);

    // Route table manipulation for transparent proxying
    static bool add_proxy_route(const std::string& proxy_ip);
    static bool remove_proxy_route(const std::string& proxy_ip);
};
