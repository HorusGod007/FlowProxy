#pragma once

#include <cstdint>

// Shared memory configuration between FlowProxy.exe and proxy_hook.dll
// Memory name format: "FlowProxy_<pid>"
//
// The main app creates shared memory for each injected process.
// The DLL reads it on load to know which proxy to use.

struct ProxyHookConfig {
    uint32_t magic;             // Must be 0x464C4F57 ('FLOW')
    bool active;                // Whether proxying is enabled
    uint8_t proxy_type;         // 0=HTTP, 1=HTTPS, 2=SOCKS4, 3=SOCKS5
    char proxy_host[256];       // Proxy server address
    uint16_t proxy_port;        // Proxy server port
    char username[128];         // Auth username (empty = no auth)
    char password[128];         // Auth password
};

static constexpr uint32_t HOOK_CONFIG_MAGIC = 0x464C4F57;
