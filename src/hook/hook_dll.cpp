// proxy_hook.dll - Transparent proxy hook
//
// This DLL is injected into target processes by FlowProxy.
// It hooks ws2_32!connect so that all TCP connections from the process
// are transparently routed through a proxy server.
// The target app thinks it is making direct connections.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

#include "shared_config.h"

#pragma comment(lib, "ws2_32.lib")

// Original connect function pointer (trampoline)
typedef int (WSAAPI *connect_fn)(SOCKET s, const struct sockaddr* name, int namelen);
static connect_fn original_connect = nullptr;

// Saved original bytes from connect()
static uint8_t saved_bytes[16] = {};
static void* connect_addr = nullptr;

// Proxy config read from shared memory
static ProxyHookConfig g_config = {};

// ============================================================================
// Shared memory
// ============================================================================

static bool read_config() {
    char name[64];
    snprintf(name, sizeof(name), "FlowProxy_%lu", (unsigned long)GetCurrentProcessId());

    HANDLE hMap = OpenFileMappingA(FILE_MAP_READ, FALSE, name);
    if (!hMap) return false;

    auto* cfg = (const ProxyHookConfig*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, sizeof(ProxyHookConfig));
    if (!cfg) { CloseHandle(hMap); return false; }

    if (cfg->magic != HOOK_CONFIG_MAGIC) {
        UnmapViewOfFile(cfg);
        CloseHandle(hMap);
        return false;
    }

    memcpy(&g_config, cfg, sizeof(g_config));
    UnmapViewOfFile(cfg);
    CloseHandle(hMap);
    return true;
}

// ============================================================================
// SOCKS5 handshake
// ============================================================================

static bool do_socks5(SOCKET s, const char* dest_host, uint16_t dest_port) {
    bool has_auth = g_config.username[0] != '\0';

    // Greeting
    uint8_t greeting[4];
    int glen;
    if (has_auth) {
        greeting[0] = 0x05; greeting[1] = 0x02;
        greeting[2] = 0x00; greeting[3] = 0x02;
        glen = 4;
    } else {
        greeting[0] = 0x05; greeting[1] = 0x01; greeting[2] = 0x00;
        glen = 3;
    }
    if (send(s, (char*)greeting, glen, 0) != glen) return false;

    uint8_t resp[2];
    if (recv(s, (char*)resp, 2, 0) < 2 || resp[0] != 0x05) return false;

    // Username/password auth
    if (resp[1] == 0x02 && has_auth) {
        uint8_t ulen = (uint8_t)strlen(g_config.username);
        uint8_t plen = (uint8_t)strlen(g_config.password);
        uint8_t auth[515];
        auth[0] = 0x01;
        auth[1] = ulen;
        memcpy(auth + 2, g_config.username, ulen);
        auth[2 + ulen] = plen;
        memcpy(auth + 3 + ulen, g_config.password, plen);
        int alen = 3 + ulen + plen;
        if (send(s, (char*)auth, alen, 0) != alen) return false;

        uint8_t aresp[2];
        if (recv(s, (char*)aresp, 2, 0) < 2 || aresp[1] != 0x00) return false;
    } else if (resp[1] != 0x00) {
        return false;
    }

    // Connect request (domain name)
    uint8_t host_len = (uint8_t)strlen(dest_host);
    uint8_t req[263];
    req[0] = 0x05; // ver
    req[1] = 0x01; // connect
    req[2] = 0x00; // reserved
    req[3] = 0x03; // domain
    req[4] = host_len;
    memcpy(req + 5, dest_host, host_len);
    req[5 + host_len] = (uint8_t)(dest_port >> 8);
    req[6 + host_len] = (uint8_t)(dest_port & 0xFF);
    int rlen = 7 + host_len;
    if (send(s, (char*)req, rlen, 0) != rlen) return false;

    // Read response (at least 10 bytes for IPv4 bind)
    uint8_t cresp[22];
    int n = recv(s, (char*)cresp, sizeof(cresp), 0);
    if (n < 4 || cresp[0] != 0x05 || cresp[1] != 0x00) return false;

    return true;
}

// ============================================================================
// SOCKS4 handshake
// ============================================================================

static bool do_socks4(SOCKET s, const char* dest_host, uint16_t dest_port) {
    // Resolve hostname to IP (SOCKS4 needs IP)
    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family = AF_INET;
    if (getaddrinfo(dest_host, nullptr, &hints, &result) != 0 || !result)
        return false;
    uint32_t ip = ((struct sockaddr_in*)result->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(result);

    uint8_t req[9];
    req[0] = 0x04; // ver
    req[1] = 0x01; // connect
    req[2] = (uint8_t)(dest_port >> 8);
    req[3] = (uint8_t)(dest_port & 0xFF);
    memcpy(req + 4, &ip, 4);
    req[8] = 0x00; // userid null terminator
    if (send(s, (char*)req, 9, 0) != 9) return false;

    uint8_t resp[8];
    if (recv(s, (char*)resp, 8, 0) < 8) return false;
    return resp[1] == 0x5A; // request granted
}

// ============================================================================
// HTTP CONNECT handshake
// ============================================================================

static bool do_http_connect(SOCKET s, const char* dest_host, uint16_t dest_port) {
    char req[1024];
    int len;

    if (g_config.username[0] != '\0') {
        // Base64 encode credentials
        static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        char auth_raw[300];
        snprintf(auth_raw, sizeof(auth_raw), "%s:%s", g_config.username, g_config.password);
        char encoded[512] = {};
        int val = 0, valb = -6;
        size_t ei = 0;
        for (const char* p = auth_raw; *p; ++p) {
            val = (val << 8) + (unsigned char)*p;
            valb += 8;
            while (valb >= 0 && ei < sizeof(encoded) - 1) {
                encoded[ei++] = b64[(val >> valb) & 0x3F];
                valb -= 6;
            }
        }
        if (valb > -6 && ei < sizeof(encoded) - 1)
            encoded[ei++] = b64[((val << 8) >> (valb + 8)) & 0x3F];
        while (ei % 4) encoded[ei++] = '=';
        encoded[ei] = '\0';

        len = snprintf(req, sizeof(req),
            "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
            "Proxy-Authorization: Basic %s\r\n\r\n",
            dest_host, dest_port, dest_host, dest_port, encoded);
    } else {
        len = snprintf(req, sizeof(req),
            "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n",
            dest_host, dest_port, dest_host, dest_port);
    }

    if (send(s, req, len, 0) != len) return false;

    char resp[1024];
    int n = recv(s, resp, sizeof(resp) - 1, 0);
    if (n <= 0) return false;
    resp[n] = '\0';

    // Check for "200" in response
    return strstr(resp, "200") != nullptr;
}

// ============================================================================
// Hooked connect()
// ============================================================================

static int WSAAPI hooked_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    // Only intercept IPv4 TCP connections
    if (!g_config.active || name->sa_family != AF_INET) {
        return original_connect(s, name, namelen);
    }

    auto* addr = (const struct sockaddr_in*)name;
    uint32_t ip = ntohl(addr->sin_addr.s_addr);
    uint16_t dest_port = ntohs(addr->sin_port);

    // Skip loopback (127.x.x.x) and LAN-local to avoid loops
    if ((ip >> 24) == 127 || ip == 0) {
        return original_connect(s, name, namelen);
    }

    // Get destination as string (IP for now, DNS reverse not available)
    char dest_host[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, dest_host, sizeof(dest_host));

    // Build proxy address
    struct sockaddr_in proxy_addr = {};
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(g_config.proxy_port);

    // Resolve proxy host
    if (inet_pton(AF_INET, g_config.proxy_host, &proxy_addr.sin_addr) != 1) {
        struct addrinfo hints = {}, *result = nullptr;
        hints.ai_family = AF_INET;
        if (getaddrinfo(g_config.proxy_host, nullptr, &hints, &result) != 0 || !result) {
            // Can't resolve proxy, fail
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        }
        proxy_addr.sin_addr = ((struct sockaddr_in*)result->ai_addr)->sin_addr;
        freeaddrinfo(result);
    }

    // Save socket blocking mode - set to blocking for handshake
    u_long was_nonblocking = 0;
    // We can't query the mode directly, so we try the connect
    // and handle WSAEWOULDBLOCK

    // Connect to proxy server using original connect
    int ret = original_connect(s, (const struct sockaddr*)&proxy_addr, sizeof(proxy_addr));
    if (ret != 0) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            // Non-blocking socket - wait for connection to complete
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(s, &wfds);
            struct timeval tv = { 10, 0 }; // 10 second timeout
            int sel = select(0, nullptr, &wfds, nullptr, &tv);
            if (sel <= 0) {
                WSASetLastError(WSAETIMEDOUT);
                return SOCKET_ERROR;
            }
            // Check for connect error
            int optval = 0;
            int optlen = sizeof(optval);
            getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&optval, &optlen);
            if (optval != 0) {
                WSASetLastError(optval);
                return SOCKET_ERROR;
            }
            was_nonblocking = 1;
            // Temporarily set to blocking for handshake
            u_long block = 0;
            ioctlsocket(s, FIONBIO, &block);
        } else {
            return SOCKET_ERROR;
        }
    }

    // Do proxy handshake
    bool ok = false;
    switch (g_config.proxy_type) {
    case 0: // HTTP
    case 1: // HTTPS
        ok = do_http_connect(s, dest_host, dest_port);
        break;
    case 2: // SOCKS4
        ok = do_socks4(s, dest_host, dest_port);
        break;
    case 3: // SOCKS5
        ok = do_socks5(s, dest_host, dest_port);
        break;
    }

    // Restore non-blocking mode if needed
    if (was_nonblocking) {
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
    }

    if (!ok) {
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }

    return 0;
}

// ============================================================================
// Inline hook installation (x64: 14-byte absolute jump)
// ============================================================================

#ifdef _WIN64

static bool install_hook() {
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2) return false;

    connect_addr = (void*)GetProcAddress(ws2, "connect");
    if (!connect_addr) return false;

    // Save original bytes
    memcpy(saved_bytes, connect_addr, 14);

    // Allocate trampoline (executable memory)
    auto* trampoline = (uint8_t*)VirtualAlloc(nullptr, 64,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) return false;

    // Copy original prologue to trampoline
    memcpy(trampoline, saved_bytes, 14);

    // Add jump back: jmp [rip+0]; dq addr
    trampoline[14] = 0xFF;
    trampoline[15] = 0x25;
    trampoline[16] = 0x00;
    trampoline[17] = 0x00;
    trampoline[18] = 0x00;
    trampoline[19] = 0x00;
    *(uint64_t*)(trampoline + 20) = (uint64_t)((uint8_t*)connect_addr + 14);

    original_connect = (connect_fn)trampoline;

    // Patch original function: jmp [rip+0]; dq hook_addr
    DWORD old_prot;
    VirtualProtect(connect_addr, 14, PAGE_EXECUTE_READWRITE, &old_prot);

    uint8_t* p = (uint8_t*)connect_addr;
    p[0] = 0xFF;
    p[1] = 0x25;
    p[2] = 0x00;
    p[3] = 0x00;
    p[4] = 0x00;
    p[5] = 0x00;
    *(uint64_t*)(p + 6) = (uint64_t)&hooked_connect;

    VirtualProtect(connect_addr, 14, old_prot, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), connect_addr, 14);

    return true;
}

#else // x86: 5-byte relative jump

static bool install_hook() {
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2) return false;

    connect_addr = (void*)GetProcAddress(ws2, "connect");
    if (!connect_addr) return false;

    memcpy(saved_bytes, connect_addr, 5);

    // Trampoline
    auto* trampoline = (uint8_t*)VirtualAlloc(nullptr, 32,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) return false;

    memcpy(trampoline, saved_bytes, 5);

    // jmp original+5
    trampoline[5] = 0xE9;
    *(uint32_t*)(trampoline + 6) = (uint32_t)((uint8_t*)connect_addr + 5 - (trampoline + 10));

    original_connect = (connect_fn)trampoline;

    // Patch
    DWORD old_prot;
    VirtualProtect(connect_addr, 5, PAGE_EXECUTE_READWRITE, &old_prot);

    uint8_t* p = (uint8_t*)connect_addr;
    p[0] = 0xE9;
    *(uint32_t*)(p + 1) = (uint32_t)((uint8_t*)&hooked_connect - (p + 5));

    VirtualProtect(connect_addr, 5, old_prot, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), connect_addr, 5);

    return true;
}

#endif

static void remove_hook() {
    if (!connect_addr) return;

    int patch_size = sizeof(void*) == 8 ? 14 : 5;

    DWORD old_prot;
    VirtualProtect(connect_addr, patch_size, PAGE_EXECUTE_READWRITE, &old_prot);
    memcpy(connect_addr, saved_bytes, patch_size);
    VirtualProtect(connect_addr, patch_size, old_prot, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), connect_addr, patch_size);

    if (original_connect) {
        VirtualFree((void*)original_connect, 0, MEM_RELEASE);
        original_connect = nullptr;
    }
}

// ============================================================================
// DLL entry point
// ============================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        if (read_config() && g_config.active) {
            install_hook();
        }
        break;
    case DLL_PROCESS_DETACH:
        remove_hook();
        break;
    }
    return TRUE;
}
