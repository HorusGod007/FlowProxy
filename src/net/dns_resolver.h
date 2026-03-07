#pragma once

#include "core/proxy.h"
#include "net/socket.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <cstdint>

// DNS resolution modes
enum class DnsMode {
    Local = 0,          // Use system DNS (default, may leak)
    RemoteProxy,        // Resolve DNS through the proxy (prevents DNS leaks)
    CustomDNS,          // Use custom DNS server through proxy
    DoH                 // DNS-over-HTTPS through proxy (future)
};

// DNS cache entry
struct DnsCacheEntry {
    std::string hostname;
    std::string ip;
    uint32_t ttl;
    time_t cached_at;
};

// Resolves DNS through proxy connections to prevent DNS leaks.
// When enabled, all hostname resolution goes through the SOCKS5 proxy
// (which supports remote DNS resolution) instead of the local network.
class DnsResolver {
public:
    DnsResolver() = default;

    void set_mode(DnsMode mode) { mode_ = mode; }
    DnsMode mode() const { return mode_; }

    void set_custom_dns(const std::string& dns_server, uint16_t port = 53);

    // Resolve hostname to IP
    // If mode is RemoteProxy, the resolution happens through the given proxy
    std::string resolve(const std::string& hostname, const Proxy* proxy = nullptr);

    // Resolve using system DNS (standard getaddrinfo)
    std::string resolve_local(const std::string& hostname);

    // Resolve through a SOCKS5 proxy (proxy does the DNS resolution)
    // SOCKS5 supports domain-name address type, so the proxy resolves it
    // Returns empty string - actual resolution happens during SOCKS5 connect
    // This function just validates the approach
    bool supports_remote_dns(const Proxy& proxy);

    // Resolve through custom DNS server via proxy
    std::string resolve_via_custom_dns(const std::string& hostname, const Proxy& proxy);

    // Cache management
    void enable_cache(bool enable) { cache_enabled_ = enable; }
    void set_cache_ttl(uint32_t seconds) { cache_ttl_ = seconds; }
    void flush_cache();
    size_t cache_size() const;

    // DNS leak check - returns true if DNS queries might leak
    bool check_dns_leak() const { return mode_ == DnsMode::Local; }

private:
    // Build a DNS query packet for a hostname
    std::vector<uint8_t> build_dns_query(const std::string& hostname, uint16_t query_id);

    // Parse DNS response to extract IP
    std::string parse_dns_response(const std::vector<uint8_t>& response);

    // Cache lookup
    std::string cache_lookup(const std::string& hostname);
    void cache_store(const std::string& hostname, const std::string& ip, uint32_t ttl);

    DnsMode mode_ = DnsMode::Local;
    std::string custom_dns_server_ = "8.8.8.8";
    uint16_t custom_dns_port_ = 53;

    bool cache_enabled_ = true;
    uint32_t cache_ttl_ = 300; // 5 minutes default

    std::unordered_map<std::string, DnsCacheEntry> cache_;
    mutable std::mutex cache_mutex_;
};
