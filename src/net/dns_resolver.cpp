#include "net/dns_resolver.h"
#include "net/socks.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#include <ctime>
#include <random>
#include <sstream>

void DnsResolver::set_custom_dns(const std::string& dns_server, uint16_t port) {
    custom_dns_server_ = dns_server;
    custom_dns_port_ = port;
}

std::string DnsResolver::resolve(const std::string& hostname, const Proxy* proxy) {
    // Check if it's already an IP
    struct in_addr addr;
    if (inet_pton(AF_INET, hostname.c_str(), &addr) == 1) {
        return hostname;
    }

    // Check cache first
    if (cache_enabled_) {
        std::string cached = cache_lookup(hostname);
        if (!cached.empty()) return cached;
    }

    std::string result;

    switch (mode_) {
    case DnsMode::Local:
        result = resolve_local(hostname);
        break;

    case DnsMode::RemoteProxy:
        // For SOCKS5, DNS resolution happens on the proxy side
        // when we use domain-name address type (0x03).
        // We return the hostname itself - the SOCKS5 connect will resolve it.
        // For HTTP CONNECT, the proxy resolves it.
        // We only need local resolution for SOCKS4 (which requires IP).
        if (proxy && proxy->type == ProxyType::SOCKS4) {
            result = resolve_local(hostname);
        } else {
            // Return hostname as-is; proxy will resolve
            return hostname;
        }
        break;

    case DnsMode::CustomDNS:
        if (proxy) {
            result = resolve_via_custom_dns(hostname, *proxy);
        } else {
            result = resolve_local(hostname);
        }
        break;

    case DnsMode::DoH:
        // DNS-over-HTTPS - would send HTTPS request to DoH server through proxy
        // For now fall back to custom DNS
        if (proxy) {
            result = resolve_via_custom_dns(hostname, *proxy);
        } else {
            result = resolve_local(hostname);
        }
        break;
    }

    if (!result.empty() && cache_enabled_) {
        cache_store(hostname, result, cache_ttl_);
    }

    return result;
}

std::string DnsResolver::resolve_local(const std::string& hostname) {
    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &result) != 0) {
        return "";
    }

    char ip[INET_ADDRSTRLEN];
    struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));

    freeaddrinfo(result);
    return std::string(ip);
}

bool DnsResolver::supports_remote_dns(const Proxy& proxy) {
    // SOCKS5 supports domain-name address type (0x03) - remote DNS
    // HTTP CONNECT sends hostname - proxy resolves
    // SOCKS4 does NOT support remote DNS (requires IP)
    // SOCKS4a supports remote DNS
    return proxy.type == ProxyType::SOCKS5 ||
           proxy.type == ProxyType::HTTP ||
           proxy.type == ProxyType::HTTPS;
}

std::string DnsResolver::resolve_via_custom_dns(const std::string& hostname, const Proxy& proxy) {
    // Connect to custom DNS server through the proxy
    Socket sock;
    if (!sock.create()) return "";
    sock.set_timeout(5000);

    // Connect to proxy
    if (!sock.connect(proxy.host, proxy.port)) return "";

    // Tunnel to DNS server through proxy
    bool connected = false;
    switch (proxy.type) {
    case ProxyType::SOCKS5:
        connected = socks5_connect(sock, custom_dns_server_, custom_dns_port_,
                                   proxy.username, proxy.password);
        break;
    case ProxyType::SOCKS4:
        connected = socks4_connect(sock, custom_dns_server_, custom_dns_port_);
        break;
    default:
        // HTTP proxies can't tunnel raw TCP to port 53 easily
        // Fall back to local resolution
        return resolve_local(hostname);
    }

    if (!connected) return resolve_local(hostname);

    // Build and send DNS query
    static std::mt19937 rng(std::random_device{}());
    uint16_t query_id = (uint16_t)(rng() & 0xFFFF);

    auto query = build_dns_query(hostname, query_id);

    // DNS over TCP: prepend 2-byte length
    uint16_t len = htons((uint16_t)query.size());
    if (!sock.send_raw((const char*)&len, 2)) return resolve_local(hostname);
    if (!sock.send_raw((const char*)query.data(), (int)query.size())) return resolve_local(hostname);

    // Read response length
    uint16_t resp_len;
    if (sock.recv_raw((char*)&resp_len, 2) != 2) return resolve_local(hostname);
    resp_len = ntohs(resp_len);

    if (resp_len > 4096 || resp_len < 12) return resolve_local(hostname);

    std::vector<uint8_t> response(resp_len);
    int received = 0;
    while (received < resp_len) {
        int n = sock.recv_raw((char*)response.data() + received, resp_len - received);
        if (n <= 0) return resolve_local(hostname);
        received += n;
    }

    return parse_dns_response(response);
}

std::vector<uint8_t> DnsResolver::build_dns_query(const std::string& hostname, uint16_t query_id) {
    std::vector<uint8_t> packet;

    // Header
    packet.push_back((uint8_t)(query_id >> 8));
    packet.push_back((uint8_t)(query_id & 0xFF));
    packet.push_back(0x01); // QR=0, Opcode=0, RD=1
    packet.push_back(0x00); // RA=0, Z=0, RCODE=0
    packet.push_back(0x00); packet.push_back(0x01); // QDCOUNT = 1
    packet.push_back(0x00); packet.push_back(0x00); // ANCOUNT = 0
    packet.push_back(0x00); packet.push_back(0x00); // NSCOUNT = 0
    packet.push_back(0x00); packet.push_back(0x00); // ARCOUNT = 0

    // Question section - encode hostname as labels
    std::istringstream iss(hostname);
    std::string label;
    while (std::getline(iss, label, '.')) {
        packet.push_back((uint8_t)label.size());
        for (char c : label) packet.push_back((uint8_t)c);
    }
    packet.push_back(0x00); // Root label

    // QTYPE = A (1)
    packet.push_back(0x00); packet.push_back(0x01);
    // QCLASS = IN (1)
    packet.push_back(0x00); packet.push_back(0x01);

    return packet;
}

std::string DnsResolver::parse_dns_response(const std::vector<uint8_t>& response) {
    if (response.size() < 12) return "";

    // Check ANCOUNT
    uint16_t ancount = ((uint16_t)response[6] << 8) | response[7];
    if (ancount == 0) return "";

    // Skip header (12 bytes) and question section
    size_t pos = 12;

    // Skip question name
    while (pos < response.size() && response[pos] != 0) {
        if ((response[pos] & 0xC0) == 0xC0) {
            pos += 2; // Pointer
            break;
        }
        pos += response[pos] + 1;
    }
    if (pos < response.size() && response[pos] == 0) ++pos;

    pos += 4; // Skip QTYPE and QCLASS

    // Parse answer records
    for (uint16_t i = 0; i < ancount && pos < response.size(); ++i) {
        // Skip name (may be compressed)
        if ((response[pos] & 0xC0) == 0xC0) {
            pos += 2;
        } else {
            while (pos < response.size() && response[pos] != 0) {
                pos += response[pos] + 1;
            }
            if (pos < response.size()) ++pos;
        }

        if (pos + 10 > response.size()) break;

        uint16_t rtype = ((uint16_t)response[pos] << 8) | response[pos + 1];
        uint16_t rdlength = ((uint16_t)response[pos + 8] << 8) | response[pos + 9];
        pos += 10;

        if (rtype == 1 && rdlength == 4 && pos + 4 <= response.size()) {
            // A record - IPv4
            char ip[INET_ADDRSTRLEN];
            snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
                     response[pos], response[pos + 1], response[pos + 2], response[pos + 3]);
            return std::string(ip);
        }

        pos += rdlength;
    }

    return "";
}

std::string DnsResolver::cache_lookup(const std::string& hostname) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = cache_.find(hostname);
    if (it != cache_.end()) {
        time_t now = time(nullptr);
        if ((now - it->second.cached_at) < (time_t)it->second.ttl) {
            return it->second.ip;
        }
        cache_.erase(it); // Expired
    }
    return "";
}

void DnsResolver::cache_store(const std::string& hostname, const std::string& ip, uint32_t ttl) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    DnsCacheEntry entry;
    entry.hostname = hostname;
    entry.ip = ip;
    entry.ttl = ttl;
    entry.cached_at = time(nullptr);
    cache_[hostname] = entry;
}

void DnsResolver::flush_cache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_.clear();
}

size_t DnsResolver::cache_size() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    return cache_.size();
}
