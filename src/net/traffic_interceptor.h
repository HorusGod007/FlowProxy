#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>

#include "core/proxy_list.h"
#include "core/rules_engine.h"
#include "core/proxy_chain.h"
#include "net/socket.h"
#include "net/dns_resolver.h"
#include "net/connection_monitor.h"

#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <mutex>

// Traffic statistics
struct TrafficStats {
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> connections_total{0};
    std::atomic<uint64_t> connections_active{0};
    std::atomic<uint64_t> connections_failed{0};
};

// The TrafficInterceptor is the core proxy routing engine.
// It runs a local HTTP/SOCKS5 proxy server that captures application traffic
// and routes it through configured proxy servers based on rules.
//
// How it works:
// 1. Applications connect to this local proxy (via system proxy settings or manual config)
// 2. The interceptor evaluates routing rules for each connection
// 3. Traffic is forwarded through the appropriate proxy/chain/direct
// 4. All connections are monitored in real-time with full logging
//
// Combined with SystemProxy (which sets the OS-level proxy to point here),
// this forces ALL applications to route through proxies - browsers, games,
// email clients, FTP tools, etc. - even apps without proxy settings.
class TrafficInterceptor {
public:
    TrafficInterceptor(ProxyList& proxy_list, RulesEngine& rules,
                       ProxyChainManager& chains, DnsResolver& dns,
                       ConnectionMonitor& monitor);
    ~TrafficInterceptor();

    // Start/stop the interceptor
    bool start(uint16_t http_port, RotationMode mode);
    bool start_socks5(uint16_t socks_port, RotationMode mode);
    void stop();
    bool is_running() const { return running_; }

    uint16_t http_port() const { return http_port_; }
    uint16_t socks_port() const { return socks_port_; }

    // Legacy stats access
    const TrafficStats& stats() const { return stats_; }
    void reset_stats();

private:
    void http_accept_loop();
    void socks5_accept_loop();

    void handle_http_client(Socket client, std::string client_addr);
    void handle_socks5_client(Socket client, std::string client_addr);

    // Protocol handlers
    void handle_connect(Socket& client, const std::string& host, uint16_t port,
                       const std::string& app_name, uint64_t conn_id);
    void handle_http_request(Socket& client, const std::string& host, uint16_t port,
                            const std::string& request, const std::string& method,
                            const std::string& app_name, uint64_t conn_id);

    // Connect to target through proxy/chain/direct based on rule
    bool connect_via_rule(Socket& remote, const ProxyRule* rule,
                         const std::string& dest_host, uint16_t dest_port,
                         std::string& proxy_name);
    bool connect_through_proxy(Socket& remote, const Proxy& proxy,
                              const std::string& dest_host, uint16_t dest_port);
    bool connect_direct(Socket& remote, const std::string& host, uint16_t port);

    // Bidirectional data relay
    void relay_data(Socket& client, Socket& remote, uint64_t conn_id);
    void relay_data_simple(Socket& client, Socket& remote);

    // Request parsing
    bool parse_request(const std::string& request, std::string& method,
                      std::string& host, uint16_t& port, std::string& path);
    std::string make_relative_request(const std::string& request, const std::string& path);

    // Get process name from connection (best-effort)
    std::string get_process_name(const std::string& client_addr, uint16_t listen_port);

    // Resolve hostname respecting DNS mode
    std::string resolve_host(const std::string& hostname, const Proxy* proxy);

    ProxyList& proxy_list_;
    RulesEngine& rules_;
    ProxyChainManager& chains_;
    DnsResolver& dns_;
    ConnectionMonitor& monitor_;

    RotationMode rotation_mode_ = RotationMode::RoundRobin;

    Socket http_listen_;
    Socket socks_listen_;
    std::thread http_thread_;
    std::thread socks_thread_;
    std::atomic<bool> running_{false};
    uint16_t http_port_ = 0;
    uint16_t socks_port_ = 0;

    TrafficStats stats_;

    // Concurrency limit
    std::atomic<int> active_handlers_{0};
    static constexpr int MAX_CONCURRENT_HANDLERS = 512;
};
