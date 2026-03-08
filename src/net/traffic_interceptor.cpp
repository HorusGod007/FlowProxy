#include "net/traffic_interceptor.h"
#include "net/socks.h"

#include <sstream>
#include <algorithm>
#include <cctype>
#include <unordered_map>
#include <psapi.h>
#include <iphlpapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")

// Get our own exe name (cached) to bypass our own traffic
static std::string get_self_exe_name() {
    static std::string name;
    if (name.empty()) {
        char path[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, path, MAX_PATH);
        std::string full(path);
        auto slash = full.find_last_of("\\/");
        name = (slash != std::string::npos) ? full.substr(slash + 1) : full;
        for (auto& c : name) c = (char)tolower(c);
    }
    return name;
}

static bool is_self_process(const std::string& app_name) {
    std::string lower = app_name;
    for (auto& c : lower) c = (char)tolower(c);
    return lower == get_self_exe_name();
}

TrafficInterceptor::TrafficInterceptor(ProxyList& proxy_list, RulesEngine& rules,
                                       ProxyChainManager& chains, DnsResolver& dns,
                                       ConnectionMonitor& monitor)
    : proxy_list_(proxy_list), rules_(rules), chains_(chains),
      dns_(dns), monitor_(monitor) {}

TrafficInterceptor::~TrafficInterceptor() {
    stop();
}

bool TrafficInterceptor::start(uint16_t http_port, RotationMode mode) {
    if (running_) return false;

    rotation_mode_ = mode;
    http_port_ = http_port;

    if (!http_listen_.create()) return false;
    if (!http_listen_.bind_listen("127.0.0.1", http_port)) {
        http_listen_.close();
        return false;
    }

    running_ = true;
    http_thread_ = std::thread(&TrafficInterceptor::http_accept_loop, this);
    return true;
}

bool TrafficInterceptor::start_socks5(uint16_t socks_port, RotationMode mode) {
    if (socks_listen_.is_valid()) return false;

    rotation_mode_ = mode;
    socks_port_ = socks_port;

    if (!socks_listen_.create()) return false;
    if (!socks_listen_.bind_listen("127.0.0.1", socks_port)) {
        socks_listen_.close();
        return false;
    }

    if (!running_) running_ = true;
    socks_thread_ = std::thread(&TrafficInterceptor::socks5_accept_loop, this);
    return true;
}

void TrafficInterceptor::stop() {
    running_ = false;
    http_listen_.close();
    socks_listen_.close();
    if (http_thread_.joinable()) http_thread_.join();
    if (socks_thread_.joinable()) socks_thread_.join();

    // Wait for detached handler threads to finish (they decrement active_handlers_)
    int wait_ms = 0;
    while (active_handlers_ > 0 && wait_ms < 5000) {
        Sleep(10);
        wait_ms += 10;
    }
}

void TrafficInterceptor::reset_stats() {
    stats_.bytes_sent = 0;
    stats_.bytes_received = 0;
    stats_.connections_total = 0;
    stats_.connections_active = 0;
    stats_.connections_failed = 0;
}

// ============================================================================
// Accept loops
// ============================================================================

void TrafficInterceptor::http_accept_loop() {
    while (running_) {
        Socket client = http_listen_.accept_client();
        if (!client.is_valid()) {
            if (!running_) break;
            continue;
        }

        // Drop connection if too many active handlers
        if (active_handlers_ >= MAX_CONCURRENT_HANDLERS) {
            client.send_all("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nBusy");
            continue;
        }

        ++stats_.connections_total;
        ++stats_.connections_active;

        struct sockaddr_in addr;
        int addr_len = sizeof(addr);
        getpeername(client.handle(), (struct sockaddr*)&addr, &addr_len);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        std::string client_addr = std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));

        ++active_handlers_;
        std::thread([this, c = std::move(client), ca = std::move(client_addr)]() mutable {
            handle_http_client(std::move(c), ca);
            --stats_.connections_active;
            --active_handlers_;
        }).detach();
    }
}

void TrafficInterceptor::socks5_accept_loop() {
    while (running_) {
        Socket client = socks_listen_.accept_client();
        if (!client.is_valid()) {
            if (!running_) break;
            continue;
        }

        if (active_handlers_ >= MAX_CONCURRENT_HANDLERS) {
            continue; // Drop SOCKS connections when overloaded
        }

        ++stats_.connections_total;
        ++stats_.connections_active;

        struct sockaddr_in addr;
        int addr_len = sizeof(addr);
        getpeername(client.handle(), (struct sockaddr*)&addr, &addr_len);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        std::string client_addr = std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));

        ++active_handlers_;
        std::thread([this, c = std::move(client), ca = std::move(client_addr)]() mutable {
            handle_socks5_client(std::move(c), ca);
            --stats_.connections_active;
            --active_handlers_;
        }).detach();
    }
}

// ============================================================================
// HTTP proxy handler
// ============================================================================

void TrafficInterceptor::handle_http_client(Socket client, std::string client_addr) {
    client.set_timeout(15000);

    char buf[16384];
    int n = client.recv_raw(buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = '\0';
    std::string request(buf, n);

    std::string method, host, path;
    uint16_t port;

    if (!parse_request(request, method, host, port, path)) {
        client.send_all("HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request");
        ++stats_.connections_failed;
        return;
    }

    std::string app_name = get_process_name(client_addr, http_port_);

    // Register connection with monitor
    LiveConnection conn;
    conn.app_name = app_name;
    conn.pid = 0;
    conn.src_addr = client_addr;
    conn.dest_host = host;
    conn.dest_port = port;
    conn.status = "Connecting";
    uint64_t conn_id = monitor_.add_connection(conn);

    if (method == "CONNECT") {
        handle_connect(client, host, port, app_name, conn_id);
    } else {
        handle_http_request(client, host, port, request, method, app_name, conn_id);
    }

    monitor_.close_connection(conn_id);
}

// ============================================================================
// SOCKS5 server handler (local SOCKS5 proxy for apps that prefer SOCKS)
// ============================================================================

void TrafficInterceptor::handle_socks5_client(Socket client, std::string client_addr) {
    client.set_timeout(30000);

    // SOCKS5 greeting
    char greeting[256];
    int n = client.recv_raw(greeting, sizeof(greeting));
    if (n < 2 || greeting[0] != 0x05) return;

    // We accept no-auth
    char reply[2] = { 0x05, 0x00 }; // No auth
    if (!client.send_raw(reply, 2)) return;

    // Read connect request
    char req[512];
    n = client.recv_raw(req, sizeof(req));
    if (n < 4 || req[0] != 0x05 || req[1] != 0x01) {
        // Only support CONNECT command
        char err[10] = { 0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0 };
        client.send_raw(err, 10);
        return;
    }

    std::string dest_host;
    uint16_t dest_port;

    if (req[3] == 0x01) {
        // IPv4
        if (n < 10) return;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &req[4], ip, sizeof(ip));
        dest_host = ip;
        dest_port = ((uint8_t)req[8] << 8) | (uint8_t)req[9];
    } else if (req[3] == 0x03) {
        // Domain
        uint8_t domain_len = (uint8_t)req[4];
        if (n < 5 + domain_len + 2) return;
        dest_host = std::string(&req[5], domain_len);
        dest_port = ((uint8_t)req[5 + domain_len] << 8) | (uint8_t)req[6 + domain_len];
    } else if (req[3] == 0x04) {
        // IPv6
        if (n < 22) return;
        char ip6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &req[4], ip6, sizeof(ip6));
        dest_host = ip6;
        dest_port = ((uint8_t)req[20] << 8) | (uint8_t)req[21];
    } else {
        return;
    }

    std::string app_name = get_process_name(client_addr, socks_port_);

    LiveConnection conn;
    conn.app_name = app_name;
    conn.src_addr = client_addr;
    conn.dest_host = dest_host;
    conn.dest_port = dest_port;
    conn.status = "Connecting";
    uint64_t conn_id = monitor_.add_connection(conn);

    // Always bypass our own process to prevent loops
    if (is_self_process(app_name)) {
        Socket remote;
        if (connect_direct(remote, dest_host, dest_port)) {
            char success[10] = { 0x05, 0x00, 0x00, 0x01, 0x7F,0x00,0x00,0x01, 0x00,0x00 };
            success[8] = (char)((dest_port >> 8) & 0xFF);
            success[9] = (char)(dest_port & 0xFF);
            client.send_raw(success, 10);
            monitor_.update_proxy_used(conn_id, "DIRECT (self-bypass)");
            relay_data(client, remote, conn_id);
        }
        monitor_.close_connection(conn_id);
        return;
    }

    // Evaluate rules — only resolve DNS if there are IP-target rules
    ProxyRule matched_rule;
    const ProxyRule* rule = nullptr;
    if (rules_.rule_count() > 0) {
        std::string dest_ip;
        if (rules_.has_ip_target_rules())
            dest_ip = dns_.resolve_local(dest_host);
        if (rules_.evaluate(app_name, dest_host, dest_ip, dest_port, matched_rule))
            rule = &matched_rule;
    }

    // Check if we should block
    if (rule && rule->action == RuleAction::Block) {
        char err_resp[10] = { 0x05, 0x02, 0x00, 0x01, 0,0,0,0, 0,0 }; // Connection not allowed
        client.send_raw(err_resp, 10);
        monitor_.update_proxy_used(conn_id, "BLOCKED (rule: " + rule->name + ")");
        monitor_.close_connection(conn_id);
        return;
    }

    Socket remote;
    std::string proxy_name;
    bool connected = connect_via_rule(remote, rule, dest_host, dest_port, proxy_name);
    monitor_.update_proxy_used(conn_id, proxy_name);

    if (!connected) {
        char err_resp[10] = { 0x05, 0x05, 0x00, 0x01, 0,0,0,0, 0,0 };
        client.send_raw(err_resp, 10);
        ++stats_.connections_failed;
        monitor_.close_connection(conn_id);
        return;
    }

    // Send success response
    char success[10] = { 0x05, 0x00, 0x00, 0x01, 0x7F,0x00,0x00,0x01, 0x00,0x00 };
    success[8] = (char)((dest_port >> 8) & 0xFF);
    success[9] = (char)(dest_port & 0xFF);
    if (!client.send_raw(success, 10)) {
        monitor_.close_connection(conn_id);
        return;
    }

    monitor_.update_connection(conn_id, 0, 0, "Relaying");
    relay_data(client, remote, conn_id);
    monitor_.close_connection(conn_id);
}

// ============================================================================
// CONNECT handler (HTTPS tunneling)
// ============================================================================

void TrafficInterceptor::handle_connect(Socket& client, const std::string& host, uint16_t port,
                                         const std::string& app_name, uint64_t conn_id) {
    // Always bypass our own process to prevent loops
    if (is_self_process(app_name)) {
        Socket remote;
        if (connect_direct(remote, host, port)) {
            client.send_all("HTTP/1.1 200 Connection Established\r\n\r\n");
            monitor_.update_proxy_used(conn_id, "DIRECT (self)");
            monitor_.update_connection(conn_id, 0, 0, "Relaying");
            relay_data(client, remote, conn_id);
        } else {
            client.send_all("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        }
        return;
    }

    // Evaluate rules — only resolve DNS if there are IP-target rules
    ProxyRule matched_rule;
    const ProxyRule* rule = nullptr;
    if (rules_.rule_count() > 0) {
        std::string dest_ip;
        if (rules_.has_ip_target_rules())
            dest_ip = dns_.resolve_local(host);
        if (rules_.evaluate(app_name, host, dest_ip, port, matched_rule))
            rule = &matched_rule;
    }

    // Check if blocked
    if (rule && rule->action == RuleAction::Block) {
        client.send_all("HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\n\r\nBlocked");
        monitor_.update_connection(conn_id, 0, 0, "Blocked");
        monitor_.update_proxy_used(conn_id, "BLOCKED");

        TrafficLogEntry log;
        log.timestamp = time(nullptr);
        log.app_name = app_name;
        log.dest_host = host;
        log.dest_port = port;
        log.proxy_used = "BLOCKED";
        log.method = "CONNECT";
        log.http_status = 403;
        log.rule_matched = rule->name;
        monitor_.log_traffic(log);
        return;
    }

    Socket remote;
    std::string proxy_name;
    bool connected = connect_via_rule(remote, rule, host, port, proxy_name);
    monitor_.update_proxy_used(conn_id, proxy_name);

    // Always log the connection (DIRECT or proxied)
    TrafficLogEntry log;
    log.timestamp = time(nullptr);
    log.app_name = app_name;
    log.dest_host = host;
    log.dest_port = port;
    log.proxy_used = proxy_name;
    log.method = "CONNECT";
    log.rule_matched = rule ? rule->name : "";

    if (!connected) {
        client.send_all("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 21\r\n\r\nProxy connect failed");
        ++stats_.connections_failed;
        monitor_.update_connection(conn_id, 0, 0, "Failed");
        log.http_status = 502;
        log.error = "Connection failed";
        monitor_.log_traffic(log);
        return;
    }

    client.send_all("HTTP/1.1 200 Connection Established\r\n\r\n");
    monitor_.update_connection(conn_id, 0, 0, "Relaying");
    relay_data(client, remote, conn_id);

    log.http_status = 200;
    monitor_.log_traffic(log);
}

// ============================================================================
// HTTP request handler
// ============================================================================

void TrafficInterceptor::handle_http_request(Socket& client, const std::string& host, uint16_t port,
                                              const std::string& request, const std::string& method,
                                              const std::string& app_name, uint64_t conn_id) {
    // Bypass our own process
    if (is_self_process(app_name)) {
        Socket remote;
        if (connect_direct(remote, host, port)) {
            // Build relative-path request
            std::string path = "/";
            auto proto = request.find("://");
            if (proto != std::string::npos) {
                auto working = request.substr(proto + 3);
                auto slash = working.find('/');
                if (slash != std::string::npos) {
                    auto space = working.find(' ', slash);
                    path = working.substr(slash, space != std::string::npos ? space - slash : std::string::npos);
                }
            }
            remote.send_all(make_relative_request(request, path));
            monitor_.update_proxy_used(conn_id, "DIRECT (self-bypass)");
            monitor_.update_connection(conn_id, 0, 0, "Relaying");
            relay_data(client, remote, conn_id);
        } else {
            client.send_all("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        }
        return;
    }

    ProxyRule matched_rule;
    const ProxyRule* rule = nullptr;
    if (rules_.rule_count() > 0) {
        std::string dest_ip;
        if (rules_.has_ip_target_rules())
            dest_ip = dns_.resolve_local(host);
        if (rules_.evaluate(app_name, host, dest_ip, port, matched_rule))
            rule = &matched_rule;
    }

    if (rule && rule->action == RuleAction::Block) {
        client.send_all("HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\n\r\nBlocked");
        monitor_.update_connection(conn_id, 0, 0, "Blocked");
        monitor_.update_proxy_used(conn_id, "BLOCKED (rule: " + rule->name + ")");
        return;
    }

    Socket remote;
    std::string proxy_name;

    TrafficLogEntry log;
    log.timestamp = time(nullptr);
    log.app_name = app_name;
    log.dest_host = host;
    log.dest_port = port;
    log.method = method;
    log.rule_matched = rule ? rule->name : "";

    if (!connect_via_rule(remote, rule, host, port, proxy_name)) {
        client.send_all("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        ++stats_.connections_failed;
        monitor_.update_proxy_used(conn_id, proxy_name + " (FAILED)");
        log.proxy_used = proxy_name;
        log.http_status = 502;
        log.error = "Connection failed";
        monitor_.log_traffic(log);
        return;
    }
    monitor_.update_proxy_used(conn_id, proxy_name);
    log.proxy_used = proxy_name;

    // For direct and SOCKS connections, send relative-path request
    // For HTTP proxy connections, forward the original absolute-URL request
    bool is_direct = (!rule || rule->action == RuleAction::Direct);
    bool is_http_proxy = false;
    if (!is_direct && rule && rule->action == RuleAction::UseProxy && rule->proxy_index >= 0) {
        std::lock_guard<std::mutex> lock(proxy_list_.mutex());
        if ((size_t)rule->proxy_index < proxy_list_.size()) {
            auto t = proxy_list_.at(rule->proxy_index).type;
            is_http_proxy = (t == ProxyType::HTTP || t == ProxyType::HTTPS);
        }
    }

    if (is_http_proxy) {
        remote.send_all(request);
    } else {
        std::string path = "/";
        auto proto = request.find("://");
        if (proto != std::string::npos) {
            auto working = request.substr(proto + 3);
            auto slash = working.find('/');
            if (slash != std::string::npos) {
                auto space = working.find(' ', slash);
                path = working.substr(slash, space != std::string::npos ? space - slash : std::string::npos);
            }
        }
        remote.send_all(make_relative_request(request, path));
    }

    monitor_.update_connection(conn_id, 0, 0, "Relaying");
    relay_data(client, remote, conn_id);

    log.http_status = 200;
    monitor_.log_traffic(log);
}

// ============================================================================
// Rule-based connection routing
// ============================================================================

bool TrafficInterceptor::connect_via_rule(Socket& remote, const ProxyRule* rule,
                                           const std::string& dest_host, uint16_t dest_port,
                                           std::string& proxy_name) {
    proxy_name = "DIRECT";

    // No matching rule = passthrough (direct connection, no proxy)
    if (!rule) {
        proxy_name = "DIRECT";
        return connect_direct(remote, dest_host, dest_port);
    }

    if (rule->action == RuleAction::Direct) {
        proxy_name = "DIRECT (rule: " + rule->name + ")";
        return connect_direct(remote, dest_host, dest_port);
    }

    if (rule->action == RuleAction::UseProxy) {
        // Copy proxy data out of the lock, then connect without holding it
        Proxy proxy_copy;
        bool have_proxy = false;

        if (rule->proxy_index >= 0) {
            std::lock_guard<std::mutex> lock(proxy_list_.mutex());
            if ((size_t)rule->proxy_index < proxy_list_.size()) {
                proxy_copy = proxy_list_.at(rule->proxy_index);
                have_proxy = true;
            }
        }

        if (!have_proxy) {
            // Use rotation — copy proxy data while locked
            std::lock_guard<std::mutex> lock(proxy_list_.mutex());
            Proxy* p = proxy_list_.next_proxy(rotation_mode_);
            if (p) { proxy_copy = *p; have_proxy = true; }
        }

        if (have_proxy) {
            proxy_name = proxy_copy.address() + " (" + proxy_type_to_str(proxy_copy.type) + ")";
            return connect_through_proxy(remote, proxy_copy, dest_host, dest_port);
        }

        proxy_name = "DIRECT (no proxy available)";
        return connect_direct(remote, dest_host, dest_port);
    }

    if (rule->action == RuleAction::UseChain) {
        if (rule->chain_index >= 0 && (size_t)rule->chain_index < chains_.chain_count()) {
            const auto& chain = chains_.chain_at(rule->chain_index);
            proxy_name = "Chain: " + chain.name;
            // Copy proxies out of the lock
            std::vector<Proxy> proxies_copy;
            {
                std::lock_guard<std::mutex> lock(proxy_list_.mutex());
                proxies_copy = proxy_list_.proxies();
            }
            return chains_.connect_through_chain(remote, chain, proxies_copy,
                                                  dest_host, dest_port);
        }
    }

    // Unknown action, go direct
    proxy_name = "DIRECT (fallback)";
    return connect_direct(remote, dest_host, dest_port);
}

bool TrafficInterceptor::connect_through_proxy(Socket& remote, const Proxy& proxy,
                                                const std::string& dest_host, uint16_t dest_port) {
    if (!remote.create()) return false;
    remote.set_timeout(5000);

    if (!remote.connect(proxy.host, proxy.port)) return false;

    switch (proxy.type) {
    case ProxyType::HTTP:
    case ProxyType::HTTPS: {
        std::string req = "CONNECT " + dest_host + ":" + std::to_string(dest_port) + " HTTP/1.1\r\n";
        req += "Host: " + dest_host + ":" + std::to_string(dest_port) + "\r\n";

        if (proxy.has_auth()) {
            static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string auth_str = proxy.username + ":" + proxy.password;
            std::string encoded;
            int val = 0, valb = -6;
            for (unsigned char c : auth_str) {
                val = (val << 8) + c;
                valb += 8;
                while (valb >= 0) {
                    encoded.push_back(b64[(val >> valb) & 0x3F]);
                    valb -= 6;
                }
            }
            if (valb > -6) encoded.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
            while (encoded.size() % 4) encoded.push_back('=');
            req += "Proxy-Authorization: Basic " + encoded + "\r\n";
        }

        req += "\r\n";
        if (!remote.send_all(req)) return false;
        std::string resp = remote.recv_all(4096);
        return resp.find("200") != std::string::npos;
    }

    case ProxyType::SOCKS4:
        return socks4_connect(remote, dest_host, dest_port);

    case ProxyType::SOCKS5:
        return socks5_connect(remote, dest_host, dest_port, proxy.username, proxy.password);

    default:
        return false;
    }
}

bool TrafficInterceptor::connect_direct(Socket& remote, const std::string& host, uint16_t port) {
    if (!remote.create()) return false;
    remote.set_timeout(10000);
    return remote.connect(host, port);
}

// ============================================================================
// Data relay with monitoring
// ============================================================================

void TrafficInterceptor::relay_data(Socket& client, Socket& remote, uint64_t conn_id) {
    fd_set fds;
    char buf[32768];
    uint64_t bytes_sent = 0, bytes_recv = 0;
    DWORD last_update = GetTickCount();

    while (running_) {
        FD_ZERO(&fds);
        FD_SET(client.handle(), &fds);
        FD_SET(remote.handle(), &fds);

        struct timeval tv;
        tv.tv_sec = 120;
        tv.tv_usec = 0;

        SOCKET max_fd = std::max(client.handle(), remote.handle()) + 1;
        int ready = select((int)max_fd, &fds, nullptr, nullptr, &tv);
        if (ready <= 0) break;

        if (FD_ISSET(client.handle(), &fds)) {
            int n = client.recv_raw(buf, sizeof(buf));
            if (n <= 0) break;
            if (!remote.send_raw(buf, n)) break;
            bytes_sent += n;
            stats_.bytes_sent += n;
            monitor_.record_bytes_sent(n);
        }

        if (FD_ISSET(remote.handle(), &fds)) {
            int n = remote.recv_raw(buf, sizeof(buf));
            if (n <= 0) break;
            if (!client.send_raw(buf, n)) break;
            bytes_recv += n;
            stats_.bytes_received += n;
            monitor_.record_bytes_received(n);
        }

        // Update monitor periodically (every 500ms)
        DWORD now = GetTickCount();
        if (now - last_update > 500) {
            monitor_.update_connection(conn_id, bytes_sent, bytes_recv, "Relaying");
            last_update = now;
        }
    }

    monitor_.update_connection(conn_id, bytes_sent, bytes_recv, "Closed");
}

// ============================================================================
// Request parsing
// ============================================================================

bool TrafficInterceptor::parse_request(const std::string& request, std::string& method,
                                        std::string& host, uint16_t& port, std::string& path) {
    std::istringstream iss(request);
    std::string url, version;
    iss >> method >> url >> version;

    if (method.empty() || url.empty()) return false;
    for (auto& c : method) c = (char)toupper(c);

    if (method == "CONNECT") {
        auto colon = url.rfind(':');
        if (colon == std::string::npos) return false;
        host = url.substr(0, colon);
        try { port = (uint16_t)std::stoi(url.substr(colon + 1)); } catch (...) { return false; }
        path = "";
        return true;
    }

    port = 80;
    std::string working = url;
    auto proto = working.find("://");
    if (proto != std::string::npos) {
        std::string scheme = working.substr(0, proto);
        for (auto& c : scheme) c = (char)tolower(c);
        if (scheme == "https") port = 443;
        working = working.substr(proto + 3);
    }

    auto slash = working.find('/');
    std::string host_port = (slash != std::string::npos) ? working.substr(0, slash) : working;
    path = (slash != std::string::npos) ? working.substr(slash) : "/";

    auto colon = host_port.rfind(':');
    if (colon != std::string::npos) {
        host = host_port.substr(0, colon);
        try { port = (uint16_t)std::stoi(host_port.substr(colon + 1)); } catch (...) {}
    } else {
        host = host_port;
    }

    return !host.empty();
}

std::string TrafficInterceptor::make_relative_request(const std::string& request, const std::string& path) {
    auto first_line_end = request.find("\r\n");
    if (first_line_end == std::string::npos) return request;

    std::istringstream iss(request);
    std::string method, url, version;
    iss >> method >> url >> version;

    return method + " " + path + " " + version + request.substr(first_line_end);
}

std::string TrafficInterceptor::get_process_name(const std::string& client_addr, uint16_t listen_port) {
    // Extract port from client_addr "ip:port"
    auto colon = client_addr.rfind(':');
    if (colon == std::string::npos) return "unknown";

    uint16_t local_port;
    try { local_port = (uint16_t)std::stoi(client_addr.substr(colon + 1)); }
    catch (...) { return "unknown"; }

    // Use GetExtendedTcpTable to find the process owning this connection
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    if (size == 0) return "unknown";

    std::vector<char> buf(size + 256);
    size = (DWORD)buf.size();
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_CONNECTIONS, 0) != NO_ERROR) {
        return "unknown";
    }

    auto* table = (MIB_TCPTABLE_OWNER_PID*)buf.data();
    DWORD pid = 0;
    DWORD loopback = htonl(INADDR_LOOPBACK); // 127.0.0.1 in network byte order
    uint16_t listen_port_n = htons(listen_port);

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        // Match: client's local port, connecting to our interceptor (127.0.0.1:listen_port)
        if (ntohs((uint16_t)row.dwLocalPort) == local_port &&
            row.dwRemoteAddr == loopback &&
            row.dwRemotePort == listen_port_n &&
            row.dwLocalAddr == loopback) {
            pid = row.dwOwningPid;
            break;
        }
    }

    if (pid == 0) return "unknown";

    // Get process name from PID (cached per-PID)
    static std::mutex cache_mutex;
    static std::unordered_map<DWORD, std::string> pid_cache;
    static DWORD cache_time = 0;

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        // Invalidate cache every 5 seconds
        DWORD now = GetTickCount();
        if (now - cache_time > 5000) {
            pid_cache.clear();
            cache_time = now;
        }
        auto it = pid_cache.find(pid);
        if (it != pid_cache.end()) return it->second;
    }

    std::string name = "PID:" + std::to_string(pid);
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process) {
        char exe_path[MAX_PATH] = {};
        DWORD path_size = MAX_PATH;
        if (QueryFullProcessImageNameA(process, 0, exe_path, &path_size)) {
            std::string full_path(exe_path);
            auto last_slash = full_path.find_last_of("\\/");
            name = (last_slash != std::string::npos) ? full_path.substr(last_slash + 1) : full_path;
        }
        CloseHandle(process);
    }

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        pid_cache[pid] = name;
    }
    return name;
}

std::string TrafficInterceptor::resolve_host(const std::string& hostname, const Proxy* proxy) {
    return dns_.resolve(hostname, proxy);
}
