#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <ctime>

// Live connection info
struct LiveConnection {
    uint64_t id;
    std::string app_name;           // Process name (e.g. "chrome.exe")
    DWORD pid;                      // Process ID
    std::string src_addr;           // Local source address
    std::string dest_host;          // Destination hostname
    std::string dest_ip;            // Destination IP
    uint16_t dest_port;
    std::string proxy_used;         // Which proxy is being used
    std::string chain_name;         // If using a chain

    uint64_t bytes_sent;
    uint64_t bytes_received;
    DWORD start_time;               // GetTickCount() when started
    DWORD duration_ms;              // How long active
    double send_rate_bps;           // Current send rate (bytes/sec)
    double recv_rate_bps;           // Current receive rate (bytes/sec)

    bool active;
    std::string status;             // "Connecting", "Connected", "Relaying", "Closed", "Error"
};

// Traffic log entry (persisted)
struct TrafficLogEntry {
    time_t timestamp;
    std::string app_name;
    DWORD pid;
    std::string dest_host;
    uint16_t dest_port;
    std::string proxy_used;
    std::string method;             // CONNECT, GET, POST, etc.
    int http_status;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t duration_ms;
    std::string error;              // Error message if failed
    std::string rule_matched;       // Which rule was applied
};

// Aggregate traffic statistics
struct TrafficSummary {
    uint64_t total_connections;
    uint64_t active_connections;
    uint64_t failed_connections;
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
    double current_send_rate;       // bytes/sec
    double current_recv_rate;       // bytes/sec
    uint64_t dns_queries;
    uint64_t dns_cache_hits;
    time_t uptime_start;
};

// System-wide TCP connection (from GetExtendedTcpTable)
struct SystemTcpConnection {
    DWORD pid;
    std::string app_name;
    std::string local_addr;
    uint16_t local_port;
    std::string remote_addr;
    uint16_t remote_port;
    std::string state;
    bool is_proxied;        // true if remote is our interceptor
};

class ConnectionMonitor {
public:
    ConnectionMonitor();
    ~ConnectionMonitor() = default;

    // Live connection tracking
    uint64_t add_connection(const LiveConnection& conn);
    void update_connection(uint64_t id, uint64_t bytes_sent, uint64_t bytes_received,
                           const std::string& status);
    void update_proxy_used(uint64_t id, const std::string& proxy_name);
    void close_connection(uint64_t id);
    std::vector<LiveConnection> get_active_connections();
    size_t active_count() const { return active_count_; }

    // System-wide TCP connection enumeration (like netstat)
    static std::vector<SystemTcpConnection> get_system_connections(
        uint16_t interceptor_http_port = 0, uint16_t interceptor_socks_port = 0);

    // Traffic logging
    void log_traffic(const TrafficLogEntry& entry);
    std::vector<TrafficLogEntry> get_recent_logs(size_t count = 200);
    void clear_logs();

    // Export logs
    bool export_logs(const std::string& filepath);

    // Aggregate stats
    TrafficSummary get_summary() const;
    void reset_stats();

    // Bandwidth tracking
    void record_bytes_sent(uint64_t bytes);
    void record_bytes_received(uint64_t bytes);
    void record_dns_query(bool cache_hit);

    // Rate calculation (call periodically)
    void update_rates();

private:
    // Live connections
    std::vector<LiveConnection> connections_;
    mutable std::mutex conn_mutex_;
    std::atomic<uint64_t> next_id_{1};
    std::atomic<size_t> active_count_{0};

    // Traffic logs
    std::vector<TrafficLogEntry> traffic_logs_;
    mutable std::mutex log_mutex_;
    static constexpr size_t MAX_LOGS = 10000;

    // Stats
    std::atomic<uint64_t> total_connections_{0};
    std::atomic<uint64_t> failed_connections_{0};
    std::atomic<uint64_t> total_bytes_sent_{0};
    std::atomic<uint64_t> total_bytes_received_{0};
    std::atomic<uint64_t> dns_queries_{0};
    std::atomic<uint64_t> dns_cache_hits_{0};

    // Rate calculation
    uint64_t prev_bytes_sent_ = 0;
    uint64_t prev_bytes_received_ = 0;
    DWORD prev_rate_time_ = 0;
    double current_send_rate_ = 0;
    double current_recv_rate_ = 0;

    time_t uptime_start_;
};
