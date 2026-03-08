#include "net/connection_monitor.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <fstream>
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <unordered_map>

ConnectionMonitor::ConnectionMonitor() {
    uptime_start_ = time(nullptr);
    prev_rate_time_ = GetTickCount();
}

uint64_t ConnectionMonitor::add_connection(const LiveConnection& conn) {
    std::lock_guard<std::mutex> lock(conn_mutex_);

    LiveConnection c = conn;
    c.id = next_id_++;
    c.active = true;
    c.start_time = GetTickCount();
    c.bytes_sent = 0;
    c.bytes_received = 0;
    c.send_rate_bps = 0;
    c.recv_rate_bps = 0;

    connections_.push_back(c);
    ++active_count_;
    ++total_connections_;

    return c.id;
}

void ConnectionMonitor::update_connection(uint64_t id, uint64_t bytes_sent, uint64_t bytes_received,
                                           const std::string& status) {
    std::lock_guard<std::mutex> lock(conn_mutex_);

    for (auto& conn : connections_) {
        if (conn.id == id) {
            conn.bytes_sent = bytes_sent;
            conn.bytes_received = bytes_received;
            conn.status = status;
            conn.duration_ms = GetTickCount() - conn.start_time;
            break;
        }
    }
}

void ConnectionMonitor::update_proxy_used(uint64_t id, const std::string& proxy_name) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    for (auto& conn : connections_) {
        if (conn.id == id) {
            conn.proxy_used = proxy_name;
            break;
        }
    }
}

void ConnectionMonitor::close_connection(uint64_t id) {
    std::lock_guard<std::mutex> lock(conn_mutex_);

    for (auto& conn : connections_) {
        if (conn.id == id && conn.active) {
            conn.active = false;
            conn.status = "Closed";
            conn.duration_ms = GetTickCount() - conn.start_time;
            --active_count_;
            break;
        }
    }

    // Remove old inactive connections (keep last 500)
    if (connections_.size() > 1000) {
        auto it = std::remove_if(connections_.begin(), connections_.end(),
            [](const LiveConnection& c) { return !c.active; });
        if (std::distance(it, connections_.end()) > 500) {
            connections_.erase(it, connections_.end() - 500);
        }
    }
}

std::vector<LiveConnection> ConnectionMonitor::get_active_connections() {
    std::unique_lock<std::mutex> lock(conn_mutex_, std::try_to_lock);
    if (!lock.owns_lock()) return {}; // Don't block UI if mutex is held

    std::vector<LiveConnection> active;
    DWORD now = GetTickCount();
    for (const auto& conn : connections_) {
        if (conn.active) {
            LiveConnection c = conn;
            c.duration_ms = now - c.start_time;
            active.push_back(c);
        }
    }
    return active;
}

void ConnectionMonitor::log_traffic(const TrafficLogEntry& entry) {
    std::lock_guard<std::mutex> lock(log_mutex_);

    if (traffic_logs_.size() >= MAX_LOGS) {
        traffic_logs_.erase(traffic_logs_.begin(),
                           traffic_logs_.begin() + (MAX_LOGS / 4));
    }

    traffic_logs_.push_back(entry);

    if (!entry.error.empty()) {
        ++failed_connections_;
    }
}

std::vector<TrafficLogEntry> ConnectionMonitor::get_recent_logs(size_t count) {
    std::unique_lock<std::mutex> lock(log_mutex_, std::try_to_lock);
    if (!lock.owns_lock()) return {}; // Don't block UI
    size_t start = (traffic_logs_.size() > count) ? traffic_logs_.size() - count : 0;
    return std::vector<TrafficLogEntry>(traffic_logs_.begin() + start, traffic_logs_.end());
}

void ConnectionMonitor::clear_logs() {
    std::lock_guard<std::mutex> lock(log_mutex_);
    traffic_logs_.clear();
}

bool ConnectionMonitor::export_logs(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    std::ofstream file(filepath);
    if (!file.is_open()) return false;

    file << "Timestamp,Application,PID,Destination,Port,Proxy,Method,Status,"
         << "BytesSent,BytesReceived,Duration(ms),Rule,Error\n";

    for (const auto& log : traffic_logs_) {
        struct tm tm_info;
        localtime_s(&tm_info, &log.timestamp);
        char time_buf[32];
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

        file << time_buf << ","
             << log.app_name << ","
             << log.pid << ","
             << log.dest_host << ","
             << log.dest_port << ","
             << log.proxy_used << ","
             << log.method << ","
             << log.http_status << ","
             << log.bytes_sent << ","
             << log.bytes_received << ","
             << log.duration_ms << ","
             << log.rule_matched << ","
             << log.error << "\n";
    }

    return true;
}

TrafficSummary ConnectionMonitor::get_summary() const {
    TrafficSummary summary;
    summary.total_connections = total_connections_;
    summary.active_connections = active_count_;
    summary.failed_connections = failed_connections_;
    summary.total_bytes_sent = total_bytes_sent_;
    summary.total_bytes_received = total_bytes_received_;
    summary.current_send_rate = current_send_rate_;
    summary.current_recv_rate = current_recv_rate_;
    summary.dns_queries = dns_queries_;
    summary.dns_cache_hits = dns_cache_hits_;
    summary.uptime_start = uptime_start_;
    return summary;
}

void ConnectionMonitor::reset_stats() {
    total_connections_ = 0;
    failed_connections_ = 0;
    total_bytes_sent_ = 0;
    total_bytes_received_ = 0;
    dns_queries_ = 0;
    dns_cache_hits_ = 0;
    current_send_rate_ = 0;
    current_recv_rate_ = 0;
    uptime_start_ = time(nullptr);
}

void ConnectionMonitor::record_bytes_sent(uint64_t bytes) {
    total_bytes_sent_ += bytes;
}

void ConnectionMonitor::record_bytes_received(uint64_t bytes) {
    total_bytes_received_ += bytes;
}

void ConnectionMonitor::record_dns_query(bool cache_hit) {
    ++dns_queries_;
    if (cache_hit) ++dns_cache_hits_;
}

void ConnectionMonitor::update_rates() {
    DWORD now = GetTickCount();
    DWORD elapsed = now - prev_rate_time_;

    if (elapsed > 0) {
        double seconds = elapsed / 1000.0;
        uint64_t sent = total_bytes_sent_;
        uint64_t received = total_bytes_received_;

        current_send_rate_ = (sent - prev_bytes_sent_) / seconds;
        current_recv_rate_ = (received - prev_bytes_received_) / seconds;

        prev_bytes_sent_ = sent;
        prev_bytes_received_ = received;
        prev_rate_time_ = now;
    }
}

// ============================================================================
// System-wide TCP connection enumeration
// ============================================================================

static std::string get_pid_process_name(DWORD pid) {
    if (pid == 0) return "System Idle";
    if (pid == 4) return "System";

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return "PID:" + std::to_string(pid);

    char exe_path[MAX_PATH] = {};
    DWORD path_size = MAX_PATH;
    if (QueryFullProcessImageNameA(process, 0, exe_path, &path_size)) {
        CloseHandle(process);
        std::string full_path(exe_path);
        auto last_slash = full_path.find_last_of("\\/");
        if (last_slash != std::string::npos)
            return full_path.substr(last_slash + 1);
        return full_path;
    }

    CloseHandle(process);
    return "PID:" + std::to_string(pid);
}

static const char* tcp_state_str(DWORD state) {
    switch (state) {
    case MIB_TCP_STATE_CLOSED:     return "CLOSED";
    case MIB_TCP_STATE_LISTEN:     return "LISTEN";
    case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
    case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING:    return "CLOSING";
    case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
    default: return "UNKNOWN";
    }
}

std::vector<SystemTcpConnection> ConnectionMonitor::get_system_connections(
    uint16_t interceptor_http_port, uint16_t interceptor_socks_port) {

    std::vector<SystemTcpConnection> result;

    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                        TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return result;

    std::vector<char> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, TRUE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return result;

    auto* table = (MIB_TCPTABLE_OWNER_PID*)buf.data();

    // Cache for process names to avoid repeated lookups
    std::unordered_map<DWORD, std::string> name_cache;
    DWORD self_pid = GetCurrentProcessId();

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];

        // Skip our own process
        if (row.dwOwningPid == self_pid) continue;

        // Skip localhost connections (127.0.0.1 <-> 127.0.0.1)
        DWORD loopback = htonl(INADDR_LOOPBACK);
        if (row.dwLocalAddr == loopback || row.dwRemoteAddr == loopback) continue;

        // Skip LISTEN, TIME_WAIT, CLOSED for cleaner view
        if (row.dwState == MIB_TCP_STATE_LISTEN ||
            row.dwState == MIB_TCP_STATE_TIME_WAIT ||
            row.dwState == MIB_TCP_STATE_CLOSED)
            continue;

        SystemTcpConnection conn;
        conn.pid = row.dwOwningPid;

        // Process name with cache
        auto it = name_cache.find(conn.pid);
        if (it != name_cache.end()) {
            conn.app_name = it->second;
        } else {
            conn.app_name = get_pid_process_name(conn.pid);
            name_cache[conn.pid] = conn.app_name;
        }

        // Local address
        struct in_addr laddr;
        laddr.s_addr = row.dwLocalAddr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &laddr, ip, sizeof(ip));
        conn.local_addr = ip;
        conn.local_port = ntohs((uint16_t)row.dwLocalPort);

        // Remote address
        struct in_addr raddr;
        raddr.s_addr = row.dwRemoteAddr;
        inet_ntop(AF_INET, &raddr, ip, sizeof(ip));
        conn.remote_addr = ip;
        conn.remote_port = ntohs((uint16_t)row.dwRemotePort);

        // State
        conn.state = tcp_state_str(row.dwState);

        // Is this connection going through our interceptor?
        conn.is_proxied = false;
        if ((conn.remote_addr == "127.0.0.1" || conn.remote_addr == "0.0.0.0") &&
            (conn.remote_port == interceptor_http_port ||
             conn.remote_port == interceptor_socks_port) &&
            interceptor_http_port > 0) {
            conn.is_proxied = true;
        }

        result.push_back(conn);
        if (result.size() >= 500) break; // Limit to prevent UI freeze
    }

    return result;
}
