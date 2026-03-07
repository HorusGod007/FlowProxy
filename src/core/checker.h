#pragma once

#include "core/proxy.h"
#include "core/proxy_list.h"
#include <thread>
#include <atomic>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

struct CheckerConfig {
    int thread_count = 10;
    int timeout_ms = 5000;
    std::string test_url = "http://httpbin.org/ip";
};

class ProxyChecker {
public:
    ProxyChecker();
    ~ProxyChecker();

    void set_config(const CheckerConfig& config) { config_ = config; }
    const CheckerConfig& config() const { return config_; }

    // Start checking all or selected proxies
    void check_all(ProxyList& list, HWND notify_hwnd);
    void check_selected(ProxyList& list, const std::vector<size_t>& indices, HWND notify_hwnd);
    void stop();

    bool is_running() const { return running_; }
    int checked_count() const { return checked_count_; }
    int total_count() const { return total_count_; }

    bool check_single_proxy(Proxy& proxy);

private:
    void worker_thread(ProxyList& list, HWND notify_hwnd);
    bool check_http_proxy(const Proxy& proxy, int& latency, AnonymityLevel& anon);
    bool check_socks_proxy(const Proxy& proxy, int& latency, AnonymityLevel& anon);

    CheckerConfig config_;
    std::vector<std::thread> workers_;
    std::queue<size_t> work_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::atomic<int> checked_count_{0};
    std::atomic<int> total_count_{0};
};
