#include "core/checker.h"
#include "net/socket.h"
#include "net/socks.h"
#include "resources/resource.h"

#include <chrono>
#include <sstream>

ProxyChecker::ProxyChecker() = default;

ProxyChecker::~ProxyChecker() {
    stop();
}

void ProxyChecker::check_all(ProxyList& list, HWND notify_hwnd) {
    if (running_) return;

    stop_requested_ = false;
    checked_count_ = 0;
    total_count_ = (int)list.size();
    running_ = true;

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        for (size_t i = 0; i < list.size(); ++i) {
            work_queue_.push(i);
            list.at(i).status = ProxyStatus::Unknown;
        }
    }

    int threads = std::min(config_.thread_count, (int)list.size());
    for (int i = 0; i < threads; ++i) {
        workers_.emplace_back(&ProxyChecker::worker_thread, this, std::ref(list), notify_hwnd);
    }
}

void ProxyChecker::check_selected(ProxyList& list, const std::vector<size_t>& indices, HWND notify_hwnd) {
    if (running_) return;

    stop_requested_ = false;
    checked_count_ = 0;
    total_count_ = (int)indices.size();
    running_ = true;

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        for (size_t idx : indices) {
            work_queue_.push(idx);
            list.at(idx).status = ProxyStatus::Unknown;
        }
    }

    int threads = std::min(config_.thread_count, (int)indices.size());
    for (int i = 0; i < threads; ++i) {
        workers_.emplace_back(&ProxyChecker::worker_thread, this, std::ref(list), notify_hwnd);
    }
}

void ProxyChecker::stop() {
    stop_requested_ = true;
    queue_cv_.notify_all();

    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();

    // Clear remaining queue
    std::lock_guard<std::mutex> lock(queue_mutex_);
    while (!work_queue_.empty()) work_queue_.pop();

    running_ = false;
}

void ProxyChecker::worker_thread(ProxyList& list, HWND notify_hwnd) {
    while (!stop_requested_) {
        size_t index;
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (work_queue_.empty()) break;
            index = work_queue_.front();
            work_queue_.pop();
        }

        {
            std::lock_guard<std::mutex> lock(list.mutex());
            if (index < list.size()) {
                list.at(index).status = ProxyStatus::Checking;
            }
        }

        // Notify UI of status change
        PostMessage(notify_hwnd, WM_PROXY_CHECK_UPDATE, (WPARAM)index, 0);

        Proxy proxy_copy;
        {
            std::lock_guard<std::mutex> lock(list.mutex());
            if (index < list.size()) {
                proxy_copy = list.at(index);
            }
        }

        bool alive = check_single_proxy(proxy_copy);

        {
            std::lock_guard<std::mutex> lock(list.mutex());
            if (index < list.size()) {
                list.at(index).status = alive ? ProxyStatus::Alive : ProxyStatus::Dead;
                list.at(index).latency_ms = proxy_copy.latency_ms;
                list.at(index).anonymity = proxy_copy.anonymity;
                list.at(index).last_checked = time(nullptr);
            }
        }

        ++checked_count_;
        PostMessage(notify_hwnd, WM_PROXY_CHECK_UPDATE, (WPARAM)index, 0);
    }

    // Check if all workers done
    bool all_done = false;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        all_done = work_queue_.empty();
    }

    if (all_done && checked_count_ >= total_count_) {
        running_ = false;
        PostMessage(notify_hwnd, WM_PROXY_CHECK_DONE, 0, 0);
    }
}

bool ProxyChecker::check_single_proxy(Proxy& proxy) {
    switch (proxy.type) {
        case ProxyType::HTTP:
        case ProxyType::HTTPS:
            return check_http_proxy(proxy, proxy.latency_ms, proxy.anonymity);
        case ProxyType::SOCKS4:
        case ProxyType::SOCKS5:
            return check_socks_proxy(proxy, proxy.latency_ms, proxy.anonymity);
        default:
            return false;
    }
}

bool ProxyChecker::check_http_proxy(const Proxy& proxy, int& latency, AnonymityLevel& anon) {
    Socket sock;
    if (!sock.create()) return false;
    sock.set_timeout(config_.timeout_ms);

    auto start = std::chrono::steady_clock::now();

    if (!sock.connect(proxy.host, proxy.port)) return false;

    // Send HTTP request through proxy
    std::string request = "GET " + config_.test_url + " HTTP/1.1\r\n";
    request += "Host: httpbin.org\r\n";
    request += "Connection: close\r\n";

    if (proxy.has_auth()) {
        // Basic auth encoding (simple base64)
        std::string auth = proxy.username + ":" + proxy.password;
        // Simple base64 encode
        static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string encoded;
        int val = 0, valb = -6;
        for (unsigned char c : auth) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                encoded.push_back(b64[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) encoded.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
        while (encoded.size() % 4) encoded.push_back('=');

        request += "Proxy-Authorization: Basic " + encoded + "\r\n";
    }

    request += "\r\n";

    if (!sock.send_all(request)) return false;

    std::string response = sock.recv_all(4096);

    auto end = std::chrono::steady_clock::now();
    latency = (int)std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (response.empty()) return false;

    // Check for HTTP 200
    if (response.find("200") == std::string::npos) return false;

    // Detect anonymity
    anon = AnonymityLevel::Elite; // Assume elite unless headers leak info

    // Check if proxy headers are present
    std::string lower_resp = response;
    for (auto& c : lower_resp) c = (char)tolower(c);

    if (lower_resp.find("x-forwarded-for") != std::string::npos ||
        lower_resp.find("via") != std::string::npos) {
        anon = AnonymityLevel::Anonymous;
    }

    // If original IP appears (would need external detection), mark transparent
    // For now, this is a simplified check

    return true;
}

bool ProxyChecker::check_socks_proxy(const Proxy& proxy, int& latency, AnonymityLevel& anon) {
    Socket sock;
    if (!sock.create()) return false;
    sock.set_timeout(config_.timeout_ms);

    auto start = std::chrono::steady_clock::now();

    if (!sock.connect(proxy.host, proxy.port)) return false;

    bool connected = false;
    if (proxy.type == ProxyType::SOCKS4) {
        connected = socks4_connect(sock, "httpbin.org", 80);
    } else {
        connected = socks5_connect(sock, "httpbin.org", 80, proxy.username, proxy.password);
    }

    if (!connected) return false;

    // Send HTTP request through established tunnel
    std::string request = "GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
    if (!sock.send_all(request)) return false;

    std::string response = sock.recv_all(4096);

    auto end = std::chrono::steady_clock::now();
    latency = (int)std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (response.empty()) return false;
    if (response.find("200") == std::string::npos) return false;

    anon = AnonymityLevel::Elite; // SOCKS proxies are typically elite
    return true;
}
