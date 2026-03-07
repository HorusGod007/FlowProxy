#include "net/local_server.h"
#include "net/socks.h"
#include "resources/resource.h"

#include <sstream>
#include <algorithm>

LocalProxyServer::LocalProxyServer(ProxyList& proxy_list)
    : proxy_list_(proxy_list) {}

LocalProxyServer::~LocalProxyServer() {
    stop();
}

bool LocalProxyServer::start(uint16_t port, RotationMode mode, HWND notify_hwnd) {
    if (running_) return false;

    rotation_mode_ = mode;
    port_ = port;

    if (!listen_socket_.create()) return false;
    if (!listen_socket_.bind_listen("127.0.0.1", port)) {
        listen_socket_.close();
        return false;
    }

    running_ = true;
    accept_thread_ = std::thread(&LocalProxyServer::accept_loop, this, notify_hwnd);
    return true;
}

void LocalProxyServer::stop() {
    running_ = false;
    listen_socket_.close(); // This unblocks accept()

    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
}

void LocalProxyServer::accept_loop(HWND notify_hwnd) {
    while (running_) {
        Socket client = listen_socket_.accept_client();
        if (!client.is_valid()) {
            if (!running_) break;
            continue;
        }

        // Handle each client in a detached thread
        std::thread(&LocalProxyServer::handle_client, this, std::move(client)).detach();
    }

    PostMessage(notify_hwnd, WM_SERVER_STATUS, 0, 0);
}

void LocalProxyServer::handle_client(Socket client) {
    client.set_timeout(30000);

    // Read the initial request
    char buf[8192];
    int n = client.recv_raw(buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = '\0';
    std::string request(buf, n);

    // Get next proxy from rotation
    Proxy* proxy = proxy_list_.next_proxy(rotation_mode_);
    if (!proxy) {
        // No proxy available, send error
        std::string error = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 18\r\n\r\nNo proxy available";
        client.send_all(error);
        return;
    }

    Proxy proxy_copy = *proxy; // Copy for thread safety

    std::string dest_host;
    uint16_t dest_port;

    if (request.substr(0, 7) == "CONNECT") {
        // HTTPS tunnel via CONNECT
        if (!parse_connect_request(request, dest_host, dest_port)) return;

        Socket remote;
        if (!remote.create()) return;
        remote.set_timeout(10000);

        if (!remote.connect(proxy_copy.host, proxy_copy.port)) return;

        bool connected = false;
        switch (proxy_copy.type) {
            case ProxyType::HTTP:
            case ProxyType::HTTPS: {
                // Forward CONNECT to upstream proxy
                std::string connect_req = "CONNECT " + dest_host + ":" + std::to_string(dest_port) + " HTTP/1.1\r\n";
                connect_req += "Host: " + dest_host + ":" + std::to_string(dest_port) + "\r\n\r\n";
                if (!remote.send_all(connect_req)) break;

                std::string resp = remote.recv_all(4096);
                connected = resp.find("200") != std::string::npos;
                break;
            }
            case ProxyType::SOCKS4:
                connected = socks4_connect(remote, dest_host, dest_port);
                break;
            case ProxyType::SOCKS5:
                connected = socks5_connect(remote, dest_host, dest_port, proxy_copy.username, proxy_copy.password);
                break;
            default:
                break;
        }

        if (!connected) return;

        // Send 200 Connection Established to client
        std::string established = "HTTP/1.1 200 Connection Established\r\n\r\n";
        if (!client.send_all(established)) return;

        // Tunnel bidirectional data
        tunnel_data(client, remote);
    } else {
        // Regular HTTP request
        std::string modified_request;
        if (!parse_http_request(request, dest_host, dest_port, modified_request)) return;

        Socket remote;
        if (!remote.create()) return;
        remote.set_timeout(10000);

        if (!remote.connect(proxy_copy.host, proxy_copy.port)) return;

        switch (proxy_copy.type) {
            case ProxyType::HTTP:
            case ProxyType::HTTPS:
                // Forward the full request to the HTTP proxy
                if (!remote.send_all(request)) return;
                break;

            case ProxyType::SOCKS4:
                if (!socks4_connect(remote, dest_host, dest_port)) return;
                if (!remote.send_all(modified_request)) return;
                break;

            case ProxyType::SOCKS5:
                if (!socks5_connect(remote, dest_host, dest_port, proxy_copy.username, proxy_copy.password)) return;
                if (!remote.send_all(modified_request)) return;
                break;

            default:
                return;
        }

        // Forward response back to client
        tunnel_data(client, remote);
    }
}

void LocalProxyServer::tunnel_data(Socket& client, Socket& remote) {
    fd_set fds;
    char buf[8192];

    while (running_) {
        FD_ZERO(&fds);
        FD_SET(client.handle(), &fds);
        FD_SET(remote.handle(), &fds);

        SOCKET max_fd = std::max(client.handle(), remote.handle()) + 1;

        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        int ready = select((int)max_fd, &fds, nullptr, nullptr, &tv);
        if (ready <= 0) break;

        if (FD_ISSET(client.handle(), &fds)) {
            int n = client.recv_raw(buf, sizeof(buf));
            if (n <= 0) break;
            if (!remote.send_raw(buf, n)) break;
        }

        if (FD_ISSET(remote.handle(), &fds)) {
            int n = remote.recv_raw(buf, sizeof(buf));
            if (n <= 0) break;
            if (!client.send_raw(buf, n)) break;
        }
    }
}

bool LocalProxyServer::parse_connect_request(const std::string& request, std::string& host, uint16_t& port) {
    // CONNECT host:port HTTP/1.x
    std::istringstream iss(request);
    std::string method, target, version;
    iss >> method >> target >> version;

    auto colon = target.rfind(':');
    if (colon == std::string::npos) return false;

    host = target.substr(0, colon);
    try {
        port = (uint16_t)std::stoi(target.substr(colon + 1));
    } catch (...) {
        return false;
    }
    return true;
}

bool LocalProxyServer::parse_http_request(const std::string& request, std::string& host, uint16_t& port,
                                          std::string& modified_request) {
    // GET http://host:port/path HTTP/1.x
    std::istringstream iss(request);
    std::string method, url, version;
    iss >> method >> url >> version;

    port = 80;

    // Remove http:// prefix
    std::string working = url;
    auto proto = working.find("://");
    if (proto != std::string::npos) {
        working = working.substr(proto + 3);
    }

    // Extract host:port
    auto slash = working.find('/');
    std::string host_port = (slash != std::string::npos) ? working.substr(0, slash) : working;
    std::string path = (slash != std::string::npos) ? working.substr(slash) : "/";

    auto colon = host_port.rfind(':');
    if (colon != std::string::npos) {
        host = host_port.substr(0, colon);
        try { port = (uint16_t)std::stoi(host_port.substr(colon + 1)); } catch (...) {}
    } else {
        host = host_port;
    }

    // Create modified request with relative URL (for SOCKS)
    modified_request = method + " " + path + " " + version + "\r\n";
    // Append remaining headers
    auto header_start = request.find("\r\n");
    if (header_start != std::string::npos) {
        modified_request += request.substr(header_start + 2);
    }

    return !host.empty();
}
