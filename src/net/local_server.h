#pragma once

#include "core/proxy_list.h"
#include "net/socket.h"
#include <thread>
#include <atomic>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

class LocalProxyServer {
public:
    LocalProxyServer(ProxyList& proxy_list);
    ~LocalProxyServer();

    bool start(uint16_t port, RotationMode mode, HWND notify_hwnd);
    void stop();
    bool is_running() const { return running_; }
    uint16_t port() const { return port_; }

private:
    void accept_loop(HWND notify_hwnd);
    void handle_client(Socket client);
    void tunnel_data(Socket& client, Socket& remote);

    bool parse_connect_request(const std::string& request, std::string& host, uint16_t& port);
    bool parse_http_request(const std::string& request, std::string& host, uint16_t& port, std::string& modified_request);

    ProxyList& proxy_list_;
    RotationMode rotation_mode_;
    Socket listen_socket_;
    std::thread accept_thread_;
    std::atomic<bool> running_{false};
    uint16_t port_ = 0;
};
