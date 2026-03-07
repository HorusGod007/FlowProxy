#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <string>
#include <cstdint>

class Socket {
public:
    Socket();
    ~Socket();

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;

    bool create();
    bool connect(const std::string& host, uint16_t port);
    bool bind_listen(const std::string& host, uint16_t port, int backlog = SOMAXCONN);
    Socket accept_client();
    void close();

    bool send_all(const std::string& data);
    bool send_all(const char* data, int len);
    std::string recv_all(int max_bytes = 65536);
    int recv_raw(char* buf, int len);
    bool send_raw(const char* buf, int len);

    void set_timeout(int ms);
    bool is_valid() const { return sock_ != INVALID_SOCKET; }
    SOCKET handle() const { return sock_; }

    // WinSock init/cleanup (call once)
    static bool init_winsock();
    static void cleanup_winsock();

private:
    SOCKET sock_ = INVALID_SOCKET;
};
