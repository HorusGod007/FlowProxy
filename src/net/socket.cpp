#include "net/socket.h"

#pragma comment(lib, "ws2_32.lib")

Socket::Socket() = default;

Socket::~Socket() {
    close();
}

Socket::Socket(Socket&& other) noexcept : sock_(other.sock_) {
    other.sock_ = INVALID_SOCKET;
}

Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) {
        close();
        sock_ = other.sock_;
        other.sock_ = INVALID_SOCKET;
    }
    return *this;
}

bool Socket::init_winsock() {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
}

void Socket::cleanup_winsock() {
    WSACleanup();
}

bool Socket::create() {
    close();
    sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    return sock_ != INVALID_SOCKET;
}

bool Socket::connect(const std::string& host, uint16_t port) {
    if (sock_ == INVALID_SOCKET) return false;

    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result) != 0) {
        return false;
    }

    bool connected = false;
    for (auto ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        if (::connect(sock_, ptr->ai_addr, (int)ptr->ai_addrlen) == 0) {
            connected = true;
            break;
        }
    }

    freeaddrinfo(result);
    return connected;
}

bool Socket::bind_listen(const std::string& host, uint16_t port, int backlog) {
    if (sock_ == INVALID_SOCKET) return false;

    // Allow reuse
    int opt = 1;
    setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (host.empty() || host == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    }

    if (::bind(sock_, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        return false;
    }

    return ::listen(sock_, backlog) == 0;
}

Socket Socket::accept_client() {
    Socket client;
    struct sockaddr_in client_addr = {};
    int addr_len = sizeof(client_addr);
    SOCKET s = ::accept(sock_, (struct sockaddr*)&client_addr, &addr_len);
    if (s != INVALID_SOCKET) {
        client.sock_ = s;
    }
    return client;
}

void Socket::close() {
    if (sock_ != INVALID_SOCKET) {
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }
}

bool Socket::send_all(const std::string& data) {
    return send_all(data.c_str(), (int)data.size());
}

bool Socket::send_all(const char* data, int len) {
    int sent = 0;
    while (sent < len) {
        int n = ::send(sock_, data + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

std::string Socket::recv_all(int max_bytes) {
    std::string result;
    char buf[4096];
    int total = 0;

    while (total < max_bytes) {
        int to_read = std::min((int)sizeof(buf), max_bytes - total);
        int n = ::recv(sock_, buf, to_read, 0);
        if (n <= 0) break;
        result.append(buf, n);
        total += n;
    }

    return result;
}

int Socket::recv_raw(char* buf, int len) {
    return ::recv(sock_, buf, len, 0);
}

bool Socket::send_raw(const char* buf, int len) {
    return send_all(buf, len);
}

void Socket::set_timeout(int ms) {
    if (sock_ == INVALID_SOCKET) return;
    DWORD timeout = (DWORD)ms;
    setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock_, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
}
