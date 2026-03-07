#include "net/socks.h"
#include <cstring>
#include <vector>

bool socks4_connect(Socket& sock, const std::string& dest_host, uint16_t dest_port,
                    const std::string& userid) {
    // Resolve hostname to IP
    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(dest_host.c_str(), nullptr, &hints, &result) != 0) {
        return false;
    }

    uint32_t ip = ((struct sockaddr_in*)result->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(result);

    // SOCKS4 request
    std::vector<char> request;
    request.push_back(0x04); // Version
    request.push_back(0x01); // CONNECT command
    request.push_back((char)((dest_port >> 8) & 0xFF)); // Port high
    request.push_back((char)(dest_port & 0xFF));        // Port low
    request.push_back((char)(ip & 0xFF));               // IP bytes
    request.push_back((char)((ip >> 8) & 0xFF));
    request.push_back((char)((ip >> 16) & 0xFF));
    request.push_back((char)((ip >> 24) & 0xFF));

    // User ID
    for (char c : userid) request.push_back(c);
    request.push_back(0x00); // Null terminator

    if (!sock.send_raw(request.data(), (int)request.size())) {
        return false;
    }

    // Read response (8 bytes)
    char response[8];
    int received = 0;
    while (received < 8) {
        int n = sock.recv_raw(response + received, 8 - received);
        if (n <= 0) return false;
        received += n;
    }

    // Check response: byte 0 = null, byte 1 = 0x5A means success
    return response[1] == 0x5A;
}

bool socks5_connect(Socket& sock, const std::string& dest_host, uint16_t dest_port,
                    const std::string& username, const std::string& password) {
    bool use_auth = !username.empty();

    // Greeting
    char greeting[4];
    greeting[0] = 0x05; // Version

    if (use_auth) {
        greeting[1] = 0x02; // 2 methods
        greeting[2] = 0x00; // No auth
        greeting[3] = 0x02; // Username/password
        if (!sock.send_raw(greeting, 4)) return false;
    } else {
        greeting[1] = 0x01; // 1 method
        greeting[2] = 0x00; // No auth
        if (!sock.send_raw(greeting, 3)) return false;
    }

    // Server choice
    char choice[2];
    int received = 0;
    while (received < 2) {
        int n = sock.recv_raw(choice + received, 2 - received);
        if (n <= 0) return false;
        received += n;
    }

    if (choice[0] != 0x05) return false;

    // Handle authentication
    if (choice[1] == 0x02) {
        // Username/password auth (RFC 1929)
        std::vector<char> auth;
        auth.push_back(0x01); // Sub-negotiation version
        auth.push_back((char)username.size());
        auth.insert(auth.end(), username.begin(), username.end());
        auth.push_back((char)password.size());
        auth.insert(auth.end(), password.begin(), password.end());

        if (!sock.send_raw(auth.data(), (int)auth.size())) return false;

        char auth_resp[2];
        received = 0;
        while (received < 2) {
            int n = sock.recv_raw(auth_resp + received, 2 - received);
            if (n <= 0) return false;
            received += n;
        }

        if (auth_resp[1] != 0x00) return false; // Auth failed
    } else if (choice[1] != 0x00) {
        return false; // No acceptable method
    }

    // Connect request
    std::vector<char> request;
    request.push_back(0x05); // Version
    request.push_back(0x01); // CONNECT
    request.push_back(0x00); // Reserved
    request.push_back(0x03); // Domain name type

    // Domain name
    request.push_back((char)dest_host.size());
    request.insert(request.end(), dest_host.begin(), dest_host.end());

    // Port
    request.push_back((char)((dest_port >> 8) & 0xFF));
    request.push_back((char)(dest_port & 0xFF));

    if (!sock.send_raw(request.data(), (int)request.size())) return false;

    // Read response header (at least 4 bytes)
    char resp[4];
    received = 0;
    while (received < 4) {
        int n = sock.recv_raw(resp + received, 4 - received);
        if (n <= 0) return false;
        received += n;
    }

    if (resp[0] != 0x05 || resp[1] != 0x00) return false; // Connection failed

    // Skip the bound address
    int skip_bytes = 0;
    if (resp[3] == 0x01) {
        skip_bytes = 4 + 2; // IPv4 + port
    } else if (resp[3] == 0x03) {
        // Domain name - need to read length byte first
        char len;
        if (sock.recv_raw(&len, 1) <= 0) return false;
        skip_bytes = (unsigned char)len + 2; // domain + port
    } else if (resp[3] == 0x04) {
        skip_bytes = 16 + 2; // IPv6 + port
    }

    // Read and discard remaining bytes
    std::vector<char> discard(skip_bytes);
    received = 0;
    while (received < skip_bytes) {
        int n = sock.recv_raw(discard.data() + received, skip_bytes - received);
        if (n <= 0) return false;
        received += n;
    }

    return true;
}
