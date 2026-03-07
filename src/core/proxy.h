#pragma once

#include <string>
#include <ctime>
#include <cstdint>

enum class ProxyType {
    HTTP = 0,
    HTTPS,
    SOCKS4,
    SOCKS5,
    COUNT
};

enum class ProxyStatus {
    Unknown = 0,
    Checking,
    Alive,
    Dead
};

enum class AnonymityLevel {
    Unknown = 0,
    Transparent,
    Anonymous,
    Elite
};

struct Proxy {
    std::string host;
    uint16_t port = 0;
    ProxyType type = ProxyType::HTTP;
    std::string username;
    std::string password;

    ProxyStatus status = ProxyStatus::Unknown;
    int latency_ms = -1;
    std::string country;
    AnonymityLevel anonymity = AnonymityLevel::Unknown;
    time_t last_checked = 0;

    std::string to_string() const;
    std::string address() const;
    bool has_auth() const;
};

const wchar_t* proxy_type_to_wstr(ProxyType type);
const char* proxy_type_to_str(ProxyType type);
const wchar_t* proxy_status_to_wstr(ProxyStatus status);
const wchar_t* anonymity_to_wstr(AnonymityLevel level);

ProxyType proxy_type_from_index(int index);
int proxy_type_to_index(ProxyType type);

std::wstring utf8_to_wide(const std::string& str);
std::string wide_to_utf8(const std::wstring& wstr);
