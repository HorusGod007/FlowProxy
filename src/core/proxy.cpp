#include "core/proxy.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

std::string Proxy::to_string() const {
    std::string result = host + ":" + std::to_string(port);
    if (has_auth()) {
        result += ":" + username + ":" + password;
    }
    return result;
}

std::string Proxy::address() const {
    return host + ":" + std::to_string(port);
}

bool Proxy::has_auth() const {
    return !username.empty();
}

const wchar_t* proxy_type_to_wstr(ProxyType type) {
    switch (type) {
        case ProxyType::HTTP:   return L"HTTP";
        case ProxyType::HTTPS:  return L"HTTPS";
        case ProxyType::SOCKS4: return L"SOCKS4";
        case ProxyType::SOCKS5: return L"SOCKS5";
        default:                return L"Unknown";
    }
}

const char* proxy_type_to_str(ProxyType type) {
    switch (type) {
        case ProxyType::HTTP:   return "HTTP";
        case ProxyType::HTTPS:  return "HTTPS";
        case ProxyType::SOCKS4: return "SOCKS4";
        case ProxyType::SOCKS5: return "SOCKS5";
        default:                return "Unknown";
    }
}

const wchar_t* proxy_status_to_wstr(ProxyStatus status) {
    switch (status) {
        case ProxyStatus::Unknown:  return L"Unknown";
        case ProxyStatus::Checking: return L"Checking...";
        case ProxyStatus::Alive:    return L"Alive";
        case ProxyStatus::Dead:     return L"Dead";
        default:                    return L"Unknown";
    }
}

const wchar_t* anonymity_to_wstr(AnonymityLevel level) {
    switch (level) {
        case AnonymityLevel::Unknown:     return L"Unknown";
        case AnonymityLevel::Transparent: return L"Transparent";
        case AnonymityLevel::Anonymous:   return L"Anonymous";
        case AnonymityLevel::Elite:       return L"Elite";
        default:                          return L"Unknown";
    }
}

ProxyType proxy_type_from_index(int index) {
    switch (index) {
        case 0: return ProxyType::HTTP;
        case 1: return ProxyType::HTTPS;
        case 2: return ProxyType::SOCKS4;
        case 3: return ProxyType::SOCKS5;
        default: return ProxyType::HTTP;
    }
}

int proxy_type_to_index(ProxyType type) {
    return static_cast<int>(type);
}

std::wstring utf8_to_wide(const std::string& str) {
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
    std::wstring result(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &result[0], size);
    return result;
}

std::string wide_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &result[0], size, nullptr, nullptr);
    return result;
}
