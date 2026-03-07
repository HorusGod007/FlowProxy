#include "core/importer.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

std::string ProxyImporter::trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

Proxy ProxyImporter::parse_line(const std::string& line, ProxyType default_type) {
    Proxy proxy;
    proxy.type = default_type;

    std::string trimmed = trim(line);
    if (trimmed.empty() || trimmed[0] == '#') {
        return proxy; // Skip comments and empty lines
    }

    std::string working = trimmed;

    // Check for protocol prefix
    auto proto_end = working.find("://");
    if (proto_end != std::string::npos) {
        std::string proto = working.substr(0, proto_end);
        for (auto& c : proto) c = (char)tolower(c);

        if (proto == "http") proxy.type = ProxyType::HTTP;
        else if (proto == "https") proxy.type = ProxyType::HTTPS;
        else if (proto == "socks4") proxy.type = ProxyType::SOCKS4;
        else if (proto == "socks5") proxy.type = ProxyType::SOCKS5;

        working = working.substr(proto_end + 3);
    }

    // Check for user:pass@host:port format
    auto at_pos = working.find('@');
    if (at_pos != std::string::npos) {
        std::string auth = working.substr(0, at_pos);
        working = working.substr(at_pos + 1);

        auto colon = auth.find(':');
        if (colon != std::string::npos) {
            proxy.username = auth.substr(0, colon);
            proxy.password = auth.substr(colon + 1);
        } else {
            proxy.username = auth;
        }
    }

    // Parse host:port[:user:pass]
    std::vector<std::string> parts;
    std::istringstream iss(working);
    std::string part;
    while (std::getline(iss, part, ':')) {
        parts.push_back(part);
    }

    if (parts.size() >= 2) {
        proxy.host = parts[0];
        try {
            proxy.port = (uint16_t)std::stoi(parts[1]);
        } catch (...) {
            proxy.port = 0;
        }

        // user:pass after host:port
        if (parts.size() >= 4 && proxy.username.empty()) {
            proxy.username = parts[2];
            proxy.password = parts[3];
        }
    }

    return proxy;
}

std::vector<Proxy> ProxyImporter::import_from_file(const std::string& filepath, ProxyType default_type) {
    std::vector<Proxy> result;
    std::ifstream file(filepath);
    if (!file.is_open()) return result;

    std::string line;
    while (std::getline(file, line)) {
        Proxy p = parse_line(line, default_type);
        if (!p.host.empty() && p.port > 0) {
            result.push_back(p);
        }
    }

    return result;
}

std::vector<Proxy> ProxyImporter::import_from_string(const std::string& text, ProxyType default_type) {
    std::vector<Proxy> result;
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        Proxy p = parse_line(line, default_type);
        if (!p.host.empty() && p.port > 0) {
            result.push_back(p);
        }
    }
    return result;
}

bool ProxyImporter::export_to_file(const std::string& filepath, const std::vector<Proxy>& proxies, bool include_type) {
    std::ofstream file(filepath);
    if (!file.is_open()) return false;

    for (const auto& p : proxies) {
        if (include_type) {
            const char* type_str = "http";
            switch (p.type) {
                case ProxyType::HTTP:   type_str = "http"; break;
                case ProxyType::HTTPS:  type_str = "https"; break;
                case ProxyType::SOCKS4: type_str = "socks4"; break;
                case ProxyType::SOCKS5: type_str = "socks5"; break;
                default: break;
            }
            file << type_str << "://";
        }

        if (p.has_auth()) {
            file << p.username << ":" << p.password << "@";
        }
        file << p.host << ":" << p.port << "\n";
    }

    return true;
}

bool ProxyImporter::export_to_csv(const std::string& filepath, const std::vector<Proxy>& proxies) {
    std::ofstream file(filepath);
    if (!file.is_open()) return false;

    file << "Host,Port,Type,Username,Password,Status,Latency(ms),Anonymity,Country\n";

    for (const auto& p : proxies) {
        const char* type_str = "HTTP";
        switch (p.type) {
            case ProxyType::HTTP:   type_str = "HTTP"; break;
            case ProxyType::HTTPS:  type_str = "HTTPS"; break;
            case ProxyType::SOCKS4: type_str = "SOCKS4"; break;
            case ProxyType::SOCKS5: type_str = "SOCKS5"; break;
            default: break;
        }

        const char* status_str = "Unknown";
        switch (p.status) {
            case ProxyStatus::Unknown: status_str = "Unknown"; break;
            case ProxyStatus::Alive:   status_str = "Alive"; break;
            case ProxyStatus::Dead:    status_str = "Dead"; break;
            default: break;
        }

        const char* anon_str = "Unknown";
        switch (p.anonymity) {
            case AnonymityLevel::Unknown:     anon_str = "Unknown"; break;
            case AnonymityLevel::Transparent: anon_str = "Transparent"; break;
            case AnonymityLevel::Anonymous:   anon_str = "Anonymous"; break;
            case AnonymityLevel::Elite:       anon_str = "Elite"; break;
        }

        file << p.host << ","
             << p.port << ","
             << type_str << ","
             << p.username << ","
             << p.password << ","
             << status_str << ","
             << p.latency_ms << ","
             << anon_str << ","
             << p.country << "\n";
    }

    return true;
}
