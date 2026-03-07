#pragma once

#include "core/proxy.h"
#include <vector>
#include <string>

class ProxyImporter {
public:
    // Import from file - supports formats:
    // ip:port
    // ip:port:user:pass
    // type://ip:port
    // type://user:pass@ip:port
    static std::vector<Proxy> import_from_file(const std::string& filepath, ProxyType default_type = ProxyType::HTTP);

    // Import from string (same formats)
    static std::vector<Proxy> import_from_string(const std::string& text, ProxyType default_type = ProxyType::HTTP);

    // Export to file
    static bool export_to_file(const std::string& filepath, const std::vector<Proxy>& proxies, bool include_type = true);

    // Export to CSV
    static bool export_to_csv(const std::string& filepath, const std::vector<Proxy>& proxies);

private:
    static Proxy parse_line(const std::string& line, ProxyType default_type);
    static std::string trim(const std::string& s);
};
