#include "core/rules_engine.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

// ============================================================================
// ProxyRule matching
// ============================================================================

bool ProxyRule::matches(const std::string& app_name, const std::string& dest_host,
                        const std::string& dest_ip, uint16_t dest_port) const {
    if (!enabled) return false;

    switch (target) {
    case RuleTarget::Application:
        return match_glob(app_name, pattern);

    case RuleTarget::Domain:
        return match_domain(dest_host, pattern);

    case RuleTarget::IP:
        return match_cidr(dest_ip, pattern);

    case RuleTarget::Port:
        return match_port_range(dest_port, pattern);

    case RuleTarget::All:
        return true;
    }

    return false;
}

bool ProxyRule::match_glob(const std::string& text, const std::string& glob_pattern) const {
    // Simple glob matching supporting * and ?
    std::string lower_text = text;
    std::string lower_pat = glob_pattern;
    for (auto& c : lower_text) c = (char)tolower(c);
    for (auto& c : lower_pat) c = (char)tolower(c);

    size_t ti = 0, pi = 0;
    size_t star_pi = std::string::npos, star_ti = 0;

    while (ti < lower_text.size()) {
        if (pi < lower_pat.size() && (lower_pat[pi] == '?' || lower_pat[pi] == lower_text[ti])) {
            ++ti;
            ++pi;
        } else if (pi < lower_pat.size() && lower_pat[pi] == '*') {
            star_pi = pi++;
            star_ti = ti;
        } else if (star_pi != std::string::npos) {
            pi = star_pi + 1;
            ti = ++star_ti;
        } else {
            return false;
        }
    }

    while (pi < lower_pat.size() && lower_pat[pi] == '*') ++pi;
    return pi == lower_pat.size();
}

bool ProxyRule::match_domain(const std::string& hostname, const std::string& domain_pattern) const {
    // If pattern contains wildcards, use glob matching directly
    if (domain_pattern.find('*') != std::string::npos ||
        domain_pattern.find('?') != std::string::npos) {
        return match_glob(hostname, domain_pattern);
    }

    // Plain domain pattern: match exact domain AND all subdomains
    // e.g. "netflix.com" matches "netflix.com", "www.netflix.com", "api.netflix.com"
    std::string lower_host = hostname;
    std::string lower_pat = domain_pattern;
    for (auto& c : lower_host) c = (char)tolower(c);
    for (auto& c : lower_pat) c = (char)tolower(c);

    // Exact match
    if (lower_host == lower_pat) return true;

    // Subdomain match: hostname ends with ".pattern"
    if (lower_host.size() > lower_pat.size() + 1) {
        size_t offset = lower_host.size() - lower_pat.size();
        if (lower_host[offset - 1] == '.' &&
            lower_host.compare(offset, lower_pat.size(), lower_pat) == 0) {
            return true;
        }
    }

    return false;
}

bool ProxyRule::match_cidr(const std::string& ip, const std::string& cidr) const {
    // Parse CIDR notation: "192.168.1.0/24" or plain IP "192.168.1.1"
    std::string net_str = cidr;
    int prefix_len = 32;

    auto slash = cidr.find('/');
    if (slash != std::string::npos) {
        net_str = cidr.substr(0, slash);
        try { prefix_len = std::stoi(cidr.substr(slash + 1)); } catch (...) { return false; }
    }

    struct in_addr ip_addr, net_addr;
    if (inet_pton(AF_INET, ip.c_str(), &ip_addr) != 1) return false;
    if (inet_pton(AF_INET, net_str.c_str(), &net_addr) != 1) return false;

    uint32_t mask = (prefix_len == 0) ? 0 : (~0u << (32 - prefix_len));
    mask = htonl(mask);

    return (ip_addr.s_addr & mask) == (net_addr.s_addr & mask);
}

bool ProxyRule::match_port_range(uint16_t port, const std::string& range) const {
    // Support: "80", "80-443", "80,443,8080", "1-1024"
    std::istringstream iss(range);
    std::string token;

    while (std::getline(iss, token, ',')) {
        // Trim
        while (!token.empty() && token[0] == ' ') token.erase(0, 1);
        while (!token.empty() && token.back() == ' ') token.pop_back();

        auto dash = token.find('-');
        if (dash != std::string::npos) {
            try {
                uint16_t low = (uint16_t)std::stoi(token.substr(0, dash));
                uint16_t high = (uint16_t)std::stoi(token.substr(dash + 1));
                if (port >= low && port <= high) return true;
            } catch (...) {}
        } else {
            try {
                if (port == (uint16_t)std::stoi(token)) return true;
            } catch (...) {}
        }
    }

    return false;
}

// ============================================================================
// RulesEngine
// ============================================================================

void RulesEngine::add_rule(const ProxyRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.push_back(rule);
    // Sort by priority
    std::stable_sort(rules_.begin(), rules_.end(),
        [](const ProxyRule& a, const ProxyRule& b) { return a.priority < b.priority; });
}

void RulesEngine::update_rule(size_t index, const ProxyRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index < rules_.size()) {
        rules_[index] = rule;
    }
}

void RulesEngine::remove_rule(size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index < rules_.size()) {
        rules_.erase(rules_.begin() + (ptrdiff_t)index);
    }
}

void RulesEngine::move_rule_up(size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index > 0 && index < rules_.size()) {
        std::swap(rules_[index], rules_[index - 1]);
    }
}

void RulesEngine::move_rule_down(size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index + 1 < rules_.size()) {
        std::swap(rules_[index], rules_[index + 1]);
    }
}

void RulesEngine::clear_rules() {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.clear();
}

size_t RulesEngine::rule_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.size();
}

bool RulesEngine::has_ip_target_rules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& r : rules_)
        if (r.enabled && r.target == RuleTarget::IP) return true;
    return false;
}

ProxyRule RulesEngine::rule_at(size_t index) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_[index];
}

bool RulesEngine::evaluate(const std::string& app_name, const std::string& dest_host,
                            const std::string& dest_ip, uint16_t dest_port,
                            ProxyRule& result) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& rule : rules_) {
        if (rule.matches(app_name, dest_host, dest_ip, dest_port)) {
            result = rule; // Copy out while still holding lock
            return true;
        }
    }

    return false; // No matching rule
}

bool RulesEngine::save_to_file(const std::string& filepath) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ofstream file(filepath);
    if (!file.is_open()) return false;

    for (const auto& rule : rules_) {
        file << (rule.enabled ? "1" : "0") << "|"
             << rule.name << "|"
             << (int)rule.target << "|"
             << rule.pattern << "|"
             << (int)rule.action << "|"
             << rule.proxy_index << "|"
             << rule.chain_index << "|"
             << rule.priority << "\n";
    }

    return true;
}

bool RulesEngine::load_from_file(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ifstream file(filepath);
    if (!file.is_open()) return false;

    rules_.clear();
    std::string line;

    while (std::getline(file, line)) {
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string token;
        ProxyRule rule;

        if (!std::getline(iss, token, '|')) continue;
        rule.enabled = (token == "1");

        if (!std::getline(iss, rule.name, '|')) continue;

        if (!std::getline(iss, token, '|')) continue;
        rule.target = (RuleTarget)std::stoi(token);

        if (!std::getline(iss, rule.pattern, '|')) continue;

        if (!std::getline(iss, token, '|')) continue;
        rule.action = (RuleAction)std::stoi(token);

        if (!std::getline(iss, token, '|')) continue;
        rule.proxy_index = std::stoi(token);

        if (!std::getline(iss, token, '|')) continue;
        rule.chain_index = std::stoi(token);

        if (!std::getline(iss, token, '|')) continue;
        rule.priority = std::stoi(token);

        rules_.push_back(rule);
    }

    return true;
}
