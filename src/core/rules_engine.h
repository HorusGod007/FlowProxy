#pragma once

#include "core/proxy.h"
#include <string>
#include <vector>
#include <mutex>
#include <regex>

// Action to take when a rule matches
enum class RuleAction {
    UseProxy = 0,       // Route through specific proxy or chain
    Direct,             // Bypass proxy, connect directly
    Block,              // Block the connection
    UseChain            // Route through a proxy chain
};

// Match target type
enum class RuleTarget {
    Application = 0,    // Match by executable name (e.g. "chrome.exe")
    Domain,             // Match by destination domain (e.g. "*.google.com")
    IP,                 // Match by destination IP (e.g. "192.168.1.0/24")
    Port,               // Match by destination port
    All                 // Match everything (default/fallback rule)
};

struct ProxyRule {
    bool enabled = true;
    std::string name;               // Display name
    RuleTarget target = RuleTarget::Application;
    std::string pattern;            // Match pattern (exe name, domain glob, IP/CIDR, port range)
    RuleAction action = RuleAction::UseProxy;
    int proxy_index = -1;           // -1 = use rotation, >=0 = specific proxy
    int chain_index = -1;           // Index into chain list
    int priority = 100;             // Lower = higher priority

    bool matches(const std::string& app_name, const std::string& dest_host,
                 const std::string& dest_ip, uint16_t dest_port) const;

private:
    bool match_glob(const std::string& text, const std::string& glob_pattern) const;
    bool match_cidr(const std::string& ip, const std::string& cidr) const;
    bool match_port_range(uint16_t port, const std::string& range) const;
};

class RulesEngine {
public:
    RulesEngine() = default;

    // Rule management
    void add_rule(const ProxyRule& rule);
    void update_rule(size_t index, const ProxyRule& rule);
    void remove_rule(size_t index);
    void move_rule_up(size_t index);
    void move_rule_down(size_t index);
    void clear_rules();

    size_t rule_count() const;
    bool has_ip_target_rules() const;
    ProxyRule rule_at(size_t index) const;
    std::vector<ProxyRule>& rules() { return rules_; }
    const std::vector<ProxyRule>& rules() const { return rules_; }

    // Evaluate rules for a connection - returns true if a rule matched, copies it to 'result'
    bool evaluate(const std::string& app_name, const std::string& dest_host,
                  const std::string& dest_ip, uint16_t dest_port,
                  ProxyRule& result) const;

    // Persistence
    bool save_to_file(const std::string& filepath) const;
    bool load_from_file(const std::string& filepath);

private:
    std::vector<ProxyRule> rules_;
    mutable std::mutex mutex_;
};
