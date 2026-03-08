#pragma once

#include "core/proxy.h"
#include <string>
#include <vector>
#include <mutex>

// Action to take when a rule matches
enum class RuleAction {
    UseProxy = 0,       // Route through specific proxy or chain
    Direct,             // Bypass proxy, connect directly
    Block,              // Block the connection
    UseChain            // Route through a proxy chain
};

struct ProxyRule {
    bool enabled = true;
    std::string name;               // Display name
    std::string apps;               // Semicolon-separated exe patterns (empty = any app)
    std::string hosts;              // Semicolon-separated domain/IP patterns (empty = any host)
    std::string ports;              // Port ranges e.g. "80,443,1-1024" (empty = any port)
    RuleAction action = RuleAction::UseProxy;
    int proxy_index = -1;           // -1 = use rotation, >=0 = specific proxy
    int chain_index = -1;           // Index into chain list

    // All non-empty fields must match (AND). Empty field = match anything.
    bool matches(const std::string& app_name, const std::string& dest_host,
                 const std::string& dest_ip, uint16_t dest_port) const;

    bool is_catch_all() const { return apps.empty() && hosts.empty() && ports.empty(); }

private:
    bool match_any_app(const std::string& app_name) const;
    bool match_any_host(const std::string& dest_host, const std::string& dest_ip) const;
    bool match_any_port(uint16_t dest_port) const;

    bool match_glob(const std::string& text, const std::string& glob_pattern) const;
    bool match_domain(const std::string& hostname, const std::string& domain_pattern) const;
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
    bool needs_dns_resolution() const;
    ProxyRule rule_at(size_t index) const;
    std::vector<ProxyRule>& rules() { return rules_; }
    const std::vector<ProxyRule>& rules() const { return rules_; }

    // Evaluate rules - specific rules checked before catch-all rules
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
