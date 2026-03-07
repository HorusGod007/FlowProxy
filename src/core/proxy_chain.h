#pragma once

#include "core/proxy.h"
#include "net/socket.h"
#include <vector>
#include <string>
#include <mutex>

// A proxy chain routes traffic through multiple proxies sequentially.
// Client -> Proxy1 -> Proxy2 -> ... -> ProxyN -> Destination
struct ProxyChain {
    std::string name;
    std::vector<int> proxy_indices;  // Indices into ProxyList
    bool enabled = true;
};

class ProxyChainManager {
public:
    ProxyChainManager() = default;

    // Chain management
    void add_chain(const ProxyChain& chain);
    void update_chain(size_t index, const ProxyChain& chain);
    void remove_chain(size_t index);
    void clear_chains();

    size_t chain_count() const;
    ProxyChain chain_at(size_t index) const;
    std::vector<ProxyChain>& chains() { return chains_; }
    const std::vector<ProxyChain>& chains() const { return chains_; }

    // Connect through a chain of proxies
    // Returns a connected socket tunneled through the entire chain to dest_host:dest_port
    bool connect_through_chain(Socket& final_socket, const ProxyChain& chain,
                               const std::vector<Proxy>& proxies,
                               const std::string& dest_host, uint16_t dest_port,
                               int timeout_ms = 10000);

    // Persistence
    bool save_to_file(const std::string& filepath) const;
    bool load_from_file(const std::string& filepath);

private:
    // Connect to next hop through current SOCKS5/HTTP proxy
    bool chain_hop_socks5(Socket& sock, const std::string& next_host, uint16_t next_port,
                          const std::string& username, const std::string& password);
    bool chain_hop_http(Socket& sock, const std::string& next_host, uint16_t next_port,
                        const Proxy& proxy);

    std::vector<ProxyChain> chains_;
    mutable std::mutex mutex_;
};
