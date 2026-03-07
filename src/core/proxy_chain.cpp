#include "core/proxy_chain.h"
#include "net/socks.h"

#include <fstream>
#include <sstream>

void ProxyChainManager::add_chain(const ProxyChain& chain) {
    std::lock_guard<std::mutex> lock(mutex_);
    chains_.push_back(chain);
}

void ProxyChainManager::update_chain(size_t index, const ProxyChain& chain) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index < chains_.size()) {
        chains_[index] = chain;
    }
}

void ProxyChainManager::remove_chain(size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index < chains_.size()) {
        chains_.erase(chains_.begin() + (ptrdiff_t)index);
    }
}

void ProxyChainManager::clear_chains() {
    std::lock_guard<std::mutex> lock(mutex_);
    chains_.clear();
}

size_t ProxyChainManager::chain_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return chains_.size();
}

ProxyChain ProxyChainManager::chain_at(size_t index) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return chains_[index];
}

bool ProxyChainManager::connect_through_chain(Socket& final_socket, const ProxyChain& chain,
                                               const std::vector<Proxy>& proxies,
                                               const std::string& dest_host, uint16_t dest_port,
                                               int timeout_ms) {
    if (chain.proxy_indices.empty()) return false;

    // Validate all indices
    for (int idx : chain.proxy_indices) {
        if (idx < 0 || (size_t)idx >= proxies.size()) return false;
    }

    // Step 1: Connect to the first proxy in the chain
    const Proxy& first = proxies[chain.proxy_indices[0]];
    if (!final_socket.create()) return false;
    final_socket.set_timeout(timeout_ms);

    if (!final_socket.connect(first.host, first.port)) return false;

    // Step 2: For each subsequent proxy, tunnel through the current one
    for (size_t i = 1; i < chain.proxy_indices.size(); ++i) {
        const Proxy& current = proxies[chain.proxy_indices[i - 1]];
        const Proxy& next = proxies[chain.proxy_indices[i]];

        // Use current proxy to connect to next proxy
        bool ok = false;
        switch (current.type) {
        case ProxyType::SOCKS5:
            ok = chain_hop_socks5(final_socket, next.host, next.port,
                                  current.username, current.password);
            break;
        case ProxyType::SOCKS4:
            ok = socks4_connect(final_socket, next.host, next.port);
            break;
        case ProxyType::HTTP:
        case ProxyType::HTTPS:
            ok = chain_hop_http(final_socket, next.host, next.port, current);
            break;
        default:
            break;
        }

        if (!ok) return false;
    }

    // Step 3: Through the last proxy, connect to the final destination
    const Proxy& last = proxies[chain.proxy_indices.back()];
    switch (last.type) {
    case ProxyType::SOCKS5:
        return socks5_connect(final_socket, dest_host, dest_port,
                              last.username, last.password);
    case ProxyType::SOCKS4:
        return socks4_connect(final_socket, dest_host, dest_port);
    case ProxyType::HTTP:
    case ProxyType::HTTPS:
        return chain_hop_http(final_socket, dest_host, dest_port, last);
    default:
        return false;
    }
}

bool ProxyChainManager::chain_hop_socks5(Socket& sock, const std::string& next_host, uint16_t next_port,
                                          const std::string& username, const std::string& password) {
    return socks5_connect(sock, next_host, next_port, username, password);
}

bool ProxyChainManager::chain_hop_http(Socket& sock, const std::string& next_host, uint16_t next_port,
                                        const Proxy& proxy) {
    std::string request = "CONNECT " + next_host + ":" + std::to_string(next_port) + " HTTP/1.1\r\n";
    request += "Host: " + next_host + ":" + std::to_string(next_port) + "\r\n";

    if (proxy.has_auth()) {
        // Base64 encode credentials
        static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string auth = proxy.username + ":" + proxy.password;
        std::string encoded;
        int val = 0, valb = -6;
        for (unsigned char c : auth) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                encoded.push_back(b64[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) encoded.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
        while (encoded.size() % 4) encoded.push_back('=');
        request += "Proxy-Authorization: Basic " + encoded + "\r\n";
    }

    request += "\r\n";
    if (!sock.send_all(request)) return false;

    std::string response = sock.recv_all(4096);
    return response.find("200") != std::string::npos;
}

bool ProxyChainManager::save_to_file(const std::string& filepath) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ofstream file(filepath);
    if (!file.is_open()) return false;

    for (const auto& chain : chains_) {
        file << (chain.enabled ? "1" : "0") << "|" << chain.name << "|";
        for (size_t i = 0; i < chain.proxy_indices.size(); ++i) {
            if (i > 0) file << ",";
            file << chain.proxy_indices[i];
        }
        file << "\n";
    }

    return true;
}

bool ProxyChainManager::load_from_file(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ifstream file(filepath);
    if (!file.is_open()) return false;

    chains_.clear();
    std::string line;

    while (std::getline(file, line)) {
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::string token;
        ProxyChain chain;

        if (!std::getline(iss, token, '|')) continue;
        chain.enabled = (token == "1");

        if (!std::getline(iss, chain.name, '|')) continue;

        if (!std::getline(iss, token, '|')) continue;
        std::istringstream idx_stream(token);
        std::string idx_str;
        while (std::getline(idx_stream, idx_str, ',')) {
            try { chain.proxy_indices.push_back(std::stoi(idx_str)); }
            catch (...) {}
        }

        if (!chain.proxy_indices.empty()) {
            chains_.push_back(chain);
        }
    }

    return true;
}
