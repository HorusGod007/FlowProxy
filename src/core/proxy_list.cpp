#include "core/proxy_list.h"
#include <random>
#include <algorithm>
#include <climits>

void ProxyList::add(const Proxy& proxy) {
    std::lock_guard<std::mutex> lock(mutex_);
    proxies_.push_back(proxy);
}

void ProxyList::update(size_t index, const Proxy& proxy) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index < proxies_.size()) {
        proxies_[index] = proxy;
    }
}

void ProxyList::remove(size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index < proxies_.size()) {
        proxies_.erase(proxies_.begin() + (ptrdiff_t)index);
    }
}

void ProxyList::remove_indices(std::vector<size_t>& indices) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::sort(indices.begin(), indices.end(), std::greater<size_t>());
    for (size_t idx : indices) {
        if (idx < proxies_.size()) {
            proxies_.erase(proxies_.begin() + (ptrdiff_t)idx);
        }
    }
}

void ProxyList::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    proxies_.clear();
    rotation_index_ = 0;
}

void ProxyList::remove_dead() {
    std::lock_guard<std::mutex> lock(mutex_);
    proxies_.erase(
        std::remove_if(proxies_.begin(), proxies_.end(),
            [](const Proxy& p) { return p.status == ProxyStatus::Dead; }),
        proxies_.end()
    );
}

Proxy& ProxyList::at(size_t index) {
    return proxies_[index];
}

const Proxy& ProxyList::at(size_t index) const {
    return proxies_[index];
}

size_t ProxyList::size() const {
    return proxies_.size();
}

bool ProxyList::empty() const {
    return proxies_.empty();
}

void ProxyList::sort_by(SortColumn column, bool ascending) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto cmp = [column, ascending](const Proxy& a, const Proxy& b) -> bool {
        // Swap operands for descending to maintain strict weak ordering
        const Proxy& lhs = ascending ? a : b;
        const Proxy& rhs = ascending ? b : a;
        switch (column) {
            case SortColumn::Host:        return lhs.host < rhs.host;
            case SortColumn::Port:        return lhs.port < rhs.port;
            case SortColumn::Type:        return lhs.type < rhs.type;
            case SortColumn::Status:      return lhs.status < rhs.status;
            case SortColumn::Latency:     return lhs.latency_ms < rhs.latency_ms;
            case SortColumn::Anonymity:   return lhs.anonymity < rhs.anonymity;
            case SortColumn::Country:     return lhs.country < rhs.country;
            case SortColumn::LastChecked: return lhs.last_checked < rhs.last_checked;
        }
        return false;
    };
    std::sort(proxies_.begin(), proxies_.end(), cmp);
}

size_t ProxyList::count_alive() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return (size_t)std::count_if(proxies_.begin(), proxies_.end(),
        [](const Proxy& p) { return p.status == ProxyStatus::Alive; });
}

size_t ProxyList::count_dead() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return (size_t)std::count_if(proxies_.begin(), proxies_.end(),
        [](const Proxy& p) { return p.status == ProxyStatus::Dead; });
}

size_t ProxyList::count_unknown() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return (size_t)std::count_if(proxies_.begin(), proxies_.end(),
        [](const Proxy& p) { return p.status == ProxyStatus::Unknown; });
}

Proxy* ProxyList::next_proxy(RotationMode mode) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Collect alive proxies
    std::vector<size_t> alive;
    for (size_t i = 0; i < proxies_.size(); ++i) {
        if (proxies_[i].status == ProxyStatus::Alive) {
            alive.push_back(i);
        }
    }
    if (alive.empty()) return nullptr;

    size_t chosen = 0;
    switch (mode) {
        case RotationMode::RoundRobin:
            if (rotation_index_ >= alive.size()) rotation_index_ = 0;
            chosen = alive[rotation_index_++];
            break;

        case RotationMode::Random: {
            static std::mt19937 rng(std::random_device{}());
            std::uniform_int_distribution<size_t> dist(0, alive.size() - 1);
            chosen = alive[dist(rng)];
            break;
        }

        case RotationMode::LeastLatency: {
            int best = INT_MAX;
            chosen = alive[0];
            for (size_t idx : alive) {
                if (proxies_[idx].latency_ms >= 0 && proxies_[idx].latency_ms < best) {
                    best = proxies_[idx].latency_ms;
                    chosen = idx;
                }
            }
            break;
        }
    }

    return &proxies_[chosen];
}

void ProxyList::reset_rotation() {
    std::lock_guard<std::mutex> lock(mutex_);
    rotation_index_ = 0;
}
