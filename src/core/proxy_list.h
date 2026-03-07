#pragma once

#include "core/proxy.h"
#include <vector>
#include <mutex>
#include <functional>
#include <algorithm>

enum class SortColumn {
    Host = 0,
    Port,
    Type,
    Status,
    Latency,
    Anonymity,
    Country,
    LastChecked
};

enum class RotationMode {
    RoundRobin = 0,
    Random,
    LeastLatency
};

class ProxyList {
public:
    ProxyList() = default;

    void add(const Proxy& proxy);
    void update(size_t index, const Proxy& proxy);
    void remove(size_t index);
    void remove_indices(std::vector<size_t>& indices);
    void clear();
    void remove_dead();

    Proxy& at(size_t index);
    const Proxy& at(size_t index) const;
    size_t size() const;
    bool empty() const;

    void sort_by(SortColumn column, bool ascending);

    size_t count_alive() const;
    size_t count_dead() const;
    size_t count_unknown() const;

    // Rotation
    Proxy* next_proxy(RotationMode mode);
    void reset_rotation();

    // Thread-safe access
    std::mutex& mutex() { return mutex_; }
    std::vector<Proxy>& proxies() { return proxies_; }
    const std::vector<Proxy>& proxies() const { return proxies_; }

private:
    std::vector<Proxy> proxies_;
    mutable std::mutex mutex_;
    size_t rotation_index_ = 0;
};
