#pragma once

#include "iocore/types.hpp"
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace iocore
{

// Per-core connection tracking with global lookup capability
class CoreConnectionMap
{
public:
    void insert(size_t core_id, std::shared_ptr<CoreConnection> conn);
    void erase(size_t core_id, std::string_view conn_id);
    [[nodiscard]] std::shared_ptr<CoreConnection> find(std::string_view conn_id) const;
    [[nodiscard]] size_t size() const;
    [[nodiscard]] std::vector<std::shared_ptr<CoreConnection>> snapshot() const;

private:
    mutable std::shared_mutex mtx;
    std::unordered_map<std::string, std::weak_ptr<CoreConnection>> conns;
};

} // namespace iocore
