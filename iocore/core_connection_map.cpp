#include "iocore/core_connection_map.hpp"

#include <algorithm>
#include <ranges>

namespace iocore
{

void CoreConnectionMap::insert(size_t core_id, std::shared_ptr<CoreConnection> conn)
{
    (void)core_id;
    std::unique_lock lock(mtx);
    conns.insert_or_assign(std::string(conn->get_id()), conn);
}

void CoreConnectionMap::erase(size_t core_id, std::string_view conn_id)
{
    (void)core_id;
    std::unique_lock lock(mtx);
    conns.erase(std::string(conn_id));
}

std::shared_ptr<CoreConnection> CoreConnectionMap::find(std::string_view conn_id) const
{
    std::shared_lock lock(mtx);
    auto it = conns.find(std::string(conn_id));
    if (it == conns.end())
    {
        return nullptr;
    }
    return it->second.lock();
}

size_t CoreConnectionMap::size() const
{
    std::shared_lock lock(mtx);
    return conns.size();
}

std::vector<std::shared_ptr<CoreConnection>> CoreConnectionMap::snapshot() const
{
    std::shared_lock lock(mtx);
    std::vector<std::shared_ptr<CoreConnection>> result;
    result.reserve(conns.size());
    
    for (const auto& [id, weak] : conns)
    {
        (void)id;
        if (auto sp = weak.lock())
        {
            result.push_back(sp);
        }
    }
    
    return result;
}

} // namespace iocore
