#pragma once

#include "iocore/types.hpp"
#include <expected>
#include <functional>
#include <memory>
#include <vector>

namespace iocore
{

// Result type for operations
enum class ContextPoolError
{
    Ok = 0,
    AlreadyStarted,
    AcceptorBindFailed,
    ThreadCreateFailed
};

// Thread-per-core I/O context pool
class ContextPool
{
public:
    using ConnectionFactory = std::function<void(tcp::socket, size_t core_id, net::io_context&)>;
    
    ContextPool(size_t n_cores, uint16_t port, ConnectionFactory factory);
    ~ContextPool();
    
    ContextPool(const ContextPool&) = delete;
    ContextPool& operator=(const ContextPool&) = delete;
    
    [[nodiscard]] std::expected<void, ContextPoolError> start();
    void stop();
    [[nodiscard]] bool is_running() const;
    
    [[nodiscard]] size_t core_count() const;
    [[nodiscard]] net::io_context& get_context(size_t core_id);
    
    // For connection deregistration (called by Connection on destroy)
    void remove_connection(size_t core_id, std::string_view conn_id);

private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace iocore
