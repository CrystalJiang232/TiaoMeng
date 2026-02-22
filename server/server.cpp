#include "server.hpp"
#include "config.hpp"
#include "logger.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/signal_set.hpp>
#include <shared_mutex>

void ConnectionsMap::insert(std::string id, std::shared_ptr<Connection> conn)
{
    std::unique_lock lock(mtx);
    conns.insert_or_assign(std::move(id), std::move(conn));
}

void ConnectionsMap::erase(std::string_view id)
{
    std::unique_lock lock(mtx);
    conns.erase(std::string(id));
}

std::shared_ptr<Connection> ConnectionsMap::find(std::string_view id) const
{
    std::shared_lock lock(mtx);
    auto it = conns.find(std::string(id));
    return (it != conns.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<Connection>> ConnectionsMap::snapshot() const
{
    std::shared_lock lock(mtx);
    return conns | std::views::values | std::ranges::to<std::vector>();
}

size_t ConnectionsMap::size() const
{
    std::shared_lock lock(mtx);
    return conns.size();
}

Server::Server(net::io_context& io, const Config& config)
    : io_ctx(io)
    , acceptor(io, tcp::endpoint(net::ip::make_address(config.server().bind_address), config.server().port))
    , signals(io, SIGINT, SIGTERM)
    , config_(config)
{
    acceptor.set_option(net::socket_base::reuse_address(true));
}

void Server::start()
{
    net::co_spawn(io_ctx, do_accept(), net::detached);
    
    signals.async_wait([&](auto, auto)
    {
        io_ctx.stop();
    });
}

net::awaitable<void> Server::do_accept()
{

    while (true)
    {
        auto [ec, sock] = co_await acceptor.async_accept(net::as_tuple(net::use_awaitable));
        
        if (ec)
        {
            LOG_ERROR("Accept error: {}", ec.message());
            continue;
        }
        std::string id = std::format("{}",sock);
        auto conn = std::make_shared<Connection>(std::move(sock), this, id, config_, io_ctx);
        connections.insert(id, conn);
        
        conn->start();
    }
}

void Server::remove_connection(std::string_view id)
{
    auto conn = connections.find(id);
    if (conn) {
        conn->mark_pipe_dead();
        connections.erase(id);
    }
}

void Server::broadcast(const Msg& msg, std::string_view exclude_id)
{
    auto conns = connections.snapshot();
    
    for (auto& conn : conns)
    {
        if (conn->get_id() == exclude_id)
        {
            continue;
        }
        
        if (conn && !conn->is_pipe_dead())
        {
            conn->send_encrypted(msg);
        }
    }
}
