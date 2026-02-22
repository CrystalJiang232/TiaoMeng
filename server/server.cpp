#include "server.hpp"
#include "config.hpp"
#include "logger.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/signal_set.hpp>

Server::Server(net::io_context& io, const Config& config)
    : io_ctx(io)
    , acceptor(io, tcp::endpoint(net::ip::make_address(config.server().bind_address), config.server().port))
    , config_(config)
{
    acceptor.set_option(net::socket_base::reuse_address(true));
}

void Server::start()
{
    net::co_spawn(io_ctx, do_accept(), net::detached);
    
    net::signal_set signals(io_ctx, SIGINT, SIGTERM);
    signals.async_wait([&](auto, auto)
    {
        io_ctx.stop();
    });
    
    io_ctx.run();
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
        auto conn = std::make_shared<Connection>(std::move(sock), this, id, config_);
        connections[id] = conn;
        
        conn->start();
    }
}

void Server::remove_connection(std::string_view id)
{
    auto it = connections.find(std::string(id));
    if (it != connections.end()) {
        // Mark pipe as dead to prevent any new sends
        it->second->mark_pipe_dead();
        
        // Erase from map - this decrements refcount
        // If coroutines still hold shared_ptr, they complete naturally
        connections.erase(it);
    }
}

void Server::broadcast(const Msg& msg, std::string_view exclude_id)
{
    for (auto it = connections.begin(); it != connections.end(); )
    {
        if (it->first == exclude_id)
        {
            ++it;
            continue;
        }
        
        auto conn = it->second;
        
        if (conn)
        {
            conn->send_encrypted(msg);
            ++it;
        }
        else
        {
            it = connections.erase(it);
        }
    }
    
}

