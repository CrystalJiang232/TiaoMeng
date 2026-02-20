#include "server.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/signal_set.hpp>
#include <iostream>
#include <print>
#include <algorithm>
#include <ranges>

Server::Server(net::io_context& io, unsigned short port)
    : io_ctx(io)
    , acceptor(io, tcp::endpoint(tcp::v4(), port))
    , router(std::make_unique<Router>())
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
            std::println(stderr, "Accept error: {}",ec.message());
            continue;
        }
        std::string id = std::format("{}",sock);
        auto conn = std::make_shared<Connection>(std::move(sock), this, id);
        connections[id] = conn;
        
        conn->start();
    }
}

void Server::remove_connection(std::string_view id)
{
    connections.erase(std::string(id)); //implicit conversion?
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
            conn->send(msg);
            ++it;
        }
        else
        {
            it = connections.erase(it);
        }
    }
    
}