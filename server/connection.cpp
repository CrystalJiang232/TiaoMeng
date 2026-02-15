#include "server.hpp"
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <iostream>

Connection::Connection(tcp::socket sock, Server* srv)
    : socket(std::move(sock))
    , server(srv)
    , write_in_progress(false)
{
    boost::uuids::uuid uuid = boost::uuids::random_generator()();
    id = boost::uuids::to_string(uuid);
}

void Connection::start()
{

    net::co_spawn(socket.get_executor(), 
        [self = shared_from_this()]() -> net::awaitable<void>
        {
            co_await self->read_header();
        }, 
        net::detached);
}

net::awaitable<void> Connection::read_header()
{
    read_buf.resize(4);
    
    if (auto [ec, n] = co_await net::async_read(
        socket,
        net::buffer(read_buf),
        net::as_tuple(net::use_awaitable));
        ec || n != 4)
    {
        server->remove_connection(id);
        co_return;
    }
    
    uint32_t len = 
        (static_cast<uint32_t>(read_buf[0]) << 24) |
        (static_cast<uint32_t>(read_buf[1]) << 16) |
        (static_cast<uint32_t>(read_buf[2]) << 8)  |
        static_cast<uint32_t>(read_buf[3]);
    
    if (len < 5 || 
        len > 1024 * 1024) //Extra constraint: DoS
    {
        server->remove_connection(id);
        co_return;
    }
    
    co_await read_body(len);
}

net::awaitable<void> Connection::read_body(uint32_t len)
{
    read_buf.resize(len);   
    
    if (auto [ec, n] = co_await net::async_read(
        socket,
        net::buffer(read_buf.data() + 4, len - 4),
        net::as_tuple(net::use_awaitable)); 
        ec || n != len - 4)
    {
        server->remove_connection(id);
        co_return;
    }
    
    auto msg = Msg::parse(read_buf);
    
    if (!msg)
    {
        server->remove_connection(id);
        co_return;
    }
    
    server->get_router()->route(shared_from_this(), *msg);
    
    co_await read_header();
}

void Connection::send(const Msg& msg)
{

    auto self = shared_from_this();
    
    net::dispatch(socket.get_executor(),
        [this, self, msg]()
        {
            bool empty = write_queue.empty();
            write_queue.push_back(msg);
            
            if (!write_in_progress && empty)
            {
                write_in_progress = true;
                net::co_spawn(socket.get_executor(),
                    [this, self]() -> net::awaitable<void>
                    {
                        co_await write();
                    },
                    net::detached);
            }
        });
}

net::awaitable<void> Connection::write()
{
    while (!write_queue.empty())
    {
        auto& msg = write_queue.front();
        auto buf = msg.serialize();
        
        if (auto [ec, n] = co_await net::async_write(
            socket,
            net::buffer(buf),
            net::as_tuple(net::use_awaitable));
            ec)
        {
            server->remove_connection(id);
            co_return;
        }
        
        write_queue.erase(write_queue.begin());
    }
    
    write_in_progress = false;
}