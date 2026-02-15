#include "server.hpp"

Connection::Connection(tcp::socket sock, Server* srv, std::string id)
    : socket(std::move(sock))
    , server(srv)
    , write_in_progress(false)
    , id(id)
{
    std::println("Connection established with id = {}",id);
}

Connection::~Connection() noexcept
{
    std::println("Disconnected with id = {}!",id);
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

    auto [ec, n] = co_await net::async_read(
        socket,
        net::buffer(read_buf,4),
        net::as_tuple(net::use_awaitable));
    
    uint32_t len = Hibiscus::endify(*reinterpret_cast<uint32_t*>(read_buf.data()));

    if (
        ec || n != 4 ||  //Read Error(ec set or insufficient bytes)
        len < 5 || len > 1024 * 1024  //invalid size(Not-a-msg / anti-DoS)
    )
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
        auto buf = write_queue.front().serialize();
        
        if (auto [ec, n] = co_await net::async_write(
            socket,
            net::buffer(buf),
            net::as_tuple(net::use_awaitable));
            ec)
        {
            server->remove_connection(id);
            co_return;
        }
        
        write_queue.pop_front();
    }
    
    write_in_progress = false;
}