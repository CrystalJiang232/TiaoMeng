#include "server.hpp"
#include "helper.hpp"
#include <bit>

Connection::Connection(tcp::socket sock, Server* srv, std::string id)
    : socket(std::move(sock))
    , server(srv)
    , write_in_progress(false)
    , id(id)
    , state(ConnState::Connected) // Last to initialize, definitely established without exception
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
        close(std::format("Length verification error!!!"));
        server->remove_connection(id);
        co_return;
    }
    
    co_await read_body(len);
}

net::awaitable<void> Connection::read_body(uint32_t len)
{
    using Hibiscus::to_bytes;

    auto decrypt = [](const Msg&) -> std::optional<Msg>
    {
        return *Msg::create(Hibiscus::to_bytes("Encrypted \"ni hao\""),MsgType::Broadcast);
    };

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
    
    switch(static_cast<MsgType>(msg->type))
    {
    using namespace Hibiscus;

    case MsgType::Handshake:
        switch(this->state)
        {
        case ConnState::Established:
            close("Invalid state: handshake already completed");
            co_return;
        case ConnState::Handshaking:
            //Verify derived shared key is OK

            //...
            if(false)
            {
                close("Derived key verification failed");
                co_return;
            }

            this->state = ConnState::Established;
            break;
        case ConnState::Connected:
            //Initialize shared key derivation
            //Get client-side pubkey, send server-side pubkey(DH key exchange)
            send(*Msg::create(to_bytes("encrypted key"),MsgType::Encrypted));
            this->state = ConnState::Handshaking;
            break;
            
        }
        break;

    case MsgType::Encrypted:

        if(this->state != ConnState::Established)
        {
            close("Invalid state: encrypted connection not yet established");
            co_return;
        }

        if(auto decrypted = decrypt(*msg);!decrypted)
        {
            send(*Msg::create(Hibiscus::to_bytes("Decryption error"),MsgType::Broadcast));
        }
        else
        {
            server->get_router()->route(shared_from_this(), *decrypted);
        }
        break;
    
    case MsgType::Command:
    [[fallthrough]];
    case MsgType::Broadcast:
        close("Invalid argument - pass command/broadcast in encrypted payload after handshake");
        co_return;

    default:
        close(std::format("Invalid message type {}",msg->type));
        co_return;
    }

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
            close("Pipe writing error");
            co_return;
        }
        
        write_queue.pop_front();
    }
    
    write_in_progress = false;
}

void Connection::close(std::string_view err)
{
    using namespace Hibiscus;

    send(Msg::create(to_bytes(err), MsgType::Broadcast).value_or(unknown_error_msg()));
    server->remove_connection(id);
}