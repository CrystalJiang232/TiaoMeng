#include "server.hpp"
#include "helper.hpp"
#include "cipher.hpp"
#include <bit>

using namespace Hibiscus;

Connection::Connection(tcp::socket sock, Server* srv, std::string conn_id)
    : socket(std::move(sock))
    , server(srv)
    , id(std::move(conn_id))
    , state(ConnState::Connected)
    , write_in_progress(false)
{
    std::println("Connection established with id = {}", id);
}

Connection::~Connection() noexcept
{
    sess.clear();
    std::println("Disconnected with id = {}!", id);
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
        net::buffer(read_buf, 4),
        net::as_tuple(net::use_awaitable));
    
    uint32_t len = to_int(read_buf);

    if (ec || n != 4 || len < 5 || len > Msg::max_len)
    {
        close("Length verification error");
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
        close("Pipe reading error");
        co_return;
    }
    
    auto m0 = Msg::parse(read_buf);
    if (!m0)
    {
        close("Message parse error");
        co_return;
    }
    
    auto& msg = *m0;
    switch(static_cast<MsgType>(msg.type))
    {
    case MsgType::Handshake:
        co_await handle_handshake(msg);
        break;
        
    case MsgType::Encrypted:
        co_await handle_encrypted(msg);
        break;
    
    case MsgType::Command:
        [[fallthrough]];
    case MsgType::Broadcast:
        close("Invalid argument - pass command/broadcast in encrypted payload after handshake");
        co_return;

    default:
        close(std::format("Invalid message type {}", msg.type));
        co_return;
    }

    co_await read_header();
}

net::awaitable<void> Connection::handle_handshake(const Msg& msg)
{
    switch(state)
    {
    case ConnState::Connected:
    {
        // Step 1: Generate our keypair and send public key to client
        auto kp_result = kem.generate_keypair();
        if (!kp_result)
        {
            close("Failed to generate keypair");
            co_return;
        }
        kp = std::move(*kp_result);
        
        // Send our public key
        auto send_result = Msg::make(
            to_bytes<uint8_t>(kp->public_key), 
            MsgType::Handshake
        );
        if (!send_result)
        {
            close("Failed to create handshake message");
            co_return;
        }
        send(*send_result);
        
        state = ConnState::Handshaking;
        break;
    }
    
    case ConnState::Handshaking:
    {
        // Step 2: Receive client's public key + ciphertext
        // Expected format: [client_pubkey (1184 bytes)] [ciphertext (1088 bytes)]
        constexpr size_t expected_len = Kyber768::public_key_size + Kyber768::ciphertext_size;
        if (msg.payload.size() != expected_len)
        {
            close(std::format("Invalid handshake payload size: expected {}, got {}", 
                expected_len, msg.payload.size()));
            co_return;
        }
        
        // Extract client's public key and ciphertext
        std::span<const uint8_t> client_pk(
            reinterpret_cast<const uint8_t*>(msg.payload.data()), 
            Kyber768::public_key_size
        );
        std::span<const uint8_t> client_ct(
            reinterpret_cast<const uint8_t*>(msg.payload.data()) + Kyber768::public_key_size,
            Kyber768::ciphertext_size
        );
        
        // Decapsulate to get the secret from client's encapsulation
        auto decap_result = kem.decapsulate(client_ct, kp->secret_key);
        if (!decap_result)
        {
            close("Failed to decapsulate client ciphertext");
            co_return;
        }
        ss_local = std::move(*decap_result);
        
        // Encapsulate to client's public key to get our shared secret
        auto encap_result = kem.encapsulate(client_pk);
        if (!encap_result)
        {
            close("Failed to encapsulate to client pubkey");
            co_return;
        }
        ss_remote = std::move(encap_result->shared_secret);
        
        // Combine secrets and complete handshake
        sess.complete_handshake(
            std::span<const uint8_t>(ss_local->data(), ss_local->size()),
            std::span<const uint8_t>(ss_remote->data(), ss_remote->size())
        );
        
        // Send our ciphertext back to client
        auto send_result = Msg::make(
            to_bytes<uint8_t>(encap_result->ciphertext),
            MsgType::Handshake
        );
        if (!send_result)
        {
            close("Failed to create handshake response");
            co_return;
        }
        send(*send_result);
        
        // Clear sensitive key material
        kp->secret_key.clear();
        kp->secret_key.shrink_to_fit();
        
        state = ConnState::Established;
        std::println("Connection {}: secure session established", id);
        break;
    }

    case ConnState::Established:
        close("Invalid state: handshake already completed");
        co_return;
    
    default:
        close("Invalid state [Unknown] for handshake");
        co_return;
    }
}

net::awaitable<void> Connection::handle_encrypted(const Msg& msg)
{
    if (state != ConnState::Established)
    {
        close("Invalid state: encrypted connection not yet established");
        co_return;
    }

    if (!sess.is_established())
    {
        close("Session key not established");
        co_return;
    }

    // TODO: Implement actual decryption using sess.key()
    // For now, pass through (placeholder)
    auto decrypted = decrypt(msg, sess.key());
    if (!decrypted)
    {
        send(get_err("Decryption failed"));
    }
    else
    {
        server->get_router()->route(shared_from_this(), *decrypted);
    }
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

net::awaitable<void> Connection::close_async(std::string_view err, CloseMode mode)
{
    if(!err.empty())
    {
        if (mode == CloseMode::Definite && !write_queue.empty())
        {
            write_queue.push_back(get_err(err));
            co_await write();
        }
        else
        {
            send(get_err(err));
        }
    }
    
    server->remove_connection(id);
    co_return;
}

void Connection::close(std::string_view err, Connection::CloseMode mode)
{
    if (mode == CloseMode::Definite)
    {
        net::co_spawn(socket.get_executor(),
            [self = shared_from_this(), err]() -> net::awaitable<void>
            {
                co_await self->close_async(err, CloseMode::Definite);
            }, net::detached);
    }
    else
    {
        if (!err.empty()) 
        {
            send(get_err(err));
        }
        server->remove_connection(id);
    }
}
