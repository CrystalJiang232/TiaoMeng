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
    if (ss_local)
    {
        secure_clear(*ss_local);
    }
    if (ss_remote)
    {
        secure_clear(*ss_remote);
    }
    if (ss_A)
    {
        secure_clear(*ss_A);
    }
    if (kp)
    {
        secure_clear(kp->secret_key);
    }
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
        if (msg.payload.size() != Kyber768::public_key_size)
        {
            close(std::format("Invalid client public key size: expected {}, got {}",
                Kyber768::public_key_size, msg.payload.size()));
            co_return;
        }
        
        auto kp_result = kem.generate_keypair();
        if (!kp_result)
        {
            close("Failed to generate keypair");
            co_return;
        }
        kp = std::move(*kp_result);
        
        std::span<const uint8_t> cpk(
            reinterpret_cast<const uint8_t*>(msg.payload.data()),
            Kyber768::public_key_size
        );


        auto encap_result = kem.encapsulate(cpk);
        if (!encap_result)
        {
            close("Failed to encapsulate to client public key");
            co_return;
        }
        ss_A = std::move(encap_result->shared_secret);
        
        std::vector<uint8_t> payload;
        payload.reserve(Kyber768::public_key_size + Kyber768::ciphertext_size);
        
        std::ranges::copy(kp->public_key, std::back_inserter(payload));
        std::ranges::copy(encap_result->ciphertext, std::back_inserter(payload));

        auto send_result = Msg::make(to_bytes<uint8_t>(payload), MsgType::Handshake);
        if (!send_result)
        {
            close(std::format("Failed to create handshake message, errc = {}", std::to_underlying(send_result.error())));
            co_return;
        }
        send(*send_result);

        
        client_pk = std::vector<uint8_t>(cpk.begin(), cpk.end());
        state = ConnState::Handshaking;
        break;
    }
    
    case ConnState::Handshaking:
    {
        if (msg.payload.size() < Kyber768::ciphertext_size)
        {
            close(std::format("Invalid handshake payload size: expected at least {}, got {}",
                Kyber768::ciphertext_size, msg.payload.size()));
            co_return;
        }
        
        std::span<const uint8_t> cct(
            reinterpret_cast<const uint8_t*>(msg.payload.data()),
            Kyber768::ciphertext_size
        );
        
        auto decap_result = kem.decapsulate(cct, kp->secret_key);
        if (!decap_result)
        {
            close("Failed to decapsulate client ciphertext");
            co_return;
        }
        ss_local = std::move(*decap_result);
        
        std::span<const uint8_t> cpk(client_pk->data(), client_pk->size());
        auto encap_result = kem.encapsulate(cpk);
        if (!encap_result)
        {
            close("Failed to encapsulate to client public key");
            co_return;
        }
        ss_remote = std::move(encap_result->shared_secret);
        
        sess.complete_handshake(
            std::span<const uint8_t>(ss_local->data(), ss_local->size()),
            std::span<const uint8_t>(ss_A->data(), ss_A->size())
        );
        
        if (msg.payload.size() > Kyber768::ciphertext_size)
        {
            std::span<const std::byte> auth_data(
                msg.payload.data() + Kyber768::ciphertext_size,
                msg.payload.size() - Kyber768::ciphertext_size
            );
            auto auth_msg = Msg::make(auth_data, MsgType::Encrypted);
            if (auth_msg)
            {
                auto decrypted = sess.decrypt(std::vector<uint8_t>(
                    reinterpret_cast<const uint8_t*>(auth_msg->payload.data()),
                    reinterpret_cast<const uint8_t*>(auth_msg->payload.data()) + auth_msg->payload.size()
                ));
                if (decrypted)
                {
                    std::println("Auth received");
                }
            }
        }
        
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
        
        kp->secret_key.clear();
        kp->secret_key.shrink_to_fit();
        ss_A.reset();
        client_pk.reset();
        
        state = ConnState::Established;
        std::println("Secure session established with {}", id);
        break;
    }

    case ConnState::Established:
        close("Handshake already completed");
        co_return;
    
    default:
        close("Invalid state for handshake");
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

    std::vector<uint8_t> ct;
    ct.reserve(msg.payload.size());
    std::ranges::transform(msg.payload, std::back_inserter(ct), 
        [](std::byte b){ return static_cast<uint8_t>(b); });
    
    auto decrypted = sess.decrypt(ct);
    if (!decrypted)
    {
        send(get_err("Decryption failed"));
        co_return;
    }
    
    auto inner_msg = Msg::parse(
        *decrypted | 
        std::views::transform(int2byte) | 
        std::ranges::to<Msg::payload_t>()
    );
    
    if (!inner_msg)
    {
        send(get_err("Invalid inner message"));
        co_return;
    }
    
    server->get_router()->route(shared_from_this(), *inner_msg);
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

void Connection::send_encrypted(const Msg& msg)
{
    if (!sess.is_established())
    {
        return;
    }
    
    std::vector<uint8_t> plaintext;
    plaintext.reserve(5 + msg.payload.size());
    uint32_t len = 5 + msg.payload.size();
    plaintext.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
    plaintext.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    plaintext.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    plaintext.push_back(static_cast<uint8_t>(len & 0xFF));
    plaintext.push_back(static_cast<uint8_t>(msg.type));
    std::ranges::transform(msg.payload, std::back_inserter(plaintext),
        [](std::byte b){ return static_cast<uint8_t>(b); });
    
    auto encrypted = sess.encrypt(plaintext);
    if (!encrypted)
    {
        return;
    }
    
    std::vector<std::byte> payload;
    payload.reserve(encrypted->size());
    std::ranges::transform(*encrypted, std::back_inserter(payload),
        [](uint8_t b){ return static_cast<std::byte>(b); });
    
    auto enc_msg = Msg::make(payload, MsgType::Encrypted);
    if (!enc_msg)
    {
        return;
    }
    
    send(*enc_msg);
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
