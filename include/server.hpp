#pragma once

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <memory>
#include <unordered_map>
#include <vector>
#include <deque>
#include <cstddef>
#include <span>
#include <functional>
#include <optional>
#include <expected>
#include <bit>

#include <print>
#include <algorithm>
#include <ranges>

#include "cipher.hpp"
#include "msg.hpp"
#include "router.hpp"

namespace net = boost::asio;
using tcp = net::ip::tcp;

class Connection;
class Server;
class Router;

enum class ConnState: uint8_t
{
    Connected,
    Handshaking,
    Established,
    Closing, //Reserved for async I/O: connection closing yet draining messages  
    Rekeying, //Reserved for round session key
};


class Server
{
public:
    Server(net::io_context& io, unsigned short port);
    void start();
    void remove_connection(std::string_view id);
    void broadcast(const Msg& msg, std::string_view exclude_id = "");
    Router* get_router() 
    { 
        return router.get(); 
    }

private:
    net::awaitable<void> do_accept();
    
    net::io_context& io_ctx;
    tcp::acceptor acceptor;
    std::unordered_map<std::string, std::shared_ptr<Connection>> connections;
    std::unique_ptr<Router> router;

};



class Connection : public std::enable_shared_from_this<Connection>
{
public:
    enum class CloseMode {BestEffort, Definite};

    Connection(tcp::socket, Server*, std::string);
    ~Connection() noexcept;
    void start();
    void send(const Msg& msg);
    void send_encrypted(const Msg& msg);
    std::string_view get_id() const { return id; }
    ConnState getstate() const {return state;}
    void setstate(ConnState newstate) {state = newstate;}

    void close(std::string_view err = "", CloseMode mode = CloseMode::BestEffort);
    
    [[nodiscard]] bool has_session_key() const { return sess.is_established(); }
    [[nodiscard]] std::span<const uint8_t> session_key() const { return sess.key(); }
    
private:
    net::awaitable<void> read_header();
    net::awaitable<void> read_body(uint32_t len);
    net::awaitable<void> write();
    net::awaitable<void> close_async(std::string_view = "", CloseMode = CloseMode::BestEffort);
    
    // Handshake handlers
    net::awaitable<void> handle_handshake(const Msg& msg);
    net::awaitable<void> handle_encrypted(const Msg& msg);
    
    // Bidirectional KEM state
    Kyber768 kem;
    std::optional<Kyber768::keypair_t> kp;
    std::optional<Kyber768::shared_secret_t> ss_local;
    std::optional<Kyber768::shared_secret_t> ss_remote;
    SessionKey sess;
    std::optional<Kyber768::key_t> client_pk;
    std::optional<Kyber768::shared_secret_t> ss_A;

    tcp::socket socket;
    Server* server;
    std::string id;
    std::vector<std::byte> read_buf;
    std::vector<std::byte> write_buf;
    std::deque<Msg> write_queue;

    ConnState state;
    bool write_in_progress = false;
};

template<>
struct std::formatter<tcp::socket>
{
    constexpr auto parse(std::format_parse_context& fpc)
    {
        return fpc.begin();
    }

    auto format(const tcp::socket& socket,std::format_context& fc) const
    {
        return std::format_to(fc.out(),"{}:{}",socket.remote_endpoint().address().to_string(),
        std::to_string(socket.remote_endpoint().port()));
    }
};

