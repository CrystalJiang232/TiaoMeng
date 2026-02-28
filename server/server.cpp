#include "server.hpp"
#include "config.hpp"
#include "logger/logger.hpp"
#include "auth/argon2_hasher.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/signal_set.hpp>
#include <shared_mutex>
#include <csignal>

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
    , metrics_signals(io, SIGUSR1)
    , cfg(config)
    , tp(calc_cpu_threads(config.server()))
{
    acceptor.set_option(net::socket_base::reuse_address(true));
    LOG_INFO("ThreadPool initialized with {} threads", tp.size());
    auto auth_result = auth::AuthManager::create("auth.db", tp);
    if (auth_result)
    {
        auth_mgr = std::move(*auth_result);
        if (auth_mgr->db().init_schema())
        {
            LOG_INFO("AuthManager initialized");

            if(!auth_mgr->db().find_user("admin"))
            {
                
                if(auto res = auth::Argon2Hasher::hash("123456");!res)
                {
                    LOG_ERROR("Hash password failed");
                }
                else
                {
                    auto rr = auth_mgr->db().create_user("admin",res->encoded);
                    LOG_INFO("Admin user created on first startup, ret = {}, password hash = {}", rr, res->encoded);
                }
            }
        }
        else
        {
            LOG_WARN("Initialization of schema failed");
        }
    }
    else
    {
        LOG_WARN("AuthManager initialization failed: {}", auth_result.error());
    }
}

size_t Server::calc_cpu_threads(const Config::ServerCfg& srv)
{
    if (srv.cpu_threads != 0)
    {
        return srv.cpu_threads;
    }
    
    size_t hw = std::thread::hardware_concurrency();
    size_t io = srv.io_threads;
    
    if (hw <= io)
    {
        return 2;
    }
    
    return std::max(2uz, hw - io);
}

Server::~Server()
{
    tp.stop();
}

void Server::start()
{
    net::co_spawn(io_ctx, do_accept(), net::detached);
    
    // Setup shutdown signals
    signals.async_wait([this](auto, auto sig)
    {
        LOG_WARN("Received signal {}, shutting down...", sig);
        LOG_INFO("{}", mts);
        io_ctx.stop();
    });
    
    // Setup metrics signal (SIGUSR1)
    metrics_signals.async_wait([this](boost::system::error_code ec, int sig)
    {
        if (!ec && sig == SIGUSR1)
        {
            LOG_INFO("{}",mts);
            // Re-register for next signal
            metrics_signals.async_wait([this](boost::system::error_code ec2, int sig2)
            {
                if (!ec2 && sig2 == SIGUSR1)
                {
                    LOG_INFO("{}",mts);
                }
            });
        }
    });
}

net::awaitable<void> Server::do_accept()
{
    LOG_DEBUG("do_accept: starting loop");
    while (true)
    {
        auto [ec, sock] = co_await acceptor.async_accept(net::as_tuple(net::use_awaitable));
        
        if (ec)
        {
            LOG_ERROR("Accept error: {}", ec.message());
            mts.errors++;
            continue;
        }
        
        mts.connections_accepted++;
        std::string id = std::format("{}",sock);
        LOG_DEBUG("do_accept: accepted {}, creating connection", id);
        auto conn = std::make_shared<Connection>(std::move(sock), this, id, cfg, io_ctx);
        LOG_DEBUG("do_accept: connection created, inserting");
        connections.insert(id, conn);
        LOG_DEBUG("do_accept: about to call start()");
        conn->start();
        LOG_DEBUG("do_accept: start() returned");
    }
}

void Server::remove_connection(std::string_view id)
{
    auto conn = connections.find(id);
    if (conn) 
    {
        conn->mark_pipe_dead();
        std::weak_ptr<Connection> wp(conn);
        connections.erase(id);
        mts.connections_closed++;
    }
}

void Server::broadcast(const Msg& m, std::string_view exclude_id)
{
    
    
    for (auto& conn : connections.snapshot() | std::views::filter([this, exclude_id](auto&& x){
        return x && 
            !x->is_pipe_dead() && 
            x->get_id() != exclude_id;
        })) //Lifetime extension?  
    {
        conn->send_encrypted(m);
    }
}

void Server::kick_connection(std::string_view conn_id, std::string_view reason)
{
    auto conn = connections.find(conn_id);
    if (!conn)
    {
        return;
    }
    
    std::ignore = conn->send_error(reason, Connection::CloseMode::CancelOthers, true);
}

void Server::register_user_session(std::string_view username, std::string_view conn_id)
{
    if (!auth_mgr)
    {
        return;
    }
    
    auto old_conn = auth_mgr->db().get_current_conn(username);
    if (old_conn && *old_conn != conn_id)
    {
        kick_connection(*old_conn, "Kicked: new login");
    }
    
    std::ignore = auth_mgr->db().set_current_conn(username, conn_id);
}

void Server::unregister_user_session(std::string_view username, std::string_view conn_id)
{
    if (!auth_mgr)
    {
        return;
    }
    
    std::ignore = auth_mgr->db().clear_conn_id_if_matches(username, conn_id);
}
