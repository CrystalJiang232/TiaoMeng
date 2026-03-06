#include "server.hpp"
#include "config.hpp"
#include "logger/logger.hpp"
#include "auth/argon2_hasher.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/signal_set.hpp>
#include <shared_mutex>
#include <csignal>

static size_t calc_cpu_threads(const Config::ServerCfg& srv)
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


Server::Server(const Config& config)
    : cfg(config)
    , tp(calc_cpu_threads(config.server()))
    , running(false)
{
    LOG_INFO("ThreadPool initialized with {} threads", tp.size());
    
    auto auth_result = auth::AuthManager::create("auth.db", tp);
    if (auth_result)
    {
        auth_mgr = std::move(*auth_result);
        if (auth_mgr->db().init_schema())
        {
            LOG_INFO("AuthManager initialized");
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

Server::~Server()
{
    stop();
    tp.stop();
}

bool Server::start()
{
    if (running)
    {
        return false;
    }
    
    // Create io_pool
    io_pool = std::make_unique<iocore::ContextPool>(
        cfg.server().io_threads,
        cfg.server().port,
        [this](tcp::socket sock, size_t core_id, net::io_context& io)
        {
            create_connection(std::move(sock), core_id, io);
        }
    );
    
    auto result = io_pool->start();
    if (!result)
    {
        LOG_ERROR("Failed to start io_pool");
        return false;
    }
    
    running = true;
    
    // Setup shutdown signals on first io_context
    auto& io = io_pool->get_context(0);
    signals.emplace(io, SIGINT, SIGTERM);
    signals->async_wait([this](auto, auto sig)
    {
        LOG_WARN("Received signal {}, shutting down...", sig);
        LOG_INFO("{}", mts);
        stop();
    });
    
    metrics_signals.emplace(io, SIGUSR1);
    std::function<void(boost::system::error_code, int)> metrics_handler = [this, &metrics_handler](boost::system::error_code ec, int sig)
    {
        if (!ec && sig == SIGUSR1)
        {
            LOG_INFO("{}", mts);
        }
        metrics_signals->async_wait(metrics_handler);
    };
    metrics_signals->async_wait(metrics_handler);
    
    LOG_INFO("Server started on {}:{} with {} I/O cores", 
             cfg.server().bind_address, cfg.server().port, io_pool->core_count());
    return true;
}

void Server::stop()
{
    if (!running)
    {
        return;
    }
    
    io_pool->stop();
    running = false;
    LOG_INFO("Server stopped");
}

bool Server::is_running() const
{
    return running;
}

void Server::create_connection(tcp::socket sock, size_t core_id, net::io_context& io)
{
    (void)core_id;
    mts.connections_accepted++;
    std::string id = std::format("{}", sock);
    auto conn = std::make_shared<Connection>(std::move(sock), this, id, cfg, io);
    connections.insert(std::string(conn->get_id()), conn);
    conn->start();
}

void Server::remove_connection(std::string_view id)
{
    auto conn = connections.find(id);
    if (conn) 
    {
        connections.erase(id);
        mts.connections_closed++;
    }
}

void Server::broadcast(const Msg& m, std::string_view exclude_id)
{
    for (auto& conn : connections.snapshot() | std::views::filter([this, exclude_id](auto&& x){
        return x && 
            x->get_id() != exclude_id && 
            x->is_authenticated();
        }))
    {
        conn->send_encrypted(m);
    }
}

bool Server::validate_conn(std::string_view username, std::string_view conn_id)
{
    return auth().db().get_current_conn(username).value_or("") == conn_id;
}

void Server::kick_connection(std::string_view conn_id, std::string_view reason)
{
    auto conn = connections.find(conn_id);
    if (!conn)
    {
        return;
    }
    
    std::ignore = conn->send_error(reason, Connection::CloseMode::Immediate, true);
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
