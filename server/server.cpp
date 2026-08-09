#include "server.hpp"
#include "config.hpp"
#include "logger/logger.hpp"
#include "auth/argon2_hasher.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/signal_set.hpp>
#include <shared_mutex>
#include <csignal>
#include <format>

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
    auto             it = conns.find(std::string(id));
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

    auto auth_result = auth::AuthManager::create(cfg.auth().db_path, tp);
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
        cfg.server().io_threads, cfg.server().port,
        [this](tcp::socket sock, tcp::endpoint peer, size_t core_id, net::io_context& io)
        {
            create_connection(std::move(sock), peer, core_id, io);
        });

    auto result = io_pool->start();
    if (!result)
    {
        LOG_ERROR("Failed to start io_pool");
        return false;
    }

    running.store(true, std::memory_order_release);

    // Setup shutdown signals on first io_context
    auto& io = io_pool->get_context(0);
    signals.emplace(io, SIGINT, SIGTERM);
    arm_shutdown_signal();

    metrics_signals.emplace(io, SIGUSR1);
    arm_metrics_signal();

    LOG_INFO("Server started on {}:{} with {} I/O cores", cfg.server().bind_address, cfg.server().port,
             io_pool->core_count());
    return true;
}

void Server::arm_shutdown_signal()
{
    signals->async_wait(
        [this](boost::system::error_code ec, int sig)
        {
            if (ec == net::error::operation_aborted)
            {
                return;
            }
            if (ec)
            {
                LOG_WARN("Shutdown signal wait failed: {}", ec.message());
                if (running.load(std::memory_order_acquire))
                {
                    arm_shutdown_signal();
                }
                return;
            }

            LOG_WARN("Received signal {}, shutting down...", sig);
            LOG_INFO("{}", mts);
            stop();
        });
}

void Server::arm_metrics_signal()
{
    metrics_signals->async_wait(
        [this](boost::system::error_code ec, int sig)
        {
            if (ec == net::error::operation_aborted)
            {
                return;
            }
            if (ec)
            {
                LOG_WARN("Metrics signal wait failed: {}", ec.message());
                if (running.load(std::memory_order_acquire))
                {
                    arm_metrics_signal();
                }
                return;
            }
            if (sig == SIGUSR1)
            {
                LOG_INFO("{}", mts);
            }
            if (running.load(std::memory_order_acquire))
            {
                arm_metrics_signal();
            }
        });
}

void Server::stop()
{
    if (!running.load(std::memory_order_acquire))
    {
        return;
    }

    if (signals)
    {
        signals->cancel();
    }
    if (metrics_signals)
    {
        metrics_signals->cancel();
    }
    io_pool->stop();
    running.store(false, std::memory_order_release);
    LOG_INFO("Server stopped");
}

bool Server::is_running() const
{
    return running.load(std::memory_order_acquire);
}

void Server::create_connection(tcp::socket sock, tcp::endpoint peer, size_t core_id, net::io_context& io)
{
    boost::system::error_code endpoint_ec;
    auto                      address = peer.address().to_string(endpoint_ec);
    if (endpoint_ec)
    {
        LOG_WARN("[ACCEPT] Core {} could not format peer address: {} ({})", core_id, endpoint_ec.message(),
                 endpoint_ec.value());
        return;
    }

    std::string id = std::format("{}:{}", address, peer.port());
    mts.inc_connections_accepted();
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
        mts.inc_connections_closed();
    }
}

void Server::broadcast(const Msg& m, std::string_view exclude_id)
{
    for (auto& conn : connections.snapshot() | std::views::filter(
                                                   [this, exclude_id](auto&& x)
                                                   {
                                                       return x && x->get_id() != exclude_id && x->is_authenticated();
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
