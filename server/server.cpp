#include "server.hpp"
#include "config.hpp"
#include "logger.hpp"
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

// ServerMetrics implementation
void ServerMetrics::print() const
{
    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
    
    uint64_t conns_accepted = connections_accepted.load();
    uint64_t conns_closed = connections_closed.load();
    uint64_t hs_completed = handshakes_completed.load();
    uint64_t hs_failed = handshakes_failed.load();
    uint64_t auth_ok = authentications_successful.load();
    uint64_t auth_fail = authentications_failed.load();
    uint64_t msgs_recv = messages_received.load();
    uint64_t msgs_sent = messages_sent.load();
    uint64_t bytes_recv = bytes_received.load();
    uint64_t bytes_sent_total = bytes_sent.load();
    uint64_t err_count = errors.load();
    uint64_t timeout_count = timeouts.load();
    
    double uptime_hours = uptime / 3600.0;
    double mb_recv = bytes_recv / (1024.0 * 1024.0);
    double mb_sent = bytes_sent_total / (1024.0 * 1024.0);
    
    std::println("");
    std::println("============================================================");
    std::println("SERVER METRICS REPORT");
    std::println("============================================================");
    std::println("Uptime: {}s ({:.2f}h)", uptime, uptime_hours);
    std::println("");
    std::println("--- CONNECTIONS ---");
    std::println("  Accepted:        {}", conns_accepted);
    std::println("  Closed:          {}", conns_closed);
    std::println("  Active:          {}", conns_accepted - conns_closed);
    std::println("  Accept Rate:     {:.1f}/min", conns_accepted * 60.0 / std::max(uptime, 1L));
    std::println("");
    std::println("--- HANDSHAKES ---");
    std::println("  Completed:       {}", hs_completed);
    std::println("  Failed:          {}", hs_failed);
    std::println("  Success Rate:    {:.1f}%", hs_completed + hs_failed > 0 ? 
               (hs_completed * 100.0 / (hs_completed + hs_failed)) : 0.0);
    std::println("");
    std::println("--- AUTHENTICATION ---");
    std::println("  Successful:      {}", auth_ok);
    std::println("  Failed:          {}", auth_fail);
    std::println("");
    std::println("--- MESSAGES ---");
    std::println("  Received:        {}", msgs_recv);
    std::println("  Sent:            {}", msgs_sent);
    std::println("  Rate (recv):     {:.1f}/sec", static_cast<double>(msgs_recv) / std::max(uptime, 1L));
    std::println("");
    std::println("--- BANDWIDTH ---");
    std::println("  Received:        {:.2f} MB ({:.2f} KB/s)", mb_recv, mb_recv * 1024.0 / std::max(uptime, 1L));
    std::println("  Sent:            {:.2f} MB ({:.2f} KB/s)", mb_sent, mb_sent * 1024.0 / std::max(uptime, 1L));
    std::println("  Total:           {:.2f} MB", mb_recv + mb_sent);
    std::println("");
    std::println("--- ERRORS ---");
    std::println("  Errors:          {}", err_count);
    std::println("  Timeouts:        {}", timeout_count);
    std::println("============================================================");
    
    LOG_INFO("Metrics: conns={}/{} hs={}/{} auth={}/{} msgs={}/{} errors={}/{} uptime={}s",
             conns_accepted, conns_closed, hs_completed, hs_failed, auth_ok, auth_fail,
             msgs_recv, msgs_sent, err_count, timeout_count, uptime);
}

Server::Server(net::io_context& io, const Config& config)
    : io_ctx(io)
    , acceptor(io, tcp::endpoint(net::ip::make_address(config.server().bind_address), config.server().port))
    , signals(io, SIGINT, SIGTERM)
    , metrics_signals(io, SIGUSR1)
    , config_(config)
{
    acceptor.set_option(net::socket_base::reuse_address(true));
}

void Server::start()
{
    net::co_spawn(io_ctx, do_accept(), net::detached);
    
    // Setup shutdown signals
    signals.async_wait([this](auto, auto sig)
    {
        LOG_INFO("Received signal {}, shutting down...", sig);
        print_metrics();  // Print final metrics on shutdown
        io_ctx.stop();
    });
    
    // Setup metrics signal (SIGUSR1)
    metrics_signals.async_wait([this](boost::system::error_code ec, int sig)
    {
        if (!ec && sig == SIGUSR1)
        {
            print_metrics();
            // Re-register for next signal
            metrics_signals.async_wait([this](boost::system::error_code ec2, int sig2)
            {
                if (!ec2 && sig2 == SIGUSR1)
                {
                    print_metrics();
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
            metrics_.errors++;
            continue;
        }
        
        metrics_.connections_accepted++;
        std::string id = std::format("{}",sock);
        LOG_DEBUG("do_accept: accepted {}, creating connection", id);
        auto conn = std::make_shared<Connection>(std::move(sock), this, id, config_, io_ctx);
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
    if (conn) {
        conn->mark_pipe_dead();
        connections.erase(id);
        metrics_.connections_closed++;
    }
}

void Server::broadcast(const Msg& msg, std::string_view exclude_id)
{
    auto conns = connections.snapshot();
    
    for (auto& conn : conns)
    {
        if (conn->get_id() == exclude_id)
        {
            continue;
        }
        
        if (conn && !conn->is_pipe_dead())
        {
            conn->send_encrypted(msg);
        }
    }
}
