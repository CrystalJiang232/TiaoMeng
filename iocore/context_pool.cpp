#include "iocore/context_pool.hpp"
#include "iocore/platform/thread_affinity.hpp"
#include "logger/logger.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <format>
#include <thread>

namespace iocore
{

namespace net = boost::asio;

class ContextPool::Impl
{
public:
    Impl(size_t n_cores, uint16_t port, ConnectionFactory factory)
        : n_cores(n_cores)
        , port(port)
        , factory(std::move(factory))
        , running(false)
    {
        cores.reserve(n_cores);
    }
    
    std::expected<void, ContextPoolError> start()
    {
        if (running)
        {
            return std::unexpected(ContextPoolError::AlreadyStarted);
        }
        
        auto ep = tcp::endpoint(net::ip::address_v4::any(), port);
        
        for (size_t i = 0; i < n_cores; ++i)
        {
            auto core = std::make_unique<CoreContext>();
            core->core_id = i;
            
            // Setup acceptor with SO_REUSEPORT on Linux
            core->acc.open(tcp::v4());
            core->acc.set_option(net::socket_base::reuse_address(true));
            
            #ifdef HAS_SO_REUSEPORT
            int fd = core->acc.native_handle();
            int opt = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
            #endif
            
            boost::system::error_code ec;
            core->acc.bind(ep, ec);
            if (ec)
            {
                LOG_ERROR("Failed to bind acceptor on core {}: {}", i, ec.message());
                return std::unexpected(ContextPoolError::AcceptorBindFailed);
            }
            
            core->acc.listen();
            
            // Start accept loop
            net::co_spawn(core->io, do_accept(core.get()), net::detached);
            
            // Start thread
            core->thd = std::jthread([this, core_ptr = core.get(), i]()
            {
                platform::set_thread_name(std::format("io_core_{}", i).c_str());
                platform::pin_to_core(i);
                core_ptr->io.run();
            });
            
            cores.push_back(std::move(core));
        }
        
        running = true;
        LOG_INFO("ContextPool started with {} cores on port {}", n_cores, port);
        return {};
    }
    
    void stop()
    {
        if (!running)
        {
            return;
        }
        
        for (auto& core : cores)
        {
            core->io.stop();
        }
        
        auto this_id = std::this_thread::get_id();
        for (auto& core : cores)
        {
            if (core->thd.joinable() && core->thd.get_id() != this_id)
            {
                core->thd.join();
            }
        }
        
        running = false;
        LOG_INFO("ContextPool stopped");
    }
    
    net::awaitable<void> do_accept(CoreContext* core)
    {
        while (true)
        {
            auto [ec, sock] = co_await core->acc.async_accept(net::as_tuple(net::use_awaitable));
            if (ec)
            {
                if (ec == net::error::operation_aborted)
                {
                    co_return;
                }
                LOG_WARN("Accept error on core {}: {}", core->core_id, ec.message());
                continue;
            }
            
            auto ep = sock.remote_endpoint();
            LOG_DEBUG("Core {} accepted connection from {}:{}", core->core_id, ep.address().to_string(), ep.port());
            factory(std::move(sock), core->core_id, core->io);
        }
    }
    
    size_t n_cores;
    uint16_t port;
    ConnectionFactory factory;
    std::atomic<bool> running;
    std::vector<std::unique_ptr<CoreContext>> cores;
};

ContextPool::ContextPool(size_t n_cores, uint16_t port, ConnectionFactory factory)
    : impl(std::make_unique<Impl>(n_cores, port, std::move(factory)))
{
}

ContextPool::~ContextPool()
{
    stop();
}

std::expected<void, ContextPoolError> ContextPool::start()
{
    return impl->start();
}

void ContextPool::stop()
{
    impl->stop();
}

bool ContextPool::is_running() const
{
    return impl->running;
}

size_t ContextPool::core_count() const
{
    return impl->n_cores;
}

net::io_context& ContextPool::get_context(size_t core_id)
{
    return impl->cores[core_id]->io;
}

void ContextPool::remove_connection(size_t core_id, std::string_view conn_id)
{
    (void)core_id;
    (void)conn_id;
    // Cleanup if needed
}

} // namespace iocore
