#include "iocore/context_pool.hpp"
#include "iocore/platform/thread_affinity.hpp"
#include "logger/logger.hpp"

#include <boost/asio/co_spawn.hpp>
#include <cerrno>
#include <exception>
#include <format>
#include <experimental/scope>
#include <system_error>
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
            if (running.load(std::memory_order_acquire))
            {
                return std::unexpected(ContextPoolError::AlreadyStarted);
            }

            auto ep       = tcp::endpoint(net::ip::address_v4::any(), port);
            auto rollback = std::experimental::scope_exit(
                [this]()
                {
                    stop_cores(true);
                });

            for (size_t i = 0; i < n_cores; ++i)
            {
                auto core     = std::make_unique<CoreContext>();
                core->core_id = i;

                // Setup acceptor with SO_REUSEPORT on Linux
                boost::system::error_code ec;
                core->acc.open(tcp::v4(), ec);
                if (ec)
                {
                    LOG_ERROR("Failed to open acceptor on core {}: {}", i, ec.message());
                    return std::unexpected(ContextPoolError::AcceptorBindFailed);
                }
                core->acc.set_option(net::socket_base::reuse_address(true), ec);
                if (ec)
                {
                    LOG_ERROR("Failed to configure acceptor on core {}: {}", i, ec.message());
                    return std::unexpected(ContextPoolError::AcceptorBindFailed);
                }

#ifdef HAS_SO_REUSEPORT
                int fd  = core->acc.native_handle();
                int opt = 1;
                if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) != 0)
                {
                    LOG_ERROR("Failed to configure SO_REUSEPORT on core {}: errno {}", i, errno);
                    return std::unexpected(ContextPoolError::AcceptorBindFailed);
                }
#endif

                core->acc.bind(ep, ec);
                if (ec)
                {
                    LOG_ERROR("Failed to bind acceptor on core {}: {}", i, ec.message());
                    return std::unexpected(ContextPoolError::AcceptorBindFailed);
                }

                core->acc.listen(net::socket_base::max_listen_connections, ec);
                if (ec)
                {
                    LOG_ERROR("Failed to listen on core {}: {}", i, ec.message());
                    return std::unexpected(ContextPoolError::AcceptorBindFailed);
                }

                cores.push_back(std::move(core));
                auto* core_ptr = cores.back().get();

                // Start accept loop
                net::co_spawn(core_ptr->io, do_accept(core_ptr),
                              [core_id = core_ptr->core_id](std::exception_ptr error) noexcept
                              {
                                  if (!error)
                                  {
                                      return;
                                  }
                                  try
                                  {
                                      try
                                      {
                                          std::rethrow_exception(error);
                                      }
                                      catch (const std::exception& e)
                                      {
                                          LOG_ERROR("[ACCEPT] Core {} coroutine terminated: {}", core_id, e.what());
                                      }
                                      catch (...)
                                      {
                                          LOG_ERROR("[ACCEPT] Core {} coroutine terminated with an unknown error",
                                                    core_id);
                                      }
                                  }
                                  catch (...)
                                  {
                                  }
                              });

                // Start thread
                try
                {
                    core_ptr->thd = std::jthread(
                        [core_ptr, i]()
                        {
                            platform::set_thread_name(std::format("io_core_{}", i).c_str());
                            platform::pin_to_core(i);
                            core_ptr->io.run();
                        });
                }
                catch (const std::system_error& e)
                {
                    LOG_ERROR("Failed to create thread for core {}: {}", i, e.what());
                    return std::unexpected(ContextPoolError::ThreadCreateFailed);
                }
            }

            running.store(true, std::memory_order_release);
            rollback.release();
            LOG_INFO("ContextPool started with {} cores on port {}", n_cores, port);
            return {};
        }

        void stop_cores(bool clear_cores)
        {
            for (auto& core : cores)
            {
                boost::system::error_code ec;
                core->acc.cancel(ec);
                core->acc.close(ec);
                core->io.stop();
            }

            auto this_id            = std::this_thread::get_id();
            bool called_from_worker = false;
            for (auto& core : cores)
            {
                if (!core->thd.joinable())
                {
                    continue;
                }
                if (core->thd.get_id() == this_id)
                {
                    called_from_worker = true;
                    continue;
                }
                core->thd.join();
            }

            if (clear_cores && !called_from_worker)
            {
                cores.clear();
            }
            running.store(false, std::memory_order_release);
        }

        void stop()
        {
            if (!running.load(std::memory_order_acquire) && cores.empty())
            {
                return;
            }

            stop_cores(false);
            LOG_INFO("ContextPool stopped");
        }

        net::awaitable<void> do_accept(CoreContext* core)
        {
            size_t accept_count = 0;
            while (true)
            {
                auto [ec, sock] = co_await core->acc.async_accept(net::as_tuple(net::use_awaitable));
                if (ec)
                {
                    if (ec == net::error::operation_aborted)
                    {
                        LOG_INFO("[ACCEPT] Core {} shutting down, accepted {} total", core->core_id, accept_count);
                        co_return;
                    }
                    LOG_WARN("[ACCEPT] Core {} error: {}", core->core_id, ec.message());
                    continue;
                }

                accept_count++;
                boost::system::error_code endpoint_ec;
                auto                      endpoint = sock.remote_endpoint(endpoint_ec);
                if (endpoint_ec)
                {
                    LOG_WARN("[ACCEPT] Core {} could not inspect peer for accept #{}: {} ({})", core->core_id,
                             accept_count, endpoint_ec.message(), endpoint_ec.value());
                    continue;
                }

                LOG_DEBUG("[ACCEPT] Core {} validated accept #{:4}", core->core_id, accept_count);
                factory(std::move(sock), endpoint, core->core_id, core->io);
            }
        }

        size_t                                    n_cores;
        uint16_t                                  port;
        ConnectionFactory                         factory;
        std::atomic<bool>                         running;
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
        return impl->running.load(std::memory_order_acquire);
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
