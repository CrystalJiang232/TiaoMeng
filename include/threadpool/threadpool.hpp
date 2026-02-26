#pragma once

#include <boost/asio.hpp>
#include <thread>
#include <vector>
#include <optional>
#include <expected>
#include <future>
#include <atomic>
#include <memory>
#include <string>

namespace net = boost::asio;

class ThreadPool
{
public:
    explicit ThreadPool(size_t n_threads);
    ~ThreadPool();
    
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;
    
    template<class Fn>
    auto submit(Fn&& fn) -> std::expected<std::invoke_result_t<Fn>, std::string>
    {
        using Ret = std::invoke_result_t<Fn>;
        
        if (!running)
        {
            return std::unexpected("ThreadPool stopped");
        }
        
        std::packaged_task<Ret()> task(std::forward<Fn>(fn));
        auto fut = task.get_future();
        
        net::post(pool_exec, [t = std::make_shared<std::packaged_task<Ret()>>(std::move(task))] { std::invoke(*t); });
        
        return fut.get();
    }
    
    net::any_io_executor get_executor() const { return pool_exec; }
    size_t size() const { return workers.size(); }
    void stop();

private:
    net::io_context pool_ctx;
    net::executor_work_guard<net::io_context::executor_type> work_guard;
    std::vector<std::jthread> workers;
    std::atomic<bool> running{true};
    
    net::any_io_executor pool_exec{pool_ctx.get_executor()};
};
