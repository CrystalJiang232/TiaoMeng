#include "threadpool/threadpool.hpp"

ThreadPool::ThreadPool(size_t n_threads)
    : work_guard(net::make_work_guard(pool_ctx))
    , workers(n_threads)
{
    for (auto& t : workers)
    {
        t = std::jthread([this] {pool_ctx.run();});
    }
}

ThreadPool::~ThreadPool()
{
    stop();
}

void ThreadPool::stop()
{
    
    if (bool was_running = running.exchange(false); !was_running)
    {
        return;
    }
    
    work_guard.reset();
    pool_ctx.stop();
    
    for (auto& t : workers)
    {
        if (t.joinable())
        {
            t.join();
        }
    }
}
