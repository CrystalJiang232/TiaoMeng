#pragma once

#include <atomic>
#include <cstdint>

struct MetricsCollector
{
    std::atomic<size_t> ok{0};
    std::atomic<size_t> fail{0};

    void record_ok() { ok.fetch_add(1, std::memory_order_relaxed); }
    void record_fail() { fail.fetch_add(1, std::memory_order_relaxed); }

    [[nodiscard]] size_t ok_count() const { return ok.load(std::memory_order_relaxed); }
    [[nodiscard]] size_t fail_count() const { return fail.load(std::memory_order_relaxed); }
};
