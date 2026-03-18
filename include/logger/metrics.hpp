#pragma once
#include <atomic>
#include <chrono>
#include <algorithm>
#include <ranges>
#include <print>

struct ServerMetrics
{
    std::atomic<uint64_t> connections_accepted{0};
    std::atomic<uint64_t> connections_closed{0};
    std::atomic<uint64_t> handshakes_completed{0};
    std::atomic<uint64_t> handshakes_failed{0};
    std::atomic<uint64_t> authentications_successful{0};
    std::atomic<uint64_t> authentications_failed{0};
    std::atomic<uint64_t> messages_received{0};
    std::atomic<uint64_t> messages_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> errors{0};
    std::atomic<uint64_t> timeouts{0};
    
    std::chrono::steady_clock::time_point start_time{std::chrono::steady_clock::now()};
    
    ServerMetrics() = default;
    
    void reset()
    {
        start_time = std::chrono::steady_clock::now();
        connections_accepted.store(0, std::memory_order_release);
        connections_closed.store(0, std::memory_order_release);
        handshakes_completed.store(0, std::memory_order_release);
        handshakes_failed.store(0, std::memory_order_release);
        authentications_successful.store(0, std::memory_order_release);
        authentications_failed.store(0, std::memory_order_release);
        messages_received.store(0, std::memory_order_release);
        messages_sent.store(0, std::memory_order_release);
        bytes_received.store(0, std::memory_order_release);
        bytes_sent.store(0, std::memory_order_release);
        errors.store(0, std::memory_order_release);
        timeouts.store(0, std::memory_order_release);
    }

    [[nodiscard]] uint64_t get_connections_accepted(bool precise = false) const
    {
        return connections_accepted.load(precise ? std::memory_order_acquire : std::memory_order_relaxed);
    }

    void inc_connections_accepted()
    {
        connections_accepted.fetch_add(1, std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get_connections_closed(bool precise = false) const
    {
        return connections_closed.load(precise ? std::memory_order_acquire : std::memory_order_relaxed);
    }

    void inc_connections_closed()
    {
        connections_closed.fetch_add(1, std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get_handshakes_completed(bool precise = false) const
    {
        return handshakes_completed.load(precise ? std::memory_order_acquire : std::memory_order_relaxed);
    }

    void inc_handshakes_completed()
    {
        handshakes_completed.fetch_add(1, std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get_handshakes_failed(bool precise = false) const
    {
        return handshakes_failed.load(precise ? std::memory_order_acquire : std::memory_order_relaxed);
    }

    void inc_handshakes_failed()
    {
        handshakes_failed.fetch_add(1, std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get_authentications_successful(bool precise = false) const
    {
        return authentications_successful.load(precise ? std::memory_order_acquire : std::memory_order_relaxed);
    }

    void inc_authentications_successful()
    {
        authentications_successful.fetch_add(1, std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get_authentications_failed(bool precise = false) const
    {
        return authentications_failed.load(precise ? std::memory_order_acquire : std::memory_order_relaxed);
    }

    void inc_authentications_failed()
    {
        authentications_failed.fetch_add(1, std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get_messages_received(bool precise = false) const
    {
        return messages_received.load(precise ? std::memory_order_acquire : std::memory_order_relaxed);
    }

    void inc_messages_received()
    {
        messages_received.fetch_add(1, std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get_messages_sent(bool precise = false) const
    {
        return messages_sent.load(precise ? std::memory_order_acquire : std::memory_order_relaxed);
    }

    void inc_messages_sent()
    {
        messages_sent.fetch_add(1, std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get_bytes_received(bool precise = false) const
    {
        return bytes_received.load(precise ? std::memory_order_acquire : std::memory_order_relaxed);
    }

    void add_bytes_received(uint64_t bytes)
    {
        bytes_received.fetch_add(bytes, std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get_bytes_sent(bool precise = false) const
    {
        return bytes_sent.load(precise ? std::memory_order_acquire : std::memory_order_relaxed);
    }

    void add_bytes_sent(uint64_t bytes)
    {
        bytes_sent.fetch_add(bytes, std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get_errors(bool precise = false) const
    {
        return errors.load(precise ? std::memory_order_acquire : std::memory_order_relaxed);
    }

    void inc_errors()
    {
        errors.fetch_add(1, std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get_timeouts(bool precise = false) const
    {
        return timeouts.load(precise ? std::memory_order_acquire : std::memory_order_relaxed);
    }

    void inc_timeouts()
    {
        timeouts.fetch_add(1, std::memory_order_relaxed);
    }

    void print() const;
};

template<>
struct std::formatter<ServerMetrics>
{
    constexpr auto parse(std::format_parse_context& fpc)
    {
        return fpc.begin();
    }

    auto format(const ServerMetrics& s, std::format_context& fc) const
    {
        auto now = std::chrono::steady_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - s.start_time).count();
        
        uint64_t conns_accepted = s.get_connections_accepted();
        uint64_t conns_closed = s.get_connections_closed();
        uint64_t hs_completed = s.get_handshakes_completed();
        uint64_t hs_failed = s.get_handshakes_failed();
        uint64_t auth_ok = s.get_authentications_successful();
        uint64_t auth_fail = s.get_authentications_failed();
        uint64_t msgs_recv = s.get_messages_received();
        uint64_t msgs_sent = s.get_messages_sent();
        uint64_t bytes_recv = s.get_bytes_received();
        uint64_t bytes_sent_total = s.get_bytes_sent();
        uint64_t err_count = s.get_errors();
        uint64_t timeout_count = s.get_timeouts();
        
        constexpr double MB = static_cast<double>(1024 * 1024);

        double uptime_hours = uptime / 3600.0;
        double mb_recv = bytes_recv / MB;
        double mb_sent = bytes_sent_total / MB;

        std::vector<std::string> lines;
        
        lines.push_back(std::format(""));
        lines.push_back(std::format("============================================================"));
        lines.push_back(std::format("SERVER METRICS REPORT"));
        lines.push_back(std::format("============================================================"));
        lines.push_back(std::format("Uptime: {}s ({:.2f}h)", uptime, uptime_hours));
        lines.push_back(std::format(""));
        lines.push_back(std::format("--- CONNECTIONS ---"));
        lines.push_back(std::format("  Accepted:        {}", conns_accepted));
        lines.push_back(std::format("  Closed:          {}", conns_closed));
        lines.push_back(std::format("  Active:          {}", conns_accepted - conns_closed));
        lines.push_back(std::format("  Accept Rate:     {:.1f}/min", conns_accepted * 60.0 / std::max(uptime, 1L)));
        lines.push_back(std::format(""));
        lines.push_back(std::format("--- HANDSHAKES ---"));
        lines.push_back(std::format("  Completed:       {}", hs_completed));
        lines.push_back(std::format("  Failed:          {}", hs_failed));
        lines.push_back(std::format("  Success Rate:    {:.1f}%", hs_completed + hs_failed > 0 ? 
                    (hs_completed * 100.0 / (hs_completed + hs_failed)) : 0.0));
        lines.push_back(std::format(""));
        lines.push_back(std::format("--- AUTHENTICATION ---"));
        lines.push_back(std::format("  Successful:      {}", auth_ok));
        lines.push_back(std::format("  Failed:          {}", auth_fail));
        lines.push_back(std::format(""));
        lines.push_back(std::format("--- MESSAGES ---"));
        lines.push_back(std::format("  Received:        {}", msgs_recv));
        lines.push_back(std::format("  Sent:            {}", msgs_sent));
        lines.push_back(std::format("  Rate (recv):     {:.1f}/sec", static_cast<double>(msgs_recv) / std::max(uptime, 1L)));
        lines.push_back(std::format(""));
        lines.push_back(std::format("--- BANDWIDTH ---"));
        lines.push_back(std::format("  Received:        {:.2f} MB ({:.2f} KB/s)", mb_recv, mb_recv * 1024.0 / std::max(uptime, 1L)));
        lines.push_back(std::format("  Sent:            {:.2f} MB ({:.2f} KB/s)", mb_sent, mb_sent * 1024.0 / std::max(uptime, 1L)));
        lines.push_back(std::format("  Total:           {:.2f} MB", mb_recv + mb_sent));
        lines.push_back(std::format(""));
        lines.push_back(std::format("--- ERRORS ---"));
        lines.push_back(std::format("  Errors:          {}", err_count));
        lines.push_back(std::format("  Timeouts:        {}", timeout_count));
        lines.push_back(std::format("============================================================"));

        return std::ranges::copy(lines | std::views::join_with('\n'), fc.out()).out;
    }
};