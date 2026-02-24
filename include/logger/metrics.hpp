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
        connections_accepted = 0;
        connections_closed = 0;
        handshakes_completed = 0;
        handshakes_failed = 0;
        authentications_successful = 0;
        authentications_failed = 0;
        messages_received = 0;
        messages_sent = 0;
        bytes_received = 0;
        bytes_sent = 0;
        errors = 0;
        timeouts = 0;
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
        
        uint64_t conns_accepted = s.connections_accepted.load();
        uint64_t conns_closed = s.connections_closed.load();
        uint64_t hs_completed = s.handshakes_completed.load();
        uint64_t hs_failed = s.handshakes_failed.load();
        uint64_t auth_ok = s.authentications_successful.load();
        uint64_t auth_fail = s.authentications_failed.load();
        uint64_t msgs_recv = s.messages_received.load();
        uint64_t msgs_sent = s.messages_sent.load();
        uint64_t bytes_recv = s.bytes_received.load();
        uint64_t bytes_sent_total = s.bytes_sent.load();
        uint64_t err_count = s.errors.load();
        uint64_t timeout_count = s.timeouts.load();
        
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