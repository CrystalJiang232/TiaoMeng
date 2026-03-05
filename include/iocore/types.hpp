#pragma once

#include <boost/asio.hpp>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

namespace iocore
{

namespace net = boost::asio;
using tcp = net::ip::tcp;

// Forward declarations
class CoreConnection;

// Per-core context structure
struct CoreContext
{
    size_t core_id;
    net::io_context io;
    tcp::acceptor acc{io};
    std::vector<std::weak_ptr<CoreConnection>> conns;
    std::jthread thd;
};

} // namespace iocore
