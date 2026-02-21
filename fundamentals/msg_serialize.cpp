#include "fundamentals/types.hpp"
#include "fundamentals/bytes.hpp"
#include <ranges>
#include <algorithm>
#include <expected>

namespace msg
{

using namespace bytes;

std::expected<Msg, Msg::errc> parse(std::span<const std::byte> data)
{
    struct MsgConstructor : public Msg
    {
        MsgConstructor(uint32_t total_len, MsgType ty, std::span<const std::byte> sp)
        {
            len = total_len;
            type = ty;
            payload = sp | std::ranges::to<payload_t>();
        }
    };

    if (data.size() < 5)
    {
        return std::unexpected(Msg::errc::size_err);
    }

    uint32_t len = to_int(data);
    MsgType type = static_cast<MsgType>(data[4]);
    
    Msg msg = MsgConstructor(len, type, data | std::views::drop(5));
    
    // Validate
    if (msg.len != msg.payload.size() + 5)
    {
        return std::unexpected(Msg::errc::len_verify_err);
    }
    
    if (msg.payload.size() == 0 || msg.payload.size() > Msg::max_len - 5)
    {
        return std::unexpected(Msg::errc::size_err);
    }
    
    return msg;
}

std::expected<Msg, Msg::errc> make(std::span<const std::byte> data, MsgType type)
{
    if (data.size() == 0 || data.size() > Msg::max_len - 5)
    {
        return std::unexpected(Msg::errc::size_err);
    }

    struct MsgConstructor : public Msg
    {
        MsgConstructor(uint32_t total_len, MsgType ty, std::span<const std::byte> sp)
        {
            len = total_len;
            type = ty;
            payload = sp | std::ranges::to<payload_t>();
        }
    };

    Msg msg = MsgConstructor(data.size() + 5, type, data);
    return msg;
}

Msg::payload_t serialize(const Msg& msg)
{
    Msg::payload_t ret(msg.len, std::byte{});

    from_int<std::byte>(ret, msg.len);
    ret[4] = static_cast<std::byte>(msg.type);

    std::ranges::copy(msg.payload, ret.data() + 5);
    return ret;
}

} // namespace msg
