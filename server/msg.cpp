#include "server.hpp"
#include "helper.hpp"
#include <ranges>
#include <algorithm>

std::expected<Msg,Msg::errc> Msg::parse(std::span<const std::byte> data)
{
    if(data.size() < 5 || data.size() > max_len)
    {
        return std::unexpected(Msg::errc::size_err);
    }

    uint32_t wire_len = Hibiscus::endify(*reinterpret_cast<const uint32_t*>(data.data())); //...

    if (wire_len != data.size())
    {
        return std::unexpected(Msg::errc::len_verify_err);
    }

    return Msg::create(data | std::views::drop(5), static_cast<MsgType>(data[4]));
}

std::expected<Msg,Msg::errc> Msg::create(std::span<const std::byte> data,MsgType type)
{
    if(data.size() > max_len - 5uz)
    {
        return std::unexpected(Msg::errc::size_err);
    }

    return Msg{.len = static_cast<uint32_t>(data.size() + 5uz),
            .type = std::to_underlying(type),
            .payload = std::ranges::to<payload_t>(data)};
}

Msg::payload_t Msg::serialize() const
{
    payload_t ret(len,{});

    *reinterpret_cast<uint32_t*>(ret.data()) = Hibiscus::endify(len);
    ret[4] = static_cast<std::byte>(type);
    
    std::ranges::copy(payload,ret.data() + 5);
    return ret;
}