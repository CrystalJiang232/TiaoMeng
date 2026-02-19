#include "server.hpp"
#include "helper.hpp"
#include <ranges>
#include <algorithm>

std::expected<Msg,Msg::errc> Msg::parse(std::span<const std::byte> data)
{
    Msg ret(Msg::intern_tag, Hibiscus::to_int(data), static_cast<MsgType>(data[4]), data | std::views::drop(5));
    if(auto ec = ret.validate(); ec != Msg::errc::OK)
    {
        return std::unexpected(ec);
    }
    return ret;
}

std::expected<Msg,Msg::errc> Msg::make(std::span<const std::byte> data,MsgType type)
{
    Msg ret(Msg::intern_tag, data.size() + 5uz, type, data);
    if(auto ec = ret.validate(); ec != Msg::errc::OK)
    {
        return std::unexpected(ec);
    }
    return ret;
}

Msg::payload_t Msg::serialize() const
{
    payload_t ret(len,{});

    Hibiscus::from_int(ret,len);
    ret[4] = static_cast<std::byte>(type);

    std::ranges::copy(payload,ret.data() + 5uz);
    return ret;
}

Msg::errc Msg::validate() const
{
    static_assert(Msg::errc{} == Msg::errc::OK);

    if (len != payload.size() + 5uz)
    {
        return Msg::errc::len_verify_err;
    }

    if(payload.size() == 0uz || payload.size() > max_len - 5uz)
    {
        return Msg::errc::size_err;
    }

    return Msg::errc::OK;
}

Msg::Msg(Msg::intern_tag_t, uint32_t ttl, MsgType ty, std::span<const std::byte> sp)
: len(ttl), type(std::to_underlying(ty)), payload(sp | std::ranges::to<payload_t>())
{

}