#pragma once
#include <concepts>
#include <bit>
#include <vector>
#include <algorithm>
#include <ranges>
#include <format>

#include "server.hpp"

namespace Hibiscus
{
    std::byte int2byte(uint8_t);

    constexpr auto endify(std::integral auto i)
    {
        if constexpr(std::endian::native == std::endian::little)
        {
            return std::byteswap(i);
        }
        else
        {
            return i;
        }
    }

    Msg::payload_t to_bytes(std::string_view);
    std::vector<std::byte> operator""_b(const char*, size_t);

    template<std::integral Ty = uint32_t>
    Ty to_int(std::span<const std::byte> from)
    {
        Ty ret = 0;
        std::memcpy(std::addressof(ret),from.data(),sizeof(Ty));
        return endify(ret);
    }

    template<class To,std::integral From>
    void from_int(std::span<To> to, From val)
    {
        val = endify(val);
        std::memcpy(to.data(),std::addressof(val),sizeof(From));
    }

    template<class From, class To>
    concept cast_toenum = requires
    {
        requires std::is_trivial_v<From> && std::is_enum_v<To>;
        {static_cast<To>(std::declval<From>())} -> std::same_as<To>;        
    };

    template<cast_toenum<std::byte> Ty>
    std::vector<std::byte> to_bytes(std::span<std::add_const_t<std::remove_cvref_t<Ty>>> sv)
    {
        return sv | 
        std::views::transform(int2byte) |
        std::ranges::to<std::vector<std::byte>>();
    }

    boost::json::object status_msg(std::string_view status, std::string_view msg);

    std::expected<std::string, std::string> extract_str(const boost::json::object& obj, std::string_view key);
}
