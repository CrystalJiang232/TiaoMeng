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

    Msg unknown_error_msg();

    template<std::integral Ty = uint32_t>
    Ty to_int(std::span<const std::byte> from)
    {
        Ty ret = 0;
        std::memcpy(std::addressof(ret),from.data(),sizeof(Ty));
        return endify(ret);
    }

    template<std::integral Ty = uint32_t>
    void from_int(std::span<std::byte> to, Ty val)
    {
        val = endify(val);
        std::memcpy(to.data(),std::addressof(val),sizeof(Ty));
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
        std::views::transform([](auto&& ch){return static_cast<std::byte>(ch);}) |
        std::ranges::to<std::vector<std::byte>>();
    }

    Msg get_err(std::string_view errstr); //Fallback enabled
    
    // Decrypt message using session key (placeholder - implement actual AES-GCM or similar)
    std::optional<Msg> decrypt(const Msg& encrypted_msg, std::span<const uint8_t> key);
}
