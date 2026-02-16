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
}
