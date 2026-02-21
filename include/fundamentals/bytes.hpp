#pragma once
#include <concepts>
#include <bit>
#include <span>
#include <vector>
#include <cstring>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <ranges>

namespace bytes
{

inline std::byte int2byte(uint8_t i)
{
    return static_cast<std::byte>(i);
}

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

template<std::integral Ty = uint32_t>
Ty to_int(std::span<const std::byte> from)
{
    Ty ret = 0;
    std::memcpy(std::addressof(ret), from.data(), sizeof(Ty));
    return endify(ret);
}

template<class To, std::integral From>
void from_int(std::span<To> to, From val)
{
    val = endify(val);
    std::memcpy(to.data(), std::addressof(val), sizeof(From));
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

// Overload for string_view
inline std::vector<std::byte> to_bytes(std::string_view sv)
{
    return sv | 
        std::views::transform([](char ch){ return int2byte(static_cast<uint8_t>(ch)); }) |
        std::ranges::to<std::vector<std::byte>>();
}

} // namespace bytes
