#include "helper.hpp"

namespace Hibiscus
{
    std::vector<std::byte> to_bytes(std::string_view sv)
    {
        return sv | 
        std::views::transform([](char ch){return static_cast<std::byte>(ch);}) |
        std::ranges::to<std::vector<std::byte>>();
    }

    Msg::payload_t operator""_b(const char* c,size_t s)
    {
        return to_bytes(std::string_view(c,s));
    }

    Msg unknown_error_msg()
    {
        return *Msg::create("Unknown Error"_b); //Force create
    }
}