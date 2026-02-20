#include "helper.hpp"
#include <string_view>

namespace Hibiscus
{
    Msg::payload_t to_bytes(std::string_view sv)
    {
        return sv | 
            std::views::transform([](char ch){return static_cast<std::byte>(ch);}) |
            std::ranges::to<std::vector<std::byte>>();
    }
    
    Msg::payload_t operator""_b(const char* c,size_t s)
    {
        return to_bytes(std::string_view(c,s));
    }

    Msg get_err(std::string_view errstr)
    {
        static const Msg decay_msg = *Msg::make(Hibiscus::to_bytes("Unknown error"), MsgType::Error);

        return Msg::make(to_bytes(errstr),MsgType::Error).value_or(decay_msg);
    }

    std::byte int2byte(uint8_t i)
    {
        return static_cast<std::byte>(i);
    }
}