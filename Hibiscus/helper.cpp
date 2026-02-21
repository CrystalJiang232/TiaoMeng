#include "helper.hpp"
#include <string_view>

namespace Hibiscus
{
    Msg::payload_t to_bytes(std::string_view sv)
    {
        return sv | 
            std::views::transform([](char ch){ return int2byte(static_cast<uint8_t>(ch)); }) |
            std::ranges::to<Msg::payload_t>();
    }
    
    Msg::payload_t operator""_b(const char* c,size_t s)
    {
        return to_bytes(std::string_view(c,s));
    }

    // Raw error message, non-encrypted
    Msg get_err(std::string_view errstr)
    {
        static const Msg decay_msg = *Msg::make(Hibiscus::to_bytes("Unknown error"), encrypted_error);

        return Msg::make(to_bytes(errstr), encrypted_error).value_or(decay_msg);
    }

    std::byte int2byte(uint8_t i)
    {
        return static_cast<std::byte>(i);
    }

    boost::json::object status_msg(std::string_view status, std::string_view msg)
    {
        return boost::json::object{
            {"status", status},
            {"message", msg}
        };
    }

    std::expected<std::string, std::string> extract_str(const boost::json::object& obj, std::string_view key)
    {
        auto it = obj.find(key);
        if(it == obj.end())
        {
            return std::unexpected(std::format("\"{}\" field required", key));
        }
        if(!it->value().is_string())
        {
            return std::unexpected(std::format("\"{}\" must be a string", key));
        }

        return static_cast<std::string>(it->value().as_string());
    }
}