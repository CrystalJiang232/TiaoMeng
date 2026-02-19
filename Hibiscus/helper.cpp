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
    
    std::optional<Msg> decrypt(const Msg& encrypted_msg, std::span<const uint8_t> key)
    {
        // TODO: Implement actual AES-GCM decryption
        // For now, just pass through the payload as-is (placeholder)
        (void)key;
        
        // Parse the decrypted payload as a message
        std::span<const std::byte> payload_span(encrypted_msg.payload);
        auto result = Msg::parse(payload_span);
        if (!result) 
        {
            std::println("Decryption Error occur!");
            return std::nullopt;
        }
        return *result;
    }
}