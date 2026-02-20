#pragma once
#include <vector>
#include <expected>
#include <cstdint>
#include <span>

enum class MsgType : uint8_t
{
    Handshake = 0x01,
    Encrypted = 0x02,
    Command = 0x03,
    Broadcast = 0x04,
    Error = 0x05
};

struct Msg
{
    using payload_t = std::vector<std::byte>;

    enum class errc
    {
        OK = 0,
        size_err = 1,
        len_verify_err = 2,
        type_err = 3
    };

    uint32_t len;
    uint8_t type;
    payload_t payload;

    static constexpr size_t max_len = 1024 * 1024;
    
    static std::expected<Msg,errc> parse(std::span<const std::byte>); //Make Msg from parsed data
    static std::expected<Msg,errc> make(std::span<const std::byte>, MsgType = MsgType::Broadcast); //Make Msg from raw data
    payload_t serialize() const;

private:
    struct intern_tag_t {};

    static constexpr inline intern_tag_t intern_tag = {};

    Msg() = default;
    Msg(intern_tag_t, uint32_t total_len, MsgType type, std::span<const std::byte> span); //No verification or check, equiv to direct member assignment/copy
    
    errc validate() const;
};
