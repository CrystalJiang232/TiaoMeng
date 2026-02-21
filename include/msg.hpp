#pragma once
#include <vector>
#include <expected>
#include <cstdint>
#include <span>

// MsgType is now a bit-flag format:
// [7] Encrypted flag: 0=Plaintext (Handshake only), 1=Encrypted (others)
// [3-0] Semantic: See MsgSemantic enum
using MsgType = uint8_t;

enum class MsgSemantic : uint8_t
{
    Control   = 0x00,  // 0: Control messages
    Handshake = 0x01,  // 1: Handshake messages
    Session   = 0x02,  // 2: Session management
    Request   = 0x03,  // 3: Client requests
    Response  = 0x04,  // 4: Server responses
    Notify    = 0x05,  // 5: Server notifications
    Error     = 0x06,  // 6: Error messages
};

// Bit flag constants
constexpr MsgType encrypted_flag = 0x80;  // bit 7
constexpr MsgType semantic_mask  = 0x0F;  // bits 3-0

// constexpr helpers
constexpr bool is_encrypted(MsgType type) { return (type & encrypted_flag) != 0; }
constexpr MsgSemantic get_semantic(MsgType type) { return static_cast<MsgSemantic>(type & semantic_mask); }
constexpr MsgType make_type(bool encrypted, MsgSemantic semantic) 
{ 
    return (encrypted ? encrypted_flag : 0) | static_cast<MsgType>(semantic); 
}

// Convenience constants for common message types
constexpr MsgType plaintext_handshake = make_type(false, MsgSemantic::Handshake);
constexpr MsgType encrypted_response  = make_type(true, MsgSemantic::Response);
constexpr MsgType encrypted_request   = make_type(true, MsgSemantic::Request);
constexpr MsgType encrypted_notify    = make_type(true, MsgSemantic::Notify);
constexpr MsgType encrypted_error     = make_type(true, MsgSemantic::Error);

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
    MsgType type;
    payload_t payload;

    static constexpr size_t max_len = 1024 * 1024;
    
    static std::expected<Msg,errc> parse(std::span<const std::byte>); //Make Msg from parsed data
    static std::expected<Msg,errc> make(std::span<const std::byte>, MsgType type = encrypted_notify); //Make Msg from raw data
    payload_t serialize() const;

private:
    struct intern_tag_t {};

    static constexpr inline intern_tag_t intern_tag = {};

    Msg() = default;
    Msg(intern_tag_t, uint32_t total_len, MsgType type, std::span<const std::byte> span); //No verification or check, equiv to direct member assignment/copy
    
    errc validate() const;
};
