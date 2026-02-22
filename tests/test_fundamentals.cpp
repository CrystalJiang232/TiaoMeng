#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>

#include "fundamentals/types.hpp"
#include "fundamentals/msg_serialize.hpp"
#include "fundamentals/bytes.hpp"

#include <vector>
#include <cstddef>

using namespace bytes;

TEST_CASE("bytes::to_bytes converts string_view correctly")
{
    auto result = to_bytes("hello");
    
    REQUIRE(result.size() == 5);
    CHECK(result[0] == std::byte{0x68});
    CHECK(result[1] == std::byte{0x65});
    CHECK(result[2] == std::byte{0x6C});
    CHECK(result[3] == std::byte{0x6C});
    CHECK(result[4] == std::byte{0x6F});
}

TEST_CASE("bytes::to_int converts span to integer with endianness")
{
    std::vector<std::byte> data
    {
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}
    };
    
    uint32_t result = to_int(std::span{data});
    
    CHECK(result == 1);
}

TEST_CASE("Msg type constants are correctly composed")
{
    CHECK(is_encrypted(encrypted_response) == true);
    CHECK(is_encrypted(plaintext_handshake) == false);
    CHECK(get_semantic(encrypted_response) == MsgSemantic::Response);
    CHECK(get_semantic(plaintext_handshake) == MsgSemantic::Handshake);
}

TEST_CASE("msg::make creates valid message with correct length")
{
    auto payload = to_bytes("test payload");
    auto result = msg::make(payload, encrypted_request);
    
    REQUIRE(result.has_value());
    CHECK(result->len == payload.size() + 5);
    CHECK(result->type == encrypted_request);
    CHECK(result->payload == payload);
}

TEST_CASE("msg::make rejects oversized payload")
{
    std::vector<std::byte> oversized(Msg::max_len);
    
    auto result = msg::make(oversized, encrypted_request);
    
    REQUIRE(!result.has_value());
    CHECK(result.error() == Msg::errc::size_err);
}

TEST_CASE("msg::serialize produces correct wire format")
{
    auto payload = to_bytes("abc");
    auto msg_result = msg::make(payload, encrypted_notify);
    
    REQUIRE(msg_result.has_value());
    
    auto serialized = msg::serialize(msg_result.value());
    
    REQUIRE(serialized.size() == 8);
    CHECK(serialized[0] == std::byte{0x00});
    CHECK(serialized[1] == std::byte{0x00});
    CHECK(serialized[2] == std::byte{0x00});
    CHECK(serialized[3] == std::byte{0x08});
    CHECK(std::to_integer<uint8_t>(serialized[4]) == encrypted_notify);
}

TEST_CASE("msg::parse validates length field")
{
    std::vector<std::byte> data
    {
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
        std::byte{0x01}
    };
    
    auto result = msg::parse(data);
    
    REQUIRE(!result.has_value());
    CHECK(result.error() == Msg::errc::len_verify_err);
}

TEST_CASE("msg roundtrip preserves data")
{
    auto original_payload = to_bytes("roundtrip test data");
    auto make_result = msg::make(original_payload, encrypted_request);
    
    REQUIRE(make_result.has_value());
    
    auto serialized = msg::serialize(make_result.value());
    auto parse_result = msg::parse(serialized);
    
    REQUIRE(parse_result.has_value());
    CHECK(parse_result->type == encrypted_request);
    CHECK(parse_result->payload == original_payload);
}
