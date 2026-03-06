#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>

#include "fundamentals/types.hpp"
#include "fundamentals/msg_serialize.hpp"
#include "fundamentals/bytes.hpp"

#include <vector>
#include <cstddef>

using namespace bytes;

TEST_CASE("bytes::to_bytes converts string_view to byte vector")
{
    auto result = to_bytes("hello");
    
    REQUIRE(result.size() == 5);
    CHECK(result[0] == std::byte{0x68});
    CHECK(result[1] == std::byte{0x65});
    CHECK(result[2] == std::byte{0x6C});
    CHECK(result[3] == std::byte{0x6C});
    CHECK(result[4] == std::byte{0x6F});
}

TEST_CASE("bytes::to_bytes handles empty string")
{
    auto result = to_bytes("");
    CHECK(result.empty());
}

TEST_CASE("bytes::to_int converts big-endian span to integer")
{
    std::vector<std::byte> data{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}
    };
    
    uint32_t result = to_int(std::span{data});
    
    CHECK(result == 1);
}

TEST_CASE("bytes::to_int converts maximum uint32 value")
{
    std::vector<std::byte> data{
        std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}
    };
    
    uint32_t result = to_int(std::span{data});
    
    CHECK(result == 0xFFFFFFFF);
}

TEST_CASE("Msg type constants correctly identify encryption status")
{
    CHECK(is_encrypted(encrypted_response) == true);
    CHECK(is_encrypted(plaintext_handshake) == false);
    CHECK(is_encrypted(plaintext_error) == false);
}

TEST_CASE("Msg type constants correctly identify semantic types")
{
    CHECK(get_semantic(encrypted_response) == MsgSemantic::Response);
    CHECK(get_semantic(plaintext_handshake) == MsgSemantic::Handshake);
    CHECK(get_semantic(encrypted_request) == MsgSemantic::Request);
    CHECK(get_semantic(encrypted_notify) == MsgSemantic::Notify);
    CHECK(get_semantic(plaintext_error) == MsgSemantic::Error);
}

TEST_CASE("msg::make creates valid message with correct length field")
{
    auto payload = to_bytes("test payload");
    auto result = msg::make(payload, encrypted_request);
    
    REQUIRE(result.has_value());
    CHECK(result->len == payload.size() + 5);
    CHECK(result->type == encrypted_request);
    CHECK(result->payload == payload);
}

TEST_CASE("msg::make rejects oversized payload exceeding maximum")
{
    std::vector<std::byte> oversized(Msg::max_len);
    
    auto result = msg::make(oversized, encrypted_request);
    
    REQUIRE(!result.has_value());
    CHECK(result.error() == Msg::errc::size_err);
}

TEST_CASE("msg::make rejects empty payload for encrypted messages")
{
    std::vector<std::byte> empty_payload;
    
    auto result = msg::make(empty_payload, encrypted_request);
    
    REQUIRE(!result.has_value());
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
    CHECK(serialized[5] == std::byte{0x61});
    CHECK(serialized[6] == std::byte{0x62});
    CHECK(serialized[7] == std::byte{0x63});
}

TEST_CASE("msg::parse validates length field matches actual data")
{
    std::vector<std::byte> data{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
        std::byte{0x01}
    };
    
    auto result = msg::parse(data);
    
    REQUIRE(!result.has_value());
    CHECK(result.error() == Msg::errc::len_verify_err);
}

TEST_CASE("msg::parse validates minimum message size")
{
    std::vector<std::byte> data{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x04},
        std::byte{0x01}
    };
    
    auto result = msg::parse(data);
    
    REQUIRE(!result.has_value());
}

TEST_CASE("msg roundtrip serialization preserves all fields")
{
    auto original_payload = to_bytes("roundtrip test data");
    auto make_result = msg::make(original_payload, encrypted_request);
    
    REQUIRE(make_result.has_value());
    
    auto serialized = msg::serialize(make_result.value());
    auto parse_result = msg::parse(serialized);
    
    REQUIRE(parse_result.has_value());
    CHECK(parse_result->type == encrypted_request);
    CHECK(parse_result->payload == original_payload);
    CHECK(parse_result->len == make_result->len);
}

TEST_CASE("msg::parse handles large payload correctly")
{
    std::vector<std::byte> large_payload(1000, std::byte{0xAB});
    auto make_result = msg::make(large_payload, encrypted_response);
    
    REQUIRE(make_result.has_value());
    
    auto serialized = msg::serialize(make_result.value());
    auto parse_result = msg::parse(serialized);
    
    REQUIRE(parse_result.has_value());
    CHECK(parse_result->payload.size() == 1000);
    CHECK(parse_result->payload == large_payload);
}
