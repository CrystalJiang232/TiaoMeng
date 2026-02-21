#pragma once
#include "fundamentals/types.hpp"
#include <span>
#include <expected>

namespace msg
{

std::expected<Msg, Msg::errc> parse(std::span<const std::byte> data);
std::expected<Msg, Msg::errc> make(std::span<const std::byte> data, MsgType type);
Msg::payload_t serialize(const Msg& msg);

} // namespace msg
