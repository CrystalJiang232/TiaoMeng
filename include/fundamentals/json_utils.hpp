#pragma once
#include <boost/json.hpp>
#include <string>
#include <string_view>
#include <expected>

namespace json_utils
{

inline boost::json::object status_msg(std::string_view status, std::string_view msg)
{
    return boost::json::object{
        {"status", status},
        {"message", msg}
    };
}

inline std::expected<std::string, std::string> extract_str(const boost::json::object& obj, std::string_view key)
{
    auto it = obj.find(key);
    if (it == obj.end())
    {
        return std::unexpected(std::format("\"{}\" field required", key));
    }
    if (!it->value().is_string())
    {
        return std::unexpected(std::format("\"{}\" must be a string", key));
    }

    return static_cast<std::string>(it->value().as_string());
}

} // namespace json_utils
