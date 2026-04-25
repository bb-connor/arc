#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "../../chio-cpp/src/json.hpp"

namespace chio {
namespace kernel {
namespace detail {

inline std::optional<std::string> json_string_field(const std::string& json,
                                                    std::string_view key) {
  auto parsed = chio::detail::parse_json(json);
  if (!parsed || !parsed->is_object()) {
    return std::nullopt;
  }
  const auto* value = parsed->get(key);
  if (value == nullptr || !value->is_string()) {
    return std::nullopt;
  }
  return value->as_string();
}

}  // namespace detail
}  // namespace kernel
}  // namespace chio
