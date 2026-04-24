#pragma once

#include <cstddef>
#include <optional>
#include <string>

namespace chio {
namespace kernel {
namespace detail {

inline bool is_hex_digit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

inline std::optional<std::string> json_string_field(const std::string& json,
                                                    const std::string& key) {
  const std::string needle = "\"" + key + "\":";
  std::size_t pos = json.find(needle);
  if (pos == std::string::npos) {
    return std::nullopt;
  }
  pos += needle.size();
  while (pos < json.size() &&
         (json[pos] == ' ' || json[pos] == '\n' || json[pos] == '\r' ||
          json[pos] == '\t')) {
    ++pos;
  }
  if (pos >= json.size() || json[pos] != '"') {
    return std::nullopt;
  }
  ++pos;
  std::string out;
  while (pos < json.size()) {
    char c = json[pos++];
    if (c == '"') {
      return out;
    }
    if (c == '\\') {
      if (pos >= json.size()) {
        return std::nullopt;
      }
      char escaped = json[pos++];
      switch (escaped) {
        case '"':
        case '\\':
        case '/':
          out.push_back(escaped);
          break;
        case 'b':
          out.push_back('\b');
          break;
        case 'f':
          out.push_back('\f');
          break;
        case 'n':
          out.push_back('\n');
          break;
        case 'r':
          out.push_back('\r');
          break;
        case 't':
          out.push_back('\t');
          break;
        case 'u':
          if (pos + 4 > json.size()) {
            return std::nullopt;
          }
          for (std::size_t offset = 0; offset < 4; ++offset) {
            if (!is_hex_digit(json[pos + offset])) {
              return std::nullopt;
            }
          }
          out += "\\u";
          out.append(json.substr(pos, 4));
          pos += 4;
          break;
        default:
          return std::nullopt;
      }
      continue;
    }
    if (static_cast<unsigned char>(c) < 0x20) {
      return std::nullopt;
    }
    out.push_back(c);
  }
  return std::nullopt;
}

}  // namespace detail
}  // namespace kernel
}  // namespace chio
