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

inline void skip_json_ws(const std::string& json, std::size_t& pos) {
  while (pos < json.size() &&
         (json[pos] == ' ' || json[pos] == '\n' || json[pos] == '\r' ||
          json[pos] == '\t')) {
    ++pos;
  }
}

inline std::optional<std::string> parse_json_string_token(const std::string& json,
                                                          std::size_t& pos) {
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

inline bool skip_json_value(const std::string& json, std::size_t& pos) {
  skip_json_ws(json, pos);
  if (pos >= json.size()) {
    return false;
  }
  if (json[pos] == '"') {
    return parse_json_string_token(json, pos).has_value();
  }
  if (json[pos] == '{' || json[pos] == '[') {
    std::string stack;
    stack.push_back(json[pos] == '{' ? '}' : ']');
    ++pos;
    while (pos < json.size() && !stack.empty()) {
      if (json[pos] == '"') {
        if (!parse_json_string_token(json, pos)) {
          return false;
        }
        continue;
      }
      if (json[pos] == '{') {
        stack.push_back('}');
      } else if (json[pos] == '[') {
        stack.push_back(']');
      } else if (json[pos] == '}' || json[pos] == ']') {
        if (json[pos] != stack.back()) {
          return false;
        }
        stack.pop_back();
      }
      ++pos;
    }
    return stack.empty();
  }
  while (pos < json.size() && json[pos] != ',' && json[pos] != '}' &&
         json[pos] != ']') {
    ++pos;
  }
  return true;
}

inline std::optional<std::string> json_string_field(const std::string& json,
                                                    const std::string& key) {
  std::size_t pos = 0;
  skip_json_ws(json, pos);
  if (pos >= json.size() || json[pos] != '{') {
    return std::nullopt;
  }
  ++pos;
  while (true) {
    skip_json_ws(json, pos);
    if (pos >= json.size()) {
      return std::nullopt;
    }
    if (json[pos] == '}') {
      return std::nullopt;
    }
    auto parsed_key = parse_json_string_token(json, pos);
    if (!parsed_key) {
      return std::nullopt;
    }
    skip_json_ws(json, pos);
    if (pos >= json.size() || json[pos] != ':') {
      return std::nullopt;
    }
    ++pos;
    skip_json_ws(json, pos);
    if (*parsed_key == key) {
      return parse_json_string_token(json, pos);
    }
    if (!skip_json_value(json, pos)) {
      return std::nullopt;
    }
    skip_json_ws(json, pos);
    if (pos >= json.size()) {
      return std::nullopt;
    }
    if (json[pos] == ',') {
      ++pos;
      continue;
    }
    if (json[pos] == '}') {
      return std::nullopt;
    }
    return std::nullopt;
  }
}

}  // namespace detail
}  // namespace kernel
}  // namespace chio
