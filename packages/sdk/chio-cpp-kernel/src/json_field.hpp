#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

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

inline bool consume_json_literal(const std::string& json,
                                 std::size_t& pos,
                                 std::string_view literal) {
  if (pos + literal.size() > json.size()) {
    return false;
  }
  if (json.compare(pos, literal.size(), literal) != 0) {
    return false;
  }
  pos += literal.size();
  return true;
}

inline bool skip_json_number(const std::string& json, std::size_t& pos) {
  const auto start = pos;
  if (pos < json.size() && json[pos] == '-') {
    ++pos;
  }
  if (pos >= json.size() || json[pos] < '0' || json[pos] > '9') {
    pos = start;
    return false;
  }
  if (json[pos] == '0') {
    ++pos;
    if (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
      pos = start;
      return false;
    }
  } else {
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
      ++pos;
    }
  }
  if (pos < json.size() && json[pos] == '.') {
    ++pos;
    const auto fraction_start = pos;
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
      ++pos;
    }
    if (pos == fraction_start) {
      pos = start;
      return false;
    }
  }
  if (pos < json.size() && (json[pos] == 'e' || json[pos] == 'E')) {
    ++pos;
    if (pos < json.size() && (json[pos] == '+' || json[pos] == '-')) {
      ++pos;
    }
    const auto exponent_start = pos;
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
      ++pos;
    }
    if (pos == exponent_start) {
      pos = start;
      return false;
    }
  }
  return pos > start;
}

inline bool skip_json_value(const std::string& json, std::size_t& pos) {
  skip_json_ws(json, pos);
  if (pos >= json.size()) {
    return false;
  }
  if (json[pos] == '"') {
    return parse_json_string_token(json, pos).has_value();
  }
  if (json[pos] == '{') {
    ++pos;
    skip_json_ws(json, pos);
    if (pos < json.size() && json[pos] == '}') {
      ++pos;
      return true;
    }
    while (pos < json.size()) {
      if (!parse_json_string_token(json, pos)) {
        return false;
      }
      skip_json_ws(json, pos);
      if (pos >= json.size() || json[pos] != ':') {
        return false;
      }
      ++pos;
      if (!skip_json_value(json, pos)) {
        return false;
      }
      skip_json_ws(json, pos);
      if (pos < json.size() && json[pos] == ',') {
        ++pos;
        skip_json_ws(json, pos);
        continue;
      }
      if (pos < json.size() && json[pos] == '}') {
        ++pos;
        return true;
      }
      return false;
    }
    return false;
  }
  if (json[pos] == '[') {
    ++pos;
    skip_json_ws(json, pos);
    if (pos < json.size() && json[pos] == ']') {
      ++pos;
      return true;
    }
    while (pos < json.size()) {
      if (!skip_json_value(json, pos)) {
        return false;
      }
      skip_json_ws(json, pos);
      if (pos < json.size() && json[pos] == ',') {
        ++pos;
        continue;
      }
      if (pos < json.size() && json[pos] == ']') {
        ++pos;
        return true;
      }
      return false;
    }
    return false;
  }
  if (json[pos] == 't') {
    return consume_json_literal(json, pos, "true");
  }
  if (json[pos] == 'f') {
    return consume_json_literal(json, pos, "false");
  }
  if (json[pos] == 'n') {
    return consume_json_literal(json, pos, "null");
  }
  if (json[pos] == '-' || (json[pos] >= '0' && json[pos] <= '9')) {
    return skip_json_number(json, pos);
  }
  return false;
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
