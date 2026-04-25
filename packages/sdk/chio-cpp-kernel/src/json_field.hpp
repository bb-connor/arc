#pragma once

#include <cctype>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace chio {
namespace kernel {
namespace detail {

inline std::string escape_json(std::string_view input) {
  std::ostringstream out;
  constexpr char kHexDigits[] = "0123456789abcdef";
  for (unsigned char c : input) {
    switch (c) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (c < 0x20) {
          out << "\\u00" << kHexDigits[(c >> 4U) & 0x0FU] << kHexDigits[c & 0x0FU];
        } else {
          out << static_cast<char>(c);
        }
    }
  }
  return out.str();
}

inline void skip_ws(std::string_view input, std::size_t& pos) {
  while (pos < input.size()) {
    const auto c = static_cast<unsigned char>(input[pos]);
    if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
      return;
    }
    ++pos;
  }
}

inline bool is_hex_digit(char c) {
  const auto ch = static_cast<unsigned char>(c);
  return std::isdigit(ch) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline std::optional<std::string> parse_json_string(std::string_view input, std::size_t& pos) {
  if (pos >= input.size() || input[pos] != '"') {
    return std::nullopt;
  }
  ++pos;

  std::string out;
  while (pos < input.size()) {
    const char c = input[pos++];
    if (c == '"') {
      return out;
    }
    if (static_cast<unsigned char>(c) < 0x20) {
      return std::nullopt;
    }
    if (c != '\\') {
      out.push_back(c);
      continue;
    }
    if (pos >= input.size()) {
      return std::nullopt;
    }
    const char escaped = input[pos++];
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
        if (pos + 4 > input.size()) {
          return std::nullopt;
        }
        for (std::size_t i = 0; i < 4; ++i) {
          if (!is_hex_digit(input[pos + i])) {
            return std::nullopt;
          }
        }
        out += "\\u";
        out.append(input.substr(pos, 4));
        pos += 4;
        break;
      default:
        return std::nullopt;
    }
  }
  return std::nullopt;
}

inline bool skip_json_value(std::string_view input, std::size_t& pos);

inline bool skip_json_literal(std::string_view input, std::size_t& pos, std::string_view literal) {
  if (input.substr(pos, literal.size()) != literal) {
    return false;
  }
  pos += literal.size();
  return true;
}

inline bool skip_json_number(std::string_view input, std::size_t& pos) {
  const std::size_t start = pos;
  if (pos < input.size() && input[pos] == '-') {
    ++pos;
  }
  if (pos >= input.size() || !std::isdigit(static_cast<unsigned char>(input[pos]))) {
    return false;
  }
  if (input[pos] == '0') {
    ++pos;
    if (pos < input.size() && std::isdigit(static_cast<unsigned char>(input[pos]))) {
      return false;
    }
  } else {
    while (pos < input.size() && std::isdigit(static_cast<unsigned char>(input[pos]))) {
      ++pos;
    }
  }
  if (pos < input.size() && input[pos] == '.') {
    ++pos;
    if (pos >= input.size() || !std::isdigit(static_cast<unsigned char>(input[pos]))) {
      return false;
    }
    while (pos < input.size() && std::isdigit(static_cast<unsigned char>(input[pos]))) {
      ++pos;
    }
  }
  if (pos < input.size() && (input[pos] == 'e' || input[pos] == 'E')) {
    ++pos;
    if (pos < input.size() && (input[pos] == '+' || input[pos] == '-')) {
      ++pos;
    }
    if (pos >= input.size() || !std::isdigit(static_cast<unsigned char>(input[pos]))) {
      return false;
    }
    while (pos < input.size() && std::isdigit(static_cast<unsigned char>(input[pos]))) {
      ++pos;
    }
  }
  return pos > start;
}

inline bool skip_json_array(std::string_view input, std::size_t& pos) {
  if (pos >= input.size() || input[pos] != '[') {
    return false;
  }
  ++pos;
  skip_ws(input, pos);
  if (pos < input.size() && input[pos] == ']') {
    ++pos;
    return true;
  }
  while (pos < input.size()) {
    if (!skip_json_value(input, pos)) {
      return false;
    }
    skip_ws(input, pos);
    if (pos < input.size() && input[pos] == ']') {
      ++pos;
      return true;
    }
    if (pos >= input.size() || input[pos] != ',') {
      return false;
    }
    ++pos;
    skip_ws(input, pos);
  }
  return false;
}

inline bool skip_json_object(std::string_view input, std::size_t& pos) {
  if (pos >= input.size() || input[pos] != '{') {
    return false;
  }
  ++pos;
  skip_ws(input, pos);
  if (pos < input.size() && input[pos] == '}') {
    ++pos;
    return true;
  }
  while (pos < input.size()) {
    auto key = parse_json_string(input, pos);
    if (!key.has_value()) {
      return false;
    }
    skip_ws(input, pos);
    if (pos >= input.size() || input[pos] != ':') {
      return false;
    }
    ++pos;
    skip_ws(input, pos);
    if (!skip_json_value(input, pos)) {
      return false;
    }
    skip_ws(input, pos);
    if (pos < input.size() && input[pos] == '}') {
      ++pos;
      return true;
    }
    if (pos >= input.size() || input[pos] != ',') {
      return false;
    }
    ++pos;
    skip_ws(input, pos);
  }
  return false;
}

inline bool skip_json_value(std::string_view input, std::size_t& pos) {
  skip_ws(input, pos);
  if (pos >= input.size()) {
    return false;
  }
  switch (input[pos]) {
    case '"': {
      auto value = parse_json_string(input, pos);
      return value.has_value();
    }
    case '{':
      return skip_json_object(input, pos);
    case '[':
      return skip_json_array(input, pos);
    case 't':
      return skip_json_literal(input, pos, "true");
    case 'f':
      return skip_json_literal(input, pos, "false");
    case 'n':
      return skip_json_literal(input, pos, "null");
    default:
      return skip_json_number(input, pos);
  }
}

inline std::optional<std::string> json_string_field(const std::string& json,
                                                    std::string_view key) {
  std::string_view input(json);
  std::size_t pos = 0;
  std::optional<std::string> found;
  skip_ws(input, pos);
  if (pos >= input.size() || input[pos] != '{') {
    return std::nullopt;
  }
  ++pos;

  skip_ws(input, pos);
  if (pos < input.size() && input[pos] == '}') {
    ++pos;
    skip_ws(input, pos);
    return pos == input.size() ? found : std::nullopt;
  }

  while (pos < input.size()) {
    auto parsed_key = parse_json_string(input, pos);
    if (!parsed_key.has_value()) {
      return std::nullopt;
    }
    skip_ws(input, pos);
    if (pos >= input.size() || input[pos] != ':') {
      return std::nullopt;
    }
    ++pos;
    skip_ws(input, pos);

    if (*parsed_key == key) {
      auto value = parse_json_string(input, pos);
      if (!value.has_value()) {
        return std::nullopt;
      }
      found = std::move(value);
      skip_ws(input, pos);
      if (pos < input.size() && input[pos] != ',' && input[pos] != '}') {
        return std::nullopt;
      }
    } else if (!skip_json_value(input, pos)) {
      return std::nullopt;
    }
    skip_ws(input, pos);
    if (pos < input.size() && input[pos] == '}') {
      ++pos;
      skip_ws(input, pos);
      return pos == input.size() ? found : std::nullopt;
    }
    if (pos >= input.size() || input[pos] != ',') {
      return std::nullopt;
    }
    ++pos;
    skip_ws(input, pos);
  }

  return std::nullopt;
}

}  // namespace detail
}  // namespace kernel
}  // namespace chio
