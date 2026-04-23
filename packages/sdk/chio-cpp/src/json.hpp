#pragma once

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <string_view>

namespace chio::detail {

inline std::string trim_right_slash(std::string value) {
  while (!value.empty() && value.back() == '/') {
    value.pop_back();
  }
  return value;
}

inline std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

inline std::string escape_json(std::string_view input) {
  std::ostringstream out;
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
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(c);
        } else {
          out << static_cast<char>(c);
        }
    }
  }
  return out.str();
}

inline std::string quote(std::string_view input) {
  return "\"" + escape_json(input) + "\"";
}

inline std::string json_string_map(const std::map<std::string, std::string>& values) {
  std::string out = "{";
  bool first = true;
  for (const auto& entry : values) {
    if (!first) {
      out += ",";
    }
    first = false;
    out += quote(entry.first);
    out += ":";
    out += quote(entry.second);
  }
  out += "}";
  return out;
}

inline std::string extract_json_string_field(const std::string& json, std::string_view field) {
  const std::string needle = "\"" + std::string(field) + "\"";
  auto pos = json.find(needle);
  if (pos == std::string::npos) {
    return {};
  }
  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) {
    return {};
  }
  pos = json.find('"', pos + 1);
  if (pos == std::string::npos) {
    return {};
  }
  std::string out;
  bool escaped = false;
  for (std::size_t i = pos + 1; i < json.size(); ++i) {
    char c = json[i];
    if (escaped) {
      out.push_back(c);
      escaped = false;
      continue;
    }
    if (c == '\\') {
      escaped = true;
      continue;
    }
    if (c == '"') {
      return out;
    }
    out.push_back(c);
  }
  return {};
}

inline std::map<std::string, std::string> lower_headers(
    const std::map<std::string, std::string>& headers) {
  std::map<std::string, std::string> out;
  for (const auto& entry : headers) {
    out[lower(entry.first)] = entry.second;
  }
  return out;
}

inline std::string url_encode(std::string_view input) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;
  for (unsigned char c : input) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      escaped << c;
    } else {
      escaped << '%' << std::uppercase << std::setw(2) << int(c) << std::nouppercase;
    }
  }
  return escaped.str();
}

}  // namespace chio::detail
