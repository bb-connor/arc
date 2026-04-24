#pragma once

#include <cstddef>
#include <functional>
#include <string>

#include "chio/result.hpp"
#include "json.hpp"

namespace chio {
namespace detail {

inline std::string trim_event_payload(std::string value) {
  while (!value.empty() &&
         (value.front() == ' ' || value.front() == '\t' || value.front() == '\r')) {
    value.erase(value.begin());
  }
  while (!value.empty() &&
         (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
    value.pop_back();
  }
  return value;
}

inline bool is_terminal_message(const std::string& payload, const std::string& id_json) {
  if (id_json.empty()) {
    return false;
  }
  auto parsed = detail::parse_json(payload);
  if (!parsed || !parsed->is_object()) {
    return false;
  }
  const auto* id = parsed->get("id");
  if (id == nullptr || id->dump() != id_json) {
    return false;
  }
  return parsed->get("result") != nullptr || parsed->get("error") != nullptr;
}

inline std::string request_id_json(const std::string& body) {
  auto parsed = detail::parse_json(body);
  if (!parsed || !parsed->is_object()) {
    return {};
  }
  const auto* id = parsed->get("id");
  return id == nullptr ? std::string() : id->dump();
}

struct CurlBodyCapture {
  std::string body;
  std::string id_json;
  std::size_t scan_pos = 0;
  bool complete = false;
  bool callback_failed = false;
  Error callback_error;
  std::function<Result<void>(const std::string&)> stream_message;
};

inline void scan_sse_events(CurlBodyCapture& capture) {
  while (true) {
    const auto line_start = capture.body.find("data:", capture.scan_pos);
    if (line_start == std::string::npos) {
      return;
    }
    const auto line_end = capture.body.find('\n', line_start);
    if (line_end == std::string::npos) {
      return;
    }
    capture.scan_pos = line_end + 1;
    auto payload = trim_event_payload(
        capture.body.substr(line_start + 5, line_end - (line_start + 5)));
    if (payload.empty() || payload == "[DONE]") {
      continue;
    }
    if (capture.stream_message) {
      auto delivered = capture.stream_message(payload);
      if (!delivered) {
        capture.callback_failed = true;
        capture.callback_error = delivered.error();
        capture.complete = true;
        return;
      }
    }
    if (is_terminal_message(payload, capture.id_json)) {
      capture.complete = true;
      return;
    }
  }
}

inline std::size_t write_curl_body(char* ptr,
                                   std::size_t size,
                                   std::size_t nmemb,
                                   void* userdata) {
  auto* capture = static_cast<CurlBodyCapture*>(userdata);
  const std::size_t len = size * nmemb;
  capture->body.append(ptr, len);
  scan_sse_events(*capture);
  if (capture->callback_failed || (capture->complete && capture->stream_message)) {
    return 0;
  }
  return len;
}

}  // namespace detail
}  // namespace chio
