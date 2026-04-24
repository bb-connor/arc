#pragma once

#include <cstddef>
#include <functional>
#include <string>

#include "chio/result.hpp"
#include "json.hpp"
#include "sse.hpp"

namespace chio {
namespace detail {

constexpr std::size_t kSseCompactThreshold = 4096;

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
  SseEventData pending_event;
  Error callback_error;
  std::function<Result<void>(const std::string&)> stream_message;
};

inline void compact_processed_sse(CurlBodyCapture& capture) {
  if (capture.scan_pos < kSseCompactThreshold) {
    return;
  }
  capture.body.erase(0, capture.scan_pos);
  capture.scan_pos = 0;
}

inline void scan_sse_events(CurlBodyCapture& capture) {
  while (true) {
    const auto line_start = capture.scan_pos;
    const auto line_end = capture.body.find('\n', line_start);
    if (line_end == std::string::npos) {
      compact_processed_sse(capture);
      return;
    }
    capture.scan_pos = line_end + 1;
    std::string_view line(capture.body.data() + line_start, line_end - line_start);
    if (is_sse_blank_line(line)) {
      auto delivered = flush_sse_event(capture.pending_event, [&](const std::string& payload) {
        if (capture.stream_message) {
          auto handled = capture.stream_message(payload);
          if (!handled) {
            return handled;
          }
        }
        if (is_terminal_message(payload, capture.id_json)) {
          capture.complete = true;
        }
        return Result<void>::success();
      });
      if (!delivered) {
        capture.callback_failed = true;
        capture.callback_error = delivered.error();
        capture.complete = true;
        return;
      }
      if (capture.complete) {
        return;
      }
      compact_processed_sse(capture);
      continue;
    }
    if (line.rfind("data:", 0) == 0) {
      append_sse_data_line(capture.pending_event, line);
    }
    compact_processed_sse(capture);
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
