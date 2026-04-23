#include "chio/session.hpp"

#include <utility>

#include "json.hpp"

namespace chio {

Session::Session(std::string base_url,
                 std::string bearer_token,
                 std::string session_id,
                 std::string protocol_version,
                 HttpTransportPtr transport)
    : base_url_(detail::trim_right_slash(std::move(base_url))),
      bearer_token_(std::move(bearer_token)),
      session_id_(std::move(session_id)),
      protocol_version_(std::move(protocol_version)),
      transport_(std::move(transport)) {}

Session::Session(Session&& other) noexcept
    : base_url_(std::move(other.base_url_)),
      bearer_token_(std::move(other.bearer_token_)),
      session_id_(std::move(other.session_id_)),
      protocol_version_(std::move(other.protocol_version_)),
      transport_(std::move(other.transport_)),
      next_request_id_(other.next_request_id_.load()) {}

Session& Session::operator=(Session&& other) noexcept {
  if (this == &other) {
    return *this;
  }
  base_url_ = std::move(other.base_url_);
  bearer_token_ = std::move(other.bearer_token_);
  session_id_ = std::move(other.session_id_);
  protocol_version_ = std::move(other.protocol_version_);
  transport_ = std::move(other.transport_);
  next_request_id_.store(other.next_request_id_.load());
  return *this;
}

HttpRequest Session::make_post(std::string body_json) const {
  return HttpRequest{
      "POST",
      base_url_ + "/mcp",
      {
          {"Authorization", "Bearer " + bearer_token_},
          {"Accept", "application/json, text/event-stream"},
          {"Content-Type", "application/json"},
          {"MCP-Session-Id", session_id_},
          {"MCP-Protocol-Version", protocol_version_},
      },
      std::move(body_json),
  };
}

std::int64_t Session::next_id() const {
  return next_request_id_.fetch_add(1);
}

Result<std::string> Session::send_envelope(std::string body_json) const {
  if (!transport_) {
    return Result<std::string>::failure(Error{ErrorCode::Transport, "missing HTTP transport"});
  }
  auto response = transport_->send(make_post(std::move(body_json)));
  if (!response) {
    return Result<std::string>::failure(response.error());
  }
  if (response.value().status < 200 || response.value().status >= 300) {
    return Result<std::string>::failure(
        Error{ErrorCode::Protocol, "MCP request returned HTTP " + std::to_string(response.value().status)});
  }
  return Result<std::string>::success(response.value().body);
}

Result<std::string> Session::request(std::string method, std::string params_json) const {
  const auto id = next_id();
  std::string body = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) +
                     ",\"method\":" + detail::quote(method) + ",\"params\":" +
                     params_json + "}";
  return send_envelope(std::move(body));
}

Result<std::string> Session::notification(std::string method, std::string params_json) const {
  std::string body = "{\"jsonrpc\":\"2.0\",\"method\":" + detail::quote(method) +
                     ",\"params\":" + params_json + "}";
  return send_envelope(std::move(body));
}

Result<std::string> Session::list_tools() const {
  return request("tools/list");
}

Result<std::string> Session::call_tool(std::string name, std::string arguments_json) const {
  return request("tools/call", "{\"name\":" + detail::quote(name) +
                                  ",\"arguments\":" + arguments_json + "}");
}

Result<std::string> Session::list_resources() const {
  return request("resources/list");
}

Result<std::string> Session::read_resource(std::string uri) const {
  return request("resources/read", "{\"uri\":" + detail::quote(uri) + "}");
}

Result<std::string> Session::list_prompts() const {
  return request("prompts/list");
}

Result<std::string> Session::get_prompt(std::string name, std::string arguments_json) const {
  return request("prompts/get", "{\"name\":" + detail::quote(name) +
                                   ",\"arguments\":" + arguments_json + "}");
}

Result<std::string> Session::list_tasks() const {
  return request("tasks/list");
}

Result<std::string> Session::get_task(std::string task_id) const {
  return request("tasks/get", "{\"taskId\":" + detail::quote(task_id) + "}");
}

Result<std::string> Session::get_task_result(std::string task_id) const {
  return request("tasks/result", "{\"taskId\":" + detail::quote(task_id) + "}");
}

Result<std::string> Session::cancel_task(std::string task_id) const {
  return request("tasks/cancel", "{\"taskId\":" + detail::quote(task_id) + "}");
}

Result<HttpResponse> Session::close() const {
  if (!transport_) {
    return Result<HttpResponse>::failure(Error{ErrorCode::Transport, "missing HTTP transport"});
  }
  HttpRequest request{
      "DELETE",
      base_url_ + "/mcp",
      {
          {"Authorization", "Bearer " + bearer_token_},
          {"MCP-Session-Id", session_id_},
      },
      "",
  };
  return transport_->send(request);
}

}  // namespace chio
