#include "chio/client.hpp"

#include <utility>

#include "json.hpp"

namespace chio {

Client::Client(ClientOptions options, HttpTransportPtr transport)
    : options_(std::move(options)), transport_(std::move(transport)) {
  options_.base_url = detail::trim_right_slash(options_.base_url);
}

Client Client::with_static_bearer(std::string base_url,
                                  std::string bearer_token,
                                  HttpTransportPtr transport) {
  return Client(ClientOptions{std::move(base_url), std::move(bearer_token)},
                std::move(transport));
}

Result<Session> Client::initialize() const {
  if (!transport_) {
    return Result<Session>::failure(Error{ErrorCode::Transport, "missing HTTP transport"});
  }

  const std::string body =
      "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{"
      "\"protocolVersion\":" +
      detail::quote(options_.protocol_version) +
      ",\"capabilities\":{},\"clientInfo\":{\"name\":" + detail::quote(options_.client_name) +
      ",\"version\":" + detail::quote(options_.client_version) + "}}}";

  HttpRequest request{
      "POST",
      options_.base_url + "/mcp",
      {
          {"Authorization", "Bearer " + options_.bearer_token},
          {"Accept", "application/json, text/event-stream"},
          {"Content-Type", "application/json"},
      },
      body,
  };
  auto response = transport_->send(request);
  if (!response) {
    return Result<Session>::failure(response.error());
  }
  if (response.value().status != 200) {
    return Result<Session>::failure(
        Error{ErrorCode::Protocol, "initialize returned HTTP " +
                                      std::to_string(response.value().status)});
  }

  const auto headers = detail::lower_headers(response.value().headers);
  auto session_header = headers.find("mcp-session-id");
  if (session_header == headers.end() || session_header->second.empty()) {
    return Result<Session>::failure(
        Error{ErrorCode::Protocol, "initialize response did not include MCP-Session-Id"});
  }
  std::string protocol = detail::extract_json_string_field(response.value().body, "protocolVersion");
  if (protocol.empty()) {
    protocol = options_.protocol_version;
  }

  Session session(options_.base_url, options_.bearer_token, session_header->second, protocol,
                  transport_);
  auto initialized = session.notification("notifications/initialized");
  if (!initialized) {
    return Result<Session>::failure(initialized.error());
  }
  return Result<Session>::success(std::move(session));
}

}  // namespace chio
