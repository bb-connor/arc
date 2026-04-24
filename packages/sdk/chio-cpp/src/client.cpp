#include "chio/client.hpp"

#include <utility>

#include "json.hpp"
#include "transport_util.hpp"

namespace chio {

Client::Client(ClientOptions options, HttpTransportPtr transport, TraceSinkPtr trace_sink)
    : options_(std::move(options)),
      transport_(std::move(transport)),
      trace_sink_(std::move(trace_sink)) {
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
  std::string bearer_token = options_.bearer_token;
  if (options_.token_provider) {
    auto token = options_.token_provider->access_token();
    if (!token) {
      return Result<Session>::failure(token.error());
    }
    bearer_token = token.value();
  }
  if (bearer_token.empty()) {
    return Result<Session>::failure(
        Error{ErrorCode::Protocol, "bearer token is required", "Client::initialize"});
  }

  const std::string body =
      "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{"
      "\"protocolVersion\":" +
      detail::quote(options_.protocol_version) +
      ",\"capabilities\":" + options_.client_capabilities_json +
      ",\"clientInfo\":{\"name\":" + detail::quote(options_.client_name) +
      ",\"version\":" + detail::quote(options_.client_version) + "}}}";

  HttpRequest request{
      "POST",
      options_.base_url + "/mcp",
      {
          {"Authorization", "Bearer " + bearer_token},
          {"Accept", "application/json, text/event-stream"},
          {"Content-Type", "application/json"},
      },
      body,
      options_.timeout,
  };
  auto response = detail::send_with_policy(transport_, request, options_.retry_policy, trace_sink_,
                                           "Client::initialize");
  if (!response) {
    return Result<Session>::failure(response.error());
  }
  if (response.value().status != 200) {
    return Result<Session>::failure(
        Error{ErrorCode::Protocol, "initialize returned HTTP " +
                                      std::to_string(response.value().status),
              "Client::initialize", response.value().status,
              detail::body_snippet(response.value().body), {}, {},
              detail::retryable_status(response.value().status)});
  }

  const auto headers = detail::lower_headers(response.value().headers);
  auto session_header = headers.find("mcp-session-id");
  if (session_header == headers.end() || session_header->second.empty()) {
    return Result<Session>::failure(
        Error{ErrorCode::Protocol, "initialize response did not include MCP-Session-Id"});
  }
  std::string protocol = detail::extract_json_string_field(response.value().body, "protocolVersion");
  if (protocol.empty()) {
    auto parsed = detail::parse_json(response.value().body);
    if (parsed) {
      protocol = detail::json_string_at(*parsed, {"result", "protocolVersion"});
    }
  }
  if (protocol.empty()) {
    protocol = options_.protocol_version;
  }

  Session session(options_.base_url, bearer_token, session_header->second, protocol,
                  transport_, options_.retry_policy, trace_sink_, options_.timeout,
                  options_.token_provider);
  if (options_.initialize_message_handler) {
    session.on_message([handler = options_.initialize_message_handler, &session](
                           const JsonMessage& message) {
      return handler(session, message);
    });
  }
  auto initialized = session.notification("notifications/initialized");
  if (options_.initialize_message_handler) {
    session.on_message({});
  }
  if (!initialized) {
    return Result<Session>::failure(initialized.error());
  }
  return Result<Session>::success(std::move(session));
}

ClientBuilder& ClientBuilder::base_url(std::string value) {
  options_.base_url = std::move(value);
  return *this;
}

ClientBuilder& ClientBuilder::bearer_token(std::string value) {
  options_.bearer_token = std::move(value);
  return *this;
}

ClientBuilder& ClientBuilder::token_provider(TokenProviderPtr value) {
  options_.token_provider = std::move(value);
  return *this;
}

ClientBuilder& ClientBuilder::transport(HttpTransportPtr value) {
  transport_ = std::move(value);
  return *this;
}

ClientBuilder& ClientBuilder::trace_sink(TraceSinkPtr value) {
  trace_sink_ = std::move(value);
  return *this;
}

ClientBuilder& ClientBuilder::timeout(std::chrono::milliseconds value) {
  options_.timeout = value;
  return *this;
}

ClientBuilder& ClientBuilder::retry_policy(RetryPolicy value) {
  options_.retry_policy = value;
  return *this;
}

ClientBuilder& ClientBuilder::client_info(std::string name, std::string version) {
  options_.client_name = std::move(name);
  options_.client_version = std::move(version);
  return *this;
}

ClientBuilder& ClientBuilder::protocol_version(std::string value) {
  options_.protocol_version = std::move(value);
  return *this;
}

ClientBuilder& ClientBuilder::client_capabilities_json(std::string value) {
  options_.client_capabilities_json = std::move(value);
  return *this;
}

ClientBuilder& ClientBuilder::initialize_message_handler(InitializeMessageHandler value) {
  options_.initialize_message_handler = std::move(value);
  return *this;
}

Result<Client> ClientBuilder::build() const {
  if (options_.base_url.empty()) {
    return Result<Client>::failure(
        Error{ErrorCode::Protocol, "base_url is required", "ClientBuilder::build"});
  }
  if (!transport_) {
    return Result<Client>::failure(
        Error{ErrorCode::Transport, "transport is required", "ClientBuilder::build"});
  }
  return Result<Client>::success(Client(options_, transport_, trace_sink_));
}

}  // namespace chio
