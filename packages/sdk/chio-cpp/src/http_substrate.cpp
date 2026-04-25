#include "chio/http_substrate.hpp"

#include <chrono>
#include <utility>

#include "json.hpp"

namespace chio::http {

std::string AuthMethod::to_json() const {
  std::string out = "{\"method\":" + detail::quote(method);
  for (const auto& field : fields) {
    out += ",";
    out += detail::quote(field.first);
    out += ":";
    out += detail::quote(field.second);
  }
  out += "}";
  return out;
}

std::string CallerIdentity::to_json() const {
  std::string out = "{\"subject\":" + detail::quote(subject) +
                    ",\"auth_method\":" + auth_method.to_json() +
                    ",\"verified\":" + (verified ? "true" : "false");
  if (!tenant.empty()) {
    out += ",\"tenant\":" + detail::quote(tenant);
  }
  if (!agent_id.empty()) {
    out += ",\"agent_id\":" + detail::quote(agent_id);
  }
  out += "}";
  return out;
}

std::string ChioHttpRequest::to_json() const {
  std::string out = "{";
  out += "\"request_id\":" + detail::quote(request_id);
  out += ",\"method\":" + detail::quote(method);
  out += ",\"route_pattern\":" + detail::quote(route_pattern);
  out += ",\"path\":" + detail::quote(path);
  out += ",\"query\":" + detail::json_string_map(query);
  out += ",\"headers\":" + detail::json_string_map(headers);
  out += ",\"caller\":" + caller.to_json();
  if (!body_hash.empty()) {
    out += ",\"body_hash\":" + detail::quote(body_hash);
  }
  out += ",\"body_length\":" + std::to_string(body_length);
  if (!session_id.empty()) {
    out += ",\"session_id\":" + detail::quote(session_id);
  }
  if (!capability_id.empty()) {
    out += ",\"capability_id\":" + detail::quote(capability_id);
  }
  out += ",\"timestamp\":" + std::to_string(timestamp);
  out += "}";
  return out;
}

Evaluator::Evaluator(std::string sidecar_url, HttpTransportPtr transport, std::uint32_t timeout_ms)
    : sidecar_url_(detail::trim_right_slash(std::move(sidecar_url))),
      transport_(std::move(transport)),
      timeout_ms_(timeout_ms) {}

Result<std::string> Evaluator::evaluate(const ChioHttpRequest& request,
                                        const std::string& capability_token) const {
  if (!transport_) {
    return Result<std::string>::failure(Error{ErrorCode::Transport, "missing HTTP transport"});
  }
  std::map<std::string, std::string> headers{
      {"Content-Type", "application/json"},
      {"Accept", "application/json"},
      {"X-Chio-Timeout-Ms", std::to_string(timeout_ms_)},
  };
  if (!capability_token.empty()) {
    headers["X-Chio-Capability"] = capability_token;
  }
  HttpRequest http_request{
      "POST",
      sidecar_url_ + "/chio/evaluate",
      std::move(headers),
      request.to_json(),
  };
  http_request.timeout = std::chrono::milliseconds(timeout_ms_);
  auto response = transport_->send(http_request);
  if (!response) {
    return Result<std::string>::failure(response.error());
  }
  if (response.value().status != 200) {
    return Result<std::string>::failure(
        Error{ErrorCode::Protocol, "sidecar evaluate returned HTTP " +
                                      std::to_string(response.value().status)});
  }
  return Result<std::string>::success(response.value().body);
}

Result<bool> Evaluator::verify_receipt(std::string receipt_json) const {
  if (!transport_) {
    return Result<bool>::failure(Error{ErrorCode::Transport, "missing HTTP transport"});
  }
  HttpRequest request{
      "POST",
      sidecar_url_ + "/chio/verify",
      {{"Content-Type", "application/json"}, {"Accept", "application/json"}},
      std::move(receipt_json),
  };
  request.timeout = std::chrono::milliseconds(timeout_ms_);
  auto response = transport_->send(request);
  if (!response) {
    return Result<bool>::failure(response.error());
  }
  if (response.value().status != 200) {
    return Result<bool>::failure(
        Error{ErrorCode::Protocol, "sidecar verify returned HTTP " +
                                      std::to_string(response.value().status)});
  }
  auto parsed = detail::parse_json(response.value().body);
  if (!parsed || !parsed->is_object()) {
    return Result<bool>::failure(
        Error{ErrorCode::Json, "sidecar verify returned malformed JSON"});
  }
  const auto* valid = parsed->get("valid");
  if (valid == nullptr || !valid->is_bool()) {
    return Result<bool>::failure(
        Error{ErrorCode::Json, "sidecar verify response missing boolean valid field"});
  }
  return Result<bool>::success(valid->as_bool());
}

Result<std::string> Evaluator::health() const {
  if (!transport_) {
    return Result<std::string>::failure(Error{ErrorCode::Transport, "missing HTTP transport"});
  }
  HttpRequest request{
      "GET",
      sidecar_url_ + "/chio/health",
      {{"Accept", "application/json"}},
      "",
  };
  request.timeout = std::chrono::milliseconds(timeout_ms_);
  auto response = transport_->send(request);
  if (!response) {
    return Result<std::string>::failure(response.error());
  }
  if (response.value().status != 200 && response.value().status != 503) {
    return Result<std::string>::failure(
        Error{ErrorCode::Protocol, "sidecar health returned HTTP " +
                                      std::to_string(response.value().status)});
  }
  return Result<std::string>::success(response.value().body);
}

Middleware::Middleware(Evaluator evaluator) : evaluator_(std::move(evaluator)) {}

EvaluateVerdict Middleware::evaluate_fail_closed(const ChioHttpRequest& request) const {
  auto response = evaluator_.evaluate(request);
  if (!response) {
    return EvaluateVerdict{"deny", response.error().message, {}, {}};
  }
  EvaluateVerdict verdict;
  verdict.raw_json = response.value();
  auto parsed = detail::parse_json(response.value());
  if (!parsed || !parsed->is_object()) {
    verdict.verdict = "deny";
    verdict.reason = "malformed evaluate response";
    return verdict;
  }
  verdict.verdict = parsed->string_field("verdict");
  verdict.reason = parsed->string_field("reason");
  const auto* receipt = parsed->get("receipt");
  if (receipt != nullptr) {
    verdict.receipt_json = receipt->dump();
  }
  if (verdict.verdict.empty()) {
    verdict.verdict = "deny";
    verdict.reason = "missing verdict";
  }
  return verdict;
}

std::string receipt_id_from_verdict(const EvaluateVerdict& verdict) {
  const auto parse_receipt_id = [](const std::string& raw_json) {
    auto parsed = detail::parse_json(raw_json);
    if (!parsed || !parsed->is_object()) {
      return std::string{};
    }
    return parsed->string_field("id");
  };

  if (!verdict.receipt_json.empty()) {
    const auto receipt_id = parse_receipt_id(verdict.receipt_json);
    if (!receipt_id.empty()) {
      return receipt_id;
    }
  }

  auto parsed = detail::parse_json(verdict.raw_json);
  if (!parsed || !parsed->is_object()) {
    return {};
  }
  const auto* receipt = parsed->get("receipt");
  if (receipt == nullptr) {
    return {};
  }
  return parse_receipt_id(receipt->dump());
}

}  // namespace chio::http
