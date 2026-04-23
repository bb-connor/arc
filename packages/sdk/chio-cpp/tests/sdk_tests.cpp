#include "chio/chio.hpp"

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

class FakeTransport final : public chio::HttpTransport {
 public:
  explicit FakeTransport(std::vector<chio::HttpResponse> responses)
      : responses_(std::move(responses)) {}

  chio::Result<chio::HttpResponse> send(const chio::HttpRequest& request) override {
    requests.push_back(request);
    if (responses_.empty()) {
      return chio::Result<chio::HttpResponse>::failure(
          chio::Error{chio::ErrorCode::Transport, "no fake response queued"});
    }
    auto response = std::move(responses_.front());
    responses_.erase(responses_.begin());
    return chio::Result<chio::HttpResponse>::success(std::move(response));
  }

  std::vector<chio::HttpRequest> requests;

 private:
  std::vector<chio::HttpResponse> responses_;
};

void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

void require_eq(const std::string& actual,
                const std::string& expected,
                const std::string& label) {
  if (actual != expected) {
    throw std::runtime_error(label + ": expected [" + expected + "], got [" + actual + "]");
  }
}

void require_contains(const std::string& haystack,
                      const std::string& needle,
                      const std::string& label) {
  if (haystack.find(needle) == std::string::npos) {
    throw std::runtime_error(label + ": missing [" + needle + "]");
  }
}

std::string read_file(const std::string& relative_path) {
  const std::string path = std::string(CHIO_CPP_REPO_ROOT) + "/" + relative_path;
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("failed to open " + path);
  }
  return std::string((std::istreambuf_iterator<char>(input)),
                     std::istreambuf_iterator<char>());
}

void test_invariants_from_shared_vectors() {
  const auto canonical_vectors = read_file("tests/bindings/vectors/canonical/v1.json");
  require_contains(canonical_vectors, "object_key_sorting", "canonical vectors");
  const auto canonical = chio::invariants::canonicalize_json("{\"z\":1,\"a\":2,\"m\":3}");
  require(canonical.ok(), canonical.error().message);
  require_eq(canonical.value(), "{\"a\":2,\"m\":3,\"z\":1}", "canonical json");

  const auto hashing_vectors = read_file("tests/bindings/vectors/hashing/v1.json");
  require_contains(hashing_vectors, "hello_utf8", "hashing vectors");
  const auto hash = chio::invariants::sha256_hex_utf8("hello");
  require(hash.ok(), hash.error().message);
  require_eq(hash.value(),
             "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
             "sha256 hello");

  const auto signing_vectors = read_file("tests/bindings/vectors/signing/v1.json");
  require_contains(signing_vectors, "valid_utf8_message", "signing vectors");
  const auto verified = chio::invariants::verify_utf8_message_ed25519(
      "hello chio",
      "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
      "4b134ccad3c684ef462bf085ea2e87c416557980e01da869703d18016f3811a0f0310f38075e2019480f8c1abc06c7d823ef1776eb95687785e5eacdbe57250c");
  require(verified.ok(), verified.error().message);
  require(verified.value(), "expected vector signature to verify");
}

void test_dpop_proof() {
  chio::DpopSignParams params;
  params.capability_id = "cap-123";
  params.tool_server = "hosted-mcp";
  params.tool_name = "read_file";
  params.action_args_json = "{\"path\":\"/tmp/demo\"}";
  params.agent_seed_hex = "0909090909090909090909090909090909090909090909090909090909090909";
  params.nonce = "test-nonce";
  params.issued_at = 1700000000;

  const auto proof = chio::sign_dpop_proof(params);
  require(proof.ok(), proof.error().message);
  require_contains(proof.value().body_json, "\"schema\":\"chio.dpop_proof.v1\"", "dpop body");
  require_contains(proof.value().body_json, "\"nonce\":\"test-nonce\"", "dpop body");
  require(!proof.value().signature_hex.empty(), "expected DPoP signature");
  require_contains(proof.value().to_json(), "\"signature\":", "dpop json");
}

void test_client_session_with_fake_transport() {
  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200, {{"MCP-Session-Id", "sess-1"}}, "{\"protocolVersion\":\"2025-11-25\"}"},
      {202, {}, "{}"},
      {200, {}, "{\"tools\":[]}"},
      {200, {}, "{\"result\":\"closed\"}"},
  });

  auto client = chio::Client::with_static_bearer("http://127.0.0.1:8080/", "token", transport);
  auto initialized = client.initialize();
  require(initialized.ok(), initialized.error().message);
  auto session = initialized.move_value();
  require_eq(session.session_id(), "sess-1", "session id");

  auto tools = session.list_tools();
  require(tools.ok(), tools.error().message);
  require_eq(tools.value(), "{\"tools\":[]}", "list tools body");

  auto closed = session.close();
  require(closed.ok(), closed.error().message);

  require(transport->requests.size() == 4, "expected initialize, initialized, tools, close");
  require_eq(transport->requests[0].method, "POST", "initialize method");
  require_eq(transport->requests[0].url, "http://127.0.0.1:8080/mcp", "initialize url");
  require_contains(transport->requests[0].body, "\"method\":\"initialize\"", "initialize body");
  require_contains(transport->requests[1].body,
                   "\"method\":\"notifications/initialized\"",
                   "initialized notification body");
  require_contains(transport->requests[2].body, "\"method\":\"tools/list\"", "tools body");
  require_eq(transport->requests[2].headers["MCP-Session-Id"], "sess-1", "session header");
}

void test_receipt_query_client() {
  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200, {}, "{\"receipts\":[]}"},
  });
  chio::ReceiptQueryClient client("http://127.0.0.1:8940/", "token", transport);
  const auto response = client.query({{"capability", "cap 1"}, {"limit", "10"}});
  require(response.ok(), response.error().message);
  require_eq(response.value(), "{\"receipts\":[]}", "receipt query body");
  require_eq(transport->requests[0].method, "GET", "receipt query method");
  require_contains(transport->requests[0].url, "capability=cap%201", "receipt query url");
  require_eq(transport->requests[0].headers["Authorization"],
             "Bearer token",
             "receipt query auth header");
}

void test_http_substrate_evaluator() {
  auto transport = std::make_shared<FakeTransport>(std::vector<chio::HttpResponse>{
      {200, {}, "{\"verdict\":\"allow\",\"receipt\":{\"id\":\"r1\"}}"},
      {200, {}, "{\"valid\":true}"},
      {503, {}, "{\"status\":\"degraded\"}"},
  });

  chio::http::ChioHttpRequest request;
  request.request_id = "req-1";
  request.method = "POST";
  request.route_pattern = "/v1/items";
  request.path = "/v1/items";
  request.headers = {{"content-type", "application/json"}};
  request.caller.subject = "agent-1";
  request.caller.verified = true;
  request.body_hash =
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
  request.body_length = 5;
  request.timestamp = 1700000000;

  chio::http::Evaluator evaluator("http://127.0.0.1:9090/", transport);
  const auto verdict = evaluator.evaluate(request);
  require(verdict.ok(), verdict.error().message);
  require_contains(verdict.value(), "\"verdict\":\"allow\"", "evaluate body");
  require_contains(transport->requests[0].body, "\"body_hash\":", "evaluate request");
  require_contains(transport->requests[0].body, "\"caller\":", "evaluate request");

  const auto verified = evaluator.verify_receipt("{\"receipt\":{\"id\":\"r1\"}}");
  require(verified.ok(), verified.error().message);
  require(verified.value(), "expected receipt verification to succeed");

  const auto health = evaluator.health();
  require(health.ok(), health.error().message);
  require_eq(health.value(), "{\"status\":\"degraded\"}", "health body");
}

}  // namespace

int main() {
  try {
    test_invariants_from_shared_vectors();
    test_dpop_proof();
    test_client_session_with_fake_transport();
    test_receipt_query_client();
    test_http_substrate_evaluator();
  } catch (const std::exception& error) {
    std::cerr << "chio_cpp_tests failed: " << error.what() << "\n";
    return 1;
  }

  std::cout << "chio_cpp_tests passed\n";
  return 0;
}
