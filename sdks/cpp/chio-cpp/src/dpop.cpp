#include "chio/dpop.hpp"

#include <chrono>
#include <algorithm>
#include <array>
#include <sstream>
#include <string_view>

#include "chio/invariants.hpp"
#include "json.hpp"
#include "random.hpp"

namespace chio {
namespace {

std::uint64_t now_unix_secs() {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

std::string parsed_string_field(const std::string& json, std::string_view field) {
  auto parsed = detail::parse_json(json);
  if (!parsed || !parsed->is_object()) {
    return {};
  }
  const auto* value = parsed->get(field);
  if (value == nullptr || !value->is_string()) {
    return {};
  }
  return value->as_string();
}

}  // namespace

std::string DpopProof::to_json() const {
  return "{\"body\":" + body_json + ",\"signature\":" + detail::quote(signature_hex) + "}";
}

namespace {

bool bounded_authority_name(std::string_view value) {
  if (value.empty() || value.size() > 512) return false;
  for (std::size_t index = 0; index < value.size(); ++index) {
    const auto byte = static_cast<unsigned char>(value[index]);
    if (byte < 0x20 || byte == 0x7f) return false;
    if (byte == 0xc2 && index + 1 < value.size()) {
      const auto next = static_cast<unsigned char>(value[index + 1]);
      if (next >= 0x80 && next <= 0x9f) return false;
    }
  }
  // Rust's remaining Unicode White_Space characters. Control whitespace was
  // rejected above. UTF-8 validity is checked by canonical JSON before signing.
  constexpr std::array<std::string_view, 19> whitespace = {
      " ", u8"\u00a0", u8"\u1680", u8"\u2000", u8"\u2001", u8"\u2002",
      u8"\u2003", u8"\u2004", u8"\u2005", u8"\u2006", u8"\u2007", u8"\u2008",
      u8"\u2009", u8"\u200a", u8"\u2028", u8"\u2029", u8"\u202f", u8"\u205f", u8"\u3000"};
  for (const auto space : whitespace) {
    if (value.size() >= space.size() &&
        (value.substr(0, space.size()) == space || value.substr(value.size() - space.size()) == space)) {
      return false;
    }
  }
  return true;
}

bool lowercase_hex(std::string_view value) {
  return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
  });
}

bool valid_authority(const DpopReplayAuthority& authority) {
  const auto& uuid = authority.destination_store_uuid;
  if (uuid.size() != 36 || uuid == "00000000-0000-0000-0000-000000000000") return false;
  for (std::size_t index = 0; index < uuid.size(); ++index) {
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      if (uuid[index] != '-') return false;
    } else if (!lowercase_hex(std::string_view(uuid).substr(index, 1))) return false;
  }
  return bounded_authority_name(authority.dpop_authority_id) &&
         authority.expectation_id.size() == 64 && lowercase_hex(authority.expectation_id) &&
         authority.proof_ttl_secs >= 1 && authority.proof_ttl_secs <= 3600 &&
         authority.max_clock_skew_secs <= 300;
}

Result<DpopProof> sign_proof(const DpopSignParams& params, const DpopReplayAuthority* authority) {
  if (authority && !valid_authority(*authority)) {
    return Result<DpopProof>::failure(Error{ErrorCode::Protocol, "invalid durable DPoP authority"});
  }
  auto canonical_args = invariants::canonicalize_json(params.action_args_json);
  if (!canonical_args) {
    return Result<DpopProof>::failure(canonical_args.error());
  }
  auto action_hash = invariants::sha256_hex_utf8(canonical_args.value());
  if (!action_hash) {
    return Result<DpopProof>::failure(action_hash.error());
  }

  auto key_signature =
      invariants::sign_utf8_message_ed25519("derive_key", params.agent_seed_hex);
  if (!key_signature) {
    return Result<DpopProof>::failure(key_signature.error());
  }
  const auto agent_key = parsed_string_field(key_signature.value(), "public_key_hex");
  if (agent_key.empty()) {
    return Result<DpopProof>::failure(
        Error{ErrorCode::Protocol, "failed to derive DPoP agent public key"});
  }

  const auto nonce = params.nonce.empty() ? detail::random_hex(16) : params.nonce;
  const auto issued_at = params.issued_at == 0 ? now_unix_secs() : params.issued_at;
  if (authority && (issued_at > 9007199254740ULL - authority->proof_ttl_secs ||
                    nonce.size() > 4096 || params.capability_id.size() > 4096)) {
    return Result<DpopProof>::failure(Error{ErrorCode::Protocol, "durable DPoP identity or clock bound exceeded"});
  }

  std::ostringstream body;
  body << "{"
       << "\"action_hash\":" << detail::quote(action_hash.value()) << ","
       << "\"agent_key\":" << detail::quote(agent_key) << ","
       << "\"capability_id\":" << detail::quote(params.capability_id) << ","
       << "\"issued_at\":" << issued_at << ","
       << "\"nonce\":" << detail::quote(nonce) << ",";
  if (authority) {
    body << "\"replay_authority\":{"
         << "\"destination_store_uuid\":" << detail::quote(authority->destination_store_uuid) << ","
         << "\"dpop_authority_id\":" << detail::quote(authority->dpop_authority_id) << ","
         << "\"expectation_id\":" << detail::quote(authority->expectation_id) << ","
         << "\"max_clock_skew_secs\":" << authority->max_clock_skew_secs << ","
         << "\"proof_ttl_secs\":" << authority->proof_ttl_secs << "},";
  }
  body << "\"schema\":" << detail::quote(authority ? "chio.dpop_proof.v2" : "chio.dpop_proof.v1") << ","
       << "\"tool_name\":" << detail::quote(params.tool_name) << ","
       << "\"tool_server\":" << detail::quote(params.tool_server) << "}";

  auto signed_body = invariants::sign_json_ed25519(body.str(), params.agent_seed_hex);
  if (!signed_body) {
    return Result<DpopProof>::failure(signed_body.error());
  }
  const auto signature = parsed_string_field(signed_body.value(), "signature_hex");
  if (signature.empty()) {
    return Result<DpopProof>::failure(
        Error{ErrorCode::Protocol, "failed to sign DPoP proof body"});
  }

  return Result<DpopProof>::success(DpopProof{body.str(), signature});
}

}  // namespace

Result<DpopProof> sign_dpop_proof(const DpopSignParams& params) {
  return sign_proof(params, nullptr);
}

Result<DpopProof> sign_authority_dpop_proof(const DpopSignParams& params,
                                          const DpopReplayAuthority& authority) {
  return sign_proof(params, &authority);
}

}  // namespace chio
