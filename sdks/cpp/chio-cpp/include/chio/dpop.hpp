#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "chio/result.hpp"

namespace chio {

struct DpopProof {
  std::string body_json;
  std::string signature_hex;

  std::string to_json() const;
};

struct DpopSignParams {
  std::string capability_id;
  std::string tool_server;
  std::string tool_name;
  std::string action_args_json;
  std::string agent_seed_hex;
  std::string nonce;
  std::uint64_t issued_at = 0;
};

Result<DpopProof> sign_dpop_proof(const DpopSignParams& params);

// Independently configured durable domain, not evidence of activation.
struct DpopReplayAuthority {
  std::string destination_store_uuid;
  std::string dpop_authority_id;
  std::string expectation_id;
  std::uint64_t proof_ttl_secs = 300;
  std::uint64_t max_clock_skew_secs = 30;
};

// V2 signatures bind the complete domain. Legacy nonce-store verifiers reject
// this profile; signing itself neither reserves a nonce nor permits execution.
Result<DpopProof> sign_authority_dpop_proof(const DpopSignParams& params,
                                          const DpopReplayAuthority& authority);

}  // namespace chio
