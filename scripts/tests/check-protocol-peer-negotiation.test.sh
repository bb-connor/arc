#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runner="scripts/check-protocol-peer-negotiation.sh"
test -x "${runner}"
bash -n "${runner}"

required_mappings=(
  'cargo test -p chio-cross-protocol tests::cross_protocol_kernel_request_preserves_complete_authorization_context -- --exact'
  'cargo test -p chio-cross-protocol tests::native_cross_protocol_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation -- --exact'
  'cargo test -p chio-mcp-edge runtime::runtime_tests::bridge_mcp_kernel_request_preserves_complete_authorization_context -- --exact'
  'cargo test -p chio-mcp-edge runtime::runtime_tests::tools_call_meta_preserves_complete_authorization_context -- --exact'
  'cargo test -p chio-mcp-edge runtime::runtime_tests::mcp_unnegotiated_authorization_extensions_deny_before_receipt_or_dispatch -- --exact'
  'cargo test -p chio-a2a-edge tests::a2a_execution_request_preserves_complete_authorization_context -- --exact'
  'cargo test -p chio-a2a-edge tests::a2a_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation -- --exact'
  'cargo test -p chio-acp-edge tests::acp_execution_request_preserves_complete_authorization_context -- --exact'
  'cargo test -p chio-acp-edge tests::acp_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation -- --exact'
  'cargo test -p chio-kernel-browser tests::browser_rejects_unnegotiated_approval_set_proposal_and_governed_intent -- --exact'
  'cargo test -p chio-kernel-mobile --test ffi_roundtrip evaluate_rejects_unnegotiated_approval_set_proposal_and_governed_intent -- --exact'
  'cargo test -p chio-cpp-kernel-ffi tests::evaluate_rejects_unnegotiated_approval_set_proposal_and_governed_intent -- --exact'
)

for required in "${required_mappings[@]}"; do
  grep -Fq -- "${required}" "${runner}"
done

run_count="$(grep -c '^  run_tests ' "${runner}")"
exact_count="$(grep -c '^  run_tests .* -- --exact$' "${runner}")"
test "${run_count}" -eq "${#required_mappings[@]}"
test "${exact_count}" -eq "${run_count}"

for gate in \
  .github/workflows/ci.yml \
  .github/workflows/enterprise-hardening.yml \
  scripts/ci-pr-tier.sh \
  scripts/ci-workspace.sh
do
  grep -Fq -- "./${runner}" "${gate}"
done

set +e
zero_match_output="$({
  # shellcheck source=scripts/check-protocol-peer-negotiation.sh
  source "${runner}"
  run_tests "zero-match peer-negotiation probe" bash -c \
    'printf "%s\n" "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out"'
} 2>&1)"
zero_match_status=$?
set -e
test "${zero_match_status}" -ne 0
grep -Fq 'zero-match peer-negotiation probe matched zero tests' <<<"${zero_match_output}"

echo "Protocol peer-negotiation gate contract passed"
