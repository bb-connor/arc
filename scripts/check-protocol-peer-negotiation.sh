#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

run_tests() {
  local label="$1"
  local expected="$2"
  shift 2
  # Pin both the listed and executed identity. A similarly named replacement,
  # ignored test or extra target must not satisfy the negotiated-peer contract.
  "${repo_root}/scripts/run-exact-cargo-test-inventory.sh" \
    --label "${label}" --allow-filtered --expected "${expected}" \
    -- "$@" --locked "${expected}"
}

main() {
  cd "${repo_root}"
  export CARGO_INCREMENTAL=0
  export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

  run_tests "native negotiated authorization preservation" tests::cross_protocol_kernel_request_preserves_complete_authorization_context cargo test -p chio-cross-protocol --lib
  run_tests "native unnegotiated authorization denial" tests::native_cross_protocol_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation cargo test -p chio-cross-protocol --lib
  run_tests "MCP bridge authorization preservation" runtime::runtime_tests::authorization::bridge_mcp_kernel_request_preserves_complete_authorization_context cargo test -p chio-mcp-edge --lib
  run_tests "MCP negotiated authorization preservation" runtime::runtime_tests::authorization::tools_call_meta_preserves_complete_authorization_context cargo test -p chio-mcp-edge --lib
  run_tests "MCP unnegotiated authorization denial" runtime::runtime_tests::authorization::mcp_unnegotiated_authorization_extensions_deny_before_receipt_or_dispatch cargo test -p chio-mcp-edge --lib
  run_tests "A2A negotiated authorization preservation" tests::a2a_execution_request_preserves_complete_authorization_context cargo test -p chio-a2a-edge --lib
  run_tests "A2A unnegotiated authorization denial" tests::a2a_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation cargo test -p chio-a2a-edge --lib
  run_tests "ACP negotiated authorization preservation" tests::acp_execution_request_preserves_complete_authorization_context cargo test -p chio-acp-edge --lib
  run_tests "ACP unnegotiated authorization denial" tests::acp_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation cargo test -p chio-acp-edge --lib
  run_tests "browser unnegotiated authorization denial" tests::browser_rejects_unnegotiated_approval_set_proposal_and_governed_intent cargo test -p chio-kernel-browser --lib
  run_tests "mobile unnegotiated authorization denial" evaluate_rejects_unnegotiated_approval_set_proposal_and_governed_intent cargo test -p chio-kernel-mobile --test ffi_roundtrip
  run_tests "C++ FFI unnegotiated authorization denial" tests::evaluate_rejects_unnegotiated_approval_set_proposal_and_governed_intent cargo test -p chio-cpp-kernel-ffi --lib

  echo "Protocol peer-negotiation gate passed"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
