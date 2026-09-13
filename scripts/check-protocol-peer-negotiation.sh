#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

run_tests() {
  local label="$1"
  shift
  local output
  output="$(mktemp "${TMPDIR:-/tmp}/chio-peer-negotiation-gate.XXXXXX")"
  set +e
  "$@" 2>&1 | tee "${output}"
  local status=${PIPESTATUS[0]}
  set -e
  if [[ "${status}" -ne 0 ]]; then
    rm -f "${output}"
    return "${status}"
  fi
  if ! grep -Eq 'test result: ok\. [1-9][0-9]* passed' "${output}"; then
    echo "${label} matched zero tests" >&2
    rm -f "${output}"
    return 1
  fi
  rm -f "${output}"
}

main() {
  cd "${repo_root}"
  export CARGO_INCREMENTAL=0
  export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

  run_tests "native negotiated authorization preservation" cargo test -p chio-cross-protocol tests::cross_protocol_kernel_request_preserves_complete_authorization_context -- --exact
  run_tests "native unnegotiated authorization denial" cargo test -p chio-cross-protocol tests::native_cross_protocol_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation -- --exact
  run_tests "MCP bridge authorization preservation" cargo test -p chio-mcp-edge runtime::runtime_tests::bridge_mcp_kernel_request_preserves_complete_authorization_context -- --exact
  run_tests "MCP negotiated authorization preservation" cargo test -p chio-mcp-edge runtime::runtime_tests::tools_call_meta_preserves_complete_authorization_context -- --exact
  run_tests "MCP unnegotiated authorization denial" cargo test -p chio-mcp-edge runtime::runtime_tests::mcp_unnegotiated_authorization_extensions_deny_before_receipt_or_dispatch -- --exact
  run_tests "A2A negotiated authorization preservation" cargo test -p chio-a2a-edge tests::a2a_execution_request_preserves_complete_authorization_context -- --exact
  run_tests "A2A unnegotiated authorization denial" cargo test -p chio-a2a-edge tests::a2a_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation -- --exact
  run_tests "ACP negotiated authorization preservation" cargo test -p chio-acp-edge tests::acp_execution_request_preserves_complete_authorization_context -- --exact
  run_tests "ACP unnegotiated authorization denial" cargo test -p chio-acp-edge tests::acp_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation -- --exact
  run_tests "browser unnegotiated authorization denial" cargo test -p chio-kernel-browser tests::browser_rejects_unnegotiated_approval_set_proposal_and_governed_intent -- --exact
  run_tests "mobile unnegotiated authorization denial" cargo test -p chio-kernel-mobile --test ffi_roundtrip evaluate_rejects_unnegotiated_approval_set_proposal_and_governed_intent -- --exact
  run_tests "C++ FFI unnegotiated authorization denial" cargo test -p chio-cpp-kernel-ffi tests::evaluate_rejects_unnegotiated_approval_set_proposal_and_governed_intent -- --exact

  echo "Protocol peer-negotiation gate passed"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
