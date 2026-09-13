#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runner="scripts/check-protocol-peer-negotiation.sh"
test -x "${runner}"
bash -n "${runner}"

required_mappings=(
  'tests::cross_protocol_kernel_request_preserves_complete_authorization_context cargo test -p chio-cross-protocol --lib'
  'tests::native_cross_protocol_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation cargo test -p chio-cross-protocol --lib'
  'runtime::runtime_tests::authorization::bridge_mcp_kernel_request_preserves_complete_authorization_context cargo test -p chio-mcp-edge --lib'
  'runtime::runtime_tests::authorization::tools_call_meta_preserves_complete_authorization_context cargo test -p chio-mcp-edge --lib'
  'runtime::runtime_tests::authorization::mcp_unnegotiated_authorization_extensions_deny_before_receipt_or_dispatch cargo test -p chio-mcp-edge --lib'
  'tests::a2a_execution_request_preserves_complete_authorization_context cargo test -p chio-a2a-edge --lib'
  'tests::a2a_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation cargo test -p chio-a2a-edge --lib'
  'tests::acp_execution_request_preserves_complete_authorization_context cargo test -p chio-acp-edge --lib'
  'tests::acp_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation cargo test -p chio-acp-edge --lib'
  'tests::browser_rejects_unnegotiated_approval_set_proposal_and_governed_intent cargo test -p chio-kernel-browser --lib'
  'evaluate_rejects_unnegotiated_approval_set_proposal_and_governed_intent cargo test -p chio-kernel-mobile --test ffi_roundtrip'
  'tests::evaluate_rejects_unnegotiated_approval_set_proposal_and_governed_intent cargo test -p chio-cpp-kernel-ffi --lib'
)

for required in "${required_mappings[@]}"; do
  grep -Fq -- "${required}" "${runner}"
done

run_count="$(grep -c '^  run_tests ' "${runner}")"
test "${run_count}" -eq "${#required_mappings[@]}"
grep -Fq 'run-exact-cargo-test-inventory.sh' "${runner}"
grep -Fq -- '--label "${label}" --allow-filtered --expected "${expected}"' "${runner}"

for gate in \
  .github/workflows/ci.yml \
  .github/workflows/enterprise-hardening.yml \
  scripts/ci-pr-tier.sh \
  scripts/ci-workspace.sh
do
  grep -Fq -- "./${runner}" "${gate}"
done

# Exercise the public wrapper with deterministic Cargo output. This does not
# execute Rust or replace the behavioral gate; it calibrates missing/ignored and
# substituted test identities without changing production source.
cargo() {
  local expected=""
  local listing=0
  local argument
  for argument in "$@"; do
    case "${argument}" in
      tests::*|runtime::*|evaluate_rejects_*) expected="${argument}" ;;
      --list) listing=1 ;;
    esac
  done
  test -n "${expected}" || return 64
  if [[ "${CHIO_PEER_TEST_VARIANT}" == "renamed" ]]; then
    expected="${expected}_replacement"
  fi
  if [[ "${listing}" -eq 1 ]]; then
    if [[ "${CHIO_PEER_TEST_VARIANT}" != "missing" ]]; then
      printf '%s: test\n' "${expected}"
    fi
    return 0
  fi
  case "${CHIO_PEER_TEST_VARIANT}" in
    zero)
      printf '%s\n' 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s'
      ;;
    ignored)
      printf 'test %s ... ignored\n' "${expected}"
      printf '%s\n' 'test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 3 filtered out; finished in 0.01s'
      ;;
    *)
      printf 'test %s ... ok\n' "${expected}"
      printf '%s\n' 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s'
      ;;
  esac
}
export -f cargo
CHIO_PEER_TEST_VARIANT=valid bash "${runner}" >/dev/null
for variant in missing renamed zero ignored; do
  if CHIO_PEER_TEST_VARIANT="${variant}" bash "${runner}" >/dev/null 2>&1; then
    echo "peer-negotiation gate accepted ${variant} test mutation" >&2
    exit 1
  fi
done

echo "Protocol peer-negotiation gate contract passed"
