#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

run_tests() {
  local label="$1"
  shift
  local output
  output="$(mktemp "${TMPDIR:-/tmp}/chio-broker-gate.XXXXXX")"
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

run_tests "broker capability and proof binding" cargo test -p chio-secret-broker --test execution
run_tests "production transport API is sealed" cargo test -p chio-secret-broker --doc
run_tests "broker execution concurrency and recovery" cargo test -p chio-secret-broker --test concurrency
run_tests "broker isolation secret boundary" cargo test -p chio-secret-broker --test no_secret_crossing
run_tests "broker network adversarial cases" cargo test -p chio-secret-broker --test network_adversarial
run_tests "governed provisioning and durable receipts" cargo test -p chio-secret-broker --test production_surfaces
run_tests "broker daemon authority and fake upstream" cargo test -p chio-secret-broker --test daemon_runtime
run_tests "daemon payload and sink governance" cargo test -p chio-secret-broker --lib daemon::tests::daemon_governance_binds_payload_and_fake_upstream_is_the_only_secret_sink
run_tests "authority IPC signed response binding" cargo test -p chio-secret-broker --lib authority_ipc::tests::authority_rpc_requires_signed_exact_responses_and_full_capabilities
run_tests "supplemental verifier and combined capture" cargo test -p chio-control-plane --lib security::broker::tests

echo "Secret broker boundary gate passed"
