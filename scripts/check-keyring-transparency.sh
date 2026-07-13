#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

run_tests() {
  local label="$1"
  shift
  local output
  output="$(mktemp "${TMPDIR:-/tmp}/chio-keyring-gate.XXXXXX")"
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

run_tests "RFC 6962 vectors" cargo test -p chio-core-types merkle
run_tests "complete key-log envelopes" cargo test -p chio-keyring --test event
run_tests "checkpoint and witness signatures" cargo test -p chio-keyring --test checkpoint
run_tests "two-stage activation and artifact time" cargo test -p chio-keyring --test state
run_tests "transactional key-log storage" cargo test -p chio-keyring --test sqlite
run_tests "signing epoch serialization" cargo test -p chio-keyring --test router
run_tests "trusted artifact-time anchors" cargo test -p chio-keyring --test time
run_tests "contiguous synchronization and split views" cargo test -p chio-keyring --test witness_sync
run_tests "complete witnessed history" cargo test -p chio-keyring --test history
run_tests "keyring service policy and seed custody" cargo test -p chio-keyring --test service

echo "Keyring transparency gate passed"
