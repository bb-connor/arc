#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

run_tests() {
  local label="$1"
  shift
  local output
  output="$(mktemp "${TMPDIR:-/tmp}/chio-response-gate.XXXXXX")"
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

run_tests "response transition state machine" cargo test -p chio-quarantine --test state_machine
run_tests "response executor crash recovery" cargo test -p chio-quarantine --test response_executor executor_crash_
run_tests "response receipt truth" cargo test -p chio-quarantine --test response_executor receipt_truth_
run_tests "scheduler stale-worker fencing" cargo test -p chio-quarantine --test response_scheduler scheduler_fencing_
run_tests "scheduler TTL recovery" cargo test -p chio-quarantine --test response_scheduler scheduler_ttl_
run_tests "durable response authorities" cargo test -p chio-store-sqlite --test security_state scheduler_
run_tests "overlapping restrictive contributions" cargo test -p chio-store-sqlite --test security_state overlapping_overlay_

echo "Response recovery gate passed"
