#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

run_tests() {
  local label="$1"
  shift
  local output
  output="$(mktemp "${TMPDIR:-/tmp}/chio-deception-gate.XXXXXX")"
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

run_tests "deception lifecycle and watermark" cargo test -p chio-decoy --all-targets
run_tests "pre-dispatch tripwire" cargo test -p chio-security-kernel --test adapters tripwire
run_tests "post-response watermark tripwire" cargo test -p chio-security-kernel --test adapters post_output_match
run_tests "sealed private registry" cargo test -p chio-store-sqlite --test sealed_decoy_registry

echo "Deception security gate passed"
