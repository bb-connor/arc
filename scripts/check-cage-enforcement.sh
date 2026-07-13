#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

run_tests() {
  local label="$1"
  shift
  local output
  output="$(mktemp "${TMPDIR:-/tmp}/chio-cage-gate.XXXXXX")"
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

python3 scripts/check-linux-enforcement-stack.py
run_tests "signed cage enforcement evidence" cargo test -p chio-cage --test enforcement_evidence

if [[ "$(uname -s)" == "Linux" ]]; then
  run_tests "cage FD and helper identity compilation" cargo test -p chio-cage --test linux_compile
else
  run_tests \
    "unsupported-host fail-closed admission" \
    cargo test -p chio-cage --lib unsupported_platform_denies_after_verified_admission
fi

if [[ "${CHIO_ENTERPRISE_SECURITY_RUNNER:-0}" != "1" ]]; then
  echo "Cage portable gate passed; no real-Linux release evidence was produced"
  exit 0
fi

if [[ "$(uname -s):$(uname -m)" != "Linux:x86_64" ]]; then
  echo "designated enterprise security runner must be Linux x86_64" >&2
  exit 1
fi
command -v cc >/dev/null
test -r /proc/self/status

run_tests \
  "real Linux cage enforcement" \
  crates/security/chio-cage/scripts/check-linux-enforcement.sh

echo "Cage enforcement gate passed with real-Linux evidence"
