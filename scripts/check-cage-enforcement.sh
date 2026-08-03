#!/usr/bin/env bash
set -euo pipefail
umask 022

if [[ "${CHIO_ENTERPRISE_SECURITY_RUNNER:-0}" == "1" ]]; then
  workspace="${CHIO_SECURITY_WORKSPACE:-}"
  stack_checker="${CHIO_SECURITY_LINUX_STACK_CHECKER:-}"
  inventory_checker="${CHIO_SECURITY_CAGE_INVENTORY_CHECKER:-}"
  linux_runner="${CHIO_SECURITY_CAGE_LINUX_RUNNER:-}"
  if [[ "$workspace" != "/private/candidate" ]] ||
    [[ "$stack_checker" != "/opt/chio-security/gates/check-linux-enforcement-stack.py" ]] ||
    [[ "$inventory_checker" != "/opt/chio-security/gates/check-cage-all-target-inventory.py" ]] ||
    [[ "$linux_runner" != "/opt/chio-security/gates/check-cage-linux-enforcement.sh" ]]; then
    echo "designated enterprise cage paths do not match the trusted contract" >&2
    exit 1
  fi
  for trusted_path in "$stack_checker" "$inventory_checker" "$linux_runner"; do
    if [[ ! -f "$trusted_path" ]] || [[ -L "$trusted_path" ]]; then
      echo "designated enterprise cage gate is missing or symbolic: $trusted_path" >&2
      exit 1
    fi
  done
else
  for variable in \
    CHIO_SECURITY_WORKSPACE \
    CHIO_SECURITY_LINUX_STACK_CHECKER \
    CHIO_SECURITY_CAGE_INVENTORY_CHECKER \
    CHIO_SECURITY_CAGE_LINUX_RUNNER; do
    if [[ -n "${!variable:-}" ]]; then
      echo "trusted enterprise cage path leaked into a portable invocation: $variable" >&2
      exit 1
    fi
  done
  workspace="$(cd "$(dirname "$0")/.." && pwd)"
  stack_checker="$workspace/scripts/check-linux-enforcement-stack.py"
  inventory_checker="$workspace/scripts/check-cage-all-target-inventory.py"
  linux_runner="$workspace/crates/security/chio-cage/scripts/check-linux-enforcement.sh"
fi
cd "$workspace"

mode="${1:---release}"
if [[ "$#" -gt 1 ]] || [[ "$mode" != "--release" && "$mode" != "--portable" ]]; then
  echo "usage: $0 [--release|--portable]" >&2
  exit 64
fi

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

python3 -I "$stack_checker" --root "$PWD" --require-lock
python3 -I "$inventory_checker" --root "$PWD" --source-only
run_tests "signed cage enforcement evidence" cargo test -p chio-cage --test enforcement_evidence

if [[ "$(uname -s)" == "Linux" ]]; then
  run_tests "cage FD and helper identity compilation" cargo test -p chio-cage --test linux_compile
else
  run_tests \
    "unsupported-host fail-closed admission" \
    cargo test -p chio-cage --lib unsupported_platform_denies_after_verified_admission
fi

if [[ "$mode" == "--portable" ]]; then
  echo "Cage portable gate passed; no real-Linux release evidence was produced"
  exit 0
fi

if [[ "${CHIO_ENTERPRISE_SECURITY_RUNNER:-0}" != "1" ]]; then
  echo "real-Linux release evidence requires the designated enterprise security runner" >&2
  exit 1
fi

if [[ "$(uname -s):$(uname -m)" != "Linux:x86_64" ]]; then
  echo "designated enterprise security runner must be Linux x86_64" >&2
  exit 1
fi
command -v cc >/dev/null
test -r /proc/self/status

challenge="$(LC_ALL=C od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
if [[ ! "$challenge" =~ ^[a-f0-9]{64}$ ]]; then
  echo "failed to generate a real-Linux evidence challenge" >&2
  exit 1
fi
output="$(mktemp "${TMPDIR:-/tmp}/chio-cage-linux-release.XXXXXX")"
trap 'rm -f "$output"' EXIT
set +e
CHIO_CAGE_EVIDENCE_CHALLENGE="$challenge" \
  "$linux_runner" 2>&1 | tee "$output"
status=${PIPESTATUS[0]}
set -e
if [[ "$status" -ne 0 ]]; then
  exit "$status"
fi
marker="CHIO_CAGE_REAL_LINUX_EVIDENCE challenge=$challenge"
if [[ "$(grep -Ec "^${marker} all_targets=68 probes=26 mutations=10$" "$output")" -ne 1 ]]; then
  echo "real-Linux cage evidence marker is absent, stale, or ambiguous" >&2
  exit 1
fi

echo "Cage enforcement gate passed with real-Linux evidence"
