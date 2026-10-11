#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  cat >&2 <<'EOF'
usage: run-exact-cargo-test-inventory.sh --label LABEL [--allow-filtered] \
  (--expected TEST [TEST ...] | --expected-count COUNT --expected-sha256 HEX) \
  -- cargo test TARGET_ARGS...
EOF
  exit 64
}

label=""
allow_filtered=0
if [[ "${1:-}" == "--label" ]] && [[ "$#" -ge 2 ]]; then
  label="$2"
  shift 2
else
  usage
fi
if [[ "${1:-}" == "--allow-filtered" ]]; then
  allow_filtered=1
  shift
fi
expected=()
expected_count=""
expected_sha256=""
if [[ "${1:-}" == "--expected" ]]; then
  shift
  while [[ "$#" -gt 0 ]] && [[ "$1" != "--" ]]; do
    expected+=("$1")
    shift
  done
  if [[ "${#expected[@]}" -eq 0 ]]; then
    usage
  fi
elif [[ "${1:-}" == "--expected-count" ]] && [[ "$#" -ge 4 ]]; then
  expected_count="$2"
  shift 2
  if [[ "${1:-}" != "--expected-sha256" ]] || [[ "$#" -lt 2 ]]; then
    usage
  fi
  expected_sha256="$2"
  shift 2
else
  usage
fi
if [[ "${1:-}" != "--" ]]; then
  usage
fi
shift
if [[ "$#" -lt 3 ]] || [[ "$1" != "cargo" ]] || [[ "$2" != "test" ]]; then
  usage
fi
for argument in "$@"; do
  if [[ "${argument}" == "--" ]]; then
    echo "${label}: Cargo command must not contain a test-harness separator" >&2
    exit 64
  fi
done

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

list_output="$(mktemp "${TMPDIR:-/tmp}/chio-exact-test-list.XXXXXX")"
run_output="$(mktemp "${TMPDIR:-/tmp}/chio-exact-test-run.XXXXXX")"
trap 'rm -f "${list_output}" "${run_output}"' EXIT

set +e
"$@" -- --list 2>&1 | tee "${list_output}"
list_status=${PIPESTATUS[0]}
set -e
if [[ "${list_status}" -ne 0 ]]; then
  exit "${list_status}"
fi

set +e
"$@" 2>&1 | tee "${run_output}"
run_status=${PIPESTATUS[0]}
set -e
if [[ "${run_status}" -ne 0 ]]; then
  exit "${run_status}"
fi

verifier=(
  python3 scripts/check-exact-cargo-test-inventory.py
  --label "${label}"
  --list-output "${list_output}"
  --run-output "${run_output}"
)
if [[ "${allow_filtered}" -eq 1 ]]; then
  verifier+=(--allow-filtered)
fi
if [[ "${#expected[@]}" -gt 0 ]]; then
  verifier+=("${expected[@]}")
  expected_count="${#expected[@]}"
else
  verifier+=(--expected-count "${expected_count}" --expected-sha256 "${expected_sha256}")
fi
"${verifier[@]}"

echo "${label} passed (${expected_count} exact tests)"
