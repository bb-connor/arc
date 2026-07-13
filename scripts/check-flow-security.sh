#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

run_tests() {
  local label="$1"
  shift
  local output
  output="$(mktemp "${TMPDIR:-/tmp}/chio-flow-gate.XXXXXX")"
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

command -v apalache-mc >/dev/null
command -v rustup >/dev/null
rustup target list --installed | grep -qx 'wasm32-unknown-unknown'

python3 scripts/check-apalache-formal-slice.py

apalache-mc check \
  --length=6 \
  --config=formal/tla/MCInformationFlowLattice.cfg \
  formal/tla/InformationFlowLattice.tla

negative_output="$(mktemp "${TMPDIR:-/tmp}/chio-flow-negative.XXXXXX")"
trap 'rm -f "${negative_output}"' EXIT
set +e
apalache-mc check \
  --length=6 \
  --config=formal/tla/_negative_tests/MCInformationFlowLatticeReaderDirectionBroken.cfg \
  formal/tla/_negative_tests/InformationFlowLatticeReaderDirectionBroken.tla \
  2>&1 | tee "${negative_output}"
negative_status=${PIPESTATUS[0]}
set -e
if [[ "${negative_status}" -eq 0 ]]; then
  echo "information-flow reader-direction mutation unexpectedly satisfied SafetyInv" >&2
  exit 1
fi
grep -Eq 'state invariant [0-9]+ violated' "${negative_output}"
grep -Fq 'The outcome is: Error' "${negative_output}"

cargo check -p chio-security-types --no-default-features --target wasm32-unknown-unknown
cargo check -p chio-flow --no-default-features --target wasm32-unknown-unknown

run_tests "chio-security-types" cargo test -p chio-security-types --all-targets
run_tests "chio-flow" cargo test -p chio-flow --all-targets
run_tests "strict manifest v2" cargo test -p chio-manifest --test manifest_v2
run_tests "flow kernel adapters" cargo test -p chio-security-kernel --test adapters flow_
run_tests "durable flow state" cargo test -p chio-store-sqlite --test security_state
run_tests "security runtime composition" cargo test -p chio-control-plane --test security_runtime
run_tests "OpenAPI flow metadata" cargo test -p chio-openapi x_chio_flow
run_tests "MCP flow sidecar" cargo test -p chio-mcp-edge constrained_tool_retains_internal_flow_sidecar
run_tests "security schema vectors" cargo test -p chio-conformance --test vectors_schema_pair

echo "Flow security gate passed"
