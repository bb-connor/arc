#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export CARGO_INCREMENTAL=0
export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }--cfg chio_kernel_loom"

output="$(mktemp "${TMPDIR:-/tmp}/chio-protocol-primitives-loom.XXXXXX")"
trap 'rm -f "${output}"' EXIT

set +e
cargo test -p chio-kernel --features loom-tests --test loom_concurrency protocol_primitives_ 2>&1 | tee "${output}"
status=${PIPESTATUS[0]}
set -e

if [[ "${status}" -ne 0 ]]; then
  exit "${status}"
fi
if ! grep -Eq 'running [1-9][0-9]* tests' "${output}"; then
  echo "protocol-primitives Loom gate matched zero tests" >&2
  exit 1
fi

echo "Protocol-primitives Loom gate passed"
