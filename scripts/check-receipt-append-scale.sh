#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

test_name="receipt_store::tests::scale_proof::append_scale_proof_is_batch_bounded_across_history_sizes"
list_output="$(mktemp "${TMPDIR:-/tmp}/chio-scale-list.XXXXXX")"
run_output="$(mktemp "${TMPDIR:-/tmp}/chio-scale-run.XXXXXX")"
trap 'rm -f "${list_output}" "${run_output}"' EXIT

command=(cargo test --locked -p chio-store-sqlite --release --lib "${test_name}")
"${command[@]}" -- --exact --ignored --list 2>&1 | tee "${list_output}"
"${command[@]}" -- --exact --ignored --nocapture 2>&1 | tee "${run_output}"

python3 scripts/check-exact-cargo-test-inventory.py \
  --label "Receipt append scale proof" \
  --list-output "${list_output}" \
  --run-output "${run_output}" \
  --allow-filtered \
  "${test_name}"

echo "Receipt append scale proof passed (1 exact test; histories 1000, 100000, 1000000)"
