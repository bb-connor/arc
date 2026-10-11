#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

test_name="receipt_store::tests::scale_recovery::million_receipts_preserve_integrity_queries_retention_and_restore"
list_output="$(mktemp "${TMPDIR:-/tmp}/chio-history-list.XXXXXX")"
run_output="$(mktemp "${TMPDIR:-/tmp}/chio-history-run.XXXXXX")"
trap 'rm -f "${list_output}" "${run_output}"' EXIT
command=(cargo test --locked -p chio-store-sqlite --release --lib "${test_name}")
"${command[@]}" -- --exact --ignored --list 2>&1 | tee "${list_output}"
"${command[@]}" -- --exact --ignored --nocapture 2>&1 | tee "${run_output}"
python3 scripts/check-exact-cargo-test-inventory.py \
  --label "Million-receipt recovery campaign" \
  --list-output "${list_output}" --run-output "${run_output}" --allow-filtered \
  "${test_name}"
echo "Million-receipt recovery campaign passed (1 exact test; 1000000 real appends)"
