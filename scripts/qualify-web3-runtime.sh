#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
  echo "web3 runtime qualification requires jq on PATH" >&2
  exit 1
fi

if ! command -v pnpm >/dev/null 2>&1; then
  echo "web3 runtime qualification requires pnpm on PATH" >&2
  exit 1
fi

output_root="target/web3-runtime-qualification"
log_path="${output_root}/qualification.log"
mkdir -p "${output_root}"
: >"${log_path}"

run() {
  printf '==> %s\n' "$*" | tee -a "${log_path}"
  "$@" 2>&1 | tee -a "${log_path}"
}

run pnpm --dir contracts install --frozen-lockfile
run cargo fmt --all --check
run env CARGO_TARGET_DIR=target/chio-cli-web3-evidence CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-cli web3_evidence -- --test-threads=1
run env CARGO_TARGET_DIR=target/chio-control-plane-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-control-plane web3_evidence -- --test-threads=1
run env CARGO_TARGET_DIR=target/chio-link-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-link -- --test-threads=1
run env CARGO_TARGET_DIR=target/chio-kernel-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-kernel web3_evidence -- --test-threads=1
run env CARGO_TARGET_DIR=target/chio-kernel-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-kernel cross_currency -- --test-threads=1
run ./scripts/check-web3-contract-parity.sh
run env CARGO_TARGET_DIR=target/chio-anchor-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-anchor evidence_bundle -- --test-threads=1
run env CARGO_TARGET_DIR=target/chio-anchor-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-anchor -- --test-threads=1
run env CARGO_TARGET_DIR=target/chio-settle-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-settle evidence_substrate -- --test-threads=1
run env CARGO_TARGET_DIR=target/chio-settle-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-settle --lib -- --test-threads=1
run env CARGO_TARGET_DIR=target/chio-settle-runtime CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-settle --test runtime_devnet -- --nocapture
run pnpm --dir contracts devnet:smoke
run ./scripts/qualify-web3-e2e.sh
run ./scripts/qualify-web3-ops-controls.sh
run jq empty \
  docs/standards/CHIO_LINK_BASE_MAINNET_CONFIG.json \
  docs/standards/CHIO_LINK_MONITOR_REPORT_EXAMPLE.json \
  docs/standards/CHIO_LINK_QUALIFICATION_MATRIX.json \
  docs/standards/CHIO_ANCHOR_DISCOVERY_EXAMPLE.json \
  docs/standards/CHIO_ANCHOR_OTS_SUBMISSION_EXAMPLE.json \
  docs/standards/CHIO_ANCHOR_SOLANA_MEMO_EXAMPLE.json \
  docs/standards/CHIO_ANCHOR_PROOF_BUNDLE_EXAMPLE.json \
  docs/standards/CHIO_ANCHOR_QUALIFICATION_MATRIX.json \
  docs/standards/CHIO_ANCHOR_RUNTIME_REPORT_EXAMPLE.json \
  docs/standards/CHIO_SETTLE_FINALITY_REPORT_EXAMPLE.json \
  docs/standards/CHIO_SETTLE_SOLANA_RELEASE_EXAMPLE.json \
  docs/standards/CHIO_SETTLE_QUALIFICATION_MATRIX.json \
  docs/standards/CHIO_SETTLE_RUNTIME_REPORT_EXAMPLE.json \
  docs/standards/CHIO_FUNCTIONS_REQUEST_EXAMPLE.json \
  docs/standards/CHIO_FUNCTIONS_RESPONSE_EXAMPLE.json \
  docs/standards/CHIO_ANCHOR_AUTOMATION_JOB_EXAMPLE.json \
  docs/standards/CHIO_SETTLEMENT_WATCHDOG_JOB_EXAMPLE.json \
  docs/standards/CHIO_CCIP_MESSAGE_EXAMPLE.json \
  docs/standards/CHIO_CCIP_RECONCILIATION_EXAMPLE.json \
  docs/standards/CHIO_X402_REQUIREMENTS_EXAMPLE.json \
  docs/standards/CHIO_EIP3009_TRANSFER_WITH_AUTHORIZATION_EXAMPLE.json \
  docs/standards/CHIO_CIRCLE_NANOPAYMENT_EXAMPLE.json \
  docs/standards/CHIO_4337_PAYMASTER_COMPAT_EXAMPLE.json \
  docs/standards/CHIO_WEB3_AUTOMATION_QUALIFICATION_MATRIX.json \
  docs/standards/CHIO_WEB3_EXTERNAL_QUALIFICATION_MATRIX.json \
  docs/standards/CHIO_WEB3_OPERATIONS_QUALIFICATION_MATRIX.json
run git diff --check

printf 'web3 runtime qualification complete; log written to %s\n' "${log_path}" | tee -a "${log_path}"
