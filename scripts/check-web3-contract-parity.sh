#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
  echo "web3 contract parity requires jq on PATH" >&2
  exit 1
fi

env CARGO_TARGET_DIR=target/arc-core-web3-parity CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p arc-core web3 -- --test-threads=1
env CARGO_TARGET_DIR=target/arc-web3-bindings-parity CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p arc-web3-bindings -- --test-threads=1
jq empty \
  docs/standards/ARC_WEB3_CONTRACT_PACKAGE.json \
  docs/standards/ARC_WEB3_CHAIN_CONFIGURATION.json \
  docs/standards/ARC_WEB3_QUALIFICATION_MATRIX.json \
  docs/standards/ARC_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json

echo "web3 contract parity verified"
