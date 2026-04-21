#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
EXAMPLE_ROOT="${ROOT}/examples/agent-commerce-network"
STATE_DIR="${EXAMPLE_ROOT}/artifacts/live/buyer-sidecar"
RECEIPT_STORE="${BUYER_RECEIPT_STORE:-${STATE_DIR}/receipts.sqlite3}"

mkdir -p "${STATE_DIR}"

cd "${ROOT}"

if [[ -n "${CHIO_BIN:-}" ]]; then
  exec "${CHIO_BIN}" \
    --control-url "${CHIO_CONTROL_URL:-http://127.0.0.1:8940}" \
    --control-token "${CHIO_CONTROL_TOKEN:-demo-token}" \
    api protect \
    --upstream "${BUYER_UPSTREAM_URL:-http://127.0.0.1:8101}" \
    --spec "${EXAMPLE_ROOT}/buyer/openapi.yaml" \
    --listen "${BUYER_SIDECAR_LISTEN:-127.0.0.1:9101}" \
    --receipt-store "${RECEIPT_STORE}"
fi

exec cargo run --bin chio -- \
  --control-url "${CHIO_CONTROL_URL:-http://127.0.0.1:8940}" \
  --control-token "${CHIO_CONTROL_TOKEN:-demo-token}" \
  api protect \
  --upstream "${BUYER_UPSTREAM_URL:-http://127.0.0.1:8101}" \
  --spec "${EXAMPLE_ROOT}/buyer/openapi.yaml" \
  --listen "${BUYER_SIDECAR_LISTEN:-127.0.0.1:9101}" \
  --receipt-store "${RECEIPT_STORE}"
