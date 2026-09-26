#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
EXAMPLE_ROOT="${ROOT}/examples/agent-commerce-network"
STATE_DIR="${EXAMPLE_ROOT}/artifacts/live/buyer-sidecar"
RECEIPT_STORE="${BUYER_RECEIPT_STORE:-${STATE_DIR}/receipts.sqlite3}"

source "${ROOT}/scripts/lib/provision-mcp-launch.sh"

mkdir -p "${STATE_DIR}"

cd "${ROOT}"

# The sidecar trusts only capabilities issued by the authority it pins.
CONTROL_URL="${CHIO_CONTROL_URL:-http://127.0.0.1:8940}"
CONTROL_TOKEN="${CHIO_CONTROL_TOKEN:-demo-control-token}"
CONTROL_AUTHORITY_PUBLIC_KEY="$(chio_control_authority_public_key "${CONTROL_URL}" "${CONTROL_TOKEN}")"

if [[ -n "${CHIO_BIN:-}" ]]; then
  exec "${CHIO_BIN}" \
    --control-url "${CONTROL_URL}" \
    --control-token "${CONTROL_TOKEN}" \
    --control-authority-public-key "${CONTROL_AUTHORITY_PUBLIC_KEY}" \
    api protect \
    --upstream "${BUYER_UPSTREAM_URL:-http://127.0.0.1:8101}" \
    --spec "${EXAMPLE_ROOT}/buyer/openapi.yaml" \
    --listen "${BUYER_SIDECAR_LISTEN:-127.0.0.1:9101}" \
    --receipt-store "${RECEIPT_STORE}"
fi

exec cargo run --bin chio -- \
  --control-url "${CONTROL_URL}" \
  --control-token "${CONTROL_TOKEN}" \
  --control-authority-public-key "${CONTROL_AUTHORITY_PUBLIC_KEY}" \
  api protect \
  --upstream "${BUYER_UPSTREAM_URL:-http://127.0.0.1:8101}" \
  --spec "${EXAMPLE_ROOT}/buyer/openapi.yaml" \
  --listen "${BUYER_SIDECAR_LISTEN:-127.0.0.1:9101}" \
  --receipt-store "${RECEIPT_STORE}"
