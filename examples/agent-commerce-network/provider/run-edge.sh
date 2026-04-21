#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
EXAMPLE_ROOT="${ROOT}/examples/agent-commerce-network"
STATE_DIR="${EXAMPLE_ROOT}/artifacts/live/provider-edge"
SESSION_DB="${PROVIDER_SESSION_DB:-${STATE_DIR}/sessions.sqlite3}"

mkdir -p "${STATE_DIR}"

cd "${ROOT}"

if [[ -n "${CHIO_BIN:-}" ]]; then
  if [[ -n "${CHIO_CONTROL_URL:-}" ]]; then
    exec "${CHIO_BIN}" \
      --control-url "${CHIO_CONTROL_URL}" \
      --control-token "${CHIO_CONTROL_TOKEN:-demo-token}" \
      mcp serve-http \
      --policy "${EXAMPLE_ROOT}/provider/policy.yaml" \
      --server-id provider-security-review \
      --server-name "Vanguard Security Review" \
      --listen "${PROVIDER_EDGE_LISTEN:-127.0.0.1:8931}" \
      --auth-token "${CHIO_EDGE_TOKEN:-demo-token}" \
      --session-db "${SESSION_DB}" \
      -- \
      python3 "${EXAMPLE_ROOT}/provider/review_server.py"
  fi

  exec "${CHIO_BIN}" \
    mcp serve-http \
    --policy "${EXAMPLE_ROOT}/provider/policy.yaml" \
    --server-id provider-security-review \
    --server-name "Vanguard Security Review" \
    --listen "${PROVIDER_EDGE_LISTEN:-127.0.0.1:8931}" \
    --auth-token "${CHIO_EDGE_TOKEN:-demo-token}" \
    --receipt-db "${STATE_DIR}/receipts.sqlite3" \
    --revocation-db "${STATE_DIR}/revocations.sqlite3" \
    --authority-db "${STATE_DIR}/authority.sqlite3" \
    --session-db "${SESSION_DB}" \
    -- \
    python3 "${EXAMPLE_ROOT}/provider/review_server.py"
fi

if [[ -n "${CHIO_CONTROL_URL:-}" ]]; then
  exec cargo run --bin chio -- \
    --control-url "${CHIO_CONTROL_URL}" \
    --control-token "${CHIO_CONTROL_TOKEN:-demo-token}" \
    mcp serve-http \
    --policy "${EXAMPLE_ROOT}/provider/policy.yaml" \
    --server-id provider-security-review \
    --server-name "Vanguard Security Review" \
    --listen "${PROVIDER_EDGE_LISTEN:-127.0.0.1:8931}" \
    --auth-token "${CHIO_EDGE_TOKEN:-demo-token}" \
    --session-db "${SESSION_DB}" \
    -- \
    python3 "${EXAMPLE_ROOT}/provider/review_server.py"
fi

exec cargo run --bin chio -- \
  mcp serve-http \
  --policy "${EXAMPLE_ROOT}/provider/policy.yaml" \
  --server-id provider-security-review \
  --server-name "Vanguard Security Review" \
  --listen "${PROVIDER_EDGE_LISTEN:-127.0.0.1:8931}" \
  --auth-token "${CHIO_EDGE_TOKEN:-demo-token}" \
  --receipt-db "${STATE_DIR}/receipts.sqlite3" \
  --revocation-db "${STATE_DIR}/revocations.sqlite3" \
  --authority-db "${STATE_DIR}/authority.sqlite3" \
  --session-db "${SESSION_DB}" \
  -- \
  python3 "${EXAMPLE_ROOT}/provider/review_server.py"
