#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
EXAMPLE_ROOT="${ROOT}/examples/agent-commerce-network"
STATE_DIR="${EXAMPLE_ROOT}/artifacts/live/provider-edge"
SESSION_DB="${PROVIDER_SESSION_DB:-${STATE_DIR}/sessions.sqlite3}"
RESUME_HMAC_KEYRING="${PROVIDER_RESUME_HMAC_KEYRING:?set a dedicated PROVIDER_RESUME_HMAC_KEYRING path}"
EDGE_TOKEN="${CHIO_EDGE_TOKEN:?set a dedicated CHIO_EDGE_TOKEN}"
ADMIN_TOKEN="${CHIO_ADMIN_TOKEN:?set a dedicated CHIO_ADMIN_TOKEN}"

if [[ "${ADMIN_TOKEN}" == "${EDGE_TOKEN}" ]]; then
  echo "CHIO_ADMIN_TOKEN must differ from CHIO_EDGE_TOKEN" >&2
  exit 64
fi
if [[ -n "${CHIO_CONTROL_URL:-}" ]]; then
  CONTROL_TOKEN="${CHIO_CONTROL_TOKEN:?set a dedicated CHIO_CONTROL_TOKEN}"
  if [[ "${ADMIN_TOKEN}" == "${CONTROL_TOKEN}" || "${EDGE_TOKEN}" == "${CONTROL_TOKEN}" ]]; then
    echo "edge, admin, and control credentials must be pairwise distinct" >&2
    exit 64
  fi
fi

mkdir -p "${STATE_DIR}"

cd "${ROOT}"

if [[ -n "${CHIO_BIN:-}" ]]; then
  if [[ -n "${CHIO_CONTROL_URL:-}" ]]; then
    exec "${CHIO_BIN}" \
      --control-url "${CHIO_CONTROL_URL}" \
      --control-token "${CONTROL_TOKEN}" \
      mcp serve-http \
      --policy "${EXAMPLE_ROOT}/provider/policy.yaml" \
      --server-id provider-security-review \
      --server-name "Vanguard Security Review" \
      --listen "${PROVIDER_EDGE_LISTEN:-127.0.0.1:8931}" \
      --auth-token "${EDGE_TOKEN}" \
      --admin-token "${ADMIN_TOKEN}" \
      --session-db "${SESSION_DB}" \
      --resume-hmac-keyring "${RESUME_HMAC_KEYRING}" \
      -- \
      python3 "${EXAMPLE_ROOT}/provider/review_server.py"
  fi

  exec "${CHIO_BIN}" \
    mcp serve-http \
    --policy "${EXAMPLE_ROOT}/provider/policy.yaml" \
    --server-id provider-security-review \
    --server-name "Vanguard Security Review" \
    --listen "${PROVIDER_EDGE_LISTEN:-127.0.0.1:8931}" \
    --auth-token "${EDGE_TOKEN}" \
    --admin-token "${ADMIN_TOKEN}" \
    --receipt-db "${STATE_DIR}/receipts.sqlite3" \
    --revocation-db "${STATE_DIR}/revocations.sqlite3" \
    --authority-db "${STATE_DIR}/authority.sqlite3" \
    --session-db "${SESSION_DB}" \
    --resume-hmac-keyring "${RESUME_HMAC_KEYRING}" \
    -- \
    python3 "${EXAMPLE_ROOT}/provider/review_server.py"
fi

if [[ -n "${CHIO_CONTROL_URL:-}" ]]; then
  exec cargo run --bin chio -- \
    --control-url "${CHIO_CONTROL_URL}" \
    --control-token "${CONTROL_TOKEN}" \
    mcp serve-http \
    --policy "${EXAMPLE_ROOT}/provider/policy.yaml" \
    --server-id provider-security-review \
    --server-name "Vanguard Security Review" \
    --listen "${PROVIDER_EDGE_LISTEN:-127.0.0.1:8931}" \
    --auth-token "${EDGE_TOKEN}" \
    --admin-token "${ADMIN_TOKEN}" \
    --session-db "${SESSION_DB}" \
    --resume-hmac-keyring "${RESUME_HMAC_KEYRING}" \
    -- \
    python3 "${EXAMPLE_ROOT}/provider/review_server.py"
fi

exec cargo run --bin chio -- \
  mcp serve-http \
  --policy "${EXAMPLE_ROOT}/provider/policy.yaml" \
  --server-id provider-security-review \
  --server-name "Vanguard Security Review" \
  --listen "${PROVIDER_EDGE_LISTEN:-127.0.0.1:8931}" \
  --auth-token "${EDGE_TOKEN}" \
  --admin-token "${ADMIN_TOKEN}" \
  --receipt-db "${STATE_DIR}/receipts.sqlite3" \
  --revocation-db "${STATE_DIR}/revocations.sqlite3" \
  --authority-db "${STATE_DIR}/authority.sqlite3" \
  --session-db "${SESSION_DB}" \
  --resume-hmac-keyring "${RESUME_HMAC_KEYRING}" \
  -- \
  python3 "${EXAMPLE_ROOT}/provider/review_server.py"
