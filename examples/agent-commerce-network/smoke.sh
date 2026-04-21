#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${EXAMPLE_ROOT}/../.." && pwd)"
source "${ROOT}/examples/_shared/hello-http-common.sh"

ARTIFACT_ROOT="${EXAMPLE_ROOT}/artifacts/live/$(date -u +"%Y%m%dT%H%M%SZ")"
LOG_DIR="${ARTIFACT_ROOT}/logs"
STATE_DIR="${ARTIFACT_ROOT}/state"
mkdir -p "${LOG_DIR}" "${STATE_DIR}"

CHIO_BIN="$(ensure_chio_bin)"
SERVICE_TOKEN="${CHIO_SERVICE_TOKEN:-demo-token}"
EDGE_TOKEN="${CHIO_EDGE_TOKEN:-demo-token}"

TRUST_PORT="$(pick_free_port)"
PROVIDER_PORT="$(pick_free_port)"
BUYER_API_PORT="$(pick_free_port)"
BUYER_SIDECAR_PORT="$(pick_free_port)"

CONTROL_URL="http://127.0.0.1:${TRUST_PORT}"
PROVIDER_URL="http://127.0.0.1:${PROVIDER_PORT}"
BUYER_API_URL="http://127.0.0.1:${BUYER_API_PORT}"
BUYER_SIDECAR_URL="http://127.0.0.1:${BUYER_SIDECAR_PORT}"

BG_PIDS=()
cleanup() {
  for pid in "${BG_PIDS[@]}"; do
    kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
  done
}
trap cleanup EXIT

# Chio trust-control
"${CHIO_BIN}" trust serve \
  --listen "127.0.0.1:${TRUST_PORT}" --service-token "${SERVICE_TOKEN}" \
  --receipt-db "${STATE_DIR}/trust-receipts.sqlite3" \
  --revocation-db "${STATE_DIR}/trust-revocations.sqlite3" \
  --authority-db "${STATE_DIR}/trust-authority.sqlite3" \
  --budget-db "${STATE_DIR}/trust-budgets.sqlite3" \
  >"${LOG_DIR}/trust.log" 2>&1 &
BG_PIDS+=($!)

wait_for_http "${CONTROL_URL}/health"

# Provider MCP edge (chio mcp serve-http wrapping the review server)
CHIO_BIN="${CHIO_BIN}" \
CHIO_CONTROL_URL="${CONTROL_URL}" \
CHIO_CONTROL_TOKEN="${SERVICE_TOKEN}" \
CHIO_EDGE_TOKEN="${EDGE_TOKEN}" \
PROVIDER_EDGE_LISTEN="127.0.0.1:${PROVIDER_PORT}" \
PROVIDER_SESSION_DB="${STATE_DIR}/provider-sessions.sqlite3" \
  "${EXAMPLE_ROOT}/provider/run-edge.sh" \
  >"${LOG_DIR}/provider-edge.log" 2>&1 &
BG_PIDS+=($!)

wait_for_port 127.0.0.1 "${PROVIDER_PORT}"

# Buyer FastAPI service
BUYER_PROVIDER_BASE_URL="${PROVIDER_URL}" \
BUYER_PROVIDER_AUTH_TOKEN="${EDGE_TOKEN}" \
  uv run --project "${EXAMPLE_ROOT}" uvicorn buyer.app:app \
  --host 127.0.0.1 --port "${BUYER_API_PORT}" \
  >"${LOG_DIR}/buyer-api.log" 2>&1 &
BG_PIDS+=($!)

wait_for_http "${BUYER_API_URL}/healthz"

# Buyer sidecar (chio api protect)
CHIO_BIN="${CHIO_BIN}" \
CHIO_CONTROL_URL="${CONTROL_URL}" \
CHIO_CONTROL_TOKEN="${SERVICE_TOKEN}" \
BUYER_UPSTREAM_URL="${BUYER_API_URL}" \
BUYER_SIDECAR_LISTEN="127.0.0.1:${BUYER_SIDECAR_PORT}" \
BUYER_RECEIPT_STORE="${STATE_DIR}/buyer-receipts.sqlite3" \
  "${EXAMPLE_ROOT}/buyer/run-sidecar.sh" \
  >"${LOG_DIR}/buyer-sidecar.log" 2>&1 &
BG_PIDS+=($!)

wait_for_port 127.0.0.1 "${BUYER_SIDECAR_PORT}"

# Run procurement agent
uv run --project "${EXAMPLE_ROOT}" python "${EXAMPLE_ROOT}/orchestrate.py" \
  --control-url "${CONTROL_URL}" \
  --service-token "${SERVICE_TOKEN}" \
  --buyer-url "${BUYER_SIDECAR_URL}" \
  --buyer-auth-token "${EDGE_TOKEN}" \
  --scope hotfix-review \
  --target "git://lattice.example/payments-api" \
  --budget-minor 90000 \
  --artifact-dir "${ARTIFACT_ROOT}" \
  > "${ARTIFACT_ROOT}/run-result.json"

# Verify
uv run --project "${EXAMPLE_ROOT}" python -c "
import sys; sys.path.insert(0, '${EXAMPLE_ROOT}')
from commerce_network.verify import verify_bundle
import json
r = verify_bundle('${ARTIFACT_ROOT}')
json.dump(r, open('${ARTIFACT_ROOT}/review-result.json', 'w'), indent=2)
assert r['ok'], r['errors']
"

printf 'agent-commerce-network smoke passed\n'
printf 'artifacts: %s\n' "${ARTIFACT_ROOT}"
