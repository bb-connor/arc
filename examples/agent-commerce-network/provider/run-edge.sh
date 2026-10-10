#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
EXAMPLE_ROOT="${ROOT}/examples/agent-commerce-network"
STATE_DIR="${EXAMPLE_ROOT}/artifacts/live/provider-edge"

source "${ROOT}/scripts/lib/provision-mcp-launch.sh"

# Session state, the resume keyring and the provisioned policy live in a
# private directory; the artifacts directory keeps only local databases.
PRIVATE_STATE="${PROVIDER_PRIVATE_STATE:-$(chio_launch_state_dir agent-commerce-provider)}"
SESSION_DB="${PROVIDER_SESSION_DB:-${PRIVATE_STATE}/sessions.sqlite3}"

mkdir -p "${STATE_DIR}" "${PRIVATE_STATE}"

cd "${ROOT}"

if [[ -z "${CHIO_BIN:-}" ]]; then
  cargo build --bin chio
  CHIO_BIN="${ROOT}/target/debug/chio"
fi

# The edge only launches the exact command its signed native-launch policy
# binds, so the policy is provisioned for this binary and this server first.
chio_provision_mcp_launch \
  "${CHIO_BIN}" \
  "${PRIVATE_STATE}/security" \
  provider-security-review \
  "Vanguard Security Review" \
  1 \
  "${ROOT}" \
  python3 "${EXAMPLE_ROOT}/provider/review_server.py"

# Under a trust service the edge borrows its authority from the control
# plane; standalone it keeps local authority and receipt state.
CONTROL_ARGS=()
EDGE_CONTROL_ARGS=()
AUTHORITY_ARGS=()
if [[ -n "${CHIO_CONTROL_URL:-}" ]]; then
  CONTROL_TOKEN="${CHIO_CONTROL_TOKEN:-demo-control-token}"
  CONTROL_ARGS=(
    --control-url "${CHIO_CONTROL_URL}"
    --control-token "${CONTROL_TOKEN}"
    --control-authority-public-key "$(chio_control_authority_public_key "${CHIO_CONTROL_URL}" "${CONTROL_TOKEN}")"
  )
  EDGE_CONTROL_ARGS=(
    --remote-authority-workload-token "${CHIO_WORKLOAD_TOKEN:-demo-workload-token}"
  )
else
  AUTHORITY_ARGS=(
    --receipt-db "${STATE_DIR}/receipts.sqlite3"
    --revocation-db "${STATE_DIR}/revocations.sqlite3"
    --authority-db "${STATE_DIR}/authority.sqlite3"
  )
fi

exec "${CHIO_BIN}" \
  ${CONTROL_ARGS[@]+"${CONTROL_ARGS[@]}"} \
  mcp serve-http \
  --policy "${EXAMPLE_ROOT}/provider/policy.yaml" \
  --server-id provider-security-review \
  --server-name "Vanguard Security Review" \
  --server-version 1 \
  --listen "${PROVIDER_EDGE_LISTEN:-127.0.0.1:8931}" \
  --auth-token "${CHIO_EDGE_TOKEN:-demo-token}" \
  --admin-token "${CHIO_ADMIN_TOKEN:-demo-admin-token}" \
  ${EDGE_CONTROL_ARGS[@]+"${EDGE_CONTROL_ARGS[@]}"} \
  ${AUTHORITY_ARGS[@]+"${AUTHORITY_ARGS[@]}"} \
  --session-db "${SESSION_DB}" \
  --resume-hmac-keyring "$(chio_write_resume_hmac_keyring "${PRIVATE_STATE}/resume-hmac-keyring.json")" \
  "${CHIO_LAUNCH_FLAGS[@]}" \
  -- \
  "${CHIO_LAUNCH_COMMAND[@]}"
