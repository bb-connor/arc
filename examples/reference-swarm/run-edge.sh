#!/usr/bin/env bash
# Launch one reference edge: provision the tool it wraps under a signed
# native-launch policy, then serve it over HTTP against trust-control.
#
# Required environment: CHIO_BIN, EDGE_ROLE (reader|writer|digest), EDGE_LISTEN,
# EDGE_PRIVATE_STATE, EDGE_SESSION_DB, EDGE_TOOL (the tool executable),
# CHIO_CONTROL_URL, CHIO_CONTROL_TOKEN, CHIO_WORKLOAD_TOKEN, CHIO_EDGE_TOKEN,
# CHIO_ADMIN_TOKEN. The reader needs EDGE_ROOT, the writer EDGE_ARTIFACT.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EXAMPLE_ROOT="${ROOT}/examples/reference-swarm"
source "${ROOT}/scripts/lib/provision-mcp-launch.sh"

: "${CHIO_BIN:?CHIO_BIN is required}"
: "${EDGE_ROLE:?EDGE_ROLE is required}"
: "${EDGE_LISTEN:?EDGE_LISTEN is required}"
: "${EDGE_PRIVATE_STATE:?EDGE_PRIVATE_STATE is required}"
: "${EDGE_SESSION_DB:?EDGE_SESSION_DB is required}"
: "${EDGE_TOOL:?EDGE_TOOL is required}"
: "${CHIO_CONTROL_URL:?CHIO_CONTROL_URL is required}"

mkdir -p "${EDGE_PRIVATE_STATE}"
chmod 0700 "${EDGE_PRIVATE_STATE}"

case "${EDGE_ROLE}" in
  reader)
    : "${EDGE_ROOT:?EDGE_ROOT is required for the reader}"
    TOOL_ARGS=(--root "${EDGE_ROOT}")
    ;;
  writer)
    : "${EDGE_ARTIFACT:?EDGE_ARTIFACT is required for the writer}"
    TOOL_ARGS=(--artifact "${EDGE_ARTIFACT}")
    ;;
  digest)
    TOOL_ARGS=()
    ;;
  *)
    echo "run-edge.sh: unknown EDGE_ROLE ${EDGE_ROLE}" >&2
    exit 1
    ;;
esac

SERVER_ID="reference-${EDGE_ROLE}"
chio_provision_mcp_launch \
  "${CHIO_BIN}" \
  "${EDGE_PRIVATE_STATE}/security" \
  "${SERVER_ID}" \
  "Reference ${EDGE_ROLE}" \
  1 \
  "${EDGE_PRIVATE_STATE}" \
  "${EDGE_TOOL}" ${TOOL_ARGS[@]+"${TOOL_ARGS[@]}"}

KEYRING="$(chio_write_resume_hmac_keyring "${EDGE_PRIVATE_STATE}/resume-hmac-keyring.json")"
CONTROL_TOKEN="${CHIO_CONTROL_TOKEN:-demo-control-token}"

exec "${CHIO_BIN}" \
  --control-url "${CHIO_CONTROL_URL}" \
  --control-token "${CONTROL_TOKEN}" \
  --control-authority-public-key "$(chio_control_authority_public_key "${CHIO_CONTROL_URL}" "${CONTROL_TOKEN}")" \
  mcp serve-http \
  --policy "${EXAMPLE_ROOT}/policies/${EDGE_ROLE}.yaml" \
  --server-id "${SERVER_ID}" \
  --server-name "Reference ${EDGE_ROLE}" \
  --server-version 1 \
  --listen "${EDGE_LISTEN}" \
  --auth-token "${CHIO_EDGE_TOKEN:-demo-token}" \
  --admin-token "${CHIO_ADMIN_TOKEN:-demo-admin-token}" \
  --remote-authority-workload-token "${CHIO_WORKLOAD_TOKEN:-demo-workload-token}" \
  --session-db "${EDGE_SESSION_DB}" \
  --resume-hmac-keyring "${KEYRING}" \
  "${CHIO_LAUNCH_FLAGS[@]}" \
  -- \
  "${CHIO_LAUNCH_COMMAND[@]}"
