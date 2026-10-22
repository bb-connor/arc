#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${EXAMPLE_ROOT}/../.." && pwd)"
CHIO_BIN="${CHIO_BIN:-${ROOT}/target/debug/chio}"
PORT="${HELLO_TRUST_CONTROL_PORT:-8051}"
SERVICE_TOKEN="${CHIO_SERVICE_TOKEN:-demo-token}"
STATE_DIR="${HELLO_TRUST_CONTROL_STATE_DIR:-${EXAMPLE_ROOT}/.artifacts/manual-state}"

mkdir -p "${STATE_DIR}"
source "${ROOT}/examples/_shared/trust-access.sh"

write_trust_access_config "${CHIO_BIN}" "${STATE_DIR}/trust-access.toml" "${SERVICE_TOKEN}"
exec "${CHIO_BIN}" trust serve \
  --listen "127.0.0.1:${PORT}" \
  --access-config "${STATE_DIR}/trust-access.toml" \
  --receipt-db "${STATE_DIR}/trust-receipts.sqlite3" \
  --revocation-db "${STATE_DIR}/trust-revocations.sqlite3" \
  --authority-db "${STATE_DIR}/trust-authority.sqlite3" \
  --budget-db "${STATE_DIR}/trust-budgets.sqlite3"
