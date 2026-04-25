#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${EXAMPLE_ROOT}/../.." && pwd)"
source "${ROOT}/examples/_shared/hello-http-common.sh"

ARTIFACT_ROOT="${EXAMPLE_ROOT}/.artifacts/$(date -u +"%Y%m%dT%H%M%SZ")"
LOG_DIR="${ARTIFACT_ROOT}/logs"
STATE_DIR="${ARTIFACT_ROOT}/state"
BUILD_DIR="${ARTIFACT_ROOT}/build"
mkdir -p "${LOG_DIR}" "${STATE_DIR}" "${BUILD_DIR}"

if ! command -v cmake >/dev/null 2>&1; then
  echo "hello-drogon smoke skipped: cmake was not found on PATH"
  exit 0
fi

if ! cmake -S "${EXAMPLE_ROOT}" -B "${BUILD_DIR}" >"${LOG_DIR}/configure.log" 2>&1; then
  echo "hello-drogon smoke configure failed; see ${LOG_DIR}/configure.log" >&2
  exit 1
fi

if [[ -f "${BUILD_DIR}/hello-drogon.skip" ]]; then
  echo "hello-drogon smoke skipped: $(tr -d '\n' < "${BUILD_DIR}/hello-drogon.skip")"
  exit 0
fi

if ! cmake --build "${BUILD_DIR}" --target hello_drogon >"${LOG_DIR}/build.log" 2>&1; then
  echo "hello-drogon smoke build failed; see ${LOG_DIR}/build.log" >&2
  exit 1
fi

CHIO_BIN="$(ensure_chio_bin)"
SERVICE_TOKEN="${CHIO_SERVICE_TOKEN:-demo-token}"
TRUST_PORT="$(pick_free_port)"
APP_PORT="$(pick_free_port)"
SIDECAR_PORT="$(pick_free_port)"
CONTROL_URL="http://127.0.0.1:${TRUST_PORT}"
APP_URL="http://127.0.0.1:${APP_PORT}"
SIDECAR_URL="http://127.0.0.1:${SIDECAR_PORT}"
RECEIPT_STORE="${STATE_DIR}/sidecar-receipts.sqlite3"

cleanup() {
  local code=$?
  for pid in ${SIDECAR_PID:-} ${APP_PID:-} ${TRUST_PID:-}; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" >/dev/null 2>&1 || true
    fi
  done
  return "${code}"
}
trap cleanup EXIT

"${CHIO_BIN}" trust serve \
  --listen "127.0.0.1:${TRUST_PORT}" \
  --service-token "${SERVICE_TOKEN}" \
  --receipt-db "${STATE_DIR}/trust-receipts.sqlite3" \
  --revocation-db "${STATE_DIR}/trust-revocations.sqlite3" \
  --authority-db "${STATE_DIR}/trust-authority.sqlite3" \
  --budget-db "${STATE_DIR}/trust-budgets.sqlite3" \
  >"${LOG_DIR}/trust.log" 2>&1 &
TRUST_PID=$!

wait_for_http "${CONTROL_URL}/health"
TRUSTED_ISSUER_KEY="$(trust_authority_public_key "${CONTROL_URL}" "${SERVICE_TOKEN}")"

(
  export CHIO_SIDECAR_URL="${SIDECAR_URL}"
  export HELLO_DROGON_PORT="${APP_PORT}"
  exec "${BUILD_DIR}/hello_drogon"
) >"${LOG_DIR}/app.log" 2>&1 &
APP_PID=$!

wait_for_http "${APP_URL}/healthz"

(
  export CHIO_TRUSTED_ISSUER_KEY="${TRUSTED_ISSUER_KEY}"
  exec "${CHIO_BIN}" \
    --control-url "${CONTROL_URL}" \
    --control-token "${SERVICE_TOKEN}" \
    api protect \
    --upstream "${APP_URL}" \
    --spec "${EXAMPLE_ROOT}/openapi.yaml" \
    --listen "127.0.0.1:${SIDECAR_PORT}" \
    --receipt-store "${RECEIPT_STORE}"
) >"${LOG_DIR}/sidecar.log" 2>&1 &
SIDECAR_PID=$!

wait_for_http "${SIDECAR_URL}/chio/health"

curl -sS -D "${ARTIFACT_ROOT}/hello.headers" "${APP_URL}/hello" > "${ARTIFACT_ROOT}/hello.json"

python3 - "${ARTIFACT_ROOT}/hello.json" <<'PY'
import json
import sys
from pathlib import Path

body = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert body["message"] == "hello from drogon", body
assert body["receipt_id"], body
assert body["handled_by"] == "drogon", body
PY

curl -sS -D "${ARTIFACT_ROOT}/deny.headers" \
  -H "content-type: application/json" \
  --data '{"message":"denied","count":1}' \
  "${APP_URL}/echo" \
  > "${ARTIFACT_ROOT}/deny.json"

python3 - "${ARTIFACT_ROOT}/deny.json" <<'PY'
import json
import sys
from pathlib import Path

body = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert body["error"] == "chio_access_denied", body
assert body["message"], body
assert body["receipt_id"], body
PY

issue_demo_capability "${CONTROL_URL}" "${SERVICE_TOKEN}" "${ARTIFACT_ROOT}/capability.json" "hello_drogon_write"
materialize_capability_token "${ARTIFACT_ROOT}/capability.json" "${ARTIFACT_ROOT}/capability.token"

ALLOW_PAYLOAD='{ "message" : "hello", "count" : 2 }'
curl -sS -D "${ARTIFACT_ROOT}/allow.headers" \
  -H "content-type: application/json" \
  -H "X-Chio-Capability: $(tr -d '\n' < "${ARTIFACT_ROOT}/capability.token")" \
  --data "${ALLOW_PAYLOAD}" \
  "${APP_URL}/echo" \
  > "${ARTIFACT_ROOT}/allow.json"

python3 - "${ARTIFACT_ROOT}/allow.json" <<'PY'
import json
import sys
from pathlib import Path

body = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert body["message"] == "hello", body
assert body["count"] == 2, body
assert body["receipt_id"], body
assert body["handled_by"] == "drogon", body
PY

"${CHIO_BIN}" receipt list --receipt-db "${RECEIPT_STORE}" --limit 20 > "${ARTIFACT_ROOT}/receipts.ndjson"

HELLO_RECEIPT_ID="$(python3 - "${ARTIFACT_ROOT}/hello.json" <<'PY'
import json
import sys
from pathlib import Path

print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["receipt_id"])
PY
)"
HELLO_HEADER_RECEIPT_ID="$(header_value "${ARTIFACT_ROOT}/hello.headers" "x-chio-receipt-id")"
DENY_RECEIPT_ID="$(python3 - "${ARTIFACT_ROOT}/deny.json" <<'PY'
import json
import sys
from pathlib import Path

print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["receipt_id"])
PY
)"
DENY_HEADER_RECEIPT_ID="$(header_value "${ARTIFACT_ROOT}/deny.headers" "x-chio-receipt-id")"
ALLOW_RECEIPT_ID="$(python3 - "${ARTIFACT_ROOT}/allow.json" <<'PY'
import json
import sys
from pathlib import Path

print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["receipt_id"])
PY
)"
ALLOW_HEADER_RECEIPT_ID="$(header_value "${ARTIFACT_ROOT}/allow.headers" "x-chio-receipt-id")"

[[ "${HELLO_RECEIPT_ID}" == "${HELLO_HEADER_RECEIPT_ID}" ]]
[[ "${DENY_RECEIPT_ID}" == "${DENY_HEADER_RECEIPT_ID}" ]]
[[ "${ALLOW_RECEIPT_ID}" == "${ALLOW_HEADER_RECEIPT_ID}" ]]

python3 - "${ARTIFACT_ROOT}/receipts.ndjson" "${ALLOW_RECEIPT_ID}" "${ALLOW_PAYLOAD}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

receipts = Path(sys.argv[1]).read_text(encoding="utf-8").strip().splitlines()
assert receipts, "expected at least one persisted receipt"
allow_receipt_id = sys.argv[2]
raw_payload = sys.argv[3]
records = [json.loads(line) for line in receipts]
receipt = next((record for record in records if record.get("id") == allow_receipt_id), None)
assert receipt is not None, f"missing allow receipt {allow_receipt_id}"
body_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
binding = {
    "body_hash": body_hash,
    "method": "POST",
    "path": "/echo",
    "query": {},
    "route_pattern": "/echo",
}
content_hash = hashlib.sha256(
    json.dumps(binding, separators=(",", ":"), sort_keys=True).encode("utf-8")
).hexdigest()
assert receipt["content_hash"] == content_hash, {
    "expected": content_hash,
    "actual": receipt["content_hash"],
    "body_hash": body_hash,
}
PY

cat <<EOF
hello-drogon smoke passed
artifacts: ${ARTIFACT_ROOT}
hello receipt: ${HELLO_RECEIPT_ID}
deny receipt: ${DENY_RECEIPT_ID}
allow receipt: ${ALLOW_RECEIPT_ID}
EOF
