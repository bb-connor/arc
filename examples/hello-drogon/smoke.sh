#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${EXAMPLE_ROOT}/../.." && pwd)"
source "${ROOT}/examples/_shared/hello-http-common.sh"

ARTIFACT_ROOT="${EXAMPLE_ROOT}/.artifacts/$(date -u +"%Y%m%dT%H%M%SZ")"
LOG_DIR="${ARTIFACT_ROOT}/logs"
BUILD_DIR="${ARTIFACT_ROOT}/build"
mkdir -p "${LOG_DIR}" "${BUILD_DIR}"

if ! command -v cmake >/dev/null 2>&1; then
  if [[ "${CHIO_DROGON_REQUIRE_DEPS:-0}" == "1" ]]; then
    echo "hello-drogon qualification requires cmake" >&2
    exit 1
  fi
  echo "hello-drogon smoke skipped: cmake was not found on PATH"
  exit 0
fi

if ! cmake -S "${EXAMPLE_ROOT}" -B "${BUILD_DIR}" >"${LOG_DIR}/configure.log" 2>&1; then
  echo "hello-drogon smoke configure failed; see ${LOG_DIR}/configure.log" >&2
  exit 1
fi

if [[ -f "${BUILD_DIR}/hello-drogon.skip" ]]; then
  if [[ "${CHIO_DROGON_REQUIRE_DEPS:-0}" == "1" ]]; then
    echo "hello-drogon qualification requires Drogon dependencies" >&2
    exit 1
  fi
  echo "hello-drogon smoke skipped: $(tr -d '\n' < "${BUILD_DIR}/hello-drogon.skip")"
  exit 0
fi

if ! cmake --build "${BUILD_DIR}" --target hello_drogon >"${LOG_DIR}/build.log" 2>&1; then
  echo "hello-drogon smoke build failed; see ${LOG_DIR}/build.log" >&2
  exit 1
fi

if ! cmake --build "${BUILD_DIR}" --target hello_drogon_contract_tests >"${LOG_DIR}/test-build.log" 2>&1; then
  echo "hello-drogon smoke test build failed; see ${LOG_DIR}/test-build.log" >&2
  exit 1
fi

if ! ctest --test-dir "${BUILD_DIR}" --output-on-failure --no-tests=error >"${LOG_DIR}/ctest.log" 2>&1; then
  echo "hello-drogon smoke contract tests failed; see ${LOG_DIR}/ctest.log" >&2
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
# Checkout ancestors can be group-writable. Keep signing custody in a fresh
# private directory; public receipt exports remain in the artifact directory.
STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/chio-hello-drogon-state.XXXXXX")"
RECEIPT_STORE="${STATE_DIR}/sidecar-receipts.sqlite3"

cleanup() {
  local code=$?
  for pid in ${SIDECAR_PID:-} ${APP_PID:-} ${TRUST_PID:-}; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" >/dev/null 2>&1 || true
    fi
  done
  # Keep signed evidence even when an assertion fails before the JSON export.
  # Do not delete the source if any receipt file cannot be retained.
  local receipt_file
  for receipt_file in "${RECEIPT_STORE}" "${RECEIPT_STORE}-wal" "${RECEIPT_STORE}-shm"; do
    if [[ -f "${receipt_file}" ]]; then
      cp -- "${receipt_file}" "${ARTIFACT_ROOT}/" || return 1
    fi
  done
  rm -rf -- "${STATE_DIR}"
  return "${code}"
}
trap cleanup EXIT

SIDECAR_AUTHORITY_SEED="${STATE_DIR}/sidecar-authority.seed"
python3 - "${SIDECAR_AUTHORITY_SEED}" <<'PY'
import os
import secrets
import sys

descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii") as stream:
    stream.write(secrets.token_hex(32) + "\n")
    stream.flush()
    os.fsync(stream.fileno())
PY

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
    --authority-seed-file "${SIDECAR_AUTHORITY_SEED}" \
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

issue_demo_capability \
  "${CONTROL_URL}" \
  "${SERVICE_TOKEN}" \
  "${ARTIFACT_ROOT}/capability.json" \
  "authorize_http_request" \
  "chio_http_authority"
materialize_capability_token "${ARTIFACT_ROOT}/capability.json" "${ARTIFACT_ROOT}/capability.token"

curl -sS -D "${ARTIFACT_ROOT}/hello.headers" \
  -H "X-Chio-Capability: $(tr -d '\n' < "${ARTIFACT_ROOT}/capability.token")" \
  "${APP_URL}/hello" > "${ARTIFACT_ROOT}/hello.json"

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
[[ "${ALLOW_RECEIPT_ID}" == "${ALLOW_HEADER_RECEIPT_ID}" ]]
if [[ -n "${DENY_HEADER_RECEIPT_ID}" ]]; then
  [[ "${DENY_RECEIPT_ID}" == "${DENY_HEADER_RECEIPT_ID}" ]]
fi

python3 - \
  "${RECEIPT_STORE}" \
  "${ARTIFACT_ROOT}/receipts.ndjson" \
  "${ARTIFACT_ROOT}/receipt-summary.json" \
  "${HELLO_RECEIPT_ID}" \
  "${DENY_RECEIPT_ID}" \
  "${ALLOW_RECEIPT_ID}" \
  "${ALLOW_PAYLOAD}" <<'PY'
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

receipt_store = Path(sys.argv[1])
output_path = Path(sys.argv[2])
summary_path = Path(sys.argv[3])
hello_receipt_id = sys.argv[4]
deny_receipt_id = sys.argv[5]
allow_receipt_id = sys.argv[6]
raw_payload = sys.argv[7]
expected_ids = {hello_receipt_id, deny_receipt_id, allow_receipt_id}
assert "" not in expected_ids, {"expected_ids": sorted(expected_ids)}

with sqlite3.connect(receipt_store) as db:
    rows = db.execute("SELECT raw_json FROM chio_tool_receipts ORDER BY seq ASC").fetchall()

kernel_records = [json.loads(row[0]) for row in rows]
records = [
    record["metadata"]["chio_http_receipt_v1"]
    for record in kernel_records
    if "chio_http_receipt_v1" in record.get("metadata", {})
]
receipt_ids = {record["id"] for record in records}
missing = expected_ids - receipt_ids
assert not missing, {"missing": sorted(missing), "stored": sorted(receipt_ids)}

decisions = {
    (
        record.get("method"),
        record.get("route_pattern"),
        record.get("verdict", {}).get("verdict"),
        record.get("response_status"),
    ): record["id"]
    for record in records
}
assert decisions.get(("GET", "/hello", "allow", 200)) == hello_receipt_id, decisions
assert decisions.get(("POST", "/echo", "deny", 403)) == deny_receipt_id, decisions
assert decisions.get(("POST", "/echo", "allow", 200)) == allow_receipt_id, decisions

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

output_path.write_text(
    "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
    encoding="utf-8",
)
output_path.with_name("kernel-receipts.ndjson").write_text(
    "".join(row[0] + "\n" for row in rows),
    encoding="utf-8",
)
summary_path.write_text(
    json.dumps(
        {
            "hello": decisions[("GET", "/hello", "allow", 200)],
            "deny": decisions[("POST", "/echo", "deny", 403)],
            "allow": decisions[("POST", "/echo", "allow", 200)],
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PY

cat <<EOF
hello-drogon smoke passed
artifacts: ${ARTIFACT_ROOT}
hello receipt: ${HELLO_RECEIPT_ID}
deny receipt: ${DENY_RECEIPT_ID}
allow receipt: ${ALLOW_RECEIPT_ID}
EOF
