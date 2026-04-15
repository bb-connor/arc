#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${EXAMPLE_ROOT}/../.." && pwd)"
source "${ROOT}/examples/_shared/hello-http-common.sh"

ARTIFACT_ROOT="${EXAMPLE_ROOT}/.artifacts/$(date -u +"%Y%m%dT%H%M%SZ")"
LOG_DIR="${ARTIFACT_ROOT}/logs"
STATE_DIR="${ARTIFACT_ROOT}/state"
mkdir -p "${LOG_DIR}" "${STATE_DIR}"

ARC_BIN="$(ensure_arc_bin)"
SERVICE_TOKEN="${ARC_SERVICE_TOKEN:-demo-token}"
TRUST_PORT="$(pick_free_port)"
CONTROL_URL="http://127.0.0.1:${TRUST_PORT}"
TRUST_RECEIPT_DB="${STATE_DIR}/trust-receipts.sqlite3"
REVOCATION_DB="${STATE_DIR}/trust-revocations.sqlite3"
AUTHORITY_DB="${STATE_DIR}/trust-authority.sqlite3"
BUDGET_DB="${STATE_DIR}/trust-budgets.sqlite3"
CHECK_RECEIPT_DB="${STATE_DIR}/check-receipts.sqlite3"
EVIDENCE_DIR="${ARTIFACT_ROOT}/evidence"

cleanup() {
  local code=$?
  if [[ -n "${TRUST_PID:-}" ]] && kill -0 "${TRUST_PID}" >/dev/null 2>&1; then
    kill "${TRUST_PID}" >/dev/null 2>&1 || true
    wait "${TRUST_PID}" >/dev/null 2>&1 || true
  fi
  return "${code}"
}
trap cleanup EXIT

"${ARC_BIN}" trust serve \
  --listen "127.0.0.1:${TRUST_PORT}" \
  --service-token "${SERVICE_TOKEN}" \
  --receipt-db "${TRUST_RECEIPT_DB}" \
  --revocation-db "${REVOCATION_DB}" \
  --authority-db "${AUTHORITY_DB}" \
  --budget-db "${BUDGET_DB}" \
  >"${LOG_DIR}/trust.log" 2>&1 &
TRUST_PID=$!

wait_for_http "${CONTROL_URL}/health"

issue_demo_capability "${CONTROL_URL}" "${SERVICE_TOKEN}" "${ARTIFACT_ROOT}/capability.json" "hello_trust_control_invoke"
materialize_capability_token "${ARTIFACT_ROOT}/capability.json" "${ARTIFACT_ROOT}/capability.token"

CAPABILITY_ID="$(python3 - "${ARTIFACT_ROOT}/capability.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(payload["capability"]["id"])
PY
)"

"${ARC_BIN}" \
  --control-url "${CONTROL_URL}" \
  --control-token "${SERVICE_TOKEN}" \
  trust status \
  --capability-id "${CAPABILITY_ID}" \
  --json \
  > "${ARTIFACT_ROOT}/status-before.json"

python3 - "${ARTIFACT_ROOT}/status-before.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert payload["capability_id"], payload
assert payload["revoked"] is False, payload
PY

"${ARC_BIN}" \
  --control-url "${CONTROL_URL}" \
  --control-token "${SERVICE_TOKEN}" \
  trust revoke \
  --capability-id "${CAPABILITY_ID}" \
  --json \
  > "${ARTIFACT_ROOT}/revoke.json"

python3 - "${ARTIFACT_ROOT}/revoke.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert payload["capability_id"], payload
assert payload["revoked"] is True, payload
assert payload["newly_revoked"] is True, payload
PY

"${ARC_BIN}" \
  --control-url "${CONTROL_URL}" \
  --control-token "${SERVICE_TOKEN}" \
  trust status \
  --capability-id "${CAPABILITY_ID}" \
  --json \
  > "${ARTIFACT_ROOT}/status-after.json"

python3 - "${ARTIFACT_ROOT}/status-after.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert payload["capability_id"], payload
assert payload["revoked"] is True, payload
PY

"${ARC_BIN}" check \
  --policy "${EXAMPLE_ROOT}/policy.yaml" \
  --tool read_file \
  --params '{"path":"README.md"}' \
  --receipt-db "${CHECK_RECEIPT_DB}" \
  --json \
  > "${ARTIFACT_ROOT}/check.json"

python3 - "${ARTIFACT_ROOT}/check.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert payload["tool"] == "read_file", payload
assert payload["verdict"] == "Allow", payload
assert payload["receipt_id"], payload
assert payload["policy_hash"], payload
PY

"${ARC_BIN}" receipt --receipt-db "${CHECK_RECEIPT_DB}" list --limit 20 > "${ARTIFACT_ROOT}/receipts.ndjson"

"${ARC_BIN}" evidence export \
  --receipt-db "${CHECK_RECEIPT_DB}" \
  --output "${EVIDENCE_DIR}"

"${ARC_BIN}" evidence verify \
  --input "${EVIDENCE_DIR}" \
  --json \
  > "${ARTIFACT_ROOT}/verify.json"

python3 - "${ARTIFACT_ROOT}/verify.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert payload["toolReceipts"] == 1, payload
assert payload["verifiedFiles"] >= 1, payload
PY

python3 - "${ARTIFACT_ROOT}" "${CAPABILITY_ID}" <<'PY'
import json
import sys
from pathlib import Path

artifact_root = Path(sys.argv[1])
capability_id = sys.argv[2]
check = json.loads((artifact_root / "check.json").read_text(encoding="utf-8"))
verify = json.loads((artifact_root / "verify.json").read_text(encoding="utf-8"))
summary = {
    "example": "hello-trust-control",
    "capability_id": capability_id,
    "receipt_id": check["receipt_id"],
    "tool": check["tool"],
    "verdict": check["verdict"],
    "evidence_verified": True,
    "tool_receipts": verify["toolReceipts"],
}
(artifact_root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
PY

RECEIPT_ID="$(python3 - "${ARTIFACT_ROOT}/check.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(payload["receipt_id"])
PY
)"

cat <<EOF
hello-trust-control smoke passed
artifacts: ${ARTIFACT_ROOT}
capability id: ${CAPABILITY_ID}
receipt id: ${RECEIPT_ID}
evidence dir: ${EVIDENCE_DIR}
EOF
