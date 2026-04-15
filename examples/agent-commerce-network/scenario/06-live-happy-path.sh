#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

ROOT="$(cd "${EXAMPLE_ROOT}/../.." && pwd)"
OUT_DIR="$(stage_bundle \
  "live-happy-path" \
  "Scenario 06: Live Happy Path" \
  "Boot the local trust, provider, buyer, and buyer-sidecar topology; execute one governed hotfix review; and capture live ARC evidence instead of seeded contracts.")"
LIVE_DIR="${OUT_DIR}/live"
LOG_DIR="${LIVE_DIR}/logs"
STATE_DIR="${LIVE_DIR}/state"
TRUST_DIR="${STATE_DIR}/trust"

mkdir -p "${LIVE_DIR}" "${LOG_DIR}" "${TRUST_DIR}"

ARC_BIN="${ROOT}/target/debug/arc"
SERVICE_TOKEN="${ARC_SERVICE_TOKEN:-demo-token}"
EDGE_TOKEN="${ARC_EDGE_TOKEN:-demo-token}"
pick_free_port() {
  python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

TRUST_PORT="${TRUST_PORT:-$(pick_free_port)}"
PROVIDER_PORT="${PROVIDER_PORT:-$(pick_free_port)}"
BUYER_API_PORT="${BUYER_API_PORT:-$(pick_free_port)}"
BUYER_SIDECAR_PORT="${BUYER_SIDECAR_PORT:-$(pick_free_port)}"

CONTROL_URL="http://127.0.0.1:${TRUST_PORT}"
PROVIDER_URL="http://127.0.0.1:${PROVIDER_PORT}"
BUYER_API_URL="http://127.0.0.1:${BUYER_API_PORT}"
BUYER_SIDECAR_URL="http://127.0.0.1:${BUYER_SIDECAR_PORT}"
BUYER_RECEIPT_STORE="${STATE_DIR}/buyer-sidecar-receipts.sqlite3"
PROVIDER_SESSION_DB="${STATE_DIR}/provider-edge-sessions.sqlite3"

cleanup() {
  local code=$?
  for pid in ${BUYER_SIDECAR_PID:-} ${BUYER_API_PID:-} ${PROVIDER_PID:-} ${TRUST_PID:-}; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" >/dev/null 2>&1 || true
    fi
  done
  return "${code}"
}
trap cleanup EXIT

cd "${ROOT}"
cargo build --bin arc >/dev/null

"${ARC_BIN}" trust serve \
  --listen "127.0.0.1:${TRUST_PORT}" \
  --service-token "${SERVICE_TOKEN}" \
  --receipt-db "${TRUST_DIR}/receipts.sqlite3" \
  --revocation-db "${TRUST_DIR}/revocations.sqlite3" \
  --authority-db "${TRUST_DIR}/authority.sqlite3" \
  --budget-db "${TRUST_DIR}/budgets.sqlite3" \
  >"${LOG_DIR}/trust.log" 2>&1 &
TRUST_PID=$!

wait_for_http "${CONTROL_URL}/health"

(
  export ARC_BIN="${ARC_BIN}"
  export ARC_CONTROL_URL="${CONTROL_URL}"
  export ARC_CONTROL_TOKEN="${SERVICE_TOKEN}"
  export ARC_EDGE_TOKEN="${EDGE_TOKEN}"
  export PROVIDER_EDGE_LISTEN="127.0.0.1:${PROVIDER_PORT}"
  export PROVIDER_SESSION_DB="${PROVIDER_SESSION_DB}"
  "${EXAMPLE_ROOT}/provider/run-edge.sh"
) >"${LOG_DIR}/provider-edge.log" 2>&1 &
PROVIDER_PID=$!

wait_for_port 127.0.0.1 "${PROVIDER_PORT}"

(
  cd "${EXAMPLE_ROOT}/buyer"
  export BUYER_PROVIDER_BASE_URL="${PROVIDER_URL}"
  export BUYER_PROVIDER_AUTH_TOKEN="${EDGE_TOKEN}"
  uv run --project . uvicorn app:app --host 127.0.0.1 --port "${BUYER_API_PORT}"
) >"${LOG_DIR}/buyer-api.log" 2>&1 &
BUYER_API_PID=$!

wait_for_http "${BUYER_API_URL}/healthz"

(
  export ARC_BIN="${ARC_BIN}"
  export ARC_CONTROL_URL="${CONTROL_URL}"
  export ARC_CONTROL_TOKEN="${SERVICE_TOKEN}"
  export BUYER_UPSTREAM_URL="${BUYER_API_URL}"
  export BUYER_SIDECAR_LISTEN="127.0.0.1:${BUYER_SIDECAR_PORT}"
  export BUYER_RECEIPT_STORE="${BUYER_RECEIPT_STORE}"
  "${EXAMPLE_ROOT}/buyer/run-sidecar.sh"
) >"${LOG_DIR}/buyer-sidecar.log" 2>&1 &
BUYER_SIDECAR_PID=$!

wait_for_port 127.0.0.1 "${BUYER_SIDECAR_PORT}"

cat > "${LIVE_DIR}/quote-request.json" <<'EOF'
{
  "service_family": "security-review",
  "target": "git://acme.example/payments-api",
  "requested_scope": "hotfix-review",
  "release_window": "2026-05-01T16:00:00Z"
}
EOF

curl -sS -D "${LIVE_DIR}/quote-response.headers" \
  -H "content-type: application/json" \
  --data @"${LIVE_DIR}/quote-request.json" \
  "${BUYER_SIDECAR_URL}/procurement/quote-requests" \
  > "${LIVE_DIR}/quote-response.json"

python3 - "${CONTROL_URL}" "${SERVICE_TOKEN}" "${LIVE_DIR}/issued-capability.json" <<'PY'
import json
import os
import urllib.request

control_url = os.sys.argv[1].rstrip("/")
token = os.sys.argv[2]
output_path = os.sys.argv[3]
subject_hex = "00" * 32
payload = {
    "subjectPublicKey": subject_hex,
    "scope": {
        "grants": [
            {
                "server_id": "http-sidecar-client",
                "tool_name": "procurement_job_write",
                "operations": ["invoke"],
                "constraints": [],
            }
        ],
        "resource_grants": [],
        "prompt_grants": [],
    },
    "ttlSeconds": 3600,
}
request = urllib.request.Request(
    f"{control_url}/v1/capabilities/issue",
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    },
    method="POST",
)
with urllib.request.urlopen(request, timeout=5) as response:
    result = json.loads(response.read().decode("utf-8"))
with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(result, handle, indent=2)
    handle.write("\n")
PY

python3 - "${LIVE_DIR}/issued-capability.json" "${LIVE_DIR}/issued-capability.token" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text())
Path(sys.argv[2]).write_text(
    json.dumps(payload["capability"], separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY

python3 - "${LIVE_DIR}/quote-response.json" "${LIVE_DIR}/create-job-request.json" <<'PY'
import json
import sys
from pathlib import Path

quote_response = json.loads(Path(sys.argv[1]).read_text())
payload = {
    "quote_id": quote_response["quote"]["quote_id"],
    "provider_id": "contoso-red-team",
    "service_family": "security-review",
    "budget_minor": 90000,
}
Path(sys.argv[2]).write_text(json.dumps(payload, indent=2) + "\n")
PY

python3 - "${LIVE_DIR}/quote-response.json" <<'PY'
import json
import sys
from pathlib import Path

quote_response = json.loads(Path(sys.argv[1]).read_text())
if "quote" not in quote_response:
    raise SystemExit(f"quote response did not include a quote: {quote_response}")
PY

curl -sS -D "${LIVE_DIR}/job-response.headers" \
  -H "content-type: application/json" \
  -H "X-Arc-Capability: $(tr -d '\n' < "${LIVE_DIR}/issued-capability.token")" \
  --data @"${LIVE_DIR}/create-job-request.json" \
  "${BUYER_SIDECAR_URL}/procurement/jobs" \
  > "${LIVE_DIR}/job-response.json"

python3 - "${LIVE_DIR}/job-response.json" <<'PY'
import json
import sys
from pathlib import Path

job_response = json.loads(Path(sys.argv[1]).read_text())
if "fulfillment" not in job_response or "settlement" not in job_response:
    raise SystemExit(f"job response was not a successful fulfillment payload: {job_response}")
PY

curl -sS \
  -H "Authorization: Bearer ${SERVICE_TOKEN}" \
  "${CONTROL_URL}/v1/receipts/query?limit=20" \
  > "${LIVE_DIR}/receipts-all.json"

"${ARC_BIN}" receipt list \
  --receipt-db "${BUYER_RECEIPT_STORE}" \
  --limit 20 \
  > "${LIVE_DIR}/buyer-sidecar-receipts.ndjson"

python3 - "${LIVE_DIR}/quote-response.json" "${LIVE_DIR}/job-response.json" "${CONTROL_URL}" "${SERVICE_TOKEN}" "${LIVE_DIR}" <<'PY'
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

quote_response = json.loads(Path(sys.argv[1]).read_text())
job_response = json.loads(Path(sys.argv[2]).read_text())
control_url = sys.argv[3].rstrip("/")
token = sys.argv[4]
live_dir = Path(sys.argv[5])

def query_capability(capability_id: str | None) -> dict:
    if not capability_id:
        return {"receipts": []}
    query = urllib.parse.urlencode({"capabilityId": capability_id, "limit": 10})
    request = urllib.request.Request(
        f"{control_url}/v1/receipts/query?{query}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))

quote_trace = quote_response.get("provider_trace") or {}
fulfillment_trace = job_response.get("fulfillment_trace") or {}

(live_dir / "provider-quote-receipts.json").write_text(
    json.dumps(query_capability(quote_trace.get("capability_id")), indent=2) + "\n"
)
(live_dir / "provider-fulfillment-receipts.json").write_text(
    json.dumps(query_capability(fulfillment_trace.get("capability_id")), indent=2) + "\n"
)

summary = {
    "buyer_quote_receipt_id": next(
        (
            line.split(":", 1)[1].strip()
            for line in (live_dir / "quote-response.headers").read_text().splitlines()
            if line.lower().startswith("x-arc-receipt-id:")
        ),
        None,
    ),
    "buyer_job_receipt_id": next(
        (
            line.split(":", 1)[1].strip()
            for line in (live_dir / "job-response.headers").read_text().splitlines()
            if line.lower().startswith("x-arc-receipt-id:")
        ),
        None,
    ),
    "provider_quote_trace": quote_trace,
    "provider_fulfillment_trace": fulfillment_trace,
    "job_status": job_response.get("status"),
}
(live_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
PY

cp "${LIVE_DIR}/quote-request.json" "${OUT_DIR}/contracts/quote-request.json"
python3 - "${LIVE_DIR}/quote-response.json" "${LIVE_DIR}/job-response.json" "${OUT_DIR}/contracts/quote-response.json" "${OUT_DIR}/contracts/fulfillment-package.json" "${OUT_DIR}/contracts/settlement-reconciliation.json" <<'PY'
import json
import sys
from pathlib import Path

quote_response = json.loads(Path(sys.argv[1]).read_text())
job_response = json.loads(Path(sys.argv[2]).read_text())
Path(sys.argv[3]).write_text(json.dumps(quote_response["quote"], indent=2) + "\n")
Path(sys.argv[4]).write_text(json.dumps(job_response["fulfillment"], indent=2) + "\n")
Path(sys.argv[5]).write_text(json.dumps(job_response["settlement"], indent=2) + "\n")
PY

cat > "${OUT_DIR}/steps.md" <<'EOF'
# Steps

1. Build the local `arc` binary once.
2. Start trust control with dedicated SQLite state under this bundle.
3. Start the wrapped provider MCP edge.
4. Start the buyer FastAPI service with the live provider client enabled.
5. Start `arc api protect` in front of the buyer.
6. Submit a governed quote request for a `hotfix-review`.
7. Create a governed job under budget so execution proceeds immediately.
8. Query trust control for all receipts plus provider capability-specific receipts.
EOF

cat > "${OUT_DIR}/expected-outputs.md" <<'EOF'
# Expected ARC Outputs

- buyer quote-request receipt id in `live/summary.json`
- buyer job-creation receipt id in `live/summary.json`
- trust-issued capability token in `live/issued-capability.json`
- provider quote capability trace and receipt query output
- provider fulfillment capability trace and receipt query output
- live trust receipt log snapshot in `live/receipts-all.json`
- local buyer sidecar receipt snapshot in `live/buyer-sidecar-receipts.ndjson`
- generated quote, fulfillment, and settlement contracts in `contracts/`
EOF

cat > "${LIVE_DIR}/README.md" <<EOF
# Live Happy Path Evidence

This bundle was generated by running the local four-process topology:

- trust control
- wrapped MCP provider edge
- buyer FastAPI API
- buyer \`arc api protect\` sidecar

Key files:

- \`quote-request.json\`
- \`quote-response.json\`
- \`job-response.json\`
- \`quote-response.headers\`
- \`job-response.headers\`
- \`receipts-all.json\`
- \`provider-quote-receipts.json\`
- \`provider-fulfillment-receipts.json\`
- \`summary.json\`
- \`logs/\`
EOF

echo "Captured live happy-path bundle at: ${OUT_DIR}"
