#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
: "${CHIO_BIN:?set CHIO_BIN to the freshly built chio executable}"
fixture_root="$(mktemp -d /tmp/chio-hello-authority.XXXXXX)"
trust_pid=""
sidecar_pid=""
cleanup() {
  if [[ -n "${sidecar_pid}" ]]; then
    kill "${sidecar_pid}" 2>/dev/null || true
    wait "${sidecar_pid}" 2>/dev/null || true
  fi
  if [[ -n "${trust_pid}" ]]; then
    kill "${trust_pid}" 2>/dev/null || true
    wait "${trust_pid}" 2>/dev/null || true
  fi
  rm -rf -- "${fixture_root}"
}
trap cleanup EXIT

# Reproduce the normal CI umask before loading the shared smoke setup.
umask 022
source "${repo_root}/examples/_shared/hello-http-common.sh"
mkdir "${fixture_root}/state"
control_url="http://127.0.0.1:$(pick_free_port)"
"${CHIO_BIN}" trust serve \
  --listen "${control_url#http://}" \
  --service-token fixture-only-token \
  --receipt-db "${fixture_root}/state/receipts.sqlite3" \
  --revocation-db "${fixture_root}/state/revocations.sqlite3" \
  --authority-db "${fixture_root}/state/authority.sqlite3" \
  --budget-db "${fixture_root}/state/budgets.sqlite3" \
  >"${fixture_root}/trust.log" 2>&1 &
trust_pid=$!
wait_for_http "${control_url}/health" 10
trust_authority_public_key "${control_url}" fixture-only-token >"${fixture_root}/public-key"
issue_demo_capability "${control_url}" fixture-only-token "${fixture_root}/capability.json"
materialize_capability_token "${fixture_root}/capability.json" "${fixture_root}/capability.token"

create_demo_signing_custody "${fixture_root}/state/sidecar.seed"
sidecar_url="http://127.0.0.1:$(pick_free_port)"
"${CHIO_BIN}" --authority-seed-file "${fixture_root}/state/sidecar.seed" api protect \
  --upstream http://127.0.0.1:1 \
  --spec "${repo_root}/examples/hello-drogon/openapi.yaml" \
  --allow-anonymous-reads \
  --listen "${sidecar_url#http://}" \
  --receipt-store "${fixture_root}/sidecar.sqlite3" \
  >"${fixture_root}/sidecar.log" 2>&1 &
sidecar_pid=$!
wait_for_http "${sidecar_url}/chio/health" 20

python3 - "${fixture_root}" <<'PY'
import json
from pathlib import Path
import stat
import sys

root = Path(sys.argv[1])
assert stat.S_IMODE((root / "state").stat().st_mode) == 0o700
for path in (root / "state").iterdir():
    assert stat.S_IMODE(path.stat().st_mode) == 0o600, path
assert len(bytes.fromhex((root / "state/sidecar.seed").read_text().strip())) == 32
for name in ("public-key", "capability.json", "capability.token"):
    assert stat.S_IMODE((root / name).stat().st_mode) == 0o600, name
assert len(bytes.fromhex((root / "public-key").read_text().strip())) == 32
assert json.loads((root / "capability.token").read_text())
print("private authority setup, issuance and token permissions passed")
PY

# An existing unsafe parent must still be refused, never silently repaired.
chmod 0755 "${fixture_root}/state"
response_code="$(curl -sS -o "${fixture_root}/refusal.json" -w '%{http_code}' \
  -H 'Authorization: Bearer fixture-only-token' "${control_url}/v1/authority")"
[[ "${response_code}" == 500 ]]
python3 - "${fixture_root}/refusal.json" <<'PY'
import json
from pathlib import Path
import sys

error = json.loads(Path(sys.argv[1]).read_text())["error"]
assert "database parent must belong to the effective user with mode 0700" in error, error
print("unsafe existing authority parent refused")
PY
