#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

bundle_dir="$(prepare_scenario_dir "revoke-midchain")"
trap stop_live_topology EXIT

start_live_topology "$bundle_dir"
run_live_scenario "$bundle_dir" "revoke-midchain"
assert_review_ok "$bundle_dir"

python3 - "${bundle_dir}/summary.json" "${bundle_dir}/provider/process-task-response.json" "${bundle_dir}/revocation/revoke-response.json" <<'PY'
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
provider = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
revoke = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
execution = provider["execution"]
assert summary["scenario_mode"] == "revoke-midchain", summary
assert summary["task_status"] == "revoked", summary
assert execution["verdict"] == "deny", execution
assert execution["reason"] == "revoked_ancestor", execution
assert revoke["revoked"] is True, revoke
PY

printf 'scenario 03-revoke-midchain passed\n'
printf 'artifacts: %s\n' "$bundle_dir"
