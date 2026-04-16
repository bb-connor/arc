#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

bundle_dir="$(prepare_scenario_dir "expiry-async-failure")"
trap stop_live_topology EXIT

start_live_topology "$bundle_dir"
run_live_scenario "$bundle_dir" "expiry-async-failure"
assert_review_ok "$bundle_dir"

python3 - "${bundle_dir}/summary.json" "${bundle_dir}/provider/process-task-response.json" "${bundle_dir}/acp/task-final.json" <<'PY'
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
provider = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
task_final = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
execution = provider["execution"]
assert summary["scenario_mode"] == "expiry-async-failure", summary
assert summary["task_status"] == "expired", summary
assert task_final["status"] == "expired", task_final
assert execution["verdict"] == "deny", execution
assert execution["reason"] == "expired_capability", execution
PY

printf 'scenario 05-expiry-async-failure passed\n'
printf 'artifacts: %s\n' "$bundle_dir"
