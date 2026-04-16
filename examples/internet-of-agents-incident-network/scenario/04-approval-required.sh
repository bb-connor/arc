#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

bundle_dir="$(prepare_scenario_dir "approval-required")"
trap stop_live_topology EXIT

start_live_topology "$bundle_dir"
run_live_scenario "$bundle_dir" "approval-required"
assert_review_ok "$bundle_dir"

python3 - "${bundle_dir}/summary.json" "${bundle_dir}/provider/process-task-response.json" "${bundle_dir}/approval/pre-approval-execution.json" "${bundle_dir}/approval/approval-token.json" "${bundle_dir}/acp/task-final.json" <<'PY'
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
provider = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
pre = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
token = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
task_final = json.loads(Path(sys.argv[5]).read_text(encoding="utf-8"))
execution = provider["execution"]

assert summary["scenario_mode"] == "approval-required", summary
assert summary["task_status"] == "completed", summary
assert summary["pre_approval_verdict"] == "deny", summary
assert summary["pre_approval_reason"] == "approval_required", summary
assert summary["approval_token_id"] == token["id"], summary
assert task_final["status"] == "completed", task_final
assert pre["verdict"] == "deny", pre
assert pre["reason"] == "approval_required", pre
assert execution["verdict"] == "allow", execution
assert execution["approval_token_id"] == token["id"], execution
PY

printf 'scenario 04-approval-required passed\n'
printf 'artifacts: %s\n' "$bundle_dir"
