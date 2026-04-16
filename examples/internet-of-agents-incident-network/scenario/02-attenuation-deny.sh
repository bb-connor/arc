#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

bundle_dir="$(prepare_scenario_dir "attenuation-deny")"
trap stop_live_topology EXIT

start_live_topology "$bundle_dir"
run_live_scenario "$bundle_dir" "attenuation-deny"
assert_review_ok "$bundle_dir"

python3 - "${bundle_dir}/summary.json" "${bundle_dir}/provider/process-task-response.json" <<'PY'
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
provider = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
execution = provider["execution"]
assert summary["scenario_mode"] == "attenuation-deny", summary
assert summary["task_status"] == "denied", summary
assert execution["verdict"] == "deny", execution
assert execution["reason"] == "attenuation_violation", execution
assert "provider_operation" not in execution, execution
PY

printf 'scenario 02-attenuation-deny passed\n'
printf 'artifacts: %s\n' "$bundle_dir"
