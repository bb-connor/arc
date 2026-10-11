#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Use CI's errexit semantics: an early failed gate must not hide later gates.
rc=0
bash -euo pipefail -c '
  source "$1/scripts/structural-gates.sh"
  run_gate bash -c "exit 17"
  run_gate touch "$2/later-ran"
  run_gate bash -c "exit 23"
  finish_gates
' _ "$ROOT" "$work" >"$work/failed.log" 2>&1 || rc=$?
[[ "$rc" == 1 && -f "$work/later-ran" ]]
grep -F 'exit=17' "$work/failed.log"
grep -F 'exit=23' "$work/failed.log"
grep -F '3 gates, 2 failures' "$work/failed.log"

bash -euo pipefail -c '
  source "$1/scripts/structural-gates.sh"
  run_gate true
  run_gate true
  finish_gates
' _ "$ROOT" >"$work/passed.log" 2>&1
grep -F '2 gates, 0 failures' "$work/passed.log"
echo 'run-structural-gates.test.sh: all assertions passed'
