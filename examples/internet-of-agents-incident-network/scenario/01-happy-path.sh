#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

bundle_dir="$(prepare_scenario_dir "happy-path")"
trap stop_live_topology EXIT

start_live_topology "$bundle_dir"
run_live_scenario "$bundle_dir" "happy-path"
assert_review_ok "$bundle_dir"

printf 'scenario 01-happy-path passed\n'
printf 'artifacts: %s\n' "$bundle_dir"
