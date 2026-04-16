#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

# Run the happy-path scenario first, then verify the bundle offline
bundle_dir="$(prepare_scenario_dir "offline-review")"
trap stop_live_topology EXIT

start_live_topology "$bundle_dir"
run_live_scenario "$bundle_dir" "happy-path"
assert_review_ok "$bundle_dir"

printf 'scenario 06-offline-review passed\n'
printf 'artifacts: %s\n' "$bundle_dir"
