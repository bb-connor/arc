#!/usr/bin/env bash
# Record every body the signing wrapper covers during one workspace test run.
#
# Usage: scripts/capture-wrapper-bodies.sh [extra cargo test args...]
#
# Enables the chio-core-types `wrapper-capture` feature for this run only and
# records into "${CARGO_TARGET_DIR:-target}/wrapper-capture", which is emptied
# first. Only test binaries record (the hook checks that it runs from a cargo
# `deps` directory). Test failures do not stop the capture; the script reports
# cargo's exit code and the recorded ids, then exits with that code. Then run
# `scripts/gen-signed-artifact-schemas.py --import-captures <that dir>`.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
mkdir -p "$target_dir"
capture_dir="$(cd "$target_dir" && pwd)/wrapper-capture"
rm -rf -- "$capture_dir"
mkdir -p "$capture_dir"

set +e
(cd "$root" && CHIO_WRAPPER_CAPTURE_DIR="$capture_dir" cargo test --workspace --no-fail-fast \
  --features chio-core-types/wrapper-capture "$@")
status=$?
set -e

ids=$(find "$capture_dir" -mindepth 1 -maxdepth 1 -type d | wc -l)
bodies=$(find "$capture_dir" -mindepth 2 -maxdepth 2 -name '*.json' | wc -l)
echo "capture-wrapper-bodies: cargo exit $status; $bodies bodies under $ids schema ids in $capture_dir"
exit "$status"
