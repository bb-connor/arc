#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=1

python3 scripts/check-kani-public-harnesses.py
exec ./scripts/run-kani-manifest.sh --lane pr --crate chio-kernel-core
