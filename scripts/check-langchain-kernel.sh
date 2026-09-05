#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

if [[ -n "${CHIO_BIN:-}" ]]; then
  chio_bin="$CHIO_BIN"
else
  cargo build --locked -p chio-cli --bin chio
  target_dir="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
  chio_bin="${target_dir}/debug/chio"
fi

uv run --locked --project sdks/python/chio-langchain --extra mcp \
  python examples/langchain-kernel/run.py --chio "$chio_bin" "$@"
