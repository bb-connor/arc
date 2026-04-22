#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v node >/dev/null 2>&1; then
  echo "bindings parity requires node on PATH" >&2
  exit 1
fi

cargo test -p chio-binding-helpers
npm --prefix packages/sdk/chio-ts test
