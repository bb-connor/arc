#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v node >/dev/null 2>&1; then
  echo "bindings parity requires node on PATH" >&2
  exit 1
fi

cargo test -p arc-bindings-core
npm --prefix packages/sdk/arc-ts test
