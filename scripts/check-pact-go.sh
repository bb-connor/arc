#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../packages/sdk/pact-go"

if ! command -v go >/dev/null 2>&1; then
  echo "pact-go checks require go on PATH" >&2
  exit 1
fi

CGO_ENABLED=0 go test ./...
