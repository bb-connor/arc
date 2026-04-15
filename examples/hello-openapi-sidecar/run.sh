#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
PORT="${HELLO_OPENAPI_SIDECAR_PORT:-8041}"

cd "${EXAMPLE_ROOT}"
exec python3 app.py
