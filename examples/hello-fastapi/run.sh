#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
PORT="${HELLO_FASTAPI_PORT:-8011}"

cd "${EXAMPLE_ROOT}"
exec uv run --project . uvicorn app:app --host 127.0.0.1 --port "${PORT}"
