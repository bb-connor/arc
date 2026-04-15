#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

exec uvicorn app:app --host "${BUYER_API_HOST:-127.0.0.1}" --port "${BUYER_API_PORT:-8101}"
