#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "${EXAMPLE_ROOT}"

exec uv run --project . python manage.py runserver "127.0.0.1:${HELLO_DJANGO_PORT:-8016}" --noreload

