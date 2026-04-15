#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "${EXAMPLE_ROOT}"

exec cargo run --quiet -- "${@:-serve}"

