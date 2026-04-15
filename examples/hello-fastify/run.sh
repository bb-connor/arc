#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -d "${EXAMPLE_ROOT}/node_modules" ]]; then
  cd "${EXAMPLE_ROOT}"
  npm install --silent --no-package-lock >/dev/null
fi

cd "${EXAMPLE_ROOT}"
exec npm run start --silent
