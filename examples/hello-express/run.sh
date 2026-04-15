#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "${EXAMPLE_ROOT}"

if [[ ! -d node_modules ]]; then
  npm install --silent --no-package-lock
fi

exec npm run start --silent

