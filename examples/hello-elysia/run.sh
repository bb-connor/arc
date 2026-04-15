#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "${EXAMPLE_ROOT}"

SDK_ROOT="${EXAMPLE_ROOT}/../../sdks/typescript/packages/elysia"
if [[ ! -f "${SDK_ROOT}/dist/index.js" ]]; then
  npm --prefix "${SDK_ROOT}" run build --silent
fi

if [[ ! -d node_modules ]]; then
  npm install --silent --no-package-lock
fi

exec npm run start --silent

