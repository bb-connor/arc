#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

matches=()
while IFS= read -r path; do
  case "${path}" in
    */__pycache__/*|*.pyc|*.pyo|*.pyd|packages/sdk/chio-py/build/*|packages/sdk/chio-py/src/*.egg-info|packages/sdk/chio-py/src/*.egg-info/*|packages/sdk/chio-ts/dist/*|packages/sdk/chio-ts/node_modules/*|crates/chio-cli/dashboard/dist/*|crates/chio-cli/dashboard/node_modules/*|tests/conformance/results/generated/*|tests/conformance/reports/generated/*)
      matches+=("${path}")
      ;;
  esac
done < <(git ls-files)

if ((${#matches[@]} > 0)); then
  echo "tracked generated or cache artifacts must not be part of release inputs:" >&2
  printf '  %s\n' "${matches[@]}" >&2
  exit 1
fi

echo "release input inventory clean"
