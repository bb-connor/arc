#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

matches=()
while IFS= read -r path; do
  case "${path}" in
    */__pycache__/*|*.pyc|*.pyo|*.pyd|packages/sdk/arc-py/build/*|packages/sdk/arc-py/src/*.egg-info|packages/sdk/arc-py/src/*.egg-info/*|packages/sdk/arc-ts/dist/*|packages/sdk/arc-ts/node_modules/*|crates/arc-cli/dashboard/dist/*|crates/arc-cli/dashboard/node_modules/*|tests/conformance/results/generated/*|tests/conformance/reports/generated/*)
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
