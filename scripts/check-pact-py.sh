#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "pact-py checks require python3 on PATH" >&2
  exit 1
fi

venv_dir="$(mktemp -d "${TMPDIR:-/tmp}/pact-py-check.XXXXXX")"
cleanup() {
  rm -rf "$venv_dir"
}
trap cleanup EXIT

python3 -m venv "$venv_dir"
. "$venv_dir/bin/activate"
python -m pip install --quiet -e packages/sdk/pact-py
python -m unittest discover -s packages/sdk/pact-py/tests
