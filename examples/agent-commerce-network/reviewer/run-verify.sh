#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <bundle-dir> [--control-url ... --auth-token ... --capability-id ...]" >&2
  exit 1
fi

exec python3 verify_bundle.py "$@"
