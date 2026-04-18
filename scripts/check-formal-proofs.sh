#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

formal_root="formal/lean4/Pact"

if ! command -v lake >/dev/null 2>&1; then
  echo "formal proof check requires lake on PATH (install Lean 4 / elan first)" >&2
  exit 1
fi

echo "==> Lean 4 proof build"
(
  cd "${formal_root}"
  lake build
)

echo "==> Lean 4 placeholder scan"
if command -v rg >/dev/null 2>&1; then
  placeholder_scan=(rg -n '\bsorry\b' \
    "${formal_root}/Arc" \
    "${formal_root}/Pact" \
    "${formal_root}/Arc.lean" \
    "${formal_root}/Pact.lean" \
    -g '*.lean')
else
  placeholder_scan=(grep -RInw --include '*.lean' 'sorry' \
    "${formal_root}/Arc" \
    "${formal_root}/Pact" \
    "${formal_root}/Arc.lean" \
    "${formal_root}/Pact.lean")
fi

if "${placeholder_scan[@]}"; then
  echo "formal proof check failed: found literal sorry in shipped Lean modules" >&2
  exit 1
fi

echo "formal proof check passed"
