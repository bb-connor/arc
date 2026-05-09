#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

OUT="$TMP_DIR/out"
ERR="$TMP_DIR/err"

if CHIO_RUST_VERIFICATION_METADATA_ONLY=1 \
  bash "$REPO_ROOT/scripts/check-rust-verification-gates.sh" >"$OUT" 2>"$ERR"; then
  echo "FAIL: deprecated metadata-only mode unexpectedly passed" >&2
  cat "$OUT" >&2
  cat "$ERR" >&2
  exit 1
fi
grep -q "cannot satisfy release evidence" "$ERR" \
  || { echo "FAIL: missing deprecated metadata-only diagnostic"; cat "$ERR" >&2; exit 1; }

CHIO_RUST_VERIFICATION_INVENTORY_LINT_ONLY=1 \
  bash "$REPO_ROOT/scripts/check-rust-verification-gates.sh" >"$OUT" 2>"$ERR"
grep -q "not release evidence" "$OUT" \
  || { echo "FAIL: missing inventory-lint-only non-release diagnostic"; cat "$OUT" >&2; exit 1; }

echo "PASS: rust verification inventory-lint mode test"
