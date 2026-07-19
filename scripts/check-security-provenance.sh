#!/usr/bin/env bash
set -euo pipefail

ROOT="${CHIO_SECURITY_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
PROVENANCE="$ROOT/docs/security/clawdstrike-active-defense-provenance.md"
SOURCE_COMMIT="666303e5f3428f3b6e6b72f118c269a02388e0a4"

if [[ ! -f "$PROVENANCE" ]]; then
  printf 'security provenance record is missing: %s\n' "$PROVENANCE" >&2
  exit 1
fi

if ! grep -Fq "\`$SOURCE_COMMIT\`" "$PROVENANCE"; then
  printf 'reviewed source commit is missing: %s\n' "$SOURCE_COMMIT" >&2
  exit 1
fi

marked_output=""
if marked_output="$(
  rg -l --hidden --fixed-strings 'Adapted from Clawdstrike' \
    --glob '!.git/**' \
    --glob '!target/**' \
    --glob '!docs/superpowers/**' \
    --glob '!docs/security/clawdstrike-active-defense-provenance.md' \
    --glob '!scripts/check-security-provenance.sh' \
    --glob '!scripts/tests/check-security-provenance.test.sh' \
    "$ROOT"
)"; then
  :
else
  scan_status=$?
  if [[ "$scan_status" -eq 1 ]]; then
    printf 'security provenance scan found no adaptation markers\n' >&2
  else
    printf 'security provenance scan failed with status %s\n' "$scan_status" >&2
    [[ -z "$marked_output" ]] || printf '%s\n' "$marked_output" >&2
  fi
  exit 1
fi

while IFS= read -r marked_file; do
  [[ -n "$marked_file" ]] || continue
  relative_path="${marked_file#"$ROOT"/}"
  if ! grep -Fq "\`$relative_path\`" "$PROVENANCE"; then
    printf 'missing provenance destination: %s\n' "$relative_path" >&2
    exit 1
  fi
done <<<"$marked_output"

printf 'security provenance check passed\n'
