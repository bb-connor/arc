#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-security-provenance.sh"
SOURCE_COMMIT="666303e5f3428f3b6e6b72f118c269a02388e0a4"

work="$(mktemp -d -t chio-security-provenance-XXXXXX)"
trap 'rm -rf "$work"' EXIT

write_file() {
  local path="$1"
  shift
  mkdir -p "$(dirname "$path")"
  printf '%s\n' "$@" > "$path"
}

run_checker() {
  local root="$1" stdout="$2" stderr="$3"
  local rc=0
  CHIO_SECURITY_ROOT="$root" "$CHECKER" >"$stdout" 2>"$stderr" || rc=$?
  printf '%s\n' "$rc"
}

assert_rc() {
  local got="$1" want="$2" label="$3"
  if [[ "$got" != "$want" ]]; then
    printf 'FAIL: %s: got rc=%s, want rc=%s\n' "$label" "$got" "$want" >&2
    exit 1
  fi
  printf 'ok: %s (rc=%s)\n' "$label" "$got"
}

missing_entry="$work/missing-entry"
write_file "$missing_entry/crates/security/chio-decoy/src/lifecycle.rs" \
  '// Adapted from Clawdstrike'
write_file "$missing_entry/docs/security/clawdstrike-active-defense-provenance.md" \
  "Source commit: \`$SOURCE_COMMIT\`"
assert_rc "$(run_checker "$missing_entry" "$work/missing-entry.out" "$work/missing-entry.err")" 1 \
  "an adapted file without a destination entry fails"
grep -F 'missing provenance destination' "$work/missing-entry.err" >/dev/null

unknown_commit="$work/unknown-commit"
write_file "$unknown_commit/crates/security/chio-decoy/src/lifecycle.rs" \
  '// Adapted from Clawdstrike'
write_file "$unknown_commit/docs/security/clawdstrike-active-defense-provenance.md" \
  'Source commit: `0000000000000000000000000000000000000000`' \
  '| `crates/security/chio-decoy/src/lifecycle.rs` | concept |'
assert_rc "$(run_checker "$unknown_commit" "$work/unknown-commit.out" "$work/unknown-commit.err")" 1 \
  "an unreviewed source commit fails"
grep -F 'reviewed source commit is missing' "$work/unknown-commit.err" >/dev/null

zero_markers="$work/zero-markers"
write_file "$zero_markers/docs/security/clawdstrike-active-defense-provenance.md" \
  "Source commit: \`$SOURCE_COMMIT\`"
assert_rc "$(run_checker "$zero_markers" "$work/zero-markers.out" "$work/zero-markers.err")" 1 \
  "a provenance record without adaptation markers fails"
grep -F 'security provenance scan found no adaptation markers' \
  "$work/zero-markers.err" >/dev/null

valid="$work/valid"
write_file "$valid/crates/security/chio-decoy/src/lifecycle.rs" \
  '// Adapted from Clawdstrike'
write_file "$valid/docs/security/clawdstrike-active-defense-provenance.md" \
  "Source commit: \`$SOURCE_COMMIT\`" \
  '| Destination | Reuse class |' \
  '| --- | --- |' \
  '| `crates/security/chio-decoy/src/lifecycle.rs` | concept |'
assert_rc "$(run_checker "$valid" "$work/valid.out" "$work/valid.err")" 0 \
  "the reviewed commit and exact destination pass"
grep -F 'security provenance check passed' "$work/valid.out" >/dev/null

printf 'check-security-provenance.test.sh: all assertions passed\n'
