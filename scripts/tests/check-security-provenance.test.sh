#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-security-provenance.sh"
SOURCE_COMMIT="666303e5f3428f3b6e6b72f118c269a02388e0a4"
RULES_ROW='| `crates/libs/hunt-correlate/src/rules.rs` | `crates/security/chio-quarantine/src/rules.rs` | concept | Ordered stages over Chio event kinds with explicit predecessor validation, bounded windows, grouping, policy-version binding, and bounded state estimates |'
ENGINE_ROW='| `crates/libs/hunt-correlate/src/engine.rs` | `crates/security/chio-quarantine/src/correlation.rs` | concept | Verified Chio event ingress, tenant-rule-group partitioning, deterministic event-time watermarks, transactional durable partials, stable finding identifiers, and detector-health suppression |'

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
  "Source commit: \`$SOURCE_COMMIT\`" \
  "$RULES_ROW" \
  "$ENGINE_ROW"
assert_rc "$(run_checker "$missing_entry" "$work/missing-entry.out" "$work/missing-entry.err")" 1 \
  "an adapted file without a destination entry fails"
grep -F 'missing provenance destination' "$work/missing-entry.err" >/dev/null

unknown_commit="$work/unknown-commit"
write_file "$unknown_commit/crates/security/chio-decoy/src/lifecycle.rs" \
  '// Adapted from Clawdstrike'
write_file "$unknown_commit/docs/security/clawdstrike-active-defense-provenance.md" \
  'Source commit: `0000000000000000000000000000000000000000`' \
  "$RULES_ROW" \
  "$ENGINE_ROW" \
  '| `crates/security/chio-decoy/src/lifecycle.rs` | concept |'
assert_rc "$(run_checker "$unknown_commit" "$work/unknown-commit.out" "$work/unknown-commit.err")" 1 \
  "an unreviewed source commit fails"
grep -F 'reviewed source commit is missing' "$work/unknown-commit.err" >/dev/null

zero_markers="$work/zero-markers"
write_file "$zero_markers/docs/security/clawdstrike-active-defense-provenance.md" \
  "Source commit: \`$SOURCE_COMMIT\`" \
  "$RULES_ROW" \
  "$ENGINE_ROW"
assert_rc "$(run_checker "$zero_markers" "$work/zero-markers.out" "$work/zero-markers.err")" 1 \
  "a provenance record without adaptation markers fails"
grep -F 'security provenance scan found no adaptation markers' \
  "$work/zero-markers.err" >/dev/null

missing_temporal="$work/missing-temporal"
write_file "$missing_temporal/crates/security/chio-decoy/src/lifecycle.rs" \
  '// Adapted from Clawdstrike'
write_file "$missing_temporal/docs/security/clawdstrike-active-defense-provenance.md" \
  "Source commit: \`$SOURCE_COMMIT\`" \
  '| `crates/security/chio-decoy/src/lifecycle.rs` | concept |'
assert_rc "$(run_checker "$missing_temporal" "$work/missing-temporal.out" "$work/missing-temporal.err")" 1 \
  "temporal provenance is required without destination markers"
grep -F 'required temporal provenance row is missing or ambiguous' \
  "$work/missing-temporal.err" >/dev/null

for mutation in \
  rules-source \
  rules-destination \
  rules-class \
  rules-modification \
  rules-duplicate \
  engine-source \
  engine-destination \
  engine-class \
  engine-modification \
  engine-duplicate; do
  hostile="$work/temporal-$mutation"
  write_file "$hostile/crates/security/chio-decoy/src/lifecycle.rs" \
    '// Adapted from Clawdstrike'
  hostile_rules="$RULES_ROW"
  hostile_engine="$ENGINE_ROW"
  case "$mutation" in
    rules-source)
      hostile_rules="${RULES_ROW/hunt-correlate\/src\/rules.rs/hunt-correlate\/src\/rule.rs}"
      ;;
    rules-destination)
      hostile_rules="${RULES_ROW/chio-quarantine\/src\/rules.rs/chio-quarantine\/src\/correlation.rs}"
      ;;
    rules-class)
      hostile_rules="${RULES_ROW/| concept |/| source adaptation |}"
      ;;
    rules-modification)
      hostile_rules="${RULES_ROW/bounded state estimates/unbounded state estimates}"
      ;;
    engine-source)
      hostile_engine="${ENGINE_ROW/hunt-correlate\/src\/engine.rs/hunt-correlate\/src\/correlation.rs}"
      ;;
    engine-destination)
      hostile_engine="${ENGINE_ROW/chio-quarantine\/src\/correlation.rs/chio-quarantine\/src\/rules.rs}"
      ;;
    engine-class)
      hostile_engine="${ENGINE_ROW/| concept |/| source adaptation |}"
      ;;
    engine-modification)
      hostile_engine="${ENGINE_ROW/deterministic event-time watermarks/ingest-time watermarks}"
      ;;
  esac
  write_file "$hostile/docs/security/clawdstrike-active-defense-provenance.md" \
    "Source commit: \`$SOURCE_COMMIT\`" \
    "$hostile_rules" \
    "$hostile_engine" \
    '| `crates/security/chio-decoy/src/lifecycle.rs` | concept |'
  if [[ "$mutation" == "rules-duplicate" ]]; then
    printf '%s\n' "$RULES_ROW" >> \
      "$hostile/docs/security/clawdstrike-active-defense-provenance.md"
  elif [[ "$mutation" == "engine-duplicate" ]]; then
    printf '%s\n' "$ENGINE_ROW" >> \
      "$hostile/docs/security/clawdstrike-active-defense-provenance.md"
  fi
  assert_rc "$(run_checker "$hostile" "$work/temporal-$mutation.out" "$work/temporal-$mutation.err")" 1 \
    "temporal provenance $mutation mutation fails"
  grep -F 'required temporal provenance row is missing or ambiguous' \
    "$work/temporal-$mutation.err" >/dev/null
done

valid="$work/valid"
write_file "$valid/crates/security/chio-decoy/src/lifecycle.rs" \
  '// Adapted from Clawdstrike'
write_file "$valid/docs/security/clawdstrike-active-defense-provenance.md" \
  "Source commit: \`$SOURCE_COMMIT\`" \
  '| Destination | Reuse class |' \
  '| --- | --- |' \
  "$RULES_ROW" \
  "$ENGINE_ROW" \
  '| `crates/security/chio-decoy/src/lifecycle.rs` | concept |'
assert_rc "$(run_checker "$valid" "$work/valid.out" "$work/valid.err")" 0 \
  "the reviewed commit and exact destination pass"
grep -F 'security provenance check passed' "$work/valid.out" >/dev/null

printf 'check-security-provenance.test.sh: all assertions passed\n'
