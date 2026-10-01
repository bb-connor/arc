#!/usr/bin/env bash
# Prove the domain-separation gate fails on a duplicate, a malformed value and a
# reachable placeholder, and does not fire on the shapes that are legitimate.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-domain-separation.py"
CAPPED='chio.fincred.source-artifact.v1\0'

work="$(mktemp -d -t chio-domain-separation-XXXXXX)"
trap 'rm -rf "$work"' EXIT

init_case() {
  mkdir -p "$1"
  git -C "$1" init -q
}

track_case() {
  git -C "$1" add .
}

write_source() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  cat > "$path"
}

run_checker() {
  local checker="$1" root="$2" stdout="$3" stderr="$4"
  local rc=0
  python3 "$checker" --root "$root" >"$stdout" 2>"$stderr" || rc=$?
  echo "$rc"
}

assert_rc() {
  local got="$1" want="$2" label="$3"
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $label: got rc=$got, want rc=$want" >&2
    exit 1
  fi
  echo "ok: $label (rc=$got)"
}

compliant="$work/compliant"
init_case "$compliant"
write_source "$compliant/crates/security/chio-example/src/lib.rs" <<'EOF'
pub const RESPONSE_PLAN_DOMAIN: &[u8] = b"chio.example.response-plan.v1\0";
pub const RESPONSE_PLAN_SIGNATURE_DOMAIN: &[u8] = b"chio.example.response-plan.signature.v2\0";
// pub const COMMENTED_DOMAIN: &[u8] = b"chio-not-a-domain-v1";
EOF
track_case "$compliant"
assert_rc "$(run_checker "$CHECKER" "$compliant" "$work/compliant.out" "$work/compliant.err")" 0 \
  "single declarations on the convention pass, and a commented-out one is not counted"
grep -F "2 byte-string domain constants, 2 distinct values, 0 declared more than once, 0 off the convention" \
  "$work/compliant.out" >/dev/null

duplicate="$work/duplicate"
init_case "$duplicate"
write_source "$duplicate/crates/security/chio-producer/src/lib.rs" <<'EOF'
pub const EFFECT_ID_DOMAIN: &[u8] = b"chio.example.effect.v1\0";
EOF
write_source "$duplicate/crates/kernel/chio-verifier/src/lib.rs" <<'EOF'
const RESPONSE_EFFECT_ID_DOMAIN: &[u8] = b"chio.example.effect.v1\0";
EOF
track_case "$duplicate"
assert_rc "$(run_checker "$CHECKER" "$duplicate" "$work/duplicate.out" "$work/duplicate.err")" 1 \
  "one value declared in two crates fails even under two different names"
grep -F 'chio.example.effect.v1\0: declared in 2 places' "$work/duplicate.err" >/dev/null

test_duplicate="$work/test-duplicate"
init_case "$test_duplicate"
write_source "$test_duplicate/crates/security/chio-producer/src/lib.rs" <<'EOF'
pub const EFFECT_ID_DOMAIN: &[u8] = b"chio.example.effect.v1\0";
EOF
write_source "$test_duplicate/crates/security/chio-producer/tests/effect.rs" <<'EOF'
const EFFECT_ID_DOMAIN: &[u8] = b"chio.example.effect.v1\0";
EOF
track_case "$test_duplicate"
assert_rc "$(run_checker "$CHECKER" "$test_duplicate" "$work/test-duplicate.out" "$work/test-duplicate.err")" 1 \
  "a test that re-declares a production domain instead of importing it fails"
grep -F 'chio.example.effect.v1\0: declared in 2 places' "$work/test-duplicate.err" >/dev/null

malformed="$work/malformed"
init_case "$malformed"
write_source "$malformed/crates/security/chio-example/src/lib.rs" <<'EOF'
pub const UNTERMINATED_DOMAIN: &[u8] = b"chio.example.effect.v1";
pub const HYPHEN_DOMAIN: &[u8] = b"chio-example-effect-v1\0";
pub const COLON_DOMAIN: &[u8] = b"chio:example:effect:v1\0";
pub const UPPERCASE_DOMAIN: &[u8] = b"CHIO.EXAMPLE.EFFECT.V1\0";
EOF
track_case "$malformed"
assert_rc "$(run_checker "$CHECKER" "$malformed" "$work/malformed.out" "$work/malformed.err")" 1 \
  "unterminated, hyphen, colon and uppercase spellings all fail"
for value in 'chio.example.effect.v1' 'chio-example-effect-v1\0' 'chio:example:effect:v1\0' 'CHIO.EXAMPLE.EFFECT.V1\0'; do
  grep -F "$value: not chio.<area>.<payload>.v<N> with a NUL terminator" "$work/malformed.err" >/dev/null
done

over_cap="$work/over-cap"
init_case "$over_cap"
for crate in chio-one chio-two chio-three; do
  write_source "$over_cap/crates/trust/$crate/src/lib.rs" <<'EOF'
pub const FINANCIAL_SOURCE_ARTIFACT_DIGEST_DOMAIN: &[u8] = b"chio.fincred.source-artifact.v1\0";
EOF
done
track_case "$over_cap"
assert_rc "$(run_checker "$CHECKER" "$over_cap" "$work/over-cap.out" "$work/over-cap.err")" 1 \
  "a recorded duplicate cannot gain another declaration"
grep -F "$CAPPED: declared in 3 places, cap is 2" "$work/over-cap.err" >/dev/null

stale_debt="$work/stale-debt"
init_case "$stale_debt"
write_source "$stale_debt/crates/trust/chio-credentials/src/financial.rs" <<'EOF'
pub const FINANCIAL_SOURCE_ARTIFACT_DIGEST_DOMAIN: &[u8] = b"chio.fincred.source-artifact.v1\0";
EOF
track_case "$stale_debt"
assert_rc "$(run_checker "$CHECKER" "$stale_debt" "$work/stale-debt.out" "$work/stale-debt.err")" 1 \
  "a debt entry that no longer excuses a violation fails"
grep -F "$CAPPED: debt entry no longer excuses a violation" "$work/stale-debt.err" >/dev/null

placeholder="$work/placeholder"
init_case "$placeholder"
write_source "$placeholder/crates/trust/chio-example/src/lib.rs" <<'EOF'
pub const PLACEHOLDER_SIGNATURE_DOMAIN: &[u8] = b"chio.example.placeholder.v1\0";
EOF
track_case "$placeholder"
assert_rc "$(run_checker "$CHECKER" "$placeholder" "$work/placeholder.out" "$work/placeholder.err")" 1 \
  "a placeholder domain reachable from production fails"
grep -F "PLACEHOLDER_SIGNATURE_DOMAIN: placeholder domain is reachable outside test scope" \
  "$work/placeholder.err" >/dev/null

placeholder_test_scope="$work/placeholder-test-scope"
init_case "$placeholder_test_scope"
write_source "$placeholder_test_scope/crates/trust/chio-example/src/lib.rs" <<'EOF'
#[cfg(any(test, feature = "test-support"))]
pub const PLACEHOLDER_SIGNATURE_DOMAIN: &[u8] = b"chio.example.placeholder.v1\0";
EOF
write_source "$placeholder_test_scope/crates/trust/chio-example/tests/loader.rs" <<'EOF'
const DUMMY_SIGNATURE_DOMAIN: &[u8] = b"DUMMY-SIGNATURE-OVERRIDE";
EOF
track_case "$placeholder_test_scope"
assert_rc "$(run_checker "$CHECKER" "$placeholder_test_scope" "$work/placeholder-test-scope.out" "$work/placeholder-test-scope.err")" 0 \
  "a placeholder behind a test cfg, and a fixture domain in test scope, both pass"

unreadable_escape="$work/unreadable-escape"
init_case "$unreadable_escape"
write_source "$unreadable_escape/crates/security/chio-example/src/lib.rs" <<'EOF'
pub const ESCAPED_DOMAIN: &[u8] = b"chio.example.effect.v1\u{0}";
EOF
track_case "$unreadable_escape"
assert_rc "$(run_checker "$CHECKER" "$unreadable_escape" "$work/unreadable-escape.out" "$work/unreadable-escape.err")" 1 \
  "a byte escape the gate cannot decode fails instead of being skipped"
grep -F "ESCAPED_DOMAIN: unsupported \\u escape" "$work/unreadable-escape.err" >/dev/null

expired="$work/expired"
init_case "$expired"
write_source "$expired/crates/security/chio-example/src/lib.rs" <<'EOF'
pub const RESPONSE_PLAN_DOMAIN: &[u8] = b"chio.example.response-plan.v1\0";
EOF
track_case "$expired"
expired_checker="$work/expired-check-domain-separation.py"
sed -E 's/"20[0-9]{2}-[0-9]{2}-[0-9]{2}"/"2000-01-01"/g' "$CHECKER" > "$expired_checker"
assert_rc "$(run_checker "$expired_checker" "$expired" "$work/expired.out" "$work/expired.err")" 1 \
  "an expired debt entry fails"
grep -F "debt entry expired on 2000-01-01" "$work/expired.err" >/dev/null

echo "check-domain-separation.test.sh: all assertions passed"
