#!/usr/bin/env bash
# Prove the wire-schema gate fails on a bumped, new or removed identifier that
# the lock does not acknowledge, records duplicates without failing them, and
# writes the same lock twice from the same tree.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-wire-schemas.py"

work="$(mktemp -d -t chio-wire-schemas-XXXXXX)"
trap 'rm -rf "$work"' EXIT

init_case() {
  mkdir -p "$1"
  git -C "$1" init -q
}

commit_case() {
  git -C "$1" add .
  git -C "$1" -c user.name=fixture -c user.email=fixture@example.invalid commit -q -m fixture
}

write_source() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  cat > "$path"
}

run_checker() {
  local root="$1" stdout="$2" stderr="$3"
  shift 3
  local rc=0
  python3 "$CHECKER" --root "$root" "$@" >"$stdout" 2>"$stderr" || rc=$?
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

# One producer crate in the security set, one verifier crate outside it, a
# test that pins the receipt identifier, and a broker identifier with no pin.
populate() {
  local root="$1"
  write_source "$root/crates/security/chio-example/src/lib.rs" <<'EOF'
pub const RECEIPT_SCHEMA: &str = "chio.example.receipt.v1";
pub const BROKER_EXECUTE_SCHEMA: &str = "chio.example.broker-execute.v1";
pub const NOT_VERSIONED: &str = "chio.example.label";
pub const UNRELATED: &str = "https://example.invalid/v1";
#[cfg(not(test))]
pub const PRODUCTION_ONLY_SCHEMA: &str = "chio.example.production-only.v1";
#[cfg(all(test, feature = "shape-fixtures"))]
pub const FIXTURE_SCHEMA: &str = "chio.example.fixture-only.v1";

#[cfg(test)]
mod tests {
    const FIXTURE_ONLY: &str = "chio.example.fixture.v9";

    #[test]
    fn receipt_identifier_is_pinned() {
        assert_eq!(super::RECEIPT_SCHEMA, "chio.example.receipt.v1");
    }
}
EOF
  write_source "$root/crates/products/chio-example-cli/src/lib.rs" <<'EOF'
pub(crate) const RECEIPT_SCHEMA: &str = "chio.example.receipt.v1";
pub static REPORT_FORMAT: &'static str =
    "chio.example.report/v2";
EOF
  write_source "$root/crates/products/chio-example-cli/tests/report.rs" <<'EOF'
const EXPECTED: &str = "chio.example.report/v2";
EOF
  write_source "$root/crates/core/chio-core-types/src/_generated/wire.rs" <<'EOF'
pub const GENERATED_SCHEMA: &str = "chio.example.generated.v1";
EOF
}

compliant="$work/compliant"
init_case "$compliant"
populate "$compliant"
commit_case "$compliant"
assert_rc "$(run_checker "$compliant" "$work/update.out" "$work/update.err" --update)" 0 \
  "--update writes the lock and the report from the tree"
grep -F "wrote 4 identifiers to spec/wire-schemas.lock (4 new, 0 retired) and 2 unpinned" "$work/update.out" >/dev/null
lock="$compliant/spec/wire-schemas.lock"
report="$compliant/spec/wire-schemas-unpinned.md"
test -f "$lock"
test -f "$report"
grep -F 'value = "chio.example.receipt.v1"' "$lock" >/dev/null
grep -F 'value = "chio.example.production-only.v1"' "$lock" >/dev/null
if grep -F 'chio.example.fixture-only.v1' "$lock" >/dev/null; then
  echo "FAIL: a constant that exists only in a test build was recorded as a declaration" >&2
  exit 1
fi
grep -F '`crates/security/chio-example/src/lib.rs:6` `PRODUCTION_ONLY_SCHEMA` = `chio.example.production-only.v1`' "$report" >/dev/null
grep -F 'files = ["crates/products/chio-example-cli/src/lib.rs", "crates/security/chio-example/src/lib.rs"]' "$lock" >/dev/null
grep -F 'value = "chio.example.report/v2"' "$lock" >/dev/null
grep -F 'value = "chio.example.broker-execute.v1"' "$lock" >/dev/null
first_seen="$(git -C "$compliant" rev-parse --short=10 HEAD)"
grep -F "first_seen = \"$first_seen\"" "$lock" >/dev/null
if grep -F 'chio.example.fixture.v9' "$lock" >/dev/null; then
  echo "FAIL: a test-scoped constant was recorded as a declaration" >&2
  exit 1
fi
if grep -F 'chio.example.generated.v1' "$lock" >/dev/null; then
  echo "FAIL: generated output was recorded as a hand-written declaration" >&2
  exit 1
fi
if grep -F 'chio.example.label' "$lock" >/dev/null; then
  echo "FAIL: an unversioned string was recorded as an identifier" >&2
  exit 1
fi
grep -F '`crates/security/chio-example/src/lib.rs:2` `BROKER_EXECUTE_SCHEMA` = `chio.example.broker-execute.v1`' "$report" >/dev/null
if grep -F 'RECEIPT_SCHEMA' "$report" >/dev/null; then
  echo "FAIL: a constant pinned by a test literal was reported unpinned" >&2
  exit 1
fi
echo "ok: the lock records duplicates with every file, skips test scope, generated output and unversioned strings, and the report names the unpinned constant"

cp "$lock" "$work/first.lock"
cp "$report" "$work/first.md"
assert_rc "$(run_checker "$compliant" "$work/update2.out" "$work/update2.err" --update)" 0 \
  "a second --update on the same tree succeeds"
cmp -s "$lock" "$work/first.lock" || { echo "FAIL: second --update changed the lock" >&2; exit 1; }
cmp -s "$report" "$work/first.md" || { echo "FAIL: second --update changed the report" >&2; exit 1; }
echo "ok: --update is deterministic"

assert_rc "$(run_checker "$compliant" "$work/compliant.out" "$work/compliant.err")" 0 \
  "a tree that matches its lock passes"
grep -F "5 identifier constants, 4 distinct values, 1 declared in more than one file, 4 lock entries; 2 of 3 security-crate constants unpinned" \
  "$work/compliant.out" >/dev/null

bumped="$work/bumped"
init_case "$bumped"
populate "$bumped"
commit_case "$bumped"
run_checker "$bumped" /dev/null /dev/null --update >/dev/null
sed -i 's/chio.example.broker-execute.v1/chio.example.broker-execute.v2/' "$bumped/crates/security/chio-example/src/lib.rs"
assert_rc "$(run_checker "$bumped" "$work/bumped.out" "$work/bumped.err")" 1 \
  "a bumped identifier without a lock change fails"
grep -F 'crates/security/chio-example/src/lib.rs:2 BROKER_EXECUTE_SCHEMA = "chio.example.broker-execute.v2" is not in the lock (new or bumped identifier)' \
  "$work/bumped.err" >/dev/null
grep -E 'spec/wire-schemas.lock:[0-9]+ chio.example.broker-execute.v1 lists crates/security/chio-example/src/lib.rs, which no longer declares it' \
  "$work/bumped.err" >/dev/null
grep -F 'BROKER_EXECUTE_SCHEMA = "chio.example.broker-execute.v2" has no pinning literal and is not listed in spec/wire-schemas-unpinned.md' \
  "$work/bumped.err" >/dev/null

added="$work/added"
init_case "$added"
populate "$added"
commit_case "$added"
run_checker "$added" /dev/null /dev/null --update >/dev/null
cat >> "$added/crates/products/chio-example-cli/src/lib.rs" <<'EOF'
pub const ENVELOPE_SCHEMA: &str = "chio.example.envelope.v1";
EOF
assert_rc "$(run_checker "$added" "$work/added.out" "$work/added.err")" 1 \
  "a new identifier without a lock entry fails"
grep -F 'crates/products/chio-example-cli/src/lib.rs:4 ENVELOPE_SCHEMA = "chio.example.envelope.v1" is not in the lock' \
  "$work/added.err" >/dev/null

moved="$work/moved"
init_case "$moved"
populate "$moved"
commit_case "$moved"
run_checker "$moved" /dev/null /dev/null --update >/dev/null
cat >> "$moved/crates/products/chio-example-cli/src/lib.rs" <<'EOF'
pub const BROKER_EXECUTE_SCHEMA: &str = "chio.example.broker-execute.v1";
EOF
assert_rc "$(run_checker "$moved" "$work/moved.out" "$work/moved.err")" 1 \
  "a recorded identifier declared in a file the lock does not list fails"
grep -F 'BROKER_EXECUTE_SCHEMA = "chio.example.broker-execute.v1" is declared in a file the lock does not list for it' \
  "$work/moved.err" >/dev/null

removed="$work/removed"
init_case "$removed"
populate "$removed"
commit_case "$removed"
run_checker "$removed" /dev/null /dev/null --update >/dev/null
sed -i '/REPORT_FORMAT/,/chio.example.report/d' "$removed/crates/products/chio-example-cli/src/lib.rs"
assert_rc "$(run_checker "$removed" "$work/removed.out" "$work/removed.err")" 1 \
  "a removed identifier still in the lock fails"
grep -E 'spec/wire-schemas.lock:[0-9]+ chio.example.report/v2 lists crates/products/chio-example-cli/src/lib.rs, which no longer declares it' \
  "$work/removed.err" >/dev/null

pinned_later="$work/pinned-later"
init_case "$pinned_later"
populate "$pinned_later"
commit_case "$pinned_later"
run_checker "$pinned_later" /dev/null /dev/null --update >/dev/null
write_source "$pinned_later/crates/security/chio-example/tests/broker_shape.rs" <<'EOF'
const EXPECTED: &str = "chio.example.broker-execute.v1";
EOF
assert_rc "$(run_checker "$pinned_later" "$work/pinned-later.out" "$work/pinned-later.err")" 0 \
  "adding a pin leaves a stale report entry in the safe direction and passes"
grep -F "1 of 3 security-crate constants unpinned" "$work/pinned-later.out" >/dev/null

not_test_bumped="$work/not-test-bumped"
init_case "$not_test_bumped"
populate "$not_test_bumped"
commit_case "$not_test_bumped"
run_checker "$not_test_bumped" /dev/null /dev/null --update >/dev/null
sed -i 's/chio.example.production-only.v1/chio.example.production-only.v2/' "$not_test_bumped/crates/security/chio-example/src/lib.rs"
assert_rc "$(run_checker "$not_test_bumped" "$work/not-test-bumped.out" "$work/not-test-bumped.err")" 1 \
  "a bumped identifier under cfg(not(test)) is production code and fails without a lock change"
grep -F 'crates/security/chio-example/src/lib.rs:6 PRODUCTION_ONLY_SCHEMA = "chio.example.production-only.v2" is not in the lock (new or bumped identifier)' \
  "$work/not-test-bumped.err" >/dev/null

unlisted="$work/unlisted"
init_case "$unlisted"
populate "$unlisted"
commit_case "$unlisted"
run_checker "$unlisted" /dev/null /dev/null --update >/dev/null
sed -i '/BROKER_EXECUTE_SCHEMA/d' "$unlisted/spec/wire-schemas-unpinned.md"
assert_rc "$(run_checker "$unlisted" "$work/unlisted.out" "$work/unlisted.err")" 1 \
  "an unpinned security-crate constant missing from the report fails"
grep -F 'BROKER_EXECUTE_SCHEMA = "chio.example.broker-execute.v1" has no pinning literal and is not listed in spec/wire-schemas-unpinned.md' \
  "$work/unlisted.err" >/dev/null

missing_lock="$work/missing-lock"
init_case "$missing_lock"
populate "$missing_lock"
commit_case "$missing_lock"
assert_rc "$(run_checker "$missing_lock" "$work/missing-lock.out" "$work/missing-lock.err")" 1 \
  "a tree with no lock fails"
grep -F "spec/wire-schemas.lock:1 missing" "$work/missing-lock.err" >/dev/null

echo "check-wire-schemas.test.sh: all assertions passed"
