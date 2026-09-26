#!/usr/bin/env bash
# Prove the accounting-arithmetic gate fails on real unchecked arithmetic, and
# does not fire on the shapes that only look like it.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-accounting-arithmetic.py"
BASELINED="crates/kernel/chio-kernel/src/budget_store/in_memory/terminal.rs"

work="$(mktemp -d -t chio-accounting-arithmetic-XXXXXX)"
trap 'rm -rf "$work"' EXIT

init_case() {
  mkdir -p "$1"
  git -C "$1" init -q
}

track_case() {
  git -C "$1" add .
}

write_subtractions() {
  local path="$1" count="$2"
  mkdir -p "$(dirname "$path")"
  {
    echo 'pub fn settle(state: &mut u64) {'
    awk -v count="$count" 'BEGIN { for (i = 1; i <= count; i++) print "    *state -= 1;" }'
    echo '}'
  } > "$path"
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

baseline_cap="$(python3 - "$CHECKER" "$BASELINED" <<'PY'
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read()
entry = re.search(
    rf'"{re.escape(sys.argv[2])}": allow\((?:[^)]*?)max_sites=([0-9]+)',
    source,
    re.S,
)
print(int(entry.group(1)))
PY
)"

checked="$work/checked"
init_case "$checked"
mkdir -p "$checked/crates/kernel/chio-kernel/src/budget_store"
cat > "$checked/crates/kernel/chio-kernel/src/budget_store/model.rs" <<'EOF'
pub fn release(remaining: u64, cost: u64) -> Option<u64> {
    remaining.checked_sub(cost)
}
EOF
mkdir -p "$checked/crates/kernel/chio-kernel/src/receipt"
cat > "$checked/crates/kernel/chio-kernel/src/receipt/sequence.rs" <<'EOF'
pub fn previous(sequence: u64) -> u64 {
    sequence - 1
}
EOF
track_case "$checked"
assert_rc "$(run_checker "$CHECKER" "$checked" "$work/checked.out" "$work/checked.err")" 0 \
  "checked arithmetic inside scope and raw arithmetic outside scope both pass"
grep -F "Accounting arithmetic: 0 unchecked sites" "$work/checked.out" >/dev/null

unrecorded="$work/unrecorded"
init_case "$unrecorded"
write_subtractions "$unrecorded/crates/kernel/chio-kernel/src/budget_store/settlement.rs" 2
track_case "$unrecorded"
assert_rc "$(run_checker "$CHECKER" "$unrecorded" "$work/unrecorded.out" "$work/unrecorded.err")" 1 \
  "a new accounting module with unchecked arithmetic and no baseline entry fails"
grep -F "crates/kernel/chio-kernel/src/budget_store/settlement.rs: 2 unchecked arithmetic sites and no baseline entry" \
  "$work/unrecorded.err" >/dev/null

over_cap="$work/over-cap"
init_case "$over_cap"
write_subtractions "$over_cap/$BASELINED" "$((baseline_cap + 1))"
track_case "$over_cap"
assert_rc "$(run_checker "$CHECKER" "$over_cap" "$work/over-cap.out" "$work/over-cap.err")" 1 \
  "a baselined accounting module cannot gain an unchecked site"
grep -F "$BASELINED: $((baseline_cap + 1)) unchecked arithmetic sites, cap is $baseline_cap" \
  "$work/over-cap.err" >/dev/null

stale_entry="$work/stale-entry"
init_case "$stale_entry"
mkdir -p "$(dirname "$stale_entry/$BASELINED")"
cat > "$stale_entry/$BASELINED" <<'EOF'
pub fn release(remaining: u64, cost: u64) -> Option<u64> {
    remaining.checked_sub(cost)
}
EOF
track_case "$stale_entry"
assert_rc "$(run_checker "$CHECKER" "$stale_entry" "$work/stale-entry.out" "$work/stale-entry.err")" 1 \
  "a baseline entry whose module is clean fails"
grep -F "$BASELINED: no unchecked arithmetic remains" "$work/stale-entry.err" >/dev/null

test_scoped="$work/test-scoped"
init_case "$test_scoped"
mkdir -p "$test_scoped/crates/kernel/chio-kernel/src/budget_store"
cat > "$test_scoped/crates/kernel/chio-kernel/src/budget_store/model.rs" <<'EOF'
pub fn release(remaining: u64, cost: u64) -> Option<u64> {
    remaining.checked_sub(cost)
}

#[cfg(test)]
mod tests {
    #[test]
    fn subtracts() {
        let mut remaining = 3_u64;
        remaining -= 1;
        assert_eq!(remaining, 2);
    }
}

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    fn subtracts_under_precondition() {
        let remaining: u64 = kani::any();
        kani::assume(remaining > 0);
        let _ = remaining - 1;
    }
}
EOF
write_subtractions "$test_scoped/crates/kernel/chio-kernel/src/budget_store_tests/model.rs" 3
write_subtractions "$test_scoped/crates/kernel/chio-kernel/tests/budget_store.rs" 3
track_case "$test_scoped"
assert_rc "$(run_checker "$CHECKER" "$test_scoped" "$work/test-scoped.out" "$work/test-scoped.err")" 0 \
  "arithmetic behind a test or kani cfg, and in test scope, does not count"
grep -F "Accounting arithmetic: 0 unchecked sites" "$work/test-scoped.out" >/dev/null

negative_cfg="$work/negative-cfg"
init_case "$negative_cfg"
mkdir -p "$negative_cfg/crates/kernel/chio-kernel/src/budget_store"
cat > "$negative_cfg/crates/kernel/chio-kernel/src/budget_store/limits.rs" <<'EOF'
#[cfg(not(test))]
pub fn remaining(limit: u64, used: u64) -> u64 {
    limit - used
}

#[cfg(any(test, feature = "diagnostics"))]
pub fn remaining_with_diagnostics(limit: u64, used: u64) -> u64 {
    limit - used
}

#[cfg(all(
    not(kani),
    unix
))]
pub fn charged(total: u64, refund: u64) -> u64 {
    total - refund
}

#[cfg(all(test, feature = "diagnostics"))]
pub fn remaining_in_tests_only(limit: u64, used: u64) -> u64 {
    limit - used
}

#[cfg(not(any(test, kani)))]
pub fn production_only(limit: u64, used: u64) -> u64 {
    limit - used
}
EOF
track_case "$negative_cfg"
assert_rc "$(run_checker "$CHECKER" "$negative_cfg" "$work/negative-cfg.out" "$work/negative-cfg.err")" 1 \
  "arithmetic behind cfg(not(test)), a feature-enabled cfg, a multi-line mixed cfg and cfg(not(any(test, kani))) is production and counts"
grep -F "crates/kernel/chio-kernel/src/budget_store/limits.rs: 4 unchecked arithmetic sites and no baseline entry" \
  "$work/negative-cfg.err" >/dev/null

word_scope="$work/word-scope"
init_case "$word_scope"
write_subtractions "$word_scope/crates/kernel/chio-kernel/src/channel_release_publisher.rs" 3
track_case "$word_scope"
assert_rc "$(run_checker "$CHECKER" "$word_scope" "$work/word-scope.out" "$work/word-scope.err")" 0 \
  "a path naming a release is not read as naming a lease"
grep -F "Accounting arithmetic: 0 unchecked sites" "$work/word-scope.out" >/dev/null

not_arithmetic="$work/not-arithmetic"
init_case "$not_arithmetic"
mkdir -p "$not_arithmetic/crates/kernel/chio-kernel/src/budget_store"
cat > "$not_arithmetic/crates/kernel/chio-kernel/src/budget_store/model.rs" <<'EOF'
use std::fmt::Debug;

pub const MAX_LEDGER_BYTES: usize = 8 * 1024;

pub fn remaining(hold: &u64) -> u64 {
    *hold
}

pub fn describe(value: &(dyn Debug + Send + Sync)) -> String {
    format!("{value:?} 5 - 4 // - * /")
}

pub fn pointer(raw: *const u64) -> bool {
    raw.is_null()
}
EOF
track_case "$not_arithmetic"
assert_rc "$(run_checker "$CHECKER" "$not_arithmetic" "$work/not-arithmetic.out" "$work/not-arithmetic.err")" 0 \
  "return arrows, dereferences, trait bounds, raw pointers, constants and literals are not arithmetic"
grep -F "Accounting arithmetic: 0 unchecked sites" "$work/not-arithmetic.out" >/dev/null

expired="$work/expired"
init_case "$expired"
mkdir -p "$expired/crates/kernel/chio-kernel/src/budget_store"
cat > "$expired/crates/kernel/chio-kernel/src/budget_store/model.rs" <<'EOF'
pub fn release(remaining: u64, cost: u64) -> Option<u64> {
    remaining.checked_sub(cost)
}
EOF
track_case "$expired"
expired_checker="$work/expired-check-accounting-arithmetic.py"
sed -E 's/"20[0-9]{2}-[0-9]{2}-[0-9]{2}"/"2000-01-01"/g' "$CHECKER" > "$expired_checker"
assert_rc "$(run_checker "$expired_checker" "$expired" "$work/expired.out" "$work/expired.err")" 1 \
  "an expired baseline entry fails"
grep -F "baseline entry expired on 2000-01-01" "$work/expired.err" >/dev/null

echo "check-accounting-arithmetic.test.sh: all assertions passed"
