#!/usr/bin/env bash
# Prove the negative-assertion gate refuses a new weak assertion and accepts the
# forms that name the rule that rejected.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-negative-assertions.py"
BASELINED="crates/security/chio-quarantine/tests/state_machine.rs"

work="$(mktemp -d -t chio-negative-assertions-XXXXXX)"
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

write_weak() {
  local path="$1" count="$2"
  mkdir -p "$(dirname "$path")"
  {
    echo '#[test]'
    echo 'fn rejects() {'
    awk -v count="$count" 'BEGIN { for (i = 1; i <= count; i++) print "    assert!(dispatch(" i ").is_err());" }'
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
entry = re.search(rf'"{re.escape(sys.argv[2])}": ([0-9]+),', source)
print(int(entry.group(1)))
PY
)"

strong="$work/strong"
init_case "$strong"
write_source "$strong/crates/security/chio-quarantine/tests/dispatch.rs" <<'EOF'
#[test]
fn rejects_a_stale_scope() {
    let error = dispatch(1).unwrap_err();
    assert!(matches!(error, StateMachineError::StaleScope));
    assert_eq!(dispatch(2).unwrap_err(), StateMachineError::StaleScope);
    assert!(dispatch(3).is_ok());
    // assert!(dispatch(4).is_err());
    let _ = "assert!(dispatch(5).is_err());";
}
EOF
write_source "$strong/crates/protocol/chio-a2a-edge/tests/dispatch.rs" <<'EOF'
#[test]
fn outside_the_gated_crates() {
    assert!(dispatch(1).is_err());
}
EOF
track_case "$strong"
assert_rc "$(run_checker "$CHECKER" "$strong" "$work/strong.out" "$work/strong.err")" 0 \
  "variant assertions pass, and a comment, a string and an ungated crate are not counted"
grep -F "Weak negative assertions: 0 across 0 files" "$work/strong.out" >/dev/null

unrecorded="$work/unrecorded"
init_case "$unrecorded"
write_weak "$unrecorded/crates/security/chio-quarantine/tests/dispatch.rs" 1
track_case "$unrecorded"
assert_rc "$(run_checker "$CHECKER" "$unrecorded" "$work/unrecorded.out" "$work/unrecorded.err")" 1 \
  "a new file with a weak negative assertion fails"
grep -F "crates/security/chio-quarantine/tests/dispatch.rs: 1 weak negative assertions and no baseline entry" \
  "$work/unrecorded.err" >/dev/null

multiline="$work/multiline"
init_case "$multiline"
write_source "$multiline/crates/kernel/chio-kernel/src/dispatch_tests.rs" <<'EOF'
#[test]
fn rejects() {
    assert!(
        dispatch(ResponsePlan::new(1, 2), &mut executor)
            .is_err()
    );
    assert!(dispatch(3).is_err(), "expected a stale scope");
}
EOF
track_case "$multiline"
assert_rc "$(run_checker "$CHECKER" "$multiline" "$work/multiline.out" "$work/multiline.err")" 1 \
  "a weak assertion split across lines, and one carrying a message, both count"
grep -F "crates/kernel/chio-kernel/src/dispatch_tests.rs: 2 weak negative assertions and no baseline entry" \
  "$work/multiline.err" >/dev/null

over_cap="$work/over-cap"
init_case "$over_cap"
write_weak "$over_cap/$BASELINED" "$((baseline_cap + 1))"
track_case "$over_cap"
assert_rc "$(run_checker "$CHECKER" "$over_cap" "$work/over-cap.out" "$work/over-cap.err")" 1 \
  "a baselined file cannot gain a weak negative assertion"
grep -F "$BASELINED: $((baseline_cap + 1)) weak negative assertions, baseline is $baseline_cap" \
  "$work/over-cap.err" >/dev/null

under_cap="$work/under-cap"
init_case "$under_cap"
write_weak "$under_cap/$BASELINED" "$((baseline_cap - 1))"
track_case "$under_cap"
assert_rc "$(run_checker "$CHECKER" "$under_cap" "$work/under-cap.out" "$work/under-cap.err")" 0 \
  "a baselined file may shed weak negative assertions"

stale_entry="$work/stale-entry"
init_case "$stale_entry"
write_source "$stale_entry/$BASELINED" <<'EOF'
#[test]
fn rejects_a_stale_scope() {
    assert!(matches!(dispatch(1).unwrap_err(), StateMachineError::StaleScope));
}
EOF
track_case "$stale_entry"
assert_rc "$(run_checker "$CHECKER" "$stale_entry" "$work/stale-entry.out" "$work/stale-entry.err")" 1 \
  "a baseline entry for a file that has converted all of them fails"
grep -F "$BASELINED: no weak negative assertions remain" "$work/stale-entry.err" >/dev/null

expired="$work/expired"
init_case "$expired"
write_source "$expired/crates/security/chio-quarantine/tests/dispatch.rs" <<'EOF'
#[test]
fn rejects_a_stale_scope() {
    assert!(matches!(dispatch(1).unwrap_err(), StateMachineError::StaleScope));
}
EOF
track_case "$expired"
expired_checker="$work/expired-check-negative-assertions.py"
sed -E 's/BASELINE_EXPIRES = "20[0-9]{2}-[0-9]{2}-[0-9]{2}"/BASELINE_EXPIRES = "2000-01-01"/' \
  "$CHECKER" > "$expired_checker"
assert_rc "$(run_checker "$expired_checker" "$expired" "$work/expired.out" "$work/expired.err")" 1 \
  "an expired baseline fails"
grep -F "weak negative assertion baseline expired on 2000-01-01" "$work/expired.err" >/dev/null

echo "check-negative-assertions.test.sh: all assertions passed"
