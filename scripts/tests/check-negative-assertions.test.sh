#!/usr/bin/env bash
# Prove the negative-assertion gate refuses a new weak assertion, including one
# added in a file whose count did not change, and accepts the forms that name
# the rule that rejected. Fixtures are built from the real baseline's entries
# for one file, so the identities under test are the identities the gate pins.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-negative-assertions.py"
BASELINE="$REPO_ROOT/scripts/negative-assertions-baseline.txt"
# A baselined file with both a single-assertion site and a multi-assertion site.
BASELINED="crates/security/chio-secret-broker/src/revocation.rs"

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

# entry <count filter> <field>: the first baseline entry for BASELINED whose
# count satisfies the awk expression, printing field 3 (function) or 4
# (condition).
entry() {
  awk -F'\t' -v path="$BASELINED" -v want="$1" -v field="$2" \
    '$2 == path && (want == "one" ? $1 == 1 : $1 >= 2) { print $field; exit }' "$BASELINE"
}

SINGLE_FN="$(entry one 3)"
SINGLE_CONDITION="$(entry one 4)"
MULTI_FN="$(entry many 3)"
if [[ -z "$SINGLE_FN" || -z "$MULTI_FN" ]]; then
  echo "FAIL: $BASELINED needs one single-assertion site and one multi-assertion site in the baseline" >&2
  exit 1
fi

# write_pinned <fixture root> <mode>: regenerate the baselined file from its
# baseline entries. Modes: exact; shed (one assertion fewer at the first
# multi-assertion site); traded (the single-assertion site's assertion is
# replaced by a new weak one, so the file's count is unchanged); grown (one
# more assertion of the single-assertion site's shape).
write_pinned() {
  local root="$1" mode="$2"
  mkdir -p "$root/$(dirname "$BASELINED")"
  python3 - "$BASELINE" "$BASELINED" "$mode" "$SINGLE_FN" "$MULTI_FN" > "$root/$BASELINED" <<'PY'
import sys
baseline, target, mode, single_fn, multi_fn = sys.argv[1:6]
entries = []
for line in open(baseline, encoding="utf-8"):
    if line.startswith("#") or not line.strip():
        continue
    count, path, function, condition = line.rstrip("\n").split("\t")
    if path == target:
        entries.append((function, condition, int(count)))
by_function = {}
for function, condition, count in entries:
    by_function.setdefault(function, []).append((condition, count))
for function, sites in by_function.items():
    print("#[test]")
    print(f"fn {function}() {{")
    for condition, count in sites:
        if mode == "shed" and function == multi_fn and count >= 2:
            count -= 1
        if mode == "grown" and function == single_fn and count == 1:
            count += 1
        if mode == "traded" and function == single_fn and count == 1:
            print("    assert!(dispatch_after_trade(9).is_err());")
            continue
        for _ in range(count):
            print(f"    assert!({condition});")
    print("}")
PY
}

run_checker() {
  local checker="$1" root="$2" baseline="$3" stdout="$4" stderr="$5"
  shift 5
  local rc=0
  python3 "$checker" --root "$root" --baseline "$baseline" "$@" >"$stdout" 2>"$stderr" || rc=$?
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
assert_rc "$(run_checker "$CHECKER" "$strong" "$BASELINE" "$work/strong.out" "$work/strong.err")" 0 \
  "variant assertions pass, and a comment, a string and an ungated crate are not counted"
grep -F "Weak negative assertions: 0 across 0 files" "$work/strong.out" >/dev/null

unrecorded="$work/unrecorded"
init_case "$unrecorded"
write_source "$unrecorded/crates/security/chio-quarantine/tests/dispatch.rs" <<'EOF'
#[test]
fn rejects() {
    assert!(dispatch(1).is_err());
}
EOF
track_case "$unrecorded"
assert_rc "$(run_checker "$CHECKER" "$unrecorded" "$BASELINE" "$work/unrecorded.out" "$work/unrecorded.err")" 1 \
  "a weak negative assertion in a new file fails"
grep -F 'crates/security/chio-quarantine/tests/dispatch.rs:3 new weak negative assertion in `rejects`: assert!(dispatch(1).is_err())' \
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
assert_rc "$(run_checker "$CHECKER" "$multiline" "$BASELINE" "$work/multiline.out" "$work/multiline.err")" 1 \
  "a weak assertion split across lines, and one carrying a message, both count"
grep -F 'crates/kernel/chio-kernel/src/dispatch_tests.rs:3 new weak negative assertion in `rejects`: assert!(dispatch(ResponsePlan::new(1, 2), &mut executor) .is_err())' \
  "$work/multiline.err" >/dev/null
grep -F 'crates/kernel/chio-kernel/src/dispatch_tests.rs:7 new weak negative assertion in `rejects`: assert!(dispatch(3).is_err())' \
  "$work/multiline.err" >/dev/null

pinned="$work/pinned"
init_case "$pinned"
write_pinned "$pinned" exact
track_case "$pinned"
assert_rc "$(run_checker "$CHECKER" "$pinned" "$BASELINE" "$work/pinned.out" "$work/pinned.err")" 0 \
  "the pinned sites of a baselined file pass"

shed="$work/shed"
init_case "$shed"
write_pinned "$shed" shed
track_case "$shed"
assert_rc "$(run_checker "$CHECKER" "$shed" "$BASELINE" "$work/shed.out" "$work/shed.err")" 0 \
  "a pinned site may shed one of its assertions"

traded="$work/traded"
init_case "$traded"
write_pinned "$traded" traded
track_case "$traded"
assert_rc "$(run_checker "$CHECKER" "$traded" "$BASELINE" "$work/traded.out" "$work/traded.err")" 1 \
  "a new weak assertion fails even when it replaces a strengthened one and the file's count is unchanged"
grep -F "new weak negative assertion in \`$SINGLE_FN\`: assert!(dispatch_after_trade(9).is_err())" "$work/traded.err" >/dev/null
grep -F "baseline entry for \`$SINGLE_FN\` assert!($SINGLE_CONDITION) no longer matches anything" "$work/traded.err" >/dev/null

grown="$work/grown"
init_case "$grown"
write_pinned "$grown" grown
track_case "$grown"
assert_rc "$(run_checker "$CHECKER" "$grown" "$BASELINE" "$work/grown.out" "$work/grown.err")" 1 \
  "a second assertion of a pinned shape in the same function fails"
grep -F "2 weak negative assertions of the shape assert!($SINGLE_CONDITION) in \`$SINGLE_FN\`, baseline pins 1" \
  "$work/grown.err" >/dev/null

stale_entry="$work/stale-entry"
init_case "$stale_entry"
write_source "$stale_entry/$BASELINED" <<'EOF'
#[test]
fn rejects_a_stale_scope() {
    assert!(matches!(dispatch(1).unwrap_err(), StateMachineError::StaleScope));
}
EOF
track_case "$stale_entry"
assert_rc "$(run_checker "$CHECKER" "$stale_entry" "$BASELINE" "$work/stale-entry.out" "$work/stale-entry.err")" 1 \
  "baseline entries for a file that has converted all of them fail until they are removed"
grep -F "$BASELINED: baseline entry for \`$SINGLE_FN\` assert!($SINGLE_CONDITION) no longer matches anything; remove it (run --ratchet)" \
  "$work/stale-entry.err" >/dev/null

ratcheted="$work/ratcheted.txt"
cp "$BASELINE" "$ratcheted"
assert_rc "$(run_checker "$CHECKER" "$shed" "$ratcheted" "$work/ratchet.out" "$work/ratchet.err" --ratchet)" 0 \
  "--ratchet rewrites the baseline from the tree"
grep -E "^tightened: $BASELINED $MULTI_FN: [0-9]+ -> [0-9]+$" "$work/ratchet.out" >/dev/null
grep -E "^dropped: " "$work/ratchet.out" >/dev/null
grep -F "expires 2027-01-31" "$ratcheted" >/dev/null
if awk -F'\t' -v path="$BASELINED" '/^[0-9]/ && $2 != path { found = 1 } END { exit !found }' "$ratcheted"; then
  echo "FAIL: --ratchet kept an entry for a file absent from the tree" >&2
  exit 1
fi
assert_rc "$(run_checker "$CHECKER" "$shed" "$ratcheted" "$work/ratcheted.out" "$work/ratcheted.err")" 0 \
  "the ratcheted baseline matches the tree it was written from"

expired="$work/expired.txt"
sed -E 's/^# expires 20[0-9]{2}-[0-9]{2}-[0-9]{2}$/# expires 2000-01-01/' "$BASELINE" > "$expired"
assert_rc "$(run_checker "$CHECKER" "$strong" "$expired" "$work/expired.out" "$work/expired.err")" 1 \
  "an expired baseline fails"
grep -F "weak negative assertion baseline expired on 2000-01-01" "$work/expired.err" >/dev/null

assert_rc "$(run_checker "$CHECKER" "$strong" "$work/absent.txt" "$work/absent.out" "$work/absent.err")" 1 \
  "a missing baseline fails"
grep -F "absent.txt: missing; run --ratchet to record the current debt" "$work/absent.err" >/dev/null

echo "check-negative-assertions.test.sh: all assertions passed"
