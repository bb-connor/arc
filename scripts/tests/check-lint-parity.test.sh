#!/usr/bin/env bash
# Prove the lint-parity gate fails when a workspace lint is not mirrored into a
# copying manifest, in either table, and does not fire on the equivalent
# spellings of the same level.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-lint-parity.py"
ALLOWLISTED="examples/hello-a2a/Cargo.toml"

work="$(mktemp -d -t chio-lint-parity-XXXXXX)"
trap 'rm -rf "$work"' EXIT

# A bare workspace: the root sets one Rust lint and two Clippy lints, and every
# case adds member crates under it.
init_workspace() {
  local root="$1"
  shift
  mkdir -p "$root"
  {
    echo '[workspace]'
    echo 'resolver = "2"'
    printf 'members = ['
    local first=1
    for member in "$@"; do
      if [[ $first -eq 0 ]]; then printf ', '; fi
      printf '"%s"' "$member"
      first=0
    done
    echo ']'
    echo
    echo '[workspace.lints.rust]'
    echo 'unsafe_op_in_unsafe_fn = "deny"'
    echo
    echo '[workspace.lints.clippy]'
    echo 'unwrap_used = "deny"'
    echo 'expect_used = "deny"'
  } > "$root/Cargo.toml"
}

# write_crate <root> <relative dir> <package name>; the lints tables come on stdin.
write_crate() {
  local root="$1" dir="$2" name="$3"
  mkdir -p "$root/$dir/src"
  : > "$root/$dir/src/lib.rs"
  {
    echo '[package]'
    echo "name = \"$name\""
    echo 'version = "0.1.0"'
    echo 'edition = "2021"'
    echo
    cat
  } > "$root/$dir/Cargo.toml"
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

inherit_lints() {
  cat <<'EOF'
[lints]
workspace = true
EOF
}

full_mirror() {
  cat <<'EOF'
[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"

[lints.rust]
unsafe_op_in_unsafe_fn = "deny"
unexpected_cfgs = { level = "warn", check-cfg = ["cfg(kani)"] }
EOF
}

compliant="$work/compliant"
init_workspace "$compliant" crates/alpha crates/beta
inherit_lints | write_crate "$compliant" crates/alpha alpha
full_mirror | write_crate "$compliant" crates/beta beta
assert_rc "$(run_checker "$CHECKER" "$compliant" "$work/compliant.out" "$work/compliant.err")" 0 \
  "an inheriting crate and a complete mirror with its own extra lint both pass"
grep -F "2 member manifests, 1 inherit, 1 mirror, 0 unreached; 3 workspace lints (1 rust, 2 clippy)" \
  "$work/compliant.out" >/dev/null

rust_unmirrored="$work/rust-unmirrored"
init_workspace "$rust_unmirrored" crates/beta
write_crate "$rust_unmirrored" crates/beta beta <<'EOF'
[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"

[lints.rust]
unexpected_cfgs = { level = "warn", check-cfg = ["cfg(kani)"] }
EOF
assert_rc "$(run_checker "$CHECKER" "$rust_unmirrored" "$work/rust-unmirrored.out" "$work/rust-unmirrored.err")" 1 \
  "a lint added to the workspace rust table and not mirrored fails"
grep -F 'crates/beta/Cargo.toml:10 [lints.rust] lacks unsafe_op_in_unsafe_fn; the workspace sets it to "deny"' \
  "$work/rust-unmirrored.err" >/dev/null

rust_table_absent="$work/rust-table-absent"
init_workspace "$rust_table_absent" crates/beta
write_crate "$rust_table_absent" crates/beta beta <<'EOF'
[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
EOF
assert_rc "$(run_checker "$CHECKER" "$rust_table_absent" "$work/rust-table-absent.out" "$work/rust-table-absent.err")" 1 \
  "a mirror with no rust table at all fails once the workspace rust table is populated"
grep -F 'crates/beta/Cargo.toml:6 [lints.rust] is absent; the workspace table sets unsafe_op_in_unsafe_fn' \
  "$work/rust-table-absent.err" >/dev/null

clippy_unmirrored="$work/clippy-unmirrored"
init_workspace "$clippy_unmirrored" crates/beta
write_crate "$clippy_unmirrored" crates/beta beta <<'EOF'
[lints.clippy]
unwrap_used = "deny"

[lints.rust]
unsafe_op_in_unsafe_fn = "deny"
EOF
assert_rc "$(run_checker "$CHECKER" "$clippy_unmirrored" "$work/clippy-unmirrored.out" "$work/clippy-unmirrored.err")" 1 \
  "a clippy lint missing from the mirror fails"
grep -F 'crates/beta/Cargo.toml:6 [lints.clippy] lacks expect_used' "$work/clippy-unmirrored.err" >/dev/null

wrong_level="$work/wrong-level"
init_workspace "$wrong_level" crates/beta
write_crate "$wrong_level" crates/beta beta <<'EOF'
[lints.clippy]
unwrap_used = "warn"
expect_used = "deny"

[lints.rust]
unsafe_op_in_unsafe_fn = "deny"
EOF
assert_rc "$(run_checker "$CHECKER" "$wrong_level" "$work/wrong-level.out" "$work/wrong-level.err")" 1 \
  "a mirrored lint at a weaker level fails and names the line"
grep -F 'crates/beta/Cargo.toml:7 [lints.clippy] unwrap_used = "warn"; the workspace sets "deny"' \
  "$work/wrong-level.err" >/dev/null

table_spelling="$work/table-spelling"
init_workspace "$table_spelling" crates/beta
write_crate "$table_spelling" crates/beta beta <<'EOF'
[lints.clippy]
unwrap_used = { level = "deny" }
expect_used = { level = "deny", priority = 0 }

[lints.rust]
unsafe_op_in_unsafe_fn = { level = "deny" }
EOF
assert_rc "$(run_checker "$CHECKER" "$table_spelling" "$work/table-spelling.out" "$work/table-spelling.err")" 0 \
  "the table spelling of the same level is the same level"

priority_differs="$work/priority-differs"
init_workspace "$priority_differs" crates/beta
write_crate "$priority_differs" crates/beta beta <<'EOF'
[lints.clippy]
unwrap_used = { level = "deny", priority = 1 }
expect_used = "deny"

[lints.rust]
unsafe_op_in_unsafe_fn = "deny"
EOF
assert_rc "$(run_checker "$CHECKER" "$priority_differs" "$work/priority-differs.out" "$work/priority-differs.err")" 1 \
  "a mirrored lint with a different priority fails"
grep -F 'unwrap_used = { level = "deny", priority = 1 }; the workspace sets "deny"' \
  "$work/priority-differs.err" >/dev/null

unreached="$work/unreached"
init_workspace "$unreached" crates/gamma
write_crate "$unreached" crates/gamma gamma </dev/null
assert_rc "$(run_checker "$CHECKER" "$unreached" "$work/unreached.out" "$work/unreached.err")" 1 \
  "a member with no lints table fails"
grep -F 'crates/gamma/Cargo.toml:1 no [lints] table; the workspace policy does not reach this crate' \
  "$work/unreached.err" >/dev/null

allowlisted="$work/allowlisted"
init_workspace "$allowlisted" "$(dirname "$ALLOWLISTED")"
write_crate "$allowlisted" "$(dirname "$ALLOWLISTED")" hello-a2a </dev/null
assert_rc "$(run_checker "$CHECKER" "$allowlisted" "$work/allowlisted.out" "$work/allowlisted.err")" 0 \
  "a recorded unreached manifest passes while the entry is live"
grep -F "1 member manifests, 0 inherit, 0 mirror, 1 unreached" "$work/allowlisted.out" >/dev/null

stale_debt="$work/stale-debt"
init_workspace "$stale_debt" "$(dirname "$ALLOWLISTED")"
inherit_lints | write_crate "$stale_debt" "$(dirname "$ALLOWLISTED")" hello-a2a
assert_rc "$(run_checker "$CHECKER" "$stale_debt" "$work/stale-debt.out" "$work/stale-debt.err")" 1 \
  "a debt entry whose manifest now inherits fails until it is removed"
grep -F "$ALLOWLISTED: debt entry no longer excuses a missing [lints] table" "$work/stale-debt.err" >/dev/null

expired="$work/expired"
init_workspace "$expired" crates/alpha
inherit_lints | write_crate "$expired" crates/alpha alpha
expired_checker="$work/expired-check-lint-parity.py"
sed -E 's/"20[0-9]{2}-[0-9]{2}-[0-9]{2}"/"2000-01-01"/g' "$CHECKER" > "$expired_checker"
assert_rc "$(run_checker "$expired_checker" "$expired" "$work/expired.out" "$work/expired.err")" 1 \
  "an expired debt entry fails"
grep -F "debt entry expired on 2000-01-01" "$work/expired.err" >/dev/null

echo "check-lint-parity.test.sh: all assertions passed"
