#!/usr/bin/env bash
# Prove the Miri crate-list runner refuses a list that hides a third exclusion
# reason, an unreached crate, or an unpinned toolchain, and prints the exact
# plan for a valid list. Every case uses --list, so nothing is compiled.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNNER="$REPO_ROOT/scripts/run-miri-crates.sh"

work="$(mktemp -d -t chio-miri-crates-XXXXXX)"
trap 'rm -rf "$work"' EXIT

run_runner() {
  local config="$1" stdout="$2" stderr="$3"
  local rc=0
  bash "$RUNNER" --config "$config" --list >"$stdout" 2>"$stderr" || rc=$?
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

valid="$work/valid.toml"
cat > "$valid" <<'EOF'
toolchain = "nightly-2026-02-07"
miriflags = "-Zmiri-disable-isolation"
timeout_seconds = 600

[[crate]]
name = "chio-example-sdk"
unsafe_sites = 9
reached = 8

[[crate]]
name = "chio-example-ipc"
unsafe_sites = 7
reached = 5
[[crate.skip]]
test = "credentials::tests::seals_require_memfd"
reason = "syscall: memfd_create is not implemented by Miri"
[[crate.skip]]
test = "tests::listener_checks_mode"
reason = "calls into C: chmod through libc"

[[excluded]]
name = "chio-example-store"
reason = "calls into C: every unit test opens SQLite through rusqlite"

[[ineligible]]
name = "chio-example-macros"
reason = "no unit test reaches its one unsafe site"
EOF
assert_rc "$(run_runner "$valid" "$work/valid.out" "$work/valid.err")" 0 \
  "a list with permitted reasons validates and prints its plan"
grep -F "miri crate list: 2 crates, 2 skipped tests, 1 excluded, 1 ineligible; toolchain nightly-2026-02-07" "$work/valid.out" >/dev/null
grep -F "  cargo +nightly-2026-02-07 miri test -p chio-example-sdk --lib" "$work/valid.out" >/dev/null
grep -F "  cargo +nightly-2026-02-07 miri test -p chio-example-ipc --lib -- --skip credentials::tests::seals_require_memfd --skip tests::listener_checks_mode" "$work/valid.out" >/dev/null

third_reason="$work/third-reason.toml"
sed 's/reason = "syscall: memfd_create is not implemented by Miri"/reason = "flaky under Miri"/' "$valid" > "$third_reason"
assert_rc "$(run_runner "$third_reason" "$work/third-reason.out" "$work/third-reason.err")" 1 \
  "a skip whose reason is neither a C call nor a syscall is refused"
grep -F "skip credentials::tests::seals_require_memfd: reason must start with one of 'calls into C:', 'syscall:'" "$work/third-reason.err" >/dev/null

excluded_reason="$work/excluded-reason.toml"
sed 's/reason = "calls into C: every unit test opens SQLite through rusqlite"/reason = "too slow"/' "$valid" > "$excluded_reason"
assert_rc "$(run_runner "$excluded_reason" "$work/excluded-reason.out" "$work/excluded-reason.err")" 1 \
  "an excluded crate with a third reason is refused"
grep -F "excluded chio-example-store: reason must start with" "$work/excluded-reason.err" >/dev/null

unreached="$work/unreached.toml"
sed 's/^reached = 8$/reached = 0/' "$valid" > "$unreached"
assert_rc "$(run_runner "$unreached" "$work/unreached.out" "$work/unreached.err")" 1 \
  "a listed crate whose unsafe code no test reaches is refused"
grep -F "chio-example-sdk: no unit test reaches its unsafe code; it does not belong on the list" "$work/unreached.err" >/dev/null

unpinned="$work/unpinned.toml"
sed 's/^toolchain = "nightly-2026-02-07"$/toolchain = "nightly"/' "$valid" > "$unpinned"
assert_rc "$(run_runner "$unpinned" "$work/unpinned.out" "$work/unpinned.err")" 1 \
  "a toolchain that is not pinned by date is refused"
grep -F "toolchain must be a nightly pinned by date, got 'nightly'" "$work/unpinned.err" >/dev/null

twice="$work/twice.toml"
{ cat "$valid"; printf '\n[[excluded]]\nname = "chio-example-sdk"\nreason = "syscall: also here"\n'; } > "$twice"
assert_rc "$(run_runner "$twice" "$work/twice.out" "$work/twice.err")" 1 \
  "a crate that is both listed and excluded is refused"
grep -F "chio-example-sdk appears twice (crate and excluded)" "$work/twice.err" >/dev/null

unqualified="$work/unqualified.toml"
sed 's/test = "tests::listener_checks_mode"/test = "listener_checks_mode"/' "$valid" > "$unqualified"
assert_rc "$(run_runner "$unqualified" "$work/unqualified.out" "$work/unqualified.err")" 1 \
  "a skip that is not module-qualified is refused, since a bare name would skip every test called that"
grep -F "skip needs a module-qualified test name" "$work/unqualified.err" >/dev/null

echo "run-miri-crates.test.sh: all assertions passed"
