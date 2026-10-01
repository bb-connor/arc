#!/usr/bin/env bash
# Prove the release-overflow gate can fail, in both ways it is meant to.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-release-overflow.sh"

work="$(mktemp -d -t chio-release-overflow-XXXXXX)"
trap 'rm -rf "$work"' EXIT

assert_rc() {
  local got="$1" want="$2" label="$3"
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $label: got rc=$got, want rc=$want" >&2
    exit 1
  fi
  echo "ok: $label (rc=$got)"
}

run() {
  local stdout="$1" stderr="$2"
  shift 2
  local rc=0
  bash "$CHECKER" "$@" >"$stdout" 2>"$stderr" || rc=$?
  echo "$rc"
}

assert_rc "$(run "$work/shipping.out" "$work/shipping.err")" 0 \
  "the shipping release profile traps u64 subtraction below zero"
grep -F 'traps u64 subtraction below zero' "$work/shipping.out" >/dev/null

# A manifest that leaves overflow-checks at Cargo's release default.
sed -E '/^overflow-checks[[:space:]]*=[[:space:]]*true$/d' "$REPO_ROOT/Cargo.toml" \
  > "$work/unchecked-Cargo.toml"
assert_rc "$(run "$work/manifest.out" "$work/manifest.err" --manifest "$work/unchecked-Cargo.toml")" 1 \
  "a manifest that drops overflow-checks fails"
grep -F 'does not set overflow-checks = true' "$work/manifest.err" >/dev/null

# A build that drops the check the manifest asks for. The probe must then reach
# its print, which is what the gate refuses.
rc=0
RUSTFLAGS="${RUSTFLAGS:-} -C overflow-checks=off" \
  bash "$CHECKER" >"$work/unchecked.out" 2>"$work/unchecked.err" || rc=$?
assert_rc "$rc" 1 "a release build without the check fails"
grep -F 'wrapped instead of trapping' "$work/unchecked.err" >/dev/null
grep -F 'wrapped: 0 - 1 = 18446744073709551615' "$work/unchecked.err" >/dev/null

echo "check-release-overflow.test.sh: all assertions passed"
