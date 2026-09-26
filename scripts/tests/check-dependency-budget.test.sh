#!/usr/bin/env bash
# Prove the dependency-budget gate fails on a denied package, a graph above its
# ceiling and a pending entry that has left the graph, and passes on a graph
# that matches its budget. Fixtures are path-only workspaces, so no network is
# needed; the ceiling case also runs against the real tree with the committed
# ceiling lowered by one.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-dependency-budget.py"

work="$(mktemp -d -t chio-dependency-budget-XXXXXX)"
trap 'rm -rf "$work"' EXIT

PENDING=(tokio hyper hyper-util reqwest tower-http rustls-webpki aws-lc-rs regex fancy-regex serde_json tracing)

# write_workspace <root> <extra helper dependency or ""> <pending package to omit or "">
write_workspace() {
  local root="$1" extra="$2" omit="$3"
  local members=("crates/security/chio-cage" "crates/security/chio-secret-broker")
  mkdir -p "$root/crates/security/chio-cage/src" "$root/crates/security/chio-secret-broker/src"
  : > "$root/crates/security/chio-cage/src/lib.rs"
  : > "$root/crates/security/chio-secret-broker/src/lib.rs"
  {
    echo '[package]'
    echo 'name = "chio-cage"'
    echo 'version = "0.1.0"'
    echo 'edition = "2021"'
    echo
    echo '[features]'
    echo 'real-linux-enforcement = []'
    echo
    echo '[dependencies]'
  } > "$root/crates/security/chio-cage/Cargo.toml"
  for name in "${PENDING[@]}" $extra; do
    if [[ "$name" == "$omit" ]]; then continue; fi
    mkdir -p "$root/vendor/$name/src"
    : > "$root/vendor/$name/src/lib.rs"
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n' "$name" > "$root/vendor/$name/Cargo.toml"
    printf '%s = { path = "../../../vendor/%s" }\n' "$name" "$name" >> "$root/crates/security/chio-cage/Cargo.toml"
    members+=("vendor/$name")
  done
  {
    echo '[package]'
    echo 'name = "chio-secret-broker"'
    echo 'version = "0.1.0"'
    echo 'edition = "2021"'
    echo
    echo '[dependencies]'
    echo 'tokio = { path = "../../../vendor/tokio" }'
  } > "$root/crates/security/chio-secret-broker/Cargo.toml"
  {
    echo '[workspace]'
    echo 'resolver = "2"'
    printf 'members = ['
    local first=1
    for member in "${members[@]}"; do
      if [[ $first -eq 0 ]]; then printf ', '; fi
      printf '"%s"' "$member"
      first=0
    done
    echo ']'
  } > "$root/Cargo.toml"
  (cd "$root" && cargo generate-lockfile --offline --quiet)
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
write_workspace "$compliant" "" ""
assert_rc "$(run_checker "$CHECKER" "$compliant" "$work/compliant.out" "$work/compliant.err")" 0 \
  "a graph under its ceiling with every pending package present and nothing denied passes"
grep -F "chio-cage (chio-cage-init) on x86_64-unknown-linux-musl: 12 packages, ceiling 260" "$work/compliant.out" >/dev/null
grep -F "0 denied, 11 pending" "$work/compliant.out" >/dev/null
grep -F "chio-secret-broker (chio-secret-brokerd) on x86_64-unknown-linux-musl: 2 packages, ceiling 478" "$work/compliant.out" >/dev/null

denied="$work/denied"
write_workspace "$denied" "openssl" ""
assert_rc "$(run_checker "$CHECKER" "$denied" "$work/denied.out" "$work/denied.err")" 1 \
  "a denied package in the helper graph fails and names the manifest line"
grep -F 'crates/security/chio-cage/Cargo.toml:21 chio-cage carries denied package openssl v0.1.0: a second TLS and crypto stack beside aws-lc-rs' \
  "$work/denied.err" >/dev/null

carried="$work/carried"
write_workspace "$carried" "" ""
mkdir -p "$carried/vendor/rusqlite/src"
: > "$carried/vendor/rusqlite/src/lib.rs"
printf '[package]\nname = "rusqlite"\nversion = "0.1.0"\nedition = "2021"\n' > "$carried/vendor/rusqlite/Cargo.toml"
printf '\n[dependencies]\nrusqlite = { path = "../rusqlite" }\n' >> "$carried/vendor/tokio/Cargo.toml"
sed -i 's|"vendor/tracing"\]|"vendor/tracing", "vendor/rusqlite"]|' "$carried/Cargo.toml"
(cd "$carried" && cargo generate-lockfile --offline --quiet)
assert_rc "$(run_checker "$CHECKER" "$carried" "$work/carried.out" "$work/carried.err")" 1 \
  "a denied package carried transitively names the direct dependency that carries it"
grep -F 'crates/security/chio-cage/Cargo.toml:10 chio-cage carries denied package rusqlite v0.1.0 through tokio: the helper owns no database' \
  "$work/carried.err" >/dev/null

stale="$work/stale"
write_workspace "$stale" "" ""
sed -i '/^tokio = /d' "$stale/crates/security/chio-cage/Cargo.toml"
(cd "$stale" && cargo generate-lockfile --offline --quiet)
assert_rc "$(run_checker "$CHECKER" "$stale" "$work/stale.out" "$work/stale.err")" 1 \
  "a pending package that has left the helper graph fails until it is promoted to the deny list"
grep -F 'crates/security/chio-cage/Cargo.toml:9 pending entry tokio is no longer in the chio-cage graph; promote it to the deny list' \
  "$work/stale.err" >/dev/null

over="$work/over"
write_workspace "$over" "" ""
over_checker="$work/over-check-dependency-budget.py"
sed -E 's/ceiling=260,/ceiling=11,/' "$CHECKER" > "$over_checker"
assert_rc "$(run_checker "$over_checker" "$over" "$work/over.out" "$work/over.err")" 1 \
  "a graph one package above its ceiling fails"
grep -F 'crates/security/chio-cage/Cargo.toml:9 chio-cage has 12 packages in its x86_64-unknown-linux-musl graph, ceiling 11' \
  "$work/over.err" >/dev/null

measured="$(python3 "$CHECKER" --root "$REPO_ROOT" | sed -nE 's/^chio-cage .*: ([0-9]+) packages, ceiling ([0-9]+) .*/\1 \2/p')"
count="${measured% *}"
ceiling="${measured#* }"
if [[ "$count" != "$ceiling" ]]; then
  echo "FAIL: the committed ceiling ($ceiling) is not the measured count ($count); re-measure and record the reason" >&2
  exit 1
fi
lowered_checker="$work/lowered-check-dependency-budget.py"
sed -E "s/ceiling=${ceiling},/ceiling=$((ceiling - 1)),/" "$CHECKER" > "$lowered_checker"
assert_rc "$(run_checker "$lowered_checker" "$REPO_ROOT" "$work/lowered.out" "$work/lowered.err")" 1 \
  "the real helper graph fails against a ceiling one below its measured count ($count)"
grep -F "chio-cage has ${count} packages in its x86_64-unknown-linux-musl graph, ceiling $((ceiling - 1))" \
  "$work/lowered.err" >/dev/null

expired="$work/expired"
write_workspace "$expired" "" ""
expired_checker="$work/expired-check-dependency-budget.py"
sed -E 's/"20[0-9]{2}-[0-9]{2}-[0-9]{2}",$/"2000-01-01",/' "$CHECKER" > "$expired_checker"
assert_rc "$(run_checker "$expired_checker" "$expired" "$work/expired.out" "$work/expired.err")" 1 \
  "an expired pending entry fails"
grep -F "pending entry tokio expired on 2000-01-01" "$work/expired.err" >/dev/null

echo "check-dependency-budget.test.sh: all assertions passed"
