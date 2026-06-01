#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-rust-public-surface.py"

work="$(mktemp -d -t chio-rust-public-surface-XXXXXX)"
trap 'rm -rf "$work"' EXIT

write_member() {
  local dir="$1" name="$2" readme="${3:-README.md}"
  mkdir -p "$dir"
  cat > "$dir/Cargo.toml" <<EOF
[package]
name = "$name"
version = "0.1.0"
edition = "2021"
publish = false
readme = "$readme"
EOF
  printf '# %s\n' "$name" > "$dir/$readme"
}

write_workspace() {
  local root="$1"
  shift
  mkdir -p "$root/crates"
  write_member "$root/crates/chio-cli" "chio-cli"
  write_member "$root/crates/chio-core" "chio-core"
  cat > "$root/Cargo.toml" <<EOF
[workspace]
members = [
    "crates/chio-cli",
    "crates/chio-core",
]

[workspace.metadata.chio]
rust_public_entrypoints = [
$*
]
EOF
}

run_checker() {
  local manifest="$1" stdout="$2" stderr="$3"
  local rc=0
  python3 "$CHECKER" --workspace-manifest "$manifest" >"$stdout" 2>"$stderr" || rc=$?
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

good="$work/good"
write_workspace "$good" '    "chio-cli",' '    "chio-core",'
assert_rc "$(run_checker "$good/Cargo.toml" "$work/good.out" "$work/good.err")" 0 \
  "valid synthetic workspace passes"

duplicate="$work/duplicate"
write_workspace "$duplicate" '    "chio-cli",' '    "chio-core",' '    "chio-core",'
assert_rc "$(run_checker "$duplicate/Cargo.toml" "$work/duplicate.out" "$work/duplicate.err")" 1 \
  "duplicate public entrypoint fails"
grep -F "duplicate rust_public_entrypoints entries: chio-core" "$work/duplicate.err" >/dev/null

unsorted="$work/unsorted"
write_workspace "$unsorted" '    "chio-core",' '    "chio-cli",'
assert_rc "$(run_checker "$unsorted/Cargo.toml" "$work/unsorted.out" "$work/unsorted.err")" 1 \
  "unsorted public entrypoints fail"
grep -F "rust_public_entrypoints must be sorted lexicographically" "$work/unsorted.err" >/dev/null

unknown="$work/unknown"
write_workspace "$unknown" '    "chio-cli",' '    "chio-core",' '    "chio-missing",'
assert_rc "$(run_checker "$unknown/Cargo.toml" "$work/unknown.out" "$work/unknown.err")" 1 \
  "unknown public entrypoint fails"
grep -F "references unknown crates: chio-missing" "$work/unknown.err" >/dev/null

missing_readme="$work/missing-readme"
write_workspace "$missing_readme" '    "chio-cli",' '    "chio-core",'
rm "$missing_readme/crates/chio-core/README.md"
assert_rc "$(run_checker "$missing_readme/Cargo.toml" "$work/missing-readme.out" "$work/missing-readme.err")" 1 \
  "missing public entrypoint README fails"
grep -F "crates/chio-core/Cargo.toml points to missing README 'README.md'" \
  "$work/missing-readme.err" >/dev/null

echo "check-rust-public-surface.test.sh: all assertions passed"
