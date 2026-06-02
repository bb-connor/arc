#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-rust-public-surface.py"

work="$(mktemp -d -t chio-rust-public-surface-XXXXXX)"
trap 'rm -rf "$work"' EXIT

write_member() {
  local dir="$1" name="$2" readme="${3:-README.md}"
  mkdir -p "$dir"
  mkdir -p "$dir/src"
  cat > "$dir/Cargo.toml" <<EOF
[package]
name = "$name"
description = "Synthetic public crate for gate tests"
version = "0.1.0"
edition = "2021"
publish = false
readme = "$readme"
EOF
  printf '# %s\n' "$name" > "$dir/$readme"
  printf 'pub fn marker() {}\n' > "$dir/src/lib.rs"
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
rust_registry_public_crates = []
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

unlisted_publishable="$work/unlisted-publishable"
write_workspace "$unlisted_publishable" '    "chio-cli",' '    "chio-core",'
write_member "$unlisted_publishable/crates/chio-leaky" "chio-leaky"
python3 - "$unlisted_publishable/Cargo.toml" "$unlisted_publishable/crates/chio-leaky/Cargo.toml" <<'PY'
from pathlib import Path
import sys

workspace = Path(sys.argv[1])
workspace.write_text(
    workspace.read_text(encoding="utf-8").replace(
        '    "crates/chio-core",\n]',
        '    "crates/chio-core",\n    "crates/chio-leaky",\n]',
    ),
    encoding="utf-8",
)

manifest = Path(sys.argv[2])
manifest.write_text(
    manifest.read_text(encoding="utf-8").replace("publish = false\n", ""),
    encoding="utf-8",
)
PY
assert_rc "$(run_checker "$unlisted_publishable/Cargo.toml" "$work/unlisted-publishable.out" "$work/unlisted-publishable.err")" 1 \
  "unlisted publishable crate fails"
grep -F "crates/chio-leaky/Cargo.toml must set publish = false or be listed in workspace.metadata.chio.rust_registry_public_crates." \
  "$work/unlisted-publishable.err" >/dev/null

registry_private_dep="$work/registry-private-dep"
write_workspace "$registry_private_dep" '    "chio-cli",' '    "chio-core",'
write_member "$registry_private_dep/crates/chio-harness" "chio-harness"
python3 - "$registry_private_dep/Cargo.toml" "$registry_private_dep/crates/chio-harness/Cargo.toml" <<'PY'
from pathlib import Path
import sys

workspace = Path(sys.argv[1])
workspace.write_text(
    workspace.read_text(encoding="utf-8")
    .replace(
        '    "crates/chio-core",\n]',
        '    "crates/chio-core",\n    "crates/chio-harness",\n]',
    )
    .replace(
        "rust_registry_public_crates = []\n",
        'rust_registry_public_crates = [\n    "chio-harness",\n]\n',
    ),
    encoding="utf-8",
)

manifest = Path(sys.argv[2])
manifest.write_text(
    manifest.read_text(encoding="utf-8").replace("publish = false\n", "")
    + '\n[dependencies]\nchio-core = { version = "0.1.0", path = "../chio-core" }\n',
    encoding="utf-8",
)
PY
assert_rc "$(run_checker "$registry_private_dep/Cargo.toml" "$work/registry-private-dep.out" "$work/registry-private-dep.err")" 1 \
  "registry-public crate depending on private workspace crate fails"
grep -F 'crates/chio-harness/Cargo.toml is registry-public but dependency `chio-core` points at workspace crate `chio-core`, which is not listed in workspace.metadata.chio.rust_registry_public_crates.' \
  "$work/registry-private-dep.err" >/dev/null

missing_readme="$work/missing-readme"
write_workspace "$missing_readme" '    "chio-cli",' '    "chio-core",'
rm "$missing_readme/crates/chio-core/README.md"
assert_rc "$(run_checker "$missing_readme/Cargo.toml" "$work/missing-readme.out" "$work/missing-readme.err")" 1 \
  "missing public entrypoint README fails"
grep -F "crates/chio-core/Cargo.toml points to missing README 'README.md'" \
  "$work/missing-readme.err" >/dev/null

missing_description="$work/missing-description"
write_workspace "$missing_description" '    "chio-cli",' '    "chio-core",'
python3 - "$missing_description/crates/chio-core/Cargo.toml" <<'PY'
from pathlib import Path
import sys

manifest = Path(sys.argv[1])
manifest.write_text(
    "\n".join(
        line
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if not line.startswith("description = ")
    )
    + "\n",
    encoding="utf-8",
)
PY
assert_rc "$(run_checker "$missing_description/Cargo.toml" "$work/missing-description.out" "$work/missing-description.err")" 1 \
  "missing public entrypoint description fails"
grep -F "crates/chio-core/Cargo.toml is a public entrypoint but does not declare a non-empty package description." \
  "$work/missing-description.err" >/dev/null

missing_target="$work/missing-target"
write_workspace "$missing_target" '    "chio-cli",' '    "chio-core",'
rm "$missing_target/crates/chio-core/src/lib.rs"
assert_rc "$(run_checker "$missing_target/Cargo.toml" "$work/missing-target.out" "$work/missing-target.err")" 1 \
  "missing public entrypoint implementation target fails"
grep -F "crates/chio-core/Cargo.toml is a public entrypoint but does not declare an existing lib or bin target." \
  "$work/missing-target.err" >/dev/null

local_public_marker="$work/local-public-marker"
write_workspace "$local_public_marker" '    "chio-cli",'
cat >> "$local_public_marker/crates/chio-core/Cargo.toml" <<'EOF'

[package.metadata.chio]
public_entrypoint = true
EOF
assert_rc "$(run_checker "$local_public_marker/Cargo.toml" "$work/local-public-marker.out" "$work/local-public-marker.err")" 1 \
  "package-local public entrypoint marker missing from root list fails"
grep -F "crates/chio-core/Cargo.toml declares package.metadata.chio.public_entrypoint = true but is missing from workspace.metadata.chio.rust_public_entrypoints." \
  "$work/local-public-marker.err" >/dev/null

echo "check-rust-public-surface.test.sh: all assertions passed"
