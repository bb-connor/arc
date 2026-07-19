#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-security-dependencies.sh"

work="$(mktemp -d -t chio-security-dependencies-XXXXXX)"
trap 'rm -rf "$work"' EXIT

write_metadata() {
  local path="$1"
  shift
  python3 - "$path" "$@" <<'PY'
import json
import sys

path, *entries = sys.argv[1:]
edges = [entry for entry in entries if "=" in entry]
names = {entry for entry in entries if "=" not in entry}
names.update(
    name
    for edge in edges
    for name in edge.split("=", maxsplit=1)
)
packages = [{"name": name, "id": f"path+file:///{name}#0.1.0"} for name in sorted(names)]
nodes = []
for name in sorted(names):
    package_id = f"path+file:///{name}#0.1.0"
    dependencies = []
    for edge in edges:
        source, destination = edge.split("=", maxsplit=1)
        if source == name:
            dependencies.append({"pkg": f"path+file:///{destination}#0.1.0"})
    nodes.append({"id": package_id, "deps": dependencies})
with open(path, "w", encoding="utf-8") as output:
    json.dump({"packages": packages, "resolve": {"nodes": nodes}}, output)
PY
}

required_packages=(
  chio-security-types
  chio-flow
  chio-security-kernel
  chio-decoy
  chio-quarantine
)

run_checker() {
  local metadata="$1" stdout="$2" stderr="$3"
  local rc=0
  CHIO_SECURITY_METADATA_FILE="$metadata" "$CHECKER" >"$stdout" 2>"$stderr" || rc=$?
  printf '%s\n' "$rc"
}

assert_rc() {
  local got="$1" want="$2" label="$3"
  if [[ "$got" != "$want" ]]; then
    printf 'FAIL: %s: got rc=%s, want rc=%s\n' "$label" "$got" "$want" >&2
    exit 1
  fi
  printf 'ok: %s (rc=%s)\n' "$label" "$got"
}

assert_rejected_edge() {
  local source="$1" destination="$2" label="$3"
  local metadata="$work/${source}-${destination}.json"
  write_metadata "$metadata" "${required_packages[@]}" "$source=$destination"
  assert_rc "$(run_checker "$metadata" "$metadata.out" "$metadata.err")" 1 "$label"
  grep -F "$source reaches forbidden dependency $destination" "$metadata.err" >/dev/null
}

zero_inventory="$work/zero-inventory.json"
write_metadata "$zero_inventory"
assert_rc "$(run_checker "$zero_inventory" "$work/zero-inventory.out" "$work/zero-inventory.err")" 1 \
  "an empty security package inventory fails"
for package_name in "${required_packages[@]}"; do
  grep -F "required security package is missing: $package_name" \
    "$work/zero-inventory.err" >/dev/null
done

omitted_inventory="$work/omitted-inventory.json"
write_metadata "$omitted_inventory" \
  chio-security-types \
  chio-flow \
  chio-security-kernel \
  chio-decoy
assert_rc "$(run_checker "$omitted_inventory" "$work/omitted-inventory.out" "$work/omitted-inventory.err")" 1 \
  "an inventory omitting one required security package fails"
grep -F 'required security package is missing: chio-quarantine' \
  "$work/omitted-inventory.err" >/dev/null

valid="$work/valid.json"
write_metadata "$valid" \
  'chio-core-types=chio-security-types' \
  'chio-flow=chio-core-types' \
  'chio-decoy=chio-core-types' \
  'chio-quarantine=chio-core-types' \
  'chio-security-kernel=chio-kernel' \
  'chio-security-kernel=chio-flow' \
  'chio-security-kernel=chio-decoy' \
  'chio-kernel=chio-core-types' \
  'chio-kernel=chio-did' \
  'chio-kernel=chio-store-sqlite'
assert_rc "$(run_checker "$valid" "$work/valid.out" "$work/valid.err")" 0 \
  "the required dependency direction passes"
grep -F 'security dependency check passed' "$work/valid.out" >/dev/null

assert_rejected_edge chio-kernel chio-flow \
  "kernel cannot reach a security engine"
assert_rejected_edge chio-guards chio-decoy \
  "guards cannot reach a security engine"
assert_rejected_edge chio-flow chio-kernel \
  "a pure flow engine cannot reach kernel"
assert_rejected_edge chio-decoy chio-guards \
  "a pure deception engine cannot reach guards"
assert_rejected_edge chio-quarantine chio-control-plane \
  "a pure containment engine cannot reach platform"
assert_rejected_edge chio-security-kernel chio-guards \
  "the kernel adapter cannot reach guards"
assert_rejected_edge chio-security-kernel chio-did \
  "the kernel adapter cannot reach trust"
assert_rejected_edge chio-security-kernel chio-store-sqlite \
  "the kernel adapter cannot reach platform"
assert_rejected_edge chio-security-types chio-core-types \
  "portable security types cannot reach Chio crates"
assert_rejected_edge chio-core-types chio-flow \
  "core types cannot reach a security engine"
assert_rejected_edge chio-core-types chio-kernel \
  "core types cannot reach kernel"
assert_rejected_edge chio-core-types chio-guards \
  "core types cannot reach guards"
assert_rejected_edge chio-core-types chio-store-sqlite \
  "core types cannot reach platform"
assert_rejected_edge chio-quarantine chio-did \
  "containment cannot reach trust"
assert_rejected_edge chio-store-sqlite chio-flow \
  "the SQLite store cannot reach a security engine"
assert_rejected_edge chio-store-sqlite chio-security-kernel \
  "the SQLite store cannot reach the security kernel adapter"

transitive="$work/transitive.json"
write_metadata "$transitive" \
  "${required_packages[@]}" \
  'chio-kernel=chio-core-types' \
  'chio-core-types=chio-flow'
assert_rc "$(run_checker "$transitive" "$work/transitive.out" "$work/transitive.err")" 1 \
  "transitive reachability is rejected"
grep -F 'chio-kernel reaches forbidden dependency chio-flow' "$work/transitive.err" >/dev/null

core_transitive="$work/core-transitive.json"
write_metadata "$core_transitive" \
  "${required_packages[@]}" \
  'chio-core-types=portable-helper' \
  'portable-helper=chio-control-plane'
assert_rc "$(run_checker "$core_transitive" "$work/core-transitive.out" "$work/core-transitive.err")" 1 \
  "core-types transitive platform reachability is rejected"
grep -F 'chio-core-types reaches forbidden dependency chio-control-plane' \
  "$work/core-transitive.err" >/dev/null

store_transitive="$work/store-transitive.json"
write_metadata "$store_transitive" \
  "${required_packages[@]}" \
  'chio-store-sqlite=store-helper' \
  'store-helper=chio-decoy'
assert_rc "$(run_checker "$store_transitive" "$work/store-transitive.out" "$work/store-transitive.err")" 1 \
  "the SQLite store cannot transitively reach a security engine"
grep -F 'chio-store-sqlite reaches forbidden dependency chio-decoy' \
  "$work/store-transitive.err" >/dev/null

printf 'check-security-dependencies.test.sh: all assertions passed\n'
