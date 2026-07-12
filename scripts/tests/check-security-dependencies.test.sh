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

path, *edges = sys.argv[1:]
names = {
    name
    for edge in edges
    for name in edge.split("=", maxsplit=1)
}
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
  write_metadata "$metadata" "$source=$destination"
  assert_rc "$(run_checker "$metadata" "$metadata.out" "$metadata.err")" 1 "$label"
  grep -F "$source reaches forbidden dependency $destination" "$metadata.err" >/dev/null
}

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

transitive="$work/transitive.json"
write_metadata "$transitive" \
  'chio-kernel=chio-core-types' \
  'chio-core-types=chio-flow'
assert_rc "$(run_checker "$transitive" "$work/transitive.out" "$work/transitive.err")" 1 \
  "transitive reachability is rejected"
grep -F 'chio-kernel reaches forbidden dependency chio-flow' "$work/transitive.err" >/dev/null

printf 'check-security-dependencies.test.sh: all assertions passed\n'
