#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
metadata="${CHIO_SECURITY_METADATA_FILE:-}"
temporary_metadata=""

if [[ -z "$metadata" ]]; then
  temporary_metadata="$(mktemp -t chio-security-metadata-XXXXXX.json)"
  trap 'rm -f "$temporary_metadata"' EXIT
  cargo metadata --manifest-path "$ROOT/Cargo.toml" --format-version 1 > "$temporary_metadata"
  metadata="$temporary_metadata"
fi

python3 - "$metadata" <<'PY'
import json
import sys
from collections import defaultdict
from pathlib import Path

metadata_path = Path(sys.argv[1])
with metadata_path.open(encoding="utf-8") as source:
    metadata = json.load(source)

packages_by_id = {package["id"]: package for package in metadata.get("packages", [])}
ids_by_name = defaultdict(set)
for package_id, package in packages_by_id.items():
    ids_by_name[package["name"]].add(package_id)

edges = defaultdict(set)
resolve = metadata.get("resolve") or {}
for node in resolve.get("nodes", []):
    for dependency in node.get("deps", []):
        dep_kinds = dependency.get("dep_kinds")
        if dep_kinds and all(kind.get("kind") == "dev" for kind in dep_kinds):
            continue
        edges[node["id"]].add(dependency["pkg"])

def package_group(package_id):
    package = packages_by_id.get(package_id, {})
    manifest = package.get("manifest_path", "").replace("\\", "/")
    name = package.get("name", "")
    if "/crates/platform/" in manifest or name in {
        "chio-control-plane",
        "chio-store-sqlite",
        "chio-manifest",
    }:
        return "platform"
    if "/crates/trust/" in manifest or name == "chio-did":
        return "trust"
    if "/crates/guards/" in manifest or name in {"chio-guards", "chio-policy"}:
        return "guards"
    if "/crates/kernel/" in manifest or name == "chio-kernel":
        return "kernel"
    return "other"

def reachable(source_id):
    seen = set()
    pending = list(edges[source_id])
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        pending.extend(edges[package_id] - seen)
    return seen

security_engines = {
    "chio-flow",
    "chio-security-kernel",
    "chio-decoy",
    "chio-quarantine",
}
enterprise_engines = {
    "chio-keyring",
    "chio-secret-broker",
    "chio-cage",
}
enterprise_boundary_sources = {"chio-kernel", "chio-guards"}
required_security_packages = security_engines | enterprise_engines | {"chio-security-types"}
pure_engines = {"chio-flow", "chio-decoy", "chio-quarantine"}
violations = set()

for package_name in sorted(required_security_packages):
    package_ids = ids_by_name.get(package_name, set())
    if not package_ids:
        violations.add(f"required security package is missing: {package_name}")
    elif len(package_ids) != 1:
        violations.add(
            f"required security package is not unique: {package_name} ({len(package_ids)} copies)"
        )

for source_id, source_package in packages_by_id.items():
    source_name = source_package["name"]
    dependencies = reachable(source_id)
    for destination_id in dependencies:
        destination = packages_by_id.get(destination_id)
        if destination is None:
            continue
        destination_name = destination["name"]
        destination_group = package_group(destination_id)
        forbidden = False
        if package_group(source_id) in {"kernel", "guards"}:
            forbidden = destination_name in security_engines
        if source_name in enterprise_boundary_sources:
            forbidden = forbidden or destination_name in enterprise_engines
        if source_name == "chio-core-types":
            forbidden = forbidden or destination_name in security_engines
            forbidden = forbidden or destination_group in {
                "kernel",
                "guards",
                "platform",
            }
        if source_name in pure_engines:
            forbidden = forbidden or destination_group in {"kernel", "guards", "platform"}
        if source_name == "chio-quarantine":
            forbidden = forbidden or destination_group == "trust"
        if source_name == "chio-security-kernel" and destination_id in edges[source_id]:
            forbidden = forbidden or destination_group in {"guards", "trust", "platform"}
        if source_name == "chio-security-types" and destination_id in edges[source_id]:
            forbidden = forbidden or destination_name.startswith("chio-")
        if source_name == "chio-store-sqlite":
            forbidden = forbidden or destination_name in security_engines
            forbidden = forbidden or destination_name == "chio-security-kernel"
        if forbidden:
            violations.add(
                f"{source_name} reaches forbidden dependency {destination_name}"
            )

if violations:
    for violation in sorted(violations):
        print(violation, file=sys.stderr)
    raise SystemExit(1)

print("security dependency check passed")
PY
