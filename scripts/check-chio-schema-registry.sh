#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGISTRY="$ROOT/spec/schemas/registry.json"

python3 - "$REGISTRY" <<'PY'
import json
import hashlib
import pathlib
import re
import subprocess
import sys

registry_path = pathlib.Path(sys.argv[1])
root = registry_path.parent.parent.parent
manifest_path = registry_path.parent / "MANIFEST.sha256"
registry = json.loads(registry_path.read_text(encoding="utf-8"))
errors = []
manifest = {}
manifest_paths = []
manifest_text = manifest_path.read_text(encoding="utf-8")
for line_number, line in enumerate(manifest_text.splitlines(), 1):
    if not line.strip():
        continue
    parts = line.split(None, 1)
    if len(parts) != 2:
        errors.append(f"MANIFEST.sha256 line {line_number} is malformed")
        continue
    digest, path = parts
    if path in manifest:
        errors.append(f"MANIFEST.sha256 has duplicate entry for {path}")
    manifest[path] = digest
    manifest_paths.append(path)
if manifest_paths != sorted(manifest_paths):
    errors.append("MANIFEST.sha256 entries must be sorted by path")

registry_rel = str(registry_path.relative_to(root))
manifest_rel = str(manifest_path.relative_to(root))
security_inventory_rel = "spec/schemas/chio-wire/v1/security/required-schema-inventory.json"
signed_artifact_map_rel = (
    "spec/schemas/chio-wire/v1/security/exported-signed-artifact-schema-map.json"
)

try:
    tracked_schema_inventory = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "spec/schemas",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    expected_manifest_paths = sorted(
        path
        for path in tracked_schema_inventory.stdout.decode("utf-8").split("\0")
        if path.endswith(".schema.json")
        or path in {
            manifest_rel,
            registry_rel,
            security_inventory_rel,
            signed_artifact_map_rel,
            "spec/schemas/VERSION",
        }
    )
except (OSError, subprocess.CalledProcessError) as error:
    expected_manifest_paths = []
    errors.append(f"unable to inspect git-tracked schema manifest inventory: {error}")

if manifest_paths != expected_manifest_paths:
    errors.append("MANIFEST.sha256 path set is not deterministic")

expected_lines_without_self = []
for rel in expected_manifest_paths:
    if rel == manifest_rel:
        continue
    path = root / rel
    if not path.is_file():
        errors.append(f"MANIFEST.sha256 expected path is missing: {rel}")
        continue
    expected_lines_without_self.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {rel}\n")
expected_manifest_self_hash = hashlib.sha256(
    "".join(expected_lines_without_self).encode("utf-8")
).hexdigest()
expected_manifest_content = "".join(
    (
        f"{expected_manifest_self_hash}  {manifest_rel}\n"
        if rel == manifest_rel
        else f"{hashlib.sha256((root / rel).read_bytes()).hexdigest()}  {rel}\n"
    )
    for rel in expected_manifest_paths
    if rel == manifest_rel or (root / rel).is_file()
)
if expected_manifest_paths and manifest_text != expected_manifest_content:
    errors.append("MANIFEST.sha256 bytes do not match deterministic regeneration")

registry_digest = hashlib.sha256(registry_path.read_bytes()).hexdigest()
if manifest.get(registry_rel) != registry_digest:
    errors.append(f"registry.json has stale or absent MANIFEST.sha256 entry for {registry_rel}")

manifest_self_digest = manifest.get(manifest_rel)
if manifest_self_digest is None:
    errors.append(f"MANIFEST.sha256 is missing self-hash entry for {manifest_rel}")
else:
    def manifest_path_from_line(raw_line):
        parts = raw_line.strip().split(None, 1)
        if len(parts) != 2:
            return None
        return parts[1].decode("utf-8", errors="replace")

    manifest_without_self_entry = b"".join(
        raw_line
        for raw_line in manifest_path.read_bytes().splitlines(keepends=True)
        if manifest_path_from_line(raw_line) != manifest_rel
    )
    manifest_self_hash = hashlib.sha256(manifest_without_self_entry).hexdigest()
    if manifest_self_digest != manifest_self_hash:
        errors.append(f"MANIFEST.sha256 has stale self-hash entry for {manifest_rel}")
registered_paths = {
    path
    for entry in registry.get("artifacts", [])
    for path in (entry.get("schemaFile"), entry.get("payloadSchemaFile"))
    if path
}
checked_chio_schema_roots = (
    "spec/schemas/chio-agent-web/",
    "spec/schemas/chio-attest/",
    "spec/schemas/chio-commerce/",
    "spec/schemas/chio-crypto/",
    "spec/schemas/chio-disclosure/",
    "spec/schemas/chio-enterprise/",
    "spec/schemas/chio-federation/",
    "spec/schemas/chio-lineage/",
    "spec/schemas/chio-oracle/",
    "spec/schemas/chio-pheromone/",
    "spec/schemas/chio-proof-room/",
    "spec/schemas/chio-risk/",
    "spec/schemas/chio-runtime/",
    "spec/schemas/chio-swarm/",
    "spec/schemas/chio-transparency/",
    "spec/schemas/chio-transaction/",
    "spec/schemas/chio-trust/",
    "spec/schemas/chio-web3/",
    "spec/schemas/chio-workflow/",
)
checked_active_chio_schema_text_roots = checked_chio_schema_roots + (
    "spec/schemas/chio-wire/",
)
try:
    tracked = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            *checked_chio_schema_roots,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    tracked_schema_paths = {
        path
        for path in tracked.stdout.decode("utf-8").split("\0")
        if path.endswith(".schema.json")
    }
except (OSError, subprocess.CalledProcessError) as error:
    tracked_schema_paths = set()
    errors.append(f"unable to inspect git-tracked Chio schema files: {error}")

try:
    tracked_active = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            *checked_active_chio_schema_text_roots,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    tracked_active_schema_paths = {
        path
        for path in tracked_active.stdout.decode("utf-8").split("\0")
        if path.endswith(".schema.json")
    }
except (OSError, subprocess.CalledProcessError) as error:
    tracked_active_schema_paths = set()
    errors.append(f"unable to inspect git-tracked active Chio schema files: {error}")

for entry in registry.get("artifacts", []):
    schema_id = entry.get("schema", "<missing schema>")
    artifact_kind = entry.get("artifactKind", "")
    introduced_by = entry.get("introducedBy", "")
    status = entry.get("status")

    for schema_field in ("schemaFile", "payloadSchemaFile"):
        schema_file = entry.get(schema_field, "")
        if not schema_file:
            continue
        if schema_file.startswith("spec/schemas/chio/"):
            errors.append(f"{schema_id} points at inactive schema root {schema_file}")
            continue
        if schema_file.startswith(checked_active_chio_schema_text_roots):
            path = root / schema_file
            if not path.is_file():
                errors.append(f"{schema_id} points at missing Chio schema file {schema_file}")
            elif manifest.get(schema_file) != hashlib.sha256(path.read_bytes()).hexdigest():
                errors.append(
                    f"{schema_id} has stale or absent MANIFEST.sha256 entry for {schema_file}"
                )

security_schema_dir = root / "spec/schemas/chio-wire/v1/security"
security_inventory_path = root / security_inventory_rel
security_schema_inventory = {}
if not security_inventory_path.is_file():
    errors.append(f"required security schema inventory is missing: {security_inventory_rel}")
else:
    try:
        security_inventory_document = json.loads(
            security_inventory_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"required security schema inventory is not valid JSON: {error}")
        security_inventory_document = {}

    if security_inventory_document.get("schema") != "chio.security-required-schema-inventory.v1":
        errors.append("required security schema inventory has an invalid schema discriminator")
    security_entries = security_inventory_document.get("schemas")
    if not isinstance(security_entries, list) or not security_entries:
        errors.append("required security schema inventory must contain at least one schema")
        security_entries = []

    inventory_names = []
    seen_inventory_ids = set()
    for index, entry in enumerate(security_entries):
        if not isinstance(entry, dict) or set(entry) != {"file", "schema_id"}:
            errors.append(
                f"required security schema inventory entry {index} must contain exactly file and schema_id"
            )
            continue
        file_name = entry.get("file")
        schema_id = entry.get("schema_id")
        if (
            not isinstance(file_name, str)
            or not file_name.endswith(".schema.json")
            or pathlib.PurePosixPath(file_name).name != file_name
        ):
            errors.append(
                f"required security schema inventory entry {index} has an unsafe schema file"
            )
            continue
        if not isinstance(schema_id, str) or not schema_id:
            errors.append(
                f"required security schema inventory entry {index} has no non-empty schema_id"
            )
            continue
        if file_name in security_schema_inventory:
            errors.append(f"required security schema inventory duplicates file {file_name}")
            continue
        if schema_id in seen_inventory_ids:
            errors.append(f"required security schema inventory duplicates schema_id {schema_id}")
            continue
        security_schema_inventory[file_name] = schema_id
        seen_inventory_ids.add(schema_id)
        inventory_names.append(file_name)

    if inventory_names != sorted(inventory_names):
        errors.append("required security schema inventory entries must be sorted by file")

actual_security_schema_names = {
    path.name for path in security_schema_dir.glob("*.schema.json")
}
declared_security_schema_names = set(security_schema_inventory)
for missing_name in sorted(actual_security_schema_names - declared_security_schema_names):
    errors.append(f"required security schema inventory omits {missing_name}")
for missing_file in sorted(declared_security_schema_names - actual_security_schema_names):
    errors.append(f"required security schema inventory points at missing file {missing_file}")
for file_name, expected_schema_id in sorted(security_schema_inventory.items()):
    schema_path = security_schema_dir / file_name
    if not schema_path.is_file():
        continue
    try:
        schema_document = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"required security schema {file_name} is not valid JSON: {error}")
        continue
    if schema_document.get("$id") != expected_schema_id:
        errors.append(
            f"required security schema {file_name} has $id {schema_document.get('$id')!r}, "
            f"expected {expected_schema_id!r}"
        )

required_wire_registry_paths = {
    f"spec/schemas/chio-wire/v1/security/{file_name}"
    for file_name in security_schema_inventory
}
required_wire_registry_paths.update(
    {
        f"spec/schemas/chio-wire/v1/capability/{name}.schema.json"
        for name in (
            "aggregate-budget-root-commitment",
            "aggregate-budget-root-binding-body",
            "aggregate-budget-root-binding",
            "aggregate-invocation-budget",
            "aggregate-family-preservation-evidence",
            "threshold-approval-proposal-body",
            "threshold-approval-proposal",
            "governed-approval-token-body",
            "governed-approval-token",
            "verified-approval-set",
        )
    }
)
required_wire_registry_paths.update(
    {
        f"spec/schemas/chio-wire/v1/trust-control/{name}.schema.json"
        for name in (
            "admission-capture-metadata",
            "admission-request-binding",
            "budget-invocation-admission-evidence",
        )
    }
)

signed_artifact_map_path = root / signed_artifact_map_rel
if not signed_artifact_map_path.is_file():
    errors.append(f"exported signed artifact schema map is missing: {signed_artifact_map_rel}")
else:
    try:
        signed_artifact_map = json.loads(
            signed_artifact_map_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"exported signed artifact schema map is not valid JSON: {error}")
        signed_artifact_map = {}

    if signed_artifact_map.get("schema") != "chio.exported-signed-artifact-schema-map.v1":
        errors.append("exported signed artifact schema map has an invalid discriminator")

    source_roots = signed_artifact_map.get("source_roots")
    if not isinstance(source_roots, list) or not source_roots:
        errors.append("exported signed artifact schema map must scan at least one Rust source root")
        source_roots = []
    if source_roots != sorted(source_roots) or len(source_roots) != len(set(source_roots)):
        errors.append("exported signed artifact source_roots entries must be sorted and unique")

    discovered_signed_exports = {}
    signed_export_pattern = re.compile(
        r"\bpub\s+struct\s+((?:Signed[A-Za-z0-9_]+)|(?:[A-Za-z0-9_]+(?:Signature|Proof)))\b"
    )
    source_text_by_path = {}
    scanned_source_paths = set()
    resolved_source_roots = []
    for index, source_root_rel in enumerate(source_roots):
        if (
            not isinstance(source_root_rel, str)
            or not source_root_rel.startswith("crates/")
            or pathlib.PurePosixPath(source_root_rel).is_absolute()
            or ".." in pathlib.PurePosixPath(source_root_rel).parts
        ):
            errors.append(f"exported signed artifact source_roots entry {index} is unsafe")
            continue
        source_root_path = root / source_root_rel
        if source_root_path.is_symlink() or not source_root_path.exists():
            errors.append(f"exported signed artifact source root is missing or aliased: {source_root_rel}")
            continue
        resolved_source_root = source_root_path.resolve()
        if any(
            resolved_source_root == previous
            or resolved_source_root in previous.parents
            or previous in resolved_source_root.parents
            for previous in resolved_source_roots
        ):
            errors.append(f"exported signed artifact source root overlaps another root: {source_root_rel}")
            continue
        resolved_source_roots.append(resolved_source_root)
        if source_root_path.is_file():
            source_paths = [source_root_path] if source_root_path.suffix == ".rs" else []
        elif source_root_path.is_dir():
            source_paths = sorted(source_root_path.rglob("*.rs"))
        else:
            source_paths = []
        if not source_paths:
            errors.append(f"exported signed artifact source root has no Rust files: {source_root_rel}")
        for source_path in source_paths:
            if source_path.is_symlink() or not source_path.is_file():
                errors.append(f"exported signed artifact source is aliased: {source_path}")
                continue
            source_rel = source_path.relative_to(root).as_posix()
            if source_rel in scanned_source_paths:
                errors.append(f"exported signed artifact source was scanned twice: {source_rel}")
                continue
            scanned_source_paths.add(source_rel)
            source_text = source_path.read_text(encoding="utf-8")
            source_text_by_path[source_rel] = source_text
            for rust_type in signed_export_pattern.findall(source_text):
                previous = discovered_signed_exports.get(rust_type)
                if previous is not None and previous != source_rel:
                    errors.append(
                        f"exported signed artifact {rust_type} is declared in both {previous} and {source_rel}"
                    )
                discovered_signed_exports[rust_type] = source_rel

    artifact_mappings = signed_artifact_map.get("artifacts")
    if not isinstance(artifact_mappings, list) or not artifact_mappings:
        errors.append("exported signed artifact schema map must contain at least one mapping")
        artifact_mappings = []
    mapping_names = [
        entry.get("rust_type")
        for entry in artifact_mappings
        if isinstance(entry, dict)
    ]
    if mapping_names != sorted(mapping_names):
        errors.append("exported signed artifact schema mappings must be sorted by rust_type")

    mapped_signed_exports = {}
    mapped_schema_paths = set()
    required_mapping_keys = {"rust_type", "source", "schema_file"}
    optional_mapping_keys = {
        "payload_schema_file",
        "schema_constant",
        "schema_constant_source",
        "schema_value",
    }
    for index, entry in enumerate(artifact_mappings):
        if not isinstance(entry, dict):
            errors.append(f"exported signed artifact mapping {index} is not an object")
            continue
        if not required_mapping_keys.issubset(entry) or not set(entry).issubset(
            required_mapping_keys | optional_mapping_keys
        ):
            errors.append(
                f"exported signed artifact mapping {index} has invalid fields"
            )
            continue
        rust_type = entry.get("rust_type")
        source_rel = entry.get("source")
        schema_file = entry.get("schema_file")
        if not isinstance(rust_type, str) or not rust_type:
            errors.append(f"exported signed artifact mapping {index} has no rust_type")
            continue
        if rust_type in mapped_signed_exports:
            errors.append(f"exported signed artifact mapping duplicates {rust_type}")
            continue
        mapped_signed_exports[rust_type] = source_rel
        discovered_source = discovered_signed_exports.get(rust_type)
        if discovered_source is None:
            errors.append(
                f"exported signed artifact mapping names undiscovered Rust type {rust_type}"
            )
        elif source_rel != discovered_source:
            errors.append(
                f"exported signed artifact {rust_type} source is {source_rel}, expected {discovered_source}"
            )

        schema_fields = ["schema_file"]
        if "payload_schema_file" in entry:
            schema_fields.append("payload_schema_file")
        resolved_schema_documents = {}
        for schema_field in schema_fields:
            mapped_rel = entry.get(schema_field)
            if (
                not isinstance(mapped_rel, str)
                or not mapped_rel.startswith("spec/schemas/chio-wire/v1/security/")
                or not mapped_rel.endswith(".schema.json")
                or pathlib.PurePosixPath(mapped_rel).is_absolute()
                or ".." in pathlib.PurePosixPath(mapped_rel).parts
            ):
                errors.append(
                    f"exported signed artifact {rust_type} has unsafe {schema_field}"
                )
                continue
            if mapped_rel in mapped_schema_paths:
                errors.append(
                    f"exported signed artifact schema map reuses mapped schema {mapped_rel}"
                )
            mapped_schema_paths.add(mapped_rel)
            mapped_path = root / mapped_rel
            if not mapped_path.is_file():
                errors.append(
                    f"exported signed artifact {rust_type} points at missing schema {mapped_rel}"
                )
                continue
            try:
                resolved_schema_documents[schema_field] = json.loads(
                    mapped_path.read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError) as error:
                errors.append(
                    f"exported signed artifact {rust_type} schema {mapped_rel} is invalid JSON: {error}"
                )
            if mapped_rel not in registered_paths:
                errors.append(
                    f"exported signed artifact {rust_type} schema is not registered: {mapped_rel}"
                )
            if pathlib.PurePosixPath(mapped_rel).name not in security_schema_inventory:
                errors.append(
                    f"exported signed artifact {rust_type} schema is not in the required inventory: {mapped_rel}"
                )

        payload_rel = entry.get("payload_schema_file")
        envelope_document = resolved_schema_documents.get("schema_file")
        if isinstance(payload_rel, str) and isinstance(envelope_document, dict):
            body_ref = (
                envelope_document.get("properties", {})
                .get("body", {})
                .get("$ref")
            )
            if body_ref != pathlib.PurePosixPath(payload_rel).name:
                errors.append(
                    f"exported signed artifact {rust_type} envelope does not reference its payload schema"
                )

        has_schema_constant = "schema_constant" in entry
        has_schema_value = "schema_value" in entry
        has_schema_constant_source = "schema_constant_source" in entry
        if has_schema_constant != has_schema_value:
            errors.append(
                f"exported signed artifact {rust_type} must declare schema_constant and schema_value together"
            )
        elif has_schema_constant:
            schema_constant = entry.get("schema_constant")
            schema_value = entry.get("schema_value")
            constant_source_rel = entry.get("schema_constant_source", source_rel)
            source_text = source_text_by_path.get(constant_source_rel, "")
            if has_schema_constant_source and constant_source_rel not in source_text_by_path:
                errors.append(
                    f"exported signed artifact {rust_type} schema_constant_source is outside the closed scan roots"
                )
            if not isinstance(schema_constant, str) or not re.fullmatch(
                r"[A-Z][A-Z0-9_]*", schema_constant
            ):
                errors.append(
                    f"exported signed artifact {rust_type} has an invalid schema_constant"
                )
            elif not isinstance(schema_value, str) or not schema_value:
                errors.append(
                    f"exported signed artifact {rust_type} has an invalid schema_value"
                )
            else:
                constant_pattern = re.compile(
                    rf"\bpub\s+const\s+{re.escape(schema_constant)}\s*:\s*&str\s*=\s*{re.escape(json.dumps(schema_value))}\s*;"
                )
                if not constant_pattern.search(source_text):
                    errors.append(
                        f"exported signed artifact {rust_type} schema constant has drifted from {schema_value}"
                    )
                discriminator_document = resolved_schema_documents.get(
                    "payload_schema_file",
                    resolved_schema_documents.get("schema_file", {}),
                )
                schema_const = (
                    discriminator_document.get("properties", {})
                    .get("schema", {})
                    .get("const")
                    if isinstance(discriminator_document, dict)
                    else None
                )
                if schema_const != schema_value:
                    errors.append(
                        f"exported signed artifact {rust_type} schema discriminator is {schema_const!r}, expected {schema_value!r}"
                    )

    exclusion_entries = signed_artifact_map.get("exclusions")
    if not isinstance(exclusion_entries, list):
        errors.append("exported signed artifact schema map exclusions must be an array")
        exclusion_entries = []
    exclusion_names = [
        entry.get("rust_type")
        for entry in exclusion_entries
        if isinstance(entry, dict)
    ]
    if exclusion_names != sorted(exclusion_names):
        errors.append("exported signed artifact exclusions must be sorted by rust_type")
    excluded_signed_exports = {}
    allowed_exclusion_kinds = {"generic_envelope", "nested_component"}
    for index, entry in enumerate(exclusion_entries):
        if not isinstance(entry, dict) or set(entry) != {
            "rust_type",
            "source",
            "kind",
            "reason",
        }:
            errors.append(f"exported signed artifact exclusion {index} has invalid fields")
            continue
        rust_type = entry.get("rust_type")
        source_rel = entry.get("source")
        kind = entry.get("kind")
        reason = entry.get("reason")
        if not isinstance(rust_type, str) or not rust_type:
            errors.append(f"exported signed artifact exclusion {index} has no rust_type")
            continue
        if rust_type in excluded_signed_exports:
            errors.append(f"exported signed artifact exclusion duplicates {rust_type}")
            continue
        excluded_signed_exports[rust_type] = source_rel
        if kind not in allowed_exclusion_kinds:
            errors.append(f"exported signed artifact {rust_type} has invalid exclusion kind {kind!r}")
        if not isinstance(reason, str) or len(reason.strip()) < 24:
            errors.append(f"exported signed artifact {rust_type} exclusion reason is not specific")
        discovered_source = discovered_signed_exports.get(rust_type)
        if discovered_source is None:
            errors.append(
                f"exported signed artifact exclusion names undiscovered Rust type {rust_type}"
            )
        elif source_rel != discovered_source:
            errors.append(
                f"exported signed artifact exclusion {rust_type} source is {source_rel}, expected {discovered_source}"
            )

    overlap = set(mapped_signed_exports) & set(excluded_signed_exports)
    for rust_type in sorted(overlap):
        errors.append(f"exported signed artifact {rust_type} is both mapped and excluded")
    accounted_signed_exports = set(mapped_signed_exports) | set(excluded_signed_exports)
    for rust_type in sorted(set(discovered_signed_exports) - accounted_signed_exports):
        errors.append(f"exported signed artifact {rust_type} has no schema mapping")
    for rust_type in sorted(accounted_signed_exports - set(discovered_signed_exports)):
        errors.append(f"schema mapping has no exported signed artifact {rust_type}")

for schema_path in sorted(required_wire_registry_paths - registered_paths):
    errors.append(f"Enterprise security schema {schema_path} is not registered in registry.json")

for schema_root in checked_chio_schema_roots:
    for schema_path in sorted((root / schema_root).glob("**/*.schema.json")):
        rel = str(schema_path.relative_to(root))
        if rel not in tracked_schema_paths:
            errors.append(f"Chio schema {rel} is not tracked by git")
        if rel not in registered_paths:
            errors.append(f"Chio schema {rel} is not registered in registry.json")
        if manifest.get(rel) != hashlib.sha256(schema_path.read_bytes()).hexdigest():
            errors.append(f"Chio schema {rel} is absent from MANIFEST.sha256 or has stale hash")
        schema_text = schema_path.read_text(encoding="utf-8")
        if '"$ref"' in schema_text and "../../chio/" in schema_text:
            errors.append(f"Chio schema {rel} references inactive chio schema paths")

seen_schema_ids = {}
for schema_root in checked_active_chio_schema_text_roots:
    for schema_path in sorted((root / schema_root).glob("**/*.schema.json")):
        rel = str(schema_path.relative_to(root))
        if schema_root not in checked_chio_schema_roots and rel not in tracked_active_schema_paths:
            errors.append(f"Active Chio schema {rel} is not tracked by git")
        if (
            schema_root not in checked_chio_schema_roots
            and manifest.get(rel) != hashlib.sha256(schema_path.read_bytes()).hexdigest()
        ):
            errors.append(f"Active Chio schema {rel} is absent from MANIFEST.sha256 or has stale hash")
        try:
            schema_document = json.loads(schema_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"Active Chio schema {rel} is not valid JSON: {error}")
            continue
        document_id = schema_document.get("$id")
        if (
            (not isinstance(document_id, str) or not document_id)
            and rel in required_wire_registry_paths
        ):
            errors.append(f"Active Chio schema {rel} has no non-empty $id")
        elif isinstance(document_id, str) and document_id in seen_schema_ids:
            errors.append(
                f"Active Chio schema $id {document_id} is duplicated by "
                f"{seen_schema_ids[document_id]} and {rel}"
            )
        elif isinstance(document_id, str) and document_id:
            seen_schema_ids[document_id] = rel
if errors:
    raise SystemExit("\n".join(errors))

print("OK Chio schema registry metadata")
PY
