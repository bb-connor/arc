#!/usr/bin/env python3
"""Generate the schema files for signed-artifact ids from recorded bodies.

Every wrapper id (`chio_core_types::KNOWN_SIGNED_ARTIFACT_SCHEMAS`, read
from its generated Python copy) has a registry row and at least one example
of the body the signing wrapper covers under it, in
`spec/schemas/signed-artifact-examples/<escaped id>/<variant>.json`; the
escaped id keeps `[a-z0-9._-]` and writes every other byte as `%XX` (a
leading `.` too). `--check` fails when a wrapper id has no row or no
example, or an example directory names no wrapper id.

`spec/schemas/signed-artifact-schemas.json` lists, under `artifacts`, every
id whose schema file this script owns. Each entry names the id, its
registry `artifactKind` and `introducedBy`, the `schemaFile` it writes and
optional `overrides`. With `envelopeSchemaFile`, a hand-maintained schema
of the signed envelope that carries the body, the registry row names that
envelope as its `schemaFile` and the generated body schema as its
`payloadSchemaFile`. `secretShapedMembers` lists, per id, the JSON
pointers of members whose names look like key material but hold none (an
API key id, for example); every other such member fails the import.

A generated schema is the closed Draft 2020-12 description of those bodies:

- an object allows exactly the members seen in any example
  (`additionalProperties: false` at every level) and requires the members
  present in every example of that object;
- an array describes the union of its items;
- a value seen with different JSON types is the union of those types;
- a top-level `schema` member equal to the id is pinned with `const`.

`overrides` maps a JSON pointer inside the body (`*` steps into array items,
`~` into map values) to a fragment that replaces the inferred one at that
location. `{"map": true}` instead turns an object into a string-keyed map
whose values are the union of the members seen there. An empty array or an
empty map has no inferable items, so the generator refuses one unless an
override covers it.

`--import-captures DIR` first replaces the `captured-<n>` examples of every
wrapper id with a covering subset of the bodies recorded under DIR by
`scripts/capture-wrapper-bodies.sh` (`DIR/<escaped id>/<sha256>.json`): the
fewest bodies that together show every member, every JSON type at every
location and every absent optional member any recorded body shows, so the
subset infers the same schema as the whole recording. Ties go to the
smaller body, then to the lower digest. An id with no recorded body keeps
its existing examples. The import refuses a body that carries a member
named like key material (`seed`, `secret`, `private`, `password`,
`passphrase`, `mnemonic`) or a string holding a PEM block, because a
recorded body must hold only test fixtures and public values.

The script also writes one `registry.json` row per entry (a contiguous
block after the hand-maintained rows, sorted by id), regenerates
`MANIFEST.sha256` in the form `check-chio-schema-registry.sh` recomputes
and refreshes the generated block of the chio-wire v1 README. `--check`
writes nothing and fails when any of those files differs from what
generation would produce. Output depends only on the tree, so a second run
is a no-op.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = Path("spec/schemas")
CONTROL = SCHEMAS / "signed-artifact-schemas.json"
REGISTRY = SCHEMAS / "registry.json"
MANIFEST = SCHEMAS / "MANIFEST.sha256"
README = SCHEMAS / "chio-wire/v1/README.md"
ID_BASE = "https://chio-protocol.dev/schemas/"
DRAFT = "https://json-schema.org/draft/2020-12/schema"
README_BEGIN = "<!-- BEGIN generated signed-artifact schemas -->"
README_END = "<!-- END generated signed-artifact schemas -->"
EXAMPLES = SCHEMAS / "signed-artifact-examples"
WRAPPER_IDS = Path("sdks/python/chio-py/src/chio/invariants/_generated_signed_artifact_schemas.py")
CONTROL_KEYS = {"schema", "artifactKind", "introducedBy", "schemaFile", "title", "overrides", "envelopeSchemaFile"}
SECRET_NAME = re.compile(r"(?:\A|_)(?:seed|secret|private|privkey|password|passphrase|mnemonic)(?:_|\Z)")
PEM = re.compile(r"-----BEGIN |PRIVATE KEY")
SCHEMA_ID = re.compile(r"\Achio\.[a-z0-9][a-z0-9._-]*\.v1\Z")


class GenerationError(Exception):
    pass


@dataclass
class Shape:
    """Accumulated observations of the values found at one location."""

    kinds: set[str] = field(default_factory=set)
    seen: int = 0
    members: dict[str, "Shape"] = field(default_factory=dict)
    member_counts: dict[str, int] = field(default_factory=dict)
    objects: int = 0
    items: "Shape | None" = None
    strings: set[str] = field(default_factory=set)

    def observe(self, value: Any) -> None:
        self.seen += 1
        if value is None:
            self.kinds.add("null")
        elif isinstance(value, bool):
            self.kinds.add("boolean")
        elif isinstance(value, int):
            self.kinds.add("integer")
        elif isinstance(value, float):
            self.kinds.add("number")
        elif isinstance(value, str):
            self.kinds.add("string")
            self.strings.add(value)
        elif isinstance(value, list):
            self.kinds.add("array")
            if self.items is None:
                self.items = Shape()
            for item in value:
                self.items.observe(item)
        elif isinstance(value, dict):
            self.kinds.add("object")
            self.objects += 1
            for key, member in value.items():
                self.members.setdefault(key, Shape()).observe(member)
                self.member_counts[key] = self.member_counts.get(key, 0) + 1
        else:
            raise GenerationError(f"unsupported JSON value {value!r}")


def pointer_join(pointer: str, step: str) -> str:
    return f"{pointer}/{step.replace('~', '~0').replace('/', '~1')}"


def render(
    shape: Shape,
    pointer: str,
    overrides: dict[str, Any],
    used: set[str],
    pinned_schema: str | None,
) -> dict[str, Any]:
    if pointer in overrides and overrides[pointer] != {"map": True}:
        used.add(pointer)
        return overrides[pointer]
    as_map = overrides.get(pointer) == {"map": True}
    if as_map:
        used.add(pointer)
    if shape.seen == 0 or not shape.kinds:
        raise GenerationError(f"{pointer or '/'}: no value observed; add an example or an override")
    kinds = set(shape.kinds)
    if {"integer", "number"} <= kinds:
        kinds.discard("integer")
    branches: list[dict[str, Any]] = []
    for kind in sorted(kinds - {"object", "array"}):
        branches.append({"type": kind})
    if "array" in kinds:
        items = shape.items
        if items is None or items.seen == 0:
            raise GenerationError(
                f"{pointer or '/'}: array is empty in every example; add an example or an override"
            )
        branches.append(
            {"type": "array", "items": render(items, pointer + "/*", overrides, used, None)}
        )
    if "object" in kinds:
        if as_map:
            if not shape.members:
                raise GenerationError(
                    f"{pointer or '/'}: map is empty in every example; add an example or an override"
                )
            values = Shape()
            for member in shape.members.values():
                merge_into(values, member)
            branches.append(
                {
                    "type": "object",
                    "additionalProperties": render(values, pointer + "/~", overrides, used, None),
                }
            )
        else:
            properties: dict[str, Any] = {}
            for key in sorted(shape.members):
                child = pointer_join(pointer, key)
                if pointer == "" and key == "schema" and pinned_schema is not None:
                    values = shape.members[key].strings
                    if shape.members[key].kinds == {"string"} and values == {pinned_schema}:
                        properties[key] = {"const": pinned_schema}
                        continue
                properties[key] = render(shape.members[key], child, overrides, used, None)
            required = sorted(k for k, n in shape.member_counts.items() if n == shape.objects)
            node: dict[str, Any] = {"type": "object", "additionalProperties": False}
            if required:
                node["required"] = required
            node["properties"] = properties
            branches.append(node)
    if len(branches) == 1:
        return branches[0]
    if all(set(branch) == {"type"} for branch in branches):
        return {"type": [branch["type"] for branch in branches]}
    return {"anyOf": branches}


def merge_into(target: Shape, source: Shape) -> None:
    target.seen += source.seen
    target.kinds |= source.kinds
    target.strings |= source.strings
    target.objects += source.objects
    for key, member in source.members.items():
        merge_into(target.members.setdefault(key, Shape()), member)
        target.member_counts[key] = target.member_counts.get(key, 0) + source.member_counts[key]
    if source.items is not None:
        if target.items is None:
            target.items = Shape()
        merge_into(target.items, source.items)


def escape_schema_id(schema_id: str) -> str:
    out = []
    for byte in schema_id.encode("utf-8"):
        char = chr(byte)
        if char.isascii() and (char.islower() or char.isdigit() or char in "._-"):
            out.append(char)
        else:
            out.append(f"%{byte:02X}")
    escaped = "".join(out)
    return "%2E" + escaped[1:] if escaped.startswith(".") else escaped


def kind_of(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number" if isinstance(value, float) else "integer"
    if isinstance(value, str):
        return "string"
    return "array" if isinstance(value, list) else "object"


def walk_features(value: Any, pointer: str, overrides: dict[str, Any], keys: dict[str, set[str]], out: set) -> None:
    if pointer in overrides and overrides[pointer] != {"map": True}:
        return
    out.add(("kind", pointer, kind_of(value)))
    if isinstance(value, list):
        for item in value:
            walk_features(item, pointer + "/*", overrides, keys, out)
    elif isinstance(value, dict):
        if overrides.get(pointer) == {"map": True}:
            for item in value.values():
                walk_features(item, pointer + "/~", overrides, keys, out)
            return
        keys.setdefault(pointer, set()).update(value)
        for key, item in value.items():
            out.add(("member", pointer, key))
            walk_features(item, pointer_join(pointer, key), overrides, keys, out)


def absent_features(value: Any, pointer: str, overrides: dict[str, Any], keys: dict[str, set[str]], out: set) -> None:
    if pointer in overrides:
        if overrides[pointer] != {"map": True} or not isinstance(value, dict):
            return
        for item in value.values():
            absent_features(item, pointer + "/~", overrides, keys, out)
        return
    if isinstance(value, list):
        for item in value:
            absent_features(item, pointer + "/*", overrides, keys, out)
    elif isinstance(value, dict):
        for key in keys.get(pointer, set()) - set(value):
            out.add(("absent", pointer, key))
        for key, item in value.items():
            absent_features(item, pointer_join(pointer, key), overrides, keys, out)


def covering_subset(bodies: list[tuple[str, bytes, Any]], overrides: dict[str, Any]) -> list[tuple[str, bytes, Any]]:
    keys: dict[str, set[str]] = {}
    features = []
    for _, _, value in bodies:
        found: set = set()
        walk_features(value, "", overrides, keys, found)
        features.append(found)
    for index, (_, _, value) in enumerate(bodies):
        absent_features(value, "", overrides, keys, features[index])
    uncovered = set().union(*features) if features else set()
    # Bodies with equal feature sets differ only in the tie-break, so the
    # best-ranked one of each set is the only one greedy selection can pick.
    representative: dict[frozenset, int] = {}
    for index, found in enumerate(features):
        key = frozenset(found)
        held = representative.get(key)
        if held is None or (len(bodies[index][1]), bodies[index][0]) < (len(bodies[held][1]), bodies[held][0]):
            representative[key] = index
    chosen = []
    remaining = sorted(representative.values())
    while uncovered:
        best = max(remaining, key=lambda i: (len(features[i] & uncovered), -len(bodies[i][1]), [-ord(c) for c in bodies[i][0]]))
        chosen.append(best)
        remaining.remove(best)
        uncovered -= features[best]
    return [bodies[i] for i in sorted(chosen, key=lambda i: bodies[i][0])]


def import_captures(root: Path, capture_dir: Path) -> dict[str, bytes | None]:
    """Example files to write (bytes) or delete (None) for recorded ids."""
    overrides = {entry["schema"]: entry.get("overrides", {}) for entry in load_control(root)}
    allowances = load_secret_allowances(root)
    ids = sorted(set(load_wrapper_ids(root)) | set(overrides))
    changes: dict[str, bytes | None] = {}
    for sid in ids:
        recorded = capture_dir / escape_schema_id(sid)
        if not recorded.is_dir():
            continue
        bodies = []
        for path in sorted(recorded.glob("*.json")):
            payload = path.read_bytes()
            if hashlib.sha256(payload).hexdigest() != path.stem:
                raise GenerationError(f"{path}: name is not the sha256 of its bytes")
            try:
                value = json.loads(payload)
            except json.JSONDecodeError as error:
                raise GenerationError(f"{path}: {error}") from error
            findings: list[str] = []
            secret_findings(value, "", findings)
            findings = [f for f in findings if f not in allowances.get(sid, set())]
            if findings:
                raise GenerationError(f"{sid}: {path.name} carries key-shaped members: {findings}")
            bodies.append((path.stem, payload, value))
        if not bodies:
            continue
        directory = EXAMPLES / escape_schema_id(sid)
        for old in sorted((root / directory).glob("captured-*.json")):
            changes[str(old.relative_to(root))] = None
        for index, (_, _, value) in enumerate(covering_subset(bodies, overrides.get(sid, {})), 1):
            changes[str(directory / f"captured-{index}.json")] = dump(value).encode("utf-8")
    return changes


def dump(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def load_json(root: Path, rel: Path | str) -> Any:
    path = root / rel
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GenerationError(f"{rel}: {error}") from error


def load_control(root: Path) -> list[dict[str, Any]]:
    control = load_json(root, CONTROL)
    if not isinstance(control, dict) or set(control) != {"schema", "artifacts", "secretShapedMembers"}:
        raise GenerationError(f"{CONTROL}: expected exactly the members schema, artifacts and secretShapedMembers")
    allowed = control["secretShapedMembers"]
    if not isinstance(allowed, dict) or not all(
        isinstance(v, list) and v == sorted(set(v)) and all(isinstance(x, str) and x.startswith("/") for x in v)
        for v in allowed.values()
    ):
        raise GenerationError(f"{CONTROL}: secretShapedMembers must map ids to sorted JSON pointer lists")
    if control["schema"] != "chio.signed-artifact-schemas.v1":
        raise GenerationError(f"{CONTROL}: schema must be chio.signed-artifact-schemas.v1")
    entries = control["artifacts"]
    if not isinstance(entries, list):
        raise GenerationError(f"{CONTROL}: artifacts must be an array")
    ids = [entry.get("schema") for entry in entries if isinstance(entry, dict)]
    if ids != sorted(ids) or len(ids) != len(set(ids)) or len(ids) != len(entries):
        raise GenerationError(f"{CONTROL}: artifacts must be objects with unique ids sorted by schema")
    files = [entry.get("schemaFile") for entry in entries]
    if len(files) != len(set(files)):
        raise GenerationError(f"{CONTROL}: two artifacts share a schemaFile")
    for entry in entries:
        sid = entry["schema"]
        unknown = set(entry) - CONTROL_KEYS
        missing = {"schema", "artifactKind", "introducedBy", "schemaFile", "title"} - set(entry)
        if unknown or missing:
            raise GenerationError(f"{sid}: unknown members {sorted(unknown)}, missing {sorted(missing)}")
        if not isinstance(sid, str) or not SCHEMA_ID.match(sid):
            raise GenerationError(f"{sid}: not a chio v1 schema id")
        schema_file = entry["schemaFile"]
        if not (
            isinstance(schema_file, str)
            and schema_file.startswith("spec/schemas/chio-wire/v1/")
            and schema_file.endswith(".schema.json")
            and ".." not in schema_file.split("/")
        ):
            raise GenerationError(f"{sid}: schemaFile must be a .schema.json under spec/schemas/chio-wire/v1/")
        envelope = entry.get("envelopeSchemaFile")
        if envelope is not None and not (
            isinstance(envelope, str)
            and envelope.startswith("spec/schemas/")
            and envelope.endswith(".schema.json")
            and envelope != schema_file
            and (root / envelope).is_file()
        ):
            raise GenerationError(f"{sid}: envelopeSchemaFile must name another existing .schema.json")
        overrides = entry.get("overrides", {})
        if not isinstance(overrides, dict) or not all(
            isinstance(k, str) and (k == "" or k.startswith("/")) for k in overrides
        ):
            raise GenerationError(f"{sid}: overrides must map JSON pointers to fragments")
    return entries


def load_wrapper_ids(root: Path) -> list[str]:
    try:
        text = (root / WRAPPER_IDS).read_text(encoding="utf-8")
    except OSError as error:
        raise GenerationError(f"{WRAPPER_IDS}: {error}; run `cargo xtask codegen --lang python`") from error
    ids = re.findall(r'^ {8}"([^"\\]+)",$', text, flags=re.M)
    if not ids or ids != sorted(set(ids)):
        raise GenerationError(f"{WRAPPER_IDS}: expected a sorted, duplicate-free id list")
    return ids


def load_secret_allowances(root: Path) -> dict[str, set[str]]:
    load_control(root)
    return {sid: set(pointers) for sid, pointers in load_json(root, CONTROL)["secretShapedMembers"].items()}


def secret_findings(value: Any, pointer: str, out: list[str]) -> None:
    if isinstance(value, str):
        if PEM.search(value):
            out.append(f"{pointer or '/'}: string holds a PEM block")
    elif isinstance(value, list):
        for item in value:
            secret_findings(item, pointer + "/*", out)
    elif isinstance(value, dict):
        for key, item in value.items():
            child = pointer_join(pointer, key)
            name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key).lower().replace("-", "_")
            if SECRET_NAME.search(name):
                out.append(child)
            secret_findings(item, child, out)


def examples_for(root: Path, schema_id: str) -> list[Path]:
    return sorted((root / EXAMPLES / escape_schema_id(schema_id)).glob("*.json"))


def generate_schema(root: Path, entry: dict[str, Any]) -> str:
    sid = entry["schema"]
    examples = examples_for(root, sid)
    if not examples:
        raise GenerationError(f"{sid}: no example under {EXAMPLES}/{escape_schema_id(sid)}")
    shape = Shape()
    for example in examples:
        shape.observe(load_json(root, example.relative_to(root)))
    if shape.kinds != {"object"}:
        raise GenerationError(f"{sid}: every example must be a JSON object")
    overrides = entry.get("overrides", {})
    used: set[str] = set()
    try:
        body = render(shape, "", overrides, used, sid)
    except GenerationError as error:
        raise GenerationError(f"{sid}: {error}") from error
    unused = sorted(set(overrides) - used)
    if unused:
        raise GenerationError(f"{sid}: overrides match no location: {unused}")
    rel = entry["schemaFile"][len("spec/schemas/") :]
    document = {"$schema": DRAFT, "$id": ID_BASE + rel, "title": entry["title"]}
    document.update(body)
    return dump(document)


def registry_text(root: Path, entries: list[dict[str, Any]]) -> str:
    registry = load_json(root, REGISTRY)
    owned = {entry["schema"] for entry in entries}
    kept = [row for row in registry["artifacts"] if row.get("schema") not in owned]
    duplicates = {row.get("schema") for row in kept if [r.get("schema") for r in kept].count(row.get("schema")) > 1}
    if duplicates:
        raise GenerationError(f"{REGISTRY}: duplicate rows {sorted(duplicates)}")
    owned_files = {entry["schemaFile"] for entry in entries}
    shared = sorted({row.get("schemaFile") for row in kept} & owned_files)
    if shared:
        raise GenerationError(f"{REGISTRY}: hand-maintained rows use generated schema files {shared}")
    generated = []
    for entry in entries:
        row = {
            "schema": entry["schema"],
            "artifactKind": entry["artifactKind"],
            "introducedBy": entry["introducedBy"],
        }
        if "envelopeSchemaFile" in entry:
            row["schemaFile"] = entry["envelopeSchemaFile"]
            row["payloadSchemaFile"] = entry["schemaFile"]
        else:
            row["schemaFile"] = entry["schemaFile"]
        generated.append(row)
    registry["artifacts"] = kept + generated
    return dump(registry)


def readme_text(root: Path, entries: list[dict[str, Any]]) -> str:
    text = (root / README).read_text(encoding="utf-8")
    lines = [README_BEGIN, "", "Signed-artifact bodies generated from recorded examples by", "`scripts/gen-signed-artifact-schemas.py`:", ""]
    for entry in entries:
        rel = entry["schemaFile"][len("spec/schemas/chio-wire/v1/") :]
        lines.append(f"- `{entry['schema']}`: `{rel}`")
    lines += ["", README_END]
    block = "\n".join(lines)
    if README_BEGIN in text:
        start = text.index(README_BEGIN)
        end = text.index(README_END, start) + len(README_END)
        return text[:start] + block + text[end:]
    return text.rstrip("\n") + "\n\n" + block + "\n"


def is_schema_inventory_path(path: str) -> bool:
    return path.endswith(".schema.json") or (
        path.startswith("spec/schemas/chio-economy/")
        and re.search(r"\.v[1-9][0-9]*\.json\Z", path) is not None
    )


def manifest_text(root: Path, contents: dict[str, bytes]) -> str:
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "spec/schemas"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout.decode("utf-8")
    manifest_rel = str(MANIFEST)
    fixed = {manifest_rel, str(REGISTRY), "spec/schemas/VERSION"}
    paths = {p for p in listed.split("\0") if p and (is_schema_inventory_path(p) or p in fixed)}
    paths |= {p for p in contents if is_schema_inventory_path(p) or p in fixed}
    paths.add(manifest_rel)

    def data(rel: str) -> bytes | None:
        if rel in contents:
            return contents[rel]
        path = root / rel
        return path.read_bytes() if path.is_file() else None

    lines = {}
    for rel in sorted(paths):
        if rel == manifest_rel:
            continue
        payload = data(rel)
        if payload is not None:
            lines[rel] = f"{hashlib.sha256(payload).hexdigest()}  {rel}\n"
    self_hash = hashlib.sha256("".join(lines[r] for r in sorted(lines)).encode("utf-8")).hexdigest()
    lines[manifest_rel] = f"{self_hash}  {manifest_rel}\n"
    return "".join(lines[r] for r in sorted(lines))


def plan(root: Path) -> dict[str, bytes]:
    entries = load_control(root)
    outputs: dict[str, bytes] = {}
    for entry in entries:
        outputs[entry["schemaFile"]] = generate_schema(root, entry).encode("utf-8")
    outputs[str(REGISTRY)] = registry_text(root, entries).encode("utf-8")
    registered = {row["schema"] for row in json.loads(outputs[str(REGISTRY)])["artifacts"]}
    wrapper_ids = load_wrapper_ids(root)
    unregistered = [sid for sid in wrapper_ids if sid not in registered]
    if unregistered:
        raise GenerationError(f"wrapper ids without a registry row: {unregistered}")
    missing = [sid for sid in wrapper_ids if not examples_for(root, sid)]
    if missing:
        raise GenerationError(f"wrapper ids without an example: {missing}")
    escaped = {escape_schema_id(sid) for sid in wrapper_ids}
    orphans = sorted(
        path.name for path in (root / EXAMPLES).iterdir() if path.is_dir() and path.name not in escaped
    ) if (root / EXAMPLES).is_dir() else []
    if orphans:
        raise GenerationError(f"example directories for ids outside the wrapper list: {orphans}")
    outputs[str(README)] = readme_text(root, entries).encode("utf-8")
    outputs[str(MANIFEST)] = manifest_text(root, outputs).encode("utf-8")
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--check", action="store_true", help="fail on drift instead of writing")
    parser.add_argument("--import-captures", type=Path, metavar="DIR", help="refresh captured examples from DIR first")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.import_captures is not None:
        if args.check:
            parser.error("--import-captures writes examples and cannot run with --check")
        try:
            changes = import_captures(root, args.import_captures.resolve())
        except GenerationError as error:
            print(f"gen-signed-artifact-schemas: {error}", file=sys.stderr)
            return 1
        for rel, payload in sorted(changes.items()):
            path = root / rel
            if payload is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
    try:
        outputs = plan(root)
    except GenerationError as error:
        print(f"gen-signed-artifact-schemas: {error}", file=sys.stderr)
        return 1
    stale = [
        rel
        for rel, payload in sorted(outputs.items())
        if not (root / rel).is_file() or (root / rel).read_bytes() != payload
    ]
    if args.check:
        if stale:
            print(
                "gen-signed-artifact-schemas: stale, rerun scripts/gen-signed-artifact-schemas.py:\n  "
                + "\n  ".join(stale),
                file=sys.stderr,
            )
            return 1
        print(f"gen-signed-artifact-schemas: {len(outputs) - 3} generated schemas in sync")
        return 0
    for rel in stale:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(outputs[rel])
    print(f"gen-signed-artifact-schemas: wrote {len(stale)} of {len(outputs)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
