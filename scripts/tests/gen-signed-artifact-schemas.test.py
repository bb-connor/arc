#!/usr/bin/env python3
"""Self-test for scripts/gen-signed-artifact-schemas.py."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(
    os.environ.get(
        "GEN_SIGNED_ARTIFACT_SCHEMAS",
        Path(__file__).resolve().parent.parent / "gen-signed-artifact-schemas.py",
    )
)

failures: list[str] = []

WORK = "spec/schemas/chio-wire/v1/work"
EXAMPLES = "spec/schemas/signed-artifact-examples"
OFFER = f"{EXAMPLES}/chio.work-offer.v1"
README = "# Chio Wire Schemas v1\n\nHand-written text.\n"
HAND_ROW = {
    "schema": "chio.hand.v1",
    "artifactKind": "hand",
    "introducedBy": "hand-v1",
    "schemaFile": "spec/schemas/chio-wire/v1/hand.schema.json",
}


def entry(**extra: object) -> dict[str, object]:
    row: dict[str, object] = {
        "schema": "chio.work-offer.v1",
        "artifactKind": "work_offer",
        "introducedBy": "signing-wrapper-v1",
        "schemaFile": f"{WORK}/work-offer.schema.json",
        "title": "Chio work offer",
    }
    row.update(extra)
    return row


WRAPPER_IDS = "sdks/python/chio-py/src/chio/invariants/_generated_signed_artifact_schemas.py"


def wrapper_ids(*ids: str) -> str:
    lines = "".join(f'        "{sid}",\n' for sid in sorted(ids))
    return f"KNOWN_SIGNED_ARTIFACT_SCHEMAS: frozenset[str] = frozenset(\n    {{\n{lines}    }}\n)\n"


def tree(root: Path, entries, examples: dict[str, object], allow: dict | None = None) -> None:
    files: dict[str, object] = {
        "spec/schemas/signed-artifact-schemas.json": {
            "schema": "chio.signed-artifact-schemas.v1",
            "artifacts": entries,
            "secretShapedMembers": allow or {},
        },
        "spec/schemas/registry.json": {"schema": "chio.signed_artifact_registry.v1", "artifacts": [HAND_ROW]},
        "spec/schemas/chio-wire/v1/hand.schema.json": {"type": "object"},
        f"{EXAMPLES}/chio.hand.v1/hand.json": {"hand": True},
    }
    for name, value in examples.items():
        files[f"{OFFER}/{name}"] = value
    for rel, value in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    ids = {"chio.hand.v1"} | {str(e["schema"]) for e in entries if isinstance(e, dict)}
    (root / WRAPPER_IDS).parent.mkdir(parents=True, exist_ok=True)
    (root / WRAPPER_IDS).write_text(wrapper_ids(*ids), encoding="utf-8")
    (root / "spec/schemas/VERSION").write_text("1\n", encoding="utf-8")
    (root / "spec/schemas/MANIFEST.sha256").write_text("", encoding="utf-8")
    (root / "spec/schemas/chio-wire/v1/README.md").write_text(README, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)


def run(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--root", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def generate(name: str, entries, examples, exit_code: int = 0, mentions: str = "", allow=None):
    directory = tempfile.TemporaryDirectory()
    root = Path(directory.name)
    tree(root, entries, examples, allow)
    result = run(root)
    if result.returncode != exit_code:
        failures.append(f"{name}: expected exit {exit_code}, got {result.returncode}\n{result.stdout}{result.stderr}")
    elif mentions and mentions not in result.stderr:
        failures.append(f"{name}: expected {mentions!r} in\n{result.stderr}")
    return directory, root


def schema_of(root: Path) -> dict:
    return json.loads((root / f"{WORK}/work-offer.schema.json").read_text(encoding="utf-8"))


def capture(directory: Path, schema_id: str, value: object) -> None:
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    target = directory / schema_id.replace("/", "%2F")
    target.mkdir(parents=True, exist_ok=True)
    (target / f"{hashlib.sha256(payload).hexdigest()}.json").write_bytes(payload)


OFFER_MAX = {
    "schema": "chio.work-offer.v1",
    "offer_id": "offer-1",
    "price": {"units": 10, "currency": "USD"},
    "note": "first",
    "tags": ["a"],
    "ratio": 1,
}
OFFER_MIN = {"schema": "chio.work-offer.v1", "offer_id": "offer-2", "price": {"units": 1, "currency": "USD"}, "tags": [], "ratio": 0.5}

holder, root = generate("closed inference", [entry()], {"max.json": OFFER_MAX, "min.json": OFFER_MIN})
schema = schema_of(root)
expected = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/work/work-offer.schema.json",
    "title": "Chio work offer",
    "type": "object",
    "additionalProperties": False,
    "required": ["offer_id", "price", "ratio", "schema", "tags"],
    "properties": {
        "note": {"type": "string"},
        "offer_id": {"type": "string"},
        "price": {
            "type": "object",
            "additionalProperties": False,
            "required": ["currency", "units"],
            "properties": {"currency": {"type": "string"}, "units": {"type": "integer"}},
        },
        "ratio": {"type": "number"},
        "schema": {"const": "chio.work-offer.v1"},
        "tags": {"type": "array", "items": {"type": "string"}},
    },
}
if schema != expected:
    failures.append(f"closed inference: unexpected schema\n{json.dumps(schema, indent=2)}")
registry = json.loads((root / "spec/schemas/registry.json").read_text(encoding="utf-8"))
if registry["artifacts"] != [
    HAND_ROW,
    {
        "schema": "chio.work-offer.v1",
        "artifactKind": "work_offer",
        "introducedBy": "signing-wrapper-v1",
        "schemaFile": f"{WORK}/work-offer.schema.json",
    },
]:
    failures.append(f"closed inference: unexpected registry rows {registry['artifacts']}")
readme = (root / "spec/schemas/chio-wire/v1/README.md").read_text(encoding="utf-8")
if not readme.startswith(README) or "- `chio.work-offer.v1`: `work/work-offer.schema.json`" not in readme:
    failures.append(f"closed inference: README block missing\n{readme}")
manifest = (root / "spec/schemas/MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
paths = [line.split("  ", 1)[1] for line in manifest]
if paths != sorted(paths) or f"{WORK}/work-offer.schema.json" not in paths or "spec/schemas/MANIFEST.sha256" not in paths:
    failures.append(f"closed inference: unexpected manifest paths {paths}")
check = run(root, "--check")
if check.returncode != 0:
    failures.append(f"second run: --check reports drift after generation\n{check.stderr}")
before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file() and ".git" not in p.parts}
again = run(root)
after = {p: p.read_bytes() for p in root.rglob("*") if p.is_file() and ".git" not in p.parts}
if again.returncode != 0 or before != after:
    failures.append("second run: generation is not idempotent")
(root / f"{WORK}/work-offer.schema.json").write_text("{}\n", encoding="utf-8")
drift = run(root, "--check")
if drift.returncode != 1 or "work-offer.schema.json" not in drift.stderr:
    failures.append(f"drift: --check accepted an edited schema\n{drift.stderr}")
if (root / f"{WORK}/work-offer.schema.json").read_text(encoding="utf-8") != "{}\n":
    failures.append("drift: --check wrote to the tree")
holder.cleanup()

holder, root = generate(
    "union and map override",
    [entry(overrides={"/limits": {"map": True}, "/extra": {"type": "string", "maxLength": 8}})],
    {
        "a.json": {"schema": "chio.work-offer.v1", "limits": {"x": 1}, "parent": None, "extra": "e"},
        "b.json": {"schema": "chio.work-offer.v1", "limits": {"y": 2}, "parent": {"id": "p"}, "extra": "f"},
    },
)
schema = schema_of(root)
if schema["properties"]["limits"] != {"type": "object", "additionalProperties": {"type": "integer"}}:
    failures.append(f"map override: {schema['properties']['limits']}")
if schema["properties"]["extra"] != {"type": "string", "maxLength": 8}:
    failures.append(f"fragment override: {schema['properties']['extra']}")
if schema["properties"]["parent"] != {
    "anyOf": [
        {"type": "null"},
        {"type": "object", "additionalProperties": False, "required": ["id"], "properties": {"id": {"type": "string"}}},
    ]
}:
    failures.append(f"null union: {schema['properties']['parent']}")
holder.cleanup()

holder, root = generate("pin only the own id", [entry()], {"a.json": {"schema": "chio.other.v1"}})
if schema_of(root)["properties"]["schema"] != {"type": "string"}:
    failures.append("pin only the own id: a foreign schema value was pinned")
holder.cleanup()

holder, root = generate("import base", [entry()], {"hand.json": {"schema": "chio.work-offer.v1", "offer_id": "h"}})
captures = root / "target/captures"
for value in [
    {"schema": "chio.work-offer.v1", "offer_id": "a", "note": "n"},
    {"schema": "chio.work-offer.v1", "offer_id": "b"},
    {"schema": "chio.work-offer.v1", "offer_id": "c"},
    {"schema": "chio.work-offer.v1", "offer_id": None},
]:
    capture(captures, "chio.work-offer.v1", value)
capture(captures, "chio.hand.v1", {"hand": False})
(root / f"{OFFER}/captured-9.json").write_text("{}\n", encoding="utf-8")
result = run(root, "--import-captures", str(captures))
if result.returncode != 0:
    failures.append(f"import: failed\n{result.stderr}")
examples = sorted(p.name for p in (root / OFFER).glob("*.json"))
if examples != ["captured-1.json", "captured-2.json", "hand.json"]:
    failures.append(f"import: unexpected examples {examples}")
if not (root / f"{EXAMPLES}/chio.hand.v1/captured-1.json").is_file():
    failures.append("import: a hand-written registry row got no captured example")
schema = schema_of(root)
if schema["properties"]["offer_id"] != {"type": ["null", "string"]} or schema.get("required") != ["offer_id", "schema"]:
    failures.append(f"import: the covering subset lost a feature\n{json.dumps(schema, indent=2)}")
again = run(root, "--import-captures", str(captures))
if again.returncode != 0 or run(root, "--check").returncode != 0:
    failures.append("import: a second import is not a no-op")
tampered = captures / "chio.work-offer.v1" / ("0" * 64 + ".json")
tampered.write_text("{}", encoding="utf-8")
bad = run(root, "--import-captures", str(captures))
if bad.returncode != 1 or "not the sha256" not in bad.stderr:
    failures.append(f"import: accepted a body under a wrong digest\n{bad.stderr}")
tampered.unlink()
capture(captures, "chio.work-offer.v1", {"schema": "chio.work-offer.v1", "signerSeed": "00"})
leak = run(root, "--import-captures", str(captures))
if leak.returncode != 1 or "/signerSeed" not in leak.stderr:
    failures.append(f"import: accepted a key-shaped member\n{leak.stderr}")
holder.cleanup()

holder, root = generate("allowed key-shaped member", [entry()], {"a.json": {"schema": "chio.work-offer.v1"}}, allow={"chio.work-offer.v1": ["/api_secret_ref"]})
captures = root / "target/captures"
capture(captures, "chio.work-offer.v1", {"schema": "chio.work-offer.v1", "api_secret_ref": "ref-1"})
if run(root, "--import-captures", str(captures)).returncode != 0:
    failures.append("allowed key-shaped member: refused an allowed member")
capture(captures, "chio.work-offer.v1", {"schema": "chio.work-offer.v1", "note": "-----BEGIN PRIVATE KEY-----"})
pem = run(root, "--import-captures", str(captures))
if pem.returncode != 1 or "PEM" not in pem.stderr:
    failures.append(f"import: accepted a PEM block\n{pem.stderr}")
holder.cleanup()

holder, root = generate("envelope row", [entry(envelopeSchemaFile="spec/schemas/chio-wire/v1/hand.schema.json")], {"a.json": {"a": 1}})
rows = json.loads((root / "spec/schemas/registry.json").read_text(encoding="utf-8"))["artifacts"]
if rows[-1] != {
    "schema": "chio.work-offer.v1",
    "artifactKind": "work_offer",
    "introducedBy": "signing-wrapper-v1",
    "schemaFile": "spec/schemas/chio-wire/v1/hand.schema.json",
    "payloadSchemaFile": f"{WORK}/work-offer.schema.json",
}:
    failures.append(f"envelope row: {rows[-1]}")
holder.cleanup()

for name, entries, examples, mentions in [
    ("empty array refused", [entry()], {"a.json": {"schema": "chio.work-offer.v1", "tags": []}}, "/tags: array is empty"),
    ("missing example refused", [entry()], {}, "no example"),
    ("unused override refused", [entry(overrides={"/nope": {"type": "string"}})], {"a.json": {"a": 1}}, "overrides match no location"),
    ("v2 id refused", [entry(schema="chio.work-offer.v2")], {"a.json": {"a": 1}}, "not a chio v1 schema id"),
    ("unknown control member refused", [entry(status="x")], {"a.json": {"a": 1}}, "unknown members"),
    ("schema file outside chio-wire refused", [entry(schemaFile="spec/schemas/chio-economy/x.schema.json")], {}, "schemaFile must be"),
    ("unsorted control refused", [entry(schema="chio.zz.v1"), entry(schemaFile=f"{WORK}/b.schema.json")], {}, "sorted by schema"),
    ("hand schema file refused", [entry(schemaFile="spec/schemas/chio-wire/v1/hand.schema.json")], {"a.json": {"a": 1}}, "hand-maintained rows use generated schema files"),
    ("missing envelope refused", [entry(envelopeSchemaFile="spec/schemas/chio-wire/v1/nope.schema.json")], {"a.json": {"a": 1}}, "envelopeSchemaFile must name"),
    ("non-object example refused", [entry()], {"a.json": [1]}, "must be a JSON object"),
]:
    holder, _ = generate(name, entries, examples, 1, mentions)
    holder.cleanup()

holder, root = generate("hand row without example", [], {})
(root / f"{EXAMPLES}/chio.hand.v1/hand.json").unlink()
missing = run(root, "--check")
if missing.returncode != 1 or "wrapper ids without an example: ['chio.hand.v1']" not in missing.stderr:
    failures.append(f"hand row without example: accepted\n{missing.stderr}")
holder.cleanup()

holder, root = generate("orphan example directory", [], {"a.json": {"a": 1}}, 1, "example directories for ids outside the wrapper list: ['chio.work-offer.v1']")
holder.cleanup()

holder, root = generate("wrapper id without a row", [], {})
(root / WRAPPER_IDS).write_text(wrapper_ids("chio.hand.v1", "chio.lost.v1"), encoding="utf-8")
lost = run(root, "--check")
if lost.returncode != 1 or "wrapper ids without a registry row: ['chio.lost.v1']" not in lost.stderr:
    failures.append(f"wrapper id without a row: accepted\n{lost.stderr}")
holder.cleanup()

if failures:
    print("\n\n".join(failures), file=sys.stderr)
    sys.exit(1)
print("gen-signed-artifact-schemas self-test: ok")
