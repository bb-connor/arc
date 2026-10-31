#!/usr/bin/env python3
"""Validate the root-authority schema examples.

Every file under `spec/schemas/chio-wire/v1/root_authority/examples/valid/`
must validate against its schema, and every file under `.../invalid/` must
fail for the reason `examples/invalid-expectations.json` pins: the instance
path and keyword of the best-matching error. An example selects its schema by
the file-name stem before the first `.` (`root-policy.alg-hs256.json` selects
`root-policy.schema.json`). When the schema pins a `schema` member, a valid
example must carry that exact value. Every schema in `SCHEMAS` needs at least
one valid example.

References resolve the way the codegen resolves them: a relative `$ref` is a
path relative to the referencing file, and an absolute `$ref` names a `$id`
in the local tree. Nothing is fetched.

Requires `jsonschema==4.26.0` and `referencing==0.37.0`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parents[1]
WIRE = ROOT / "spec/schemas/chio-wire/v1"
EXAMPLES = WIRE / "root_authority/examples"
EXPECTATIONS = EXAMPLES / "invalid-expectations.json"
BASE_URI = "https://chio-protocol.dev/schemas/chio-wire/v1/"

SCHEMAS = {
    "root-anchor": "root_authority/root-anchor.schema.json",
    "delegation-context": "root_authority/delegation-context.schema.json",
    "root-policy": "root_authority/root-policy.schema.json",
    "enterprise-provider-identity": "root_authority/enterprise-provider-identity.schema.json",
    "idp-key-snapshot": "root_authority/idp-key-snapshot.schema.json",
    "verifier-trust": "root_authority/verifier-trust.schema.json",
    "revocation-request": "root_authority/revocation-request.schema.json",
    "revocation-entry": "root_authority/revocation-entry.schema.json",
    "revocation-admin-request": "root_authority/revocation-admin-request.schema.json",
    "presentation": "capability/presentation.schema.json",
    "disclosure": "receipt/disclosure.schema.json",
    "settlement-closure": "receipt/settlement-closure.schema.json",
}


def load_registry() -> tuple[Registry, dict[str, dict]]:
    registry = Registry()
    by_path: dict[str, dict] = {}
    for path in sorted(WIRE.rglob("*.schema.json")):
        rel = path.relative_to(WIRE).as_posix()
        contents = json.loads(path.read_text(encoding="utf-8"))
        declared_id = contents.get("$id")
        path_uri = BASE_URI + rel
        contents["$id"] = path_uri
        resource = Resource.from_contents(contents, default_specification=DRAFT202012)
        registry = registry.with_resource(path_uri, resource)
        if isinstance(declared_id, str) and declared_id != path_uri:
            registry = registry.with_resource(declared_id, resource)
        by_path[rel] = contents
    return registry, by_path


def schema_for(example: Path) -> str:
    stem = example.name.split(".", 1)[0]
    if stem not in SCHEMAS:
        raise SystemExit(f"{example}: no schema for stem {stem!r}")
    return SCHEMAS[stem]


def main() -> int:
    registry, by_path = load_registry()
    validators = {}
    for rel in SCHEMAS.values():
        if rel not in by_path:
            raise SystemExit(f"missing schema {rel}")
        schema = by_path[rel]
        Draft202012Validator.check_schema(schema)
        validators[rel] = Draft202012Validator(schema, registry=registry)

    failures: list[str] = []
    covered: set[str] = set()
    valid_files = sorted((EXAMPLES / "valid").glob("*.json"))
    invalid_files = sorted((EXAMPLES / "invalid").glob("*.json"))
    if not valid_files or not invalid_files:
        raise SystemExit(f"no examples under {EXAMPLES}")

    for example in valid_files:
        rel = schema_for(example)
        instance = json.loads(example.read_text(encoding="utf-8"))
        errors = sorted(validators[rel].iter_errors(instance), key=lambda e: list(e.path))
        if errors:
            failures.append(f"valid example {example.name} fails {rel}: {errors[0].message}")
            continue
        pinned = by_path[rel].get("properties", {}).get("schema", {}).get("const")
        if pinned is not None and instance.get("schema") != pinned:
            failures.append(f"valid example {example.name} does not carry schema {pinned}")
            continue
        covered.add(rel)
        print(f"ok valid   {example.name}")

    expectations = json.loads(EXPECTATIONS.read_text(encoding="utf-8"))
    names = {example.name for example in invalid_files}
    for name in sorted(names ^ set(expectations)):
        failures.append(f"invalid example {name} is not paired with an expectation")
    for example in invalid_files:
        rel = schema_for(example)
        instance = json.loads(example.read_text(encoding="utf-8"))
        error = best_match(validators[rel].iter_errors(instance))
        if error is None:
            failures.append(f"invalid example {example.name} validates against {rel}")
            continue
        location = "".join(f"/{part}" for part in error.absolute_path)
        expected = expectations.get(example.name, {})
        if (location, error.validator) != (expected.get("path"), expected.get("keyword")):
            failures.append(
                f"invalid example {example.name} fails at {location or '(root)'} ({error.validator}), "
                f"expected {expected.get('path') or '(root)'} ({expected.get('keyword')}): {error.message[:120]}"
            )
            continue
        print(f"ok invalid {example.name}: {location or '(root)'}: {error.validator}")

    for rel in sorted(set(SCHEMAS.values()) - covered):
        failures.append(f"schema {rel} has no passing valid example")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(
        f"root-authority schema examples: {len(valid_files)} valid and "
        f"{len(invalid_files)} invalid examples behave as expected"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
