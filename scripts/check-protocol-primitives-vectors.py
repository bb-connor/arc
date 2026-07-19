#!/usr/bin/env python3

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "spec/schemas/chio-wire/v1"
VECTOR_ROOT = ROOT / "tests/bindings/vectors/security/protocol-primitives"
WIRE_SCHEMA_BASE = "https://chio.world/schemas/chio-wire/v1/"
EXPECTED_POSITIVES = 18
EXPECTED_MUTATIONS = 20
EXPECTED_NEGATIVES = 21
EXPECTED_STRUCTURAL_REJECTIONS = 8
EXPECTED_SEMANTIC_REJECTIONS = 13


class ContractError(RuntimeError):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"{path}: invalid JSON: {error}") from error


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def schema_registry() -> tuple[Registry, dict[str, tuple[Path, Any]]]:
    resources: list[tuple[str, Resource]] = []
    schemas: dict[str, tuple[Path, Any]] = {}
    for path in sorted(SCHEMA_ROOT.rglob("*.json")):
        schema = load_json(path)
        if not isinstance(schema, dict) or not isinstance(schema.get("$id"), str):
            continue
        schema_id = schema["$id"]
        if schema_id in schemas:
            raise ContractError(f"duplicate schema ID {schema_id}")
        schemas[schema_id] = (path, schema)
        resources.append((schema_id, Resource.from_contents(schema)))
    return Registry().with_resources(resources), schemas


def schema_accepts(
    schema_id: str,
    instance: Any,
    registry: Registry,
    schemas: dict[str, tuple[Path, Any]],
) -> bool:
    if schema_id not in schemas:
        raise ContractError(f"unregistered schema ID {schema_id}")
    _, schema = schemas[schema_id]
    return not any(Draft202012Validator(schema, registry=registry).iter_errors(instance))


def pointer_segments(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        raise ContractError(f"mutation pointer is not absolute: {pointer}")
    return [segment.replace("~1", "/").replace("~0", "~") for segment in pointer[1:].split("/")]


def apply_mutation(value: Any, mutation: dict[str, Any]) -> Any:
    operation = mutation.get("op")
    if operation == "append_bytes":
        raise ContractError("append_bytes must be applied to the source byte sequence")
    path = mutation.get("path")
    if not isinstance(path, str):
        raise ContractError("JSON mutation has no string path")
    segments = pointer_segments(path)
    parent = value
    for segment in segments[:-1]:
        parent = parent[int(segment)] if isinstance(parent, list) else parent[segment]
    target = segments[-1]
    if operation in {"add", "replace"}:
        if "value" not in mutation:
            raise ContractError(f"{operation} mutation has no value")
        if isinstance(parent, list):
            parent[int(target)] = mutation["value"]
        else:
            parent[target] = mutation["value"]
    elif operation == "remove":
        if isinstance(parent, list):
            del parent[int(target)]
        else:
            del parent[target]
    else:
        raise ContractError(f"unsupported mutation operation {operation}")
    return value


def mutated_bytes(base: bytes, mutation: dict[str, Any]) -> bytes:
    if mutation.get("op") == "append_bytes":
        suffix = mutation.get("hex")
        if not isinstance(suffix, str):
            raise ContractError("append_bytes mutation has no hex payload")
        try:
            return base + bytes.fromhex(suffix)
        except ValueError as error:
            raise ContractError(f"append_bytes payload is invalid hex: {suffix}") from error
    return canonical_json_bytes(apply_mutation(json.loads(base), mutation))


def validate() -> dict[str, Any]:
    registry, schemas = schema_registry()
    index = load_json(VECTOR_ROOT / "index.json")
    positives = index.get("positive") if isinstance(index, dict) else None
    negatives = index.get("negative") if isinstance(index, dict) else None
    if not isinstance(positives, list) or len(positives) != EXPECTED_POSITIVES:
        raise ContractError(f"positive inventory must contain exactly {EXPECTED_POSITIVES} entries")
    if not isinstance(negatives, list) or len(negatives) != 2:
        raise ContractError("negative inventory must contain the direct vector and mutation corpus")

    positive_ids: set[str] = set()
    positive_files: set[str] = set()
    schema_by_file: dict[str, str] = {}
    for entry in positives:
        if not isinstance(entry, dict):
            raise ContractError("positive inventory entry is not an object")
        identifier = entry.get("id")
        relative = entry.get("file")
        schema_id = entry.get("schema_id")
        if not all(isinstance(item, str) for item in (identifier, relative, schema_id)):
            raise ContractError("positive inventory entry has non-string fields")
        if identifier in positive_ids or relative in positive_files:
            raise ContractError(f"duplicate positive inventory entry {identifier}")
        positive_ids.add(identifier)
        positive_files.add(relative)
        schema_by_file[relative] = schema_id
        path = VECTOR_ROOT / relative
        source = path.read_bytes()
        instance = json.loads(source)
        if canonical_json_bytes(instance) != source.removesuffix(b"\n"):
            raise ContractError(f"{path}: positive vector is not canonical JSON")
        if not schema_accepts(schema_id, instance, registry, schemas):
            raise ContractError(f"{path}: positive vector fails {schema_id}")

    direct = negatives[0]
    if not isinstance(direct, dict):
        raise ContractError("direct negative inventory entry is not an object")
    direct_path = VECTOR_ROOT / direct["file"]
    direct_instance = load_json(direct_path)
    direct_schema_valid = schema_accepts(
        direct["schema_id"], direct_instance, registry, schemas
    )
    if direct_schema_valid:
        raise ContractError(f"{direct_path}: direct negative vector passed its schema")

    corpus = load_json(VECTOR_ROOT / negatives[1]["file"])
    cases = corpus.get("cases") if isinstance(corpus, dict) else None
    if not isinstance(cases, list) or len(cases) != EXPECTED_MUTATIONS:
        raise ContractError(f"mutation corpus must contain exactly {EXPECTED_MUTATIONS} cases")
    case_ids: set[str] = set()
    case_results: list[dict[str, Any]] = []
    structural_rejections = 1
    semantic_rejections = 0
    for case in cases:
        if not isinstance(case, dict):
            raise ContractError("mutation case is not an object")
        identifier = case.get("id")
        base = case.get("base")
        mutation = case.get("mutation")
        expected = case.get("expected")
        if not isinstance(identifier, str) or identifier in case_ids:
            raise ContractError(f"duplicate or invalid mutation ID {identifier}")
        case_ids.add(identifier)
        if not isinstance(base, str) or base not in schema_by_file:
            raise ContractError(f"{identifier}: mutation base is not a positive vector")
        if not isinstance(mutation, dict) or not isinstance(expected, dict):
            raise ContractError(f"{identifier}: malformed mutation or expectation")
        raw = mutated_bytes((VECTOR_ROOT / base).read_bytes().removesuffix(b"\n"), mutation)
        try:
            instance = json.loads(raw)
            parse_valid = True
        except json.JSONDecodeError:
            instance = None
            parse_valid = False
        if parse_valid != expected.get("json_parse_valid"):
            raise ContractError(f"{identifier}: JSON parse classification drifted")
        schema_valid = parse_valid and schema_accepts(
            schema_by_file[base], instance, registry, schemas
        )
        if schema_valid != expected.get("json_schema_valid"):
            raise ContractError(f"{identifier}: JSON Schema classification drifted")
        if expected.get("semantic_valid") is not False:
            raise ContractError(f"{identifier}: mutation is not classified semantic-invalid")
        case_results.append(
            {
                "id": identifier,
                "json_parse_valid": parse_valid,
                "json_schema_valid": schema_valid,
                "semantic_valid": False,
            }
        )
        if schema_valid:
            semantic_rejections += 1
        else:
            structural_rejections += 1

    if structural_rejections != EXPECTED_STRUCTURAL_REJECTIONS:
        raise ContractError(
            f"structural rejection count is {structural_rejections}, expected {EXPECTED_STRUCTURAL_REJECTIONS}"
        )
    if semantic_rejections != EXPECTED_SEMANTIC_REJECTIONS:
        raise ContractError(
            f"semantic rejection count is {semantic_rejections}, expected {EXPECTED_SEMANTIC_REJECTIONS}"
        )
    if structural_rejections + semantic_rejections != EXPECTED_NEGATIVES:
        raise ContractError(f"negative corpus must contain exactly {EXPECTED_NEGATIVES} cases")
    return {
        "direct": {
            "id": direct["id"],
            "json_parse_valid": True,
            "json_schema_valid": direct_schema_valid,
            "semantic_valid": False,
        },
        "cases": case_results,
    }


def main() -> int:
    try:
        report = validate()
    except (ContractError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"protocol primitive vector contract failed: {error}", file=sys.stderr)
        return 1
    if sys.argv[1:] == ["--report-json"]:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    if sys.argv[1:]:
        print(f"unsupported arguments: {' '.join(sys.argv[1:])}", file=sys.stderr)
        return 1
    print(
        "protocol primitive vectors passed "
        f"({EXPECTED_POSITIVES} positive, {EXPECTED_STRUCTURAL_REJECTIONS} structural negative, "
        f"{EXPECTED_SEMANTIC_REJECTIONS} semantic negative)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
