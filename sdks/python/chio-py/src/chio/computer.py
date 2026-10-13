from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .errors import ChioInvariantError, parse_json_text_unique_keys
from .invariants.json import canonicalize_json

DESCRIPTION_SCHEMA = "chio.computer.description.v1"
COMPILED_SCHEMA = "chio.computer.compiled-description.v1"
MAX_BYTES = 2 * 1024 * 1024
MAX_TRANSFER = 64 * 1024 * 1024
MAX_SAFE_INTEGER = 9007199254740991
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class DescriptionError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(f"Computer description rejected: {code}")


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise DescriptionError(code)


def _object(value: Any, keys: str) -> None:
    _require(isinstance(value, dict) and set(value) == set(keys.split()), "json_shape")


def _array(value: Any, limit: int, code: str) -> None:
    _require(isinstance(value, list), "json_shape")
    _require(len(value) <= limit, code)


def _id(value: Any) -> None:
    _require(isinstance(value, str) and _ID.fullmatch(value) is not None, "identifier")


def _hash(value: Any) -> None:
    _require(isinstance(value, str) and _HASH.fullmatch(value) is not None, "digest_format")


def _generation(value: Any) -> None:
    _require(type(value) is int and 0 < value <= MAX_SAFE_INTEGER, "generation")


def _namespace(value: Any) -> None:
    _require(isinstance(value, str) and value.isascii() and len(value) <= 256 and value.startswith("/") and value != "/", "namespace")
    _require(all(_ID.fullmatch(part) and part not in (".", "..") for part in value.split("/")[1:]), "namespace")


def _content(value: Any) -> int:
    _object(value, "ownerDomain artifactId sha256 byteLength")
    _id(value["ownerDomain"])
    _id(value["artifactId"])
    _hash(value["sha256"])
    size = value["byteLength"]
    _require(type(size) is int and 0 <= size <= MAX_TRANSFER, "transfer_bytes")
    return size


def _profiles(values: Any) -> int:
    _array(values, 64, "profiles")
    total = sum(_content(value) for value in values)
    _require(len({(value["ownerDomain"], value["artifactId"]) for value in values}) == len(values), "duplicate_profile")
    return total


def _shape(value: Any) -> int:
    _require(isinstance(value, dict), "json_shape")
    if value.get("kind") == "value":
        _object(value, "kind schema")
        return _content(value["schema"])
    _require(value.get("kind") == "all_success", "json_shape")
    _object(value, "kind schemas")
    _array(value["schemas"], 16, "parent_count")
    _require(len(value["schemas"]) >= 2, "parent_count")
    return sum(_content(item) for item in value["schemas"])


def _operations(value: Any) -> None:
    _array(value, 3, "operations")
    _require(bool(value) and all(type(item) is str and item in ("read", "write", "invoke") for item in value), "operations")
    _require(len(set(value)) == len(value), "operations")


def _resources(values: Any) -> int:
    _array(values, 256, "resource_count")
    total = 0
    seen = set()
    for value in values:
        _object(value, "namespace resourceId ownerDomain generation provider operations version")
        _namespace(value["namespace"])
        _require(value["namespace"] not in seen, "duplicate_namespace")
        seen.add(value["namespace"])
        _id(value["resourceId"])
        _id(value["ownerDomain"])
        _generation(value["generation"])
        _operations(value["operations"])
        total += _content(value["provider"])
        version = value["version"]
        _require(isinstance(version, dict), "json_shape")
        if version.get("kind") == "live":
            _object(version, "kind")
        else:
            _object(version, "kind content")
            _require(version["kind"] == "pinned", "json_shape")
            total += _content(version["content"])
    return total


def _digest(domain: str, body: Any) -> str:
    return hashlib.sha256(canonicalize_json({"domain": domain, "body": body}).encode()).hexdigest()


def _wire_bound(value: Any, bound: int) -> None:
    size = 0
    for chunk in json.JSONEncoder(ensure_ascii=False, separators=(",", ":")).iterencode(value):
        size += len(chunk.encode())
        _require(size <= bound, "wire_bytes")


def namespace_digest(resources: list) -> str:
    _require(_resources(resources) <= MAX_TRANSFER, "transfer_bytes")
    return _digest("chio.computer.namespace.v1", resources)


def _revision_fields(revision: Any) -> int:
    _object(revision, "computerId ownerDomain revisionId namespaceDigest boot input inputSchema resources profileRefs creationOperation")
    for field in ("computerId", "ownerDomain", "creationOperation"):
        _id(revision[field])
    _hash(revision["namespaceDigest"])
    return (_content(revision["boot"]) + _content(revision["input"]) + _shape(revision["inputSchema"])
            + _profiles(revision["profileRefs"]) + _resources(revision["resources"]))


def revision_digest(revision: dict) -> str:
    _require(_revision_fields(revision) <= MAX_TRANSFER, "transfer_bytes")
    if revision["revisionId"] != "":
        _hash(revision["revisionId"])
    return _digest("chio.computer.revision.v1", {key: value for key, value in revision.items() if key != "revisionId"})


def validate_computer(description: dict) -> int:
    _object(description, "schema record revision image")
    _require(description["schema"] == DESCRIPTION_SCHEMA, "description_schema")
    record, revision, image = description["record"], description["revision"], description["image"]
    _object(record, "computerId ownerDomain parentRevision headRevision lifecycleGeneration profileRefs")
    _object(image, "revisionId boot input resourceManifestDigest requirements")
    _id(record["computerId"])
    _id(record["ownerDomain"])
    _generation(record["lifecycleGeneration"])
    _hash(record["headRevision"])
    if record["parentRevision"] is not None:
        _hash(record["parentRevision"])
    total = _profiles(record["profileRefs"]) + _revision_fields(revision)
    _hash(revision["revisionId"])
    _hash(image["revisionId"])
    _hash(image["resourceManifestDigest"])
    total += _content(image["boot"]) + _content(image["input"]) + _profiles(image["requirements"])
    _require(total <= MAX_TRANSFER, "transfer_bytes")
    _require(record["computerId"] == revision["computerId"] and record["ownerDomain"] == revision["ownerDomain"]
             and record["headRevision"] == revision["revisionId"] and record["profileRefs"] == revision["profileRefs"]
             and image["revisionId"] == revision["revisionId"] and image["boot"] == revision["boot"]
             and image["input"] == revision["input"] and image["resourceManifestDigest"] == revision["namespaceDigest"], "revision_binding")
    _require(all(profile in revision["profileRefs"] for profile in image["requirements"]), "profile_subset")
    _require(revision["namespaceDigest"] == namespace_digest(revision["resources"]), "namespace_digest")
    _require(revision["revisionId"] == revision_digest(revision), "revision_digest")
    return total


def _integer_token(token: str) -> str:
    _require(len(token) <= 1024, "json_number")
    match = re.fullmatch(r"(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?", token)
    _require(match is not None, "json_shape")
    sign, whole, fraction, exponent = match.groups()
    fraction = fraction or ""
    digits = (whole + fraction).lstrip("0")
    if not digits:
        return "0"
    _require(not sign, "json_number")
    exponent = exponent or "0"
    exponent_digits = exponent.lstrip("+-").lstrip("0")
    _require(len(exponent_digits) <= 4, "json_number")
    power = int(exponent) - len(fraction)
    if power < 0:
        _require(-power <= len(digits) and digits[power:] == "0" * -power, "json_number")
        digits = digits[:power]
    else:
        _require(len(digits) + power <= 16, "json_number")
        digits += "0" * power
    _require(len(digits) <= 16 and (len(digits) < 16 or digits <= "9007199254740991"), "json_number")
    return digits


def _normalize_numbers(text: str, bound: int) -> str:
    tokens = re.compile(r'"(?:[^"\\]|\\.)*"|-?[0-9][0-9.eE+\-]*')
    result = tokens.sub(lambda match: match[0] if match[0].startswith('"') else _integer_token(match[0]), text)
    _require(len(result.encode()) <= bound, "wire_bytes")
    return result


def _utf8_size(value: str) -> int:
    try:
        return len(value.encode())
    except UnicodeError as error:
        raise DescriptionError("json_shape") from error


def _parse_bounded(text: str, bound: int, entry_limit: int) -> Any:
    _require(type(text) is str, "json_shape")
    _require(_utf8_size(text) <= bound, "wire_bytes")
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '\"':
                quoted = False
        elif char == '\"':
            quoted = True
        elif char in "[{":
            depth += 1
            _require(depth <= 96, "json_depth")
        elif char in "]}":
            depth -= 1
    try:
        normalized = _normalize_numbers(text, bound)
        value = parse_json_text_unique_keys(normalized)
    except DescriptionError:
        raise
    except (ChioInvariantError, ValueError, RecursionError) as error:
        raise DescriptionError("json_shape") from error
    pending = [value]
    entries = 0
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            _require(_utf8_size(item) <= 1024, "string_bytes")
        elif isinstance(item, (dict, list)):
            entries += len(item)
            _require(entries <= entry_limit, "json_entries")
            if isinstance(item, dict):
                _require(all(_utf8_size(key) <= 1024 for key in item), "string_bytes")
                pending.extend(item.values())
            else:
                pending.extend(item)
    return value


def parse_description(text: str) -> Any:
    return _parse_bounded(text, MAX_BYTES, 65536)


def parse_compiled_description(text: str) -> Any:
    return _parse_bounded(text, 8 * 1024 * 1024, 262144)


@dataclass(frozen=True)
class ProgramExpr:
    description: dict

    @staticmethod
    def leaf(descriptor: dict) -> ProgramExpr:
        return ProgramExpr({"op": "leaf", "leaf": descriptor})

    def __and__(self, other: ProgramExpr) -> ProgramExpr:
        return parallel(self, other)

    def __or__(self, other: ProgramExpr) -> ProgramExpr:
        return self.pipe(other)

    def pipe(self, other: ProgramExpr) -> ProgramExpr:
        return ProgramExpr({"op": "sequence", "items": [self.description, other.description]})


def parallel(*items: ProgramExpr) -> ProgramExpr:
    return ProgramExpr({"op": "parallel", "items": [item.description for item in items]})


def _leaf(leaf: Any) -> int:
    _require(isinstance(leaf, dict), "json_shape")
    if leaf.get("kind") == "task":
        _object(leaf, "kind contract inputSchema outputSchema acceptance harnessRequirements resources")
        total = _content(leaf["contract"]) + _content(leaf["acceptance"]) + _profiles(leaf["harnessRequirements"])
        _require(bool(leaf["harnessRequirements"]), "harness_requirements")
    else:
        _object(leaf, "kind bundle entrypoint inputSchema outputSchema resources")
        _require(leaf["kind"] == "program", "json_shape")
        total = _content(leaf["bundle"])
        _id(leaf["entrypoint"])
    total += _shape(leaf["inputSchema"]) + _content(leaf["outputSchema"])
    _array(leaf["resources"], 256, "resource_count")
    seen = set()
    for resource in leaf["resources"]:
        _object(resource, "namespace resourceId ownerDomain generation operations")
        _namespace(resource["namespace"])
        _require(resource["namespace"] not in seen, "duplicate_namespace")
        seen.add(resource["namespace"])
        _id(resource["resourceId"])
        _id(resource["ownerDomain"])
        _generation(resource["generation"])
        _operations(resource["operations"])
    return total


def _preflight(expression: Any) -> int:
    pending = [(expression, 1)]
    nodes = leaves = total = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        _require(nodes <= 2047, "expression_nodes")
        _require(depth <= 32, "expression_depth")
        _require(isinstance(item, dict), "json_shape")
        if item.get("op") == "leaf":
            _object(item, "op leaf")
            leaves += 1
            _require(leaves <= 1024, "leaf_count")
            total += _leaf(item["leaf"])
            _require(total <= MAX_TRANSFER, "transfer_bytes")
        else:
            _object(item, "op items")
            _require(item["op"] in ("parallel", "sequence"), "json_shape")
            _array(item["items"], 2047, "expression_nodes")
            _require(len(item["items"]) >= 2 and nodes + len(pending) + len(item["items"]) <= 2047, "expression_nodes")
            pending.extend((child, depth + 1) for child in reversed(item["items"]))
    return total


def _normalize(expression: dict) -> dict:
    if expression["op"] == "leaf":
        return copy.deepcopy(expression)
    items = []
    for child in expression["items"]:
        normalized = _normalize(child)
        if normalized["op"] == expression["op"]:
            items.extend(normalized["items"])
        else:
            items.append(normalized)
    return {"op": expression["op"], "items": items}


def compile_program(computer: dict, request_id: str, expression: dict | ProgramExpr) -> dict:
    if isinstance(expression, ProgramExpr):
        expression = expression.description
    _id(request_id)
    total = _preflight(expression)
    _require(validate_computer(computer) + total <= MAX_TRANSFER, "transfer_bytes")
    _wire_bound([computer, request_id, expression], MAX_BYTES)
    expression = _normalize(expression)
    program_digest = _digest("chio.computer.program.v1", expression)
    occurrences = []
    edges = 0

    def walk(item: dict, path: list[int], input_shape: dict, parents: list[str]) -> tuple[dict, list[str]]:
        nonlocal edges
        if item["op"] == "leaf":
            leaf = item["leaf"]
            _require(leaf["inputSchema"] == input_shape, "input_schema")
            _require(len(parents) <= 16, "parent_count")
            edges += len(parents)
            _require(edges <= 4096, "dependency_edges")
            for required in leaf["resources"]:
                binding = next((candidate for candidate in computer["revision"]["resources"] if candidate["namespace"] == required["namespace"]), None)
                _require(binding is not None and all(binding[key] == required[key] for key in ("resourceId", "ownerDomain", "generation"))
                         and all(operation in binding["operations"] for operation in required["operations"]), "resource_subset")
            identity = _digest("chio.computer.occurrence.v1", {
                "requestId": request_id, "computerId": computer["record"]["computerId"], "ownerDomain": computer["record"]["ownerDomain"],
                "revisionId": computer["revision"]["revisionId"], "programDigest": program_digest, "path": path,
            })
            occurrences.append({"occurrenceId": identity, "path": path, "parents": list(parents), "leaf": copy.deepcopy(leaf)})
            return {"kind": "value", "schema": copy.deepcopy(leaf["outputSchema"])}, [identity]
        if item["op"] == "parallel":
            schemas, outputs = [], []
            for index, child in enumerate(item["items"]):
                shape, terminal = walk(child, path + [index], input_shape, parents)
                schemas.extend([shape["schema"]] if shape["kind"] == "value" else shape["schemas"])
                outputs.extend(terminal)
                _require(len(schemas) <= 16, "parent_count")
            return {"kind": "all_success", "schemas": schemas}, outputs
        shape, terminal = input_shape, parents
        for index, child in enumerate(item["items"]):
            shape, terminal = walk(child, path + [index], shape, terminal)
        return shape, terminal

    output, _ = walk(expression, [], computer["revision"]["inputSchema"], [])
    result = {
        "schema": COMPILED_SCHEMA, "requestId": request_id, "computerId": computer["record"]["computerId"],
        "ownerDomain": computer["record"]["ownerDomain"], "revisionId": computer["revision"]["revisionId"],
        "lifecycleGeneration": computer["record"]["lifecycleGeneration"], "programDigest": program_digest,
        "expression": expression, "occurrences": occurrences, "outputSchema": output,
    }
    result["digest"] = _digest("chio.computer.compiled.v1", result)
    _wire_bound(result, 8 * 1024 * 1024)
    return result


def validate_compiled_program(computer: dict, request_id: str, expression: dict | ProgramExpr, supplied: dict) -> dict:
    _object(supplied, "schema requestId computerId ownerDomain revisionId lifecycleGeneration programDigest expression occurrences outputSchema digest")
    _require(supplied["schema"] == COMPILED_SCHEMA, "description_schema")
    for field in ("requestId", "computerId", "ownerDomain"):
        _id(supplied[field])
    for field in ("revisionId", "programDigest", "digest"):
        _hash(supplied[field])
    _generation(supplied["lifecycleGeneration"])
    _require(_shape(supplied["outputSchema"]) <= MAX_TRANSFER, "transfer_bytes")
    _preflight(supplied["expression"])
    _array(supplied["occurrences"], 1024, "leaf_count")
    total = 0
    for occurrence in supplied["occurrences"]:
        _object(occurrence, "occurrenceId path parents leaf")
        _hash(occurrence["occurrenceId"])
        _array(occurrence["path"], 32, "plan_bounds")
        _require(all(type(index) is int and 0 <= index < 2047 for index in occurrence["path"]), "plan_bounds")
        _array(occurrence["parents"], 16, "plan_bounds")
        for parent in occurrence["parents"]:
            _hash(parent)
        total += _leaf(occurrence["leaf"])
        _require(total <= MAX_TRANSFER, "transfer_bytes")
    _wire_bound(supplied, 8 * 1024 * 1024)
    result = compile_program(computer, request_id, expression)
    _require(result == supplied, "compiled_mismatch")
    return result
