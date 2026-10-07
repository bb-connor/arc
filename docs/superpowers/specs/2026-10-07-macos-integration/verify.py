#!/usr/bin/env python3
"""Validate this specification package; never qualify a runtime or native authority."""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent
PLANS = ROOT.parents[1] / "plans" / ROOT.name
REPO = ROOT.parents[3]
MAX_BYTES = 65536
MAX_DEPTH = 16
SAFE_INTEGER = 9007199254740991
PREFIX_PLAN = {
    "PRD": "01-native-operator.md", "UX": "01-native-operator.md",
    "KER": "00-kernel-prerequisites.md", "AUT": "00-kernel-prerequisites.md",
    "ARC": "02-protocol-controller.md", "IPC": "02-protocol-controller.md",
    "VM": "03-vm-project.md", "ES": "05-native-enforcement.md",
    "NE": "05-native-enforcement.md", "RES": "04-resources-publication.md",
    "REC": "06-recovery-evidence.md", "DST": "08-distribution-qualification.md",
    "PRV": "08-distribution-qualification.md", "OPS": "08-distribution-qualification.md",
    "HST": "07-adapters-delegation.md", "DEL": "07-adapters-delegation.md",
    "VER": "08-distribution-qualification.md", "CLW": "07-adapters-delegation.md",
    "RDM": "00-kernel-prerequisites.md",
}
CHECKER = FormatChecker()


@CHECKER.checks("uint64-decimal")
def uint64_decimal(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"0|[1-9][0-9]{0,19}", value)) and int(value) <= 18446744073709551615


def reject_float(value: str) -> None:
    raise ValueError(f"Non-integer numeric literal: {value}")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate key: {key}")
        result[key] = value
    return result


def scalar_bounds(value: object, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("Nesting limit exceeded")
    if isinstance(value, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise ValueError("Unpaired surrogate")
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, int):
        if abs(value) > SAFE_INTEGER:
            raise ValueError("Unsafe JSON integer")
    elif isinstance(value, list):
        for item in value:
            scalar_bounds(item, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            scalar_bounds(key, depth + 1)
            scalar_bounds(item, depth + 1)
    else:
        raise ValueError("Unsupported JSON value")


def wire_decode(data: bytes) -> object:
    if len(data) > MAX_BYTES:
        raise ValueError("Envelope byte limit exceeded")
    value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=unique_object,
                       parse_float=reject_float, parse_constant=reject_float)
    scalar_bounds(value)
    return value


def read_json(path: Path) -> object:
    # Schema/catalog files are not wire envelopes and may be larger/deeper.
    return json.loads(path.read_text(), object_pairs_hook=unique_object,
                      parse_float=reject_float, parse_constant=reject_float)


def pair_matches(request: dict, response: dict) -> bool:
    if any(request.get(k) != response.get(k) for k in ("version", "request_id", "method")):
        return False
    if not response.get("ok"):
        original = request["params"].get("operation_ref")
        echoed = response["error"].get("operation_ref")
        return original is None or echoed is None or original == echoed
    params, result = request["params"], response["result"]
    for key in ("operation_ref", "task_id", "subscription_id", "decision"):
        if key in params and key in result and params[key] != result[key]:
            return False
    return True


def validators() -> dict[str, Draft202012Validator]:
    schemas = {p.name: read_json(p) for p in sorted((ROOT / "contracts").glob("*.schema.json"))}
    registry = Registry()
    for name, value in schemas.items():
        Draft202012Validator.check_schema(value)
        registry = registry.with_resource(name, Resource.from_contents(value))
    return {name: Draft202012Validator(value, registry=registry, format_checker=CHECKER)
            for name, value in schemas.items()}


def requirement_records() -> list[dict]:
    records, identifiers = [], set()
    for path in sorted(ROOT.glob("[0-9][0-9]-*.md")):
        text = path.read_text()
        for line_no, line in enumerate(text.splitlines(), 1):
            match = re.fullmatch(r"\| (MAC-([A-Z]+)-\d{3}) \| (.+) \| (AT-MAC-[A-Z]+-\d{3}) \|", line)
            if not match:
                if re.match(r"\| MAC-[A-Z]+-\d{3} \|", line):
                    raise ValueError(f"Malformed requirement table: {path.name}:{line_no}")
                continue
            identifier, prefix, statement, acceptance = match.groups()
            if identifier in identifiers or acceptance != "AT-" + identifier:
                raise ValueError(f"Duplicate or mismatched requirement: {identifier}")
            if prefix not in PREFIX_PLAN:
                raise ValueError(f"Unmapped requirement prefix: {prefix}")
            definition = re.compile(r"^(?:\| " + re.escape(acceptance) + r" \||#{2,4} " + re.escape(acceptance) + r"(?::|\s))", re.M)
            if len(definition.findall(text)) != 1:
                raise ValueError(f"Acceptance procedure must be defined once: {acceptance}")
            if not (PLANS / PREFIX_PLAN[prefix]).is_file():
                raise ValueError(f"Missing implementation plan: {PREFIX_PLAN[prefix]}")
            identifiers.add(identifier)
            records.append({"id": identifier, "spec": path.name, "line": line_no,
                            "requirement": statement, "acceptance": acceptance,
                            "plan": PREFIX_PLAN[prefix], "acceptance_status": "specified_not_executed"})
    if not records:
        raise ValueError("No requirements found")
    return records


def check_documents() -> int:
    paths = sorted(ROOT.rglob("*.md")) + sorted(PLANS.rglob("*.md"))
    for path in paths:
        text = path.read_text()
        if "\u2014" in text or any(line != line.rstrip() for line in text.splitlines()):
            raise ValueError(f"Prose/whitespace convention violation: {path}")
        if re.search(r"\b(?:TO" + r"DO|TB" + r"D|FIX" + r"ME)\b", text):
            raise ValueError(f"Unresolved placeholder: {path}")
        fences = [line for line in text.splitlines() if re.match(r"^\s*```", line)]
        if len(fences) % 2:
            raise ValueError(f"Unbalanced fences: {path}")
        for link in re.findall(r"\]\(([^\s)]+)\)", text):
            if link.startswith(("http:", "https:", "mailto:")):
                continue
            file_part, _, fragment = link.partition("#")
            target = (path.parent / file_part).resolve() if file_part else path
            if not target.is_relative_to(REPO) or not target.is_file():
                raise ValueError(f"Missing/nonportable local reference {link} in {path}")
            if fragment and target.suffix == ".md":
                headings = re.findall(r"^#{1,6}\s+(.+)$", target.read_text(), re.M)
                anchors = {re.sub(r"[^\w\- ]", "", h.lower()).replace(" ", "-") for h in headings}
                if fragment not in anchors:
                    raise ValueError(f"Missing local anchor {link} in {path}")
    return len(paths)


def check_fixtures(loaded: dict) -> tuple[int, int]:
    catalog = read_json(ROOT / "contracts/fixture-catalog.json")
    if catalog.get("synthetic_only") is not True:
        raise ValueError("Examples must remain synthetic")
    files, coverage, correlated = set(), set(), 0
    for entry in catalog["fixtures"]:
        name = entry["file"]
        if name in files or Path(name).name != name:
            raise ValueError(f"Duplicate/unsafe fixture path: {name}")
        files.add(name)
        data = (ROOT / "examples" / name).read_bytes()
        try:
            value = wire_decode(data)
            valid = not list(loaded[entry["schema"]].iter_errors(value))
        except (ValueError, UnicodeError):
            value, valid = None, False
        if valid != entry["schema_valid"]:
            raise ValueError(f"Unexpected schema result for {name}: {valid}")
        if valid and entry["schema"] == "operator-request.schema.json":
            coverage.add(value["method"])
        if "request" in entry:
            request = wire_decode((ROOT / "examples" / entry["request"]).read_bytes())
            if not valid or pair_matches(request, value) != entry["pair_valid"]:
                raise ValueError(f"Unexpected response correlation result: {name}")
            correlated += 1
        if entry["schema"] == "release-evidence.schema.json" and valid:
            if value["synthetic"] is not True or value["status"] != "candidate":
                raise ValueError("Checked-in release vectors cannot qualify runtime")
    actual = {p.name for p in (ROOT / "examples").glob("*.json")}
    if actual != files:
        raise ValueError(f"Fixture catalog drift: {sorted(actual ^ files)}")
    methods = read_json(ROOT / "contracts/method-catalog.json")
    expected = {entry["name"] for entry in methods["methods"]}
    if coverage != expected or len(expected) != len(methods["methods"]):
        raise ValueError("Missing method request coverage or duplicate catalog method")
    for method in methods["methods"]:
        request = wire_decode((ROOT / "examples" / method["request_example"]).read_bytes())
        response = wire_decode((ROOT / "examples" / method["response_example"]).read_bytes())
        if request["method"] != method["name"] or not pair_matches(request, response):
            raise ValueError(f"Method catalog substitution: {method['name']}")
        # Every method must reject unexpected parameters, independently of hand-written vectors.
        mutant = copy.deepcopy(request)
        mutant["params"]["unexpected_authority"] = True
        if not list(loaded["operator-request.schema.json"].iter_errors(mutant)):
            raise ValueError(f"Open parameter shape: {method['name']}")
    return len(files), correlated


def self_test(loaded: dict) -> int:
    malformed = [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1.1}', b'"\\ud800"',
                 b'"\xff"', b'{"a":9007199254740992}', b' ' * (MAX_BYTES + 1),
                 ("[" * 18 + "0" + "]" * 18).encode()]
    for value in malformed:
        try:
            wire_decode(value)
        except (ValueError, UnicodeError):
            continue
        raise ValueError(f"Strict decoder accepted invalid input: {value[:40]!r}")
    wire_decode(b'{"safe":9007199254740991,"flag":true}')
    if not uint64_decimal("18446744073709551615") or uint64_decimal("18446744073709551616"):
        raise ValueError("Unsigned decimal boundary validation failed")
    request = wire_decode((ROOT / "examples/request-approval-submit.json").read_bytes())
    response = wire_decode((ROOT / "examples/response-approval-submit.json").read_bytes())
    for field in ("request_id", "method", "version"):
        mutant = copy.deepcopy(response)
        mutant[field] = "substituted"
        if pair_matches(request, mutant):
            raise ValueError(f"Correlation accepted substitution: {field}")
    mutant = copy.deepcopy(response)
    mutant["result"]["decision"] = "deny"
    if pair_matches(request, mutant):
        raise ValueError("Correlation accepted different decision")
    mutant = copy.deepcopy(request)
    mutant["params"]["endorsement_ref"]["generation"] = "18446744073709551616"
    if not list(loaded["operator-request.schema.json"].iter_errors(mutant)):
        raise ValueError("Schema accepted overflowing native generation")
    return len(malformed) + 7


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-traceability", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        records = requirement_records()
        trace = {"status": "specified_not_executed", "requirements": records}
        encoded = json.dumps(trace, indent=2, ensure_ascii=False) + "\n"
        path = ROOT / "requirements.json"
        if args.write_traceability:
            path.write_text(encoded)
        elif not path.exists() or path.read_text() != encoded:
            raise ValueError("Traceability drift; review changes then run --write-traceability")
        docs = check_documents()
        loaded = validators()
        fixtures, correlated = check_fixtures(loaded)
        checks = self_test(loaded) if args.self_test else 0
        print(json.dumps({"document_validation": "pass", "documents": docs,
                          "requirements": len(records), "schemas": len(loaded),
                          "synthetic_fixtures": fixtures, "response_pairs": correlated,
                          "self_checks": checks, "runtime_qualification": False}, indent=2))
        return 0
    except (ValueError, OSError, KeyError) as error:
        print(f"Document validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
