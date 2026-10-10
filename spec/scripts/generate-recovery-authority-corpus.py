#!/usr/bin/env python3
"""Preserve historical signed bytes and publish deterministic wire profiles."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

PROFILE_PREFIX = "current-origin/"
UTF8_PROFILE_PREFIX = "utf8-bound/"


def canonical(value: object) -> str:
    # The native export uses ASCII object keys and unsigned safe metadata.
    # Preserve exact embedded strings; this generator never signs an artifact.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def current_vectors(native: dict) -> list[dict]:
    contracts = {
        "action": native["action"], "requirements": native["requirements"],
        "grant_binding": native["grant"]["body"]["recovery"],
        "approval_intent": native["approval_intent"], "grant": native["grant"],
        "coverage": native["coverage"][0], "provider_finality": native["provider_finality"],
        "provider_body": native["provider_finality"]["body"], "command": native["command"],
        "support_issue_effect": native["support_issue_effect"],
        "support_issue_input": native["support_issue_input"],
        "command_response": native["command_response"], "command_result": native["command_result"],
        "review_document": native["review_document"],
    }
    rows = [{"name": PROFILE_PREFIX + name + "-positive", "contract": name,
             "valid": True, "schema_valid": True, "wire": canonical(value),
             "reason": "Current native origin-bound export; native context remains authoritative."}
            for name, value in contracts.items()]
    action = native["action"]
    if not isinstance(action.get("origin"), dict):
        raise ValueError("native export is missing the mandatory current origin")
    wire = canonical(action)

    def refused(name: str, *, value: object = None, raw: str | None = None,
                schema_valid: bool = False) -> None:
        rows.append({"name": PROFILE_PREFIX + name, "contract": "action",
                     "valid": False, "schema_valid": schema_valid,
                     "wire": raw if raw is not None else canonical(value),
                     "reason": "Closed current origin profile refusal."})

    def mutation(name: str, change) -> None:
        value = copy.deepcopy(action)
        change(value)
        refused(name, value=value)

    mutation("origin-null", lambda value: value.__setitem__("origin", None))
    mutation("origin-empty", lambda value: value.__setitem__("origin", {}))
    mutation("origin-array", lambda value: value.__setitem__("origin", [value["origin"]]))
    mutation("origin-unknown-member", lambda value: value["origin"].__setitem__("claimed_authority", True))
    for member in ("operation", "request_id", "closure"):
        mutation("origin-missing-" + member, lambda value, member=member: value["origin"].pop(member))
    for version, name in ((0, "zero"), (2**53, "unsafe")):
        mutation("origin-operation-version-" + name,
                 lambda value, version=version: value["origin"]["operation"].__setitem__("operation_version", version))
    mutation("origin-operation-unknown-member", lambda value: value["origin"]["operation"].__setitem__("other", True))
    mutation("origin-closure-newline", lambda value: value["origin"].__setitem__("closure", "closure\n"))
    mutation("origin-request-id-newline", lambda value: value["origin"].__setitem__("request_id", "request\n"))
    version_token = '"operation_version":' + str(action["origin"]["operation"]["operation_version"])
    if wire.count(version_token) != 1:
        raise ValueError("origin version mutation is ambiguous")
    for token, name in (("1.0", "float-token"), ("1e0", "exponent-token")):
        refused("origin-operation-version-" + name,
                raw=wire.replace(version_token, '"operation_version":' + token, 1), schema_valid=True)
    origin = canonical(action["origin"])
    refused("duplicate-origin", raw=wire.replace('"origin":' + origin,
            '"origin":null,"origin":' + origin, 1), schema_valid=True)
    closure = canonical(action["origin"]["closure"])
    refused("duplicate-origin-closure", raw=wire.replace('"closure":' + closure,
            '"closure":' + closure + ',"closure":"substituted-closure"', 1), schema_valid=True)
    refused("current-action-noncanonical", raw=json.dumps(action, indent=1, sort_keys=True), schema_valid=True)
    return rows


def build_corpus(previous: dict, native: dict) -> dict:
    if previous.get("format_version") != 1:
        raise ValueError("unsupported authority corpus version")
    legacy = [copy.deepcopy(row) for row in previous["vectors"]
              if not row["name"].startswith((PROFILE_PREFIX, UTF8_PROFILE_PREFIX))]
    current = current_vectors(native)
    utf8 = utf8_vectors(native)
    names = [row["name"] for row in legacy + current + utf8]
    if len(names) != len(set(names)):
        raise ValueError("authority vector names are not unique")
    result = copy.deepcopy(previous)
    result["vectors"] = legacy + current + utf8
    result["profiles"] = {
        "legacy_compatibility": {
            "vectors": [row["name"] for row in legacy],
            "origin": "Omitted legacy signed actions; decoding does not establish current serving authority.",
        },
        "native_origin_bound": {
            "vectors": [row["name"] for row in current], "source": "authority-positive.json",
            "origin": "Mandatory for fresh native authorization; omitted legacy origin is never fresh authority.",
        },
        "decoded_utf8_bounds": {
            "vectors": [row["name"] for row in utf8], "source": "authority-positive.json",
            "bounds": "Unsigned data contracts require decoded UTF-8 byte ceilings in addition to scalar and wire limits.",
        },
    }
    return result


def utf8_vectors(native: dict) -> list[dict]:
    """Exercise byte boundaries in unsigned DTOs without fabricating signatures."""
    rows = []
    limits = {"title": 256, "body": 16384, "resource": 2048,
              "provider": 256, "account": 256, "capability": 256,
              "recipient": 256, "purpose": 256, "owner": 256,
              "reader": 256, "compartment": 256}
    for role, limit in limits.items():
        for suffix, valid, size in [("exact", True, limit), ("oversized", False, limit + 2)]:
            text = "é" * (size // 2)
            if role in {"title", "body"}:
                contract, value = "support_issue_input", copy.deepcopy(native["support_issue_input"])
                value[role] = text
            elif role == "resource":
                contract, value = "support_issue_effect", copy.deepcopy(native["support_issue_effect"])
                value[role] = text
            elif role in {"provider", "account"}:
                contract, value = "provider_body", copy.deepcopy(native["provider_finality"]["body"])
                value[role] = text
            elif role == "capability":
                contract, value = "action", copy.deepcopy(native["action"])
                value["capability_id"] = text
            else:
                contract, value = "requirements", copy.deepcopy(native["requirements"])
                if role in {"recipient", "purpose"}:
                    value[role] = text
                elif role == "owner":
                    value["source_label"] = {"kind": "known", "owners": {text: [text]}, "compartments": []}
                elif role == "reader":
                    value["source_label"] = {"kind": "known", "owners": {"owner": ["owner", text]}, "compartments": []}
                else:
                    value["source_label"] = {"kind": "known", "owners": {}, "compartments": [text]}
            rows.append({"name": UTF8_PROFILE_PREFIX + role + "-" + suffix,
                         "contract": contract, "valid": valid, "schema_valid": valid,
                         "wire": canonical(value),
                         "reason": "Native " + role + " decoded UTF-8 boundary: " + str(size) + " bytes, ceiling " + str(limit) + "."})
    return rows


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    corpus_path = root / "spec/vectors/recovery/v1/authority-contracts.json"
    previous = json.loads(corpus_path.read_bytes())
    native = json.loads((corpus_path.parent / "authority-positive.json").read_bytes())
    result = build_corpus(previous, native)
    if args.check:
        if previous != result:
            parser.exit(1, "authority corpus is stale; regenerate its current wire profiles\n")
        return 0
    (args.output or corpus_path).write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
