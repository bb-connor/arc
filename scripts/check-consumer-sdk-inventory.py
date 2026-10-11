#!/usr/bin/env python3
"""Check terminal SDK acceptance identities, not merely process exit codes."""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Each SDK decoder's treatment of the raw duplicate-key cases. "rejects" must be
# an ordinary passing test. "last-wins" is a declared decoder gap that must be
# reported as a strict expected failure (Python xfail, TypeScript it.fails).
RAW_CASE_STATUS = {
    "receipt-duplicate-id": {"go": "rejects", "python": "rejects", "typescript": "rejects"},
    "receipt-duplicate-parameter": {"go": "rejects", "python": "rejects", "typescript": "rejects"},
}
TYPESCRIPT_GAP_SUFFIX = " (known gap: JSON.parse keeps the last duplicate)"


def verify(evidence: Path, root: Path) -> None:
    manifest = json.loads((root / "tests/bindings/fixtures/manifest-v2-consumers.json").read_text())["cases"]
    corpus = json.loads((root / "tests/bindings/fixtures/protocol-primitives-v1.json").read_text())
    primitives, raw = corpus["cases"], corpus["raw_cases"]
    if len(manifest) != 14 or len(primitives) != 39 or len(raw) != 2:
        raise ValueError("shared consumer fixture inventory changed")
    if sorted(case["name"] for case in raw) != sorted(RAW_CASE_STATUS):
        raise ValueError("raw fixture decoder status is not recorded")
    if any(status["go"] != "rejects" for status in RAW_CASE_STATUS.values()):
        raise ValueError("Go raw fixtures have no expected-failure form")
    expected_python = {f"test_manifest_v2_runtime_corpus[{case['name']}]" for case in manifest}
    expected_python.add("test_protocol_primitives_shared_fixtures_parse_reject_and_round_trip")
    python_raw = {
        f"test_protocol_primitives_raw_cases_reject_duplicate_keys[{name}]": status["python"]
        for name, status in RAW_CASE_STATUS.items()
    }
    expected_python |= set(python_raw)
    python = ET.parse(evidence / "python.xml")
    cases = list(python.iter("testcase"))
    if len(cases) != len(expected_python) or {case.get("name") for case in cases} != expected_python:
        raise ValueError("Python consumer inventory mismatch")
    for case in cases:
        expected_outcome = [("skipped", "pytest.xfail")] if python_raw.get(case.get("name")) == "last-wins" else []
        if [(child.tag, child.get("type")) for child in case] != expected_outcome:
            raise ValueError("Python consumer test skipped, failed or changed its raw decoder status")

    expected_go = {
        "TestGeneratedProtocolPrimitivesConsumeSharedFixtures",
        "TestGeneratedManifestV2RuntimeCorpus",
        "TestChioToolCallRequestPreservesApprovalSetAndOpaqueExtension",
        "TestProtocolPublicDecoderRejectsMutationsWithoutReplacingPriorValue",
        "TestProtocolNumbersPreserveOpaqueValuesAndRejectTypedOverflow",
        "TestAggregatePublicUnionRejectsUnknownAndForbiddenRootProperties",
        "TestProtocolWireBoundsAndOpaqueDuplicatesReject",
        "TestReceiptOriginRejectsInvalidValuesWithoutReplacingPriorValue",
    }
    events = [json.loads(line) for line in (evidence / "go.jsonl").read_text().splitlines()]
    if any(event["Action"] in {"fail", "skip"} for event in events):
        raise ValueError("Go consumer case skipped or failed")
    passed = [event["Test"] for event in events if event["Action"] == "pass" and "Test" in event and "/" not in event["Test"]]
    if len(passed) != len(expected_go) or set(passed) != expected_go:
        raise ValueError("Go consumer inventory mismatch")
    for test, fixtures in [("TestGeneratedProtocolPrimitivesConsumeSharedFixtures", primitives + raw), ("TestGeneratedManifestV2RuntimeCorpus", manifest)]:
        expected = {f"{test}/{case['name']}" for case in fixtures}
        observed = [event.get("Test") for event in events if event["Action"] == "pass" and event.get("Test", "").startswith(test + "/")]
        if len(observed) != len(expected) or set(observed) != expected:
            raise ValueError("Go shared fixture inventory mismatch")

    typescript = json.loads((evidence / "typescript.json").read_text())
    if not typescript["success"] or typescript["numTotalTests"] != 21 or typescript["numPassedTests"] != 21:
        raise ValueError("TypeScript consumer test totals mismatch")
    assertions = [item for suite in typescript["testResults"] for item in suite["assertionResults"]]
    if len(assertions) != 21 or any(item["status"] != "passed" for item in assertions):
        raise ValueError("TypeScript consumer case skipped or failed")
    expected_titles = {case["name"] for case in manifest} | {
        "retains the complete shared inventory",
        "compile and validate the shared positive and negative fixtures",
        "accepts representable bounds without modifying input",
        "rejects unsafe numbers, unknown authority, coercion and unknown domains",
        "compiles references at setup and rejects cycles in input",
    } | {
        f"raw {name} rejects duplicate keys" + (TYPESCRIPT_GAP_SUFFIX if status["typescript"] == "last-wins" else "")
        for name, status in RAW_CASE_STATUS.items()
    }
    if {item["title"] for item in assertions} != expected_titles:
        raise ValueError("TypeScript consumer inventory mismatch")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-consumer-sdk-inventory.py EVIDENCE_DIRECTORY")
    verify(Path(sys.argv[1]), Path(__file__).resolve().parents[1])
