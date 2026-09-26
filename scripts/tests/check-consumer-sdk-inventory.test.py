#!/usr/bin/env python3
"""Calibrate the SDK gate against false-green terminal reports."""

import copy
import importlib.util
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("consumer_sdk_inventory", ROOT / "scripts/check-consumer-sdk-inventory.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SdkInventoryCalibration(unittest.TestCase):
    def test_terminal_inventory_mutations(self):
        manifest = json.loads((ROOT / "tests/bindings/fixtures/manifest-v2-consumers.json").read_text())["cases"]
        primitives = json.loads((ROOT / "tests/bindings/fixtures/protocol-primitives-v1.json").read_text())["cases"]
        python = ET.Element("testsuites")
        suite = ET.SubElement(python, "testsuite")
        for name in [f"test_manifest_v2_runtime_corpus[{case['name']}]" for case in manifest] + ["test_protocol_primitives_shared_fixtures_parse_reject_and_round_trip"]:
            ET.SubElement(suite, "testcase", name=name)
        go = [{"Action": "pass", "Test": name} for name in [
            "TestGeneratedProtocolPrimitivesConsumeSharedFixtures",
            "TestGeneratedManifestV2RuntimeCorpus",
            "TestChioToolCallRequestPreservesApprovalSetAndOpaqueExtension",
            "TestProtocolPublicDecoderRejectsMutationsWithoutReplacingPriorValue",
            "TestProtocolNumbersPreserveOpaqueValuesAndRejectTypedOverflow",
            "TestAggregatePublicUnionRejectsUnknownAndForbiddenRootProperties",
            "TestProtocolWireBoundsAndOpaqueDuplicatesReject",
            "TestReceiptOriginRejectsInvalidValuesWithoutReplacingPriorValue",
        ]]
        for test, corpus in [("TestGeneratedProtocolPrimitivesConsumeSharedFixtures", primitives), ("TestGeneratedManifestV2RuntimeCorpus", manifest)]:
            go.extend({"Action": "pass", "Test": f"{test}/{case['name']}"} for case in corpus)
        titles = [case["name"] for case in manifest] + [
            "retains the complete shared inventory",
            "compile and validate the shared positive and negative fixtures",
            "accepts representable bounds without modifying input",
            "rejects unsafe numbers, unknown authority, coercion and unknown domains",
            "compiles references at setup and rejects cycles in input",
        ]
        typescript = {"success": True, "numTotalTests": 19, "numPassedTests": 19,
                      "testResults": [{"assertionResults": [{"title": title, "status": "passed"} for title in titles]}]}
        with tempfile.TemporaryDirectory(prefix="chio-sdk-inventory-calibration-") as directory:
            evidence = Path(directory)

            def check(py=python, golang=go, ts=typescript):
                ET.ElementTree(py).write(evidence / "python.xml")
                (evidence / "go.jsonl").write_text("\n".join(json.dumps(item) for item in golang))
                (evidence / "typescript.json").write_text(json.dumps(ts))
                MODULE.verify(evidence, ROOT)

            check()
            for mutation in ("missing", "renamed", "ignored", "zero", "duplicate"):
                with self.subTest(language="python", mutation=mutation):
                    altered = copy.deepcopy(python)
                    first = altered[0][0]
                    if mutation == "missing":
                        altered[0].remove(first)
                    elif mutation == "renamed":
                        first.set("name", "replacement")
                    elif mutation == "ignored":
                        ET.SubElement(first, "skipped")
                    elif mutation == "zero":
                        altered.clear()
                    else:
                        altered[0].append(copy.deepcopy(first))
                    with self.assertRaises(ValueError):
                        check(py=altered)
                with self.subTest(language="go", mutation=mutation):
                    altered = copy.deepcopy(go)
                    if mutation == "missing":
                        altered.pop()
                    elif mutation == "renamed":
                        altered[-1]["Test"] = "replacement"
                    elif mutation == "ignored":
                        altered[-1]["Action"] = "skip"
                    elif mutation == "zero":
                        altered.clear()
                    else:
                        altered.append(copy.deepcopy(altered[0]))
                    with self.assertRaises(ValueError):
                        check(golang=altered)
                with self.subTest(language="typescript", mutation=mutation):
                    altered = copy.deepcopy(typescript)
                    assertions = altered["testResults"][0]["assertionResults"]
                    if mutation == "missing":
                        assertions.pop()
                    elif mutation == "renamed":
                        assertions[0]["title"] = "replacement"
                    elif mutation == "ignored":
                        assertions[0]["status"] = "pending"
                    elif mutation == "zero":
                        assertions.clear()
                    else:
                        assertions.append(copy.deepcopy(assertions[0]))
                    with self.assertRaises(ValueError):
                        check(ts=altered)


if __name__ == "__main__":
    unittest.main()
