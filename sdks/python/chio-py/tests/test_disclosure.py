from __future__ import annotations

import json
import unittest
from pathlib import Path

from chio.errors import ChioInvariantError
from chio.invariants import (
    decode_salt,
    open_commitments,
    parse_receipt_disclosure,
    parse_receipt_disclosure_json,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
COMMITTED = REPO_ROOT / "tests" / "bindings" / "vectors" / "receipt" / "committed" / "v1.json"
EXAMPLES = REPO_ROOT / "spec" / "schemas" / "chio-wire" / "v1" / "root_authority" / "examples"
REJECTED_ALL = {"content": "rejected", "disclosure_valid": False, "parameters": "rejected"}
# Committed vectors whose disclosure carries a salt outside the canonical b64u form of 32 bytes.
# Every other vector decodes.
DECODE_REFUSED = {"salt_31_bytes", "salt_padded_b64u", "salt_noncanonical_tail"}
SALT_WIRE_ERROR = "salt is not the canonical b64u form of 32 bytes"


class DisclosureTests(unittest.TestCase):
    def test_opener_reproduces_committed_vectors(self) -> None:
        cases = json.loads(COMMITTED.read_text())["cases"]
        self.assertLessEqual(DECODE_REFUSED, {case["id"] for case in cases})
        for case in cases:
            receipt = case["receipt"]
            if case["id"] in DECODE_REFUSED:
                with self.assertRaises(ChioInvariantError, msg=case["id"]) as refusal:
                    parse_receipt_disclosure(case["disclosure"])
                self.assertEqual(refusal.exception.code, "disclosure", case["id"])
                self.assertEqual(str(refusal.exception), SALT_WIRE_ERROR, case["id"])
                report = dict(REJECTED_ALL)
            else:
                report = open_commitments(
                    receipt["id"],
                    receipt["action"]["parameter_commitment"],
                    receipt["content_commitment"],
                    parse_receipt_disclosure(case["disclosure"]),
                    json.loads(case["preimages"]["parameters_canonical"]),
                    bytes.fromhex(case["preimages"]["content_preimage_hex"]),
                )
            expected = case["expected"]
            self.assertEqual(report["parameters"], expected["parameters"], case["id"])
            self.assertEqual(report["content"], expected["content"], case["id"])
            if "delegation_context" not in case:
                self.assertEqual(report["disclosure_valid"], expected["disclosure_valid"], case["id"])

    def test_disclosure_examples_decode_as_the_schema_says(self) -> None:
        parse_receipt_disclosure_json((EXAMPLES / "valid" / "disclosure.json").read_text())
        invalid = sorted((EXAMPLES / "invalid").glob("disclosure.*.json"))
        self.assertEqual(len(invalid), 7)
        for path in invalid:
            with self.assertRaises(ChioInvariantError, msg=path.name):
                parse_receipt_disclosure_json(path.read_text())

    def test_duplicate_keys_refused(self) -> None:
        text = (EXAMPLES / "valid" / "disclosure.json").read_text()
        document = json.loads(text)
        duplicated = text.replace('"receipt_id"', f'"receipt_id": "{document["receipt_id"]}", "receipt_id"', 1)
        with self.assertRaises(ChioInvariantError):
            parse_receipt_disclosure_json(duplicated)

    def test_salt_wire_form_is_strict(self) -> None:
        canonical = "b64u:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA"
        self.assertEqual(decode_salt(canonical), bytes([0x10]) * 32)
        for encoded in (canonical + "=", "b64u:" + "A" * 42 + "B", canonical[:-1], 16):
            with self.assertRaises(ChioInvariantError, msg=repr(encoded)):
                decode_salt(encoded)


if __name__ == "__main__":
    unittest.main()
