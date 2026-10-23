from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from chio.errors import ChioInvariantError
from chio.invariants import verify_receipt, verify_receipt_with_trusted_signers

REPO_ROOT = Path(__file__).resolve().parents[4]


def _load(relative: str) -> dict:
    return json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))


def _receipt(case_id: str) -> dict:
    cases = _load("tests/bindings/vectors/receipt/v1.json")["cases"]
    return copy.deepcopy(next(case for case in cases if case["id"] == case_id)["receipt"])


def _padded(case_id: str, pointer: str) -> dict:
    receipt = _receipt(case_id)
    if pointer == "/actor_chain/0":
        receipt["actor_chain"] = [{"actor_id": "agent-1", "pad": 0}]
        return receipt
    if pointer == "/bbs_signature":
        receipt["bbs_signature"] = {"pad": 0}
        return receipt
    target = receipt
    for part in pointer.split("/")[1:]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    target["pad"] = 0
    return receipt


class ReceiptUnknownMemberTests(unittest.TestCase):
    def assert_refused(self, receipt: dict, member: str) -> None:
        with self.assertRaises(ChioInvariantError) as raised:
            verify_receipt_with_trusted_signers(receipt, [receipt["kernel_key"]])
        self.assertEqual(raised.exception.code, "json")
        self.assertEqual(str(raised.exception), f"unknown receipt member: {member}")

    def test_every_receipt_record_refuses_an_unknown_member(self) -> None:
        for case_id, pointer in (
            ("allow_receipt", ""),
            ("allow_receipt", "/action"),
            ("allow_receipt", "/decision"),
            ("deny_receipt", "/decision"),
            ("allow_receipt", "/evidence/0"),
            ("allow_receipt", "/actor_chain/0"),
            ("allow_receipt", "/bbs_signature"),
        ):
            with self.subTest(case_id=case_id, pointer=pointer):
                self.assert_refused(_padded(case_id, pointer), f"{pointer}/pad")

    def test_unsigned_schema_member_is_refused(self) -> None:
        receipt = _receipt("allow_receipt")
        receipt["schema"] = "chio.receipt.v1"
        self.assert_refused(receipt, "/schema")

    def test_protocol_primitives_unknown_field_case_is_refused(self) -> None:
        corpus = _load("tests/bindings/fixtures/protocol-primitives-v1.json")
        case = next(case for case in corpus["cases"] if case["name"] == "receipt-unknown-field")
        self.assertFalse(case["valid"])
        with self.assertRaises(ChioInvariantError) as raised:
            verify_receipt(case["instance"])
        self.assertEqual(str(raised.exception), "unknown receipt member: /unsigned_extension")


if __name__ == "__main__":
    unittest.main()
