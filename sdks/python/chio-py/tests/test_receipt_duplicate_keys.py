from __future__ import annotations

import json
import unittest
from pathlib import Path

from chio.errors import ChioInvariantError
from chio.invariants import (
    parse_receipt_json,
    verify_receipt,
    verify_receipt_with_trusted_signers,
)

REPO_ROOT = Path(__file__).resolve().parents[4]


def _load(relative: str) -> dict:
    return json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))


def _receipt_vector(case_id: str) -> dict:
    cases = _load("tests/bindings/vectors/receipt/v1.json")["cases"]
    return next(case for case in cases if case["id"] == case_id)


def _inject_once(text: str, anchor: str, inserted: str) -> str:
    assert text.count(anchor) == 1, anchor
    return text.replace(anchor, anchor + inserted, 1)


def _forgeries(compact: str) -> list[tuple[str, str]]:
    return [
        (
            "nested action.parameters",
            _inject_once(compact, '"parameters":{', '"path":"/etc/shadow",'),
        ),
        ("nested metadata", _inject_once(compact, '"metadata":{', '"surface":"forged",')),
        (
            "nested evidence entry",
            _inject_once(compact, '"evidence":[{', '"details":"forged",'),
        ),
        ("top-level tool_name", compact.replace("{", '{"tool_name":"shell_exec",', 1)),
    ]


class ReceiptDuplicateKeyTests(unittest.TestCase):
    def assert_rejected(self, text: str, label: str) -> None:
        trusted = [json.loads(text)["kernel_key"]]
        try:
            verification = verify_receipt_with_trusted_signers(parse_receipt_json(text), trusted)
        except ChioInvariantError as error:
            self.assertEqual(error.code, "json", label)
        else:
            self.fail(f"duplicate keys in {label} were accepted: {verification}")

    def test_signed_receipt_with_duplicate_keys_rejects_at_original_text(self) -> None:
        case = _receipt_vector("allow_receipt")
        compact = json.dumps(case["receipt"], separators=(",", ":"))
        verification = verify_receipt_with_trusted_signers(
            parse_receipt_json(compact), [case["receipt"]["kernel_key"]]
        )
        self.assertTrue(verification["ok"] and verification["authorized"])
        for label, forged in _forgeries(compact):
            self.assertEqual(json.loads(forged), case["receipt"], f"{label} collapses last-wins")
            self.assert_rejected(forged, label)

    def test_protocol_primitives_raw_cases_reject_at_original_text(self) -> None:
        corpus = _load("tests/bindings/fixtures/protocol-primitives-v1.json")
        names = []
        for case in corpus["raw_cases"]:
            if case["schema_file"] != "receipt/record.schema.json":
                continue
            self.assert_rejected(case["instance_text"], case["name"])
            names.append(case["name"])
        self.assertEqual(names, ["receipt-duplicate-id", "receipt-duplicate-parameter"])

    def test_receipt_vectors_verify_identically_compact_and_pretty(self) -> None:
        for case in _load("tests/bindings/vectors/receipt/v1.json")["cases"]:
            for text in (
                json.dumps(case["receipt"], separators=(",", ":")),
                json.dumps(case["receipt"], indent=2, ensure_ascii=False),
                json.dumps(case["receipt"], indent=2, ensure_ascii=True),
            ):
                self.assertEqual(verify_receipt(parse_receipt_json(text)), case["expected"], case["id"])

    def test_number_and_string_tokens_parse_exactly_as_json_loads(self) -> None:
        for text in (
            '{"max":18446744073709551615,"min":-9223372036854775808,"wide":1180591620717411303424}',
            '{"zero":-0,"float_zero":-0.0,"exp":1e2,"padded":0.10,"small":1.5e-7,"big":1E+21}',
            '{"nested":[{"a":1.0},[2,[3.25]],{"b":{"c":null,"d":true}}]}',
            '{"text":"caf\\u00e9 \\u2028 \\ud83d\\ude00 tab\\t","raw":"café"}',
            '{"same":"a","\\u0073ame2":"b"}',
        ):
            self.assertEqual(repr(parse_receipt_json(text)), repr(json.loads(text)), text)


if __name__ == "__main__":
    unittest.main()
