from __future__ import annotations

import json
import unittest
from pathlib import Path

from chio.invariants import (
    capability_signing_body_canonical_json,
    canonicalize_json,
    canonicalize_json_string,
    parse_capability_json,
    parse_receipt_json,
    receipt_body_canonical_json,
    receipt_signing_body_canonical_json,
    sha256_hex_utf8,
    public_key_from_seed_ed25519,
    sign_wrapped_json_ed25519,
    verify_capability,
    verify_receipt,
    verify_receipt_with_trusted_signers,
    verify_wrapped_json,
)
from chio.errors import ChioInvariantError

REPO_ROOT = Path(__file__).resolve().parents[4]
VECTORS_ROOT = REPO_ROOT / "tests" / "bindings" / "vectors"


def load_vector(name: str) -> dict:
    return json.loads((VECTORS_ROOT / name / "v1.json").read_text())


class VectorTests(unittest.TestCase):
    def test_canonical_vectors(self) -> None:
        fixture = load_vector("canonical")
        for case in fixture["cases"]:
            self.assertEqual(
                canonicalize_json_string(case["input_json"]),
                case["canonical_json"],
                case["id"],
            )

    def test_canonical_strings_pass_del_and_c1_controls_through(self) -> None:
        controls = "\u007f\u009f"

        self.assertEqual(canonicalize_json(controls), f'"{controls}"')
        self.assertEqual(
            canonicalize_json({controls: controls}),
            f'{{"{controls}":"{controls}"}}',
        )

    def test_hashing_vectors(self) -> None:
        fixture = load_vector("hashing")
        for case in fixture["cases"]:
            self.assertEqual(
                sha256_hex_utf8(case["input_utf8"]),
                case["sha256_hex"],
                case["id"],
            )

    def test_signing_vectors(self) -> None:
        fixture = load_vector("signing")
        if any("schema_id" not in case for case in fixture["json_cases"]):
            self.skipTest("signing vectors carry no schema_id until they regenerate")
        self.assertNotIn("utf8_cases", fixture)
        for case in fixture["json_cases"]:
            if case["expected_verify"]:
                verify_wrapped_json(
                    case["schema_id"],
                    case["input_json"],
                    case["public_key_hex"],
                    case["signature_hex"],
                )
                signed = sign_wrapped_json_ed25519(
                    case["schema_id"], case["input_json"], fixture["signing_key_seed_hex"]
                )
                self.assertEqual(signed["canonical_json"], case["canonical_json"], case["id"])
                self.assertEqual(signed["public_key_hex"], case["public_key_hex"], case["id"])
                self.assertEqual(signed["signature_hex"], case["signature_hex"], case["id"])
            else:
                with self.assertRaises(ChioInvariantError, msg=case["id"]):
                    verify_wrapped_json(
                        case["schema_id"],
                        case["input_json"],
                        case["public_key_hex"],
                        case["signature_hex"],
                    )

    def test_wrapped_signer_identity(self) -> None:
        seed = "01" * 32
        signed = sign_wrapped_json_ed25519("chio.receipt.v1", '{"b":1,"a":2}', seed)
        self.assertEqual(signed["public_key_hex"], public_key_from_seed_ed25519(seed))
        self.assertEqual(signed["canonical_json"], '{"a":2,"b":1}')
        verify_wrapped_json("chio.receipt.v1", '{"a":2,"b":1}', signed["public_key_hex"], signed["signature_hex"])

    def test_unregistered_schema_id_is_refused(self) -> None:
        seed = "01" * 32
        with self.assertRaises(ChioInvariantError) as raised:
            sign_wrapped_json_ed25519("chio.unregistered-fixture.v1", '{"a":1}', seed)
        self.assertEqual(raised.exception.code, "unregistered_schema_id")
        self.assertEqual(
            str(raised.exception), "unregistered signed-artifact schema id: chio.unregistered-fixture.v1"
        )
        signed = sign_wrapped_json_ed25519("chio.receipt.v1", '{"a":1}', seed)
        with self.assertRaises(ChioInvariantError) as raised:
            verify_wrapped_json("chio.capability.v1", '{"a":1}', signed["public_key_hex"], signed["signature_hex"])
        self.assertEqual(raised.exception.code, "signature_rejected")
        self.assertEqual(str(raised.exception), "signature rejected")

    def test_capability_with_algorithm_member_is_refused(self) -> None:
        fixture = load_vector("capability")
        for algorithm in ("ed25519", "p256"):
            capability = dict(fixture["cases"][0]["capability"])
            capability["algorithm"] = algorithm
            with self.assertRaises(ChioInvariantError) as raised:
                parse_capability_json(json.dumps(capability))
            self.assertEqual(raised.exception.code, "json")
            self.assertEqual(str(raised.exception), "capability has unknown member algorithm")

    def test_signing_wrapper_vectors(self) -> None:
        fixture = json.loads((VECTORS_ROOT / "signing" / "wrapper" / "v1.json").read_text())
        skipped = set()
        for case in fixture["signature_cases"]:
            if case["algorithm"] != "ed25519":
                skipped.add(case["algorithm"])
                continue
            try:
                verify_wrapped_json(
                    case["verify_schema_id"],
                    case["canonical_body"],
                    case["public_key"],
                    case["signature"],
                )
                verified = True
            except ChioInvariantError:
                verified = False
            self.assertEqual(verified, case["expected_verify"], case["id"])
        self.assertEqual(skipped, {"p256", "p384"})

    def test_receipt_vectors(self) -> None:
        fixture = load_vector("receipt")
        for case in fixture["cases"]:
            receipt = parse_receipt_json(json.dumps(case["receipt"]))
            self.assertEqual(receipt_body_canonical_json(receipt), case["receipt_body_canonical_json"])
            self.assertEqual(verify_receipt(receipt), case["expected"], case["id"])

    def test_receipt_vectors_support_trusted_signers(self) -> None:
        fixture = load_vector("receipt")
        case = next(item for item in fixture["cases"] if item["id"] == "allow_receipt")
        receipt = parse_receipt_json(json.dumps(case["receipt"]))
        verification = verify_receipt_with_trusted_signers(receipt, [receipt["kernel_key"]])
        self.assertTrue(verification["signer_trusted"])
        self.assertTrue(verification["ok"])
        self.assertTrue(verification["authorized"])

    def test_receipt_semantics_ignore_legacy_metadata_payloads(self) -> None:
        fixture = load_vector("receipt")
        case = next(item for item in fixture["cases"] if item["id"] == "allow_receipt")
        receipt = parse_receipt_json(json.dumps(case["receipt"]))
        receipt["metadata"] = {
            "receipt_semantics": {
                "receiptKind": "trace_observation",
                "boundaryClass": "detect_only",
            }
        }
        verification = verify_receipt_with_trusted_signers(receipt, [receipt["kernel_key"]])
        self.assertEqual(verification["receipt_kind"], "mediated_decision")
        self.assertEqual(verification["boundary_class"], "prevent")
        self.assertFalse(verification["receipt_id_valid"])
        self.assertFalse(verification["signature_valid"])
        self.assertFalse(verification["authorized"])

    def test_receipt_signature_valid_fails_when_content_addressed_id_mismatches(self) -> None:
        fixture = load_vector("receipt")
        case = next(item for item in fixture["cases"] if item["id"] == "allow_receipt")
        receipt = parse_receipt_json(json.dumps(case["receipt"]))
        receipt["id"] = "0000000000000000000000000000000000000000000000000000000000000000"
        receipt["signature"] = sign_wrapped_json_ed25519(
            "chio.receipt.v1",
            receipt_signing_body_canonical_json(receipt),
            fixture["signing_key_seed_hex"],
        )["signature_hex"]
        verification = verify_receipt(receipt)
        self.assertFalse(verification["receipt_id_valid"])
        self.assertFalse(verification["signature_valid"])
        self.assertFalse(verification["ok"])

    def test_capability_without_v1_schema_is_refused(self) -> None:
        for payload in ('{"id":"cap"}', '{"id":"cap","schema":"chio.capability.v2"}'):
            with self.assertRaises(ChioInvariantError) as raised:
                parse_capability_json(payload)
            self.assertEqual(raised.exception.code, "json")
            self.assertIn('capability schema must be "chio.capability.v1"', str(raised.exception))

    def test_capability_vectors(self) -> None:
        fixture = load_vector("capability")
        for case in fixture["cases"]:
            capability = parse_capability_json(json.dumps(case["capability"]))
            self.assertEqual(
                capability_signing_body_canonical_json(capability),
                case["capability_signing_body_canonical_json"],
                case["id"],
            )
            self.assertEqual(
                verify_capability(capability, case.get("root_delegator_hex"), case["verify_at"]),
                case["expected"],
                case["id"],
            )
            if "expected_with_max_delegation_depth" in case:
                self.assertEqual(
                    verify_capability(
                        capability,
                        case.get("root_delegator_hex"),
                        case["verify_at"],
                        case["max_delegation_depth"],
                    ),
                    case["expected_with_max_delegation_depth"],
                    case["id"],
                )

    def _delegated_case(self) -> dict:
        for case in load_vector("capability")["cases"]:
            if case["id"] == "valid_delegated_capability":
                return case
        raise AssertionError("valid_delegated_capability vector missing")

    def test_delegated_capability_without_root_delegator_is_refused(self) -> None:
        case = self._delegated_case()
        with self.assertRaises(ChioInvariantError) as raised:
            verify_capability(case["capability"], None, case["verify_at"])
        self.assertEqual(raised.exception.code, "delegation_root_unresolved")

    def test_empty_root_delegator_is_not_an_absent_root(self) -> None:
        case = self._delegated_case()
        with self.assertRaises(ChioInvariantError) as raised:
            verify_capability(case["capability"], "", case["verify_at"])
        self.assertEqual(raised.exception.code, "invalid_public_key")

    def test_delegated_capability_with_wrong_root_delegator_fails_chain_shape(self) -> None:
        case = self._delegated_case()
        wrong = "00" * 32
        self.assertNotEqual(wrong, case["root_delegator_hex"])
        result = verify_capability(case["capability"], wrong, case["verify_at"])
        self.assertFalse(result["delegation_chain_shape_valid"])

    def test_delegated_capability_with_malformed_root_delegator_is_refused(self) -> None:
        case = self._delegated_case()
        with self.assertRaises(ChioInvariantError) as raised:
            verify_capability(case["capability"], "zz", case["verify_at"])
        self.assertEqual(raised.exception.code, "invalid_public_key")

    def test_malformed_root_delegator_is_refused_without_delegation_chain(self) -> None:
        for case in load_vector("capability")["cases"]:
            if not case["capability"].get("delegation_chain"):
                with self.assertRaises(ChioInvariantError) as raised:
                    verify_capability(case["capability"], "zz", case["verify_at"])
                self.assertEqual(raised.exception.code, "invalid_public_key", case["id"])
                return
        raise AssertionError("no undelegated capability vector")

    def test_capability_parser_rejects_non_object_json(self) -> None:
        for payload in ("null", "[]", '"capability"', "42"):
            with self.subTest(payload=payload):
                with self.assertRaises(ChioInvariantError) as raised:
                    parse_capability_json(payload)
                self.assertEqual(raised.exception.code, "json")
                self.assertEqual(str(raised.exception), "capability must be a JSON object")


if __name__ == "__main__":
    unittest.main()
