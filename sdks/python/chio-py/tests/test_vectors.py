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


ROOT_ANCHOR = {
    "kind": "oidc_jwt",
    "context_digest": "sha256:" + "a" * 64,
    "root_policy_digest": "sha256:" + "b" * 64,
    "anchored_at": 1700000000,
    "assertion_exp": 1700000600,
}


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

    def _anchored_capability_json(self, anchor: object) -> str:
        capability = dict(load_vector("capability")["cases"][0]["capability"])
        capability["root_anchor"] = anchor
        return json.dumps(capability)

    def test_root_anchor_decodes_every_kind_and_enters_the_signing_body(self) -> None:
        for kind in (
            "oauth_id_jag",
            "entra_jwt",
            "entra_agent_id",
            "oidc_jwt",
            "oauth_introspection",
            "chio_local_as",
            "chio_operator_key",
            "operator_static_bearer",
        ):
            anchor = {**ROOT_ANCHOR, "kind": kind}
            capability = parse_capability_json(self._anchored_capability_json(anchor))
            expected = (
                '"root_anchor":{"anchored_at":1700000000,"assertion_exp":1700000600,'
                f'"context_digest":"{ROOT_ANCHOR["context_digest"]}","kind":"{kind}",'
                f'"root_policy_digest":"{ROOT_ANCHOR["root_policy_digest"]}"}}'
            )
            self.assertIn(expected, capability_signing_body_canonical_json(capability), kind)

    def test_root_anchor_refuses_malformed_values(self) -> None:
        without_kind = {k: v for k, v in ROOT_ANCHOR.items() if k != "kind"}
        without_exp = {k: v for k, v in ROOT_ANCHOR.items() if k != "assertion_exp"}
        cases = [
            ("oidc_jwt", "root_anchor must be a JSON object"),
            ({**ROOT_ANCHOR, "padding": "x"}, "root_anchor has unknown member padding"),
            (without_kind, "root_anchor is missing member kind"),
            (without_exp, "root_anchor is missing member assertion_exp"),
            ({**ROOT_ANCHOR, "kind": "spiffe"}, "root_anchor kind is not a known anchor kind"),
            ({**ROOT_ANCHOR, "kind": 1}, "root_anchor kind is not a known anchor kind"),
            (
                {**ROOT_ANCHOR, "context_digest": "sha256:" + "A" * 64},
                "root_anchor context_digest must be a sha256 digest",
            ),
            (
                {**ROOT_ANCHOR, "root_policy_digest": "b" * 64},
                "root_anchor root_policy_digest must be a sha256 digest",
            ),
            (
                {**ROOT_ANCHOR, "anchored_at": -1},
                "root_anchor anchored_at must be an unsigned integer",
            ),
            (
                {**ROOT_ANCHOR, "anchored_at": True},
                "root_anchor anchored_at must be an unsigned integer",
            ),
            (
                {**ROOT_ANCHOR, "assertion_exp": "1700000600"},
                "root_anchor assertion_exp must be an unsigned integer",
            ),
            (
                {**ROOT_ANCHOR, "assertion_exp": 9007199254740992},
                "root_anchor assertion_exp must be an unsigned integer",
            ),
        ]
        for anchor, message in cases:
            with self.assertRaises(ChioInvariantError) as raised:
                parse_capability_json(self._anchored_capability_json(anchor))
            self.assertEqual(raised.exception.code, "json")
            self.assertEqual(str(raised.exception), message)

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
                verify_capability(capability, case["verify_at"]),
                case["expected"],
                case["id"],
            )
            if "expected_with_max_delegation_depth" in case:
                self.assertEqual(
                    verify_capability(
                        capability,
                        case["verify_at"],
                        case["max_delegation_depth"],
                    ),
                    case["expected_with_max_delegation_depth"],
                    case["id"],
                )

    def test_capability_parser_rejects_non_object_json(self) -> None:
        for payload in ("null", "[]", '"capability"', "42"):
            with self.subTest(payload=payload):
                with self.assertRaises(ChioInvariantError) as raised:
                    parse_capability_json(payload)
                self.assertEqual(raised.exception.code, "json")
                self.assertEqual(str(raised.exception), "capability must be a JSON object")


if __name__ == "__main__":
    unittest.main()
