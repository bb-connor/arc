from __future__ import annotations

import base64
import json
import unittest
from pathlib import Path

from chio.invariants import (
    capability_body_canonical_json,
    canonicalize_json_string,
    parse_capability_json,
    parse_receipt_json,
    parse_signed_manifest_json,
    receipt_body_canonical_json,
    receipt_signing_body_canonical_json,
    sha256_hex_utf8,
    sign_json_string_ed25519,
    sign_utf8_message_ed25519,
    signed_manifest_body_canonical_json,
    verify_capability,
    verify_json_string_signature_ed25519,
    verify_receipt,
    verify_receipt_with_trusted_signers,
    verify_signed_manifest,
    verify_utf8_message_ed25519,
)
from chio.errors import ChioInvariantError

REPO_ROOT = Path(__file__).resolve().parents[4]
VECTORS_ROOT = REPO_ROOT / "tests" / "bindings" / "vectors"
WATERMARK_VECTORS_ROOT = (
    REPO_ROOT / "crates" / "tooling" / "chio-conformance" / "vectors" / "security" / "watermark"
)
WATERMARK_PAYLOAD_FIELDS = {
    "application_id",
    "encoding",
    "expires_at_unix_ms",
    "issued_at_unix_ms",
    "key_id",
    "marker_ref",
    "sequence",
    "session_id",
    "source_receipt_id",
    "tenant_id",
    "tool_id",
}
WATERMARK_NUMERIC_FIELDS = {
    "expires_at_unix_ms",
    "issued_at_unix_ms",
    "sequence",
}
DECLASSIFICATION_ENVELOPE_FIELDS = {
    "algorithm",
    "authority_key",
    "body",
    "signature",
}
DECLASSIFICATION_BODY_FIELDS = {
    "agent_id",
    "authority_key_id",
    "capability_id",
    "destination_id",
    "domain_version",
    "expires_at_unix_seconds",
    "grant_id",
    "issued_at_unix_seconds",
    "purpose",
    "request_hash",
    "session_id",
    "source_label_hash",
    "subject_id",
    "target_label",
    "tenant_id",
    "tool_name",
}


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
        signed_utf8 = sign_utf8_message_ed25519(
            fixture["utf8_cases"][0]["input_utf8"],
            fixture["signing_key_seed_hex"],
        )
        self.assertEqual(signed_utf8["public_key_hex"], fixture["utf8_cases"][0]["public_key_hex"])
        self.assertEqual(signed_utf8["signature_hex"], fixture["utf8_cases"][0]["signature_hex"])

        signed_json = sign_json_string_ed25519(
            fixture["json_cases"][0]["input_json"],
            fixture["signing_key_seed_hex"],
        )
        self.assertEqual(signed_json["canonical_json"], fixture["json_cases"][0]["canonical_json"])
        self.assertEqual(signed_json["public_key_hex"], fixture["json_cases"][0]["public_key_hex"])
        self.assertEqual(signed_json["signature_hex"], fixture["json_cases"][0]["signature_hex"])

        for case in fixture["utf8_cases"]:
            self.assertEqual(
                verify_utf8_message_ed25519(
                    case["input_utf8"],
                    case["public_key_hex"],
                    case["signature_hex"],
                ),
                case["expected_verify"],
                case["id"],
            )

        for case in fixture["json_cases"]:
            self.assertEqual(
                verify_json_string_signature_ed25519(
                    case["input_json"],
                    case["public_key_hex"],
                    case["signature_hex"],
                ),
                case["expected_verify"],
                case["id"],
            )

    def test_declassification_vector(self) -> None:
        fixture = load_vector("declassification")
        case = fixture["positive"]
        grant = case["grant"]
        self.assertEqual(set(grant), DECLASSIFICATION_ENVELOPE_FIELDS)
        self.assertEqual(set(grant["body"]), DECLASSIFICATION_BODY_FIELDS)
        self.assertEqual(grant["algorithm"], "ed25519")
        canonical_body = canonicalize_json_string(
            json.dumps(grant["body"], ensure_ascii=False, separators=(",", ":"))
        )
        self.assertEqual(canonical_body, case["canonical_body_json"])
        signing_message = "chio:declassification-grant:v1\0" + canonical_body
        signed = sign_utf8_message_ed25519(signing_message, case["signing_seed_hex"])
        self.assertEqual(signed["public_key_hex"], grant["authority_key"])
        self.assertEqual(signed["signature_hex"], grant["signature"])
        self.assertTrue(
            verify_utf8_message_ed25519(
                signing_message,
                grant["authority_key"],
                grant["signature"],
            )
        )
        self.assertFalse(
            verify_utf8_message_ed25519(
                canonical_body,
                grant["authority_key"],
                grant["signature"],
            )
        )

    def test_signed_watermark_vectors(self) -> None:
        fixture = json.loads((WATERMARK_VECTORS_ROOT / "v1.json").read_text())
        self.assertEqual(fixture["schema"], "chio.signed-watermark-vectors.v1")
        self.assertEqual(fixture["signing_domain"], "chio.signed-watermark.v1\0")

        for case in fixture["cases"]:
            with self.subTest(case=case["id"]):
                payload = case["payload"]
                self.assertEqual(set(payload), WATERMARK_PAYLOAD_FIELDS)
                self.assertEqual(payload["encoding"], "base64_url_canonical_json")
                for field in WATERMARK_NUMERIC_FIELDS:
                    self.assertIsInstance(payload[field], int)
                    self.assertLessEqual(payload[field], (2**53) - 1)
                self.assertEqual(payload["sequence"], (2**53) - 1)

                canonical_payload = canonicalize_json_string(
                    json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
                )
                self.assertEqual(canonical_payload, case["canonical_payload_json"])
                signing_message = fixture["signing_domain"] + canonical_payload
                self.assertEqual(signing_message.encode("utf-8").hex(), case["signing_message_hex"])
                signed = sign_utf8_message_ed25519(
                    signing_message,
                    fixture["signing_key_seed_hex"],
                )
                self.assertEqual(signed["public_key_hex"], case["public_key_hex"])
                self.assertEqual(signed["signature_hex"], case["signature_hex"])
                self.assertTrue(
                    verify_utf8_message_ed25519(
                        signing_message,
                        case["public_key_hex"],
                        case["signature_hex"],
                    )
                )
                self.assertFalse(
                    verify_utf8_message_ed25519(
                        canonical_payload,
                        case["public_key_hex"],
                        case["signature_hex"],
                    )
                )

                encoded_payload = (
                    base64.urlsafe_b64encode(canonical_payload.encode("utf-8"))
                    .rstrip(b"=")
                    .decode("ascii")
                )
                self.assertNotIn("=", case["encoded_payload"])
                self.assertEqual(encoded_payload, case["encoded_payload"])
                payload_padding = "=" * (-len(case["encoded_payload"]) % 4)
                decoded_payload = base64.urlsafe_b64decode(
                    case["encoded_payload"] + payload_padding
                ).decode("utf-8")
                self.assertEqual(decoded_payload, canonical_payload)
                self.assertEqual(
                    base64.urlsafe_b64encode(decoded_payload.encode("utf-8"))
                    .rstrip(b"=")
                    .decode("ascii"),
                    case["encoded_payload"],
                )

                envelope = case["envelope"]
                self.assertEqual(
                    set(envelope),
                    {"encoded_payload", "payload", "schema", "signature"},
                )
                self.assertEqual(envelope["schema"], "chio.signed-watermark-envelope.v1")
                self.assertEqual(envelope["payload"], payload)
                self.assertEqual(envelope["encoded_payload"], case["encoded_payload"])
                self.assertEqual(envelope["signature"], case["signature_hex"])
                canonical_envelope = canonicalize_json_string(
                    json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
                )
                self.assertEqual(canonical_envelope, case["canonical_envelope_json"])

                self.assertTrue(case["token"].startswith("[[chio-wm1:"))
                self.assertTrue(case["token"].endswith("]]"))
                encoded_envelope = case["token"][len("[[chio-wm1:") : -len("]]")]
                self.assertNotIn("=", encoded_envelope)
                envelope_padding = "=" * (-len(encoded_envelope) % 4)
                decoded_envelope = base64.urlsafe_b64decode(
                    encoded_envelope + envelope_padding
                ).decode("utf-8")
                self.assertEqual(decoded_envelope, canonical_envelope)
                self.assertEqual(
                    base64.urlsafe_b64encode(decoded_envelope.encode("utf-8"))
                    .rstrip(b"=")
                    .decode("ascii"),
                    encoded_envelope,
                )
                self.assertEqual(json.loads(decoded_envelope), envelope)

    def test_signed_watermark_vectors_reject_unsafe_integer(self) -> None:
        fixture = json.loads((WATERMARK_VECTORS_ROOT / "v1-rejections.json").read_text())
        for case in fixture["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(
                    canonicalize_json_string(case["input_payload_json"]),
                    case["canonical_payload_json"],
                )
                payload = json.loads(case["input_payload_json"])
                self.assertEqual(set(payload), WATERMARK_PAYLOAD_FIELDS)
                self.assertEqual(payload[case["field"]], int(case["value_decimal"]))
                self.assertGreater(payload[case["field"]], (2**53) - 1)
                self.assertEqual(payload[case["field"]], 2**53)
                self.assertEqual(case["expected_error"], "unsafe_integer")

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
        receipt["signature"] = sign_json_string_ed25519(
            receipt_signing_body_canonical_json(receipt),
            fixture["signing_key_seed_hex"],
        )["signature_hex"]
        verification = verify_receipt(receipt)
        self.assertFalse(verification["receipt_id_valid"])
        self.assertFalse(verification["signature_valid"])
        self.assertFalse(verification["ok"])

    def test_capability_vectors(self) -> None:
        fixture = load_vector("capability")
        for case in fixture["cases"]:
            capability = parse_capability_json(json.dumps(case["capability"]))
            self.assertEqual(
                capability_body_canonical_json(capability),
                case["capability_body_canonical_json"],
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

    def test_manifest_vectors(self) -> None:
        for version in ("v1", "v2"):
            fixture = json.loads(
                (VECTORS_ROOT / "manifest" / f"{version}.json").read_text()
            )
            for case in fixture["cases"]:
                signed_manifest = parse_signed_manifest_json(json.dumps(case["signed_manifest"]))
                self.assertEqual(
                    signed_manifest_body_canonical_json(signed_manifest),
                    case["manifest_body_canonical_json"],
                    f"{version}:{case['id']}",
                )
                self.assertEqual(
                    verify_signed_manifest(signed_manifest),
                    case["expected"],
                    f"{version}:{case['id']}",
                )

    def test_manifest_v2_canonical_rejection_vectors(self) -> None:
        fixture = json.loads((VECTORS_ROOT / "manifest" / "v2.json").read_text())
        baseline = next(case for case in fixture["cases"] if case["id"] == "valid_signed_manifest")
        rejection_vectors = json.loads(
            (VECTORS_ROOT / "manifest" / "v2-canonical-rejections.json").read_text()
        )
        for case in rejection_vectors["cases"]:
            envelope = json.loads(json.dumps(baseline["signed_manifest"]))
            permissions = envelope["manifest"]["required_permissions"]
            field = case["field"].split(".")
            if field == ["network_destinations", "0", "host"]:
                permissions["network_destinations"][0]["host"] = case["replacement"]
            elif field == ["read_paths", "0"]:
                permissions["read_paths"][0] = case["replacement"]
            else:
                permissions[field[0]] = case["replacement"]
            parsed = parse_signed_manifest_json(json.dumps(envelope))
            self.assertFalse(
                verify_signed_manifest(parsed)["structure_valid"],
                case["id"],
            )


if __name__ == "__main__":
    unittest.main()
