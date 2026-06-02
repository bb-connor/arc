from __future__ import annotations

from typing import Any

from chio.invariants import verify_signed_manifest


def priced_signed_manifest() -> dict[str, Any]:
    return {
        "manifest": {
            "schema": "chio.manifest.v1",
            "server_id": "srv-priced",
            "name": "Priced Server",
            "version": "1.0.0",
            "tools": [
                {
                    "name": "greet",
                    "description": "Returns a greeting",
                    "input_schema": {"type": "object"},
                    "has_side_effects": False,
                }
            ],
            "public_key": "22" * 32,
        },
        "signature": "33" * 64,
        "signer_key": "11" * 32,
    }


def test_manifest_structure_does_not_include_embedded_public_key_validity() -> None:
    signed_manifest = priced_signed_manifest()
    signed_manifest["manifest"]["public_key"] = "demo-placeholder"

    verification = verify_signed_manifest(signed_manifest)

    assert verification["structure_valid"] is True
    assert verification["embedded_public_key_valid"] is False
    assert verification["embedded_public_key_matches_signer"] is False


def test_manifest_structure_rejects_empty_or_padded_identity_fields() -> None:
    cases = [
        ("server_id", ""),
        ("server_id", " srv-priced"),
        ("server_id", "srv-priced "),
        ("name", ""),
        ("name", " Priced Server"),
        ("name", "Priced Server "),
        ("version", ""),
        ("version", " 1.0.0"),
        ("version", "1.0.0 "),
    ]
    for field, value in cases:
        signed_manifest = priced_signed_manifest()
        signed_manifest["manifest"][field] = value

        verification = verify_signed_manifest(signed_manifest)

        assert verification["structure_valid"] is False, f"{field} {value!r}"
        assert verification["signature_valid"] is False
        assert verification["embedded_public_key_valid"] is True


def test_manifest_structure_rejects_empty_or_padded_tool_names() -> None:
    for name in ["", " greet", "greet "]:
        signed_manifest = priced_signed_manifest()
        signed_manifest["manifest"]["tools"][0]["name"] = name

        assert verify_signed_manifest(signed_manifest)["structure_valid"] is False


def test_manifest_structure_rejects_non_object_tool_schemas() -> None:
    bad_input_schema = priced_signed_manifest()
    bad_input_schema["manifest"]["tools"][0]["input_schema"] = []
    assert verify_signed_manifest(bad_input_schema)["structure_valid"] is False

    bad_output_schema = priced_signed_manifest()
    bad_output_schema["manifest"]["tools"][0]["output_schema"] = "not an object"
    assert verify_signed_manifest(bad_output_schema)["structure_valid"] is False
