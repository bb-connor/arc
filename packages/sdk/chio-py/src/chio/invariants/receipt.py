from __future__ import annotations

from typing import Any

from ..errors import parse_json_text
from .hashing import sha256_hex_utf8
from .json import canonicalize_json
from .signing import verify_utf8_message_ed25519


def parse_receipt_json(input_text: str) -> dict[str, Any]:
    return parse_json_text(input_text)


def _receipt_body(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in receipt.items() if key != "signature"}


def receipt_body_canonical_json(receipt: dict[str, Any]) -> str:
    return canonicalize_json(_receipt_body(receipt))


def verify_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "signature_valid": verify_utf8_message_ed25519(
            receipt_body_canonical_json(receipt),
            receipt["kernel_key"],
            receipt["signature"],
        ),
        "parameter_hash_valid": receipt["action"]["parameter_hash"]
        == sha256_hex_utf8(canonicalize_json(receipt["action"]["parameters"])),
        "decision": receipt["decision"]["verdict"],
    }


def verify_receipt_json(input_text: str) -> dict[str, Any]:
    return verify_receipt(parse_receipt_json(input_text))
