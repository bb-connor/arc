from __future__ import annotations

import hashlib

from pure25519.ed25519_oop import BadSignatureError, SigningKey, VerifyingKey

from ..errors import ChioInvariantError
from ._generated_signed_artifact_schemas import KNOWN_SIGNED_ARTIFACT_SCHEMAS
from .json import canonicalize_json_string

SIGNING_WRAPPER_PREFIX = b"chio.signing-wrapper.v1\x00"


def _normalize_hex(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


def _hex_to_bytes(value: str, *, expected_bytes: int, code: str) -> bytes:
    normalized = _normalize_hex(value).lower()
    if len(normalized) != expected_bytes * 2:
        raise ChioInvariantError(code, f"expected {expected_bytes} bytes of hex, got {len(normalized) // 2}")
    try:
        return bytes.fromhex(normalized)
    except ValueError as exc:
        raise ChioInvariantError(code, "value is not valid hexadecimal") from exc


def _signing_key_from_seed_hex(seed_hex: str) -> SigningKey:
    return SigningKey(_hex_to_bytes(seed_hex, expected_bytes=32, code="invalid_hex"))


def _verifying_key_from_hex(public_key_hex: str) -> VerifyingKey:
    try:
        return VerifyingKey(_hex_to_bytes(public_key_hex, expected_bytes=32, code="invalid_public_key"))
    except ValueError as exc:
        raise ChioInvariantError("invalid_public_key", "value is not a valid Ed25519 public key") from exc


def _encoded_algorithm(value: str) -> str:
    for prefix in ("p256", "p384", "hybrid"):
        if value.startswith(f"{prefix}:"):
            return prefix
    return "ed25519"


def is_valid_public_key_hex(value: str) -> bool:
    try:
        _hex_to_bytes(value, expected_bytes=32, code="invalid_public_key")
        return True
    except ChioInvariantError:
        return False


def is_valid_signature_hex(value: str) -> bool:
    try:
        _hex_to_bytes(value, expected_bytes=64, code="invalid_signature")
        return True
    except ChioInvariantError:
        return False


def public_key_hex_matches(left: str, right: str) -> bool:
    return _normalize_hex(left).lower() == _normalize_hex(right).lower()


def signing_wrapper(schema_id: str, canonical_json: str) -> bytes:
    """The 88 bytes a Chio signature covers; refuses an unregistered schema id."""

    if schema_id not in KNOWN_SIGNED_ARTIFACT_SCHEMAS:
        raise ChioInvariantError(
            "unregistered_schema_id",
            f"unregistered signed-artifact schema id: {schema_id}",
        )
    return (
        SIGNING_WRAPPER_PREFIX
        + hashlib.sha256(schema_id.encode("utf-8")).digest()
        + hashlib.sha256(canonical_json.encode("utf-8")).digest()
    )


def public_key_from_seed_ed25519(seed_hex: str) -> str:
    return _signing_key_from_seed_hex(seed_hex).get_verifying_key().to_bytes().hex()


def sign_wrapped_json_ed25519(schema_id: str, input_text: str, seed_hex: str) -> dict[str, str]:
    canonical_json = canonicalize_json_string(input_text)
    wrapper = signing_wrapper(schema_id, canonical_json)
    signing_key = _signing_key_from_seed_hex(seed_hex)
    return {
        "schema_id": schema_id,
        "canonical_json": canonical_json,
        "public_key_hex": signing_key.get_verifying_key().to_bytes().hex(),
        "signature_hex": signing_key.sign(wrapper).hex(),
    }


def _verify_wrapped_canonical(
    schema_id: str,
    canonical_json: str,
    public_key_hex: str,
    signature_hex: str,
) -> None:
    wrapper = signing_wrapper(schema_id, canonical_json)
    key_algorithm = _encoded_algorithm(public_key_hex)
    signature_algorithm = _encoded_algorithm(signature_hex)
    if key_algorithm != signature_algorithm:
        raise ChioInvariantError(
            "signature_algorithm_mismatch",
            f"signature algorithm {signature_algorithm} does not match the pinned key algorithm {key_algorithm}",
        )
    if key_algorithm != "ed25519":
        raise ChioInvariantError(
            "unsupported_algorithm",
            f"signature algorithm {key_algorithm} is not supported by this SDK",
        )
    verifying_key = _verifying_key_from_hex(public_key_hex)
    signature = _hex_to_bytes(signature_hex, expected_bytes=64, code="invalid_signature")
    try:
        verifying_key.verify(signature, wrapper)
    except BadSignatureError as exc:
        raise ChioInvariantError("signature_rejected", "signature rejected") from exc


def verify_wrapped_json(
    schema_id: str,
    input_text: str,
    public_key_hex: str,
    signature_hex: str,
) -> None:
    """Verify a signature over the wrapper of ``input_text`` under ``schema_id``.

    The pinned key's encoding alone selects the algorithm; a signature encoded
    for another algorithm raises before any cryptographic check.
    """

    _verify_wrapped_canonical(
        schema_id,
        canonicalize_json_string(input_text),
        public_key_hex,
        signature_hex,
    )


def wrapped_signature_valid(
    schema_id: str,
    canonical_json: str,
    public_key_hex: str,
    signature_hex: str,
) -> bool:
    """A rejected signature is ``False``; every other refusal raises."""

    try:
        _verify_wrapped_canonical(schema_id, canonical_json, public_key_hex, signature_hex)
    except ChioInvariantError as error:
        if error.code == "signature_rejected":
            return False
        raise
    return True
