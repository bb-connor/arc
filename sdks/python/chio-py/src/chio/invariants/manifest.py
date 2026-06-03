from __future__ import annotations

from typing import Any

from ..errors import parse_json_text
from .json import canonicalize_json
from .signing import is_valid_public_key_hex, public_key_hex_matches, verify_utf8_message_ed25519

_REQUIRED_PERMISSION_FIELDS = (
    "read_paths",
    "write_paths",
    "network_hosts",
    "environment_variables",
)
_REQUIRED_PERMISSION_FIELD_SET = set(_REQUIRED_PERMISSION_FIELDS)
_PRICING_MODELS = {"flat", "per_invocation", "per_unit", "hybrid"}
_SIGNED_MANIFEST_FIELDS = {"manifest", "signature", "signer_key"}
_MAX_U64 = 2**64 - 1


def parse_signed_manifest_json(input_text: str) -> dict[str, Any]:
    return parse_json_text(input_text)


def signed_manifest_body_canonical_json(signed_manifest: dict[str, Any]) -> str:
    return canonicalize_json(signed_manifest["manifest"])


def _validate_manifest_structure(manifest: dict[str, Any]) -> bool:
    if manifest.get("schema") != "chio.manifest.v1":
        return False
    if not (
        _is_valid_manifest_text_field(manifest.get("server_id"))
        and _is_valid_manifest_text_field(manifest.get("name"))
        and _is_valid_manifest_text_field(manifest.get("version"))
    ):
        return False
    tools = manifest.get("tools", [])
    if not isinstance(tools, list) or not tools:
        return False
    seen: set[str] = set()
    for tool in tools:
        if not isinstance(tool, dict):
            return False
        name = tool.get("name")
        if not _is_valid_tool_name(name) or name in seen:
            return False
        seen.add(name)
        if not _is_json_object(tool.get("input_schema")):
            return False
        output_schema = tool.get("output_schema")
        if output_schema is not None and not _is_json_object(output_schema):
            return False
        if not _validate_tool_pricing(tool.get("pricing")):
            return False
    return _validate_required_permissions(manifest.get("required_permissions"))


def _is_valid_manifest_text_field(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value.strip() == value


def _is_valid_tool_name(name: Any) -> bool:
    return _is_valid_manifest_text_field(name)


def _is_json_object(value: Any) -> bool:
    return isinstance(value, dict)


def _validate_tool_pricing(pricing: Any) -> bool:
    if pricing is None:
        return True
    if not isinstance(pricing, dict):
        return False
    model = pricing.get("pricing_model")
    if model not in _PRICING_MODELS:
        return False
    if model == "flat":
        if not _require_pricing_amount(pricing.get("base_price")):
            return False
    elif model in {"per_invocation", "per_unit"}:
        if not _require_pricing_amount(
            pricing.get("unit_price")
        ) or not _is_valid_manifest_text_field(pricing.get("billing_unit")):
            return False
    elif model == "hybrid":
        if (
            not _require_pricing_amount(pricing.get("base_price"))
            or not _require_pricing_amount(pricing.get("unit_price"))
            or not _is_valid_manifest_text_field(pricing.get("billing_unit"))
        ):
            return False
    if not _validate_optional_pricing_amount(pricing.get("base_price")):
        return False
    if not _validate_optional_pricing_amount(pricing.get("unit_price")):
        return False
    billing_unit = pricing.get("billing_unit")
    if billing_unit is not None and not _is_valid_manifest_text_field(billing_unit):
        return False
    return True


def _require_pricing_amount(amount: Any) -> bool:
    return amount is not None and _validate_pricing_amount(amount)


def _validate_optional_pricing_amount(amount: Any) -> bool:
    if amount is None:
        return True
    return _validate_pricing_amount(amount)


def _validate_pricing_amount(amount: Any) -> bool:
    return (
        isinstance(amount, dict)
        and isinstance(amount.get("units"), int)
        and not isinstance(amount.get("units"), bool)
        and amount["units"] >= 0
        and amount["units"] <= _MAX_U64
        and _is_iso_4217_currency_code(amount.get("currency"))
    )


def _is_iso_4217_currency_code(currency: Any) -> bool:
    return (
        isinstance(currency, str)
        and len(currency) == 3
        and all("A" <= character <= "Z" for character in currency)
    )


def _validate_required_permissions(permissions: Any) -> bool:
    if permissions is None:
        return True
    if not isinstance(permissions, dict):
        return False
    if any(field not in _REQUIRED_PERMISSION_FIELD_SET for field in permissions):
        return False
    return all(
        _validate_required_permission_values(permissions.get(field))
        for field in _REQUIRED_PERMISSION_FIELDS
    )


def _validate_required_permission_values(values: Any) -> bool:
    if values is None:
        return True
    if not isinstance(values, list):
        return False
    seen: set[str] = set()
    for value in values:
        if not _is_valid_manifest_text_field(value) or value in seen:
            return False
        seen.add(value)
    return True


def verify_signed_manifest(signed_manifest: dict[str, Any]) -> dict[str, Any]:
    embedded_public_key_valid = is_valid_public_key_hex(
        signed_manifest["manifest"]["public_key"]
    )
    return {
        "structure_valid": _validate_signed_manifest_envelope(signed_manifest)
        and _validate_manifest_structure(signed_manifest["manifest"]),
        "signature_valid": verify_utf8_message_ed25519(
            signed_manifest_body_canonical_json(signed_manifest),
            signed_manifest["signer_key"],
            signed_manifest["signature"],
        ),
        "embedded_public_key_valid": embedded_public_key_valid,
        "embedded_public_key_matches_signer": embedded_public_key_valid
        and public_key_hex_matches(
            signed_manifest["manifest"]["public_key"],
            signed_manifest["signer_key"],
        ),
    }


def _validate_signed_manifest_envelope(signed_manifest: Any) -> bool:
    return isinstance(signed_manifest, dict) and set(signed_manifest) == _SIGNED_MANIFEST_FIELDS


def verify_signed_manifest_json(input_text: str) -> dict[str, Any]:
    return verify_signed_manifest(parse_signed_manifest_json(input_text))
