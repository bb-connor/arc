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
_MANIFEST_FIELDS = {
    "schema",
    "server_id",
    "name",
    "description",
    "version",
    "tools",
    "server_tools",
    "required_permissions",
    "public_key",
}
_TOOL_FIELDS = {
    "name",
    "description",
    "input_schema",
    "output_schema",
    "pricing",
    "has_side_effects",
    "latency_hint",
}
_V2_TOOL_FIELDS = {
    "name", "description", "input_schema", "output_schema", "pricing",
    "annotations", "latency_hint", "flow",
}
_V2_ANNOTATION_FIELDS = {
    "read_only", "destructive", "idempotent", "requires_approval",
}
_V2_PERMISSION_FIELDS = {
    "read_paths", "write_paths", "network_destinations",
    "environment_variables", "native_syscall_profile",
}
_FLOW_FIELDS = {
    "output_label", "input_clearance", "egress", "declassification_purposes",
}
_NATIVE_PROFILES = {"native_minimal_v1", "native_standard_v1", "brokered_native_v1"}
_FORBIDDEN_ENVIRONMENT_PREFIXES = ("LD_", "DYLD_", "BASH_FUNC_", "MALLOC_")
_FORBIDDEN_ENVIRONMENT_NAMES = {
    "BASH_ENV",
    "DOCKER_CONFIG",
    "ENV",
    "GCONV_PATH",
    "GEM_HOME",
    "GEM_PATH",
    "GIT_ASKPASS",
    "GLIBC_TUNABLES",
    "GPG_AGENT_INFO",
    "IFS",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "KRB5CCNAME",
    "LOCPATH",
    "NETRC",
    "NLSPATH",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NPM_CONFIG_USERCONFIG",
    "PERL5OPT",
    "PERL5LIB",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "RUBYLIB",
    "RUBYOPT",
    "RUSTC_WRAPPER",
    "SSLKEYLOGFILE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SSH_AUTH_SOCK",
    "SUDO_ASKPASS",
    "ZDOTDIR",
    "_JAVA_OPTIONS",
}
_CREDENTIAL_ENVIRONMENT_MARKERS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "API_KEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "AUTHORIZATION",
)
_PRICING_FIELDS = {"pricing_model", "base_price", "unit_price", "billing_unit"}
_SERVER_TOOLS = {"computer_use", "bash", "text_editor"}
_LATENCY_HINTS = {"instant", "fast", "moderate", "slow"}
_MAX_U64 = 2**64 - 1


def parse_signed_manifest_json(input_text: str) -> dict[str, Any]:
    return parse_json_text(input_text)


def signed_manifest_body_canonical_json(signed_manifest: dict[str, Any]) -> str:
    return canonicalize_json(signed_manifest["manifest"])


def _validate_manifest_structure(manifest: dict[str, Any]) -> bool:
    if manifest.get("schema") == "chio.manifest.v2":
        return _validate_manifest_v2(manifest)
    return _validate_manifest_v1(manifest)


def _validate_manifest_v1(manifest: dict[str, Any]) -> bool:
    if not _has_only_known_keys(manifest, _MANIFEST_FIELDS):
        return False
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
    if not isinstance(manifest.get("public_key"), str):
        return False
    if not _validate_server_tools(manifest.get("server_tools")):
        return False
    seen: set[str] = set()
    for tool in tools:
        if not isinstance(tool, dict):
            return False
        if not _has_only_known_keys(tool, _TOOL_FIELDS):
            return False
        name = tool.get("name")
        if not _is_valid_tool_name(name) or name in seen:
            return False
        seen.add(name)
        if not _is_json_object(tool.get("input_schema")):
            return False
        if not isinstance(tool.get("description"), str) or not isinstance(
            tool.get("has_side_effects"), bool
        ):
            return False
        output_schema = tool.get("output_schema")
        if output_schema is not None and not _is_json_object(output_schema):
            return False
        if not _validate_tool_pricing(tool.get("pricing")):
            return False
        latency_hint = tool.get("latency_hint")
        if latency_hint is not None and latency_hint not in _LATENCY_HINTS:
            return False
    return _validate_required_permissions(manifest.get("required_permissions"))


def _validate_manifest_v2(manifest: dict[str, Any]) -> bool:
    if not _has_only_known_keys(manifest, _MANIFEST_FIELDS):
        return False
    if not (
        manifest.get("schema") == "chio.manifest.v2"
        and _is_valid_manifest_text_field(manifest.get("server_id"))
        and _is_valid_manifest_text_field(manifest.get("name"))
        and _is_valid_manifest_text_field(manifest.get("version"))
        and isinstance(manifest.get("public_key"), str)
    ):
        return False
    if "description" in manifest and not isinstance(manifest["description"], str):
        return False
    if "server_tools" in manifest:
        tools = manifest["server_tools"]
        if not isinstance(tools, list) or not tools or not _validate_server_tools(tools):
            return False
    if "required_permissions" in manifest and not _validate_required_permissions_v2(
        manifest["required_permissions"]
    ):
        return False
    tools = manifest.get("tools")
    if not isinstance(tools, list) or not tools:
        return False
    seen: set[str] = set()
    for tool in tools:
        if not isinstance(tool, dict) or not _has_only_known_keys(tool, _V2_TOOL_FIELDS):
            return False
        name = tool.get("name")
        if not _is_valid_tool_name(name) or name in seen:
            return False
        seen.add(name)
        if not isinstance(tool.get("description"), str) or not _is_json_object(
            tool.get("input_schema")
        ):
            return False
        if "output_schema" in tool and not _is_json_object(tool["output_schema"]):
            return False
        if "pricing" in tool and (
            tool["pricing"] is None or not _validate_tool_pricing(tool["pricing"])
        ):
            return False
        if not _validate_annotations_v2(tool.get("annotations")):
            return False
        if "latency_hint" in tool and tool["latency_hint"] not in _LATENCY_HINTS:
            return False
        if "flow" in tool and not _validate_flow_v2(tool["flow"]):
            return False
    return True


def _validate_annotations_v2(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == _V2_ANNOTATION_FIELDS
        and all(isinstance(value[field], bool) for field in _V2_ANNOTATION_FIELDS)
    )


def _validate_flow_v2(value: Any) -> bool:
    if not isinstance(value, dict) or not _has_only_known_keys(value, _FLOW_FIELDS):
        return False
    if not isinstance(value.get("egress"), bool):
        return False
    for field in ("output_label", "input_clearance"):
        if field in value and not _validate_known_label(value[field]):
            return False
    if "declassification_purposes" in value:
        purposes = value["declassification_purposes"]
        if not isinstance(purposes, list) or not purposes:
            return False
        seen: set[str] = set()
        for purpose in purposes:
            if not _is_valid_identifier(purpose) or purpose in seen:
                return False
            seen.add(purpose)
    return True


def _validate_known_label(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {"kind", "owners", "compartments"}:
        return False
    owners = value.get("owners")
    compartments = value.get("compartments")
    if value.get("kind") != "known" or not isinstance(owners, dict) or not isinstance(
        compartments, list
    ):
        return False
    if len(owners) > 64 or len(compartments) > 64:
        return False
    seen_compartments: set[str] = set()
    for item in compartments:
        if not _is_valid_identifier(item) or item in seen_compartments:
            return False
        seen_compartments.add(item)
    for owner, readers in owners.items():
        if not _is_valid_identifier(owner) or not isinstance(readers, list) or len(readers) > 256:
            return False
        seen_readers: set[str] = set()
        for reader in readers:
            if not _is_valid_identifier(reader) or reader in seen_readers:
                return False
            seen_readers.add(reader)
        if owner not in seen_readers:
            return False
    return True


def _is_valid_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value.encode()) <= 256
        and value.strip() == value
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _validate_required_permissions_v2(value: Any) -> bool:
    if not isinstance(value, dict) or not _has_only_known_keys(value, _V2_PERMISSION_FIELDS):
        return False
    if value.get("native_syscall_profile") not in _NATIVE_PROFILES:
        return False
    for field in ("read_paths", "write_paths"):
        if field in value and not _validate_path_list(value[field]):
            return False
    if "environment_variables" in value and not _validate_environment_list(
        value["environment_variables"]
    ):
        return False
    if "network_destinations" in value and not _validate_network_destinations(
        value["network_destinations"]
    ):
        return False
    return True


def _validate_path_list(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    seen: set[str] = set()
    for path in value:
        if not (
            isinstance(path, str)
            and path.startswith("/")
            and path != "/"
            and all(component not in {"", ".", ".."} for component in path.split("/")[1:])
            and path.strip() == path
            and not any(ord(character) < 32 or ord(character) == 127 for character in path)
            and path not in seen
        ):
            return False
        seen.add(path)
    return True


def _validate_environment_list(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    seen: set[str] = set()
    for name in value:
        if not (
            isinstance(name, str)
            and name
            and (name[0].isascii() and (name[0].isalpha() or name[0] == "_"))
            and all(character.isascii() and (character.isalnum() or character == "_") for character in name)
            and not _is_forbidden_environment_name(name)
            and name not in seen
        ):
            return False
        seen.add(name)
    return True


def _is_forbidden_environment_name(name: str) -> bool:
    return (
        name.startswith(_FORBIDDEN_ENVIRONMENT_PREFIXES)
        or name in _FORBIDDEN_ENVIRONMENT_NAMES
        or any(marker in name for marker in _CREDENTIAL_ENVIRONMENT_MARKERS)
    )


def _validate_network_destinations(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    seen: set[tuple[str, int]] = set()
    for destination in value:
        if not isinstance(destination, dict) or set(destination) != {"host", "port"}:
            return False
        host = destination.get("host")
        port = destination.get("port")
        if (
            not isinstance(host, str)
            or not host
            or len(host) > 253
            or host != host.lower()
            or any(character.isspace() or character in "*/" for character in host)
            or not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65535
            or (host, port) in seen
        ):
            return False
        seen.add((host, port))
    return True


def _is_valid_manifest_text_field(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and value.strip() == value
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _is_valid_tool_name(name: Any) -> bool:
    return _is_valid_manifest_text_field(name)


def _is_json_object(value: Any) -> bool:
    return isinstance(value, dict)


def _has_only_known_keys(value: dict[str, Any], known_keys: set[str]) -> bool:
    return all(key in known_keys for key in value)


def _validate_tool_pricing(pricing: Any) -> bool:
    if pricing is None:
        return True
    if not isinstance(pricing, dict):
        return False
    if not _has_only_known_keys(pricing, _PRICING_FIELDS):
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


def _validate_server_tools(server_tools: Any) -> bool:
    if server_tools is None:
        return True
    if not isinstance(server_tools, list):
        return False
    seen: set[str] = set()
    for server_tool in server_tools:
        if (
            not isinstance(server_tool, str)
            or server_tool not in _SERVER_TOOLS
            or server_tool in seen
        ):
            return False
        seen.add(server_tool)
    return True


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
    envelope_valid = _validate_signed_manifest_envelope(signed_manifest)
    manifest = signed_manifest.get("manifest") if isinstance(signed_manifest, dict) else None
    manifest_valid = isinstance(manifest, dict)
    signature = signed_manifest.get("signature") if isinstance(signed_manifest, dict) else None
    signer_key = signed_manifest.get("signer_key") if isinstance(signed_manifest, dict) else None
    embedded_public_key = manifest.get("public_key") if manifest_valid else None
    embedded_public_key_valid = isinstance(
        embedded_public_key, str
    ) and is_valid_public_key_hex(embedded_public_key)
    signature_valid = (
        envelope_valid
        and manifest_valid
        and isinstance(signature, str)
        and isinstance(signer_key, str)
        and _verify_signed_manifest_signature(manifest, signer_key, signature)
    )
    return {
        "structure_valid": envelope_valid
        and manifest_valid
        and _validate_manifest_structure(manifest),
        "signature_valid": signature_valid,
        "embedded_public_key_valid": embedded_public_key_valid,
        "embedded_public_key_matches_signer": embedded_public_key_valid
        and isinstance(signer_key, str)
        and public_key_hex_matches(
            embedded_public_key,
            signer_key,
        ),
    }


def _verify_signed_manifest_signature(
    manifest: dict[str, Any], signer_key: str, signature: str
) -> bool:
    try:
        return verify_utf8_message_ed25519(
            canonicalize_json(manifest),
            signer_key,
            signature,
        )
    except Exception:
        return False


def _validate_signed_manifest_envelope(signed_manifest: Any) -> bool:
    return isinstance(signed_manifest, dict) and set(signed_manifest) == _SIGNED_MANIFEST_FIELDS


def verify_signed_manifest_json(input_text: str) -> dict[str, Any]:
    return verify_signed_manifest(parse_signed_manifest_json(input_text))
