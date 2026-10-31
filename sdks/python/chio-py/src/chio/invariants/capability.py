from __future__ import annotations

import re
from typing import Any

from ..errors import ChioInvariantError, parse_json_text_unique_keys
from .json import canonicalize_json
from .signing import wrapped_signature_valid


CAPABILITY_SCHEMA = "chio.capability.v1"
DELEGATION_LINK_SCHEMA = "chio.delegation-link.v1"

_CAPABILITY_MEMBERS = frozenset(
    {
        "schema",
        "id",
        "issuer",
        "subject",
        "scope",
        "issued_at",
        "expires_at",
        "delegation_chain",
        "aggregate_invocation_budget",
        "caveats",
        "scope_attenuations",
        "attenuation_proof",
        "budget_share_bps",
        "root_anchor",
        "signature",
    }
)
_DELEGATION_LINK_MEMBERS = frozenset(
    {
        "capability_id",
        "delegator",
        "delegatee",
        "attenuations",
        "timestamp",
        "scope_hash",
        "aggregate_budget",
        "cumulative_approval",
        "signature",
    }
)


_ROOT_ANCHOR_REQUIRED = (
    "kind",
    "context_digest",
    "root_policy_digest",
    "anchored_at",
    "assertion_exp",
)
_ROOT_ANCHOR_MEMBERS = frozenset(_ROOT_ANCHOR_REQUIRED)
_ROOT_ANCHOR_KINDS = frozenset(
    {
        "oauth_id_jag",
        "entra_jwt",
        "entra_agent_id",
        "oidc_jwt",
        "oauth_introspection",
        "chio_local_as",
        "chio_operator_key",
        "operator_static_bearer",
    }
)
_ROOT_ANCHOR_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_ROOT_ANCHOR_INTEGER = 2**53 - 1


def _reject_unknown_members(value: dict[str, Any], allowed: frozenset[str], kind: str) -> None:
    for key in sorted(value):
        if key not in allowed:
            raise ChioInvariantError("json", f"{kind} has unknown member {key}")


def parse_capability_json(input_text: str) -> dict[str, Any]:
    parsed = parse_json_text_unique_keys(input_text)
    if not isinstance(parsed, dict):
        raise ChioInvariantError("json", "capability must be a JSON object")
    _require_capability_schema(parsed)
    return parsed


def _require_capability_schema(capability: dict[str, Any]) -> None:
    if capability.get("schema") != CAPABILITY_SCHEMA:
        raise ChioInvariantError("json", 'capability schema must be "chio.capability.v1"')
    _reject_unknown_members(capability, _CAPABILITY_MEMBERS, "capability")
    if "root_anchor" in capability:
        _validate_root_anchor(capability["root_anchor"])


def _validate_root_anchor(anchor: Any) -> None:
    if not isinstance(anchor, dict):
        raise ChioInvariantError("json", "root_anchor must be a JSON object")
    _reject_unknown_members(anchor, _ROOT_ANCHOR_MEMBERS, "root_anchor")
    for member in _ROOT_ANCHOR_REQUIRED:
        if member not in anchor:
            raise ChioInvariantError("json", f"root_anchor is missing member {member}")
    kind = anchor["kind"]
    if not isinstance(kind, str) or kind not in _ROOT_ANCHOR_KINDS:
        raise ChioInvariantError("json", "root_anchor kind is not a known anchor kind")
    for member in ("context_digest", "root_policy_digest"):
        digest = anchor[member]
        if not isinstance(digest, str) or _ROOT_ANCHOR_DIGEST.fullmatch(digest) is None:
            raise ChioInvariantError("json", f"root_anchor {member} must be a sha256 digest")
    for member in ("anchored_at", "assertion_exp"):
        if not _is_root_anchor_integer(anchor[member]):
            raise ChioInvariantError("json", f"root_anchor {member} must be an unsigned integer")


def _is_root_anchor_integer(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= _MAX_ROOT_ANCHOR_INTEGER
    )


def _capability_body(capability: dict[str, Any]) -> dict[str, Any]:
    omitted = {
        "attenuation_proof",
        "budget_share_bps",
        "caveats",
        "schema",
        "scope_attenuations",
        "signature",
    }
    return {key: value for key, value in capability.items() if key not in omitted}


def _delegation_link_body(link: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in link.items() if key != "signature"}


def _non_empty_list(value: Any) -> bool:
    return isinstance(value, list) and len(value) > 0


def capability_signing_body(capability: dict[str, Any]) -> dict[str, Any]:
    _require_capability_schema(capability)
    body = _capability_body(capability)
    signing_body = {
        "schema": capability["schema"],
        **body,
    }
    if not _non_empty_list(signing_body.get("delegation_chain")):
        signing_body.pop("delegation_chain", None)
    if _non_empty_list(capability.get("caveats")):
        signing_body["caveats"] = capability["caveats"]
    if _non_empty_list(capability.get("scope_attenuations")):
        signing_body["scope_attenuations"] = capability["scope_attenuations"]
    if capability.get("attenuation_proof") is not None:
        signing_body["attenuation_proof"] = capability["attenuation_proof"]
    if capability.get("budget_share_bps") is not None:
        signing_body["budget_share_bps"] = capability["budget_share_bps"]
    return signing_body


def capability_signing_body_canonical_json(capability: dict[str, Any]) -> str:
    return canonicalize_json(capability_signing_body(capability))


def _verify_delegation_chain(
    chain: list[dict[str, Any]],
    max_delegation_depth: int | None,
) -> bool:
    if max_delegation_depth is not None and len(chain) > max_delegation_depth:
        return False
    for index, current in enumerate(chain):
        _reject_unknown_members(current, _DELEGATION_LINK_MEMBERS, "delegation link")
        if not wrapped_signature_valid(
            DELEGATION_LINK_SCHEMA,
            canonicalize_json(_delegation_link_body(current)),
            current["delegator"],
            current["signature"],
        ):
            return False
        if index > 0:
            previous = chain[index - 1]
            if previous["delegatee"] != current["delegator"]:
                return False
            if current["timestamp"] < previous["timestamp"]:
                return False
    return True


def verify_capability(
    capability: dict[str, Any],
    now: int,
    max_delegation_depth: int | None = None,
) -> dict[str, Any]:
    if now < capability["issued_at"]:
        time_status = "not_yet_valid"
    elif now >= capability["expires_at"]:
        time_status = "expired"
    else:
        time_status = "valid"
    return {
        "signature_valid": wrapped_signature_valid(
            CAPABILITY_SCHEMA,
            capability_signing_body_canonical_json(capability),
            capability["issuer"],
            capability["signature"],
        ),
        "delegation_chain_shape_valid": _verify_delegation_chain(
            capability.get("delegation_chain", []),
            max_delegation_depth,
        ),
        "time_valid": time_status == "valid",
        "time_status": time_status,
    }


def verify_capability_json(
    input_text: str,
    now: int,
    max_delegation_depth: int | None = None,
) -> dict[str, Any]:
    return verify_capability(parse_capability_json(input_text), now, max_delegation_depth)
