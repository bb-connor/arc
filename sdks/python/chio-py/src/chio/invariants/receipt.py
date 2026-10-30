from __future__ import annotations

from typing import Any

from ..errors import ChioInvariantError, parse_json_text_unique_keys
from .hashing import sha256_hex_utf8
from .json import canonicalize_json
from .signing import (
    public_key_hex_matches,
    wrapped_signature_valid,
)

RECEIPT_SCHEMA = "chio.receipt.v1"


def _safe_verify_receipt_signature(
    signed_text: str,
    signature: str,
    public_key: str,
) -> bool:
    """Receipts whose signature this SDK cannot check report ``False``."""

    try:
        return wrapped_signature_valid(RECEIPT_SCHEMA, signed_text, public_key, signature)
    except ChioInvariantError:
        return False


_RECEIPT_MEMBERS = frozenset({
    "action",
    "actor_chain",
    "bbs_projection_version",
    "bbs_signature",
    "boundary_class",
    "capability_id",
    "content_hash",
    "decision",
    "evidence",
    "id",
    "kernel_key",
    "metadata",
    "observation_outcome",
    "policy_hash",
    "receipt_kind",
    "redaction_mode",
    "signature",
    "tenant_id",
    "timestamp",
    "tool_name",
    "tool_origin",
    "tool_server",
    "trust_level",
})
_ACTION_MEMBERS = frozenset({"parameters", "parameter_hash"})
_ACTOR_MEMBERS = frozenset({"actor_id", "actor_kind"})
_EVIDENCE_MEMBERS = frozenset({"guard_name", "verdict", "details"})
_BBS_SIGNATURE_MEMBERS = frozenset({
    "schema",
    "projection_version",
    "algorithm",
    "ciphersuite",
    "issuer_fingerprint",
    "issuer_public_key_hex",
    "message_count",
    "signature_hex",
})
_DECISION_MEMBERS = {
    "allow": frozenset({"verdict"}),
    "deny": frozenset({"verdict", "reason", "guard"}),
    "cancelled": frozenset({"verdict", "reason"}),
    "incomplete": frozenset({"verdict", "reason"}),
}


def _require_members(value: Any, allowed: frozenset[str], path: str) -> None:
    if not isinstance(value, dict):
        return
    for key in sorted(value):
        if key not in allowed:
            raise ChioInvariantError("json", f"unknown receipt member: {path}/{key}")


def _require_closed_receipt(receipt: dict[str, Any]) -> None:
    """Refuse any member the signed receipt shape does not define."""
    _require_members(receipt, _RECEIPT_MEMBERS, "")
    _require_members(receipt.get("action"), _ACTION_MEMBERS, "/action")
    _require_members(receipt.get("bbs_signature"), _BBS_SIGNATURE_MEMBERS, "/bbs_signature")
    decision = receipt.get("decision")
    if isinstance(decision, dict):
        allowed = _DECISION_MEMBERS.get(decision.get("verdict"), frozenset({"verdict"}))
        _require_members(decision, allowed, "/decision")
    for name, allowed in (("actor_chain", _ACTOR_MEMBERS), ("evidence", _EVIDENCE_MEMBERS)):
        entries = receipt.get(name)
        if isinstance(entries, list):
            for index, entry in enumerate(entries):
                _require_members(entry, allowed, f"/{name}/{index}")


def parse_receipt_json(input_text: str) -> dict[str, Any]:
    """Decode signed receipt text. A repeated object key at any depth raises
    ``ChioInvariantError`` with code ``json`` before any field is read."""
    return parse_json_text_unique_keys(input_text)


def _receipt_body(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in receipt.items()
        if key != "signature" and value is not None
    }


def receipt_body_canonical_json(receipt: dict[str, Any]) -> str:
    return canonicalize_json(_receipt_body(receipt))


def _receipt_id_input(receipt: dict[str, Any]) -> dict[str, Any]:
    value: dict[str, Any] = {
        "timestamp": receipt["timestamp"],
        "capability_id": receipt["capability_id"],
        "tool_server": receipt["tool_server"],
        "tool_name": receipt["tool_name"],
        "action": receipt["action"],
        "receipt_kind": receipt["receipt_kind"],
        "boundary_class": receipt["boundary_class"],
        "tool_origin": receipt["tool_origin"],
        "redaction_mode": receipt["redaction_mode"],
        "content_hash": receipt["content_hash"],
        "policy_hash": receipt["policy_hash"],
        "kernel_key": receipt["kernel_key"],
    }
    if receipt.get("decision") is not None:
        value["decision"] = receipt["decision"]
    if receipt.get("observation_outcome") is not None:
        value["observation_outcome"] = receipt["observation_outcome"]
    if receipt.get("actor_chain"):
        value["actor_chain"] = receipt["actor_chain"]
    if receipt.get("evidence"):
        value["evidence"] = receipt["evidence"]
    if receipt.get("metadata") is not None:
        value["metadata"] = receipt["metadata"]
    value["trust_level"] = receipt["trust_level"]
    if receipt.get("tenant_id") is not None:
        value["tenant_id"] = receipt["tenant_id"]
    return value


def _content_addressed_receipt_id(receipt: dict[str, Any]) -> str:
    return sha256_hex_utf8(canonicalize_json(_receipt_id_input(receipt)))


def receipt_signing_body_canonical_json(receipt: dict[str, Any]) -> str:
    return canonicalize_json({
        "id": receipt["id"],
        "body": _receipt_id_input(receipt),
    })


def _receipt_semantics(receipt: dict[str, Any]) -> tuple[str, str]:
    return receipt["receipt_kind"], receipt["boundary_class"]


def _result_label(semantic_authorized: bool, receipt_kind: str, decision: str) -> str:
    if semantic_authorized:
        return "Authorized"
    if receipt_kind == "trace_observation":
        return "Observed"
    if receipt_kind == "advisory_evaluation":
        return "Advisory"
    return {
        "allow": "Allowed",
        "deny": "Denied",
        "cancelled": "Cancelled",
        "incomplete": "Incomplete",
        "none": "Invalid",
    }[decision]


def _valid_observation_outcome(value: Any) -> bool:
    return value in {"observed", "evaluated", "dropped"}


def _semantically_signable(receipt: dict[str, Any], decision: str) -> bool:
    receipt_kind, boundary_class = _receipt_semantics(receipt)
    trust_level = receipt.get("trust_level")
    observation_outcome = receipt.get("observation_outcome")
    if receipt_kind == "mediated_decision":
        return (
            boundary_class == "prevent"
            and trust_level == "mediated"
            and decision != "none"
            and observation_outcome is None
        )
    if receipt_kind == "trace_observation":
        return (
            boundary_class == "detect_only"
            and trust_level == "verified"
            and decision == "none"
            and _valid_observation_outcome(observation_outcome)
        )
    if receipt_kind == "advisory_evaluation":
        return (
            boundary_class == "advisory_only"
            and trust_level == "advisory"
            and decision == "none"
            and _valid_observation_outcome(observation_outcome)
        )
    return False


def verify_receipt(
    receipt: dict[str, Any],
    trusted_signers: list[str] | None = None,
) -> dict[str, Any]:
    _require_closed_receipt(receipt)
    decision_value = receipt.get("decision")
    decision = (
        decision_value.get("verdict", "none")
        if isinstance(decision_value, dict)
        else "none"
    )
    receipt_kind, boundary_class = _receipt_semantics(receipt)
    semantic_authorized = (
        receipt_kind == "mediated_decision"
        and boundary_class == "prevent"
        and receipt.get("trust_level") == "mediated"
        and receipt.get("observation_outcome") is None
        and decision == "allow"
    )
    receipt_id_valid = receipt["id"] == _content_addressed_receipt_id(receipt)
    signature_valid = (
        receipt_id_valid
        and _semantically_signable(receipt, decision)
        and _safe_verify_receipt_signature(
            receipt_signing_body_canonical_json(receipt),
            receipt["signature"],
            receipt["kernel_key"],
        )
    )
    parameter_hash_valid = receipt["action"]["parameter_hash"] == sha256_hex_utf8(
        canonicalize_json(receipt["action"]["parameters"])
    )
    signer_trusted = bool(trusted_signers) and any(
        public_key_hex_matches(signer, receipt["kernel_key"])
        for signer in trusted_signers or []
    )
    authorized = (
        semantic_authorized
        and signature_valid
        and parameter_hash_valid
        and receipt_id_valid
        and signer_trusted
    )
    return {
        "signature_valid": signature_valid,
        "parameter_hash_valid": parameter_hash_valid,
        "receipt_id_valid": receipt_id_valid,
        "decision": decision,
        "receipt_kind": receipt_kind,
        "boundary_class": boundary_class,
        "trust_level": receipt["trust_level"],
        "result": _result_label(semantic_authorized, receipt_kind, decision),
        "authorized": authorized,
        "signer_key_hex": receipt["kernel_key"],
        "signer_trusted": signer_trusted,
        "ok": signature_valid and parameter_hash_valid and receipt_id_valid and signer_trusted,
    }


def verify_receipt_with_trusted_signers(
    receipt: dict[str, Any],
    trusted_signers: list[str],
) -> dict[str, Any]:
    return verify_receipt(receipt, trusted_signers)


def verify_receipt_json(input_text: str) -> dict[str, Any]:
    return verify_receipt(parse_receipt_json(input_text))
