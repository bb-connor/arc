"""Shared client-side shape checks, without claiming signature verification.

The service remains responsible for cryptography, current authority, exact
invocation binding, expiry and durable single-use redemption.
"""

from __future__ import annotations

from typing import Any

from chio_sdk.errors import ChioValidationError


def require_capability(
    token: Any, capability_id: str | None, requested_by: str | None
) -> dict[str, Any]:
    if not isinstance(token, dict) or not token.get("id") or not token.get("signature"):
        raise ChioValidationError("a full signed capability is required")
    if capability_id is not None and capability_id != token["id"]:
        raise ChioValidationError("capability_id does not match the signed capability")
    if not requested_by or requested_by != token.get("subject"):
        raise ChioValidationError("requested_by must match the capability subject")
    return token


def require_decision(token: Any, approval_id: str, decision: str) -> dict[str, Any]:
    if not isinstance(token, dict) or not all(
        token.get(field)
        for field in ("id", "approver", "signature", "governed_intent_hash")
    ):
        raise ChioValidationError("an approver-signed token is required")
    if token.get("request_id") != approval_id:
        raise ChioValidationError("signed token request_id must match approval_id")
    if token.get("decision") != decision:
        raise ChioValidationError("signed token decision must match verdict")
    return token
