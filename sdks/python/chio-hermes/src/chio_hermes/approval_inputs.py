"""Bounded parsing for externally signed decision artifacts.

Parsing preserves the signed object. Signature and authority validation take
place at the service; Hermes never provisions or uses an approver private key.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_DECISION_BYTES = 65_536


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate field in signed token")
        value[key] = item
    return value


def _reject_number(value: str) -> Any:
    raise ValueError(f"non-integer number in signed token: {value}")


def parse_signed_token(raw: str | bytes) -> dict[str, Any]:
    if len(raw.encode("utf-8") if isinstance(raw, str) else raw) > MAX_DECISION_BYTES:
        raise ValueError("signed token exceeds 64 KiB")
    try:
        token = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except RecursionError as exc:
        raise ValueError("signed token nesting is too deep") from exc
    if not isinstance(token, dict) or not token.get("signature"):
        raise ValueError("an externally signed decision token is required")
    return token


def read_signed_token(path: str) -> dict[str, Any]:
    with Path(path).open("rb") as stream:
        return parse_signed_token(stream.read(MAX_DECISION_BYTES + 1))
