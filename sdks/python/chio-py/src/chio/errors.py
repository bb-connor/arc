from __future__ import annotations

import json
from typing import Any, Literal

ChioInvariantErrorCode = Literal[
    "json",
    "canonical_json",
    "invalid_hex",
    "invalid_public_key",
    "invalid_signature",
]


class ChioError(Exception):
    pass


class ChioInvariantError(ChioError):
    def __init__(self, code: ChioInvariantErrorCode, message: str):
        super().__init__(message)
        self.code = code


class ChioTransportError(ChioError):
    pass


class ChioQueryError(ChioError):
    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(message)
        self.status = status


class ChioRpcError(ChioError):
    def __init__(self, message: str, *, code: int | None = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


def parse_json_text(input_text: str) -> Any:
    try:
        return json.loads(input_text)
    except json.JSONDecodeError as exc:
        raise ChioInvariantError("json", "input is not valid JSON") from exc


def _unique_key_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for key, value in pairs:
        if key in decoded:
            raise ChioInvariantError("json", f"input contains duplicate object key: {key}")
        decoded[key] = value
    return decoded


def parse_json_text_unique_keys(input_text: str) -> Any:
    """Parse like ``parse_json_text``, rejecting a repeated object key at any depth.

    Numbers and strings decode exactly as ``json.loads`` decodes them.
    """
    try:
        return json.loads(input_text, object_pairs_hook=_unique_key_object)
    except json.JSONDecodeError as exc:
        raise ChioInvariantError("json", "input is not valid JSON") from exc
