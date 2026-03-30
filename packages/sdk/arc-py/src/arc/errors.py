from __future__ import annotations

import json
from typing import Any, Literal

ArcInvariantErrorCode = Literal[
    "json",
    "canonical_json",
    "invalid_hex",
    "invalid_public_key",
    "invalid_signature",
]


class ArcError(Exception):
    pass


class ArcInvariantError(ArcError):
    def __init__(self, code: ArcInvariantErrorCode, message: str):
        super().__init__(message)
        self.code = code


class ArcTransportError(ArcError):
    pass


class ArcRpcError(ArcError):
    def __init__(self, message: str, *, code: int | None = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


def parse_json_text(input_text: str) -> Any:
    try:
        return json.loads(input_text)
    except json.JSONDecodeError as exc:
        raise ArcInvariantError("json", "input is not valid JSON") from exc
