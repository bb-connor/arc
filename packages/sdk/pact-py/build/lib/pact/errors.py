from __future__ import annotations

import json
from typing import Any, Literal

PactInvariantErrorCode = Literal[
    "json",
    "canonical_json",
    "invalid_hex",
    "invalid_public_key",
    "invalid_signature",
]


class PactError(Exception):
    pass


class PactInvariantError(PactError):
    def __init__(self, code: PactInvariantErrorCode, message: str):
        super().__init__(message)
        self.code = code


class PactTransportError(PactError):
    pass


class PactRpcError(PactError):
    def __init__(self, message: str, *, code: int | None = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


def parse_json_text(input_text: str) -> Any:
    try:
        return json.loads(input_text)
    except json.JSONDecodeError as exc:
        raise PactInvariantError("json", "input is not valid JSON") from exc
