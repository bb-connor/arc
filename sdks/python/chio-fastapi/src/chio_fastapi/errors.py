"""Chio error codes and framework-native error responses for FastAPI."""

from __future__ import annotations

import enum
from typing import Any

from fastapi.responses import JSONResponse


class ChioErrorCode(str, enum.Enum):
    """Standard Chio error codes returned in JSON error responses."""

    CAPABILITY_REQUIRED = "CHIO_CAPABILITY_REQUIRED"
    CAPABILITY_EXPIRED = "CHIO_CAPABILITY_EXPIRED"
    CAPABILITY_INSUFFICIENT = "CHIO_CAPABILITY_INSUFFICIENT"
    GUARD_DENIED = "CHIO_GUARD_DENIED"
    APPROVAL_REQUIRED = "CHIO_APPROVAL_REQUIRED"
    BUDGET_EXCEEDED = "CHIO_BUDGET_EXCEEDED"
    SIDECAR_UNAVAILABLE = "CHIO_SIDECAR_UNAVAILABLE"
    INTERNAL_ERROR = "CHIO_INTERNAL_ERROR"


def chio_error_response(
    status_code: int,
    code: ChioErrorCode,
    message: str,
    *,
    guard: str | None = None,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    """Build a standard Chio JSON error response for FastAPI.

    Returns a JSONResponse with the Chio error envelope::

        {
            "error": {
                "code": "CHIO_GUARD_DENIED",
                "message": "ForbiddenPathGuard denied the request",
                "guard": "ForbiddenPathGuard",
                "details": {}
            }
        }
    """
    body: dict[str, Any] = {
        "error": {
            "code": code.value,
            "message": message,
        }
    }
    if guard is not None:
        body["error"]["guard"] = guard
    if details is not None:
        body["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=body)
