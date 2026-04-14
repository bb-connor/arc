"""ARC error codes and framework-native error responses for FastAPI."""

from __future__ import annotations

import enum
from typing import Any

from fastapi.responses import JSONResponse


class ArcErrorCode(str, enum.Enum):
    """Standard ARC error codes returned in JSON error responses."""

    CAPABILITY_REQUIRED = "ARC_CAPABILITY_REQUIRED"
    CAPABILITY_EXPIRED = "ARC_CAPABILITY_EXPIRED"
    CAPABILITY_INSUFFICIENT = "ARC_CAPABILITY_INSUFFICIENT"
    GUARD_DENIED = "ARC_GUARD_DENIED"
    APPROVAL_REQUIRED = "ARC_APPROVAL_REQUIRED"
    BUDGET_EXCEEDED = "ARC_BUDGET_EXCEEDED"
    SIDECAR_UNAVAILABLE = "ARC_SIDECAR_UNAVAILABLE"
    INTERNAL_ERROR = "ARC_INTERNAL_ERROR"


def arc_error_response(
    status_code: int,
    code: ArcErrorCode,
    message: str,
    *,
    guard: str | None = None,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    """Build a standard ARC JSON error response for FastAPI.

    Returns a JSONResponse with the ARC error envelope::

        {
            "error": {
                "code": "ARC_GUARD_DENIED",
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
