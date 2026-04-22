"""Chio error codes and Django-native error responses."""

from __future__ import annotations

import enum
import json
from typing import Any

from django.http import JsonResponse


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
) -> JsonResponse:
    """Build a standard Chio JSON error response for Django.

    Returns a JsonResponse with the Chio error envelope.
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
    return JsonResponse(body, status=status_code)
