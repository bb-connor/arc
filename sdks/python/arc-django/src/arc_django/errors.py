"""ARC error codes and Django-native error responses."""

from __future__ import annotations

import enum
import json
from typing import Any

from django.http import JsonResponse


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
) -> JsonResponse:
    """Build a standard ARC JSON error response for Django.

    Returns a JsonResponse with the ARC error envelope.
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
