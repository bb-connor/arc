"""ARC FastAPI integration -- decorators and dependency injection for ARC capabilities."""

from arc_fastapi.decorators import arc_requires, arc_approval, arc_budget
from arc_fastapi.dependencies import (
    get_arc_client,
    get_arc_receipt,
    get_caller_identity,
)
from arc_fastapi.errors import ArcErrorCode, arc_error_response

__all__ = [
    "arc_requires",
    "arc_approval",
    "arc_budget",
    "get_arc_client",
    "get_arc_receipt",
    "get_caller_identity",
    "ArcErrorCode",
    "arc_error_response",
]
