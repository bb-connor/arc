"""Chio FastAPI integration -- decorators and dependency injection for Chio capabilities."""

from chio_fastapi.decorators import chio_requires, chio_approval, chio_budget
from chio_fastapi.dependencies import (
    get_chio_client,
    get_chio_passthrough,
    get_chio_receipt,
    get_caller_identity,
)
from chio_fastapi.errors import ChioErrorCode, chio_error_response

__all__ = [
    "chio_requires",
    "chio_approval",
    "chio_budget",
    "get_chio_client",
    "get_chio_passthrough",
    "get_chio_receipt",
    "get_caller_identity",
    "ChioErrorCode",
    "chio_error_response",
]
