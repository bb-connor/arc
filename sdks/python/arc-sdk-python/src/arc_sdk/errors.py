"""ARC SDK error types."""

from __future__ import annotations


class ArcError(Exception):
    """Base error for all ARC SDK operations."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


class ArcConnectionError(ArcError):
    """Failed to connect to the ARC sidecar."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="CONNECTION_ERROR")


class ArcTimeoutError(ArcError):
    """Request to the ARC sidecar timed out."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="TIMEOUT")


class ArcDeniedError(ArcError):
    """The ARC kernel denied the request."""

    def __init__(
        self,
        message: str,
        *,
        guard: str | None = None,
        reason: str | None = None,
    ) -> None:
        super().__init__(message, code="DENIED")
        self.guard = guard
        self.reason = reason


class ArcValidationError(ArcError):
    """Local validation failed before contacting the sidecar."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="VALIDATION_ERROR")
