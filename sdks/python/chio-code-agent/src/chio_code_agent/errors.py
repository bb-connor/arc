"""Error types for the Chio code-agent SDK."""

from __future__ import annotations

from typing import Any

from chio_sdk.errors import ChioError


class ChioCodeAgentError(ChioError):
    """Base error for the chio-code-agent package.

    Raised for policy misconfiguration and for denials that originated
    locally (before reaching the sidecar). Sidecar denials continue to
    surface as :class:`chio_sdk.errors.ChioDeniedError`.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str = "CODE_AGENT_ERROR",
        tool_name: str | None = None,
        reason: str | None = None,
        guard: str | None = None,
    ) -> None:
        super().__init__(message, code=code)
        self.message = message
        self.tool_name = tool_name
        self.reason = reason
        self.guard = guard

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        for key, value in (
            ("tool_name", self.tool_name),
            ("reason", self.reason),
            ("guard", self.guard),
        ):
            if value is not None:
                payload[key] = value
        return payload


class ChioCodeAgentPolicyError(ChioCodeAgentError):
    """The bundled or user-supplied policy failed to load or validate."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="POLICY_ERROR")


class ChioCodeAgentDeniedError(ChioCodeAgentError):
    """A tool call was denied before it reached the sidecar.

    Raised by the local pre-flight check so that the caller sees an
    error shape consistent with :class:`chio_sdk.errors.ChioDeniedError`
    even when the operation never made it on the wire.
    """

    def __init__(
        self,
        message: str,
        *,
        tool_name: str,
        reason: str,
        guard: str,
    ) -> None:
        super().__init__(
            message,
            code="DENIED_LOCAL",
            tool_name=tool_name,
            reason=reason,
            guard=guard,
        )


__all__ = [
    "ChioCodeAgentError",
    "ChioCodeAgentPolicyError",
    "ChioCodeAgentDeniedError",
]
