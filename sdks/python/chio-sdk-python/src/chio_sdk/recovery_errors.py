"""Closed public errors for the native recovery transport."""
from __future__ import annotations

from enum import StrEnum


class RecoveryErrorCode(StrEnum):
    INVALID_COMMAND = "recovery.invalid_command"
    AUTHORITY_DENIED = "recovery.authority_denied"
    CONFLICT = "recovery.conflict"
    UNSUPPORTED_PROFILE = "recovery.unsupported_profile"
    UNCOVERED_MEDIATION = "recovery.uncovered_mediation"
    RESTART_REQUIRED = "recovery.restart_required"
    UNKNOWN_EFFECT = "recovery.unknown_effect"
    PROBE_EXPIRED = "recovery.probe_expired"
    ORIGIN_REFUSED = "recovery.origin_refused"
    BUSY = "recovery.busy"
    PROJECTION_TOO_LARGE = "recovery.projection_too_large"
    UNAVAILABLE = "recovery.unavailable"
    INVALID_RESPONSE = "recovery.invalid_response"
    REFUSED_OR_UNAVAILABLE = "recovery.refused_or_unavailable"


class RecoveryError(RuntimeError):
    """A fixed category without provider diagnostics or credentials."""

    def __init__(self, code: RecoveryErrorCode):
        self.code = code
        super().__init__(code.value)


_HOST_ERRORS = {
    400: frozenset({RecoveryErrorCode.INVALID_COMMAND}),
    403: frozenset({RecoveryErrorCode.AUTHORITY_DENIED}),
    409: frozenset({RecoveryErrorCode.CONFLICT, RecoveryErrorCode.UNSUPPORTED_PROFILE,
                    RecoveryErrorCode.UNCOVERED_MEDIATION, RecoveryErrorCode.RESTART_REQUIRED,
                    RecoveryErrorCode.UNKNOWN_EFFECT, RecoveryErrorCode.PROBE_EXPIRED,
                    RecoveryErrorCode.ORIGIN_REFUSED}),
    413: frozenset({RecoveryErrorCode.PROJECTION_TOO_LARGE}),
    503: frozenset({RecoveryErrorCode.UNAVAILABLE, RecoveryErrorCode.BUSY}),
}


def native_error(status: int, body: bytes) -> RecoveryError:
    """Accept only an exact category valid for its native HTTP status."""
    try:
        code = RecoveryErrorCode(body.decode("ascii")) if len(body) <= 64 else None
    except (UnicodeError, ValueError):
        code = None
    if code not in _HOST_ERRORS.get(status, ()):
        code = RecoveryErrorCode.REFUSED_OR_UNAVAILABLE
    return RecoveryError(code)
