"""Closed historical projections of native recovery responses for host adapters."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ._generated.recovery.command_response_schema import RecoveryCommandResponseControl, RecoveryCommandResponseV1
from .recovery_errors import RecoveryError, RecoveryErrorCode


class RecoveryHostCategory(StrEnum):
    COMPLETE = "complete"
    COMPLETED_WITH_EFFECTS = "completed_with_effects"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    WAITING_FOR_OUTCOME = "waiting_for_outcome"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    CLOSED_WITHOUT_EFFECT = "closed_without_effect"
    WITHHELD = "withheld"
    QUARANTINED = "quarantined"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"
    REFUSED = "refused"
    UNAVAILABLE = "unavailable"
    RESTART_REQUIRED = "restart_required"
    CONFLICT = "conflict"
    UNSUPPORTED_PROFILE = "unsupported_profile"
    UNCOVERED_MEDIATION = "uncovered_mediation"
    PROBE_EXPIRED = "probe_expired"
    ORIGIN_REFUSED = "origin_refused"
    BUSY = "busy"
    PROJECTION_TOO_LARGE = "projection_too_large"
    BUDGET_EXHAUSTED = "budget_exhausted"
    INVALID_CHOICE = "invalid_choice"


_EFFECT_CATEGORIES = {
    "complete": RecoveryHostCategory.COMPLETE,
    "partial": RecoveryHostCategory.COMPLETED_WITH_EFFECTS,
    "failed_after_effect": RecoveryHostCategory.COMPLETED_WITH_EFFECTS,
    "awaiting_approval": RecoveryHostCategory.WAITING_FOR_APPROVAL,
    "in_flight": RecoveryHostCategory.WAITING_FOR_OUTCOME,
    "awaiting_caller_report": RecoveryHostCategory.WAITING_FOR_OUTCOME,
    "unknown": RecoveryHostCategory.RECONCILIATION_REQUIRED,
    "admission_unresolved": RecoveryHostCategory.RECONCILIATION_REQUIRED,
    "never_admitted": RecoveryHostCategory.CLOSED_WITHOUT_EFFECT,
    "closed_before_effect": RecoveryHostCategory.CLOSED_WITHOUT_EFFECT,
}
_ERROR_CATEGORIES = {
    RecoveryErrorCode.UNKNOWN_EFFECT: RecoveryHostCategory.RECONCILIATION_REQUIRED,
    RecoveryErrorCode.UNAVAILABLE: RecoveryHostCategory.UNAVAILABLE,
    RecoveryErrorCode.RESTART_REQUIRED: RecoveryHostCategory.RESTART_REQUIRED,
    RecoveryErrorCode.CONFLICT: RecoveryHostCategory.CONFLICT,
    RecoveryErrorCode.UNSUPPORTED_PROFILE: RecoveryHostCategory.UNSUPPORTED_PROFILE,
    RecoveryErrorCode.UNCOVERED_MEDIATION: RecoveryHostCategory.UNCOVERED_MEDIATION,
    RecoveryErrorCode.PROBE_EXPIRED: RecoveryHostCategory.PROBE_EXPIRED,
    RecoveryErrorCode.ORIGIN_REFUSED: RecoveryHostCategory.ORIGIN_REFUSED,
    RecoveryErrorCode.BUSY: RecoveryHostCategory.BUSY,
    RecoveryErrorCode.PROJECTION_TOO_LARGE: RecoveryHostCategory.PROJECTION_TOO_LARGE,
}


def _status_category(status: dict) -> RecoveryHostCategory:
    # A completed effect cannot override current custody or release restrictions.
    if status["control"] != "active":
        return RecoveryHostCategory(status["control"])
    if status["release"]["kind"] in {"withheld", "denied"}:
        return RecoveryHostCategory.WITHHELD
    return _EFFECT_CATEGORIES[status["effect"]["kind"]]


@dataclass(frozen=True, slots=True)
class RecoveryHostOutcome:
    """Historical native state and advisory category, without raw results.

    Effect, control and release remain independent native discriminants. Their
    presence records an observed response, never permission to execute an effect.
    """
    category: RecoveryHostCategory
    command_id: str = ""
    workflow_id: str = ""
    effect: str | None = None
    control: RecoveryCommandResponseControl | None = None
    release: str | None = None
    error_code: RecoveryErrorCode | None = None

    def __post_init__(self) -> None:
        # Preserve the existing string constructor while refusing an open
        # diagnostic string in this public, persistable result type.
        object.__setattr__(self, "category", RecoveryHostCategory(self.category))
        if self.effect is not None and self.effect not in _EFFECT_CATEGORIES:
            raise ValueError("recovery.invalid_outcome")
        if self.release is not None and self.release not in {
                "not_available", "pending", "withheld", "released", "denied"}:
            raise ValueError("recovery.invalid_outcome")
        if self.control is not None:
            object.__setattr__(self, "control", RecoveryCommandResponseControl(self.control))
        if self.error_code is not None:
            object.__setattr__(self, "error_code", RecoveryErrorCode(self.error_code))

    def as_dict(self) -> dict[str, str]:
        result = {"category": self.category.value}
        if self.command_id:
            result["command_id"] = self.command_id
        if self.workflow_id:
            result["workflow_id"] = self.workflow_id
        if self.effect is not None:
            result["effect"] = self.effect
        if self.control is not None:
            result["control"] = self.control.value
        if self.release is not None:
            result["release"] = self.release
        if self.error_code is not None:
            result["error_code"] = self.error_code.value
        return result

    @classmethod
    def from_status(cls, response: RecoveryCommandResponseV1) -> RecoveryHostOutcome:
        """Preserve native discriminants independently of advisory precedence."""
        status = response.model_dump(mode="json", by_alias=True)
        return cls(_status_category(status), status["command_id"], status["workflow_id"],
                   effect=status["effect"]["kind"], control=status["control"], release=status["release"]["kind"])

    @classmethod
    def from_error(cls, error: RecoveryError) -> RecoveryHostOutcome:
        """Retain the fixed transport category without upstream diagnostics."""
        return cls(_ERROR_CATEGORIES.get(error.code, RecoveryHostCategory.REFUSED), error_code=error.code)

