"""Error types raised by the ARC Airflow integration."""

from __future__ import annotations

from typing import Any

from arc_sdk.errors import ArcError


class ArcAirflowError(ArcError):
    """An ARC-governed Airflow task invocation was denied or failed.

    Carries the sidecar verdict so callers (and Airflow task instance
    logs / XCom receipts) can inspect the guard that denied, the reason,
    and any structured hint the kernel emitted. The
    :class:`arc_airflow.ArcOperator` wrapper and the
    :func:`arc_airflow.arc_task` decorator translate this into an
    :class:`airflow.exceptions.AirflowException` whose ``__cause__`` is
    a :class:`PermissionError` so the roadmap's
    ``except PermissionError`` idiom keeps working even though Airflow
    re-raises the scheduler-facing exception type.
    """

    def __init__(
        self,
        message: str,
        *,
        task_id: str | None = None,
        dag_id: str | None = None,
        run_id: str | None = None,
        capability_id: str | None = None,
        tool_server: str | None = None,
        guard: str | None = None,
        reason: str | None = None,
        receipt_id: str | None = None,
        decision: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code="TASK_DENIED")
        self.message = message
        self.task_id = task_id
        self.dag_id = dag_id
        self.run_id = run_id
        self.capability_id = capability_id
        self.tool_server = tool_server
        self.guard = guard
        self.reason = reason
        self.receipt_id = receipt_id
        self.decision = decision or {}

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict of the populated fields."""
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        for key, value in (
            ("task_id", self.task_id),
            ("dag_id", self.dag_id),
            ("run_id", self.run_id),
            ("capability_id", self.capability_id),
            ("tool_server", self.tool_server),
            ("guard", self.guard),
            ("reason", self.reason),
            ("receipt_id", self.receipt_id),
        ):
            if value is not None:
                payload[key] = value
        if self.decision:
            payload["decision"] = dict(self.decision)
        return payload


class ArcAirflowConfigError(ArcError):
    """The ARC Airflow configuration is invalid.

    Raised when the operator / decorator wiring cannot be satisfied
    before any task is dispatched. Typical causes: empty
    ``capability_id`` on :class:`arc_airflow.ArcOperator`, missing
    ``inner_operator`` on the wrapper, or a missing ``scope`` on
    :func:`arc_airflow.arc_task`.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, code="AIRFLOW_CONFIG_ERROR")


__all__ = [
    "ArcAirflowConfigError",
    "ArcAirflowError",
]
