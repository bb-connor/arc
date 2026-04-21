"""Emit Chio receipts as Prefect Events.

The Chio Prefect integration surfaces every capability evaluation as a
:class:`prefect.events.Event` so the Prefect UI renders allow / deny
verdicts directly on the flow-run timeline, and so Prefect Automations
can trigger on repeated denials (circuit breakers, paging, etc.).

Two event names are used:

* ``chio.receipt.allow`` -- emitted after an allow verdict. Payload
  carries the receipt id, capability, tool server / name, and any
  timing metadata captured from the sidecar call.
* ``chio.receipt.deny`` -- emitted after a deny verdict (including the
  ``raise_on_deny`` HTTP 403 path). Payload carries the same shape plus
  the guard that denied and the reason string.

When the Prefect events backend is unavailable (for example in unit
tests without a running server or in a process that cannot reach the
API), emission falls back to :mod:`logging` at ``INFO`` level so the
receipt trail is never silently dropped.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from chio_sdk.models import ChioReceipt

logger = logging.getLogger(__name__)

#: Prefect event name for an allow verdict.
EVENT_ALLOW = "chio.receipt.allow"
#: Prefect event name for a deny verdict.
EVENT_DENY = "chio.receipt.deny"


def _prefect_emit_event(
    *,
    event: str,
    resource: dict[str, str],
    payload: dict[str, Any],
    related: list[dict[str, str]] | None = None,
) -> Any | None:
    """Call :func:`prefect.events.emit_event`, swallowing import / runtime errors.

    Returns the emitted :class:`prefect.events.Event` on success, or
    ``None`` when emission failed (Prefect missing, client misconfigured,
    etc.). Failures are logged at ``DEBUG`` so they do not pollute task
    logs during normal offline test runs.
    """
    try:
        from prefect.events import emit_event as _emit
    except Exception:  # pragma: no cover -- import guard
        logger.debug("chio-prefect: prefect.events unavailable; falling back to logging")
        return None

    try:
        return _emit(
            event=event,
            resource=resource,
            payload=payload,
            related=list(related or []),
        )
    except Exception:  # noqa: BLE001 -- event emission must not fail tasks
        logger.debug(
            "chio-prefect: prefect.events.emit_event failed; falling back to logging",
            exc_info=True,
        )
        return None


def _logging_fallback(event: str, payload: Mapping[str, Any]) -> None:
    """Structured ``INFO`` log entry when the events backend is unavailable."""
    logger.info(
        "chio-prefect event: %s receipt_id=%s tool=%s verdict=%s",
        event,
        payload.get("receipt_id"),
        payload.get("tool_name"),
        payload.get("verdict"),
    )


def _receipt_resource(receipt: ChioReceipt) -> dict[str, str]:
    """Build the :class:`prefect.events.Resource` dict for a receipt."""
    return {
        "prefect.resource.id": f"chio.receipt.{receipt.id}",
        "prefect.resource.role": "chio-receipt",
        "chio.capability_id": receipt.capability_id or "",
        "chio.tool_server": receipt.tool_server or "",
        "chio.tool_name": receipt.tool_name or "",
    }


def _task_related(
    *,
    task_name: str,
    flow_run_id: str | None,
    task_run_id: str | None,
) -> list[dict[str, str]]:
    """Build the related-resource list tying the event to the Prefect task run.

    The ids are used by Prefect's UI to draw the event on the correct
    flow-run / task-run timeline. Empty strings are omitted so we do not
    emit malformed related-resource entries.
    """
    related: list[dict[str, str]] = []
    if flow_run_id:
        related.append(
            {
                "prefect.resource.id": f"prefect.flow-run.{flow_run_id}",
                "prefect.resource.role": "flow-run",
            }
        )
    if task_run_id:
        related.append(
            {
                "prefect.resource.id": f"prefect.task-run.{task_run_id}",
                "prefect.resource.role": "task-run",
                "prefect.resource.name": task_name,
            }
        )
    return related


def emit_allow_event(
    *,
    receipt: ChioReceipt,
    task_name: str,
    flow_run_id: str | None = None,
    task_run_id: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> Any | None:
    """Emit an ``chio.receipt.allow`` Prefect event.

    Returns the emitted :class:`prefect.events.Event` (or ``None`` when
    the events backend was unavailable and we fell back to logging).
    Never raises; event emission must not fail the task.
    """
    payload: dict[str, Any] = {
        "receipt_id": receipt.id,
        "verdict": "allow",
        "capability_id": receipt.capability_id,
        "tool_server": receipt.tool_server,
        "tool_name": receipt.tool_name,
        "task_name": task_name,
        "timestamp": receipt.timestamp,
    }
    if extra:
        payload.update(dict(extra))

    related = _task_related(
        task_name=task_name,
        flow_run_id=flow_run_id,
        task_run_id=task_run_id,
    )
    emitted = _prefect_emit_event(
        event=EVENT_ALLOW,
        resource=_receipt_resource(receipt),
        payload=payload,
        related=related,
    )
    if emitted is None:
        _logging_fallback(EVENT_ALLOW, payload)
    return emitted


def emit_deny_event(
    *,
    receipt: ChioReceipt | None,
    task_name: str,
    reason: str,
    guard: str | None = None,
    receipt_id: str | None = None,
    capability_id: str | None = None,
    tool_server: str | None = None,
    flow_run_id: str | None = None,
    task_run_id: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> Any | None:
    """Emit an ``chio.receipt.deny`` Prefect event.

    Accepts either a deny :class:`ChioReceipt` (receipt-path deny) or a
    bare ``receipt_id`` string (HTTP-403 deny path, where no full receipt
    body was returned). The payload shape is identical in both cases so
    Prefect Automations can trigger on ``chio.receipt.deny`` uniformly.
    """
    resolved_receipt_id: str | None
    resolved_capability_id: str | None
    resolved_tool_server: str | None
    if receipt is not None:
        resource = _receipt_resource(receipt)
        resolved_receipt_id = receipt.id
        resolved_capability_id = receipt.capability_id
        resolved_tool_server = receipt.tool_server
    else:
        resolved_receipt_id = receipt_id
        resolved_capability_id = capability_id
        resolved_tool_server = tool_server
        resource = {
            "prefect.resource.id": (
                f"chio.receipt.{resolved_receipt_id}"
                if resolved_receipt_id
                else f"chio.receipt.denied.{task_name}"
            ),
            "prefect.resource.role": "chio-receipt",
            "chio.capability_id": resolved_capability_id or "",
            "chio.tool_server": resolved_tool_server or "",
            "chio.tool_name": task_name,
        }

    payload: dict[str, Any] = {
        "receipt_id": resolved_receipt_id,
        "verdict": "deny",
        "capability_id": resolved_capability_id,
        "tool_server": resolved_tool_server,
        "tool_name": task_name,
        "task_name": task_name,
        "reason": reason,
        "guard": guard,
    }
    if receipt is not None:
        payload["timestamp"] = receipt.timestamp
    if extra:
        payload.update(dict(extra))

    related = _task_related(
        task_name=task_name,
        flow_run_id=flow_run_id,
        task_run_id=task_run_id,
    )
    emitted = _prefect_emit_event(
        event=EVENT_DENY,
        resource=resource,
        payload=payload,
        related=related,
    )
    if emitted is None:
        _logging_fallback(EVENT_DENY, payload)
    return emitted


__all__ = [
    "EVENT_ALLOW",
    "EVENT_DENY",
    "emit_allow_event",
    "emit_deny_event",
]
