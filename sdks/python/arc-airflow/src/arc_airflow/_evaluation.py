"""Shared ARC evaluation plumbing for the Airflow integration.

Both :class:`arc_airflow.ArcOperator` and :func:`arc_airflow.arc_task`
take the same pre-dispatch path: resolve a :class:`ArcClient`, call
``evaluate_tool_call``, translate denies into an
:class:`airflow.exceptions.AirflowException` whose ``__cause__`` is a
:class:`PermissionError` (roadmap 17.3 acceptance), and return the
allow-path receipt so the caller can push its id into XCom.

The kernel / transport error path deliberately does *not* translate to
``PermissionError``. A sidecar that is down is not a denial; Airflow's
retry policy should apply.
"""

from __future__ import annotations

import asyncio
from typing import Any

from arc_sdk.client import ArcClient
from arc_sdk.errors import ArcDeniedError, ArcError
from arc_sdk.models import ArcReceipt

from arc_airflow.errors import ArcAirflowError

# Anything that quacks like an :class:`arc_sdk.ArcClient` -- the real
# async client plus :class:`arc_sdk.testing.MockArcClient` are both
# accepted.
ArcClientLike = Any


class _ArcClientOwner:
    """Owns a lazily-constructed :class:`ArcClient` for one dispatch.

    If the caller supplied their own client (operator kwarg, test
    fixture), we do not close it. If we had to mint one pointing at
    ``sidecar_url``, we close it after the evaluation to avoid leaking
    httpx connections between task invocations.
    """

    __slots__ = ("_client", "_owns", "_sidecar_url")

    def __init__(self, *, client: ArcClientLike | None, sidecar_url: str) -> None:
        self._client = client
        self._owns = client is None
        self._sidecar_url = sidecar_url

    def get(self) -> ArcClientLike:
        if self._client is None:
            self._client = ArcClient(self._sidecar_url)
        return self._client

    async def close(self) -> None:
        if self._owns and self._client is not None:
            try:
                await self._client.close()
            finally:
                self._client = None


async def _evaluate(
    *,
    arc_client: ArcClientLike,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
    task_id: str,
    dag_id: str | None,
    run_id: str | None,
) -> ArcReceipt:
    """Call the sidecar, raising on deny.

    Returns the allow-path :class:`ArcReceipt` so the caller can push
    ``receipt.id`` into XCom. Raises :class:`PermissionError` on both
    the receipt-path deny (``receipt.is_denied``) and the HTTP-403
    ``ArcDeniedError`` path; the original :class:`ArcAirflowError`
    rides along on ``PermissionError.arc_error`` so structured-log
    consumers see the full context.

    Kernel / transport errors propagate as :class:`ArcError` so the
    Airflow retry policy can apply.
    """
    try:
        receipt = await arc_client.evaluate_tool_call(
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
        )
    except ArcDeniedError as exc:
        raise _denied_permission_error(
            task_id=task_id,
            dag_id=dag_id,
            run_id=run_id,
            capability_id=capability_id,
            tool_server=tool_server,
            reason=exc.reason or exc.message,
            guard=exc.guard,
            receipt_id=exc.receipt_id,
        ) from exc
    except ArcError:
        # Transport / sidecar outage -- let the Airflow retry policy
        # apply. Deliberately NOT translated to PermissionError.
        raise

    if receipt.is_denied:
        decision = receipt.decision
        raise _denied_permission_error(
            task_id=task_id,
            dag_id=dag_id,
            run_id=run_id,
            capability_id=capability_id,
            tool_server=tool_server,
            reason=decision.reason or "denied by ARC kernel",
            guard=decision.guard,
            receipt_id=receipt.id,
            decision=decision.model_dump(exclude_none=True),
        )

    return receipt


def _denied_permission_error(
    *,
    task_id: str,
    dag_id: str | None,
    run_id: str | None,
    capability_id: str | None,
    tool_server: str | None,
    reason: str,
    guard: str | None,
    receipt_id: str | None,
    decision: dict[str, Any] | None = None,
) -> PermissionError:
    """Build the :class:`PermissionError` that denies raise.

    The :class:`ArcAirflowError` rides along on
    :attr:`PermissionError.arc_error` so structured-log consumers can
    inspect the full deny context. The surface type is
    :class:`PermissionError` so callers can ``except PermissionError``
    naturally, per the roadmap acceptance criterion.
    """
    err = ArcAirflowError(
        reason,
        task_id=task_id,
        dag_id=dag_id,
        run_id=run_id,
        capability_id=capability_id,
        tool_server=tool_server,
        guard=guard,
        reason=reason,
        receipt_id=receipt_id,
        decision=decision,
    )
    permission_error = PermissionError(f"ARC capability denied: {reason}")
    permission_error.arc_error = err  # type: ignore[attr-defined]
    return permission_error


def evaluate_sync(
    *,
    arc_client: ArcClientLike | None,
    sidecar_url: str,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
    task_id: str,
    dag_id: str | None,
    run_id: str | None,
) -> ArcReceipt:
    """Synchronous wrapper around :func:`_evaluate`.

    Airflow's :meth:`BaseOperator.execute` signature is synchronous so
    this function hides the async evaluation plumbing behind a blocking
    call. A throwaway event loop is spun up per call because Airflow
    worker processes do not own a persistent loop we can schedule onto
    safely. The per-call cost is dominated by the sidecar round-trip,
    not loop creation.
    """
    owner = _ArcClientOwner(client=arc_client, sidecar_url=sidecar_url)

    async def _run() -> ArcReceipt:
        try:
            return await _evaluate(
                arc_client=owner.get(),
                capability_id=capability_id,
                tool_server=tool_server,
                tool_name=tool_name,
                parameters=parameters,
                task_id=task_id,
                dag_id=dag_id,
                run_id=run_id,
            )
        finally:
            await owner.close()

    return asyncio.run(_run())


__all__ = [
    "ArcClientLike",
    "evaluate_sync",
]
