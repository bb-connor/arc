"""Convenience builder for a Chio-governed Temporal worker.

:func:`build_chio_worker` wires the standard pieces together:

* An :class:`chio_temporal.ChioActivityInterceptor` mounted on the
  Temporal :class:`temporalio.worker.Worker`'s ``interceptors`` list.
* A :class:`chio_temporal.WorkflowGrant` holding the signed capability
  token (supplied, or minted from ``scope``) for ``workflow_id`` and
  pre-registered on the interceptor.

The function returns ``(worker, interceptor, grant)`` so callers retain
handles to the interceptor (for per-run :class:`WorkflowReceipt`
inspection) and the grant (for attenuation).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import Any

from chio_sdk.models import CapabilityToken, ChioScope
from temporalio.client import Client
from temporalio.worker import Worker

from chio_temporal.errors import ChioTemporalConfigError
from chio_temporal.executor import CallerExecutor
from chio_temporal.grants import ChioClientLike, WorkflowGrant
from chio_temporal.interceptor import ChioActivityInterceptor


async def build_chio_worker(
    client: Client,
    *,
    task_queue: str,
    activities: Sequence[Callable[..., Any]],
    workflows: Sequence[type] | None = None,
    workflow_id: str,
    chio_client: ChioClientLike,
    executor: CallerExecutor,
    control_token: str,
    token: CapabilityToken | None = None,
    scope: ChioScope | None = None,
    subject: str | None = None,
    tool_server: str = "",
    default_tool_server: str = "",
    activity_tool_server_map: dict[str, str] | None = None,
    sidecar_url: str = "http://127.0.0.1:9090",
    ttl_seconds: int = 3600,
    interceptors: Iterable[Any] | None = None,
    receipt_sink: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None,
    **worker_kwargs: Any,
) -> tuple[Worker, ChioActivityInterceptor, WorkflowGrant]:
    """Build a Temporal worker with the Chio interceptor + grant wired in.

    Parameters
    ----------
    client:
        A connected :class:`temporalio.client.Client`.
    task_queue:
        Temporal task queue the worker polls.
    activities:
        Activity callables to register.
    workflows:
        Workflow classes to register. Optional; activity-only workers
        are valid.
    workflow_id:
        Temporal workflow identifier the grant is scoped to.
    chio_client:
        :class:`chio_sdk.ChioClient` used to mint the capability token
        and drive the mediated activity lifecycle. The interceptor reuses
        this client; callers own its lifecycle.
    executor:
        :class:`chio_temporal.CallerExecutor` key material matching the
        sidecar's configured caller executor.
    control_token:
        Sidecar-control bearer for ``/v1/caller/start`` and
        ``/v1/caller/report``.
    token:
        The complete signed :class:`CapabilityToken` the workflow runs
        under. Exactly one of ``token`` and ``scope`` must be supplied.
    scope:
        Optional :class:`ChioScope`. When provided, the builder mints a
        new capability token via ``chio_client.create_capability`` and
        uses that token.
    subject:
        Hex-encoded Ed25519 public key bound to the minted capability.
        Required when ``scope`` is provided; ignored otherwise.
    tool_server:
        Default Chio tool server id for activities that do not appear in
        ``activity_tool_server_map``. Can be overridden per-activity.
    default_tool_server:
        Fallback when neither the grant nor the map resolve a server.
        Takes effect only when ``tool_server`` is empty.
    activity_tool_server_map:
        Optional mapping from activity type to Chio tool server id. See
        :class:`ChioActivityInterceptor`.
    sidecar_url:
        Sidecar base URL. Only used when ``chio_client`` is ``None`` in
        the interceptor chain; the builder always passes ``chio_client``,
        so this argument is unused on that path.
    ttl_seconds:
        Lifetime of the minted capability token when ``scope`` is set.
    interceptors:
        Extra :class:`temporalio.worker.Interceptor` instances to chain
        after the Chio interceptor.
    receipt_sink:
        Optional callable invoked with each finalised workflow receipt
        envelope. See :class:`ChioActivityInterceptor.receipt_sink`.
    worker_kwargs:
        Forwarded to :class:`temporalio.worker.Worker`.

    Returns
    -------
    (worker, interceptor, grant):
        ``worker`` is the configured :class:`temporalio.worker.Worker`;
        ``interceptor`` is the :class:`ChioActivityInterceptor` mounted
        on it; ``grant`` is the :class:`WorkflowGrant` registered for
        ``workflow_id``.
    """
    if scope is not None and token is None:
        if not subject:
            raise ChioTemporalConfigError(
                "subject is required when scope is provided"
            )
        grant_token: CapabilityToken = await chio_client.create_capability(
            subject=subject, scope=scope, ttl_seconds=ttl_seconds
        )
    elif token is not None and scope is None:
        grant_token = token
    else:
        raise ChioTemporalConfigError(
            "build_chio_worker requires exactly one of token or scope"
        )

    grant = WorkflowGrant(
        workflow_id=workflow_id,
        token=grant_token,
        tool_server=tool_server,
    )

    interceptor = ChioActivityInterceptor(
        executor=executor,
        control_token=control_token,
        chio_client=chio_client,
        sidecar_url=sidecar_url,
        default_tool_server=default_tool_server,
        activity_tool_server_map=activity_tool_server_map,
        receipt_sink=receipt_sink,
    )
    interceptor.register_workflow_grant(grant)

    all_interceptors: list[Any] = [interceptor]
    if interceptors:
        all_interceptors.extend(interceptors)

    worker = Worker(
        client,
        task_queue=task_queue,
        activities=list(activities),
        workflows=list(workflows or []),
        interceptors=all_interceptors,
        **worker_kwargs,
    )
    return worker, interceptor, grant


__all__ = [
    "build_chio_worker",
]
