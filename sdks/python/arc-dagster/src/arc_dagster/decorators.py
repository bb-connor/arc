"""ARC-governed Dagster decorators.

:func:`arc_asset` wraps Dagster's :func:`dagster.asset` so every asset
materialization flows through the ARC sidecar for capability-scoped
authorisation. :func:`arc_op` wraps :func:`dagster.op` with the same
pre-execute gate.

The decorators preserve Dagster's compute-function contract: the wrapped
function still receives its :class:`dagster.AssetExecutionContext` (or
:class:`dagster.OpExecutionContext`) plus any upstream inputs, and may
return the same values it always would (plain objects,
:class:`dagster.MaterializeResult`, etc.). The wrapper inserts exactly
one sidecar round-trip before the body runs.

Denied materializations raise :class:`PermissionError` so Dagster marks
the run as failed, and the wrapper attaches the deny receipt id and
reason to the :class:`dagster.OpExecutionContext` via
``add_output_metadata`` so the failure surfaces on the Dagster UI.

Allow verdicts attach the receipt id, capability id, tool server, and
partition key (when present) as :class:`dagster.MetadataValue` entries
so the Dagster UI renders the receipt on every successful asset
materialization row.

Partition scoping
-----------------

If the materialization targets a partitioned asset, the wrapper reads
the partition key from the execution context and includes it in the
capability evaluation payload under ``parameters["partition"]`` and in a
mirrored top-level ``parameters["partition_key"]`` key. Guards can then
enforce per-partition access (the canonical ``region=eu-west`` data
residency pattern).
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar, cast, overload

from arc_sdk.client import ArcClient
from arc_sdk.errors import ArcDeniedError, ArcError
from arc_sdk.models import ArcReceipt, ArcScope

from arc_dagster.errors import ArcDagsterConfigError, ArcDagsterError
from arc_dagster.partitions import extract_partition_info

# Anything that quacks like an :class:`arc_sdk.ArcClient` -- we accept the
# real client and :class:`arc_sdk.testing.MockArcClient` interchangeably.
ArcClientLike = Any

F = TypeVar("F", bound=Callable[..., Any])


# ---------------------------------------------------------------------------
# ArcClient ownership -- close clients we minted, leave caller clients alone.
# ---------------------------------------------------------------------------


class _ArcClientOwner:
    """Owns a lazily-constructed :class:`ArcClient` for a single call."""

    __slots__ = ("_client", "_owns", "_sidecar_url")

    def __init__(
        self, *, client: ArcClientLike | None, sidecar_url: str
    ) -> None:
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


# ---------------------------------------------------------------------------
# Context helpers
# ---------------------------------------------------------------------------


def _context_run_id(context: Any) -> str | None:
    """Best-effort extraction of the Dagster run id from a context.

    Dagster exposes the run id via ``context.run.run_id`` on newer
    versions (``context.run_id`` was deprecated in Dagster 1.8). We try
    the newer surface first and fall back to the legacy property so we
    work across the supported version range without emitting deprecation
    warnings on 1.8+.
    """
    try:
        run = getattr(context, "run", None)
        if run is not None:
            run_id = getattr(run, "run_id", None)
            if run_id:
                return str(run_id)
    except Exception:
        pass
    try:
        run_id = getattr(context, "run_id", None)
        if run_id:
            return str(run_id)
    except Exception:
        pass
    return None


def _context_asset_key(context: Any) -> str | None:
    """Best-effort ``asset_key.to_user_string()`` extraction."""
    try:
        asset_key = getattr(context, "asset_key", None)
        if asset_key is None:
            return None
        to_user = getattr(asset_key, "to_user_string", None)
        if callable(to_user):
            return str(to_user())
        return str(asset_key)
    except Exception:
        return None


def _context_log(context: Any, level: str, message: str) -> None:
    """Log via ``context.log`` when available, silently otherwise."""
    try:
        log = getattr(context, "log", None)
        if log is None:
            return
        fn = getattr(log, level, None)
        if callable(fn):
            fn(message)
    except Exception:
        pass


def _find_context_argument(
    args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any | None:
    """Pick the Dagster execution context out of a compute-fn call.

    Dagster passes the context either as the first positional argument
    or as a keyword argument named ``context``. We do not require the
    argument; ops / assets that opt out of the context object work
    without one, in which case the wrapper falls back to a
    partition-less evaluation.
    """
    if args:
        candidate = args[0]
        if _looks_like_dagster_context(candidate):
            return candidate
    return kwargs.get("context")


def _looks_like_dagster_context(value: Any) -> bool:
    """Heuristic: does ``value`` expose the Dagster context surface?"""
    return hasattr(value, "has_partition_key") or hasattr(value, "run_id")


# ---------------------------------------------------------------------------
# Parameter canonicalisation
# ---------------------------------------------------------------------------


def _compute_parameters(
    *,
    context: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool_name: str,
) -> dict[str, Any]:
    """Canonicalise the compute-fn arguments + partition into a sidecar payload.

    We deliberately do NOT forward raw upstream objects -- they may not
    be JSON-serialisable (DataFrames, numpy arrays, ...). Instead we
    record the asset / op name and the partition info the policy needs
    to make a routing decision. Callers that need to pass specific
    scalar arguments to guards can forward them via ``tool_name`` or via
    a custom ``parameters`` dict resolved outside this helper.
    """
    partition = extract_partition_info(context) if context is not None else {}
    payload: dict[str, Any] = {
        "asset": tool_name,
        "kwargs": _sanitise_kwargs(kwargs),
    }
    if partition:
        # ``partition`` is the structured dict (key + optional range).
        payload["partition"] = dict(partition)
        # Mirror the primary key at the top level so guards written for
        # the Dagster documentation's canonical shape keep working.
        if "partition_key" in partition:
            payload["partition_key"] = partition["partition_key"]
    _ = args  # Positional upstream inputs are not forwarded -- see docstring.
    return payload


def _sanitise_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Strip values that are not trivially JSON-able from ``kwargs``.

    The sidecar canonicalises whatever we send to JSON for the parameter
    hash, so we drop anything that would break the serialisation. A
    caller-supplied upstream asset (``pd.DataFrame``, ``np.ndarray``,
    ...) is represented by its type name so guards can still reason
    about "an input of type X was present".
    """
    result: dict[str, Any] = {}
    for key, value in kwargs.items():
        if key == "context":
            continue
        if _is_json_safe(value):
            result[key] = value
        else:
            result[key] = {"__arc_type__": type(value).__name__}
    return result


def _is_json_safe(value: Any) -> bool:
    """Return ``True`` for values safe to embed in the sidecar payload."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return True
    if isinstance(value, (list, tuple)):
        return all(_is_json_safe(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(k, str) and _is_json_safe(v) for k, v in value.items()
        )
    return False


# ---------------------------------------------------------------------------
# Core evaluation -- call the sidecar, raise on deny, return the receipt.
# ---------------------------------------------------------------------------


async def _evaluate(
    *,
    arc_client: ArcClientLike,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
) -> ArcReceipt:
    """Evaluate a materialization via the ARC sidecar.

    Returns the :class:`ArcReceipt`. Raises :class:`ArcDeniedError`
    through on deny-path-403 (caller converts to
    :class:`PermissionError`) and returns a deny receipt on the
    receipt-path deny.
    """
    return await arc_client.evaluate_tool_call(
        capability_id=capability_id,
        tool_server=tool_server,
        tool_name=tool_name,
        parameters=parameters,
    )


def _denied_permission_error(
    *,
    asset_or_op: str,
    kind: str,
    partition_key: str | None,
    run_id: str | None,
    capability_id: str | None,
    tool_server: str | None,
    reason: str,
    guard: str | None,
    receipt_id: str | None,
    decision: dict[str, Any] | None = None,
) -> PermissionError:
    """Build the :class:`PermissionError` the decorator raises on deny.

    The :class:`ArcDagsterError` rides along on ``arc_error`` (set as an
    attribute, not via ``__cause__``, so callers can recover the
    structured payload after ``except PermissionError``).
    """
    err = ArcDagsterError(
        reason,
        asset_key=asset_or_op if kind == "asset" else None,
        op_name=asset_or_op if kind == "op" else None,
        partition_key=partition_key,
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


# ---------------------------------------------------------------------------
# Receipt metadata helpers
# ---------------------------------------------------------------------------


def _attach_receipt_metadata(
    context: Any,
    *,
    receipt: ArcReceipt,
    partition_key: str | None,
) -> None:
    """Attach the allow-receipt fields to Dagster asset metadata.

    Dagster's :class:`AssetExecutionContext` and :class:`OpExecutionContext`
    expose :meth:`add_output_metadata` (the canonical surface for
    attaching :class:`MetadataValue` entries to the emitted
    :class:`AssetMaterialization`). We import :class:`MetadataValue`
    lazily so this module imports cleanly when Dagster is absent (for
    example, during type-only imports in tests).
    """
    try:
        from dagster import MetadataValue
    except Exception:  # pragma: no cover -- lazy import guard
        return

    add_metadata = getattr(context, "add_output_metadata", None)
    if not callable(add_metadata):
        return

    metadata: dict[str, Any] = {
        "arc_receipt_id": MetadataValue.text(str(receipt.id)),
        "arc_verdict": MetadataValue.text("allow"),
    }
    if receipt.capability_id:
        metadata["arc_capability_id"] = MetadataValue.text(
            str(receipt.capability_id)
        )
    if receipt.tool_server:
        metadata["arc_tool_server"] = MetadataValue.text(
            str(receipt.tool_server)
        )
    if receipt.tool_name:
        metadata["arc_tool_name"] = MetadataValue.text(str(receipt.tool_name))
    if partition_key is not None:
        metadata["arc_partition_key"] = MetadataValue.text(partition_key)

    try:
        add_metadata(metadata)
    except Exception:  # noqa: BLE001 -- metadata emission never fails runs
        pass


def _attach_deny_metadata(
    context: Any,
    *,
    receipt_id: str | None,
    reason: str,
    guard: str | None,
    partition_key: str | None,
) -> None:
    """Attach deny-context fields to Dagster output metadata on failure.

    Dagster still records ``add_output_metadata`` entries on a failed
    op, so this surfaces the deny reason on the Dagster UI even though
    the run transitions to a ``FAILURE`` state.
    """
    try:
        from dagster import MetadataValue
    except Exception:  # pragma: no cover -- lazy import guard
        return

    add_metadata = getattr(context, "add_output_metadata", None)
    if not callable(add_metadata):
        return

    metadata: dict[str, Any] = {
        "arc_verdict": MetadataValue.text("deny"),
        "arc_reason": MetadataValue.text(reason),
    }
    if receipt_id:
        metadata["arc_receipt_id"] = MetadataValue.text(str(receipt_id))
    if guard:
        metadata["arc_guard"] = MetadataValue.text(str(guard))
    if partition_key is not None:
        metadata["arc_partition_key"] = MetadataValue.text(partition_key)

    try:
        add_metadata(metadata)
    except Exception:  # noqa: BLE001 -- metadata emission never fails runs
        pass


# ---------------------------------------------------------------------------
# Shared pre-dispatch body for assets and ops
# ---------------------------------------------------------------------------


async def _run_with_guard(
    *,
    fn: Callable[..., Any],
    kind: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    tool_name: str,
    scope: ArcScope | None,
    capability_id: str | None,
    tool_server: str | None,
    arc_client: ArcClientLike | None,
    sidecar_url: str | None,
    is_async: bool,
) -> Any:
    """Shared evaluate-then-invoke path for :func:`arc_asset` / :func:`arc_op`.

    Runs the sidecar evaluation, attaches the receipt (or deny context)
    to the Dagster execution context, then invokes the original compute
    function. Sync bodies run inline; async bodies are awaited.
    """
    if not capability_id:
        raise ArcDagsterConfigError(
            f"arc_{kind} {tool_name!r} requires a capability_id"
        )
    resolved_tool_server = tool_server or ""
    context = _find_context_argument(args, kwargs)
    partition_info = extract_partition_info(context) if context is not None else {}
    partition_key: str | None = partition_info.get("partition_key")
    run_id = _context_run_id(context) if context is not None else None

    parameters = _compute_parameters(
        context=context, args=args, kwargs=kwargs, tool_name=tool_name
    )

    resolved_sidecar = sidecar_url or ArcClient.DEFAULT_BASE_URL
    owner = _ArcClientOwner(client=arc_client, sidecar_url=resolved_sidecar)
    try:
        try:
            receipt = await _evaluate(
                arc_client=owner.get(),
                capability_id=capability_id,
                tool_server=resolved_tool_server,
                tool_name=tool_name,
                parameters=parameters,
            )
        except ArcDeniedError as exc:
            # HTTP-403 path -- no full receipt body, translate directly.
            reason = exc.reason or exc.message
            _attach_deny_metadata(
                context,
                receipt_id=exc.receipt_id,
                reason=reason,
                guard=exc.guard,
                partition_key=partition_key,
            )
            _context_log(
                context,
                "error",
                f"ARC denied {kind} {tool_name!r}: {reason}",
            )
            raise _denied_permission_error(
                asset_or_op=tool_name,
                kind=kind,
                partition_key=partition_key,
                run_id=run_id,
                capability_id=capability_id,
                tool_server=resolved_tool_server,
                reason=reason,
                guard=exc.guard,
                receipt_id=exc.receipt_id,
            ) from exc
        except ArcError:
            # Transport / kernel outage -- let Dagster apply its retry
            # policy rather than translating to PermissionError.
            raise
    finally:
        await owner.close()

    if receipt.is_denied:
        decision = receipt.decision
        reason = decision.reason or "denied by ARC kernel"
        _attach_deny_metadata(
            context,
            receipt_id=receipt.id,
            reason=reason,
            guard=decision.guard,
            partition_key=partition_key,
        )
        _context_log(
            context,
            "error",
            f"ARC denied {kind} {tool_name!r}: {reason}",
        )
        raise _denied_permission_error(
            asset_or_op=tool_name,
            kind=kind,
            partition_key=partition_key,
            run_id=run_id,
            capability_id=capability_id,
            tool_server=resolved_tool_server,
            reason=reason,
            guard=decision.guard,
            receipt_id=receipt.id,
            decision=decision.model_dump(exclude_none=True),
        )

    # Allow path -- log, attach metadata, scope unused but retained for
    # future guard-composition integrations.
    _ = scope
    _attach_receipt_metadata(
        context,
        receipt=receipt,
        partition_key=partition_key,
    )
    _context_log(
        context,
        "info",
        f"ARC allow receipt {receipt.id} for {kind} {tool_name!r}",
    )

    if is_async:
        return await fn(*args, **kwargs)
    return fn(*args, **kwargs)


# ---------------------------------------------------------------------------
# @arc_asset
# ---------------------------------------------------------------------------


@overload
def arc_asset(
    __fn: F,
) -> F: ...


@overload
def arc_asset(
    *,
    scope: ArcScope | None = None,
    capability_id: str | None = None,
    tool_server: str | None = None,
    tool_name: str | None = None,
    arc_client: ArcClientLike | None = None,
    sidecar_url: str | None = None,
    **asset_options: Any,
) -> Callable[[F], F]: ...


def arc_asset(
    __fn: F | None = None,
    *,
    scope: ArcScope | None = None,
    capability_id: str | None = None,
    tool_server: str | None = None,
    tool_name: str | None = None,
    arc_client: ArcClientLike | None = None,
    sidecar_url: str | None = None,
    **asset_options: Any,
) -> Any:
    """Decorator that wraps a compute function as an ARC-governed Dagster asset.

    Parameters
    ----------
    scope:
        The asset's :class:`ArcScope`. Currently forwarded to the
        receipt metadata; reserved for future per-asset scope
        attenuation against a wrapping :func:`arc_job` context.
    capability_id:
        Pre-minted capability id to evaluate against. Required -- a
        missing capability id raises :class:`ArcDagsterConfigError` at
        materialization time.
    tool_server:
        ARC tool server id for this asset's evaluation. Defaults to an
        empty string; concrete deployments should set this to the
        server that implements the asset's backing tool.
    tool_name:
        ARC tool name to use for evaluation. Defaults to the compute
        function name (which matches Dagster's default asset key).
    arc_client:
        Optional :class:`arc_sdk.ArcClient` (or mock) to use instead of
        minting a default one. The decorator does not close
        caller-owned clients; it only closes clients it created.
    sidecar_url:
        Base URL of the ARC sidecar when the decorator has to mint its
        own client. Defaults to ``http://127.0.0.1:9090``.
    asset_options:
        Forwarded verbatim to :func:`dagster.asset` (e.g.
        ``partitions_def``, ``ins``, ``deps``, ``io_manager_key``,
        ``group_name``, ``metadata``, ``description``). The wrapper
        preserves Dagster's sync contract -- async compute functions
        are supported as well and the wrapper runs them on a fresh
        event loop when Dagster invokes them synchronously.
    """
    from dagster import asset as dagster_asset

    def decorator(fn: F) -> F:
        resolved_tool_name = tool_name or fn.__name__
        asset_kwargs = dict(asset_options)
        asset_kwargs.setdefault("name", resolved_tool_name)

        is_coro = inspect.iscoroutinefunction(fn)

        if is_coro:

            @functools.wraps(fn)
            def async_body(*args: Any, **kwargs: Any) -> Any:
                return asyncio.run(
                    _run_with_guard(
                        fn=fn,
                        kind="asset",
                        args=args,
                        kwargs=kwargs,
                        tool_name=resolved_tool_name,
                        scope=scope,
                        capability_id=capability_id,
                        tool_server=tool_server,
                        arc_client=arc_client,
                        sidecar_url=sidecar_url,
                        is_async=True,
                    )
                )

            return cast(F, dagster_asset(**asset_kwargs)(async_body))

        @functools.wraps(fn)
        def sync_body(*args: Any, **kwargs: Any) -> Any:
            return asyncio.run(
                _run_with_guard(
                    fn=fn,
                    kind="asset",
                    args=args,
                    kwargs=kwargs,
                    tool_name=resolved_tool_name,
                    scope=scope,
                    capability_id=capability_id,
                    tool_server=tool_server,
                    arc_client=arc_client,
                    sidecar_url=sidecar_url,
                    is_async=False,
                )
            )

        return cast(F, dagster_asset(**asset_kwargs)(sync_body))

    if __fn is not None:
        return decorator(__fn)
    return decorator


# ---------------------------------------------------------------------------
# @arc_op
# ---------------------------------------------------------------------------


@overload
def arc_op(
    __fn: F,
) -> F: ...


@overload
def arc_op(
    *,
    scope: ArcScope | None = None,
    capability_id: str | None = None,
    tool_server: str | None = None,
    tool_name: str | None = None,
    arc_client: ArcClientLike | None = None,
    sidecar_url: str | None = None,
    **op_options: Any,
) -> Callable[[F], F]: ...


def arc_op(
    __fn: F | None = None,
    *,
    scope: ArcScope | None = None,
    capability_id: str | None = None,
    tool_server: str | None = None,
    tool_name: str | None = None,
    arc_client: ArcClientLike | None = None,
    sidecar_url: str | None = None,
    **op_options: Any,
) -> Any:
    """Decorator that wraps a compute function as an ARC-governed Dagster op.

    Semantics mirror :func:`arc_asset` -- a pre-execute capability check
    gates the op body, allow verdicts run the body and attach the
    receipt to the op's output metadata, deny verdicts raise
    :class:`PermissionError` so Dagster records a ``FAILURE`` state.

    ``op_options`` forward to :func:`dagster.op` verbatim (e.g. ``ins``,
    ``out``, ``config_schema``, ``retry_policy``, ``tags``).
    """
    from dagster import op as dagster_op

    def decorator(fn: F) -> F:
        resolved_tool_name = tool_name or fn.__name__
        op_kwargs = dict(op_options)
        op_kwargs.setdefault("name", resolved_tool_name)

        is_coro = inspect.iscoroutinefunction(fn)

        if is_coro:

            @functools.wraps(fn)
            def async_body(*args: Any, **kwargs: Any) -> Any:
                return asyncio.run(
                    _run_with_guard(
                        fn=fn,
                        kind="op",
                        args=args,
                        kwargs=kwargs,
                        tool_name=resolved_tool_name,
                        scope=scope,
                        capability_id=capability_id,
                        tool_server=tool_server,
                        arc_client=arc_client,
                        sidecar_url=sidecar_url,
                        is_async=True,
                    )
                )

            return cast(F, dagster_op(**op_kwargs)(async_body))

        @functools.wraps(fn)
        def sync_body(*args: Any, **kwargs: Any) -> Any:
            return asyncio.run(
                _run_with_guard(
                    fn=fn,
                    kind="op",
                    args=args,
                    kwargs=kwargs,
                    tool_name=resolved_tool_name,
                    scope=scope,
                    capability_id=capability_id,
                    tool_server=tool_server,
                    arc_client=arc_client,
                    sidecar_url=sidecar_url,
                    is_async=False,
                )
            )

        return cast(F, dagster_op(**op_kwargs)(sync_body))

    if __fn is not None:
        return decorator(__fn)
    return decorator


__all__ = [
    "ArcClientLike",
    "arc_asset",
    "arc_op",
]
