"""ARC-governed ``ray.remote`` decorator.

:func:`arc_remote` wraps :func:`ray.remote` so every remote task
invocation flows through the ARC sidecar for capability-scoped
authorisation before the remote body executes. The decorator preserves
Ray's ``.remote(...)`` / ``ray.get(...)`` contract: callers use the
wrapped task exactly like a ``@ray.remote`` task.

The capability check runs inside the remote worker (not on the driver)
so the sidecar URL the worker resolves -- typically
``http://127.0.0.1:9090`` against the node-local sidecar -- is the one
that produces the receipt. Denied remote tasks raise
:class:`PermissionError` (with the originating :class:`ArcRayError` on
``__cause__``) inside the worker; Ray propagates the exception through
:func:`ray.get` as a ``RayTaskError`` whose underlying type is
:class:`PermissionError`, matching the roadmap acceptance shape.

Sync and async function bodies are both supported -- Ray's own
``remote`` handles the async case by returning a coroutine that its
scheduler awaits.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar, cast

from arc_sdk.client import ArcClient
from arc_sdk.errors import ArcDeniedError, ArcError
from arc_sdk.models import ArcReceipt, ArcScope

from arc_ray.errors import ArcRayConfigError, ArcRayError
from arc_ray.grants import scope_from_spec

# Anything that quacks like an :class:`arc_sdk.ArcClient` -- real client
# and mock are accepted interchangeably.
ArcClientLike = Any

F = TypeVar("F", bound=Callable[..., Any])


# ---------------------------------------------------------------------------
# Sidecar evaluation shared with the actor module.
# ---------------------------------------------------------------------------


async def _evaluate_with_sidecar(
    *,
    arc_client: ArcClientLike,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
) -> ArcReceipt:
    """Call the sidecar and return the :class:`ArcReceipt`.

    Translates :class:`ArcDeniedError` (HTTP 403 path) into an
    :class:`ArcRayError` wrapped in :class:`PermissionError`; allow
    receipts are returned unchanged. Receipt-path denies (``is_denied``)
    are translated in the caller so the caller can record metadata like
    the actor-class name in the error.
    """
    try:
        return await arc_client.evaluate_tool_call(
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
        )
    except ArcDeniedError as exc:
        err = ArcRayError(
            exc.message,
            task_name=tool_name,
            capability_id=capability_id,
            tool_server=tool_server,
            guard=exc.guard,
            reason=exc.reason or exc.message,
            receipt_id=exc.receipt_id,
        )
        raise _permission_error(err) from exc
    except ArcError:
        # Transport / sidecar failure -- propagate so Ray's retry logic
        # (or the caller's ``try/except``) can observe the underlying
        # error unchanged.
        raise


def _permission_error(err: ArcRayError) -> PermissionError:
    """Wrap an :class:`ArcRayError` in a :class:`PermissionError` for Ray.

    Ray's scheduler wraps task exceptions in ``RayTaskError`` whose
    ``cause`` is the original class, so callers can still do
    ``except PermissionError`` at the driver.
    """
    pe = PermissionError(f"ARC capability denied: {err.reason or err.message}")
    pe.arc_error = err  # type: ignore[attr-defined]
    return pe


async def _evaluate_allow_or_raise(
    *,
    arc_client: ArcClientLike | None,
    sidecar_url: str,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
    actor_class: str | None = None,
    method_name: str | None = None,
) -> ArcReceipt:
    """Run the shared allow/deny path used by :func:`arc_remote` and :class:`ArcActor`.

    When ``arc_client`` is ``None``, a fresh :class:`ArcClient` pointing
    at ``sidecar_url`` is minted and closed inside this call. Callers
    that want to keep a long-lived client (every :class:`ArcActor`
    instance does) must pass one in.
    """
    if not capability_id:
        raise _permission_error(
            ArcRayError(
                "missing capability_id",
                task_name=tool_name,
                actor_class=actor_class,
                method_name=method_name,
                reason="missing_capability",
            )
        )

    owned = False
    client = arc_client
    if client is None:
        client = ArcClient(sidecar_url)
        owned = True

    try:
        receipt = await _evaluate_with_sidecar(
            arc_client=client,
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
        )
    finally:
        if owned:
            await client.close()

    if receipt.is_denied:
        decision = receipt.decision
        err = ArcRayError(
            decision.reason or "denied by ARC kernel",
            task_name=tool_name,
            actor_class=actor_class,
            method_name=method_name,
            capability_id=capability_id,
            tool_server=tool_server,
            guard=decision.guard,
            reason=decision.reason or "denied by ARC kernel",
            receipt_id=receipt.id,
            decision=decision.model_dump(exclude_none=True),
        )
        raise _permission_error(err)

    return receipt


# ---------------------------------------------------------------------------
# @arc_remote
# ---------------------------------------------------------------------------


def arc_remote(
    __fn: F | None = None,
    *,
    scope: str | ArcScope,
    capability_id: str | None = None,
    tool_server: str = "",
    tool_name: str | None = None,
    arc_client: ArcClientLike | None = None,
    sidecar_url: str = "http://127.0.0.1:9090",
    **ray_options: Any,
) -> Any:
    """Decorator that wraps a function as an ARC-governed Ray remote task.

    Parameters
    ----------
    scope:
        Either a short-string scope spec (``"tools:search"``) or a
        fully-formed :class:`ArcScope`. Recorded on the task for
        downstream introspection; also used to construct the
        ``tool_name`` the sidecar evaluates on when no explicit
        ``tool_name`` is supplied.
    capability_id:
        Pre-minted capability token id the worker evaluates against.
        Required. Typically minted by the driver and injected into the
        wrapped function's closure via :func:`ray.put` or an env var in
        production; the SDK accepts the id directly for ergonomic tests.
    tool_server:
        ARC tool server id for this task's evaluation. Defaults to the
        scope's implied server (``"*"`` when the scope is a short
        string without a server prefix).
    tool_name:
        ARC tool name the sidecar evaluates. Defaults to the wrapped
        function's ``__name__``.
    arc_client:
        Optional pre-built :class:`ArcClient` or mock. When supplied,
        the wrapper uses it verbatim and does not close it. Useful for
        in-process tests; in a real Ray cluster the client cannot be
        serialised across the driver/worker boundary so production
        callers should leave this ``None`` and let the worker mint a
        client against ``sidecar_url``.
    sidecar_url:
        Base URL of the ARC sidecar running on the Ray worker node.
        Defaults to ``http://127.0.0.1:9090`` (the node-local sidecar).
    ray_options:
        Forwarded verbatim to :func:`ray.remote` (``num_cpus``,
        ``num_gpus``, ``resources``, ``runtime_env``, ``max_calls``,
        ``max_retries``, etc.). The wrapper preserves the
        ``.remote(...)`` invocation contract unchanged.

    Returns
    -------
    A Ray remote handle, identical in shape to the object
    :func:`ray.remote` returns. ``.remote(...)`` returns an
    ``ObjectRef`` that :func:`ray.get` resolves to the function's
    result (or raises on deny).
    """
    import ray  # lazy import -- ray is heavy and only needed at decoration

    resolved_scope: ArcScope = scope_from_spec(scope)
    # Record the original short-string spec (if any) on the wrapper so
    # callers can introspect what the task was declared with.
    scope_spec_for_intro: str | None = scope if isinstance(scope, str) else None

    def decorator(fn: F) -> Any:
        if not capability_id:
            raise ArcRayConfigError(
                f"arc_remote requires a non-empty 'capability_id' for task "
                f"{fn.__name__!r}; mint a token via arc_sdk.ArcClient.create_capability "
                "and pass its id on the decorator."
            )

        resolved_tool_name = tool_name or fn.__name__
        is_coro = inspect.iscoroutinefunction(fn)

        # Capture values in locals so the wrapper body does not close
        # over the outer decorator kwargs (which would make the function
        # non-serialisable in some Ray runtimes).
        bound_capability_id = capability_id
        bound_tool_server = tool_server
        bound_sidecar_url = sidecar_url
        bound_arc_client = arc_client

        if is_coro:

            @functools.wraps(fn)
            async def async_body(*args: Any, **kwargs: Any) -> Any:
                await _evaluate_allow_or_raise(
                    arc_client=bound_arc_client,
                    sidecar_url=bound_sidecar_url,
                    capability_id=bound_capability_id,
                    tool_server=bound_tool_server,
                    tool_name=resolved_tool_name,
                    parameters=_task_parameters(args, kwargs),
                )
                return await cast(Callable[..., Awaitable[Any]], fn)(
                    *args, **kwargs
                )

            wrapper = async_body
        else:

            @functools.wraps(fn)
            def sync_body(*args: Any, **kwargs: Any) -> Any:
                asyncio.run(
                    _evaluate_allow_or_raise(
                        arc_client=bound_arc_client,
                        sidecar_url=bound_sidecar_url,
                        capability_id=bound_capability_id,
                        tool_server=bound_tool_server,
                        tool_name=resolved_tool_name,
                        parameters=_task_parameters(args, kwargs),
                    )
                )
                return fn(*args, **kwargs)

            wrapper = sync_body

        # Introspection metadata -- mirrors the protocol doc's
        # ``wrapper._arc_scope`` convention so other tooling (e.g.
        # aggregators) can discover ARC-decorated tasks by attribute.
        wrapper._arc_scope = resolved_scope  # type: ignore[attr-defined]
        wrapper._arc_scope_spec = scope_spec_for_intro  # type: ignore[attr-defined]
        wrapper._arc_capability_id = bound_capability_id  # type: ignore[attr-defined]
        wrapper._arc_tool_server = bound_tool_server  # type: ignore[attr-defined]
        wrapper._arc_tool_name = resolved_tool_name  # type: ignore[attr-defined]

        if ray_options:
            remote_handle = ray.remote(**ray_options)(wrapper)
        else:
            remote_handle = ray.remote(wrapper)

        # Ray's remote handle forwards arbitrary attribute access to the
        # underlying function for static handles, but for safety we
        # store the ARC metadata on the returned handle too when
        # possible.
        for attr in (
            "_arc_scope",
            "_arc_scope_spec",
            "_arc_capability_id",
            "_arc_tool_server",
            "_arc_tool_name",
        ):
            try:
                setattr(remote_handle, attr, getattr(wrapper, attr))
            except (AttributeError, TypeError):
                # Some Ray remote handles are frozen; introspection
                # falls back to the wrapped function's attributes.
                pass
        return remote_handle

    if __fn is not None:
        return decorator(__fn)
    return decorator


def _task_parameters(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Canonicalise task call arguments for the sidecar payload.

    The sidecar evaluates on a dict; we wrap positional args under a
    stable ``args`` key so the parameter hash remains deterministic
    across runs with identical inputs.
    """
    return {"args": list(args), "kwargs": dict(kwargs)}


__all__ = [
    "ArcClientLike",
    "arc_remote",
]
