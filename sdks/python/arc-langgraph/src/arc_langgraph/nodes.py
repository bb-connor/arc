"""The :func:`arc_node` wrapper.

``arc_node`` takes a LangGraph node callable (sync or async) plus an
:class:`arc_sdk.ArcScope` and returns a node callable that -- before the
wrapped body runs -- evaluates the node dispatch through the ARC sidecar.
A deny verdict raises :class:`ArcLangGraphError`; an allow verdict lets
the wrapped body run exactly as it would have otherwise.

Design notes
------------

* LangGraph nodes may be either plain functions returning a state
  update dict, or async coroutines. The wrapper preserves both shapes:
  it inspects the wrapped callable with :func:`asyncio.iscoroutinefunction`
  and returns the matching shape so LangGraph's state machine keeps
  working.
* The wrapper calls ``evaluate_tool_call`` on the :class:`arc_sdk.ArcClient`
  using ``tool_server=<server_id>`` and ``tool_name=<node_name>``. From
  the sidecar's perspective, a node dispatch is a tool call against a
  virtual tool; scope enforcement, receipt signing, and delegation all
  work the same way.
* When the config carries a ``configurable["arc_capability_id"]``, that
  id overrides the token resolved from the :class:`ArcGraphConfig`.
  This lets supervisor nodes hand a narrower capability to a child
  subgraph via LangGraph's standard config propagation.
* The wrapper refuses to invoke a node whose scope is broader than the
  parent graph's ceiling -- :func:`enforce_subgraph_ceiling` is called
  at wrap time so configuration errors surface *before* any state moves.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from arc_sdk.errors import ArcDeniedError, ArcError
from arc_sdk.models import ArcReceipt, ArcScope

from arc_langgraph.errors import ArcLangGraphError
from arc_langgraph.scoping import ArcGraphConfig, enforce_subgraph_ceiling

logger = logging.getLogger(__name__)


# LangGraph node shapes: either ``fn(state)`` or ``fn(state, config)``,
# sync or async. The wrapper auto-detects which by introspection.
NodeCallable = Callable[..., Any]
NodeResult = Any


def arc_node(
    fn: NodeCallable,
    *,
    scope: ArcScope,
    config: ArcGraphConfig,
    name: str | None = None,
    tool_server: str = "langgraph",
) -> NodeCallable:
    """Wrap a LangGraph node with ARC capability enforcement.

    Parameters
    ----------
    fn:
        The underlying node callable. May be sync or async, and may
        accept either ``(state)`` or ``(state, config)`` in the usual
        LangGraph style. The wrapper preserves the original arity and
        async contract.
    scope:
        The :class:`ArcScope` this node operates under. The scope must
        be a subset of the parent graph's effective ceiling
        (enforced at wrap time via
        :func:`arc_langgraph.scoping.enforce_subgraph_ceiling`).
    config:
        The enclosing :class:`ArcGraphConfig`. The wrapper looks up the
        capability token minted for ``name`` (falling back to the
        workflow-level token) and sends each node dispatch through
        ``config.arc_client``.
    name:
        Name under which to register the node. Defaults to
        ``fn.__name__``. Also used as the ``tool_name`` sent to the
        sidecar so receipts correlate with the graph topology.
    tool_server:
        Sidecar ``tool_server`` identifier. Defaults to
        ``"langgraph"``; override when a single kernel fronts several
        distinct graphs and needs per-graph receipt filtering.

    Returns
    -------
    A new node callable that evaluates the dispatch via the sidecar
    before invoking ``fn``.

    Raises
    ------
    ArcLangGraphConfigError
        If ``scope`` exceeds the graph ceiling.
    """
    node_name: str = name or str(getattr(fn, "__name__", "node"))

    # Enforce the ceiling at wrap time so the error surfaces during
    # graph construction, not at first invocation. Also register the
    # node scope on the config so provisioning picks it up.
    enforce_subgraph_ceiling(config, node_name, scope)
    config.node_scopes.setdefault(node_name, scope)

    is_async = asyncio.iscoroutinefunction(fn)
    sig = inspect.signature(fn) if callable(fn) else None
    takes_config = _node_accepts_config(sig)

    async def _dispatch(state: Any, runtime_config: Any) -> NodeResult:
        """Core ARC dispatch: evaluate, then call the wrapped node."""
        cap_id = _resolve_capability_id(
            config=config,
            node_name=node_name,
            runtime_config=runtime_config,
        )
        if not cap_id:
            raise ArcLangGraphError(
                "no capability bound to node; call ArcGraphConfig.provision() "
                "before running the graph",
                node_name=node_name,
                tool_server=tool_server,
                tool_name=node_name,
                reason="missing_capability",
            )
        parameters = _state_to_parameters(state)
        receipt = await _evaluate(
            arc_client=config.arc_client,
            capability_id=cap_id,
            tool_server=tool_server,
            tool_name=node_name,
            parameters=parameters,
        )
        if receipt.decision.is_denied:
            raise ArcLangGraphError(
                receipt.decision.reason or "denied by ARC kernel",
                node_name=node_name,
                tool_server=tool_server,
                tool_name=node_name,
                guard=receipt.decision.guard,
                reason=receipt.decision.reason,
                receipt_id=receipt.id,
                decision=receipt.decision.model_dump(exclude_none=True),
            )

        # Allow verdict: invoke the wrapped body preserving sync/async
        # and arity. LangGraph inspects the returned value and treats
        # it as the state update.
        if takes_config:
            result = fn(state, runtime_config)
        else:
            result = fn(state)
        if isinstance(result, Awaitable):
            return await result
        return result

    if is_async:

        async def async_wrapper(
            state: Any, runtime_config: Any = None
        ) -> NodeResult:
            return await _dispatch(state, runtime_config)

        _copy_metadata(fn, async_wrapper, node_name)
        async_wrapper.__arc_scope__ = scope  # type: ignore[attr-defined]
        async_wrapper.__arc_node_name__ = node_name  # type: ignore[attr-defined]
        return async_wrapper

    def sync_wrapper(state: Any, runtime_config: Any = None) -> NodeResult:
        coro = _dispatch(state, runtime_config)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        # Inside a running loop we *must* return the coroutine; LangGraph's
        # async pipeline awaits it directly.
        return coro

    _copy_metadata(fn, sync_wrapper, node_name)
    sync_wrapper.__arc_scope__ = scope  # type: ignore[attr-defined]
    sync_wrapper.__arc_node_name__ = node_name  # type: ignore[attr-defined]
    return sync_wrapper


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _evaluate(
    *,
    arc_client: Any,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
) -> ArcReceipt:
    """Send a sidecar evaluation and translate deny-on-wire errors."""
    try:
        return await arc_client.evaluate_tool_call(
            capability_id=capability_id,
            tool_server=tool_server,
            tool_name=tool_name,
            parameters=parameters,
        )
    except ArcDeniedError as exc:
        raise ArcLangGraphError(
            exc.message,
            tool_server=tool_server,
            tool_name=tool_name,
            guard=exc.guard,
            reason=exc.reason,
            receipt_id=exc.receipt_id,
        ) from exc
    except ArcError:
        raise


def _resolve_capability_id(
    *,
    config: ArcGraphConfig,
    node_name: str,
    runtime_config: Any,
) -> str | None:
    """Pick the capability id for this dispatch.

    Priority order:

    1. ``runtime_config["configurable"]["arc_capability_id"]`` -- lets a
       supervisor node hand a narrower token to a child node via
       standard LangGraph config propagation.
    2. The token minted for ``node_name`` on the :class:`ArcGraphConfig`.
    3. The workflow-level token, if one was minted.
    """
    if isinstance(runtime_config, dict):
        configurable = runtime_config.get("configurable")
        if isinstance(configurable, dict):
            override = configurable.get("arc_capability_id")
            if isinstance(override, str) and override:
                return override
    token = config.token_for(node_name)
    if token is not None:
        return token.id
    workflow = config.workflow_token()
    if workflow is not None:
        return workflow.id
    return None


def _state_to_parameters(state: Any) -> dict[str, Any]:
    """Render a LangGraph state into a params dict for the sidecar.

    LangGraph states are typically ``TypedDict`` instances which are
    regular dicts at runtime. Pydantic models also show up; for those
    we emit the model dump. Anything else falls back to ``str(state)``
    under a single ``state`` key so the sidecar always receives a
    hashable payload.
    """
    if state is None:
        return {}
    if isinstance(state, dict):
        return dict(state)
    model_dump = getattr(state, "model_dump", None)
    if callable(model_dump):
        dumped = model_dump(exclude_none=True)
        if isinstance(dumped, dict):
            return dumped
    return {"state": repr(state)}


def _node_accepts_config(sig: inspect.Signature | None) -> bool:
    """Return True when the node callable wants a ``config`` argument."""
    if sig is None:
        return False
    params = [
        p
        for p in sig.parameters.values()
        if p.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    return len(params) >= 2


def _copy_metadata(src: Any, dest: Any, node_name: str) -> None:
    """Copy ``__name__``/``__doc__`` so LangGraph introspection works."""
    try:
        dest.__name__ = node_name
    except (AttributeError, TypeError):
        pass
    if getattr(src, "__doc__", None):
        try:
            dest.__doc__ = src.__doc__
        except (AttributeError, TypeError):
            pass


__all__ = [
    "NodeCallable",
    "arc_node",
]
