"""ARC-governed AutoGen function registration.

AutoGen's :class:`autogen.ConversableAgent` executes tool calls through
its ``function_map``. This module wraps function registration so every
invocation flows through the ARC sidecar for capability-scoped
authorization and signed receipts. Only after an allow verdict does the
underlying callable execute.

Two entry points are supported:

1. :class:`ArcFunctionRegistry` -- a per-agent registry whose
   :meth:`register` method wraps a callable and installs it into the
   target agent's ``function_map`` (and, when an LLM config is
   available, registers it for LLM tool use).
2. :class:`ArcFunctionRegistry.as_decorator` -- returns a decorator
   suitable for use as ``@registry.as_decorator(scope=...)`` on the raw
   function.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from typing import Any

from arc_sdk.errors import ArcDeniedError, ArcError
from arc_sdk.models import ArcReceipt, ArcScope, CapabilityToken

from arc_autogen.errors import ArcAutogenConfigError, ArcToolError

logger = logging.getLogger(__name__)


# Structural alias -- the registry accepts the real ArcClient and the
# MockArcClient from arc_sdk.testing interchangeably. Importing the
# testing helper here would be wrong, so keep this opaque.
ArcClientLike = Any

# Tool executor: may be sync or async.
ToolExecutor = Callable[..., Any]

# Shape accepted for an agent. We don't import ConversableAgent at
# module scope to keep ``import arc_autogen`` cheap.
AgentLike = Any


class ArcFunctionRegistry:
    """Per-agent registry of ARC-governed AutoGen functions.

    Parameters
    ----------
    agent:
        The :class:`autogen.ConversableAgent` (or compatible) whose
        ``function_map`` will receive the wrapped callables.
    arc_client:
        :class:`arc_sdk.ArcClient` (or test double) used to evaluate
        each call. Reused across every registered function.
    server_id:
        Tool server identifier reported to the ARC sidecar. Per-function
        overrides are supported at registration time.
    capability_id:
        Default capability token id bound to every function. Per-role
        scoping via :class:`arc_autogen.ArcGroupChatManager` rewrites
        this on dispatch.
    role:
        Optional logical role label for this agent. Consulted by
        :class:`arc_autogen.ArcGroupChatManager` when enforcing
        per-role scopes.

    Example
    -------

    .. code-block:: python

        agent = ConversableAgent(name="researcher", ...)
        registry = ArcFunctionRegistry(
            agent=agent,
            arc_client=arc_client,
            server_id="research-tools",
            capability_id=token.id,
        )

        @registry.as_decorator(scope=ArcScope(grants=[search_grant]))
        def search(query: str, max_results: int = 10) -> str:
            '''Search the web.'''
            return do_search(query, max_results)
    """

    def __init__(
        self,
        *,
        agent: AgentLike,
        arc_client: ArcClientLike,
        server_id: str,
        capability_id: str = "",
        role: str | None = None,
        sidecar_url: str = "http://127.0.0.1:9090",
    ) -> None:
        if agent is None:
            raise ArcAutogenConfigError("agent must not be None")
        if not server_id:
            raise ArcAutogenConfigError("server_id must not be empty")
        self._agent = agent
        self._arc_client = arc_client
        self._server_id = server_id
        self._capability_id = capability_id
        self._role = role or getattr(agent, "name", None)
        self._sidecar_url = sidecar_url
        self._scopes: dict[str, ArcScope] = {}
        self._receipts: dict[str, ArcReceipt] = {}

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def agent(self) -> AgentLike:
        """The AutoGen agent bound to this registry."""
        return self._agent

    @property
    def role(self) -> str | None:
        """Logical role label used for GroupChat scope checks."""
        return self._role

    @property
    def server_id(self) -> str:
        """Default ARC tool server id for every registered function."""
        return self._server_id

    @property
    def capability_id(self) -> str:
        """Current capability token id used on every dispatch."""
        return self._capability_id

    def scope_for(self, name: str) -> ArcScope | None:
        """Return the :class:`ArcScope` recorded at registration, if any."""
        return self._scopes.get(name)

    def last_receipt(self, name: str) -> ArcReceipt | None:
        """Return the most recent receipt returned for ``name``."""
        return self._receipts.get(name)

    # ------------------------------------------------------------------
    # Binding helpers (used by GroupChat scoping)
    # ------------------------------------------------------------------

    def bind_capability(self, capability: CapabilityToken | str) -> None:
        """Swap the capability token id used on subsequent invocations.

        Accepts either a :class:`CapabilityToken` or a raw id string.
        :class:`arc_autogen.ArcGroupChatManager` calls this when it
        assigns per-role capabilities to agent-owned registries.
        """
        if isinstance(capability, str):
            self._capability_id = capability
        else:
            self._capability_id = capability.id

    def bind_arc_client(self, client: ArcClientLike) -> None:
        """Attach an :class:`ArcClient` (or mock) to reuse across calls."""
        self._arc_client = client

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        name: str,
        func: ToolExecutor,
        *,
        scope: ArcScope | None = None,
        description: str | None = None,
        server_id: str | None = None,
    ) -> ToolExecutor:
        """Wrap ``func`` with ARC enforcement and install it on the agent.

        The returned callable preserves ``func``'s sync/async contract:
        calls to a sync ``func`` yield a sync wrapper; calls to an
        ``async def`` yield an async wrapper. This matters because
        AutoGen dispatches sync and async functions down different
        code paths (``execute_function`` vs ``a_execute_function``).

        Parameters
        ----------
        name:
            Tool name under which the function is registered in the
            agent's ``function_map`` and reported to ARC.
        func:
            The callable to wrap. Must accept keyword arguments; AutoGen
            always dispatches registered functions with ``**kwargs``.
        scope:
            Optional :class:`ArcScope` describing what the function
            requires. Recorded for offline checks; not sent to the
            sidecar directly.
        description:
            Optional LLM-facing description. When supplied and the
            agent has an ``llm_config`` set, the function is also
            registered via ``register_for_llm``.
        server_id:
            Per-function override of the registry-level server id.
        """
        if not name:
            raise ArcAutogenConfigError("function name must not be empty")
        effective_server = server_id or self._server_id
        if scope is not None:
            self._scopes[name] = scope

        wrapped = self._wrap(
            name=name,
            func=func,
            server_id=effective_server,
        )

        # Install into the agent's function_map -- this is how AutoGen
        # actually dispatches tool calls. register_function is the
        # documented entry point on ConversableAgent.
        register_function = getattr(self._agent, "register_function", None)
        if callable(register_function):
            register_function(function_map={name: wrapped})
        else:
            # Fall back to setting function_map directly for a duck-typed
            # test agent.
            fmap = getattr(self._agent, "function_map", None)
            if isinstance(fmap, dict):
                fmap[name] = wrapped
            else:
                raise ArcAutogenConfigError(
                    "agent does not expose register_function or function_map"
                )

        # Best-effort LLM registration so the model can see the tool.
        if description is not None:
            reg_llm = getattr(self._agent, "register_for_llm", None)
            if callable(reg_llm) and getattr(self._agent, "llm_config", None):
                try:
                    reg_llm(name=name, description=description)(func)
                except Exception as exc:  # pragma: no cover - autogen quirks
                    logger.debug(
                        "register_for_llm failed for %r: %s", name, exc
                    )

        return wrapped

    def as_decorator(
        self,
        *,
        scope: ArcScope | None = None,
        description: str | None = None,
        server_id: str | None = None,
        name: str | None = None,
    ) -> Callable[[ToolExecutor], ToolExecutor]:
        """Return a decorator that registers the wrapped function.

        The resulting decorator uses the function's ``__name__`` as the
        tool name unless ``name`` is supplied. The function's docstring
        is used as the LLM-facing description unless ``description`` is
        supplied.
        """

        def decorator(func: ToolExecutor) -> ToolExecutor:
            tool_name = name or func.__name__
            desc = description or (func.__doc__ or "").strip() or None
            return self.register(
                tool_name,
                func,
                scope=scope,
                description=desc,
                server_id=server_id,
            )

        return decorator

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _wrap(
        self,
        *,
        name: str,
        func: ToolExecutor,
        server_id: str,
    ) -> ToolExecutor:
        """Produce a sync or async wrapper preserving ``func``'s shape."""
        if inspect.iscoroutinefunction(func):

            async def async_wrapper(**kwargs: Any) -> Any:
                receipt = await self._evaluate(
                    name=name,
                    server_id=server_id,
                    parameters=kwargs,
                )
                self._receipts[name] = receipt
                self._raise_if_denied(
                    name=name, server_id=server_id, receipt=receipt
                )
                return await func(**kwargs)

            async_wrapper.__name__ = getattr(func, "__name__", name)
            async_wrapper.__doc__ = func.__doc__
            return async_wrapper

        def sync_wrapper(**kwargs: Any) -> Any:
            coro = self._evaluate(
                name=name,
                server_id=server_id,
                parameters=kwargs,
            )
            receipt = _run_sync(coro)
            self._receipts[name] = receipt
            self._raise_if_denied(
                name=name, server_id=server_id, receipt=receipt
            )
            result = func(**kwargs)
            if isinstance(result, Awaitable):
                # A sync declaration that returned a coroutine -- let
                # AutoGen await it.
                return result
            return result

        sync_wrapper.__name__ = getattr(func, "__name__", name)
        sync_wrapper.__doc__ = func.__doc__
        return sync_wrapper

    async def _evaluate(
        self,
        *,
        name: str,
        server_id: str,
        parameters: dict[str, Any],
    ) -> ArcReceipt:
        """Call the sidecar's ``evaluate_tool_call`` endpoint."""
        if not self._capability_id:
            raise ArcToolError(
                "no capability_id bound to registry",
                tool_name=name,
                server_id=server_id,
                reason="missing_capability",
            )
        client = self._arc_client
        if client is None:
            raise ArcToolError(
                "no ArcClient bound to registry",
                tool_name=name,
                server_id=server_id,
                reason="missing_arc_client",
            )

        try:
            return await client.evaluate_tool_call(
                capability_id=self._capability_id,
                tool_server=server_id,
                tool_name=name,
                parameters=parameters,
            )
        except ArcDeniedError as exc:
            raise ArcToolError(
                exc.message,
                tool_name=name,
                server_id=server_id,
                guard=exc.guard,
                reason=exc.reason,
                receipt_id=exc.receipt_id,
            ) from exc
        except ArcError:
            raise

    @staticmethod
    def _raise_if_denied(
        *,
        name: str,
        server_id: str,
        receipt: ArcReceipt,
    ) -> None:
        """Translate a deny receipt into :class:`ArcToolError`."""
        if not receipt.is_denied:
            return
        raise ArcToolError(
            receipt.decision.reason or "denied by ARC kernel",
            tool_name=name,
            server_id=server_id,
            guard=receipt.decision.guard,
            reason=receipt.decision.reason,
            receipt_id=receipt.id,
            decision=receipt.decision.model_dump(exclude_none=True),
        )


def _run_sync(coro: Coroutine[Any, Any, Any]) -> Any:
    """Execute ``coro`` synchronously, tolerating a running event loop.

    AutoGen dispatches sync functions through ``execute_function``,
    which typically runs outside of any event loop. To stay robust for
    callers who invoke our sync wrapper from within a running loop
    (e.g. pytest-asyncio), we run the coroutine on a fresh loop in a
    worker thread and block on its completion.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: dict[str, Any] = {}

    def _runner() -> None:
        loop = asyncio.new_event_loop()
        try:
            result["value"] = loop.run_until_complete(coro)
        except BaseException as exc:  # re-raise on caller thread
            result["error"] = exc
        finally:
            loop.close()

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join()
    if "error" in result:
        raise result["error"]
    return result.get("value")


def attach_registry(agent: AgentLike, registry: ArcFunctionRegistry) -> None:
    """Attach ``registry`` to ``agent`` for later lookup by GroupChat.

    Stored on a conventional ``_arc_registry`` attribute so the
    :class:`arc_autogen.ArcGroupChatManager` can locate the registry
    for a given speaker without relying on a global table.
    """
    try:
        agent._arc_registry = registry
    except Exception as exc:  # pragma: no cover - pydantic agents
        raise ArcAutogenConfigError(
            f"could not attach ARC registry to agent: {exc}"
        ) from exc


def registry_for(agent: AgentLike) -> ArcFunctionRegistry | None:
    """Return the :class:`ArcFunctionRegistry` attached to ``agent``."""
    reg = getattr(agent, "_arc_registry", None)
    if isinstance(reg, ArcFunctionRegistry):
        return reg
    return None


def iter_registries(
    agents: Mapping[str, AgentLike] | list[AgentLike] | None,
) -> list[ArcFunctionRegistry]:
    """Return every :class:`ArcFunctionRegistry` attached to ``agents``."""
    if agents is None:
        return []
    values = agents.values() if isinstance(agents, Mapping) else agents
    out: list[ArcFunctionRegistry] = []
    for a in values:
        reg = registry_for(a)
        if reg is not None:
            out.append(reg)
    return out


__all__ = [
    "ArcClientLike",
    "ArcFunctionRegistry",
    "ToolExecutor",
    "attach_registry",
    "iter_registries",
    "registry_for",
]
