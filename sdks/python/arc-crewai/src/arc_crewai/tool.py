"""ARC-governed CrewAI ``BaseTool`` wrapper.

This module wraps CrewAI's :class:`crewai.tools.BaseTool` so every
``_run`` invocation first flows through the ARC sidecar for capability
validation and guard evaluation. Only after an allow verdict does the
underlying tool implementation execute.

Two shapes are supported:

1. *Subclass* -- override :meth:`ArcBaseTool._execute` with the real
   tool body. ``_run`` is final in :class:`ArcBaseTool`.
2. *Delegate* -- pass ``executor=callable(**kwargs)`` to an
   :class:`ArcBaseTool` instance to wrap an existing callable.

The public ``name``, ``description``, ``args_schema``, ``result_as_answer``
and other CrewAI ``BaseTool`` fields are preserved unchanged.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from arc_sdk.client import ArcClient
from arc_sdk.errors import ArcDeniedError, ArcError
from arc_sdk.models import ArcReceipt, ArcScope
from crewai.tools import BaseTool
from pydantic import ConfigDict, Field, PrivateAttr

from arc_crewai.errors import ArcToolError

logger = logging.getLogger(__name__)


# Callable shape accepted as ``executor``: may be sync or async.
ToolExecutor = Callable[..., Any]

# Anything that looks like an ``ArcClient`` -- we accept the real client
# and the ``MockArcClient`` from ``arc_sdk.testing`` interchangeably. A
# structural type alias keeps the annotation readable without importing
# the testing helpers in production code.
ArcClientLike = Any


class ArcBaseTool(BaseTool):
    """CrewAI tool whose every invocation is gated by the ARC sidecar.

    Parameters
    ----------
    name, description:
        Standard CrewAI ``BaseTool`` fields.
    server_id:
        The ARC tool server identifier this tool belongs to.
    capability_id:
        Capability token id that authorizes this invocation. Per-role
        scoping is applied by :class:`arc_crewai.ArcCrew` which rewrites
        this field on assignment.
    sidecar_url:
        Base URL of the ARC sidecar.
    arc_client:
        Optional pre-built :class:`arc_sdk.ArcClient` (or
        ``MockArcClient``) to use instead of constructing one per call.
        When supplied, the tool does not close the client.
    executor:
        Optional callable that implements the real tool body. When
        ``None`` (the default) subclasses must override :meth:`_execute`.
    scope:
        Optional :class:`ArcScope` describing what the tool requires.
        Recorded on the tool for :class:`ArcCrew` scoping checks; not
        sent to the sidecar directly.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    server_id: str = ""
    capability_id: str = ""
    sidecar_url: str = "http://127.0.0.1:9090"
    scope: ArcScope | None = None

    # Implementation + runtime collaborators are kept in private attrs so
    # pydantic does not try to validate them and so the public
    # ``model_dump`` stays compact.
    _executor: ToolExecutor | None = PrivateAttr(default=None)
    _arc_client: ArcClientLike | None = PrivateAttr(default=None)
    _last_receipt: ArcReceipt | None = PrivateAttr(default=None)

    # Captured at construction so mypy/Pydantic do not shadow the base
    # class default when callers inspect the field.
    last_receipt: ArcReceipt | None = Field(default=None, exclude=True)

    def __init__(
        self,
        *,
        executor: ToolExecutor | None = None,
        arc_client: ArcClientLike | None = None,
        **data: Any,
    ) -> None:
        super().__init__(**data)
        self._executor = executor
        self._arc_client = arc_client

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def last_arc_receipt(self) -> ArcReceipt | None:
        """Most recent :class:`ArcReceipt` returned by the sidecar."""
        return self._last_receipt

    def bind_arc_client(self, client: ArcClientLike) -> None:
        """Attach an :class:`ArcClient` (or mock) to reuse across calls."""
        self._arc_client = client

    def bind_capability(self, capability_id: str) -> None:
        """Set the capability token id used on subsequent invocations.

        :class:`ArcCrew` calls this when it assigns per-role capabilities
        to agent-owned tools.
        """
        self.capability_id = capability_id

    # ------------------------------------------------------------------
    # CrewAI BaseTool contract
    # ------------------------------------------------------------------

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Synchronous entry point required by CrewAI.

        CrewAI's :meth:`BaseTool.run` auto-awaits coroutines returned
        from ``_run`` via ``asyncio.run``, so we delegate to the async
        core. When an event loop is already running (e.g. the caller is
        inside an async framework) we return the coroutine directly so
        the caller can ``await`` it.
        """
        if args:
            raise TypeError(
                "ArcBaseTool only supports keyword arguments on _run; "
                "CrewAI dispatches tools with **kwargs."
            )
        coro = self._arun(**kwargs)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No running loop -- block synchronously. CrewAI's own
            # BaseTool.run detects coroutines and does the same, but
            # doing it here keeps the sync contract explicit.
            return asyncio.run(coro)
        return coro

    async def _arun(self, **kwargs: Any) -> Any:
        """Evaluate the tool call with ARC and, on allow, run the body."""
        receipt = await self._evaluate(kwargs)
        self._last_receipt = receipt
        self.last_receipt = receipt

        if receipt.is_denied:
            raise ArcToolError(
                receipt.decision.reason or "denied by ARC kernel",
                tool_name=self.name,
                server_id=self.server_id,
                guard=receipt.decision.guard,
                reason=receipt.decision.reason,
                receipt_id=receipt.id,
                decision=receipt.decision.model_dump(exclude_none=True),
            )

        return await self._invoke_executor(kwargs)

    # ------------------------------------------------------------------
    # Extension point for subclasses
    # ------------------------------------------------------------------

    def _execute(self, **kwargs: Any) -> Any:
        """Override in a subclass to implement the real tool body.

        The default implementation raises ``NotImplementedError`` unless
        an ``executor`` callable was supplied at construction time.
        """
        if self._executor is None:
            raise NotImplementedError(
                "ArcBaseTool._execute must be overridden or an 'executor' "
                "callable must be provided at construction."
            )
        return self._executor(**kwargs)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _evaluate(self, parameters: dict[str, Any]) -> ArcReceipt:
        """Call the sidecar's ``evaluate_tool_call`` endpoint."""
        if not self.capability_id:
            raise ArcToolError(
                "no capability_id bound to tool",
                tool_name=self.name,
                server_id=self.server_id,
                reason="missing_capability",
            )

        client = self._arc_client
        owns_client = False
        if client is None:
            client = ArcClient(self.sidecar_url)
            owns_client = True

        try:
            return await client.evaluate_tool_call(
                capability_id=self.capability_id,
                tool_server=self.server_id,
                tool_name=self.name,
                parameters=parameters,
            )
        except ArcDeniedError as exc:
            raise ArcToolError(
                exc.message,
                tool_name=self.name,
                server_id=self.server_id,
                guard=exc.guard,
                reason=exc.reason,
                receipt_id=exc.receipt_id,
            ) from exc
        except ArcError:
            raise
        finally:
            if owns_client:
                await client.close()

    async def _invoke_executor(self, kwargs: dict[str, Any]) -> Any:
        """Run ``_execute`` / ``executor``, awaiting if it returned a coro."""
        result: Any = self._execute(**kwargs)
        if asyncio.iscoroutine(result) or isinstance(result, Awaitable):
            return await result
        return result


__all__ = [
    "ArcBaseTool",
    "ToolExecutor",
]
