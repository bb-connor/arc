"""ARC-governed :class:`QueryEngineTool` with vector-collection scoping.

LlamaIndex's :class:`QueryEngineTool` wraps a RAG pipeline (retriever +
response synthesiser) as a callable tool. Because retrieval sits
behind a single ``query`` entry point, LlamaIndex itself has no notion
of which *vector collection* the tool is authorised to query.
:class:`ArcQueryEngineTool` fills that gap in two layers:

1. **Client-side scope check.** The tool is instantiated against a
   specific ``collection`` string. Each call verifies that the
   capability's scope permits querying that collection *before* the
   sidecar is contacted or the retriever is invoked.
2. **Sidecar evaluation.** The collection, the query string, and any
   caller-supplied metadata are forwarded to the ARC sidecar under
   ``tool_name=<collection>`` and ``parameters={"query": ..., "collection": ...}``.
   The sidecar may veto the call via its own policy, independent of the
   client-side check.

Collection scoping constraint
-----------------------------

The ARC core type :class:`Constraint` ships a
``MemoryStoreAllowlist(Vec<String>)`` variant that is semantically a
list of memory-store identifiers -- exactly the shape needed for a
vector-collection allowlist. We reuse it here.

The Python :class:`arc_sdk.models.Constraint` in the currently-shipped
SDK only exposes ``value: str | int | None``. To keep this SDK useful
without touching the core types crate (phase 2.2 owns that file), the
:class:`ArcQueryEngineTool` performs the allowlist check *client-side*
against an :class:`ArcScope` it carries. The client-side check is
enforced fail-closed: if no allowlist is present the call is denied.
When the Python :class:`Constraint` is extended to hold list values,
the wrapper will transparently pick up the scope constraint instead of
its locally-cached allowlist.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from arc_sdk.client import ArcClient
from arc_sdk.errors import ArcDeniedError, ArcError
from arc_sdk.models import ArcReceipt, ArcScope
from llama_index.core.base.base_query_engine import BaseQueryEngine
from llama_index.core.tools import QueryEngineTool, ToolOutput
from llama_index.core.tools.types import ToolMetadata

from arc_llamaindex.errors import ArcLlamaIndexConfigError, ArcToolError
from arc_llamaindex.function_tool import ArcClientLike

logger = logging.getLogger(__name__)


# Constraint tag name matching the Rust ``Constraint::MemoryStoreAllowlist``
# variant. See the module docstring for why we spell it out here instead
# of importing from :mod:`arc_sdk.models`.
MEMORY_STORE_ALLOWLIST_TAG = "memory_store_allowlist"


class ArcQueryEngineTool(QueryEngineTool):
    """LlamaIndex :class:`QueryEngineTool` scoped to a vector collection.

    Parameters
    ----------
    query_engine:
        The underlying :class:`BaseQueryEngine` implementing retrieval
        and synthesis.
    collection:
        Human-readable identifier of the vector collection this tool is
        bound to. The capability's scope must permit queries against
        this collection.
    name, description:
        Standard :class:`ToolMetadata` fields. ``name`` defaults to
        ``query_<collection>``.
    capability_scope:
        Optional :class:`ArcScope` that carries the collection allowlist
        for client-side scoping. If omitted, the wrapper accepts any
        collection (i.e. defers entirely to the sidecar policy).
    allowed_collections:
        Convenience shortcut: provide a list of collections and the
        wrapper synthesises a local allowlist without requiring a full
        :class:`ArcScope`.
    server_id, capability_id, sidecar_url, arc_client, raise_on_deny:
        As on :class:`arc_llamaindex.ArcFunctionTool`.
    """

    def __init__(
        self,
        *,
        query_engine: BaseQueryEngine,
        collection: str,
        name: str | None = None,
        description: str | None = None,
        resolve_input_errors: bool = True,
        capability_scope: ArcScope | None = None,
        allowed_collections: Iterable[str] | None = None,
        server_id: str = "",
        capability_id: str = "",
        sidecar_url: str = "http://127.0.0.1:9090",
        arc_client: ArcClientLike | None = None,
        raise_on_deny: bool = True,
    ) -> None:
        if not collection:
            raise ArcLlamaIndexConfigError(
                "ArcQueryEngineTool requires a non-empty 'collection'"
            )

        resolved_name = name or f"query_{collection}"
        resolved_description = description or (
            f"Query the '{collection}' vector collection through an "
            f"ARC-governed RAG pipeline."
        )
        metadata = ToolMetadata(
            name=resolved_name,
            description=resolved_description,
        )

        super().__init__(
            query_engine=query_engine,
            metadata=metadata,
            resolve_input_errors=resolve_input_errors,
        )

        self._collection = collection
        self._capability_scope = capability_scope
        self._local_allowlist: frozenset[str] | None = (
            frozenset(allowed_collections) if allowed_collections is not None else None
        )
        self._server_id = server_id
        self._capability_id = capability_id
        self._sidecar_url = sidecar_url
        self._arc_client = arc_client
        self._raise_on_deny = bool(raise_on_deny)
        self._last_receipt: ArcReceipt | None = None

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def collection(self) -> str:
        """The vector collection this tool is bound to."""
        return self._collection

    @property
    def server_id(self) -> str:
        """ARC tool-server identifier associated with this tool."""
        return self._server_id

    @property
    def capability_id(self) -> str:
        """Capability token id used on evaluate calls."""
        return self._capability_id

    @property
    def sidecar_url(self) -> str:
        """Base URL of the ARC sidecar the tool will talk to."""
        return self._sidecar_url

    @property
    def capability_scope(self) -> ArcScope | None:
        """Capability :class:`ArcScope` used for client-side allowlist checks."""
        return self._capability_scope

    @capability_scope.setter
    def capability_scope(self, value: ArcScope | None) -> None:
        self._capability_scope = value

    @property
    def last_arc_receipt(self) -> ArcReceipt | None:
        """Most recent :class:`ArcReceipt` returned by the sidecar."""
        return self._last_receipt

    def bind_arc_client(self, client: ArcClientLike) -> None:
        """Attach an :class:`ArcClient` (or mock) to reuse across calls."""
        self._arc_client = client

    def bind_capability(
        self,
        capability_id: str,
        *,
        scope: ArcScope | None = None,
    ) -> None:
        """Set the capability token id (and optionally its scope)."""
        self._capability_id = capability_id
        if scope is not None:
            self._capability_scope = scope

    def allowed_collections(self) -> frozenset[str]:
        """Return the effective collection allowlist, if any.

        Prefers an explicit ``allowed_collections`` override, then falls
        back to ``Constraint``-typed entries on ``capability_scope`` that
        match ``MemoryStoreAllowlist``. Returns an empty set when no
        allowlist is configured, which is distinct from "any collection"
        (``None``).
        """
        if self._local_allowlist is not None:
            return self._local_allowlist

        scope = self._capability_scope
        if scope is None:
            return frozenset()

        collected: set[str] = set()
        for grant in scope.grants:
            for constraint in grant.constraints:
                tag = getattr(constraint, "type", None)
                if tag != MEMORY_STORE_ALLOWLIST_TAG:
                    continue
                value = getattr(constraint, "value", None)
                # Values may be a single string (current
                # ``arc_sdk.models.Constraint``) or an iterable
                # (future-extended Constraint carrying a list).
                if isinstance(value, str):
                    collected.add(value)
                elif isinstance(value, Iterable):
                    for v in value:
                        if isinstance(v, str):
                            collected.add(v)
        return frozenset(collected)

    # ------------------------------------------------------------------
    # LlamaIndex BaseTool contract
    # ------------------------------------------------------------------

    def call(self, *args: Any, **kwargs: Any) -> ToolOutput:
        """Synchronous query entry point.

        Performs the client-side collection check, evaluates via the
        sidecar, then delegates to :class:`QueryEngineTool.call` on
        allow. Blocks by running the async path to completion.
        """
        import asyncio

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.acall(*args, **kwargs))
        raise RuntimeError(
            "ArcQueryEngineTool.call() cannot be used from a running event loop; "
            "await ArcQueryEngineTool.acall(...) instead."
        )

    async def acall(self, *args: Any, **kwargs: Any) -> ToolOutput:
        """Asynchronous query entry point.

        Enforces the collection allowlist, evaluates through the
        sidecar, and on allow calls :meth:`QueryEngineTool.acall`.
        """
        query_str = self._get_query_str(*args, **kwargs)
        self._check_collection_allowed()

        parameters: dict[str, Any] = {
            "query": query_str,
            "collection": self._collection,
        }
        receipt = await self._evaluate(parameters)
        self._last_receipt = receipt

        if receipt.is_denied:
            return self._on_deny(receipt, parameters)

        return await super().acall(*args, **kwargs)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _check_collection_allowed(self) -> None:
        """Fail-closed client-side check of the collection allowlist.

        Semantics:

        * No ``capability_scope`` and no ``allowed_collections`` override:
          defer entirely to the sidecar (no client-side check).
        * Allowlist configured and ``self.collection`` is not in it:
          raise :class:`ArcToolError` (fail-closed).
        * Allowlist configured and ``self.collection`` is in it: pass.
        """
        if self._local_allowlist is None and self._capability_scope is None:
            return
        allowed = self.allowed_collections()
        if not allowed:
            raise ArcToolError(
                "no collection allowlist in scope",
                tool_name=self.metadata.name,
                server_id=self._server_id,
                guard="CollectionScopeGuard",
                reason="missing_collection_allowlist",
            )
        if self._collection not in allowed:
            raise ArcToolError(
                f"collection {self._collection!r} not in capability allowlist",
                tool_name=self.metadata.name,
                server_id=self._server_id,
                guard="CollectionScopeGuard",
                reason="collection_not_allowed",
            )

    async def _evaluate(self, parameters: dict[str, Any]) -> ArcReceipt:
        """Call the sidecar's ``evaluate_tool_call`` endpoint."""
        if not self._capability_id:
            raise ArcToolError(
                "no capability_id bound to tool",
                tool_name=self.metadata.name,
                server_id=self._server_id,
                reason="missing_capability",
            )

        client = self._arc_client
        owns_client = False
        if client is None:
            client = ArcClient(self._sidecar_url)
            owns_client = True

        try:
            return await client.evaluate_tool_call(
                capability_id=self._capability_id,
                tool_server=self._server_id,
                tool_name=self.metadata.name or "",
                parameters=parameters,
            )
        except ArcDeniedError as exc:
            raise ArcToolError(
                exc.message,
                tool_name=self.metadata.name,
                server_id=self._server_id,
                guard=exc.guard,
                reason=exc.reason,
                receipt_id=exc.receipt_id,
            ) from exc
        except ArcError:
            raise
        finally:
            if owns_client:
                await client.close()

    def _on_deny(
        self,
        receipt: ArcReceipt,
        parameters: dict[str, Any],
    ) -> ToolOutput:
        """Translate a deny receipt into the configured outcome."""
        reason = receipt.decision.reason or "denied by ARC kernel"
        if self._raise_on_deny:
            raise ArcToolError(
                reason,
                tool_name=self.metadata.name,
                server_id=self._server_id,
                guard=receipt.decision.guard,
                reason=receipt.decision.reason,
                receipt_id=receipt.id,
                decision=receipt.decision.model_dump(exclude_none=True),
            )

        return ToolOutput(
            content=f"DENIED: {reason}",
            tool_name=self.metadata.name or "",
            raw_input=dict(parameters),
            raw_output=reason,
            is_error=True,
        )


__all__ = [
    "ArcQueryEngineTool",
    "MEMORY_STORE_ALLOWLIST_TAG",
]
