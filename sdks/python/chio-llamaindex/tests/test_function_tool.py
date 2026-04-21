"""Unit tests for :class:`ChioFunctionTool` capability enforcement."""

from __future__ import annotations

from typing import Any

import pytest
from chio_sdk.models import ChioScope, Operation, ToolGrant
from chio_sdk.testing import (
    MockChioClient,
    MockVerdict,
    allow_all,
    deny_all,
)
from llama_index.core.tools import ToolOutput
from pydantic import BaseModel, Field

from chio_llamaindex import ChioFunctionTool, ChioToolError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scope_for_tools(*tool_names: str, server_id: str = "srv") -> ChioScope:
    """Build a scope that authorises exactly the given tools."""
    return ChioScope(
        grants=[
            ToolGrant(
                server_id=server_id,
                tool_name=name,
                operations=[Operation.INVOKE],
            )
            for name in tool_names
        ]
    )


def _scope_aware_policy(mock_client: MockChioClient) -> Any:
    """Policy that denies when the tool isn't in the token's scope."""

    def policy(
        tool_name: str,
        _scope_hint: dict[str, Any],
        context: dict[str, Any],
    ) -> MockVerdict:
        cap_id = context.get("capability_id")
        token = getattr(mock_client, "_tokens", {}).get(cap_id)
        if token is None:
            return MockVerdict.deny_verdict(
                f"unknown capability {cap_id!r}",
                guard="CapabilityGuard",
            )
        allowed = {g.tool_name for g in token.scope.grants}
        if tool_name in allowed or "*" in allowed:
            return MockVerdict.allow_verdict()
        return MockVerdict.deny_verdict(
            f"tool {tool_name!r} not in capability scope",
            guard="ScopeGuard",
        )

    return policy


async def _mint_token(
    client: MockChioClient,
    *,
    subject: str,
    scope: ChioScope,
) -> Any:
    """Mint a capability via the mock and index it for the policy."""
    token = await client.create_capability(subject=subject, scope=scope)
    store: dict[str, Any] = getattr(client, "_tokens", {})
    store[token.id] = token
    client._tokens = store  # type: ignore[attr-defined]
    return token


# ---------------------------------------------------------------------------
# (a) allow verdict runs the underlying function
# ---------------------------------------------------------------------------


class TestAllowVerdict:
    async def test_allow_runs_sync_fn(self) -> None:
        called: list[dict[str, Any]] = []

        def search(q: str) -> str:
            called.append({"q": q})
            return f"hit:{q}"

        async with allow_all() as arc:
            tool = ChioFunctionTool(
                fn=search,
                name="search",
                description="search the index",
                server_id="srv",
                capability_id="cap-1",
                chio_client=arc,
            )
            output = await tool.acall(q="quantum")

        assert isinstance(output, ToolOutput)
        assert "hit:quantum" in output.content
        assert called == [{"q": "quantum"}]
        assert tool.last_chio_receipt is not None
        assert tool.last_chio_receipt.is_allowed

    async def test_allow_awaits_async_fn(self) -> None:
        async def search(q: str) -> str:
            return f"async-hit:{q}"

        async with allow_all() as arc:
            tool = ChioFunctionTool(
                async_fn=search,
                name="search",
                description="search the index",
                server_id="srv",
                capability_id="cap-1",
                chio_client=arc,
            )
            output = await tool.acall(q="relativity")

        assert isinstance(output, ToolOutput)
        assert "async-hit:relativity" in output.content

    async def test_preserves_fn_schema(self) -> None:
        """LlamaIndex's ``fn_schema`` must flow through unchanged."""

        class SearchArgs(BaseModel):
            q: str = Field(description="query text")
            top_k: int = Field(default=5, ge=1, le=100)

        def search(q: str, top_k: int = 5) -> str:
            return f"{q}@{top_k}"

        async with allow_all() as arc:
            tool = ChioFunctionTool(
                fn=search,
                name="search",
                description="scoped search",
                fn_schema=SearchArgs,
                server_id="srv",
                capability_id="cap-1",
                chio_client=arc,
            )
            assert tool.metadata.fn_schema is SearchArgs
            # Schema JSON schema must be serialisable (LlamaIndex relies on
            # this to build the LLM-facing tool descriptor).
            schema = tool.metadata.fn_schema.model_json_schema()
            assert "properties" in schema
            assert "q" in schema["properties"]

    def test_sync_call_runs_fn_when_no_loop(self) -> None:
        """Pure-sync test: ``tool.call`` must bootstrap its own event loop."""

        def add(a: int, b: int) -> int:
            return a + b

        arc = allow_all()
        tool = ChioFunctionTool(
            fn=add,
            name="add",
            description="add two ints",
            server_id="srv",
            capability_id="cap-1",
            chio_client=arc,
        )
        out = tool.call(a=2, b=3)
        assert isinstance(out, ToolOutput)
        assert "5" in out.content

    async def test_sync_call_inside_running_loop_raises(self) -> None:
        arc = allow_all()
        tool = ChioFunctionTool(
            fn=lambda a, b: a + b,
            name="add",
            description="add",
            server_id="srv",
            capability_id="cap-1",
            chio_client=arc,
        )
        with pytest.raises(RuntimeError):
            tool.call(a=1, b=2)


# ---------------------------------------------------------------------------
# (b) deny verdict raises ChioToolError
# ---------------------------------------------------------------------------


class TestDenyVerdict:
    async def test_deny_raises_chio_tool_error(self) -> None:
        def executor(**_kw: Any) -> str:
            pytest.fail("fn must not run on deny")
            return ""

        async with deny_all(raise_on_deny=False) as arc:
            tool = ChioFunctionTool(
                fn=executor,
                name="write",
                description="write a file",
                server_id="srv",
                capability_id="cap-x",
                chio_client=arc,
            )
            with pytest.raises(ChioToolError) as exc_info:
                await tool.acall(path="/tmp/x")

        err = exc_info.value
        assert err.tool_name == "write"
        assert err.server_id == "srv"
        assert err.receipt_id is not None
        assert tool.last_chio_receipt is not None
        assert tool.last_chio_receipt.is_denied

    async def test_deny_from_403_raises_chio_tool_error(self) -> None:
        async with deny_all(reason="no write perms", guard="ScopeGuard") as arc:
            tool = ChioFunctionTool(
                fn=lambda **_kw: "unreached",
                name="write",
                description="write a file",
                server_id="srv",
                capability_id="cap-x",
                chio_client=arc,
            )
            with pytest.raises(ChioToolError) as exc_info:
                await tool.acall(path="/tmp/x")

        err = exc_info.value
        assert err.guard == "ScopeGuard"
        assert "no write perms" in (err.reason or "")

    async def test_missing_capability_id_denies(self) -> None:
        async with allow_all() as arc:
            tool = ChioFunctionTool(
                fn=lambda **_kw: "unreached",
                name="search",
                description="search",
                server_id="srv",
                capability_id="",
                chio_client=arc,
            )
            with pytest.raises(ChioToolError) as exc_info:
                await tool.acall(q="hi")
        assert exc_info.value.reason == "missing_capability"

    async def test_deny_returns_tool_output_when_raise_on_deny_false(
        self,
    ) -> None:
        """Some planners prefer deny-as-ToolOutput; exercise that path."""

        async with deny_all(raise_on_deny=False) as arc:
            tool = ChioFunctionTool(
                fn=lambda **_kw: "unreached",
                name="write",
                description="write",
                server_id="srv",
                capability_id="cap-x",
                chio_client=arc,
                raise_on_deny=False,
            )
            output = await tool.acall(path="/tmp/x")

        assert isinstance(output, ToolOutput)
        assert output.is_error is True
        assert output.content.startswith("DENIED:")


# ---------------------------------------------------------------------------
# (c) researcher-vs-writer scoping
# ---------------------------------------------------------------------------


class TestResearcherCannotWrite:
    async def test_researcher_write_is_denied(self) -> None:
        arc = MockChioClient()
        arc._tokens = {}  # type: ignore[attr-defined]
        arc.set_policy(_scope_aware_policy(arc))

        researcher_token = await _mint_token(
            arc,
            subject="agent:researcher",
            scope=_scope_for_tools("search", "browse"),
        )

        write_tool = ChioFunctionTool(
            fn=lambda **_kw: "unreached",
            name="write",
            description="write to disk",
            server_id="srv",
            capability_id=researcher_token.id,
            chio_client=arc,
        )

        with pytest.raises(ChioToolError) as exc_info:
            await write_tool.acall(path="/out")

        assert exc_info.value.guard == "ScopeGuard"
        assert "not in capability scope" in (exc_info.value.reason or "")

    async def test_writer_search_is_denied(self) -> None:
        arc = MockChioClient()
        arc._tokens = {}  # type: ignore[attr-defined]
        arc.set_policy(_scope_aware_policy(arc))

        writer_token = await _mint_token(
            arc,
            subject="agent:writer",
            scope=_scope_for_tools("write", "format"),
        )

        search_tool = ChioFunctionTool(
            fn=lambda **_kw: "unreached",
            name="search",
            description="search the web",
            server_id="srv",
            capability_id=writer_token.id,
            chio_client=arc,
        )
        with pytest.raises(ChioToolError) as exc_info:
            await search_tool.acall(q="secrets")
        assert exc_info.value.guard == "ScopeGuard"


# ---------------------------------------------------------------------------
# (d) recorded calls carry the right metadata
# ---------------------------------------------------------------------------


class TestRecordedInvocation:
    async def test_call_records_parameters_and_capability(self) -> None:
        arc = allow_all()

        def search(q: str, top_k: int = 5) -> str:
            return f"res:{q}:{top_k}"

        tool = ChioFunctionTool(
            fn=search,
            name="search",
            description="search",
            server_id="srv",
            capability_id="cap-42",
            chio_client=arc,
        )
        await tool.acall(q="hi", top_k=3)

        eval_calls = [c for c in arc.calls if c.method == "evaluate_tool_call"]
        assert len(eval_calls) == 1
        recorded = eval_calls[0]
        assert recorded.tool_name == "search"
        assert recorded.tool_server == "srv"
        assert recorded.capability_id == "cap-42"
        # Parameters flow through as-is.
        assert recorded.parameters == {"q": "hi", "top_k": 3}
