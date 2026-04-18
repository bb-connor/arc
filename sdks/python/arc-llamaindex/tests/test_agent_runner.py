"""Tests for :class:`ArcAgentRunner` capability binding."""

from __future__ import annotations

from typing import Any

import pytest
from arc_sdk.errors import ArcValidationError
from arc_sdk.models import ArcScope, Operation, ToolGrant
from arc_sdk.testing import MockArcClient, MockVerdict

from arc_llamaindex import (
    ArcAgentRunner,
    ArcFunctionTool,
    ArcLlamaIndexConfigError,
    ArcQueryEngineTool,
    ArcToolError,
)
from arc_llamaindex.query_engine_tool import MEMORY_STORE_ALLOWLIST_TAG

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeAgentWorker:
    """Minimal duck-typed stand-in for :class:`BaseAgentWorker`.

    Real :class:`AgentRunner` instances store their tools on
    ``agent_worker._tools``; we replicate that shape so the discovery
    helper on :class:`ArcAgentRunner` finds them.
    """

    def __init__(self, tools: list[Any]) -> None:
        self._tools = list(tools)


class _FakeAgentRunner:
    """Minimal duck-typed stand-in for :class:`AgentRunner`."""

    def __init__(self, tools: list[Any]) -> None:
        self.agent_worker = _FakeAgentWorker(tools)


class _FakeRunnerWithTopLevelTools:
    """Stand-in exposing tools at the runner level (newer LlamaIndex shapes)."""

    def __init__(self, tools: list[Any]) -> None:
        self.tools = list(tools)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scope_for_tools(*tool_names: str, server_id: str = "srv") -> ArcScope:
    return ArcScope(
        grants=[
            ToolGrant(
                server_id=server_id,
                tool_name=name,
                operations=[Operation.INVOKE],
            )
            for name in tool_names
        ]
    )


def _instrumented_client() -> MockArcClient:
    """MockArcClient that records minted tokens for policy lookup."""

    arc = MockArcClient()
    arc._tokens = {}  # type: ignore[attr-defined]

    original_create = arc.create_capability
    original_attenuate = arc.attenuate_capability

    async def create_capability(**kwargs: Any) -> Any:
        token = await original_create(**kwargs)
        arc._tokens[token.id] = token  # type: ignore[attr-defined]
        return token

    async def attenuate_capability(parent: Any, **kwargs: Any) -> Any:
        child = await original_attenuate(parent, **kwargs)
        arc._tokens[child.id] = child  # type: ignore[attr-defined]
        return child

    arc.create_capability = create_capability  # type: ignore[method-assign]
    arc.attenuate_capability = attenuate_capability  # type: ignore[method-assign]

    def policy(
        tool_name: str,
        _scope: dict[str, Any],
        context: dict[str, Any],
    ) -> MockVerdict:
        cap_id = context.get("capability_id")
        token = arc._tokens.get(cap_id)  # type: ignore[attr-defined]
        if token is None:
            return MockVerdict.deny_verdict(
                f"unknown capability {cap_id!r}",
                guard="CapabilityGuard",
            )
        allowed = {g.tool_name for g in token.scope.grants}
        if tool_name in allowed:
            return MockVerdict.allow_verdict()
        return MockVerdict.deny_verdict(
            f"tool {tool_name!r} not in capability scope",
            guard="ScopeGuard",
        )

    arc.set_policy(policy)
    return arc


# ---------------------------------------------------------------------------
# (a) provision_capability binds the token to every ARC tool
# ---------------------------------------------------------------------------


class TestProvisionCapability:
    async def test_binds_to_function_tools(self) -> None:
        arc = _instrumented_client()
        search = ArcFunctionTool(
            fn=lambda q: f"hit:{q}",
            name="search",
            description="search",
            server_id="srv",
        )
        write = ArcFunctionTool(
            fn=lambda **_kw: "wrote",
            name="write",
            description="write",
            server_id="srv",
        )
        runner = _FakeAgentRunner(tools=[search, write])

        arc_runner = ArcAgentRunner(
            runner=runner,
            capability_scope=_scope_for_tools("search"),
            arc_client=arc,
            agent_name="analyst",
        )
        token = await arc_runner.provision_capability()

        assert search.capability_id == token.id
        assert write.capability_id == token.id
        # Each tool is now wired to use the shared client.
        # (We cannot compare equality on ArcClient; the assertion that
        # evaluate_tool_call works through ``search`` is the real test
        # below in acceptance.)

    async def test_acceptance_allows_in_scope_denies_out_of_scope(self) -> None:
        """Roadmap acceptance: an AgentRunner with ArcFunctionTool evaluates
        each tool dispatch through the sidecar."""
        arc = _instrumented_client()

        search = ArcFunctionTool(
            fn=lambda q: f"hit:{q}",
            name="search",
            description="search",
            server_id="srv",
        )
        write = ArcFunctionTool(
            fn=lambda **_kw: "wrote",
            name="write",
            description="write",
            server_id="srv",
        )
        runner = _FakeAgentRunner(tools=[search, write])

        arc_runner = ArcAgentRunner(
            runner=runner,
            capability_scope=_scope_for_tools("search"),
            arc_client=arc,
            agent_name="analyst",
        )
        await arc_runner.provision_capability()

        # In-scope dispatch succeeds.
        out = await search.acall(q="llm")
        assert "hit:llm" in out.content

        # Out-of-scope dispatch via the other tool on the same runner
        # is denied by the sidecar.
        with pytest.raises(ArcToolError) as exc_info:
            await write.acall(path="/out")
        assert exc_info.value.guard == "ScopeGuard"

    async def test_picks_up_top_level_tools_attribute(self) -> None:
        arc = _instrumented_client()
        tool = ArcFunctionTool(
            fn=lambda q: q,
            name="search",
            description="s",
            server_id="srv",
        )
        runner = _FakeRunnerWithTopLevelTools(tools=[tool])
        arc_runner = ArcAgentRunner(
            runner=runner,
            capability_scope=_scope_for_tools("search"),
            arc_client=arc,
            agent_name="a",
        )
        token = await arc_runner.provision_capability()
        assert tool.capability_id == token.id

    async def test_non_arc_tools_are_ignored(self) -> None:
        """Plain LlamaIndex tools must be left alone."""
        arc = _instrumented_client()

        class _Plain:
            capability_id = "untouched"

        plain = _Plain()
        arc_tool = ArcFunctionTool(
            fn=lambda q: q,
            name="search",
            description="s",
            server_id="srv",
        )
        runner = _FakeAgentRunner(tools=[plain, arc_tool])
        arc_runner = ArcAgentRunner(
            runner=runner,
            capability_scope=_scope_for_tools("search"),
            arc_client=arc,
            agent_name="a",
        )
        token = await arc_runner.provision_capability()

        assert plain.capability_id == "untouched"
        assert arc_tool.capability_id == token.id

    async def test_extra_tools_are_bound_too(self) -> None:
        arc = _instrumented_client()
        registered = ArcFunctionTool(
            fn=lambda q: q,
            name="search",
            description="s",
            server_id="srv",
        )
        ad_hoc = ArcFunctionTool(
            fn=lambda q: q,
            name="search",
            description="s",
            server_id="srv",
        )
        runner = _FakeAgentRunner(tools=[registered])

        arc_runner = ArcAgentRunner(
            runner=runner,
            capability_scope=_scope_for_tools("search"),
            arc_client=arc,
            agent_name="a",
        )
        await arc_runner.provision_capability(extra_tools=[ad_hoc])
        assert registered.capability_id
        assert ad_hoc.capability_id == registered.capability_id


# ---------------------------------------------------------------------------
# (b) binding query engine tools propagates the scope
# ---------------------------------------------------------------------------


class TestQueryEngineBinding:
    async def test_query_engine_tool_receives_scope(self) -> None:
        arc = _instrumented_client()

        from llama_index.core.base.base_query_engine import BaseQueryEngine
        from llama_index.core.base.response.schema import Response

        class _Engine(BaseQueryEngine):
            def __init__(self) -> None:
                super().__init__(callback_manager=None)

            def _query(self, bundle: Any) -> Any:  # pragma: no cover
                return Response(response="r")

            async def _aquery(self, bundle: Any) -> Any:
                return Response(response="r")

            def _get_prompt_modules(self) -> dict[str, Any]:
                return {}

        from arc_sdk.models import Constraint

        scope = ArcScope(
            grants=[
                ToolGrant(
                    server_id="rag-srv",
                    tool_name="query_prod-docs",
                    operations=[Operation.INVOKE],
                    constraints=[
                        Constraint(
                            type=MEMORY_STORE_ALLOWLIST_TAG,
                            value="prod-docs",
                        ),
                    ],
                )
            ]
        )

        qet = ArcQueryEngineTool(
            query_engine=_Engine(),
            collection="prod-docs",
            server_id="rag-srv",
        )
        runner = _FakeAgentRunner(tools=[qet])

        arc_runner = ArcAgentRunner(
            runner=runner,
            capability_scope=scope,
            arc_client=arc,
            agent_name="analyst",
        )
        token = await arc_runner.provision_capability()

        # After provisioning, the query engine tool has a capability id,
        # the shared client, and the scope for client-side checks.
        assert qet.capability_id == token.id
        assert qet.capability_scope is scope
        assert qet.allowed_collections() == frozenset({"prod-docs"})


# ---------------------------------------------------------------------------
# (c) attenuation produces child capabilities
# ---------------------------------------------------------------------------


class TestAttenuation:
    async def test_attenuate_narrows_scope(self) -> None:
        arc = _instrumented_client()
        tool = ArcFunctionTool(
            fn=lambda q: q,
            name="search",
            description="s",
            server_id="srv",
        )
        runner = _FakeAgentRunner(tools=[tool])
        arc_runner = ArcAgentRunner(
            runner=runner,
            capability_scope=_scope_for_tools("search", "write"),
            arc_client=arc,
            agent_name="lead",
        )
        parent = await arc_runner.provision_capability()
        child = await arc_runner.attenuate(new_scope=_scope_for_tools("search"))
        assert child.scope.is_subset_of(parent.scope)
        assert not parent.scope.is_subset_of(child.scope)

    async def test_attenuate_rejects_broader_scope(self) -> None:
        arc = _instrumented_client()
        tool = ArcFunctionTool(
            fn=lambda q: q,
            name="search",
            description="s",
            server_id="srv",
        )
        runner = _FakeAgentRunner(tools=[tool])
        arc_runner = ArcAgentRunner(
            runner=runner,
            capability_scope=_scope_for_tools("search"),
            arc_client=arc,
            agent_name="lead",
        )
        await arc_runner.provision_capability()
        with pytest.raises(ArcValidationError):
            await arc_runner.attenuate(
                new_scope=_scope_for_tools("search", "write")
            )

    async def test_attenuate_before_provisioning_raises(self) -> None:
        arc = _instrumented_client()
        runner = _FakeAgentRunner(tools=[])
        arc_runner = ArcAgentRunner(
            runner=runner,
            capability_scope=_scope_for_tools("search"),
            arc_client=arc,
            agent_name="lead",
        )
        with pytest.raises(ArcLlamaIndexConfigError):
            await arc_runner.attenuate(new_scope=_scope_for_tools("search"))


# ---------------------------------------------------------------------------
# (d) config validation
# ---------------------------------------------------------------------------


class TestConfig:
    def test_none_runner_rejected(self) -> None:
        arc = _instrumented_client()
        with pytest.raises(ArcLlamaIndexConfigError):
            ArcAgentRunner(
                runner=None,
                capability_scope=_scope_for_tools("search"),
                arc_client=arc,
                agent_name="a",
            )

    async def test_bind_tools_without_provision_raises(self) -> None:
        arc = _instrumented_client()
        runner = _FakeAgentRunner(tools=[])
        arc_runner = ArcAgentRunner(
            runner=runner,
            capability_scope=_scope_for_tools("search"),
            arc_client=arc,
            agent_name="a",
        )
        tool = ArcFunctionTool(
            fn=lambda q: q, name="search", description="s", server_id="srv"
        )
        with pytest.raises(ArcLlamaIndexConfigError):
            arc_runner.bind_tools([tool])
