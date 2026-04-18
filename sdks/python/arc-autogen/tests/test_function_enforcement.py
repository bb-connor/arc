"""Unit tests for ArcFunctionRegistry capability enforcement."""

from __future__ import annotations

from typing import Any

import pytest
from arc_sdk.models import (
    ArcScope,
    Operation,
    ToolGrant,
)
from arc_sdk.testing import (
    MockArcClient,
    MockVerdict,
    allow_all,
    deny_all,
)
from autogen import ConversableAgent

from arc_autogen import ArcAutogenConfigError, ArcFunctionRegistry, ArcToolError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agent(name: str) -> ConversableAgent:
    """Build a ConversableAgent safe to use in offline unit tests."""
    return ConversableAgent(
        name=name,
        llm_config=False,
        human_input_mode="NEVER",
        code_execution_config=False,
    )


def _scope_for_tools(*tool_names: str, server_id: str = "srv") -> ArcScope:
    """Build a scope that authorises exactly the given tools."""
    grants = [
        ToolGrant(
            server_id=server_id,
            tool_name=name,
            operations=[Operation.INVOKE],
        )
        for name in tool_names
    ]
    return ArcScope(grants=grants)


def _scope_aware_policy(mock_client: MockArcClient) -> Any:
    """Policy that enforces the scope bound to the capability_id."""

    def policy(
        tool_name: str,
        scope: dict[str, Any],
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
    client: MockArcClient,
    *,
    subject: str,
    scope: ArcScope,
) -> Any:
    """Mint a capability via the mock and index it for policy lookup."""
    token = await client.create_capability(subject=subject, scope=scope)
    store: dict[str, Any] = getattr(client, "_tokens", {})
    store[token.id] = token
    client._tokens = store  # type: ignore[attr-defined]
    return token


# ---------------------------------------------------------------------------
# (a) allow verdict runs the wrapped function
# ---------------------------------------------------------------------------


class TestAllowVerdict:
    async def test_allow_runs_sync_callable(self) -> None:
        called: list[dict[str, Any]] = []

        def do_search(**kwargs: Any) -> str:
            called.append(kwargs)
            return f"result={kwargs.get('q')}"

        async with allow_all() as arc:
            agent = _make_agent("researcher")
            registry = ArcFunctionRegistry(
                agent=agent,
                arc_client=arc,
                server_id="srv",
                capability_id="cap-1",
            )
            registry.register("search", do_search)

            wrapped = agent.function_map["search"]
            result = wrapped(q="hello")

        assert result == "result=hello"
        assert called == [{"q": "hello"}]
        assert registry.last_receipt("search") is not None
        assert registry.last_receipt("search").is_allowed  # type: ignore[union-attr]

    async def test_allow_awaits_async_callable(self) -> None:
        async def do_search(**kwargs: Any) -> str:
            return f"async:{kwargs.get('q')}"

        async with allow_all() as arc:
            agent = _make_agent("researcher")
            registry = ArcFunctionRegistry(
                agent=agent,
                arc_client=arc,
                server_id="srv",
                capability_id="cap-1",
            )
            registry.register("search", do_search)

            wrapped = agent.function_map["search"]
            # The registry preserved the async contract so the wrapped
            # callable is a coroutine function.
            import inspect as _inspect

            assert _inspect.iscoroutinefunction(wrapped)
            result = await wrapped(q="hi")

        assert result == "async:hi"


# ---------------------------------------------------------------------------
# (b) deny verdict raises ArcToolError
# ---------------------------------------------------------------------------


class TestDenyVerdict:
    async def test_deny_raises_arc_tool_error_from_receipt(self) -> None:
        def do_write(**kwargs: Any) -> str:
            pytest.fail("executor must not run on deny")
            return ""

        async with deny_all(raise_on_deny=False) as arc:
            agent = _make_agent("writer")
            registry = ArcFunctionRegistry(
                agent=agent,
                arc_client=arc,
                server_id="srv",
                capability_id="cap-x",
            )
            registry.register("write", do_write)

            wrapped = agent.function_map["write"]
            with pytest.raises(ArcToolError) as exc_info:
                wrapped(path="/tmp/x")

        err = exc_info.value
        assert err.tool_name == "write"
        assert err.server_id == "srv"
        assert "denied" in (err.reason or "").lower()
        assert err.receipt_id is not None
        assert registry.last_receipt("write") is not None
        assert registry.last_receipt("write").is_denied  # type: ignore[union-attr]

    async def test_deny_via_raise_raises_arc_tool_error(self) -> None:
        async with deny_all(reason="no write perms", guard="ScopeGuard") as arc:
            agent = _make_agent("writer")
            registry = ArcFunctionRegistry(
                agent=agent,
                arc_client=arc,
                server_id="srv",
                capability_id="cap-x",
            )
            registry.register("write", lambda **_kw: "unreached")
            wrapped = agent.function_map["write"]
            with pytest.raises(ArcToolError) as exc_info:
                wrapped(path="/tmp/x")

        err = exc_info.value
        assert err.guard == "ScopeGuard"
        assert "no write perms" in (err.reason or "")

    async def test_missing_capability_denies(self) -> None:
        async with allow_all() as arc:
            agent = _make_agent("researcher")
            registry = ArcFunctionRegistry(
                agent=agent,
                arc_client=arc,
                server_id="srv",
                capability_id="",
            )
            registry.register("search", lambda **_kw: "unreached")
            wrapped = agent.function_map["search"]
            with pytest.raises(ArcToolError) as exc_info:
                wrapped(q="hi")
        assert exc_info.value.reason == "missing_capability"

    async def test_missing_arc_client_denies(self) -> None:
        agent = _make_agent("researcher")
        registry = ArcFunctionRegistry(
            agent=agent,
            arc_client=None,
            server_id="srv",
            capability_id="cap-1",
        )
        registry.register("search", lambda **_kw: "unreached")
        wrapped = agent.function_map["search"]
        with pytest.raises(ArcToolError) as exc_info:
            wrapped(q="hi")
        assert exc_info.value.reason == "missing_arc_client"


# ---------------------------------------------------------------------------
# (c) scope enforcement via mock policy -- role-scoped behaviour
# ---------------------------------------------------------------------------


class TestRoleScopedFunctions:
    async def test_researcher_cannot_write(self) -> None:
        arc = MockArcClient()
        arc.set_policy(_scope_aware_policy(arc))

        researcher_token = await _mint_token(
            arc,
            subject="agent:researcher",
            scope=_scope_for_tools("search", "browse"),
        )

        agent = _make_agent("researcher")
        registry = ArcFunctionRegistry(
            agent=agent,
            arc_client=arc,
            server_id="srv",
            capability_id=researcher_token.id,
        )
        registry.register("write", lambda **_kw: "unreached")

        wrapped = agent.function_map["write"]
        with pytest.raises(ArcToolError) as exc_info:
            wrapped(path="/out")

        assert exc_info.value.guard == "ScopeGuard"
        assert "not in capability scope" in (exc_info.value.reason or "")

    async def test_writer_cannot_search(self) -> None:
        arc = MockArcClient()
        arc.set_policy(_scope_aware_policy(arc))

        writer_token = await _mint_token(
            arc,
            subject="agent:writer",
            scope=_scope_for_tools("write", "format"),
        )

        agent = _make_agent("writer")
        registry = ArcFunctionRegistry(
            agent=agent,
            arc_client=arc,
            server_id="srv",
            capability_id=writer_token.id,
        )
        registry.register("search", lambda **_kw: "unreached")
        wrapped = agent.function_map["search"]
        with pytest.raises(ArcToolError) as exc_info:
            wrapped(q="secrets")
        assert exc_info.value.guard == "ScopeGuard"


# ---------------------------------------------------------------------------
# (d) decorator-style registration
# ---------------------------------------------------------------------------


class TestDecoratorRegistration:
    async def test_as_decorator_uses_function_name_and_docstring(self) -> None:
        async with allow_all() as arc:
            agent = _make_agent("researcher")
            registry = ArcFunctionRegistry(
                agent=agent,
                arc_client=arc,
                server_id="srv",
                capability_id="cap-1",
            )

            @registry.as_decorator(scope=_scope_for_tools("search"))
            def search(query: str) -> str:
                """Search the web."""
                return f"hits:{query}"

            wrapped = agent.function_map["search"]
            assert wrapped(query="ml") == "hits:ml"
            assert registry.scope_for("search") is not None


# ---------------------------------------------------------------------------
# (e) rebinding capability via GroupChat-style attenuation
# ---------------------------------------------------------------------------


class TestCapabilityRebind:
    async def test_bind_capability_switches_token(self) -> None:
        arc = MockArcClient()
        arc.set_policy(_scope_aware_policy(arc))
        broad = await _mint_token(
            arc,
            subject="agent:lead",
            scope=_scope_for_tools("search", "write"),
        )
        narrow = await arc.attenuate_capability(
            broad, new_scope=_scope_for_tools("search")
        )
        arc._tokens[narrow.id] = narrow  # type: ignore[attr-defined]

        agent = _make_agent("lead")
        registry = ArcFunctionRegistry(
            agent=agent,
            arc_client=arc,
            server_id="srv",
            capability_id=broad.id,
        )
        registry.register("write", lambda **_kw: "written")
        registry.register("search", lambda **_kw: "searched")

        # Broad token: write is fine.
        assert agent.function_map["write"](path="/x") == "written"

        # Rebind to narrow token; write must now fail.
        registry.bind_capability(narrow)
        with pytest.raises(ArcToolError):
            agent.function_map["write"](path="/x")

        # Search still works.
        assert agent.function_map["search"](q="q") == "searched"


# ---------------------------------------------------------------------------
# (f) config errors
# ---------------------------------------------------------------------------


class TestConfigErrors:
    def test_empty_server_id_rejected(self) -> None:
        agent = _make_agent("r")
        with pytest.raises(ArcAutogenConfigError):
            ArcFunctionRegistry(
                agent=agent,
                arc_client=None,
                server_id="",
                capability_id="cap",
            )

    def test_none_agent_rejected(self) -> None:
        with pytest.raises(ArcAutogenConfigError):
            ArcFunctionRegistry(
                agent=None,
                arc_client=None,
                server_id="srv",
                capability_id="cap",
            )

    def test_empty_function_name_rejected(self) -> None:
        agent = _make_agent("r")
        registry = ArcFunctionRegistry(
            agent=agent,
            arc_client=None,
            server_id="srv",
            capability_id="cap",
        )
        with pytest.raises(ArcAutogenConfigError):
            registry.register("", lambda **_kw: None)
