"""Tests for :func:`chio_prefect.chio_flow` scope attenuation.

The flow's scope must bound every enclosed :func:`chio_task`'s scope.
Tasks declaring a broader scope than their flow are rejected at call
time with :class:`ChioPrefectConfigError`. Tasks declaring a subset
scope pass through; tasks declaring no scope inherit the flow's scope.
"""

from __future__ import annotations

from typing import Any

import pytest
from chio_sdk.models import ChioScope, Operation, ToolGrant
from chio_sdk.testing import allow_all

from chio_prefect import chio_flow, chio_task
from chio_prefect.errors import ChioPrefectConfigError


def _scope_for_tools(*tool_names: str, server_id: str = "srv") -> ChioScope:
    grants = [
        ToolGrant(
            server_id=server_id,
            tool_name=name,
            operations=[Operation.INVOKE],
        )
        for name in tool_names
    ]
    return ChioScope(grants=grants)


class TestFlowScopeBounds:
    def test_subset_task_scope_is_accepted(self) -> None:
        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("search"),
            chio_client=chio,
        )
        def search() -> str:
            return "hits"

        @chio_flow(
            scope=_scope_for_tools("search", "analyze"),
            capability_id="cap-flow",
            tool_server="srv",
            chio_client=chio,
        )
        def pipeline() -> str:
            return search()

        assert pipeline() == "hits"

    def test_broader_task_scope_is_rejected(self) -> None:
        """A task that widens the flow scope fails before evaluation."""
        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("search", "write"),
            chio_client=chio,
        )
        def rogue_task() -> str:
            return "should-not-run"

        @chio_flow(
            scope=_scope_for_tools("search"),
            capability_id="cap-flow",
            tool_server="srv",
            chio_client=chio,
        )
        def pipeline() -> str:
            return rogue_task()

        # The ChioPrefectConfigError is raised inside the task body, so
        # Prefect surfaces it via the Failed task-run state as the
        # original exception class when the flow re-raises.
        with pytest.raises(ChioPrefectConfigError) as exc_info:
            pipeline()

        assert "not a subset" in str(exc_info.value)
        # No sidecar evaluation should have happened for the rogue task.
        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert evaluate_calls == []

    def test_task_without_scope_inherits_flow_scope(self) -> None:
        chio = allow_all()

        @chio_task(chio_client=chio)
        def inherits() -> str:
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("inherits"),
            capability_id="cap-flow",
            tool_server="srv",
            chio_client=chio,
        )
        def pipeline() -> str:
            return inherits()

        assert pipeline() == "ok"
        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        # The flow's capability_id and tool_server are used when the
        # task leaves them unset.
        assert evaluate_calls[0].capability_id == "cap-flow"
        assert evaluate_calls[0].tool_server == "srv"

    def test_task_tool_server_override_beats_flow_tool_server(self) -> None:
        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("fetch"),
            tool_server="override-srv",
            chio_client=chio,
        )
        def fetch() -> str:
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("fetch"),
            capability_id="cap-flow",
            tool_server="flow-srv",
            chio_client=chio,
        )
        def pipeline() -> str:
            return fetch()

        pipeline()
        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        assert evaluate_calls[0].tool_server == "override-srv"

    def test_flow_requires_scope_and_capability_id(self) -> None:
        # Calling chio_flow with missing args must fail at decoration
        # time -- not at flow-run time -- so operators catch it early.
        with pytest.raises(ChioPrefectConfigError):

            @chio_flow()  # type: ignore[call-overload]
            def bad_flow() -> None:
                return None


class TestFlowScopeComposition:
    def test_multiple_tasks_all_evaluate_under_flow_grant(self) -> None:
        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("a"),
            chio_client=chio,
        )
        def a() -> str:
            return "a"

        @chio_task(
            scope=_scope_for_tools("b"),
            chio_client=chio,
        )
        def b() -> str:
            return "b"

        @chio_task(
            scope=_scope_for_tools("c"),
            chio_client=chio,
        )
        def c() -> str:
            return "c"

        @chio_flow(
            scope=_scope_for_tools("a", "b", "c"),
            capability_id="cap-compose",
            tool_server="srv",
            chio_client=chio,
        )
        def pipeline() -> list[str]:
            return [a(), b(), c()]

        assert pipeline() == ["a", "b", "c"]
        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert [c.tool_name for c in evaluate_calls] == ["a", "b", "c"]
        # All evaluated under the flow's capability id.
        assert {c.capability_id for c in evaluate_calls} == {"cap-compose"}

    async def test_async_flow_bounds_async_tasks(self) -> None:
        chio = allow_all()

        @chio_task(
            scope=_scope_for_tools("step"),
            chio_client=chio,
        )
        async def step(x: int) -> int:
            return x + 1

        @chio_flow(
            scope=_scope_for_tools("step"),
            capability_id="cap-async",
            tool_server="srv",
            chio_client=chio,
        )
        async def pipeline(n: int) -> int:
            v = 0
            for _ in range(n):
                v = await step(v)
            return v

        result = await pipeline(3)
        assert result == 3
        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 3
        assert {c.capability_id for c in evaluate_calls} == {"cap-async"}


class TestFlowScopeIsolation:
    def test_flow_context_does_not_leak_across_runs(self) -> None:
        """After a flow returns, a subsequent standalone task call must not
        see the previous flow's capability_id."""
        chio = allow_all()

        @chio_task(chio_client=chio)
        def inherits() -> str:
            return "ok"

        @chio_flow(
            scope=_scope_for_tools("inherits"),
            capability_id="cap-first",
            tool_server="srv",
            chio_client=chio,
        )
        def pipeline() -> str:
            return inherits()

        assert pipeline() == "ok"

        # Second flow run uses a different capability id; the context
        # must be fresh.
        @chio_flow(
            scope=_scope_for_tools("inherits"),
            capability_id="cap-second",
            tool_server="srv",
            chio_client=chio,
        )
        def pipeline_two() -> str:
            return inherits()

        pipeline_two()
        evaluate_calls: list[Any] = [
            c for c in chio.calls if c.method == "evaluate_tool_call"
        ]
        assert len(evaluate_calls) == 2
        assert evaluate_calls[0].capability_id == "cap-first"
        assert evaluate_calls[1].capability_id == "cap-second"
