"""Tests for :func:`arc_prefect.arc_flow` scope attenuation.

The flow's scope must bound every enclosed :func:`arc_task`'s scope.
Tasks declaring a broader scope than their flow are rejected at call
time with :class:`ArcPrefectConfigError`. Tasks declaring a subset
scope pass through; tasks declaring no scope inherit the flow's scope.
"""

from __future__ import annotations

from typing import Any

import pytest
from arc_sdk.models import ArcScope, Operation, ToolGrant
from arc_sdk.testing import allow_all

from arc_prefect import arc_flow, arc_task
from arc_prefect.errors import ArcPrefectConfigError


def _scope_for_tools(*tool_names: str, server_id: str = "srv") -> ArcScope:
    grants = [
        ToolGrant(
            server_id=server_id,
            tool_name=name,
            operations=[Operation.INVOKE],
        )
        for name in tool_names
    ]
    return ArcScope(grants=grants)


class TestFlowScopeBounds:
    def test_subset_task_scope_is_accepted(self) -> None:
        arc = allow_all()

        @arc_task(
            scope=_scope_for_tools("search"),
            arc_client=arc,
        )
        def search() -> str:
            return "hits"

        @arc_flow(
            scope=_scope_for_tools("search", "analyze"),
            capability_id="cap-flow",
            tool_server="srv",
            arc_client=arc,
        )
        def pipeline() -> str:
            return search()

        assert pipeline() == "hits"

    def test_broader_task_scope_is_rejected(self) -> None:
        """A task that widens the flow scope fails before evaluation."""
        arc = allow_all()

        @arc_task(
            scope=_scope_for_tools("search", "write"),
            arc_client=arc,
        )
        def rogue_task() -> str:
            return "should-not-run"

        @arc_flow(
            scope=_scope_for_tools("search"),
            capability_id="cap-flow",
            tool_server="srv",
            arc_client=arc,
        )
        def pipeline() -> str:
            return rogue_task()

        # The ArcPrefectConfigError is raised inside the task body, so
        # Prefect surfaces it via the Failed task-run state as the
        # original exception class when the flow re-raises.
        with pytest.raises(ArcPrefectConfigError) as exc_info:
            pipeline()

        assert "not a subset" in str(exc_info.value)
        # No sidecar evaluation should have happened for the rogue task.
        evaluate_calls = [c for c in arc.calls if c.method == "evaluate_tool_call"]
        assert evaluate_calls == []

    def test_task_without_scope_inherits_flow_scope(self) -> None:
        arc = allow_all()

        @arc_task(arc_client=arc)
        def inherits() -> str:
            return "ok"

        @arc_flow(
            scope=_scope_for_tools("inherits"),
            capability_id="cap-flow",
            tool_server="srv",
            arc_client=arc,
        )
        def pipeline() -> str:
            return inherits()

        assert pipeline() == "ok"
        evaluate_calls = [c for c in arc.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        # The flow's capability_id and tool_server are used when the
        # task leaves them unset.
        assert evaluate_calls[0].capability_id == "cap-flow"
        assert evaluate_calls[0].tool_server == "srv"

    def test_task_tool_server_override_beats_flow_tool_server(self) -> None:
        arc = allow_all()

        @arc_task(
            scope=_scope_for_tools("fetch"),
            tool_server="override-srv",
            arc_client=arc,
        )
        def fetch() -> str:
            return "ok"

        @arc_flow(
            scope=_scope_for_tools("fetch"),
            capability_id="cap-flow",
            tool_server="flow-srv",
            arc_client=arc,
        )
        def pipeline() -> str:
            return fetch()

        pipeline()
        evaluate_calls = [c for c in arc.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        assert evaluate_calls[0].tool_server == "override-srv"

    def test_flow_requires_scope_and_capability_id(self) -> None:
        # Calling arc_flow with missing args must fail at decoration
        # time -- not at flow-run time -- so operators catch it early.
        with pytest.raises(ArcPrefectConfigError):

            @arc_flow()  # type: ignore[call-overload]
            def bad_flow() -> None:
                return None


class TestFlowScopeComposition:
    def test_multiple_tasks_all_evaluate_under_flow_grant(self) -> None:
        arc = allow_all()

        @arc_task(
            scope=_scope_for_tools("a"),
            arc_client=arc,
        )
        def a() -> str:
            return "a"

        @arc_task(
            scope=_scope_for_tools("b"),
            arc_client=arc,
        )
        def b() -> str:
            return "b"

        @arc_task(
            scope=_scope_for_tools("c"),
            arc_client=arc,
        )
        def c() -> str:
            return "c"

        @arc_flow(
            scope=_scope_for_tools("a", "b", "c"),
            capability_id="cap-compose",
            tool_server="srv",
            arc_client=arc,
        )
        def pipeline() -> list[str]:
            return [a(), b(), c()]

        assert pipeline() == ["a", "b", "c"]
        evaluate_calls = [c for c in arc.calls if c.method == "evaluate_tool_call"]
        assert [c.tool_name for c in evaluate_calls] == ["a", "b", "c"]
        # All evaluated under the flow's capability id.
        assert {c.capability_id for c in evaluate_calls} == {"cap-compose"}

    async def test_async_flow_bounds_async_tasks(self) -> None:
        arc = allow_all()

        @arc_task(
            scope=_scope_for_tools("step"),
            arc_client=arc,
        )
        async def step(x: int) -> int:
            return x + 1

        @arc_flow(
            scope=_scope_for_tools("step"),
            capability_id="cap-async",
            tool_server="srv",
            arc_client=arc,
        )
        async def pipeline(n: int) -> int:
            v = 0
            for _ in range(n):
                v = await step(v)
            return v

        result = await pipeline(3)
        assert result == 3
        evaluate_calls = [c for c in arc.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 3
        assert {c.capability_id for c in evaluate_calls} == {"cap-async"}


class TestFlowScopeIsolation:
    def test_flow_context_does_not_leak_across_runs(self) -> None:
        """After a flow returns, a subsequent standalone task call must not
        see the previous flow's capability_id."""
        arc = allow_all()

        @arc_task(arc_client=arc)
        def inherits() -> str:
            return "ok"

        @arc_flow(
            scope=_scope_for_tools("inherits"),
            capability_id="cap-first",
            tool_server="srv",
            arc_client=arc,
        )
        def pipeline() -> str:
            return inherits()

        assert pipeline() == "ok"

        # Second flow run uses a different capability id; the context
        # must be fresh.
        @arc_flow(
            scope=_scope_for_tools("inherits"),
            capability_id="cap-second",
            tool_server="srv",
            arc_client=arc,
        )
        def pipeline_two() -> str:
            return inherits()

        pipeline_two()
        evaluate_calls: list[Any] = [
            c for c in arc.calls if c.method == "evaluate_tool_call"
        ]
        assert len(evaluate_calls) == 2
        assert evaluate_calls[0].capability_id == "cap-first"
        assert evaluate_calls[1].capability_id == "cap-second"
