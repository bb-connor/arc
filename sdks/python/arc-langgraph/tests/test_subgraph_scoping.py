"""Tests for subgraph scope-ceiling enforcement.

Roadmap acceptance (phase 10.3): *Subgraph nodes cannot exceed the
parent graph's scope ceiling.*

We exercise three cases:

1. A subgraph whose node scopes fit under the parent ceiling succeeds
   and its nodes dispatch normally.
2. Adding a node whose scope exceeds the parent ceiling raises
   :class:`ArcLangGraphConfigError` at registration time (fail-fast).
3. Constructing the subgraph with an offending ``node_scopes`` dict up
   front also raises -- the ``__post_init__`` hook runs the same check.
"""

from __future__ import annotations

from typing import Any, TypedDict

import pytest
from arc_sdk.models import ArcScope, Operation, ToolGrant
from arc_sdk.testing import allow_all

from arc_langgraph import (
    ArcGraphConfig,
    ArcLangGraphConfigError,
    arc_node,
    enforce_subgraph_ceiling,
)


class State(TypedDict, total=False):
    value: str


SERVER_ID = "demo-srv"


def _scope(*tools: str) -> ArcScope:
    return ArcScope(
        grants=[
            ToolGrant(
                server_id=SERVER_ID,
                tool_name=name,
                operations=[Operation.INVOKE],
            )
            for name in tools
        ]
    )


# ---------------------------------------------------------------------------
# (a) Subgraph whose nodes fit under the ceiling works end-to-end
# ---------------------------------------------------------------------------


class TestSubgraphWithinCeiling:
    async def test_nodes_within_ceiling_dispatch_successfully(self) -> None:
        arc = allow_all()
        outer = ArcGraphConfig(
            arc_client=arc,
            workflow_scope=_scope("search", "browse", "analyze"),
            node_scopes={"research": _scope("search", "browse", "analyze")},
        )
        await outer.provision()

        # Build a child config for the subgraph. Its ceiling inherits
        # from ``outer``'s effective ceiling.
        inner = outer.subgraph_config(
            workflow_scope=_scope("search", "browse"),
        )
        inner.register_node_scope("search", _scope("search"))
        inner.register_node_scope("browse", _scope("browse"))
        await inner.provision()

        def search_body(_state: State) -> dict[str, Any]:
            return {"value": "searched"}

        wrapped_search = arc_node(
            search_body, scope=_scope("search"), config=inner, name="search"
        )
        assert (await wrapped_search({"value": "x"})) == {
            "value": "searched"
        }


# ---------------------------------------------------------------------------
# (b) Register-time attenuation refuses a broader scope
# ---------------------------------------------------------------------------


class TestRegisterRefusesBroaderScope:
    async def test_register_node_scope_raises_when_broader(self) -> None:
        arc = allow_all()
        outer = ArcGraphConfig(
            arc_client=arc,
            workflow_scope=_scope("search", "browse"),
        )
        inner = outer.subgraph_config()

        with pytest.raises(ArcLangGraphConfigError):
            inner.register_node_scope(
                "write", _scope("search", "browse", "write")
            )

    async def test_arc_node_refuses_broader_scope(self) -> None:
        arc = allow_all()
        outer = ArcGraphConfig(
            arc_client=arc,
            workflow_scope=_scope("search"),
        )

        def body(_s: State) -> dict[str, Any]:
            return {"value": "ok"}

        with pytest.raises(ArcLangGraphConfigError):
            arc_node(
                body,
                scope=_scope("search", "write"),
                config=outer,
                name="escalate",
            )


# ---------------------------------------------------------------------------
# (c) Subgraph constructor validates the scope map
# ---------------------------------------------------------------------------


class TestSubgraphConstructorValidates:
    async def test_constructor_rejects_broader_node_scope(self) -> None:
        arc = allow_all()
        outer = ArcGraphConfig(
            arc_client=arc,
            workflow_scope=_scope("search"),
        )
        with pytest.raises(ArcLangGraphConfigError):
            outer.subgraph_config(
                node_scopes={"write": _scope("search", "write")},
            )

    async def test_constructor_accepts_exact_subset(self) -> None:
        arc = allow_all()
        outer = ArcGraphConfig(
            arc_client=arc,
            workflow_scope=_scope("search", "browse"),
        )
        inner = outer.subgraph_config(
            node_scopes={"search": _scope("search")},
        )
        assert inner.scope_for("search") == _scope("search")


# ---------------------------------------------------------------------------
# (d) enforce_subgraph_ceiling is usable standalone
# ---------------------------------------------------------------------------


class TestStandaloneCeilingCheck:
    def test_no_ceiling_is_noop(self) -> None:
        arc = allow_all()
        cfg = ArcGraphConfig(arc_client=arc)
        # Should not raise.
        enforce_subgraph_ceiling(cfg, "anything", _scope("anything"))

    def test_with_ceiling_rejects_broader(self) -> None:
        arc = allow_all()
        cfg = ArcGraphConfig(
            arc_client=arc, workflow_scope=_scope("search")
        )
        with pytest.raises(ArcLangGraphConfigError):
            enforce_subgraph_ceiling(
                cfg, "write", _scope("search", "write")
            )

    def test_parent_ceiling_is_stricter_than_workflow_scope(self) -> None:
        arc = allow_all()
        outer = ArcGraphConfig(
            arc_client=arc, workflow_scope=_scope("search")
        )
        # The subgraph claims a broader workflow_scope, but its
        # parent_ceiling (propagated from outer) is narrower. The
        # effective ceiling is parent_ceiling.
        inner = ArcGraphConfig(
            arc_client=arc,
            workflow_scope=_scope("search", "write"),
            parent_ceiling=outer.effective_ceiling(),
        )
        # A node scope that fits under parent_ceiling but looks ok to
        # ``workflow_scope`` alone must still fail the ceiling check.
        with pytest.raises(ArcLangGraphConfigError):
            inner.register_node_scope("write", _scope("write"))
