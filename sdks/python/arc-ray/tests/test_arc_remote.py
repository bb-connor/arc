"""Unit tests for :func:`arc_ray.arc_remote`.

These tests drive the decorator against a :class:`arc_sdk.testing.MockArcClient`
so every allow/deny path exercises the real sidecar-evaluation plumbing
without needing a live ARC kernel. Ray's scheduler is replaced by a
lightweight fake (see ``conftest.py``) that calls the wrapped function
in-process on ``.remote(...)``; the ARC behaviour we are asserting is
identical in the real cluster, but the fake keeps the suite fast and
deterministic.
"""

from __future__ import annotations

from typing import Any

import pytest
import ray
from arc_sdk.models import ArcScope, Operation, ToolGrant
from arc_sdk.testing import MockArcClient, MockVerdict, allow_all, deny_all

from arc_ray import ArcRayConfigError, ArcRayError, arc_remote

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# (a) Allow path -- wrapped task runs and returns its value through ray.get.
# ---------------------------------------------------------------------------


class TestAllowPath:
    def test_sync_remote_runs_under_allow_verdict(self) -> None:
        arc = allow_all()

        @arc_remote(
            scope="tools:search",
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        def search(query: str) -> list[str]:
            return [f"hit:{query}"]

        ref = search.remote("hello")
        assert ray.get(ref) == ["hit:hello"]

        # One evaluation recorded on the mock client.
        eval_calls = [c for c in arc.calls if c.method == "evaluate_tool_call"]
        assert len(eval_calls) == 1
        assert eval_calls[0].tool_name == "search"
        assert eval_calls[0].capability_id == "cap-1"
        assert eval_calls[0].tool_server == "srv"
        # Positional and keyword arguments flow through to the sidecar
        # payload so deterministic parameter hashing works.
        assert eval_calls[0].parameters == {
            "args": ["hello"],
            "kwargs": {},
        }

    def test_async_remote_runs_under_allow_verdict(self) -> None:
        arc = allow_all()

        @arc_remote(
            scope="tools:search",
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        async def search(query: str) -> list[str]:
            return [f"async:{query}"]

        ref = search.remote("hi")
        assert ray.get(ref) == ["async:hi"]

    def test_decorator_metadata_preserved(self) -> None:
        arc = allow_all()

        @arc_remote(
            scope="tools:search",
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
            tool_name="custom_search",
        )
        def search(query: str) -> str:
            return query

        # Short-spec is preserved alongside the fully-formed scope so
        # tooling can render the human-friendly string.
        assert search._arc_scope_spec == "tools:search"
        assert isinstance(search._arc_scope, ArcScope)
        assert search._arc_capability_id == "cap-1"
        assert search._arc_tool_name == "custom_search"


# ---------------------------------------------------------------------------
# (b) Deny path -- wrapped task raises PermissionError through ray.get.
# ---------------------------------------------------------------------------


class TestDenyPath:
    def test_deny_raises_permission_error_via_ray_get(self) -> None:
        arc = deny_all(reason="out of scope", guard="ScopeGuard")

        def _body(q: str) -> str:
            pytest.fail("body must not run on deny")
            return ""

        decorated = arc_remote(
            scope="tools:search",
            capability_id="cap-x",
            tool_server="srv",
            arc_client=arc,
        )(_body)

        ref = decorated.remote("hello")
        with pytest.raises(PermissionError) as exc_info:
            ray.get(ref)

        assert "ARC capability denied" in str(exc_info.value)
        inner: ArcRayError = exc_info.value.arc_error  # type: ignore[attr-defined]
        assert inner.tool_server == "srv"
        assert inner.guard == "ScopeGuard"
        assert "out of scope" in (inner.reason or "")

    def test_deny_from_receipt_path_raises_permission_error(self) -> None:
        """``raise_on_deny=False`` -- the sidecar returns a deny receipt."""
        arc = deny_all(
            reason="not allowed",
            guard="ScopeGuard",
            raise_on_deny=False,
        )

        @arc_remote(
            scope="tools:search",
            capability_id="cap-x",
            tool_server="srv",
            arc_client=arc,
        )
        def search(q: str) -> str:
            pytest.fail("body must not run on deny")
            return ""

        ref = search.remote("hi")
        with pytest.raises(PermissionError) as exc_info:
            ray.get(ref)

        inner: ArcRayError = exc_info.value.arc_error  # type: ignore[attr-defined]
        assert inner.receipt_id is not None
        assert inner.guard == "ScopeGuard"
        assert inner.reason == "not allowed"

    def test_missing_capability_id_is_config_error(self) -> None:
        arc = allow_all()

        with pytest.raises(ArcRayConfigError):

            @arc_remote(
                scope="tools:search",
                capability_id="",
                tool_server="srv",
                arc_client=arc,
            )
            def search(q: str) -> str:
                return q


# ---------------------------------------------------------------------------
# (c) Scope-aware policy -- allow some tools, deny others via capability id.
# ---------------------------------------------------------------------------


class TestScopeAwarePolicy:
    def test_policy_allows_in_scope_denies_out_of_scope(self) -> None:
        arc = MockArcClient()
        # Policy: allow anything whose ``tool_name`` matches the
        # capability ``cap-search``'s authorised tools, deny otherwise.
        allowed_tools = {"cap-search": {"search", "browse"}}

        def policy(
            tool_name: str,
            _scope: dict[str, Any],
            context: dict[str, Any],
        ) -> MockVerdict:
            cap_id = context.get("capability_id")
            allowed = allowed_tools.get(cap_id or "", set())
            if tool_name in allowed:
                return MockVerdict.allow_verdict()
            return MockVerdict.deny_verdict(
                f"tool {tool_name!r} not in capability {cap_id!r}",
                guard="ScopeGuard",
            )

        arc.set_policy(policy)

        @arc_remote(
            scope="tools:search",
            capability_id="cap-search",
            tool_server="srv",
            arc_client=arc,
        )
        def search(q: str) -> str:
            return f"result:{q}"

        @arc_remote(
            scope="tools:write",
            capability_id="cap-search",
            tool_server="srv",
            arc_client=arc,
        )
        def write(path: str) -> str:
            pytest.fail("write must not run for cap-search")
            return ""

        # In-scope call allowed.
        assert ray.get(search.remote("alpha")) == "result:alpha"

        # Out-of-scope call denied.
        with pytest.raises(PermissionError):
            ray.get(write.remote("/tmp/x"))
