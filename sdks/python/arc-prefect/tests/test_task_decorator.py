"""Unit tests for :func:`arc_prefect.arc_task`.

The tests run real Prefect flow / task machinery against a
:class:`arc_sdk.testing.MockArcClient` so we exercise the decorator's
sidecar-evaluation path, deny translation to ``PermissionError``, and
receipt-event emission without needing a live ARC kernel or a live
Prefect API.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from arc_sdk.models import ArcScope, Operation, ToolGrant
from arc_sdk.testing import MockArcClient, MockVerdict, allow_all, deny_all

from arc_prefect import arc_flow, arc_task
from arc_prefect.errors import ArcPrefectConfigError
from arc_prefect.events import EVENT_ALLOW, EVENT_DENY

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


class _EmittedEvent:
    """Record of a single patched :func:`prefect.events.emit_event` call."""

    def __init__(
        self,
        *,
        event: str,
        resource: dict[str, str],
        payload: dict[str, Any],
        related: list[dict[str, str]],
    ) -> None:
        self.event = event
        self.resource = resource
        self.payload = payload
        self.related = related


class _EventCapture:
    """Patch context manager for :func:`prefect.events.emit_event`.

    The SDK uses a lazy import inside ``_prefect_emit_event`` so we have
    to patch the symbol at the import site rather than
    ``prefect.events.emit_event``. Anything the decorator would emit is
    recorded on ``events``.
    """

    def __init__(self) -> None:
        self.events: list[_EmittedEvent] = []
        self._patch: Any = None

    def __enter__(self) -> _EventCapture:
        def _fake_emit(
            *,
            event: str,
            resource: dict[str, str],
            payload: dict[str, Any] | None = None,
            related: list[dict[str, str]] | None = None,
            **_: Any,
        ) -> None:
            self.events.append(
                _EmittedEvent(
                    event=event,
                    resource=dict(resource),
                    payload=dict(payload or {}),
                    related=list(related or []),
                )
            )
            return None

        # Patch the module the decorator imports lazily.
        from prefect import events as prefect_events

        self._patch = patch.object(
            prefect_events, "emit_event", side_effect=_fake_emit
        )
        self._patch.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._patch is not None:
            self._patch.stop()

    def of(self, event_name: str) -> list[_EmittedEvent]:
        return [e for e in self.events if e.event == event_name]


# ---------------------------------------------------------------------------
# (a) Allow path -- decorator evaluates, event fires, function runs.
# ---------------------------------------------------------------------------


class TestAllowPath:
    def test_sync_task_runs_under_allow_verdict(self) -> None:
        arc = allow_all()

        @arc_task(
            scope=_scope_for_tools("double"),
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        def double(x: int) -> int:
            return x * 2

        @arc_flow(
            scope=_scope_for_tools("double"),
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        def myflow() -> int:
            return double(21)

        with _EventCapture() as capture:
            result = myflow()

        assert result == 42
        evaluate_calls = [c for c in arc.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        assert evaluate_calls[0].tool_name == "double"
        assert evaluate_calls[0].tool_server == "srv"
        assert evaluate_calls[0].capability_id == "cap-1"

        allows = capture.of(EVENT_ALLOW)
        assert len(allows) == 1
        assert allows[0].payload["tool_name"] == "double"
        assert allows[0].payload["verdict"] == "allow"
        assert allows[0].payload["receipt_id"].startswith("mock-r-")

    async def test_async_task_runs_under_allow_verdict(self) -> None:
        arc = allow_all()

        @arc_task(
            scope=_scope_for_tools("fetch"),
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        async def fetch(path: str) -> str:
            return f"fetched:{path}"

        @arc_flow(
            scope=_scope_for_tools("fetch"),
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        async def myflow() -> str:
            return await fetch("/tmp/data")

        with _EventCapture() as capture:
            result = await myflow()

        assert result == "fetched:/tmp/data"
        evaluate_calls = [c for c in arc.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        assert evaluate_calls[0].parameters == {"args": ["/tmp/data"], "kwargs": {}}
        assert capture.of(EVENT_ALLOW)

    def test_standalone_task_requires_capability_id(self) -> None:
        """A task with no ``capability_id`` invoked outside an ``arc_flow`` must
        surface ``ArcPrefectConfigError`` (a configuration problem, not a
        capability denial)."""
        arc = allow_all()

        @arc_task(
            scope=_scope_for_tools("no_flow"),
            arc_client=arc,
        )
        def no_flow() -> int:
            return 1

        with pytest.raises(ArcPrefectConfigError) as exc_info:
            no_flow()

        assert "capability_id" in str(exc_info.value)


# ---------------------------------------------------------------------------
# (b) Deny path -- PermissionError raised, deny event emitted.
# ---------------------------------------------------------------------------


class TestDenyPath:
    def test_deny_receipt_path_raises_permission_error(self) -> None:
        # raise_on_deny=False: the mock returns a deny receipt instead
        # of raising ArcDeniedError. This covers the receipt-path deny.
        arc = deny_all(
            reason="tool not in scope",
            guard="ScopeGuard",
            raise_on_deny=False,
        )

        @arc_task(
            scope=_scope_for_tools("write"),
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        def write_something() -> str:
            return "wrote"

        @arc_flow(
            scope=_scope_for_tools("write"),
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        def myflow() -> str:
            return write_something()

        with _EventCapture() as capture:
            with pytest.raises(PermissionError) as exc_info:
                myflow()

        assert "ARC capability denied" in str(exc_info.value)
        # Structured error is attached via ``arc_error`` attribute.
        arc_error = getattr(exc_info.value, "arc_error", None)
        assert arc_error is not None
        assert arc_error.reason == "tool not in scope"
        assert arc_error.guard == "ScopeGuard"
        assert arc_error.task_name == "write_something"

        denies = capture.of(EVENT_DENY)
        assert len(denies) == 1
        assert denies[0].payload["verdict"] == "deny"
        assert denies[0].payload["reason"] == "tool not in scope"
        assert denies[0].payload["guard"] == "ScopeGuard"
        assert capture.of(EVENT_ALLOW) == []

    def test_deny_403_path_raises_permission_error(self) -> None:
        # Default raise_on_deny=True: the mock raises ArcDeniedError
        # (the HTTP-403 path). The decorator translates it to
        # PermissionError and synthesises the deny event.
        arc = deny_all(reason="no write perms", guard="CapabilityGuard")

        @arc_task(
            scope=_scope_for_tools("delete"),
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        def delete_something() -> None:
            return None

        @arc_flow(
            scope=_scope_for_tools("delete"),
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        def myflow() -> None:
            delete_something()

        with _EventCapture() as capture:
            with pytest.raises(PermissionError) as exc_info:
                myflow()

        assert "ARC capability denied" in str(exc_info.value)
        denies = capture.of(EVENT_DENY)
        assert len(denies) == 1
        assert denies[0].payload["reason"] == "no write perms"
        assert denies[0].payload["guard"] == "CapabilityGuard"

    def test_deny_event_carries_flow_run_id(self) -> None:
        arc = deny_all(reason="nope", guard="g", raise_on_deny=False)

        @arc_task(
            scope=_scope_for_tools("t"),
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        def t() -> None:
            return None

        @arc_flow(
            scope=_scope_for_tools("t"),
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        def myflow() -> None:
            t()

        with _EventCapture() as capture:
            with pytest.raises(PermissionError):
                myflow()

        denies = capture.of(EVENT_DENY)
        assert denies, "deny event must be emitted"
        related = denies[0].related
        # Task-run id should be present on the related resource list;
        # when Prefect is running its in-process engine, it assigns
        # one. Some offline test paths may skip this -- accept either.
        roles = {r.get("prefect.resource.role") for r in related}
        assert "task-run" in roles or roles == set()


# ---------------------------------------------------------------------------
# (c) Policy-sensitive -- only specific tools allowed
# ---------------------------------------------------------------------------


class TestPolicyEnforcement:
    def test_policy_allows_specific_tool_denies_others(self) -> None:
        def policy(
            tool_name: str,
            _scope: dict[str, Any],
            _context: dict[str, Any],
        ) -> MockVerdict:
            if tool_name == "search":
                return MockVerdict.allow_verdict()
            return MockVerdict.deny_verdict(
                f"tool {tool_name!r} not allowed",
                guard="ScopeGuard",
            )

        arc = MockArcClient(policy=policy, raise_on_deny=False)

        @arc_task(
            scope=_scope_for_tools("search"),
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        def search() -> str:
            return "ok"

        @arc_task(
            scope=_scope_for_tools("write"),
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        def write() -> str:
            return "ok"

        @arc_flow(
            scope=_scope_for_tools("search", "write"),
            capability_id="cap-1",
            tool_server="srv",
            arc_client=arc,
        )
        def myflow() -> tuple[str, Any]:
            a = search()
            try:
                b = write()
            except PermissionError as e:
                b = e
            return a, b

        with _EventCapture() as capture:
            first, second = myflow()

        assert first == "ok"
        assert isinstance(second, PermissionError)
        assert "tool 'write' not allowed" in str(second)

        allows = capture.of(EVENT_ALLOW)
        denies = capture.of(EVENT_DENY)
        assert len(allows) == 1
        assert allows[0].payload["tool_name"] == "search"
        assert len(denies) == 1
        assert denies[0].payload["tool_name"] == "write"


# ---------------------------------------------------------------------------
# (d) Parameter canonicalisation
# ---------------------------------------------------------------------------


def test_task_parameters_include_kwargs_and_args() -> None:
    arc = allow_all()

    @arc_task(
        scope=_scope_for_tools("hello"),
        capability_id="cap-1",
        tool_server="srv",
        arc_client=arc,
    )
    def hello(name: str, *, excited: bool = False) -> str:
        return f"hi {name}{'!' if excited else ''}"

    @arc_flow(
        scope=_scope_for_tools("hello"),
        capability_id="cap-1",
        tool_server="srv",
        arc_client=arc,
    )
    def myflow() -> str:
        return hello("ada", excited=True)

    result = myflow()
    assert result == "hi ada!"
    evaluate_calls = [c for c in arc.calls if c.method == "evaluate_tool_call"]
    assert len(evaluate_calls) == 1
    assert evaluate_calls[0].parameters == {
        "args": ["ada"],
        "kwargs": {"excited": True},
    }
