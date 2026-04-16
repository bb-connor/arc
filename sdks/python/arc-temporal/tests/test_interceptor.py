"""Unit tests for ArcActivityInterceptor capability enforcement.

The tests exercise the inbound-interceptor path without a live
Temporal cluster: we build an :class:`ExecuteActivityInput`, construct
an :class:`activity.Info`, patch ``activity.info()`` to return it, and
invoke the ``_ArcInboundInterceptor.execute_activity`` directly.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from arc_sdk.models import (
    ArcScope,
    CapabilityToken,
    Operation,
    ToolGrant,
)
from arc_sdk.testing import (
    MockArcClient,
    MockVerdict,
    allow_all,
    deny_all,
)
from temporalio import activity
from temporalio.exceptions import ApplicationError

from arc_temporal import (
    ArcActivityInterceptor,
    WorkflowGrant,
)
from arc_temporal.interceptor import (
    DENIED_ERROR_TYPE,
    _ArcInboundInterceptor,
)

# ---------------------------------------------------------------------------
# Test doubles / helpers
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


def _default_info(
    *,
    activity_type: str,
    activity_id: str = "act-1",
    workflow_id: str = "wf-1",
    workflow_run_id: str = "run-1",
    attempt: int = 1,
) -> activity.Info:
    """Build a minimal :class:`activity.Info` for direct interceptor testing."""
    utc_zero = datetime.fromtimestamp(0, tz=UTC)
    # Temporal's Priority type is a dataclass on modern versions; we
    # replicate its default via an attribute shim that is attribute-
    # compatible enough for info construction. Falling back to
    # ``Priority.default`` keeps us aligned with upstream when present.
    import temporalio.common as temporal_common

    return activity.Info(
        activity_id=activity_id,
        activity_type=activity_type,
        attempt=attempt,
        current_attempt_scheduled_time=utc_zero,
        heartbeat_details=[],
        heartbeat_timeout=None,
        is_local=False,
        namespace="default",
        schedule_to_close_timeout=timedelta(seconds=10),
        scheduled_time=utc_zero,
        start_to_close_timeout=timedelta(seconds=10),
        started_time=utc_zero,
        task_queue="tq",
        task_token=b"tt",
        workflow_id=workflow_id,
        workflow_namespace="default",
        workflow_run_id=workflow_run_id,
        workflow_type="TestWorkflow",
        priority=temporal_common.Priority.default,
        retry_policy=None,
        activity_run_id=None,
    )


class _NextInterceptor:
    """Stand-in for the downstream :class:`ActivityInboundInterceptor`."""

    def __init__(self, result: Any = "ok") -> None:
        self.result = result
        self.called = False

    def init(self, outbound: Any) -> None:  # pragma: no cover -- unused
        pass

    async def execute_activity(self, input: Any) -> Any:
        self.called = True
        return self.result


@contextmanager
def _patched_activity_info(info: activity.Info):
    """Temporarily patch ``activity.info()`` to return ``info``."""
    original = activity.info
    activity.info = lambda: info  # type: ignore[assignment]
    try:
        yield
    finally:
        activity.info = original  # type: ignore[assignment]


def _make_input(*args: Any) -> Any:
    """Build an :class:`ExecuteActivityInput`-compatible object."""
    from temporalio.worker import ExecuteActivityInput

    async def _fn() -> None:  # pragma: no cover -- not invoked
        pass

    return ExecuteActivityInput(
        fn=_fn,
        args=list(args),
        executor=None,
        headers={},
    )


async def _mint_token(
    arc: MockArcClient,
    *,
    subject: str,
    scope: ArcScope,
) -> CapabilityToken:
    """Mint a capability via the mock and index it for policy lookups."""
    token = await arc.create_capability(subject=subject, scope=scope)
    store: dict[str, Any] = getattr(arc, "_tokens", {})
    store[token.id] = token
    arc._tokens = store  # type: ignore[attr-defined]
    return token


def _scope_aware_policy(arc: MockArcClient) -> Any:
    """Policy that enforces the scope bound to the capability_id."""

    def policy(
        tool_name: str,
        scope: dict[str, Any],
        context: dict[str, Any],
    ) -> MockVerdict:
        cap_id = context.get("capability_id")
        token = getattr(arc, "_tokens", {}).get(cap_id)
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


# ---------------------------------------------------------------------------
# (a) Allow verdict delegates to the next interceptor
# ---------------------------------------------------------------------------


class TestAllowVerdict:
    async def test_allow_runs_next_interceptor(self) -> None:
        async with allow_all() as arc:
            token = await _mint_token(
                arc,
                subject="agent:alice",
                scope=_scope_for_tools("send_email"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ArcActivityInterceptor(arc_client=arc)
            interceptor.register_workflow_grant(grant)

            next_interceptor = _NextInterceptor(result="delivered")
            inbound = _ArcInboundInterceptor(next_interceptor, interceptor)

            info = _default_info(activity_type="send_email")
            with _patched_activity_info(info):
                result = await inbound.execute_activity(_make_input("hi"))

        assert result == "delivered"
        assert next_interceptor.called

        receipt = interceptor.workflow_receipt("wf-1", "run-1")
        assert receipt is not None
        assert receipt.step_count == 1
        assert receipt.allow_count == 1
        assert receipt.deny_count == 0
        assert receipt.steps[0].activity_type == "send_email"
        assert receipt.steps[0].activity_id == "act-1"
        assert receipt.steps[0].receipt.is_allowed

    async def test_allow_respects_activity_tool_server_map(self) -> None:
        async with allow_all() as arc:
            token = await _mint_token(
                arc,
                subject="agent:alice",
                scope=_scope_for_tools("send_email", server_id="srv"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="unused",
            )
            interceptor = ArcActivityInterceptor(
                arc_client=arc,
                activity_tool_server_map={"send_email": "email-srv"},
            )
            interceptor.register_workflow_grant(grant)

            next_interceptor = _NextInterceptor()
            inbound = _ArcInboundInterceptor(next_interceptor, interceptor)

            info = _default_info(activity_type="send_email")
            with _patched_activity_info(info):
                await inbound.execute_activity(_make_input())

        evaluate_calls = [c for c in arc.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        assert evaluate_calls[0].tool_server == "email-srv"


# ---------------------------------------------------------------------------
# (b) Deny verdict raises non-retryable ApplicationError
# ---------------------------------------------------------------------------


class TestDenyVerdict:
    async def test_deny_raises_non_retryable_application_error(self) -> None:
        # raise_on_deny=False -> receipt-based deny path
        async with deny_all(raise_on_deny=False) as arc:
            token = await _mint_token(
                arc,
                subject="agent:alice",
                scope=_scope_for_tools("send_email"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ArcActivityInterceptor(arc_client=arc)
            interceptor.register_workflow_grant(grant)

            next_interceptor = _NextInterceptor()
            inbound = _ArcInboundInterceptor(next_interceptor, interceptor)

            info = _default_info(activity_type="send_email")
            with _patched_activity_info(info):
                with pytest.raises(ApplicationError) as exc_info:
                    await inbound.execute_activity(_make_input("payload"))

        err = exc_info.value
        assert err.non_retryable is True
        assert err.type == DENIED_ERROR_TYPE
        assert "ARC capability denied" in str(err)
        assert not next_interceptor.called

        # Deny receipt is recorded even though the activity did not run.
        receipt = interceptor.workflow_receipt("wf-1", "run-1")
        assert receipt is not None
        assert receipt.deny_count == 1
        assert receipt.allow_count == 0
        assert receipt.steps[0].receipt.is_denied

    async def test_deny_from_403_raises_non_retryable(self) -> None:
        # raise_on_deny=True -> mock raises ArcDeniedError that the
        # interceptor translates to a non-retryable ApplicationError.
        async with deny_all(reason="no write perms", guard="ScopeGuard") as arc:
            token = await _mint_token(
                arc,
                subject="agent:alice",
                scope=_scope_for_tools("send_email"),
            )
            grant = WorkflowGrant(
                workflow_id="wf-1",
                token=token,
                tool_server="srv",
            )
            interceptor = ArcActivityInterceptor(arc_client=arc)
            interceptor.register_workflow_grant(grant)

            inbound = _ArcInboundInterceptor(_NextInterceptor(), interceptor)
            info = _default_info(activity_type="send_email")
            with _patched_activity_info(info):
                with pytest.raises(ApplicationError) as exc_info:
                    await inbound.execute_activity(_make_input())

        err = exc_info.value
        assert err.non_retryable is True
        assert err.type == DENIED_ERROR_TYPE

    async def test_missing_workflow_grant_raises_config_error(self) -> None:
        """Activities with no registered grant must be refused before dispatch.

        :class:`ArcTemporalConfigError` is used so the failure is a
        configuration issue surfaced to the operator, not a kernel
        denial. Temporal's worker treats unhandled exceptions from an
        interceptor as a (retryable) activity failure unless they are
        :class:`ApplicationError`; callers that want non-retryable
        behaviour should raise from their own wiring.
        """
        from arc_temporal import ArcTemporalConfigError

        async with allow_all() as arc:
            interceptor = ArcActivityInterceptor(arc_client=arc)
            # Deliberately no register_workflow_grant.

            inbound = _ArcInboundInterceptor(_NextInterceptor(), interceptor)
            info = _default_info(activity_type="send_email", workflow_id="wf-missing")
            with _patched_activity_info(info):
                with pytest.raises(ArcTemporalConfigError):
                    await inbound.execute_activity(_make_input())


# ---------------------------------------------------------------------------
# (c) Attenuated activity-level grant enforcement
# ---------------------------------------------------------------------------


class TestAttenuatedGrant:
    async def test_activity_override_narrows_scope_and_is_enforced(self) -> None:
        arc = MockArcClient()
        arc.set_policy(_scope_aware_policy(arc))

        parent = await _mint_token(
            arc,
            subject="agent:parent",
            scope=_scope_for_tools("search", "write"),
        )
        parent_grant = WorkflowGrant(
            workflow_id="wf-1",
            token=parent,
            tool_server="srv",
        )

        # Child scope only authorises "search". Register it via the
        # override hook so the interceptor swaps it in for the
        # ``write`` activity type.
        child_scope = _scope_for_tools("search")
        child_grant = await parent_grant.attenuate_for_activity(
            arc, new_scope=child_scope
        )
        # Index child token for the policy.
        arc._tokens[child_grant.token.id] = child_grant.token  # type: ignore[attr-defined]

        interceptor = ArcActivityInterceptor(arc_client=arc)
        interceptor.register_workflow_grant(parent_grant)
        interceptor.register_activity_grant_override(
            "write", lambda _info: child_grant
        )

        inbound = _ArcInboundInterceptor(_NextInterceptor(), interceptor)

        # The ``write`` activity now runs under the attenuated grant
        # that does NOT include ``write`` -- must be denied.
        info = _default_info(activity_type="write", activity_id="act-write")
        with _patched_activity_info(info):
            with pytest.raises(ApplicationError) as exc_info:
                await inbound.execute_activity(_make_input("/tmp/x"))

        err = exc_info.value
        assert err.non_retryable is True
        assert err.type == DENIED_ERROR_TYPE

    async def test_attenuation_rejects_broader_scope(self) -> None:
        arc = MockArcClient()
        parent = await _mint_token(
            arc,
            subject="agent:parent",
            scope=_scope_for_tools("search"),
        )
        parent_grant = WorkflowGrant(
            workflow_id="wf-1",
            token=parent,
            tool_server="srv",
        )

        # Broader scope -- must raise ArcValidationError.
        from arc_sdk.errors import ArcValidationError

        broader = _scope_for_tools("search", "write")
        with pytest.raises(ArcValidationError):
            await parent_grant.attenuate_for_activity(arc, new_scope=broader)

    async def test_activity_override_rejects_scope_outside_parent(self) -> None:
        """Override hooks that return a non-subset grant must be refused.

        A hook that smuggles in a broader-than-workflow grant (e.g. by
        bypassing attenuate_for_activity) is caught by the interceptor's
        subset check before any evaluation occurs.
        """
        arc = MockArcClient()
        arc.set_policy(_scope_aware_policy(arc))

        parent = await _mint_token(
            arc,
            subject="agent:parent",
            scope=_scope_for_tools("search"),
        )
        parent_grant = WorkflowGrant(
            workflow_id="wf-1",
            token=parent,
            tool_server="srv",
        )

        # Craft a rogue grant whose scope exceeds the parent's. This
        # should never happen via attenuate_for_activity, but a buggy
        # hook could produce one.
        rogue_token = parent.model_copy(
            update={"scope": _scope_for_tools("search", "write")}
        )
        rogue_grant = WorkflowGrant(
            workflow_id="wf-1",
            token=rogue_token,
            tool_server="srv",
        )

        interceptor = ArcActivityInterceptor(arc_client=arc)
        interceptor.register_workflow_grant(parent_grant)
        interceptor.register_activity_grant_override(
            "write", lambda _info: rogue_grant
        )

        inbound = _ArcInboundInterceptor(_NextInterceptor(), interceptor)
        info = _default_info(activity_type="write")
        with _patched_activity_info(info):
            with pytest.raises(Exception) as exc_info:
                await inbound.execute_activity(_make_input())

        # ArcTemporalConfigError expected; not an ApplicationError.
        from arc_temporal import ArcTemporalConfigError

        assert isinstance(exc_info.value, ArcTemporalConfigError)
