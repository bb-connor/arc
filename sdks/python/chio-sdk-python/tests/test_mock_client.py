"""Tests for :mod:`chio_sdk.testing`.

These tests demonstrate that ``MockChioClient`` and its factory helpers work
without a running Chio sidecar: every assertion below is in-process. If you
see any outbound network call during collection, that is a bug.
"""

from __future__ import annotations

import pytest

from chio_sdk.errors import ChioDeniedError, ChioValidationError
from chio_sdk.models import (
    ChioScope,
    CallerIdentity,
    GuardEvidence,
    Operation,
    ToolGrant,
)
from chio_sdk.testing import (
    MockChioClient,
    MockVerdict,
    RecordedCall,
    allow_all,
    deny_all,
    with_policy,
)


# ---------------------------------------------------------------------------
# Package-level exports
# ---------------------------------------------------------------------------


def test_public_exports_are_importable() -> None:
    """``from chio_sdk.testing import ...`` works for all documented names."""

    # All imports above succeeded, this just pins them down.
    assert MockChioClient is not None
    assert callable(allow_all)
    assert callable(deny_all)
    assert callable(with_policy)
    assert RecordedCall is not None
    assert MockVerdict is not None


def test_top_level_chio_sdk_reexports_testing_symbols() -> None:
    """The testing helpers are also available via ``chio_sdk``."""

    import chio_sdk

    assert chio_sdk.MockChioClient is MockChioClient
    assert chio_sdk.allow_all is allow_all
    assert chio_sdk.deny_all is deny_all
    assert chio_sdk.with_policy is with_policy


# ---------------------------------------------------------------------------
# allow_all()
# ---------------------------------------------------------------------------


async def test_allow_all_permits_every_tool_call() -> None:
    async with allow_all() as arc:
        receipt = await arc.evaluate_tool_call(
            capability_id="cap-1",
            tool_server="srv",
            tool_name="read",
            parameters={"path": "/tmp"},
        )
    assert receipt.is_allowed
    assert receipt.decision.verdict == "allow"
    assert receipt.tool_name == "read"


async def test_allow_all_permits_http_request() -> None:
    async with allow_all() as arc:
        result = await arc.evaluate_http_request(
            request_id="req-1",
            method="GET",
            route_pattern="/pets/{petId}",
            path="/pets/42",
            caller=CallerIdentity.anonymous(),
        )
    assert result.verdict.is_allowed
    assert result.receipt.response_status == 200


# ---------------------------------------------------------------------------
# deny_all()
# ---------------------------------------------------------------------------


async def test_deny_all_raises_chio_denied_error() -> None:
    arc = deny_all(reason="session is read-only", guard="ReadOnlyGuard")
    with pytest.raises(ChioDeniedError) as exc_info:
        await arc.evaluate_tool_call(
            capability_id="cap-1",
            tool_server="srv",
            tool_name="write",
            parameters={"data": "x"},
        )
    err = exc_info.value
    assert err.code == "DENIED"
    assert err.guard == "ReadOnlyGuard"
    assert err.reason == "session is read-only"
    assert "session is read-only" in str(err)


async def test_deny_all_returns_deny_receipt_when_not_raising() -> None:
    arc = deny_all(raise_on_deny=False)
    receipt = await arc.evaluate_tool_call(
        capability_id="cap-1",
        tool_server="srv",
        tool_name="write",
        parameters={},
    )
    assert receipt.is_denied
    assert receipt.decision.verdict == "deny"
    assert receipt.decision.reason


async def test_deny_all_blocks_http_request() -> None:
    arc = deny_all(reason="nope", guard="HttpGuard")
    with pytest.raises(ChioDeniedError) as exc_info:
        await arc.evaluate_http_request(
            request_id="req-1",
            method="POST",
            route_pattern="/pets",
            path="/pets",
            caller=CallerIdentity.anonymous(),
        )
    assert exc_info.value.guard == "HttpGuard"


# ---------------------------------------------------------------------------
# with_policy() -- callable form
# ---------------------------------------------------------------------------


async def test_with_policy_callable_applies_allow_deny_rules() -> None:
    def policy(
        tool_name: str,
        _scope: dict,
        _ctx: dict,
    ) -> MockVerdict:
        if tool_name == "read":
            return MockVerdict.allow_verdict()
        return MockVerdict.deny_verdict(
            f"tool '{tool_name}' not permitted",
            guard="TestGuard",
        )

    arc = with_policy(policy)

    allowed = await arc.evaluate_tool_call(
        capability_id="cap-1",
        tool_server="srv",
        tool_name="read",
        parameters={},
    )
    assert allowed.is_allowed

    with pytest.raises(ChioDeniedError) as exc_info:
        await arc.evaluate_tool_call(
            capability_id="cap-1",
            tool_server="srv",
            tool_name="write",
            parameters={},
        )
    assert exc_info.value.guard == "TestGuard"
    assert "write" in (exc_info.value.reason or "")


async def test_with_policy_callable_accepts_bool_shorthand() -> None:
    arc = with_policy(lambda tool, _s, _c: tool == "ok")
    allowed = await arc.evaluate_tool_call(
        capability_id="cap-1",
        tool_server="srv",
        tool_name="ok",
        parameters={},
    )
    assert allowed.is_allowed
    with pytest.raises(ChioDeniedError):
        await arc.evaluate_tool_call(
            capability_id="cap-1",
            tool_server="srv",
            tool_name="nope",
            parameters={},
        )


# ---------------------------------------------------------------------------
# with_policy() -- dict spec form
# ---------------------------------------------------------------------------


async def test_with_policy_dict_default_deny() -> None:
    arc = with_policy({"default": "deny", "allow": ["read", "list"]})
    ok = await arc.evaluate_tool_call(
        capability_id="cap-1",
        tool_server="srv",
        tool_name="read",
        parameters={},
    )
    assert ok.is_allowed

    with pytest.raises(ChioDeniedError) as exc_info:
        await arc.evaluate_tool_call(
            capability_id="cap-1",
            tool_server="srv",
            tool_name="write",
            parameters={},
        )
    assert "not in allow list" in (exc_info.value.reason or "")


async def test_with_policy_dict_deny_takes_precedence() -> None:
    arc = with_policy(
        {
            "default": "allow",
            "deny": {"write": "read-only session"},
        },
    )
    with pytest.raises(ChioDeniedError) as exc_info:
        await arc.evaluate_tool_call(
            capability_id="cap-1",
            tool_server="srv",
            tool_name="write",
            parameters={},
        )
    assert exc_info.value.reason == "read-only session"


def test_with_policy_rejects_invalid_spec() -> None:
    with pytest.raises(ChioValidationError):
        with_policy(123)  # type: ignore[arg-type]


def test_with_policy_rejects_invalid_default() -> None:
    with pytest.raises(ChioValidationError):
        with_policy({"default": "maybe"})


# ---------------------------------------------------------------------------
# Call history tracking
# ---------------------------------------------------------------------------


async def test_call_history_records_each_evaluation() -> None:
    arc = allow_all()
    await arc.evaluate_tool_call(
        capability_id="cap-1",
        tool_server="srv",
        tool_name="read",
        parameters={"path": "/etc"},
    )
    await arc.evaluate_tool_call(
        capability_id="cap-1",
        tool_server="srv",
        tool_name="list",
        parameters={"prefix": "/etc"},
    )

    assert len(arc.calls) == 2
    assert [c.tool_name for c in arc.calls] == ["read", "list"]

    read_calls = arc.calls_for("read")
    assert len(read_calls) == 1
    call = read_calls[0]
    assert call.method == "evaluate_tool_call"
    assert call.tool_server == "srv"
    assert call.capability_id == "cap-1"
    assert call.parameters == {"path": "/etc"}
    assert call.verdict is not None
    assert call.verdict.allow is True


async def test_call_history_records_denies_too() -> None:
    arc = deny_all(reason="no")
    with pytest.raises(ChioDeniedError):
        await arc.evaluate_tool_call(
            capability_id="cap-1",
            tool_server="srv",
            tool_name="write",
            parameters={},
        )
    assert len(arc.calls) == 1
    recorded = arc.calls[0]
    assert recorded.tool_name == "write"
    assert recorded.verdict is not None
    assert recorded.verdict.allow is False
    assert recorded.verdict.reason == "no"


async def test_reset_clears_history() -> None:
    arc = allow_all()
    await arc.health()
    assert arc.calls
    arc.reset()
    assert arc.calls == []


# ---------------------------------------------------------------------------
# Other public surface smoke tests
# ---------------------------------------------------------------------------


async def test_lifecycle_tracks_closed_flag() -> None:
    arc = allow_all()
    assert not arc.closed
    async with arc as ctx:
        assert ctx is arc
    assert arc.closed


async def test_create_and_validate_capability_round_trip() -> None:
    arc = allow_all()
    scope = ChioScope(
        grants=[
            ToolGrant(
                server_id="srv",
                tool_name="read",
                operations=[Operation.INVOKE],
            )
        ]
    )
    token = await arc.create_capability(subject="bb", scope=scope)
    assert token.id.startswith("mock-tok-")
    assert await arc.validate_capability(token) is True


async def test_attenuate_capability_rejects_superset() -> None:
    arc = allow_all()
    scope = ChioScope(
        grants=[
            ToolGrant(
                server_id="srv",
                tool_name="read",
                operations=[Operation.INVOKE],
            )
        ]
    )
    token = await arc.create_capability(subject="bb", scope=scope)
    wider = ChioScope(
        grants=[
            ToolGrant(
                server_id="srv",
                tool_name="write",
                operations=[Operation.INVOKE],
            )
        ]
    )
    with pytest.raises(ChioValidationError):
        await arc.attenuate_capability(token, new_scope=wider)


async def test_set_policy_swaps_behaviour_midstream() -> None:
    arc = MockChioClient()
    first = await arc.evaluate_tool_call(
        capability_id="cap-1",
        tool_server="srv",
        tool_name="read",
        parameters={},
    )
    assert first.is_allowed

    arc.set_policy(
        lambda _t, _s, _c: MockVerdict.deny_verdict("now denied")
    )
    with pytest.raises(ChioDeniedError) as exc_info:
        await arc.evaluate_tool_call(
            capability_id="cap-1",
            tool_server="srv",
            tool_name="read",
            parameters={},
        )
    assert exc_info.value.reason == "now denied"


async def test_evidence_flows_through_to_receipt() -> None:
    evidence = (
        GuardEvidence(guard_name="MockGuard", verdict=True, details="ok"),
    )

    def policy(_t: str, _s: dict, _c: dict) -> MockVerdict:
        return MockVerdict(
            allow=True, guard="MockGuard", evidence=evidence
        )

    arc = with_policy(policy)
    receipt = await arc.evaluate_tool_call(
        capability_id="cap-1",
        tool_server="srv",
        tool_name="read",
        parameters={},
    )
    assert len(receipt.evidence) == 1
    assert receipt.evidence[0].guard_name == "MockGuard"
