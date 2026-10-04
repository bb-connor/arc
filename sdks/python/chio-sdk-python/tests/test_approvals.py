"""Tests for HITL approval methods on ChioClient."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioValidationError
from chio_sdk.models_approvals import (
    ApprovalVerdict,
    PendingApproval,
)

BASE = "http://127.0.0.1:9090"


@pytest.mark.asyncio
async def test_mock_rejects_id_only_approval_submission():
    from chio_sdk.testing import MockChioClient

    client = MockChioClient()
    with pytest.raises(ChioValidationError, match="a full signed capability is required"):
        await client.submit_for_approval(
            capability_id="cap-1", tool_name="run_command", tool_args={}
        )
    assert await client.list_pending_approvals() == []


@pytest.mark.asyncio
async def test_mock_rejects_unsigned_approval_without_resolving_pending():
    from chio_sdk.testing import MockChioClient

    client = MockChioClient()
    client._pending_approvals = {"ap-1": _pending_dict()}
    with pytest.raises(ChioValidationError, match="an approver-signed token is required"):
        await client.respond_approval("ap-1", "approve")
    assert (await client.get_approval("ap-1")).pending is not None


def _signed_vote(outcome: str = "approved") -> dict:
    return {
        "id": "vote-1", "approver": "aa" * 32, "subject": "bb" * 32,
        "request_id": "ap-1", "governed_intent_hash": "cc" * 32,
        "issued_at": 1, "expires_at": 301, "decision": outcome,
        "signature": "dd" * 64,
    }


def _signed_capability() -> dict:
    return {
        "id": "cap-1", "subject": "bb" * 32, "issuer": "ee" * 32,
        "issued_at": 1, "expires_at": 601, "scope": {"grants": []},
        "signature": "ff" * 64,
    }


def _pending_dict(approval_id: str = "ap-1") -> dict:
    return {
        "approval_id": approval_id,
        "policy_id": "policy-hermes-hitl",
        "subject_id": "00" * 32,
        "capability_id": "cap-1",
        "tool_server": "shell",
        "tool_name": "run_command",
        "action": "invoke",
        "parameter_hash": "a" * 64,
        "expires_at": 4_000_000_000,
        "created_at": 100,
        "summary": "rm -rf old_build",
        "triggered_by": ["shell.requires_approval"],
    }


@pytest.mark.asyncio
@respx.mock
async def test_list_pending_approvals_parses_array_payload():
    respx.get(f"{BASE}/approvals/pending").mock(
        return_value=httpx.Response(
            200,
            json={"approvals": [_pending_dict("ap-1"), _pending_dict("ap-2")], "count": 2},
        )
    )
    client = ChioClient(BASE)
    rows = await client.list_pending_approvals()
    await client.close()
    assert len(rows) == 2
    assert all(isinstance(row, PendingApproval) for row in rows)
    assert rows[0].approval_id == "ap-1"
    assert rows[1].tool_server == "shell"


@pytest.mark.asyncio
@respx.mock
async def test_list_pending_approvals_tolerates_bare_list():
    respx.get(f"{BASE}/approvals/pending").mock(
        return_value=httpx.Response(200, json=[_pending_dict("ap-9")])
    )
    client = ChioClient(BASE)
    rows = await client.list_pending_approvals()
    await client.close()
    assert len(rows) == 1
    assert rows[0].approval_id == "ap-9"


@pytest.mark.asyncio
@respx.mock
async def test_get_approval_returns_either_pending_or_resolution():
    respx.get(f"{BASE}/approvals/ap-1").mock(
        return_value=httpx.Response(
            200,
            json={
                "pending": _pending_dict("ap-1"),
                "resolution": None,
            },
        )
    )
    client = ChioClient(BASE)
    approval = await client.get_approval("ap-1")
    await client.close()
    assert approval.pending is not None
    assert approval.pending.approval_id == "ap-1"
    assert approval.resolution is None


@pytest.mark.asyncio
async def test_get_approval_rejects_empty_id():
    client = ChioClient(BASE)
    with pytest.raises(ChioValidationError):
        await client.get_approval("")
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_respond_approval_posts_signed_token_with_string_verdict():
    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "approval_id": "ap-1",
                "outcome": "approved",
                "resolved_at": 4242,
            },
        )

    respx.post(f"{BASE}/approvals/ap-1/respond").mock(side_effect=_handler)
    client = ChioClient(BASE)
    response = await client.respond_approval("ap-1", "approve", reason="ok", signed_token=_signed_vote())
    await client.close()

    assert captured["url"].endswith("/approvals/ap-1/respond")
    assert captured["body"] == {"outcome": "approved", "reason": "ok",
                                 "approver": "aa" * 32, "token": _signed_vote()}
    assert response.outcome is ApprovalVerdict.APPROVED
    assert response.resolved_at == 4242


@pytest.mark.asyncio
@respx.mock
async def test_respond_approval_accepts_enum_verdict():
    respx.post(f"{BASE}/approvals/ap-1/respond").mock(
        return_value=httpx.Response(
            200,
            json={
                "approval_id": "ap-1",
                "outcome": "denied",
                "resolved_at": 1,
            },
        )
    )
    client = ChioClient(BASE)
    response = await client.respond_approval("ap-1", ApprovalVerdict.DENIED, signed_token=_signed_vote("denied"))
    await client.close()
    assert response.outcome is ApprovalVerdict.DENIED


@pytest.mark.asyncio
async def test_respond_approval_rejects_unknown_verdict_string():
    client = ChioClient(BASE)
    with pytest.raises(ValueError):
        await client.respond_approval("ap-1", "maybe")
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_submit_for_approval_sends_full_arguments_and_signed_capability():
    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            201,
            json={
                "approval_id": "ap-new-1",
                "expires_at": 4_000_000_000,
                "created_at": 100,
                "trusted_approvers": ["aa" * 32],
            },
        )

    respx.post(f"{BASE}/approvals/submit").mock(side_effect=_handler)
    client = ChioClient(BASE)
    args = {"command": "rm -rf old_build"}
    approval_id = await client.submit_for_approval(
        capability=_signed_capability(),
        tool_name="run_command",
        tool_args=args,
        requested_by="bb" * 32,
        ttl_seconds=600,
        triggered_by=["shell.requires_approval"],
    )
    await client.close()

    assert approval_id == "ap-new-1"
    body = captured["body"]
    assert body["capability"] == _signed_capability()
    assert body["tool_server"] == "shell"
    assert body["tool_name"] == "run_command"
    assert body["parameters"] == {"command": "rm -rf old_build"}
    assert "parameter_hash" not in body
    assert body["requested_by"] == "bb" * 32
    assert body["ttl_seconds"] == 600
    assert body["triggered_by"] == ["shell.requires_approval"]


@pytest.mark.asyncio
async def test_submit_for_approval_rejects_missing_capability():
    client = ChioClient(BASE)
    with pytest.raises(ChioValidationError):
        await client.submit_for_approval(
            capability_id="",
            tool_name="run_command",
            tool_args={"command": "ls"},
        )
    await client.close()


@pytest.mark.asyncio
async def test_submit_for_approval_rejects_missing_tool_name():
    client = ChioClient(BASE)
    with pytest.raises(ChioValidationError):
        await client.submit_for_approval(
            capability_id="cap-1",
            tool_name="",
            tool_args={"command": "ls"},
        )
    await client.close()


def test_approval_verdict_from_action_normalisation():
    assert ApprovalVerdict.from_action("approve") is ApprovalVerdict.APPROVED
    assert ApprovalVerdict.from_action("Approved") is ApprovalVerdict.APPROVED
    assert ApprovalVerdict.from_action("allow") is ApprovalVerdict.APPROVED
    assert ApprovalVerdict.from_action("deny") is ApprovalVerdict.DENIED
    assert ApprovalVerdict.from_action("REJECT") is ApprovalVerdict.DENIED
    with pytest.raises(ValueError):
        ApprovalVerdict.from_action("something-else")


@pytest.mark.asyncio
@respx.mock
async def test_ap23_submit_requires_full_signed_capability():
    route = respx.post(f"{BASE}/approvals/submit").mock(
        return_value=httpx.Response(201, json={
            "approval_id": "ap-1", "expires_at": 3600, "created_at": 1,
            "trusted_approvers": [],
        })
    )
    async with ChioClient(BASE) as client:
        with pytest.raises(ChioValidationError):
            await client.submit_for_approval(
                capability_id="cap-1", tool_name="effect", tool_args={"value": "A"},
                requested_by="ab" * 32,
            )
    assert not route.called


@pytest.mark.asyncio
@respx.mock
async def test_ap23_respond_requires_approver_signed_token():
    route = respx.post(f"{BASE}/approvals/ap-1/respond").mock(
        return_value=httpx.Response(200, json={
            "approval_id": "ap-1", "outcome": "approved", "resolved_at": 1,
        })
    )
    async with ChioClient(BASE) as client:
        with pytest.raises(ChioValidationError):
            await client.respond_approval("ap-1", "approve")
    assert not route.called


@pytest.mark.asyncio
@respx.mock
async def test_configured_control_bearer_authenticates_approval_workflow_only():
    seen: dict[str, str | None] = {}

    def record(payload):
        def handler(request: httpx.Request) -> httpx.Response:
            seen[request.url.path] = request.headers.get("authorization")
            return httpx.Response(200, json=payload)
        return handler

    respx.get(f"{BASE}/approvals/pending").mock(side_effect=record({"approvals": []}))
    respx.get(f"{BASE}/approvals/ap-1").mock(side_effect=record({"pending": _pending_dict()}))
    respx.post(f"{BASE}/approvals/submit").mock(side_effect=record({
        "approval_id": "ap-1", "created_at": 1, "expires_at": 301, "trusted_approvers": ["aa" * 32],
    }))
    respx.post(f"{BASE}/approvals/ap-1/respond").mock(side_effect=record({
        "approval_id": "ap-1", "outcome": "approved", "resolved_at": 1,
    }))
    respx.post(f"{BASE}/v1/evaluate").mock(side_effect=record({"status": "deny"}))
    async with ChioClient(BASE, control_token="approval-control") as client:
        await client.list_pending_approvals()
        await client.get_approval("ap-1")
        await client.submit_for_approval(capability=_signed_capability(), requested_by="bb" * 32,
                                         tool_name="run_command", tool_args={"command": "true"})
        await client.respond_approval("ap-1", "approve", signed_token=_signed_vote())
        await client.evaluate_tool_call_mediated(capability=_signed_capability(),
                                                tool_server="shell", tool_name="run_command", parameters={})
    assert seen == {
        "/approvals/pending": "Bearer approval-control",
        "/approvals/ap-1": "Bearer approval-control",
        "/approvals/submit": "Bearer approval-control",
        "/approvals/ap-1/respond": "Bearer approval-control",
        "/v1/evaluate": None,
    }
