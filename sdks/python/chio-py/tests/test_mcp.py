from __future__ import annotations

import asyncio
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from chio.invariants.hashing import sha256_hex_utf8
from chio.invariants.json import canonicalize_json
from chio.invariants.receipt import (
    _content_addressed_receipt_id,
    receipt_signing_body_canonical_json,
)
from chio.invariants.signing import sign_utf8_message_ed25519
from chio.mcp import McpEvidenceError, VerifiedMcpSession, verify_mcp_result

SEED = "43" * 32
KEY = sign_utf8_message_ed25519("key", SEED)["public_key_hex"]
ARGS = {"message": "Hello 世界", "threshold": 0.000001}
OUTPUT = {"content": [{"type": "text", "text": "actual signed output"}]}


def signed_receipt(*, verdict, request_id, arguments, content_hash):
    receipt = {
        "timestamp": 1800000000,
        "capability_id": "cap-1",
        "tool_server": "workspace",
        "tool_name": "echo",
        "action": {
            "parameters": arguments,
            "parameter_hash": sha256_hex_utf8(canonicalize_json(arguments)),
        },
        "decision": {"verdict": verdict},
        "receipt_kind": "mediated_decision",
        "boundary_class": "prevent",
        "tool_origin": "caller_executed",
        "redaction_mode": "none",
        "content_hash": content_hash,
        "policy_hash": "policy",
        "trust_level": "mediated",
        "kernel_key": KEY,
        "metadata": {"receipt_context": {"request_id": request_id}},
    }
    if verdict == "deny":
        receipt["decision"]["reason"] = "budget exhausted"
    receipt["id"] = _content_addressed_receipt_id(receipt)
    receipt["signature"] = sign_utf8_message_ed25519(
        receipt_signing_body_canonical_json(receipt), SEED
    )["signature_hex"]
    return receipt


def tool_result(*, verdict="allow", request_id="request-1", arguments=None):
    arguments = deepcopy(ARGS if arguments is None else arguments)
    output = deepcopy(OUTPUT) if verdict == "allow" else None
    receipt = signed_receipt(
        verdict=verdict,
        request_id=request_id,
        arguments=arguments,
        content_hash=sha256_hex_utf8(canonicalize_json(output)),
    )
    return {
        "content": [{"type": "text", "text": "unsigned display content"}],
        "isError": verdict != "allow",
        "_meta": {
            "chio": {
                "decision": verdict,
                "receipt": receipt,
                "receiptId": receipt["id"],
                "terminalState": {"kind": "completed"},
            },
            "chioEvidence": {
                "schema": "chio.mcp.execution-evidence.v1",
                "requestId": request_id,
                "receipt": receipt,
                "outputKind": "value" if output is not None else "none",
                "output": output,
                "terminalState": "completed",
            },
        },
    }


def verify(value, **overrides):
    options = {
        "trusted_signers": [KEY],
        "request_id": "request-1",
        "server_id": "workspace",
        "tool_name": "echo",
        "arguments": ARGS,
    }
    return verify_mcp_result(value, **{**options, **overrides})


def test_only_the_committed_output_is_returned():
    result = verify(tool_result())
    assert result.allowed
    assert result.output == OUTPUT


def test_a_verified_denial_has_no_output():
    result = verify(tool_result(verdict="deny"))
    assert not result.allowed
    assert result.output is None


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "schema",
        "signature",
        "output",
        "request",
        "envelope_request",
        "arguments",
        "stream",
        "unknown_kind",
        "none_with_output",
        "receipt",
        "denied_value",
    ],
)
def test_missing_or_tampered_evidence_fails_closed(change):
    result = tool_result()
    evidence = result["_meta"]["chioEvidence"]
    if change == "missing":
        del result["_meta"]["chioEvidence"]
    elif change == "schema":
        evidence["schema"] = "chio.mcp.execution-evidence.v2"
    elif change == "signature":
        evidence["receipt"]["signature"] = "00" * 64
    elif change == "output":
        evidence["output"]["content"][0]["text"] = "tampered"
    elif change == "request":
        result = tool_result(request_id="replayed-other-request")
    elif change == "envelope_request":
        evidence["requestId"] = "replayed-other-request"
    elif change == "arguments":
        result = tool_result(arguments={"message": "something else"})
    elif change == "stream":
        evidence["outputKind"] = "stream"
        evidence["output"] = None
    elif change == "unknown_kind":
        evidence["outputKind"] = "partial"
    elif change == "none_with_output":
        evidence["outputKind"] = "none"
    elif change == "receipt":
        evidence["receipt"] = None
    else:
        result = tool_result(verdict="deny")
        result["_meta"]["chioEvidence"]["outputKind"] = "value"
    with pytest.raises(McpEvidenceError):
        verify(result)


def test_unsigned_projection_cannot_stand_in_for_evidence():
    result = tool_result()
    result["_meta"] = {"chio": result["_meta"]["chio"]}
    with pytest.raises(McpEvidenceError):
        verify(result)


@pytest.mark.parametrize(
    "overrides",
    [
        {"trusted_signers": []},
        {"trusted_signers": ["00" * 32]},
        {"tool_name": "different"},
        {"server_id": "different"},
    ],
)
def test_signer_and_tool_identity_must_match_operator_configuration(overrides):
    with pytest.raises(McpEvidenceError):
        verify(tool_result(), **overrides)


@pytest.mark.parametrize("signers", [[], ["not-a-key"]])
def test_session_requires_a_valid_signer_pin(signers):
    with pytest.raises(ValueError):
        VerifiedMcpSession(None, trusted_signers=signers, server_id="workspace")


def test_session_binds_fresh_request_ids_and_snapshots_arguments():
    async def scenario():
        request_ids = []
        dispatched = asyncio.Event()
        proceed = asyncio.Event()

        async def call_tool(name, parameters, *, meta):
            assert name == "echo"
            assert set(meta) == {"chioRequestId"}
            request_ids.append(meta["chioRequestId"])
            dispatched.set()
            await proceed.wait()
            value = tool_result(request_id=meta["chioRequestId"], arguments=parameters)
            return SimpleNamespace(model_dump=lambda **kwargs: value)

        session = VerifiedMcpSession(
            SimpleNamespace(call_tool=call_tool),
            trusted_signers=[KEY],
            server_id="workspace",
        )
        arguments = deepcopy(ARGS)
        pending = asyncio.create_task(session.call_tool("echo", arguments))
        await dispatched.wait()
        arguments["message"] = "changed while the request is in flight"
        proceed.set()
        first = await pending
        second = await session.call_tool("echo", arguments)
        assert first.receipt["action"]["parameters"] == ARGS
        assert second.receipt["action"]["parameters"] == arguments
        assert request_ids[0] != request_ids[1]

    asyncio.run(scenario())


def test_session_does_not_retry_an_uncertain_effect():
    invoke = AsyncMock(side_effect=TimeoutError("response lost after possible effect"))
    session = VerifiedMcpSession(
        SimpleNamespace(call_tool=invoke), trusted_signers=[KEY], server_id="workspace"
    )
    with pytest.raises(TimeoutError):
        asyncio.run(session.call_tool("echo", ARGS))
    assert invoke.await_count == 1


def test_the_mcp_client_session_accepts_request_meta():
    import inspect

    from mcp import ClientSession

    assert "meta" in inspect.signature(ClientSession.call_tool).parameters
