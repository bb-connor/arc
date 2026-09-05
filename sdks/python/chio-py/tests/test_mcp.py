from __future__ import annotations

from copy import deepcopy

import pytest
from chio.invariants.hashing import sha256_hex_utf8
from chio.invariants.json import canonicalize_json
from chio.invariants.receipt import receipt_signing_body_canonical_json
from chio.invariants.signing import sign_utf8_message_ed25519
from chio.mcp import McpReceiptError, VerifiedMcpSession, verify_mcp_result

SEED = "43" * 32
KEY = sign_utf8_message_ed25519("key", SEED)["public_key_hex"]
ARGS = {"message": "Hello 世界", "threshold": 0.000001}


def envelope(*, verdict="allow", request_id="request-1", arguments=None):
    arguments = deepcopy(ARGS if arguments is None else arguments)
    output = (
        {"content": [{"type": "text", "text": "actual signed output"}]}
        if verdict == "allow"
        else None
    )
    body = {
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
        "content_hash": sha256_hex_utf8(canonicalize_json(output)),
        "policy_hash": "policy",
        "trust_level": "mediated",
        "kernel_key": KEY,
        "metadata": {"receipt_context": {"request_id": request_id}},
    }
    receipt = {**body, "id": sha256_hex_utf8(canonicalize_json(body))}
    receipt["signature"] = sign_utf8_message_ed25519(
        receipt_signing_body_canonical_json(receipt), SEED
    )["signature_hex"]
    return {
        "content": [{"type": "text", "text": "unsigned display content"}],
        "_meta": {
            "chioReceipt": {
                "version": 1,
                "receipt": receipt,
                "output_kind": "value" if output is not None else "none",
                "output": output,
            }
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


def test_only_committed_output_is_returned():
    result = verify(envelope())
    assert result.allowed
    assert result.output["content"][0]["text"] == "actual signed output"
    assert not verify(envelope(verdict="deny")).allowed


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "signature",
        "output",
        "request",
        "arguments",
        "version",
        "stream",
        "receipt_type",
    ],
)
def test_missing_or_tampered_evidence_fails_closed(change):
    result = envelope()
    evidence = result["_meta"]["chioReceipt"]
    if change == "missing":
        del result["_meta"]
    elif change == "signature":
        evidence["receipt"]["signature"] = "00" * 64
    elif change == "output":
        evidence["output"]["content"][0]["text"] = "tampered"
    elif change == "request":
        result = envelope(request_id="replayed-other-request")
    elif change == "arguments":
        result = envelope(arguments={"message": "something else"})
    elif change == "version":
        evidence["version"] = True
    elif change == "stream":
        evidence["output_kind"] = "stream"
    else:
        evidence["receipt"] = None
    with pytest.raises(McpReceiptError):
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
    with pytest.raises(McpReceiptError):
        verify(envelope(), **overrides)


def test_session_requires_explicit_signer_pin():
    with pytest.raises(ValueError):
        VerifiedMcpSession(None, trusted_signers=[], server_id="workspace")


def test_session_binds_fresh_ids_and_snapshots_arguments():
    import asyncio
    from types import SimpleNamespace

    async def scenario():
        request_ids = []
        dispatched = asyncio.Event()
        proceed = asyncio.Event()

        async def call_tool(name, parameters, *, meta):
            assert name == "echo"
            assert meta["chioIncludeReceipt"] is True
            request_ids.append(meta["chioRequestId"])
            dispatched.set()
            await proceed.wait()
            value = envelope(request_id=meta["chioRequestId"], arguments=parameters)
            return SimpleNamespace(model_dump=lambda **kwargs: value)

        session = VerifiedMcpSession(
            SimpleNamespace(call_tool=call_tool),
            trusted_signers=[KEY],
            server_id="workspace",
        )
        arguments = deepcopy(ARGS)
        pending = asyncio.create_task(session.call_tool("echo", arguments))
        await dispatched.wait()
        arguments["message"] = "changed while request is in flight"
        proceed.set()
        first = await pending
        second = await session.call_tool("echo", arguments)
        assert first.receipt["action"]["parameters"] == ARGS
        assert second.receipt["action"]["parameters"] == arguments
        assert request_ids[0] != request_ids[1]

    asyncio.run(scenario())


def test_session_does_not_retry_an_uncertain_effect():
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    invoke = AsyncMock(side_effect=TimeoutError("response lost after possible effect"))
    session = VerifiedMcpSession(
        SimpleNamespace(call_tool=invoke), trusted_signers=[KEY], server_id="workspace"
    )
    with pytest.raises(TimeoutError):
        asyncio.run(session.call_tool("echo", ARGS))
    assert invoke.await_count == 1
