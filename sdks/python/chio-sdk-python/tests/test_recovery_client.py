import asyncio
import json
import httpx
import pytest
from chio_sdk import RecoveryClient
from chio_sdk._generated.recovery.command_schema import RecoveryCommandV1

REPLY = {"status":{"command_id":"original-command","workflow_id":"workflow","revision":1,"control":"active","effect":{"kind":"never_admitted"},"release":{"kind":"not_available"}}}

COMMAND = {"schema": "chio.recovery.command.v1", "version": 1, "command_id": "original-command",
           "command": {"kind": "inspect_workflow", "workflow_id": "workflow"}}


@pytest.mark.parametrize("endpoint,route", [
    ("https://host.example", b"/v1/recovery/commands"),
    ("https://host.example/gateway", b"/gateway/v1/recovery/commands"),
    ("https://host.example/gateway/", b"/gateway/v1/recovery/commands"),
    ("https://host.example/gateway/encoded%2Fsegment", b"/gateway/encoded%2Fsegment/v1/recovery/commands"),
])
def test_recovery_preserves_canonical_identity_without_automatic_retry(endpoint, route):
    async def run():
        requests = []
        def handle(request):
            assert request.url.raw_path == route
            requests.append(request.content)
            return httpx.Response(503 if len(requests) == 1 else 200, json=REPLY)
        client = RecoveryClient(endpoint, transport=httpx.MockTransport(handle))
        model = RecoveryCommandV1.model_validate_json(json.dumps(COMMAND), strict=True)
        with pytest.raises(RuntimeError, match="^recovery.refused_or_unavailable$"):
            await client.execute("protected-capability", model)
        assert len(requests) == 1
        result = await client.execute("protected-capability", model)
        assert result.status.effect.kind == "never_admitted"
        assert len(requests) == 2 and requests[0] == requests[1]
        assert json.loads(json.loads(requests[0])["command"]) == COMMAND
        await client.aclose()
    asyncio.run(run())


@pytest.mark.parametrize("status,body", [(302, b"private-canary"), (200, b"x" * 262145), (200,b"{private-canary"), (200,b"{}")])
def test_recovery_refuses_redirect_and_oversized_reply(status, body):
    async def run():
        calls = []
        def handle(request):
            calls.append(request)
            return httpx.Response(status, content=body)
        client = RecoveryClient("https://host.example", transport=httpx.MockTransport(handle))
        with pytest.raises((ValueError, RuntimeError), match="^recovery\\."):
            await client.execute("private-canary", json.dumps(COMMAND).encode())
        assert len(calls) == 1
        await client.aclose()
    asyncio.run(run())


def test_recovery_bounds_intake_before_transport():
    async def run():
        calls = []
        client = RecoveryClient("https://host.example", transport=httpx.MockTransport(lambda request: calls.append(request)))
        with pytest.raises(ValueError, match="^recovery.resource_exhausted$"):
            await client.execute("x" * 65536, b"{}")
        assert not calls
        await client.aclose()
    asyncio.run(run())


def test_recovery_charges_escaped_string_budget_before_transport():
    async def run():
        calls = []
        client = RecoveryClient("https://host.example", transport=httpx.MockTransport(
            lambda request: calls.append(request) or httpx.Response(503, text="recovery.unavailable")))
        command = {"schema": "chio.recovery.command.v1", "version": 1, "command_id": "command",
                   "command": {"kind": "create_workflow", "creation_key": "key",
                               "template": "support_ticket_public_issue", "request_seed": "\x00" * 6000}}
        model = RecoveryCommandV1.model_validate_json(json.dumps(command), strict=True)
        with pytest.raises(ValueError, match="^recovery.invalid_command$"):
            await client.execute("capability", model)
        assert not calls
        await client.aclose()
    asyncio.run(run())


@pytest.mark.parametrize("url", ["http://foreign.example", "https://token@host.example", "https://host.example?credential=canary", "https:///missing-host", "https:missing-host"])
def test_recovery_refuses_unsafe_endpoint(url):
    with pytest.raises(ValueError, match="^recovery.invalid_endpoint$"):
        RecoveryClient(url)


def test_recovery_transport_failure_is_bounded_and_does_not_resubmit():
    async def run():
        calls = []
        def handle(request):
            calls.append(request)
            raise httpx.ReadError("private-canary", request=request)
        client = RecoveryClient("https://host.example", transport=httpx.MockTransport(handle))
        with pytest.raises(RuntimeError, match="^recovery.unavailable$"):
            await client.execute("private-canary", json.dumps(COMMAND).encode())
        assert len(calls) == 1
        with pytest.raises(ValueError, match="^recovery.invalid_command$"):
            await client.execute("private-canary", b"\xffprivate-canary")
        assert len(calls) == 1
        await client.aclose()
    asyncio.run(run())
