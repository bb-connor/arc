"""Framework advice retains effects and release restrictions without raw output."""
import asyncio
import httpx
import pytest
from chio_sdk.recovery import RecoveryClient
from chio_sdk.recovery_host import RecoveryHostSession

OPERATION = {"operation_id": "operation", "native_admission_digest": [1] * 32,
             "operation_version": 1}


def status(effect, control="active", release=None):
    return {"command_id": "command", "workflow_id": "workflow", "revision": 1,
            "control": control, "effect": effect,
            "release": release or {"kind": "not_available"}}


@pytest.mark.parametrize("native,category", [
    (status({"kind": "never_admitted"}), "closed_without_effect"),
    (status({"kind": "closed_before_effect", "operation": OPERATION, "closure": "closure"}), "closed_without_effect"),
    (status({"kind": "awaiting_approval", "operation": OPERATION}), "waiting_for_approval"),
    (status({"kind": "admission_unresolved", "admission_intent": "intent"}), "reconciliation_required"),
    (status({"kind": "unknown", "operation": OPERATION}), "reconciliation_required"),
    (status({"kind": "in_flight", "operation": OPERATION}), "waiting_for_outcome"),
    (status({"kind": "awaiting_caller_report", "operation": OPERATION}), "waiting_for_outcome"),
    (status({"kind": "partial", "operation": OPERATION, "applied_effects": 1}), "completed_with_effects"),
    (status({"kind": "failed_after_effect", "operation": OPERATION, "applied_effects": 1}), "completed_with_effects"),
    (status({"kind": "complete", "operation": OPERATION, "effect_count": 1}), "complete"),
    (status({"kind": "complete", "operation": OPERATION, "effect_count": 1}, release={"kind": "withheld", "evidence": "withheld"}), "withheld"),
    (status({"kind": "complete", "operation": OPERATION, "effect_count": 1}, release={"kind": "denied", "reason": "audience_denied"}), "withheld"),
    (status({"kind": "complete", "operation": OPERATION, "effect_count": 1}, "quarantined", {"kind": "withheld", "evidence": "withheld"}), "quarantined"),
    (status({"kind": "in_flight", "operation": OPERATION}, "cancel_requested"), "cancel_requested"),
    (status({"kind": "closed_before_effect", "operation": OPERATION, "closure": "closure"}, "cancelled"), "cancelled"),
])
def test_host_projects_every_native_state(native, category):
    async def run():
        calls = []
        def serve(request):
            calls.append(request)
            return httpx.Response(200, json={"status": native})
        session = RecoveryHostSession("http://localhost:1", "private-capability",
                                      {"selected": b"{}"}, transport=httpx.MockTransport(serve))
        outcome = await session.execute("selected")
        assert outcome.as_dict() == {"category": category, "command_id": "command", "workflow_id": "workflow"}
        assert len(calls) == session.attempts == 1
    asyncio.run(run())


@pytest.mark.parametrize("http_status,code,category", [
    (400, "invalid_command", "refused"), (403, "authority_denied", "refused"),
    (409, "conflict", "conflict"), (409, "unsupported_profile", "unsupported_profile"),
    (409, "uncovered_mediation", "uncovered_mediation"), (409, "restart_required", "restart_required"),
    (409, "unknown_effect", "reconciliation_required"), (503, "unavailable", "unavailable"),
    (409, "probe_expired", "probe_expired"), (409, "origin_refused", "origin_refused"),
    (503, "busy", "busy"), (413, "projection_too_large", "projection_too_large"),
])
def test_fixed_native_errors_keep_semantics(http_status, code, category):
    async def run():
        transport = httpx.MockTransport(lambda _: httpx.Response(http_status, text="recovery." + code))
        client = RecoveryClient("http://localhost:1", transport=transport)
        with pytest.raises(RuntimeError, match="^recovery\\." + code + "$"):
            await client.execute("private-capability", b"{}")
        await client.aclose()
        session = RecoveryHostSession("http://localhost:1", "private-capability", {"selected": b"{}"}, transport=transport)
        assert (await session.execute("selected")).as_dict() == {"category": category}
    asyncio.run(run())


def test_ambient_proxy_cannot_intercept_loopback_capability(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.invalid:3128")
    monkeypatch.delenv("NO_PROXY", raising=False)
    async def run():
        client = RecoveryClient("http://127.0.0.1:12345")
        assert client._http._transport_for_url(httpx.URL("http://127.0.0.1:12345")) is client._http._transport
        await client.aclose()
    asyncio.run(run())


def test_setup_default_wait_matches_operator_contract():
    async def run():
        observed = []
        def serve(request):
            observed.append((request.url.path, request.extensions["timeout"]["read"]))
            return httpx.Response(503, text="recovery.unavailable")
        client = RecoveryClient("http://localhost:1", transport=httpx.MockTransport(serve))
        for invoke in [lambda: client.execute("capability", b"{}"), lambda: client.setup_probe("capability", "workflow")]:
            with pytest.raises(RuntimeError):
                await invoke()
        assert observed == [("/v1/recovery/commands", 20), ("/v1/recovery/setup/probe", 120)]
        await client.aclose()
    asyncio.run(run())
