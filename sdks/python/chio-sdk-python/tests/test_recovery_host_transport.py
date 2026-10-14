"""Even a transport close failure cannot put raw diagnostics into a host result."""
import json
import asyncio
import inspect
from pathlib import Path
import httpx
import pytest
from chio_sdk.recovery_host import RecoveryHostSession


@pytest.mark.asyncio
async def test_request_scheduling_failure_closes_unstarted_work_and_releases_admission(monkeypatch):
    requests = []
    pending = []

    def refuse_scheduling(coroutine):
        pending.append(coroutine)
        raise RuntimeError("local-scheduler-canary")

    def observe(request):
        requests.append(request)
        return httpx.Response(503, text="private-transport-diagnostic")

    session = RecoveryHostSession("http://localhost:1", "synthetic-capability",
        {"resume": b"{}"}, transport=httpx.MockTransport(observe))
    with monkeypatch.context() as scheduling:
        scheduling.setattr(asyncio, "create_task", refuse_scheduling)
        outcome = await session.execute("resume")
    assert outcome.as_dict() == {"category": "unavailable"}
    assert len(pending) == 1
    assert inspect.getcoroutinestate(pending[0]) == inspect.CORO_CLOSED
    assert requests == [] and session.attempts == 1
    # A subsequent explicit action may use the admission released by the failed
    # scheduler. It performs exactly one request and retains its native refusal.
    successor = await session.execute("resume")
    assert successor.as_dict() == {"category": "refused", "error_code": "recovery.refused_or_unavailable"}
    assert len(requests) == 1 and session.attempts == 2


@pytest.mark.asyncio
async def test_close_failure_retains_the_native_effect_without_retry_or_diagnostics():
    root = Path(__file__).resolve().parents[4]
    corpus = json.loads((root/"spec/vectors/recovery/v1/authority-contracts.json").read_text())
    response = json.loads(next(row["wire"] for row in corpus["vectors"] if row["contract"] == "command_result" and row["valid"]))
    class ClosingFailure(httpx.AsyncBaseTransport):
        calls = 0
        async def handle_async_request(self, request):
            self.calls += 1
            return httpx.Response(200, json=response)
        async def aclose(self):
            raise RuntimeError("transport-close-canary credential")
    transport = ClosingFailure()
    session = RecoveryHostSession("http://localhost:1", "synthetic-credential",
        {"resume":b'{"command_id":"owned"}'}, transport=transport)
    outcome = await session.execute("resume")
    assert outcome.as_dict() == {"category":"complete", "command_id":response["status"]["command_id"],
                               "workflow_id":response["status"]["workflow_id"],
                               "effect":response["status"]["effect"]["kind"],
                               "control":response["status"]["control"],
                               "release":response["status"]["release"]["kind"]}
    assert transport.calls == 1 and session.attempts == 1
    assert "canary" not in repr(outcome)


@pytest.mark.asyncio
async def test_cleanup_scheduling_failure_preserves_received_outcome_and_closes_coroutine(monkeypatch):
    root = Path(__file__).resolve().parents[4]
    corpus = json.loads((root/"spec/vectors/recovery/v1/authority-contracts.json").read_text())
    response = json.loads(next(row["wire"] for row in corpus["vectors"] if row["contract"] == "command_result" and row["valid"]))
    schedule = asyncio.create_task
    pending = []
    requests = []

    def fail_cleanup(coroutine):
        if coroutine.cr_code.co_name == "_close_without_diagnostics":
            pending.append(coroutine)
            raise RuntimeError("cleanup-scheduler-canary")
        return schedule(coroutine)

    def observe(request):
        requests.append(request)
        return httpx.Response(200, json=response)

    session = RecoveryHostSession("http://localhost:1", "synthetic-capability",
        {"resume": b"{}"}, transport=httpx.MockTransport(observe))
    with monkeypatch.context() as scheduling:
        scheduling.setattr(asyncio, "create_task", fail_cleanup)
        outcome = await session.execute("resume")
    assert outcome.category.value == "complete"
    assert outcome.command_id == response["status"]["command_id"]
    assert outcome.effect == response["status"]["effect"]["kind"]
    assert len(requests) == session.attempts == len(pending) == 1
    assert inspect.getcoroutinestate(pending[0]) == inspect.CORO_CLOSED
    assert "canary" not in repr(outcome)


def test_host_selected_wait_budget_is_bounded_and_does_not_retry():
    import asyncio
    import httpx
    import pytest
    from chio_sdk.recovery_host import RecoveryHostSession
    for invalid in [0, 121, True, 1.5]:
        with pytest.raises(ValueError, match="^recovery.invalid_budget$"):
            RecoveryHostSession("http://localhost:1", "private", {"resume":b"{}"}, timeout_seconds=invalid)
    requests = []
    def observe(request):
        requests.append(request)
        assert request.extensions["timeout"]["read"] == 120
        return httpx.Response(503, text="raw-error-canary")
    session = RecoveryHostSession("http://localhost:1", "private", {"resume":b"{}"},
        timeout_seconds=120, transport=httpx.MockTransport(observe), max_tool_actions=1)
    result = asyncio.run(session.execute("resume"))
    assert result.as_dict() == {"category":"refused", "error_code":"recovery.refused_or_unavailable"}
    assert len(requests) == 1
    assert session.attempts == 1
