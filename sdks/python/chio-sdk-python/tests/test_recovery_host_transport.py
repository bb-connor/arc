"""Even a transport close failure cannot put raw diagnostics into a host result."""
import json
from pathlib import Path
import httpx
import pytest
from chio_sdk.recovery_host import RecoveryHostSession


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
