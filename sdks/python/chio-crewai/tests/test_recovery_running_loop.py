"""The synchronous CrewAI tool remains usable inside an async application."""
import asyncio
import json
import httpx
from chio_crewai.recovery import RecoveryTool
from chio_sdk.recovery_host import RecoveryHostSession


def test_sync_tool_in_running_loop_returns_one_native_outcome():
    requests = []
    def serve(request):
        requests.append(request)
        return httpx.Response(409, text="recovery.unknown_effect")
    session = RecoveryHostSession("http://localhost:1", "private-capability", {"resume": b"{}"},
                                  transport=httpx.MockTransport(serve))
    tool = RecoveryTool(session=session)
    async def run():
        assert json.loads(tool.run(choice="resume")) == {"category": "reconciliation_required", "error_code": "recovery.unknown_effect"}
    asyncio.run(run())
    assert len(requests) == session.attempts == 1
