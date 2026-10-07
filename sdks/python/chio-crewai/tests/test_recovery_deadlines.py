"""Native outcome delivery is independent of private-loop cleanup shutdown."""
import asyncio
import json
from pathlib import Path
import threading
import time

import httpx
import pytest

from chio_crewai.recovery import RecoveryTool
from chio_sdk.recovery_host import RecoveryHostSession


def native_response():
    root = Path(__file__).resolve().parents[4]
    corpus = json.loads((root / "spec/vectors/recovery/v1/authority-contracts.json").read_text())
    return json.loads(next(row["wire"] for row in corpus["vectors"]
                           if row["contract"] == "command_result" and row["valid"]))


class SlowShutdown(httpx.MockTransport):
    def __init__(self, *, fail_after_close=False):
        super().__init__(self.respond)
        self.calls = 0
        self.cancellations = 0
        self.completed = threading.Event()
        self.fail_after_close = fail_after_close
        self.worker = None

    def respond(self, request):
        self.calls += 1
        self.worker = threading.current_thread()
        return httpx.Response(200, json=native_response())

    async def aclose(self):
        until = time.monotonic() + 2
        try:
            while (remaining := until - time.monotonic()) > 0:
                try:
                    await asyncio.sleep(remaining)
                except asyncio.CancelledError:
                    self.cancellations += 1
            if self.fail_after_close:
                raise ValueError("transport-close-canary private credential")
        finally:
            self.completed.set()


@pytest.mark.parametrize("running_loop", [False, True])
@pytest.mark.parametrize("fail_after_close", [False, True])
def test_tool_delivery_does_not_wait_for_cancellation_resistant_loop_shutdown(running_loop, fail_after_close, capsys, caplog):
    transport = SlowShutdown(fail_after_close=fail_after_close)
    session = RecoveryHostSession("http://localhost:1", "synthetic-credential",
                                  {"resume": b"{}"}, timeout_seconds=1,
                                  transport=transport)
    tool = RecoveryTool(session=session)
    started = time.monotonic()
    if running_loop:
        async def dispatch():
            return tool.run(choice="resume")
        outcome = json.loads(asyncio.run(dispatch()))
    else:
        outcome = json.loads(tool.run(choice="resume"))
    elapsed = time.monotonic() - started
    assert elapsed < 1.3
    assert outcome == {"category": "complete", "command_id": native_response()["status"]["command_id"],
                       "workflow_id": native_response()["status"]["workflow_id"]}
    assert session.attempts == transport.calls == 1
    # Observe worker drain separately from the selected native action wait.
    assert transport.completed.wait(timeout=3)
    assert transport.worker is not threading.current_thread()
    transport.worker.join(timeout=1)
    assert not transport.worker.is_alive()
    captured = capsys.readouterr()
    assert "canary" not in captured.out + captured.err + caplog.text
