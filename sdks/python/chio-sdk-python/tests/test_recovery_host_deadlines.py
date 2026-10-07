"""An action deadline includes cleanup and never erases a retained native result."""
import asyncio
import time

import httpx
import pytest

from chio_sdk.recovery_host import RecoveryHostSession


@pytest.mark.asyncio
@pytest.mark.parametrize("response_delay", [0, 0.6])
@pytest.mark.parametrize("effect,category", [
    ({"kind": "complete", "effect_count": 1}, "complete"),
    ({"kind": "partial", "applied_effects": 1}, "completed_with_effects"),
])
async def test_cleanup_uses_the_remaining_action_deadline_without_losing_effects(response_delay, effect, category):
    operation = {"operation_id": "operation", "native_admission_digest": [1] * 32,
                 "operation_version": 1}
    status = {"command_id": "command", "workflow_id": "workflow", "revision": 1,
              "control": "active", "effect": {**effect, "operation": operation},
              "release": {"kind": "not_available"}}

    class StalledClose(httpx.AsyncBaseTransport):
        calls = 0
        close_started = False
        close_cancelled = False

        def __init__(self):
            self.cancelled = asyncio.Event()

        async def handle_async_request(self, request):
            self.calls += 1
            await asyncio.sleep(response_delay)
            return httpx.Response(200, json={"status": status})

        async def aclose(self):
            self.close_started = True
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.close_cancelled = True
                self.cancelled.set()
                raise

    transport = StalledClose()
    session = RecoveryHostSession("http://localhost:1", "synthetic-capability",
        {"resume": b"{}"}, transport=transport, timeout_seconds=1)
    outcome = await asyncio.wait_for(session.execute("resume"), timeout=1.4)
    assert outcome.as_dict() == {"category": category, "command_id": "command", "workflow_id": "workflow"}
    assert transport.calls == session.attempts == 1
    # The action returns when its deadline ends; observe task cancellation
    # separately so the observation cannot extend the selected action wait.
    await asyncio.wait_for(transport.cancelled.wait(), timeout=1)
    assert transport.close_started and transport.close_cancelled


@pytest.mark.asyncio
async def test_delayed_cleanup_cancellation_cannot_renew_the_action_budget():
    operation = {"operation_id": "operation", "native_admission_digest": [1] * 32,
                 "operation_version": 1}
    status = {"command_id": "command", "workflow_id": "workflow", "revision": 1,
              "control": "active", "effect": {"kind": "complete", "operation": operation, "effect_count": 1},
              "release": {"kind": "not_available"}}

    class DelayedCancellationClose(httpx.MockTransport):
        completed = None

        async def aclose(self):
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await asyncio.sleep(0.5)
            finally:
                self.completed.set()

    transport = DelayedCancellationClose(lambda _: httpx.Response(200, json={"status": status}))
    transport.completed = asyncio.Event()
    session = RecoveryHostSession("http://localhost:1", "synthetic-capability",
        {"resume": b"{}"}, transport=transport, timeout_seconds=1)
    started = time.monotonic()
    outcome = await asyncio.wait_for(session.execute("resume"), timeout=2)
    assert time.monotonic() - started < 1.3
    assert outcome.as_dict() == {"category": "complete", "command_id": "command", "workflow_id": "workflow"}
    assert session.attempts == 1
    # Observe eventual cleanup separately from the action's selected wait.
    await asyncio.wait_for(transport.completed.wait(), timeout=1)
