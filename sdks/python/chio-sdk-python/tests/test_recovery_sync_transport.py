"""One session owns synchronous delivery and all retained cleanup admission."""
import asyncio
import json
from pathlib import Path
import threading
import time
from unittest.mock import patch

import httpx
import pytest

from chio_sdk.recovery_host import RecoveryHostSession


def native_response():
    root = Path(__file__).resolve().parents[4]
    corpus = json.loads((root / "spec/vectors/recovery/v1/authority-contracts.json").read_text())
    return json.loads(next(row["wire"] for row in corpus["vectors"]
                           if row["contract"] == "command_result" and row["valid"]))


class RetainedCleanup(httpx.AsyncBaseTransport):
    def __init__(self, *, hold_request=False):
        self.calls = 0
        self.request_started = threading.Event()
        self.request_release = threading.Event()
        if not hold_request:
            self.request_release.set()
        self.cleanup_started = threading.Event()
        self.cleanup_release = threading.Event()
        self.closed = threading.Event()
        self.worker = None

    async def handle_async_request(self, request):
        self.calls += 1
        self.worker = threading.current_thread()
        self.request_started.set()
        while not self.request_release.is_set():
            await asyncio.sleep(0.01)
        return httpx.Response(200, json=native_response())

    async def aclose(self):
        self.cleanup_started.set()
        while not self.cleanup_release.is_set():
            try:
                await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                continue
        self.closed.set()


def session_for(transport, *, budget=4, command=b"{}"):
    return RecoveryHostSession("http://localhost:1", "synthetic-credential",
                               {"resume": command}, timeout_seconds=1,
                               max_tool_actions=budget, transport=transport)


def drain_worker(transport):
    transport.request_release.set()
    transport.cleanup_release.set()
    assert transport.closed.wait(timeout=2)
    transport.worker.join(timeout=2)
    assert not transport.worker.is_alive()


def test_sync_and_async_choices_are_busy_until_the_session_worker_drains():
    transport = RetainedCleanup()
    session = session_for(transport)
    try:
        assert session.execute_sync("resume").category == "complete"
        worker = transport.worker
        assert session.execute_sync("resume").as_dict() == {"category": "busy"}
        assert asyncio.run(session.execute("resume")).as_dict() == {"category": "busy"}
        assert transport.calls == 1 and session.attempts == 3
        assert transport.worker is worker
    finally:
        drain_worker(transport)
    assert session.execute_sync("resume").category == "complete"
    transport.worker.join(timeout=2)
    assert transport.calls == 2 and session.attempts == 4
    assert session.execute_sync("resume").as_dict() == {"category": "budget_exhausted"}
    assert transport.calls == 2


@pytest.mark.asyncio
async def test_async_admission_blocks_new_worker_and_retains_cleanup_across_delivery():
    transport = RetainedCleanup(hold_request=True)
    session = session_for(transport)
    action = asyncio.create_task(session.execute("resume"))
    try:
        while not transport.request_started.is_set():
            await asyncio.sleep(0.01)
        assert session.execute_sync("resume").as_dict() == {"category": "busy"}
        assert transport.calls == 1 and session.attempts == 2
        transport.request_release.set()
        assert (await asyncio.wait_for(action, timeout=1.4)).category == "complete"
        assert (await session.execute("resume")).as_dict() == {"category": "busy"}
        assert transport.calls == 1 and session.attempts == 3
    finally:
        transport.request_release.set()
        transport.cleanup_release.set()
        await asyncio.gather(action, return_exceptions=True)
        while not transport.closed.is_set():
            await asyncio.sleep(0.01)
        await asyncio.sleep(0)
    assert session.execute_sync("resume").category == "complete"
    transport.worker.join(timeout=2)
    assert transport.calls == 2 and session.attempts == 4


def test_unexpected_transport_error_is_a_closed_future_result_without_diagnostics(capsys, caplog):
    calls = []
    def fail(request):
        calls.append(request)
        raise LookupError("transport-error-canary private credential")
    session = session_for(httpx.MockTransport(fail), budget=1)
    assert session.execute_sync("resume").as_dict() == {"category": "refused"}
    assert session.execute_sync("resume").as_dict() == {"category": "budget_exhausted"}
    assert session.attempts == len(calls) == 1
    output = capsys.readouterr()
    assert "canary" not in output.out + output.err + caplog.text


def test_worker_launch_failure_spends_one_action_and_releases_admission(capsys):
    calls = []
    def respond(request):
        calls.append(request)
        return httpx.Response(200, json=native_response())
    session = session_for(httpx.MockTransport(respond), budget=2)
    with patch("chio_sdk.recovery_host.Thread.start", side_effect=RuntimeError("launch-error-canary")):
        assert session.execute_sync("resume").as_dict() == {"category": "unavailable"}
    assert session.attempts == 1 and not calls
    assert session.execute_sync("resume").category == "complete"
    assert session.attempts == 2 and len(calls) == 1
    output = capsys.readouterr()
    assert "canary" not in output.out + output.err


def test_caller_interruption_retains_the_worker_and_never_retries_the_admitted_call():
    transport = RetainedCleanup(hold_request=True)
    session = session_for(transport, budget=2)
    try:
        with patch("chio_sdk.recovery_host.Future.result", side_effect=KeyboardInterrupt):
            with pytest.raises(KeyboardInterrupt):
                session.execute_sync("resume")
        assert transport.request_started.wait(timeout=1)
        assert session.execute_sync("resume").as_dict() == {"category": "busy"}
        assert transport.calls == 1 and session.attempts == 2
    finally:
        drain_worker(transport)
    assert session.execute_sync("resume").as_dict() == {"category": "budget_exhausted"}
    assert transport.calls == 1


def test_external_loop_shutdown_cannot_log_a_local_cleanup_exception(caplog):
    class DelayedFailure(httpx.MockTransport):
        async def aclose(self):
            until = asyncio.get_running_loop().time() + 2
            while (remaining := until - asyncio.get_running_loop().time()) > 0:
                try:
                    await asyncio.sleep(remaining)
                except asyncio.CancelledError:
                    continue
            raise ValueError("cleanup-log-canary private credential")

    transport = DelayedFailure(lambda _: httpx.Response(200, json=native_response()))
    session = session_for(transport, budget=1)
    assert asyncio.run(session.execute("resume")).category == "complete"
    assert session.attempts == 1
    assert "canary" not in caplog.text


class DelayedNativeRequest(httpx.AsyncBaseTransport):
    """Finish one request after cancellation without authorizing a second one."""
    def __init__(self, *, fail_late=False):
        self.calls = 0
        self.wires = []
        self.started = threading.Event()
        self.release = threading.Event()
        self.cancelled = threading.Event()
        self.closed = threading.Event()
        self.worker = None
        self.fail_late = fail_late

    async def handle_async_request(self, request):
        self.calls += 1
        self.wires.append(json.loads(request.content))
        self.worker = threading.current_thread()
        self.started.set()
        until = asyncio.get_running_loop().time() + 2
        while not self.release.is_set() and asyncio.get_running_loop().time() < until:
            try:
                await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                self.cancelled.set()
        if self.fail_late:
            raise ValueError("late-native-request-canary private credential")
        return httpx.Response(200, json=native_response())

    async def aclose(self):
        self.closed.set()


def selected_native_command():
    root = Path(__file__).resolve().parents[4]
    corpus = json.loads((root / "spec/vectors/recovery/v1/authority-contracts.json").read_text())
    return next(row["wire"].encode() for row in corpus["vectors"]
                if row["contract"] == "command" and row["valid"])


@pytest.mark.asyncio
async def test_completed_native_tasks_release_admission_before_delayed_completion_callbacks():
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json=native_response())

    session = session_for(httpx.MockTransport(respond), budget=2,
                          command=selected_native_command())
    completed = session._retained_completed
    deferred = []
    try:
        # Delay only bookkeeping callbacks; the native request and cleanup run
        # as real tasks to completion before the next public action.
        with patch.object(session, "_retained_completed", side_effect=deferred.append):
            assert (await session.execute("resume")).category == "complete"
            assert session._retained_tasks
            assert all(task.done() for task in session._retained_tasks)
            assert (await session.execute("resume")).category == "complete"
            assert len(calls) == session.attempts == 2
    finally:
        for task in deferred:
            completed(task)


def assert_selected_native_intent(transport, command, count):
    assert transport.calls == len(transport.wires) == count
    assert all(wire["command"].encode() == command for wire in transport.wires)
    assert all(wire["capability"] == "synthetic-credential" for wire in transport.wires)


async def drain_async_request(transport):
    transport.release.set()
    async with asyncio.timeout(2):
        while not transport.closed.is_set():
            await asyncio.sleep(0.01)
        # Observe the completion callback through the public next admission.
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_late_native_success_cannot_extend_async_delivery_or_change_its_outcome():
    transport = DelayedNativeRequest()
    command = selected_native_command()
    session = session_for(transport, command=command)
    started = asyncio.get_running_loop().time()
    try:
        outcome = await session.execute("resume")
        assert asyncio.get_running_loop().time() - started < 1.5
        assert outcome.as_dict() == {"category": "unavailable"}
        async with asyncio.timeout(0.3):
            while not transport.cancelled.is_set():
                await asyncio.sleep(0.01)
        assert not transport.closed.is_set()
        assert (await session.execute("resume")).as_dict() == {"category": "busy"}
        assert_selected_native_intent(transport, command, 1)
        assert session.attempts == 2
    finally:
        await drain_async_request(transport)
    assert outcome.as_dict() == {"category": "unavailable"}
    assert (await session.execute("resume")).category == "complete"
    assert_selected_native_intent(transport, command, 2)
    assert session.attempts == 3


@pytest.mark.parametrize("fail_late", [False, True])
@pytest.mark.parametrize("running_loop", [False, True])
def test_sync_delivery_retains_the_late_request_worker_without_diagnostics(fail_late, running_loop, caplog, capsys):
    transport = DelayedNativeRequest(fail_late=fail_late)
    command = selected_native_command()
    session = session_for(transport, budget=2, command=command)
    started = time.monotonic()
    try:
        if running_loop:
            async def invoke_inside_loop():
                return session.execute_sync("resume")
            outcome = asyncio.run(invoke_inside_loop())
        else:
            outcome = session.execute_sync("resume")
        assert time.monotonic() - started < 1.5
        assert outcome.as_dict() == {"category": "unavailable"}
        assert transport.cancelled.wait(timeout=0.3) and not transport.closed.is_set()
        assert session.execute_sync("resume").as_dict() == {"category": "busy"}
        assert_selected_native_intent(transport, command, 1)
        assert session.attempts == 2
    finally:
        transport.release.set()
        transport.worker.join(timeout=2)
        assert not transport.worker.is_alive() and transport.closed.is_set()
    assert outcome.as_dict() == {"category": "unavailable"}
    assert session.execute_sync("resume").as_dict() == {"category": "budget_exhausted"}
    output = capsys.readouterr()
    assert "canary" not in output.out + output.err + caplog.text


@pytest.mark.asyncio
async def test_async_caller_cancellation_returns_while_native_request_keeps_admission(caplog):
    transport = DelayedNativeRequest(fail_late=True)
    command = selected_native_command()
    session = session_for(transport, budget=2, command=command)
    action = asyncio.create_task(session.execute("resume"))
    try:
        while not transport.started.is_set():
            await asyncio.sleep(0.01)
        started = asyncio.get_running_loop().time()
        action.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(action, timeout=0.3)
        assert asyncio.get_running_loop().time() - started < 0.5
        assert (await session.execute("resume")).as_dict() == {"category": "busy"}
        assert_selected_native_intent(transport, command, 1)
        assert session.attempts == 2
    finally:
        transport.release.set()
        await asyncio.gather(action, return_exceptions=True)
        await drain_async_request(transport)
    assert "canary" not in caplog.text
    assert (await session.execute("resume")).as_dict() == {"category": "budget_exhausted"}
    assert transport.calls == 1
