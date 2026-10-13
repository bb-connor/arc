"""A delivered synchronous result releases only its own finished admission."""
import asyncio
from concurrent.futures import Future
import json
from pathlib import Path
import threading
from unittest.mock import patch

import httpx
import pytest

from chio_sdk.recovery_host import RecoveryHostSession


def native_response():
    root = Path(__file__).resolve().parents[4]
    corpus = json.loads((root / "spec/vectors/recovery/v1/authority-contracts.json").read_text())
    return json.loads(next(row["wire"] for row in corpus["vectors"]
                           if row["contract"] == "command_result" and row["valid"]))


def test_completed_sync_delivery_allows_replay_without_clearing_the_new_action():
    response = native_response()
    requests = []

    def respond(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=response)

    session = RecoveryHostSession("http://localhost:1", "synthetic-capability",
                                  {"resume": b"{}"}, max_tool_actions=3,
                                  timeout_seconds=1, transport=httpx.MockTransport(respond))
    release_publisher = threading.Event()
    release_second = threading.Event()
    second_started = threading.Event()
    second_progress = threading.Event()
    second_result = Future()
    first_worker = []

    class PausedPublication(Future):
        def set_result(self, outcome):
            first_worker.append(threading.current_thread())
            super().set_result(outcome)
            if not release_publisher.wait(timeout=5):
                raise AssertionError("publisher barrier was not released")

    first_delivery = PausedPublication()
    admitted = session._execute_admitted

    async def pause_second_before_native(choice):
        second_started.set()
        second_progress.set()
        if not await asyncio.to_thread(release_second.wait, 5):
            raise AssertionError("second action barrier was not released")
        return await admitted(choice)

    def replay():
        try:
            second_result.set_result(session.execute_sync("resume"))
        except BaseException as error:
            second_result.set_exception(error)
        finally:
            second_progress.set()

    caller = threading.Thread(target=replay, daemon=True)
    try:
        with patch("chio_sdk.recovery_host.Future", return_value=first_delivery):
            assert session.execute_sync("resume").category == "complete"
        with patch.object(session, "_execute_admitted", pause_second_before_native):
            caller.start()
            assert second_progress.wait(timeout=5), "replay made no progress"
            assert second_started.is_set(), "completed delivery left replay busy"
            # The old publisher can now finish while the next action owns
            # admission but has not yet created a retained native task.
            release_publisher.set()
            first_worker[0].join(timeout=5)
            assert not first_worker[0].is_alive()
            assert session.execute_sync("resume").as_dict() == {"category": "busy"}
            release_second.set()
            caller.join(timeout=5)
            assert not caller.is_alive()
            assert second_result.result(timeout=0).category == "complete"
        assert requests == [{"capability": "synthetic-capability", "command": "{}"}] * 2
        assert session.attempts == 3
        assert session.execute_sync("resume").as_dict() == {"category": "budget_exhausted"}
    finally:
        release_publisher.set()
        release_second.set()
        for worker in [*first_worker, caller]:
            if worker.ident is not None:
                worker.join(timeout=5)


@pytest.mark.parametrize("hold_close", [False, True], ids=["completed-close", "late-close"])
def test_owned_completion_releases_admission_before_default_executor_teardown(hold_close):
    helper_started = threading.Event()
    release_helper = threading.Event()
    helper_finished = threading.Event()
    teardown_started = threading.Event()
    close_started = threading.Event()
    close_cancelled = threading.Event()
    close_completed = threading.Event()
    result = Future()
    workers, requests = [], []

    def unrelated_helper():
        helper_started.set()
        try:
            if not release_helper.wait(timeout=10):
                raise AssertionError("executor helper was not released")
        finally:
            helper_finished.set()

    class ExecutorTransport(httpx.AsyncBaseTransport):
        loop = None
        release_close = None

        async def handle_async_request(self, request):
            workers.append(threading.current_thread())
            requests.append(json.loads(request.content))
            if len(requests) == 1:
                self.loop = asyncio.get_running_loop()
                self.release_close = asyncio.Event()
                work = self.loop.run_in_executor(None, unrelated_helper)
                while not helper_started.is_set():
                    await asyncio.sleep(0)
                # The asyncio Future can be cancelled without stopping the
                # executor callable. The native request and close still finish.
                work.cancel()
            return httpx.Response(200, json=native_response())

        async def aclose(self):
            close_started.set()
            if hold_close and len(requests) == 1:
                while not self.release_close.is_set():
                    try:
                        await self.release_close.wait()
                    except asyncio.CancelledError:
                        close_cancelled.set()
            close_completed.set()

    transport = ExecutorTransport()
    expected_attempts = 3 if hold_close else 2
    session = RecoveryHostSession("http://localhost:1", "synthetic-capability",
                                  {"resume": b"{}"}, max_tool_actions=expected_attempts,
                                  timeout_seconds=1, transport=transport)
    original_shutdown = asyncio.BaseEventLoop.shutdown_default_executor

    async def observe_shutdown(loop, *args, **kwargs):
        teardown_started.set()
        return await original_shutdown(loop, *args, **kwargs)

    def execute():
        try:
            result.set_result(session.execute_sync("resume"))
        except BaseException as error:
            result.set_exception(error)

    caller = threading.Thread(target=execute, daemon=True)
    try:
        with patch.object(asyncio.BaseEventLoop, "shutdown_default_executor", observe_shutdown):
            caller.start()
            if hold_close:
                assert close_started.wait(timeout=5)
                assert result.result(timeout=1.25).category == "complete"
                assert not close_completed.is_set()
                assert session.execute_sync("resume").as_dict() == {"category": "busy"}
                assert close_cancelled.wait(timeout=5), "close did not receive deadline cancellation"
                transport.loop.call_soon_threadsafe(transport.release_close.set)
            assert teardown_started.wait(timeout=5), "executor teardown was not reached"
            assert close_completed.is_set()
            with session._lock:
                assert not any(not task.done() for task in session._retained_tasks)
            # The helper stays behind its barrier beyond the action deadline.
            # Completed results and the next explicit action must not await it.
            assert result.result(timeout=1.25).category == "complete"
            assert not helper_finished.is_set()
            assert session.execute_sync("resume").category == "complete"
            assert requests == [{"capability": "synthetic-capability", "command": "{}"}] * 2
            assert session.attempts == expected_attempts
    finally:
        if transport.loop is not None and not transport.loop.is_closed():
            transport.loop.call_soon_threadsafe(transport.release_close.set)
        release_helper.set()
        caller.join(timeout=5)
        for worker in workers:
            worker.join(timeout=5)
        assert not caller.is_alive()
        assert all(not worker.is_alive() for worker in workers)
        assert helper_finished.is_set()
