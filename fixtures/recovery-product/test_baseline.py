"""Explicit supervisor must preserve original identity and fresh refusal."""
import asyncio
import unittest
from threading import Event, Thread
import json
import time
from types import SimpleNamespace
from unittest.mock import patch
import httpx
from campaign_baseline import SupervisorSession


class BaselineTest(unittest.TestCase):
    def test_async_cleanup_scheduling_failure_preserves_received_completion(self):
        operation = {"operation_id":"operation", "native_admission_digest":[1]*32, "operation_version":1}
        status = {"command_id":"native-command", "workflow_id":"native-workflow", "revision":1,
                  "control":"active", "effect":{"kind":"complete", "operation":operation, "effect_count":1},
                  "release":{"kind":"not_available"}}
        requests = []
        def endpoint(request):
            requests.append(request.content)
            return httpx.Response(200, json={"status":status})
        original = asyncio.create_task
        def schedule(coroutine, *args, **kwargs):
            if coroutine.cr_code.co_name == "close":
                coroutine.close()
                raise RuntimeError("private-async-cleanup-canary")
            return original(coroutine, *args, **kwargs)
        session = SupervisorSession("http://127.0.0.1:1", "capability", b"{}",
                                    transport=httpx.MockTransport(endpoint), timeout_seconds=1)
        with patch("campaign_baseline.asyncio.create_task", schedule):
            outcome = asyncio.run(session.execute("resume")).as_dict()
        self.assertEqual(outcome, {"category":"complete", "command_id":"native-command", "workflow_id":"native-workflow"})
        self.assertEqual(len(requests), 1)
        self.assertEqual(session.attempts, 1)

    def test_failed_async_cleanup_schedule_closes_its_unscheduled_coroutine(self):
        scheduled = []
        original = asyncio.create_task
        def schedule(coroutine, *args, **kwargs):
            if coroutine.cr_code.co_name == "close":
                scheduled.append(coroutine)
                raise RuntimeError("private-task-factory-canary")
            return original(coroutine, *args, **kwargs)
        class Client:
            async def aclose(self):
                raise AssertionError("a failed task factory cannot run this coroutine")
        session = SupervisorSession("http://127.0.0.1:1", "capability", b"{}", timeout_seconds=1)
        async def cleanup():
            await session._close_within_deadline(Client(), asyncio.get_running_loop().time()+1)
        with patch("campaign_baseline.asyncio.create_task", schedule):
            asyncio.run(cleanup())
        self.assertEqual(len(scheduled), 1)
        self.assertIsNone(scheduled[0].cr_frame)

    def test_cleanup_failures_do_not_replace_a_received_native_completion(self):
        operation = {"operation_id":"operation", "native_admission_digest":[1]*32, "operation_version":1}
        status = {"command_id":"native-command", "workflow_id":"native-workflow", "revision":1,
                  "control":"active", "effect":{"kind":"complete", "operation":operation, "effect_count":1},
                  "release":{"kind":"not_available"}}
        for failure in ["schedule", "teardown"]:
            with self.subTest(failure=failure):
                requests = []
                def endpoint(request):
                    requests.append(request.content)
                    return httpx.Response(200, json={"status":status})
                session = SupervisorSession("http://127.0.0.1:1", "capability", b"{}",
                                            transport=httpx.MockTransport(endpoint), timeout_seconds=1)
                original_schedule = asyncio.create_task
                original_run = asyncio.run
                def schedule(coroutine, *args, **kwargs):
                    if failure == "schedule" and coroutine.cr_code.co_name == "close":
                        coroutine.close()
                        raise RuntimeError("private-cleanup-canary")
                    return original_schedule(coroutine, *args, **kwargs)
                def run(coroutine):
                    outcome = original_run(coroutine)
                    if failure == "teardown":
                        raise RuntimeError("private-teardown-canary")
                    return outcome
                with patch("campaign_baseline.asyncio.create_task", schedule), \
                     patch("campaign_baseline.asyncio.run", run):
                    outcome = session.execute_sync("resume").as_dict()
                self.assertEqual(outcome, {"category":"complete", "command_id":"native-command", "workflow_id":"native-workflow"})
                self.assertEqual(len(requests), 1)
                self.assertEqual(session.attempts, 1)

    def test_private_loop_shutdown_keeps_shared_admission_until_the_worker_exits(self):
        operation = {"operation_id":"operation", "native_admission_digest":[1]*32, "operation_version":1}
        status = {"command_id":"native-command", "workflow_id":"native-workflow", "revision":1,
                  "control":"active", "effect":{"kind":"complete", "operation":operation, "effect_count":1},
                  "release":{"kind":"not_available"}}
        requests = []
        def endpoint(request):
            requests.append(request.content)
            return httpx.Response(200, json={"status":status})
        shutdown_started = Event()
        shutdown_release = Event()
        original_run = asyncio.run
        def delayed_shutdown(coroutine):
            result = original_run(coroutine)
            shutdown_started.set()
            shutdown_release.wait(3)
            return result
        session = SupervisorSession("http://127.0.0.1:1", "capability", b"{}", timeout_seconds=1,
                                    transport=httpx.MockTransport(endpoint))
        with patch("campaign_baseline.asyncio.run", delayed_shutdown):
            try:
                self.assertEqual(session.execute_sync("resume").category, "complete")
                self.assertTrue(shutdown_started.wait(1))
                self.assertEqual(session.execute_sync("resume").as_dict(), {"category":"busy"})
                self.assertEqual(len(requests), 1)
            finally:
                shutdown_release.set()

    def test_sync_delivery_retains_completion_and_admission_during_delayed_cleanup(self):
        operation = {"operation_id":"operation", "native_admission_digest":[1]*32, "operation_version":1}
        status = {"command_id":"native-command", "workflow_id":"native-workflow", "revision":1,
                  "control":"active", "effect":{"kind":"complete", "operation":operation, "effect_count":1},
                  "release":{"kind":"not_available"}}
        release = Event()
        closed = Event()
        requests = []
        class Client:
            def __init__(self, *_args, **_kwargs): pass
            async def execute(self, capability, command):
                requests.append((capability, command))
                return SimpleNamespace(status=SimpleNamespace(model_dump=lambda **_kwargs:status))
            async def aclose(self):
                try:
                    while not release.is_set():
                        await asyncio.sleep(0.01)
                except asyncio.CancelledError:
                    while not release.is_set():
                        await asyncio.sleep(0.01)
                finally:
                    closed.set()
        def delayed_worker(*, target, args, **kwargs):
            def run():
                time.sleep(0.2)
                target(*args)
            return Thread(target=run, **kwargs)
        with patch("campaign_baseline.RecoveryClient", Client), patch("campaign_baseline.Thread", delayed_worker):
            session = SupervisorSession("http://127.0.0.1:1", "capability", b"{}", timeout_seconds=1)
            started = time.monotonic()
            try:
                outcome = session.execute_sync("resume")
                self.assertLess(time.monotonic() - started, 2)
                self.assertEqual(outcome.as_dict(), {"category":"complete", "command_id":"native-command", "workflow_id":"native-workflow"})
                self.assertEqual(session.execute_sync("resume").as_dict(), {"category":"busy"})
                self.assertEqual(len(requests), 1)
            finally:
                release.set()
            self.assertTrue(closed.wait(2))

    def test_sync_and_async_share_the_original_action_budget(self):
        requests = []
        def endpoint(request):
            requests.append(request.content)
            return httpx.Response(403, content=b"private-provider-canary")
        session = SupervisorSession("http://127.0.0.1:1", "capability", b"{}",
                                    transport=httpx.MockTransport(endpoint))
        for index in range(8):
            outcome = session.execute_sync("resume") if index % 2 else asyncio.run(session.execute("resume"))
            self.assertEqual(outcome.as_dict(), {"category":"refused"})
        self.assertEqual(session.execute_sync("resume").as_dict(), {"category":"budget_exhausted"})
        self.assertEqual(asyncio.run(session.execute("resume")).as_dict(), {"category":"budget_exhausted"})
        self.assertEqual(len(requests), 8)
        self.assertEqual(session.attempts, 8)

    def test_supported_crewai_baseline_uses_the_same_owned_native_command_once(self):
        from campaign_runner import crew_trial
        from preflight import ExplicitAction
        requests = []
        operation = {"operation_id":"operation", "native_admission_digest":[1]*32, "operation_version":1}
        status = {"command_id":"native-command", "workflow_id":"native-workflow", "revision":1,
                  "control":"active", "effect":{"kind":"complete", "operation":operation, "effect_count":1},
                  "release":{"kind":"not_available"}}
        def endpoint(request):
            requests.append(request.content)
            return httpx.Response(200, json={"status": status})
        command = b'{"owned":"native"}'
        session = SupervisorSession("http://127.0.0.1:1", "capability", command,
                                    transport=httpx.MockTransport(endpoint))
        model = ExplicitAction()
        outcome = crew_trial(session, model, "Call recovery once with choice resume.")
        self.assertEqual(outcome, {"category":"complete", "command_id":"native-command", "workflow_id":"native-workflow"})
        self.assertEqual(len(requests), 1)
        self.assertEqual(json.loads(requests[0]), {"capability":"capability", "command":command.decode()})
        self.assertEqual(session.attempts, 1)
        self.assertEqual(model.calls, 1)

    def test_effect_custody_and_fixed_errors_remain_distinct(self):
        operation = {"operation_id":"operation", "native_admission_digest":[1]*32, "operation_version":1}
        states = [
            ({"kind":"partial", "operation":operation, "applied_effects":1}, "active", {"kind":"not_available"}, "completed_with_effects"),
            ({"kind":"unknown", "operation":operation}, "active", {"kind":"not_available"}, "reconciliation_required"),
            ({"kind":"complete", "operation":operation, "effect_count":1}, "quarantined", {"kind":"withheld", "evidence":"withheld"}, "quarantined"),
            ({"kind":"complete", "operation":operation, "effect_count":1}, "active", {"kind":"withheld", "evidence":"withheld"}, "withheld"),
        ]
        for effect, control, release, category in states:
            with self.subTest(category=category):
                status = {"command_id":"command", "workflow_id":"workflow", "revision":1,
                          "control":control, "effect":effect, "release":release}
                session = SupervisorSession("http://127.0.0.1:1", "capability", b"{}",
                    transport=httpx.MockTransport(lambda _:httpx.Response(200, json={"status":status})))
                self.assertEqual(asyncio.run(session.execute("resume")).as_dict(),
                                 {"category":category, "command_id":"command", "workflow_id":"workflow"})
        for http_status, code, category in [(409,"unknown_effect","reconciliation_required"),
                                            (503,"unavailable","unavailable"), (409,"conflict","conflict"),
                                            (409,"probe_expired","probe_expired"),
                                            (409,"origin_refused","origin_refused"),
                                            (503,"busy","busy"),
                                            (413,"projection_too_large","projection_too_large")]:
            with self.subTest(error=code):
                session = SupervisorSession("http://127.0.0.1:1", "capability", b"{}",
                    transport=httpx.MockTransport(lambda _:httpx.Response(http_status, text="recovery."+code)))
                self.assertEqual(asyncio.run(session.execute("resume")).as_dict(), {"category":category})

    def test_no_fallback_or_hidden_retry_after_authoritative_refusal(self):
        requests = []
        def endpoint(request):
            requests.append(request.content)
            return httpx.Response(403, content=b"private-provider-canary")
        session = SupervisorSession("http://127.0.0.1:20096", "private-credential-canary", b'{"owned":"native"}',
                                    transport=httpx.MockTransport(endpoint))
        for _ in range(2):
            outcome = asyncio.run(session.execute("resume"))
            self.assertEqual(outcome.as_dict(), {"category":"refused"})
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0], requests[1])
        self.assertEqual(session.attempts, 2)
        self.assertNotIn("canary", repr(session))


if __name__ == "__main__": unittest.main()
