"""Failed launch and shutdown observations retain their declared trial slots."""
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import campaign_main
from owned_native_process import NativeProcessOwner, owned_native_process


REAL_POPEN = subprocess.Popen
REAL_KILLPG = os.killpg


class CampaignRetentionTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, {}, clear=True))
        self.network_attempts = []
        def refuse_network(*args, **kwargs):
            self.network_attempts.append(True)
            raise AssertionError("offline test attempted network")
        for target in ("socket.socket.connect", "socket.socket.connect_ex",
                       "socket.create_connection", "socket.getaddrinfo"):
            self.stack.enter_context(patch(target, refuse_network))
        self.addCleanup(lambda: self.assertEqual(self.network_attempts, []))
        self.children, self.logs, self.launch_options = [], [], []
        self.finish_publications = []
        self.finish_failure = False
        self.ignore_finish = False
        self.unresolved = False
        self.unresolved_pids = set()
        self.malformed_evidence = False
        self.invalid_log = False
        self.cleanup_budgets = []
        touch = Path.touch
        def finish_touch(path, *args, **kwargs):
            if path.name == "finish":
                self.finish_publications.append(path)
                if self.finish_failure:
                    raise OSError("synthetic private publication detail")
            return touch(path, *args, **kwargs)
        self.stack.enter_context(patch.object(Path, "touch", finish_touch))
        def owner(command, **options):
            self.cleanup_budgets.append((options["grace_seconds"], options["terminate_seconds"], options["kill_seconds"]))
            options.update(terminate_seconds=0.05, kill_seconds=0.05)
            return owned_native_process(command, **options)
        self.stack.enter_context(patch.object(campaign_main, "owned_native_process", owner, create=True))
        def killpg(pid, number):
            if pid in self.unresolved_pids:
                return None
            return REAL_KILLPG(pid, number)
        self.stack.enter_context(patch("owned_native_process.os.killpg", killpg))
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.evidence = Path(self.temporary.name)
        self.addCleanup(self.rescue_children)
        self.manifest = {"model":"fixed-model", "authority_policy":hashlib.sha256(b"{}").hexdigest(),
            "source_binding":"test-candidate", "base_commit":"1"*40,
            "source_inventory_version":campaign_main.SOURCE_INVENTORY_VERSION,
            "provider_endpoint":"https://api.openai.com/v1",
            "budgets":{"native_preparation_seconds":1, "native_shutdown_seconds":0.05,
                "host_start_deadline_seconds":1, "provider_seconds":1,
                "model_calls":1, "prompt_bytes":512, "output_tokens":128}}
        self.trial = {"id":"retained-trial", "host":"langgraph", "workflow":"support", "arm":"product",
                      "case":"authorized", "repetition":1}

    def launch(self, command, **options):
        exchange = Path(options["stdout"].name).parent
        for name, data in [("authority-contract.json", b"{}"), ("capability.json", b"synthetic"),
                           ("command.json", b"{}")]:
            (exchange / name).write_bytes(data)
        options["stdout"].write(b"test result: ok. 1 passed; 0 failed; 0 ignored\n")
        options["stdout"].flush()
        self.logs.append(options["stdout"])
        self.launch_options.append(options)
        if self.malformed_evidence:
            (exchange / "native-evidence.json").write_text("malformed")
        if self.invalid_log:
            options["stdout"].write(b"\xff")
            options["stdout"].flush()
        code = "from pathlib import Path; import time; Path('child-ready').touch()\nwhile not Path('finish').exists(): time.sleep(0.005)"
        unresolved = self.unresolved(exchange) if callable(self.unresolved) else self.unresolved
        if self.ignore_finish or unresolved or self.finish_failure:
            code = "from pathlib import Path; import time,signal; signal.signal(signal.SIGTERM,signal.SIG_IGN); Path('child-ready').touch(); time.sleep(60)"
        child = REAL_POPEN([sys.executable, "-I", "-B", "-c", code], cwd=exchange,
                           env={}, stdout=options["stdout"], stderr=options["stderr"],
                           start_new_session=True)
        self.children.append(child)
        deadline = time.monotonic() + 3
        while not (exchange / "child-ready").exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue((exchange / "child-ready").exists())
        wait = child.wait
        child.wait = lambda timeout=None: wait(timeout=min(timeout, 0.1) if timeout is not None else 0.1)
        if unresolved:
            self.unresolved_pids.add(child.pid)
            child.terminate = lambda: None
            child.kill = lambda: None
        return child

    def rescue_children(self):
        for child in self.children:
            if child.poll() is None:
                REAL_KILLPG(child.pid, signal.SIGKILL)
                subprocess.Popen.wait(child, timeout=3)
        for log in self.logs:
            if not log.closed:
                log.close()

    def body(self, *, failure=False):
        class Provider:
            def __init__(self, **options):
                self.chat = SimpleNamespace(completions=SimpleNamespace())
            def __enter__(self): return self
            def __exit__(self, *arguments): return False
        async def run(session, model, task):
            if failure:
                raise RuntimeError("campaign.provider_unavailable")
            return {"category":"complete"}
        providers = {"openai":SimpleNamespace(OpenAI=Provider),
                     "httpx":SimpleNamespace(Client=lambda **kwargs:None)}
        self.stack.enter_context(patch.object(campaign_main, "installed_module",
            lambda distribution, name: (providers[name], {"module":name, "synthetic":True})))
        self.stack.enter_context(patch.object(campaign_main, "graph_trial", run))
        self.stack.enter_context(patch.dict(os.environ, {"OPENAI_API_KEY":"synthetic"}, clear=True))
        self.stack.enter_context(patch.object(campaign_main, "wait_endpoint", return_value="http://127.0.0.1:20096"))

    def retained(self, row):
        stored = json.loads((self.evidence / self.trial["id"] / "result.json").read_bytes())
        self.assertEqual(stored, row)
        self.assertGreaterEqual(row["elapsed_seconds"], 0)
        self.assertGreaterEqual(row["native_preparation_seconds"], 0)

    def test_native_launch_failure_is_retained_with_unknown_facts(self):
        with patch.object(campaign_main.subprocess, "Popen", side_effect=FileNotFoundError("synthetic")):
            row = campaign_main.trial_run(Path.cwd(), self.evidence, self.manifest, self.trial)
        self.retained(row)
        self.assertEqual(row["outcome"], "native_error")
        self.assertEqual(row["error_category"], "campaign.native_launch_failed")
        self.assertEqual(row["native_observation"], "unknown")
        self.assertIsNone(row["native"])

    def test_ready_timeout_is_native_error_and_retains_preparation_duration(self):
        with patch.object(campaign_main.subprocess, "Popen", self.launch), \
             patch.object(campaign_main, "wait_endpoint", side_effect=TimeoutError("campaign.native_preparation_failed")):
            row = campaign_main.trial_run(Path.cwd(), self.evidence, self.manifest, self.trial)
        self.retained(row)
        self.assertEqual(row["outcome"], "native_error")
        self.assertEqual(row["error_category"], "campaign.native_preparation_failed")

    def test_host_failure_retains_host_duration(self):
        self.body(failure=True)
        with patch.object(campaign_main.subprocess, "Popen", self.launch):
            row = campaign_main.trial_run(Path.cwd(), self.evidence, self.manifest, self.trial)
        self.retained(row)
        self.assertEqual(row["outcome"], "provider_error")
        self.assertGreaterEqual(row["host_model_native_seconds"], 0)

    def run_failed_cleanup(self):
        error = None
        row = None
        with patch.object(campaign_main.subprocess, "Popen", self.launch):
            try:
                row = campaign_main.trial_run(Path.cwd(), self.evidence, self.manifest, self.trial)
            except BaseException as caught:
                error = caught
        result = self.evidence / self.trial["id"] / "result.json"
        self.assertTrue(result.is_file(), "cleanup must retain the exact attempted trial")
        stored = json.loads(result.read_bytes())
        self.assertIsNotNone(error, "cleanup failure must close later trial admission")
        self.assertEqual(str(error), "campaign.native_cleanup_failed")
        self.assertEqual(error.row, stored)
        self.assertEqual(stored["outcome"], "native_error")
        self.assertTrue(stored["native_shutdown_error"])
        self.assertTrue(stored["native_execution_error"])
        self.assertEqual(stored["native_cleanup_error"], "campaign.native_cleanup_failed")
        self.assertTrue(all(log.closed for log in self.logs))
        self.retained(stored)
        return stored

    def test_failed_shutdown_and_malformed_native_evidence_still_retain_row(self):
        self.unresolved = True
        self.malformed_evidence = True
        self.stack.enter_context(patch.object(campaign_main, "wait_endpoint",
            side_effect=TimeoutError("campaign.native_preparation_failed")))
        row = self.run_failed_cleanup()
        self.assertIsNone(row["native"])
        self.assertIsNone(row["native_exit_code"])
        self.assertEqual(row["native_observation"], "unknown")
        self.assertEqual(row["error_category"], "campaign.native_preparation_failed")
        self.assertTrue(row["native_evidence_error"])

    def test_finish_publication_failure_retains_primary_body_outcome(self):
        self.finish_failure = True
        self.body(failure=True)
        row = self.run_failed_cleanup()
        self.assertEqual(row["body_outcome"], "provider_error")
        self.assertEqual(row["error_category"], "campaign.provider_unavailable")
        self.assertEqual(row["native_exit_code"], -signal.SIGKILL)
        self.assertEqual(len(self.finish_publications), 1)
        self.assertGreaterEqual(row["host_model_native_seconds"], 0)
        self.assertGreater(row["native_shutdown_seconds"], 0)

    def test_forced_kill_never_proves_native_execution_from_success_log(self):
        self.ignore_finish = True
        self.body()
        row = self.run_failed_cleanup()
        self.assertEqual(row["body_outcome"], "complete", "retain body outcome without claiming native success")
        self.assertEqual(row["native_exit_code"], -signal.SIGKILL)
        self.assertNotIn("native_executable", row)
        self.assertEqual(len(self.finish_publications), 1)

    def test_invalid_native_log_still_retains_trial(self):
        self.invalid_log = True
        self.body()
        with patch.object(campaign_main.subprocess, "Popen", self.launch):
            try:
                row = campaign_main.trial_run(Path.cwd(), self.evidence, self.manifest, self.trial)
            except Exception:
                row = None
        self.assertIsNotNone(row, "log decoding must not erase the trial")
        self.retained(row)
        self.assertTrue(row["native_log_error"])
        self.assertTrue(row["native_execution_error"])

    def test_graceful_owner_finishes_once_and_closes_log(self):
        self.body()
        with patch.object(campaign_main.subprocess, "Popen", self.launch):
            row = campaign_main.trial_run(Path.cwd(), self.evidence, self.manifest, self.trial)
        self.retained(row)
        self.assertEqual(row["native_exit_code"], 0)
        self.assertFalse(row.get("native_shutdown_error", False))
        self.assertTrue(all(log.closed for log in self.logs))
        self.assertEqual(len(self.finish_publications), 1)
        self.assertTrue(self.launch_options[0].get("start_new_session"), "shared owner must own a process group")
        self.assertEqual(self.cleanup_budgets, [(0.05, 5, 5)])
        self.assertGreaterEqual(row["native_shutdown_seconds"], 0)

    def run_main(self, launch, *, workers=1):
        manifest = {**self.manifest, "schema":"chio.recovery-live-corpus.v2", "hosts":{}, "sources":[],
                    "budgets":{**self.manifest["budgets"], "concurrent_trials":workers},
                    "trials":[{**self.trial, "id":f"trial-{n}"} for n in range(96)]}
        manifest_path = self.evidence / "manifest.json"
        raw = json.dumps(manifest).encode()
        manifest_path.write_bytes(raw)
        manifest_path.with_suffix(".sha256").write_text(hashlib.sha256(raw).hexdigest())
        output = self.evidence / "campaign"
        stdout = io.StringIO()
        with patch.object(campaign_main.subprocess, "Popen", launch), \
             patch.object(campaign_main.subprocess, "check_output", return_value=b"1"*40), \
             patch.object(campaign_main, "source_inventory", return_value=[]), \
             patch.object(campaign_main, "source_binding", return_value=manifest["source_binding"]), \
             patch.object(campaign_main, "optional_compiler_capture", return_value=(None,None)), \
             patch.object(campaign_main, "summarize", return_value={}) as summarize, \
             patch.object(sys, "argv", ["campaign_main", "--manifest",str(manifest_path), "--checkout",str(Path.cwd()), "--evidence",str(output)]), \
             redirect_stdout(stdout):
            error = None
            try:
                campaign_main.main()
            except BaseException as caught:
                error = caught
        journal = output/"results.jsonl"
        rows = [json.loads(line) for line in journal.read_text().splitlines()] if journal.exists() else []
        return rows, error, output, summarize, stdout.getvalue()

    def test_main_retains_abort_row_and_never_launches_later_trials(self):
        self.unresolved = True
        self.body(failure=True)
        launches = []
        def launch(command, **options):
            launches.append(True)
            if self.children:
                raise OSError("later trial was launched")
            return self.launch(command, **options)
        rows, error, output, summarize, stdout = self.run_main(launch)
        self.assertEqual(len(launches), 1, "unadmitted slots must never start a native child")
        self.assertEqual(len(rows), 1, "stopped admission must preserve an incomplete denominator")
        self.assertEqual(rows[0], json.loads((output/"trial-0/result.json").read_bytes()))
        self.assertEqual(str(error), "campaign.native_cleanup_failed")
        self.assertEqual(summarize.call_count, 0)
        self.assertFalse((output/"summary.json").exists())
        abort = json.loads((output/"campaign-abort.json").read_bytes())
        self.assertEqual(abort, {"error_category":"campaign.native_cleanup_failed", "planned_trials":96,
                                "retained_trials":1, "completed":False})
        self.assertNotIn("Completed source-bound", stdout)
        self.assertTrue(all(log.closed for log in self.logs))

    def test_main_stops_submission_while_active_trial_finishes_and_is_retained(self):
        self.body()
        self.unresolved = lambda exchange: exchange.name == "trial-0"
        cleanup_observed = threading.Event()
        second_started = threading.Event()
        reads = Path.read_text
        def read(path, *args, **kwargs):
            if path.name == "native.log" and path.parent.name == "trial-0":
                cleanup_observed.set()
            return reads(path, *args, **kwargs)
        self.stack.enter_context(patch.object(Path, "read_text", read))
        async def host(session, model, task):
            if task == "trial-0":
                self.assertTrue(second_started.wait(3))
            else:
                second_started.set()
                self.assertTrue(cleanup_observed.wait(3))
            return {"category":"complete"}
        self.stack.enter_context(patch.object(campaign_main, "public_task", lambda trial: trial["id"]))
        self.stack.enter_context(patch.object(campaign_main, "graph_trial", host))
        executor = campaign_main.ThreadPoolExecutor
        submissions = []
        class CountingExecutor(executor):
            def submit(self, fn, *args, **kwargs):
                submissions.append(args[0]["id"])
                return super().submit(fn, *args, **kwargs)
        self.stack.enter_context(patch.object(campaign_main, "ThreadPoolExecutor", CountingExecutor))
        rows, error, output, summarize, stdout = self.run_main(self.launch, workers=2)
        self.assertEqual(submissions, ["trial-0", "trial-1"])
        self.assertEqual({row["id"] for row in rows}, {"trial-0", "trial-1"})
        self.assertEqual(len(self.children), 2)
        self.assertEqual(str(error), "campaign.native_cleanup_failed")
        self.assertEqual(summarize.call_count, 0)
        retained = {row["id"]:row for row in rows}
        self.assertTrue(retained["trial-0"]["native_shutdown_error"])
        self.assertIsNone(retained["trial-0"]["native_exit_code"])
        self.assertEqual(retained["trial-1"]["native_exit_code"], 0)
        self.assertNotIn("native_shutdown_error", retained["trial-1"])
        self.assertTrue(all(log.closed for log in self.logs))
        for row in rows:
            self.assertEqual(row, json.loads((output/row["id"]/"result.json").read_bytes()))

    def test_log_close_failure_retains_zero_exit_without_proving_execution(self):
        self.body()
        path_open = Path.open
        class FailingClose:
            def __init__(self, file): self.file = file
            def __getattr__(self, name): return getattr(self.file, name)
            def close(self):
                self.file.close()
                raise OSError("synthetic private log failure detail")
        def open_path(path, *args, **kwargs):
            file = path_open(path, *args, **kwargs)
            return FailingClose(file) if path.name == "native.log" and args == ("wb",) else file
        self.stack.enter_context(patch.object(Path, "open", open_path))
        row = self.run_failed_cleanup()
        self.assertEqual(row["body_outcome"], "complete")
        self.assertEqual(row["native_exit_code"], 0)
        self.assertNotIn("native_executable", row)

    def test_interrupted_finish_retains_result_and_uses_same_owner_once(self):
        self.body()
        finish = NativeProcessOwner.finish
        calls = []
        def interrupted(owner):
            result = finish(owner)
            calls.append(owner)
            if len(calls) == 1:
                raise KeyboardInterrupt("synthetic private interruption detail")
            return result
        self.stack.enter_context(patch.object(NativeProcessOwner, "finish", interrupted))
        row = self.run_failed_cleanup()
        self.assertEqual(row["native_exit_code"], 0)
        self.assertEqual(len(calls), 2)
        self.assertIs(calls[0], calls[1])
        self.assertEqual(len(self.finish_publications), 1)

    def check_body_interruption(self, stage, unresolved, interruption_type):
        self.body()
        self.unresolved = unresolved
        primary = interruption_type("synthetic private body interruption detail")
        admission = campaign_main.CampaignAdmission()
        observed_admission = []
        read_bytes, read_text = Path.read_bytes, Path.read_text
        def read_evidence(path, *args, **kwargs):
            if path.name == "native-evidence.json":
                observed_admission.append(admission.stopped.is_set())
            return read_bytes(path, *args, **kwargs)
        def read_log(path, *args, **kwargs):
            if path.name == "native.log":
                observed_admission.append(admission.stopped.is_set())
            return read_text(path, *args, **kwargs)
        async def interrupted(*args):
            raise primary
        target = patch.object(campaign_main, "wait_endpoint", side_effect=primary) if stage == "ready" else \
                 patch.object(campaign_main, "graph_trial", interrupted)
        with patch.object(campaign_main.subprocess, "Popen", self.launch), target, \
             patch.object(Path, "read_bytes", read_evidence), patch.object(Path, "read_text", read_log):
            caught = None
            try:
                campaign_main.trial_run(Path.cwd(), self.evidence, self.manifest, self.trial,
                                        admission=admission)
            except BaseException as error:
                caught = error
        row = json.loads((self.evidence/self.trial["id"]/"result.json").read_bytes())
        self.assertEqual(observed_admission, [True, True], "interruption must close admission before evidence processing")
        self.assertEqual(str(caught), "campaign.interrupted")
        self.assertIs(caught.interruption, primary)
        self.assertIs(caught.__cause__, primary)
        self.assertEqual(caught.row, row)
        self.assertEqual(row["error_category"], "campaign.interrupted")
        self.assertTrue(row["interrupted"])
        self.assertNotIn(str(primary), json.dumps(row))
        self.assertTrue(all(log.closed for log in self.logs))
        self.assertEqual(len(self.finish_publications), 1)
        self.assertEqual(row["native_exit_code"], None if unresolved else 0)
        self.assertGreaterEqual(row["native_shutdown_seconds"], 0)
        self.assertGreaterEqual(row["native_preparation_seconds"], 0)
        if stage == "host":
            self.assertGreaterEqual(row["host_model_native_seconds"], 0)
        if unresolved:
            self.assertEqual(row["outcome"], "native_error")
            self.assertTrue(row["native_shutdown_error"])
            self.assertTrue(row["native_execution_error"])
            self.assertEqual(row["native_cleanup_error"], "campaign.native_cleanup_failed")
            self.assertNotIn("native_executable", row)
            self.assertTrue(any(child.poll() is None for child in self.children))
        else:
            self.assertNotIn("native_shutdown_error", row)
        self.retained(row)

    def test_ready_interruption_retains_row_after_graceful_cleanup(self):
        self.check_body_interruption("ready", False, SystemExit)

    def test_host_interruption_retains_row_after_graceful_cleanup(self):
        self.check_body_interruption("host", False, KeyboardInterrupt)

    def test_ready_interruption_unresolved_cleanup_stops_before_evidence(self):
        self.check_body_interruption("ready", True, KeyboardInterrupt)

    def test_host_interruption_unresolved_cleanup_stops_before_evidence(self):
        self.check_body_interruption("host", True, SystemExit)

    def check_main_body_interruption(self, stage, interruption_type):
        self.body()
        primary = interruption_type("synthetic private aggregate interruption detail")
        async def interrupted(*args):
            raise primary
        target = patch.object(campaign_main, "wait_endpoint", side_effect=primary) if stage == "ready" else \
                 patch.object(campaign_main, "graph_trial", interrupted)
        with target:
            rows, error, output, summarize, stdout = self.run_main(self.launch)
        self.assertEqual(len(rows), 1, "every attempted slot must reach the aggregate before interruption propagates")
        self.assertIs(error, primary)
        self.assertEqual(len(self.children), 1)
        self.assertEqual(rows[0], json.loads((output/"trial-0/result.json").read_bytes()))
        self.assertEqual(rows[0]["error_category"], "campaign.interrupted")
        self.assertTrue(rows[0]["interrupted"])
        self.assertNotIn(str(primary), (output/"results.jsonl").read_text())
        self.assertEqual(json.loads((output/"campaign-abort.json").read_bytes()), {
            "error_category":"campaign.interrupted", "planned_trials":96, "retained_trials":1, "completed":False})
        self.assertEqual(summarize.call_count, 0)
        self.assertFalse((output/"summary.json").exists())
        self.assertTrue(all(log.closed for log in self.logs))

    def test_main_aggregates_ready_interruption_before_rethrowing_original(self):
        self.check_main_body_interruption("ready", KeyboardInterrupt)

    def test_main_aggregates_host_interruption_before_rethrowing_original(self):
        self.check_main_body_interruption("host", SystemExit)

    def check_scheduler_interruption(self, active_count):
        self.body()
        primary = KeyboardInterrupt("synthetic private scheduler interruption detail")
        admissions, futures, submissions, active_observations = [], [], [], []
        active_lock = threading.Lock()
        all_active = threading.Event()
        admission_type = campaign_main.CampaignAdmission
        def admission():
            value = admission_type()
            admissions.append(value)
            return value
        async def active_body(*args):
            with active_lock:
                active_observations.append(None)
                index = len(active_observations)-1
                if len(active_observations) == active_count:
                    all_active.set()
            # The RED path times out because it never stops admission. The fixed
            # path releases promptly, without cancelling the active host thread.
            active_observations[index] = admissions[0].stopped.wait(0.5)
            return {"category":"complete"}
        def interrupted_wait(*args, **kwargs):
            self.assertTrue(all_active.wait(3), "expected owned trial bodies before interrupting wait")
            raise primary
        executor_type = campaign_main.ThreadPoolExecutor
        class ControlledExecutor(executor_type):
            def __init__(self, max_workers):
                # One physical worker makes the second bounded submission remain
                # unstarted. The two-worker variant retains both active owners.
                super().__init__(max_workers=active_count)
            def submit(self, function, *args, **kwargs):
                submissions.append(args[0]["id"])
                future = super().submit(function, *args, **kwargs)
                futures.append(future)
                return future
        with patch.object(campaign_main, "CampaignAdmission", admission), \
             patch.object(campaign_main, "graph_trial", active_body), \
             patch.object(campaign_main, "ThreadPoolExecutor", ControlledExecutor), \
             patch.object(campaign_main, "wait", interrupted_wait):
            rows, error, output, summarize, stdout = self.run_main(self.launch, workers=2)
        self.assertTrue(admissions[0].stopped.is_set(), "scheduler interruption must stop before draining owners")
        self.assertEqual(active_observations, [True]*active_count)
        self.assertIs(error, primary)
        self.assertEqual(submissions, ["trial-0", "trial-1"])
        self.assertEqual(len(self.children), active_count)
        self.assertEqual(len(rows), active_count)
        self.assertTrue(all(log.closed for log in self.logs))
        self.assertTrue(all(child.poll() == 0 for child in self.children))
        if active_count == 1:
            self.assertTrue(futures[1].cancelled(), "unstarted submitted slot must be cancelled")
            self.assertFalse((output/"trial-1").exists(), "unstarted slot must not fabricate a trial")
        for row in rows:
            self.assertEqual(row, json.loads((output/row["id"]/"result.json").read_bytes()))
        self.assertEqual(json.loads((output/"campaign-abort.json").read_bytes()), {
            "error_category":"campaign.interrupted", "planned_trials":96,
            "retained_trials":active_count, "completed":False})
        self.assertNotIn(str(primary), (output/"campaign-abort.json").read_text())
        self.assertEqual(summarize.call_count, 0)
        self.assertFalse((output/"summary.json").exists())

    def test_scheduler_interruption_cancels_unstarted_slot_before_draining_owner(self):
        self.check_scheduler_interruption(1)

    def test_scheduler_interruption_retains_both_already_active_owners(self):
        self.check_scheduler_interruption(2)

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(signal, "SIGALRM"), "POSIX FIFO")
    def test_native_image_rejects_fifo_without_blocking(self):
        image = self.evidence / "target/debug/deps/chio_control_plane-synthetic"
        image.parent.mkdir(parents=True)
        os.mkfifo(image)
        previous = signal.getsignal(signal.SIGALRM)
        def expired(*arguments):
            raise TimeoutError("native image reader blocked")
        signal.signal(signal.SIGALRM, expired)
        signal.alarm(1)
        try:
            with self.assertRaisesRegex(ValueError, "^qualification.native_executable$"):
                campaign_main.observed_native_executable(self.evidence,
                    "Running unittests src/lib.rs (target/debug/deps/chio_control_plane-synthetic)\n")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)

    def test_native_image_cannot_follow_a_replaced_parent_directory(self):
        image = self.evidence / "target/debug/deps/chio_control_plane-synthetic"
        image.parent.mkdir(parents=True)
        image.write_bytes(b"synthetic executable observation")
        actual = self.evidence / "alternate/debug/deps"
        actual.parent.mkdir(parents=True)
        image.parent.rename(actual)
        image.parent.symlink_to(actual, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            campaign_main.observed_native_executable(self.evidence,
                "Running unittests src/lib.rs (target/debug/deps/chio_control_plane-synthetic)\n")

    def test_provider_origin_is_checked_before_a_shadow_module_can_execute(self):
        root = Path(__file__).resolve().parents[2]
        marker = self.evidence / "shadow-executed"
        (self.evidence / "httpx.py").write_text(
            "from pathlib import Path\nPath("+repr(str(marker))+").touch()\n"
            "raise RuntimeError('shadow executed')\n")
        code = "import sys;from pathlib import Path;root=Path(sys.argv[1]);" \
               "sys.path[:0]=[sys.argv[2],str(root/'fixtures/recovery-product')," \
               "str(root/'sdks/python/chio-sdk-python/src'),str(root/'sdks/python/chio-adapter-base/src')];" \
               "\ntry: import campaign_main\n" \
               "except ValueError as error:\n" \
               " if str(error)!='qualification.provider_module_origin':raise\n" \
               "else: raise SystemExit('shadow module was not refused')\n"
        result = subprocess.run([sys.executable,"-I","-B","-c",code,str(root),str(self.evidence)],
                                cwd=root,env={},capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())
        self.assertFalse(marker.exists(),"provider shadow executed before origin validation")


if __name__ == "__main__":
    unittest.main()
