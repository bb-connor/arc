"""Offline entrypoint regressions using only owned, harmless Python children."""
from contextlib import ExitStack
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch


FIXTURES = Path(__file__).parent
REAL_POPEN = subprocess.Popen


def load_entrypoint(name):
    """Replace optional framework imports without importing any provider runtime."""
    session = type("Session", (), {"attempts": 0, "__init__": lambda self, *a, **kw: None})
    sdk = types.ModuleType("chio_sdk")
    sdk.recovery_host = types.ModuleType("chio_sdk.recovery_host")
    sdk.recovery_host.RecoveryHostSession = session
    baseline = types.ModuleType("campaign_baseline")
    baseline.SupervisorSession = session
    runner = types.ModuleType("campaign_runner")
    async def invalid_trial(*args):
        return {"category": "refused"}
    runner.graph_trial = invalid_trial
    runner.crew_trial = lambda *args: {"category": "refused"}
    runner.public_task = lambda trial: "synthetic offline input"
    httpx = types.ModuleType("httpx")
    httpx.AsyncBaseTransport = object
    httpx.AsyncHTTPTransport = lambda **kw: None
    with patch.dict(sys.modules, {"chio_sdk": sdk, "chio_sdk.recovery_host": sdk.recovery_host,
                                 "campaign_baseline": baseline, "campaign_runner": runner,
                                 "httpx": httpx}), patch.dict(os.environ, {}, clear=True):
        spec = importlib.util.spec_from_file_location("offline_" + name, FIXTURES / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    module.graph_case = invalid_trial
    return module, sdk


class FixtureChildCleanupTest(unittest.TestCase):
    def check_trial(self, name, reason=None, *, success=False, unresolved=False, ignore_finish=False):
        module, sdk = load_entrypoint(name)
        children, logs = [], []
        events = []
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            evidence = Path(temporary) / "evidence"

            def launch(argv, **options):
                logs.append(options["stdout"])
                code = "import time; time.sleep(60)"
                if success:
                    code = "from pathlib import Path; import time; Path('child-ready').touch()\nwhile not Path('finish').exists(): time.sleep(0.005)"
                if ignore_finish:
                    code = "import signal,time; from pathlib import Path; signal.signal(signal.SIGTERM,signal.SIG_IGN); Path('child-ready').touch(); time.sleep(60)"
                child = REAL_POPEN([sys.executable, "-I", "-c", code],
                                   stdout=options["stdout"], stderr=options["stderr"],
                                   cwd=Path(options["stdout"].name).parent, env={},
                                   start_new_session=options.get("start_new_session", False))
                children.append(child)
                # Reproduce the original timeout without waiting two minutes.
                real_wait = child.wait
                cap = 0.2 if ignore_finish else 5 if success else 0.05
                def wait(timeout=None):
                    if ignore_finish:
                        events.append("separate_process_wait")
                    return real_wait(timeout=min(timeout, cap) if timeout is not None else cap)
                child.wait = wait
                return child

            def ready(path, process, timeout, **options):
                directory = path.parent
                if success:
                    deadline = time.monotonic() + 5
                    while not (directory / "child-ready").exists() and time.monotonic() < deadline:
                        time.sleep(0.005)
                    self.assertTrue((directory / "child-ready").exists())
                (directory / "authority-contract.json").write_text('{"synthetic": true}')
                (directory / "capability.json").write_text("synthetic-capability")
                (directory / "command.json").write_bytes(b"synthetic-command")
                (directory / "revoked").touch()
                facts = {"useful_completion": True, "source_label_retained": True,
                         "unauthorized_effects": 0, "duplicate_effects": 0,
                         "workload_effects": 1, "effects": 2, "revoked": True}
                (directory / "native-evidence.json").write_text(json.dumps(facts))
                return "http://127.0.0.1:20096"

            stack.enter_context(patch.dict(sys.modules, {"chio_sdk": sdk,
                                                         "chio_sdk.recovery_host": sdk.recovery_host}))
            stack.enter_context(patch.object(sys, "argv", [name, "--checkout", temporary,
                                                           "--evidence", str(evidence)]))
            stack.enter_context(patch.object(subprocess, "Popen", launch))
            stack.enter_context(patch.object(module, "wait_endpoint", ready))
            if success:
                complete = {"category": "complete", "command_id": "synthetic-command",
                            "workflow_id": "synthetic-workflow", "effect": "complete",
                            "control": "active", "release": "released"}
                refused = {"category": "refused", "error_code": "recovery.authority_denied"}
                def completed_trial(session, model, task):
                    session.attempts = 1
                    model.call([])
                    return {"category": "complete"}
                async def completed_graph(session, model, task):
                    return completed_trial(session, model, task)
                async def completed_host(session, revoked):
                    session.attempts = 3
                    return {"first": complete, "replay": complete, "revoked": refused}
                def completed_crew(session):
                    session.attempts += 1
                    return complete if session.attempts < 3 else refused
                module.graph_trial, module.crew_trial = completed_graph, completed_trial
                module.graph_case, module.crew_action = completed_host, completed_crew
            if unresolved:
                stack.enter_context(patch.object(os, "killpg", side_effect=PermissionError("synthetic secret")))
            if ignore_finish:
                real_touch, real_killpg = Path.touch, os.killpg
                def touch(path, *args, **kwargs):
                    if path.name == "finish":
                        events.append("finish")
                    return real_touch(path, *args, **kwargs)
                def signal_group(group, number):
                    if number:
                        events.append(number)
                    return real_killpg(group, number)
                stack.enter_context(patch.object(Path, "touch", touch))
                stack.enter_context(patch.object(os, "killpg", signal_group))
            # Cooperative children need time to observe finish and shut down
            # under load. Forced-cleanup controls retain short stage budgets.
            if hasattr(module, "owned_native_process"):
                owner = module.owned_native_process
                def short_owner(*args, **kwargs):
                    grace = 0.2 if ignore_finish else 5 if success and not unresolved else 0.05
                    kwargs.update(grace_seconds=grace, terminate_seconds=0.1, kill_seconds=2)
                    return owner(*args, **kwargs)
                stack.enter_context(patch.object(module, "owned_native_process", short_owner))
            output = io.StringIO()
            try:
                with redirect_stdout(output):
                    if success and not unresolved and not ignore_finish:
                        module.main()
                    else:
                        with self.assertRaises(BaseException) as caught:
                            module.main()
                        if ignore_finish:
                            self.assertEqual(events, ["finish", signal.SIGTERM, signal.SIGKILL],
                                             "body must not add a separate wait or restart shutdown")
                            self.assertIn("native_cleanup.forced_termination", str(caught.exception))
                        elif unresolved and success:
                            self.assertIn("native_cleanup.unresolved", str(caught.exception))
                        else:
                            self.assertIsInstance(caught.exception, ValueError, "cleanup must preserve primary refusal")
                            self.assertEqual(str(caught.exception), reason)
                            if unresolved:
                                self.assertIn("native_cleanup.unresolved", " ".join(caught.exception.__notes__))
                if success and not unresolved and not ignore_finish:
                    report = json.loads((evidence / "result.json").read_text())
                    expected = 8 if name == "preflight" else 2
                    self.assertTrue(report["passed"])
                    self.assertEqual(len(report["cases"]), expected)
                    self.assertEqual(len(children), expected)
                else:
                    self.assertEqual(len(children), 1, "failure must refuse the next trial")
                    self.assertFalse((evidence / "result.json").exists(), "failure cannot publish success")
                    self.assertNotIn("passed", output.getvalue(), "cleanup failure cannot print success")
                if not unresolved:
                    self.assertTrue(all(child.poll() is not None for child in children), "children must be reaped")
                self.assertTrue(all(log.closed for log in logs), "diagnostic logs must close")
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                        REAL_POPEN.wait(child, timeout=2)
                for log in logs:
                    log.close()

    def test_preflight_invalid_result_preserves_failure_and_reaps_running_child(self):
        self.check_trial("preflight", "qualification.preflight_model_free_completion")

    def test_host_invalid_result_preserves_failure_and_reaps_running_child(self):
        self.check_trial("host_acceptance", "qualification.host_tool_budget")

    def test_successful_preflight_completes_all_owned_trials(self):
        self.check_trial("preflight", success=True)

    def test_successful_host_acceptance_completes_all_owned_trials(self):
        self.check_trial("host_acceptance", success=True)

    def test_preflight_unresolved_cleanup_cannot_report_success_or_start_next_trial(self):
        self.check_trial("preflight", success=True, unresolved=True)

    def test_host_unresolved_cleanup_cannot_report_success_or_start_next_trial(self):
        self.check_trial("host_acceptance", success=True, unresolved=True)

    def test_preflight_unresolved_cleanup_preserves_primary_refusal(self):
        self.check_trial("preflight", "qualification.preflight_model_free_completion", unresolved=True)

    def test_host_unresolved_cleanup_preserves_primary_refusal(self):
        self.check_trial("host_acceptance", "qualification.host_tool_budget", unresolved=True)

    def test_preflight_body_and_finalizer_share_shutdown_deadline(self):
        self.check_trial("preflight", success=True, ignore_finish=True)

    def test_host_body_and_finalizer_share_shutdown_deadline(self):
        self.check_trial("host_acceptance", success=True, ignore_finish=True)


if __name__ == "__main__":
    unittest.main()
