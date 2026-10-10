"""Bounded lifecycle contracts for fixture-owned local subprocess groups."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.find_spec("owned_native_process")
if SPEC is not None:
    import owned_native_process as lifecycle
else:
    lifecycle = None


class OwnedNativeProcessTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(lifecycle, "missing common subprocess lifecycle owner")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.children = []
        self.addCleanup(self.rescue)

    def rescue(self):
        for process in self.children:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)

    def owner(self, code, **options):
        return lifecycle.owned_native_process(
            [sys.executable, "-I", "-c", code], cwd=self.directory, env={},
            log_path=self.directory / "native.log", finish_path=self.directory / "finish",
            grace_seconds=options.pop("grace_seconds", 0.05),
            terminate_seconds=options.pop("terminate_seconds", 0.1),
            kill_seconds=options.pop("kill_seconds", 0.3), **options)

    def wait_ready(self, path):
        deadline = time.monotonic() + 2
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue(path.exists(), "dummy child did not become ready")

    def test_finish_allows_successful_child_to_exit_and_closes_log(self):
        code = "from pathlib import Path; import time\nwhile not Path('finish').exists(): time.sleep(0.005)"
        with self.owner(code, grace_seconds=1) as owner:
            process, log = owner.process, owner.log
            self.children.append(process)
            self.assertEqual(os.getpgid(process.pid), process.pid)
            self.assertNotEqual(process.pid, os.getpgrp())
        self.assertEqual(process.returncode, 0)
        self.assertTrue(log.closed)

    def test_ignored_finish_and_termination_escalate_to_kill_and_reap(self):
        code = "import signal,time; from pathlib import Path; signal.signal(signal.SIGTERM,signal.SIG_IGN); Path('ready').touch(); time.sleep(60)"
        with self.assertRaisesRegex(lifecycle.NativeProcessCleanupError, "forced_termination"):
            with self.owner(code) as owner:
                process, log = owner.process, owner.log
                self.children.append(process)
                self.wait_ready(self.directory / "ready")
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertTrue(log.closed)

    def test_primary_failure_survives_finish_failure_with_closed_diagnostics(self):
        primary = ValueError("synthetic.primary")
        with self.assertRaises(ValueError) as caught:
            with self.owner("import time; time.sleep(60)") as owner:
                process, log = owner.process, owner.log
                self.children.append(process)
                (self.directory / "finish").symlink_to(self.directory / "missing" / "finish")
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertIn("native_cleanup.finish_publication_failed", " ".join(primary.__notes__))
        self.assertNotIn(str(self.directory), " ".join(primary.__notes__))
        self.assertIsNotNone(process.returncode)
        self.assertTrue(log.closed)

    def test_owned_descendant_is_terminated_when_launcher_exits_first(self):
        code = """import subprocess,sys
from pathlib import Path
child = subprocess.Popen([sys.executable, '-I', '-c', "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)"], env={})
Path('descendant').write_text(str(child.pid))
"""
        with self.assertRaises(lifecycle.NativeProcessCleanupError):
            with self.owner(code) as owner:
                process, log = owner.process, owner.log
                self.children.append(process)
                self.wait_ready(self.directory / "descendant")
                process.wait(timeout=2)
                descendant = int((self.directory / "descendant").read_text())
        self.assertTrue(log.closed)
        with self.assertRaises(ProcessLookupError):
            os.kill(descendant, 0)

    def test_signals_are_confined_to_the_launched_group(self):
        calls = []
        real_killpg = os.killpg
        def signal_group(group, number):
            calls.append((group, number))
            return real_killpg(group, number)
        with patch.object(lifecycle.os, "killpg", signal_group):
            with self.assertRaises(lifecycle.NativeProcessCleanupError):
                with self.owner("import time; time.sleep(60)") as owner:
                    process, log = owner.process, owner.log
                    self.children.append(process)
        self.assertTrue(calls)
        self.assertEqual({group for group, _ in calls}, {process.pid})
        self.assertNotEqual(process.pid, os.getpgrp())

    def test_unresolved_cleanup_is_bounded_and_cannot_return_success(self):
        with patch.object(lifecycle.os, "killpg", side_effect=PermissionError("synthetic secret")):
            with self.assertRaises(lifecycle.NativeProcessCleanupError) as caught:
                with self.owner("import time; time.sleep(60)") as owner:
                    process, log = owner.process, owner.log
                    self.children.append(process)
        self.assertIn("native_cleanup.unresolved", str(caught.exception))
        self.assertNotIn("synthetic secret", str(caught.exception))
        self.assertTrue(log.closed)

    def test_shutdown_deadlines_share_the_first_clock_even_after_delayed_waits(self):
        process = Mock(returncode=-signal.SIGKILL)
        owner = lifecycle.NativeProcessOwner(process, None, self.directory / "finish", (2, 3, 5), [])
        deadlines = []
        clock = [100]

        def delayed_wait(child, deadline, errors):
            self.assertIs(child, process)
            deadlines.append(deadline)
            # Simulate arbitrary scheduling delay. Subsequent stages may not
            # reset their deadlines relative to the resumed clock.
            clock[0] += 100
            return len(deadlines) == 3

        with patch.object(lifecycle.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(lifecycle, "_wait_group", delayed_wait), \
             patch.object(lifecycle, "_signal_group") as signal_group:
            with self.assertRaisesRegex(lifecycle.NativeProcessCleanupError, "forced_termination") as first:
                owner.finish()
            with self.assertRaises(lifecycle.NativeProcessCleanupError) as repeated:
                owner.finish()
        self.assertIs(repeated.exception, first.exception)
        self.assertEqual(deadlines, [102, 105, 110])
        self.assertEqual([call.args[1] for call in signal_group.call_args_list],
                         [signal.SIGTERM, signal.SIGKILL])
        self.assertTrue((self.directory / "finish").is_file())

    def test_invalid_deadlines_refuse_before_log_or_child_creation(self):
        for option in ["grace_seconds", "terminate_seconds", "kill_seconds"]:
            for invalid in [float("nan"), float("inf"), -1, True, "1", 10 ** 400]:
                with self.subTest(option=option, invalid=repr(invalid)):
                    with self.assertRaisesRegex(ValueError, "native_cleanup.timeout"):
                        with self.owner("raise SystemExit(0)", **{option: invalid}):
                            self.fail("invalid timeout was accepted")
                    self.assertFalse((self.directory / "native.log").exists())

    def test_launch_failure_closes_opened_log(self):
        logs = []
        def fail_launch(*args, **options):
            logs.append(options["stdout"])
            raise OSError("synthetic.launch")
        with patch.object(lifecycle.subprocess, "Popen", fail_launch):
            with self.assertRaisesRegex(OSError, "synthetic.launch"):
                with self.owner(""):
                    self.fail("launch failure continued")
        self.assertTrue(logs[0].closed)

    def test_log_close_failure_preserves_primary_with_closed_diagnostic(self):
        real_open = Path.open
        logs = []
        class CloseFailure:
            def __init__(self, stream):
                self.stream = stream
            def __getattr__(self, name):
                return getattr(self.stream, name)
            def close(self):
                self.stream.close()
                raise OSError("synthetic secret")
        def open_log(path, *args, **options):
            stream = real_open(path, *args, **options)
            if path.name == "native.log":
                logs.append(stream)
                return CloseFailure(stream)
            return stream
        primary = ValueError("synthetic.primary")
        with patch.object(Path, "open", open_log):
            with self.assertRaises(ValueError) as caught:
                with self.owner("import time; time.sleep(60)") as owner:
                    process, log = owner.process, owner.log
                    self.children.append(process)
                    raise primary
        self.assertIs(caught.exception, primary)
        self.assertIn("native_cleanup.log_close_failed", " ".join(primary.__notes__))
        self.assertNotIn("synthetic secret", " ".join(primary.__notes__))
        self.assertTrue(logs[0].closed)
        self.assertIsNotNone(process.returncode)

    def test_keyboard_interrupt_in_trial_preserves_interruption_and_reaps(self):
        primary = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as caught:
            with self.owner("import time; time.sleep(60)") as owner:
                process, log = owner.process, owner.log
                self.children.append(process)
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertTrue(log.closed)
        self.assertIsNotNone(process.returncode)
        self.assertTrue((self.directory / "finish").is_file(),
                        "clock interruption must not skip possible finish publication")

    def test_explicit_finish_reuses_failure_without_restarting_shutdown(self):
        code = "import signal,time; from pathlib import Path; signal.signal(signal.SIGTERM,signal.SIG_IGN); Path('ready').touch(); time.sleep(60)"
        with self.assertRaises(lifecycle.NativeProcessCleanupError) as final:
            with self.owner(code) as owner:
                if isinstance(owner, tuple):
                    self.children.append(owner[0])
                else:
                    self.children.append(owner.process)
                self.assertTrue(hasattr(owner, "finish"), "missing owner-controlled finish operation")
                self.wait_ready(self.directory / "ready")
                with self.assertRaises(lifecycle.NativeProcessCleanupError) as first:
                    owner.finish()
                with patch.object(lifecycle.time, "monotonic", side_effect=AssertionError("clock restarted")):
                    with self.assertRaises(lifecycle.NativeProcessCleanupError) as repeated:
                        owner.finish()
                self.assertIs(repeated.exception, first.exception)
                raise first.exception
        self.assertIs(final.exception, first.exception)
        self.assertTrue(owner.log.closed)
        self.assertIsNotNone(owner.process.returncode)

    def test_explicit_finish_reuses_success_without_republishing_or_restarting(self):
        code = "from pathlib import Path; import time\nwhile not Path('finish').exists(): time.sleep(0.005)"
        with self.owner(code, grace_seconds=1) as owner:
            if isinstance(owner, tuple):
                self.children.append(owner[0])
            else:
                self.children.append(owner.process)
            self.assertTrue(hasattr(owner, "finish"), "missing owner-controlled finish operation")
            self.assertEqual(owner.finish(), 0)
            with patch.object(lifecycle.time, "monotonic", side_effect=AssertionError("clock restarted")), \
                 patch.object(Path, "touch", side_effect=AssertionError("finish republished")):
                self.assertEqual(owner.finish(), 0)
        self.assertTrue(owner.log.closed)

    def test_running_leader_does_not_require_a_racing_group_probe(self):
        real_killpg = os.killpg
        code = "from pathlib import Path; import time\nwhile not Path('finish').exists(): time.sleep(0.005)\ntime.sleep(0.05)"
        with self.owner(code, grace_seconds=1) as owner:
            self.children.append(owner.process)
            def probe(group, number):
                if number == 0 and owner.process.poll() is None:
                    raise PermissionError("synthetic exiting-group probe race")
                return real_killpg(group, number)
            with patch.object(lifecycle.os, "killpg", probe):
                try:
                    self.assertEqual(owner.finish(), 0)
                except lifecycle.NativeProcessCleanupError as error:
                    self.fail("running leader triggered unnecessary group probe: " + str(error))
        self.assertTrue(owner.log.closed)

    def test_caught_finish_interruption_still_refuses_context_success(self):
        with self.assertRaisesRegex(lifecycle.NativeProcessCleanupError, "native_cleanup.unresolved"):
            with self.owner("import time; time.sleep(60)") as owner:
                self.children.append(owner.process)
                # An interruption can occur between entering the operation and
                # its first guarded system call. Catching it must not clear custody.
                with patch.object(owner, "_shutdown", side_effect=KeyboardInterrupt()):
                    with self.assertRaises(KeyboardInterrupt):
                        owner.finish()
        self.assertTrue(owner.log.closed)

    def test_uncaught_finish_interruption_preserves_primary_and_closes_log(self):
        primary = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as caught:
            with self.owner("import time; time.sleep(60)") as owner:
                self.children.append(owner.process)
                with patch.object(owner, "_shutdown", side_effect=primary):
                    owner.finish()
        self.assertIs(caught.exception, primary)
        self.assertTrue(owner.log.closed)
        self.assertIn("native_cleanup.unresolved", " ".join(getattr(primary, "__notes__", [])))

    def test_interrupted_cleanup_cannot_replace_primary_or_leave_log_open(self):
        primary = ValueError("synthetic.primary")
        real_clock = time.monotonic
        calls = []
        def interrupted_clock():
            calls.append(None)
            if len(calls) == 2:
                raise KeyboardInterrupt()
            return real_clock()
        with patch.object(lifecycle.time, "monotonic", interrupted_clock):
            with self.assertRaises(BaseException) as caught:
                with self.owner("import time; time.sleep(60)") as owner:
                    process, log = owner.process, owner.log
                    self.children.append(process)
                    raise primary
        self.assertIs(caught.exception, primary)
        self.assertTrue(log.closed)
        self.assertIsNotNone(process.returncode)

    def test_interruption_starting_cleanup_kills_owned_child_and_preserves_primary(self):
        primary = ValueError("synthetic.primary")
        real_clock = time.monotonic
        with patch.object(lifecycle.time, "monotonic", side_effect=[KeyboardInterrupt(), real_clock()]):
            with self.assertRaises(BaseException) as caught:
                with self.owner("import time; time.sleep(60)") as owner:
                    process, log = owner.process, owner.log
                    self.children.append(process)
                    raise primary
        self.assertIs(caught.exception, primary)
        self.assertTrue(log.closed)
        self.assertIsNotNone(process.returncode)
        self.assertTrue((self.directory / "finish").is_file(),
                        "clock interruption must not skip possible finish publication")


if __name__ == "__main__":
    unittest.main()
