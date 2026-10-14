"""Real benign child processes must stay inside the version probe lifetime."""
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

HELPER = Path(__file__).resolve().parents[1] / "check-kani-toolchain.sh"
if "--helper" in sys.argv:
    index = sys.argv.index("--helper")
    HELPER = Path(sys.argv[index + 1]).resolve()
    del sys.argv[index:index + 2]

VERSION = "Kani Rust Verifier 0.68.0 (kani-0.68.0) (cargo plugin)\n" \
          "using rustc 1.100.0-nightly (8925ea358 2026-08-20) " \
          "(commit 8925ea35 2026-08-20) with LLVM 22.1.0\nCBMC 6.11.0\n"


class ProbeLifecycleTest(unittest.TestCase):
    def run_probe(self, mode):
        body = HELPER.read_text().split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        with tempfile.TemporaryDirectory(prefix="chio-kani-probe-child-") as temporary:
            work = Path(temporary)
            cargo = work / "cargo"
            cargo.write_text(
                "#!" + sys.executable + "\n"
                "import os,subprocess,sys,time\nfrom pathlib import Path\n"
                "mode=os.environ['PROBE_FIXTURE_MODE']\n"
                "if mode!='healthy':\n"
                " child=subprocess.Popen([sys.executable,'-c',"
                "\"import os,time;from pathlib import Path;time.sleep(3);"
                "Path(os.environ['PROBE_FIXTURE_FINISHED']).write_text('finished')\"],"
                "stdout=subprocess.DEVNULL if mode=='closed' else None,"
                "stderr=subprocess.DEVNULL if mode=='closed' else None)\n"
                " Path(os.environ['PROBE_FIXTURE_PID']).write_text(str(child.pid))\n"
                "print(os.environ['PROBE_FIXTURE_VERSION'],end='',flush=True)\n"
                "if mode in ('pipe','interrupt'):time.sleep(3)\n"
            )
            cargo.chmod(0o755)
            namespace = {"__name__": "probe_lifecycle_control"}
            original_popen = subprocess.Popen
            processes = []
            cancelled = threading.Event()
            interrupts = []

            class OwnedControlProcess(original_popen):
                def __init__(self, *args, **kwargs):
                    # Isolation for the old direct-process implementation too.
                    kwargs["start_new_session"] = True
                    super().__init__(*args, **kwargs)
                    processes.append(self)
                    if mode == "interrupt":
                        def interrupt_after_child():
                            limit = time.monotonic() + 1
                            while not cancelled.is_set() and not (work / "pid").exists():
                                if time.monotonic() >= limit:
                                    return
                                cancelled.wait(0.01)
                            if not cancelled.is_set():
                                os.kill(os.getpid(), signal.SIGINT)
                        thread = threading.Thread(target=interrupt_after_child)
                        interrupts.append(thread)
                        thread.start()

                def communicate(self, *args, **kwargs):
                    timeout = kwargs.get("timeout")
                    if timeout is not None:
                        kwargs["timeout"] = min(timeout, 1.5)
                    return super().communicate(*args, **kwargs)

            environment = {"PATH": str(work) + os.pathsep + os.environ.get("PATH", ""),
                           "PROBE_FIXTURE_MODE": mode, "PROBE_FIXTURE_PID": str(work / "pid"),
                           "PROBE_FIXTURE_FINISHED": str(work / "finished"),
                           "PROBE_FIXTURE_VERSION": VERSION}
            failed = False
            interrupted = False
            began = time.monotonic()
            try:
                with patch.dict(os.environ, environment), \
                     patch.object(subprocess, "Popen", OwnedControlProcess), redirect_stdout(io.StringIO()):
                    try:
                        exec(compile(body, str(HELPER), "exec"), namespace)
                        if "main" in namespace:
                            namespace["PROBE_TIMEOUT_SECONDS"] = 1.5
                            namespace["DRAIN_TIMEOUT_SECONDS"] = 1
                            namespace["main"]()
                    except SystemExit:
                        failed = True
                    except KeyboardInterrupt:
                        failed = True
                        interrupted = True
                elapsed = time.monotonic() - began
                if mode != "healthy":
                    self.assertTrue((work / "pid").exists(), "benign child prerequisite was not reached")
                pid = int((work / "pid").read_text()) if (work / "pid").exists() else None
                active = False
                if pid is not None:
                    limit = time.monotonic() + 0.5
                    while True:
                        try:
                            os.kill(pid, 0)
                        except ProcessLookupError:
                            break
                        if time.monotonic() >= limit:
                            active = True
                            break
                        time.sleep(0.01)
                return failed, elapsed, active, (work / "finished").exists(), interrupted, all(process.returncode is not None for process in processes)
            finally:
                cancelled.set()
                for thread in interrupts:
                    thread.join(timeout=1)
                for process in processes:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.communicate(timeout=1)
                    except (OSError, ValueError, subprocess.TimeoutExpired):
                        for stream in [process.stdout, process.stderr]:
                            if stream is not None:
                                stream.close()
                        process.wait(timeout=1)

    def test_timeout_kills_descendant_and_drains_its_inherited_pipe(self):
        failed, elapsed, active, finished, _, _ = self.run_probe("pipe")
        self.assertTrue(failed)
        self.assertLess(elapsed, 2.5)
        self.assertFalse(active)
        self.assertFalse(finished)

    def test_successful_leader_cannot_leave_a_detached_output_child(self):
        failed, elapsed, active, finished, _, _ = self.run_probe("closed")
        self.assertTrue(failed)
        self.assertLess(elapsed, 2.5)
        self.assertFalse(active)
        self.assertFalse(finished)

    def test_interrupted_probe_kills_descendant_and_reaps_the_direct_child(self):
        failed, elapsed, active, finished, interrupted, reaped = self.run_probe("interrupt")
        self.assertTrue(interrupted)
        self.assertTrue(reaped)
        self.assertTrue(failed)
        self.assertLess(elapsed, 2.5)
        self.assertFalse(active)
        self.assertFalse(finished)

    def test_healthy_version_probe_finishes_without_descendants(self):
        failed, elapsed, active, finished, _, _ = self.run_probe("healthy")
        self.assertFalse(failed)
        self.assertLess(elapsed, 2.5)
        self.assertFalse(active)
        self.assertFalse(finished)


if __name__ == "__main__":
    unittest.main(verbosity=2)
