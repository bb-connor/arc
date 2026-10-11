"""Lifecycle regressions use real worker exits, SQLite and filesystem faults."""

import ctypes
import errno
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import runner
from runner import command, write

BINARY = sys.argv.pop(1)


def prepare(binary, directory):
    directory.mkdir(mode=0o700)
    state = directory / "host"
    policy = directory / "policy.yaml"
    policy.write_text("""kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 1
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: chio-ipc
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    config = directory / "config.json"
    write(
        config,
        {
            "schema": "chio.process.host.v1",
            "policy": str(policy),
            "mailboxes": [{"id": "jobs"}],
            "limits": {"max_processes": 3, "max_depth": 1, "max_calls": 10},
            "children": [
                {
                    "id": name,
                    "parent": "root",
                    "budget_share_bps": 4000,
                    "tools": [{"server_id": "chio-ipc", "tool_name": "send_jobs"}],
                }
                for name in ("reader", "publisher")
            ],
        },
    )
    command(binary, "init", "--config", config, "--state", state)
    plan = {
        "schema": "chio.process.run.v1",
        "max_parallel": 1,
        "workers": [
            {
                "process": "reader",
                "command": [sys.executable, "-c", "import json,sys; json.load(sys.stdin)"],
                "cwd": str(directory),
                "depends_on": [],
                "max_attempts": 3,
                "timeout_seconds": 10,
            }
        ],
    }
    path = directory / "plan.json"
    write(path, plan)
    return state, path, plan


class NativeLifecycle(unittest.TestCase):
    def test_cancelled_worker_preserves_terminal_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "case"
            state, path, plan = prepare(BINARY, directory)
            pid_file = directory / "cancelled.pid"
            plan["workers"][0]["command"] = [sys.executable, runner.__file__, "--cancel"]
            plan["workers"][0]["input"] = {"pid_file": str(pid_file)}
            write(path, plan)
            result = command(BINARY, "run", "--state", state, "--plan", path, success=False)
            with sqlite3.connect(state / "runner.db") as db:
                self.assertEqual(
                    db.execute("SELECT state,attempts,outcome FROM run_workers").fetchone(),
                    ("failed", 1, "process_cancelled"),
                    result.stdout + result.stderr,
                )
            self.assertFalse((Path("/proc") / pid_file.read_text()).exists())

    def test_failed_attempt_retains_bounded_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            state, path, plan = prepare(BINARY, Path(temporary) / "case")
            plan["workers"][0]["max_attempts"] = 1
            plan["workers"][0]["command"] = [
                sys.executable,
                "-c",
                "import json,subprocess,sys; json.load(sys.stdin); "
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(2)']); "
                "print('failed-work'); sys.exit(1)",
            ]
            write(path, plan)
            command(BINARY, "run", "--state", state, "--plan", path, success=False)
            self.assertTrue(
                (state / "run-logs/reader-1.stdout").exists(), "failed attempt lost its diagnostics"
            )
            self.assertEqual((state / "run-logs/reader-1.stdout").read_text(), "failed-work\n")

    def test_reaped_exit_survives_interruption_during_descendant_log_drain(self):
        for unfinished in (False, True):
            with self.subTest(unfinished=unfinished), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "case"
                state, path, plan = prepare(BINARY, directory)
                code = f"""
import json, os, pathlib, sys, time
json.load(sys.stdin)
root = pathlib.Path({str(directory)!r})
with (root / 'effects').open('a') as marker:
    marker.write('effect\\n')
if os.fork() == 0:
    (root / 'descendant.pid').write_text(str(os.getpid()))
    while root.exists() and not (root / 'release').exists():
        time.sleep(0.001)
    os._exit(0)
(root / 'worker.pid').write_text(str(os.getpid()))
if {unfinished!r}:
    while root.exists() and not (root / 'release').exists():
        time.sleep(0.001)
os._exit(0)
"""
                plan["workers"][0]["command"] = [sys.executable, "-c", code]
                write(path, plan)
                host = subprocess.Popen(
                    [BINARY, "process", "run", "--state", str(state), "--plan", str(path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    deadline = time.monotonic() + 10
                    while not all(
                        (directory / name).exists() and (directory / name).read_text().isdigit()
                        for name in ("worker.pid", "descendant.pid")
                    ):
                        self.assertIsNone(host.poll())
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.001)
                    worker = Path("/proc") / (directory / "worker.pid").read_text()
                    if not unfinished:
                        # Disappearance proves the real wait4 reaped the worker.
                        # Its descendant still owns stdout, so log EOF cannot occur.
                        while worker.exists():
                            self.assertLess(time.monotonic(), deadline)
                            time.sleep(0.001)
                    self.assertTrue(
                        (Path("/proc") / (directory / "descendant.pid").read_text()).exists()
                    )
                    host.send_signal(signal.SIGTERM)
                    host.communicate(timeout=10)
                    self.assertNotEqual(host.returncode, 0)
                    with sqlite3.connect(state / "runner.db") as db:
                        self.assertEqual(
                            db.execute("SELECT state,attempts,outcome FROM run_workers").fetchone(),
                            ("pending", 1, "runner_interrupted")
                            if unfinished
                            else ("completed", 1, "exit_0"),
                        )
                        self.assertGreater(
                            db.execute("SELECT peak_resident_bytes FROM run_workers").fetchone()[0],
                            0,
                            "reaper's final resource accounting was lost",
                        )
                    (directory / "release").touch()
                    if not unfinished:
                        command(BINARY, "run", "--state", state, "--plan", path)
                        self.assertEqual((directory / "effects").read_text(), "effect\n")
                        with sqlite3.connect(state / "runner.db") as db:
                            self.assertEqual(
                                db.execute("SELECT attempts FROM run_workers").fetchone(), (1,)
                            )
                finally:
                    (directory / "release").touch()
                    if host.poll() is None:
                        host.kill()
                    host.communicate(timeout=10)

    def test_invalid_container_plans_precede_journal(self):
        for template in (False, True):
            for fault in ("image", "cwd", "resources"):
                with (
                    self.subTest(template=template, fault=fault),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    state, path, plan = prepare(BINARY, Path(temporary) / "case")
                    worker = {
                        "command": ["/usr/local/bin/python"],
                        "cwd": "/work",
                        "max_attempts": 1,
                        "timeout_seconds": 1,
                        "container": {"image": "sha256:" + "1" * 64},
                    }
                    if fault == "image":
                        worker["container"]["image"] = "python:latest"
                    elif fault == "cwd":
                        worker["cwd"] = "/tmp"
                    else:
                        worker["resources"] = {"max_open_files": 128}
                    if template:
                        plan["templates"] = [{"id": "child", **worker}]
                    else:
                        plan["workers"] = [{"process": "reader", **worker}]
                    write(path, plan)
                    result = command(BINARY, "run", "--state", state, "--plan", path, success=False)
                    self.assertIn("container workers require", result.stderr)
                    self.assertFalse((state / "runner.db").exists())

    def test_definite_exec_refusal_refunds_only_unexecuted_reservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "case"
            state, path, plan = prepare(BINARY, directory)
            script = directory / "bad-interpreter"
            script.write_text("#!/definitely/absent/interpreter\n")
            script.chmod(0o700)
            plan["workers"][0]["command"] = [str(script)]
            write(path, plan)
            result = command(BINARY, "run", "--state", state, "--plan", path, success=False)
            with sqlite3.connect(state / "runner.db") as db:
                self.assertEqual(
                    db.execute("SELECT state,attempts FROM run_workers").fetchone(), ("pending", 0)
                )
            self.assertIn("No such file", result.stderr)

    def test_pidfd_support_and_post_spawn_failure_identity(self):
        class Filter(ctypes.Structure):
            _fields_ = [
                ("code", ctypes.c_ushort),
                ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte),
                ("k", ctypes.c_uint),
            ]

        class Program(ctypes.Structure):
            _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]

        for own_probe in (False, True):
            with self.subTest(own_probe=own_probe), tempfile.TemporaryDirectory() as temporary:
                state, path, _ = prepare(BINARY, Path(temporary) / "case")

                def restrict_pidfd(own_probe=own_probe):
                    # Kernel syscall seam: 434 is pidfd_open on supported Linux
                    # x86_64/aarch64 hosts. Keep the own-process probe available in
                    # the post-spawn case; all child opens return ENOSYS.
                    instructions = [
                        (0x20, 0, 0, 0),
                        (0x15, 0, 3, 434),
                        (0x20, 0, 0, 16),
                        (0x15, 1 if own_probe else 0, 0, os.getpid()),
                        (0x06, 0, 0, 0x50000 | errno.ENOSYS),
                        (0x06, 0, 0, 0x7FFF0000),
                    ]
                    filters = (Filter * len(instructions))(
                        *(Filter(*entry) for entry in instructions)
                    )
                    program = Program(len(filters), filters)
                    libc = ctypes.CDLL(None, use_errno=True)
                    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program)):
                        raise OSError(ctypes.get_errno(), "seccomp test filter")

                result = subprocess.run(
                    [BINARY, "process", "run", "--state", str(state), "--plan", str(path)],
                    preexec_fn=restrict_pidfd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Function not implemented", result.stderr)
                if own_probe:
                    with sqlite3.connect(state / "runner.db") as db:
                        self.assertEqual(
                            db.execute("SELECT state,attempts FROM run_workers").fetchone(),
                            ("failed", 1),
                        )
                else:
                    self.assertFalse(
                        (state / "runner.db").exists(), "unsupported pidfd host reserved an attempt"
                    )

    def test_unstartable_plan_precedes_journal(self):
        for fault in ("missing", "cwd", "permission"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "case"
                state, path, plan = prepare(BINARY, directory)
                worker = plan["workers"][0]
                plan["workers"] = [worker]
                if fault == "missing":
                    worker["command"] = [str(directory / "absent")]
                elif fault == "cwd":
                    worker["cwd"] = str(path)
                else:
                    executable = directory / "nonexecutable"
                    executable.write_text("#!/bin/sh\nexit 0\n")
                    executable.chmod(0o600)
                    worker["command"] = [str(executable)]
                write(path, plan)
                command(BINARY, "run", "--state", state, "--plan", path, success=False)
                self.assertFalse(
                    (state / "runner.db").exists(), "invalid immutable launch spent an attempt"
                )

    def test_known_exit_survives_log_and_status_faults(self):
        for fault in ("log", "status"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "case"
                state, path, plan = prepare(BINARY, directory)
                worker = plan["workers"][0]
                plan["workers"] = [worker]
                if fault == "log":
                    logs = state / "run-logs"
                    logs.mkdir(mode=0o700)
                    (logs / "reader-1.stdout").mkdir(mode=0o700)
                    code = "import json,sys; json.load(sys.stdin)"
                else:
                    code = (
                        "import json,sys,pathlib; json.load(sys.stdin); "
                        f"p=pathlib.Path({str(state / 'run-status.json')!r}); "
                        "p.unlink(); p.mkdir(mode=0o700)"
                    )
                    plan["workers"].append(
                        {
                            **worker,
                            "process": "publisher",
                            "depends_on": ["reader"],
                            "command": [
                                sys.executable,
                                "-c",
                                "import json,sys; json.load(sys.stdin)",
                            ],
                        }
                    )
                worker["command"] = [sys.executable, "-c", code]
                write(path, plan)
                command(BINARY, "run", "--state", state, "--plan", path, success=False)
                with sqlite3.connect(state / "runner.db") as db:
                    self.assertEqual(
                        db.execute(
                            "SELECT state,attempts,outcome FROM run_workers WHERE process='reader'"
                        ).fetchone(),
                        ("completed", 1, "exit_0"),
                    )
                    if fault == "status":
                        self.assertEqual(
                            db.execute(
                                "SELECT state,attempts,outcome FROM run_workers "
                                "WHERE process='publisher'"
                            ).fetchone(),
                            ("completed", 1, "exit_0"),
                        )


if __name__ == "__main__":
    unittest.main()
