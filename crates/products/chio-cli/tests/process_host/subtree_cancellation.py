"""Native workers retain independent authority when a process subtree is cancelled."""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from chio_process import ProcessClient, WorkerError


def write(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value))
    temporary.replace(path)


def worker():
    bootstrap = json.load(sys.stdin)
    connection = bootstrap["connection"]
    directory = Path(bootstrap["input"]["directory"])
    role = connection["process_id"]
    client = ProcessClient(connection["socket_path"], connection["credential"])

    def invoke(stage):
        response = client.invoke(
            stage,
            "chio-ipc",
            "send_results",
            {"message_key": f"{role}-{stage}", "payload": {"process": role}},
            known_outcome_only=True,
        )
        assert response["verdict"] == "allow", response
        return response

    write(
        directory / f"{role}-ready.json",
        {"pid": os.getpid(), "connection": connection, "receipt": invoke("before")},
    )
    while not (directory / "begin").exists():
        time.sleep(0.01)
    if role == "A":
        if bootstrap["input"]["failure"]:
            os._exit(67)
        try:
            cancelled = client.cancel()
            assert cancelled["cancelled_processes"] == 2, cancelled
        except WorkerError as refusal:
            assert refusal.code == "unauthenticated", refusal
    if role in ("A", "A1"):
        time.sleep(60)
        raise AssertionError("cancelled worker was not stopped")
    while not (directory / "release").exists():
        time.sleep(0.01)
    if bootstrap["input"]["fail_after_cancel"]:
        if role == "B":
            os._exit(68)
        time.sleep(60)
        raise AssertionError("independent failure did not stop the parent")
    write(directory / f"{role}-after.json", invoke("after"))


def alive(pid):
    try:
        return "\nState:\tZ" not in Path(f"/proc/{pid}/status").read_text()
    except (FileNotFoundError, ProcessLookupError):
        return False


def wait_until(predicate, host, message):
    deadline = time.monotonic() + 45
    while not predicate():
        assert host.poll() is None, (message, *host.communicate())
        assert time.monotonic() < deadline, message
        time.sleep(0.02)


def subtree_cancelled(state):
    with sqlite3.connect(state / "process.db") as database:
        return database.execute(
            "SELECT id,state FROM processes WHERE id IN ('A','A1') ORDER BY id"
        ).fetchall() == [("A", "cancelled"), ("A1", "cancelled")]


def subtree_credentials_removed(state):
    with sqlite3.connect(state / "process.db") as database:
        return database.execute(
            "SELECT COUNT(*) FROM worker_credentials WHERE process_id IN ('A','A1')"
        ).fetchone() == (0,)


def mailbox_effects(state):
    with sqlite3.connect(state / "mailboxes.db") as database:
        return database.execute(
            "SELECT message_key,sender,payload FROM mailbox_messages ORDER BY message_key"
        ).fetchall()


def prepare(binary, directory, failure, pending, fail_after_cancel):
    directory.chmod(0o700)
    policy = directory / "policy.yaml"
    policy.write_text("""kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 2
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: chio-ipc
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    routes = [{"server_id": "chio-ipc", "tool_name": "send_results"}]
    config = directory / "config.json"
    write(config, {
        "schema": "chio.process.host.v1",
        "policy": str(policy),
        "servers": [],
        "mailboxes": [{"id": "results"}],
        "limits": {"max_processes": 4, "max_depth": 2, "max_calls": 16},
        "children": [
            {"id": "A", "parent": "root", "budget_share_bps": 4000, "tools": routes},
            {"id": "B", "parent": "root", "budget_share_bps": 4000, "tools": routes},
            {"id": "A1", "parent": "A", "budget_share_bps": 2000, "tools": routes},
        ],
    })
    state = directory / "host"
    initialized = subprocess.run(
        [binary, "process", "init", "--config", str(config), "--state", str(state)],
        capture_output=True, text=True, timeout=45, check=False,
    )
    assert initialized.returncode == 0, (initialized.stdout, initialized.stderr)
    plan = directory / "plan.json"
    write(plan, {
        "schema": "chio.process.run.v1",
        "max_parallel": 3 if pending else 4,
        "failure_policy": "stop",
        "workers": [
            {
                "process": role,
                "command": [sys.executable, str(Path(__file__).resolve()), "--worker"],
                "cwd": str(directory),
                "input": {
                    "directory": str(directory),
                    "failure": failure,
                    "fail_after_cancel": fail_after_cancel,
                },
                "depends_on": [],
                "max_attempts": 1,
                "timeout_seconds": 60,
            }
            for role in ("root", "A", "B", "A1")
        ],
    })
    return state, subprocess.Popen(
        [binary, "process", "run", "--state", str(state), "--plan", str(plan)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


class SubtreeCancellation(unittest.TestCase):
    def exercise(self, failure=False, pending=False, fail_after_cancel=False):
        with tempfile.TemporaryDirectory(prefix="chio-subtree-") as temporary:
            directory = Path(temporary)
            state, host = prepare(BINARY, directory, failure, pending, fail_after_cancel)
            workers = {}
            try:
                launched = ("root", "A", "B") if pending else ("root", "A", "B", "A1")
                cancelled = ("A",) if pending else ("A", "A1")
                for role in launched:
                    path = directory / f"{role}-ready.json"
                    wait_until(path.exists, host, f"{role} did not invoke before the cut")
                    workers[role] = json.loads(path.read_text())
                self.assertTrue(all(alive(worker["pid"]) for worker in workers.values()))
                with sqlite3.connect(state / "process.db") as database:
                    identities = database.execute("SELECT id,parent_id,capability FROM processes ORDER BY id").fetchall()
                    self.assertEqual(database.execute("SELECT tree_calls FROM processes WHERE id='root'").fetchone(), (len(launched),))
                (directory / "begin").touch()
                if failure:
                    out, err = host.communicate(timeout=45)
                    self.assertNotEqual(host.returncode, 0, (out, err))
                    report = {row["process"]: row for row in json.loads(out)["workers"]}
                    self.assertEqual(report["A"]["outcome"], "exit_67")
                    self.assertTrue(all(not alive(worker["pid"]) for worker in workers.values()))
                    self.assertFalse((directory / "root-after.json").exists())
                    self.assertFalse((directory / "B-after.json").exists())
                    return
                wait_until(lambda: subtree_cancelled(state), host, "A did not cancel its subtree")
                wait_until(
                    lambda: all(not alive(workers[role]["pid"]) for role in cancelled),
                    host,
                    "cancelled workers remain alive",
                )
                wait_until(
                    lambda: subtree_credentials_removed(state),
                    host,
                    "cancelled credentials remain live",
                )
                self.assertIsNone(host.poll(), "subtree cancellation stopped the host")
                for role in ("root", "B"):
                    self.assertTrue(alive(workers[role]["pid"]), f"unrelated {role} was stopped")
                for role in cancelled:
                    connection = workers[role]["connection"]
                    stale = ProcessClient(connection["socket_path"], connection["credential"])
                    with self.assertRaises(WorkerError) as refusal:
                        stale.invoke("after", "chio-ipc", "send_results", {
                            "message_key": f"{role}-after", "payload": {"process": role},
                        })
                    self.assertEqual(refusal.exception.code, "unauthenticated")
                with sqlite3.connect(state / "process.db") as database:
                    self.assertEqual(database.execute("SELECT id,parent_id,capability FROM processes ORDER BY id").fetchall(), identities)
                    self.assertEqual(database.execute("SELECT id,state FROM processes ORDER BY id").fetchall(), [("A", "cancelled"), ("A1", "cancelled"), ("B", "running"), ("root", "running")])
                    self.assertEqual(database.execute("SELECT tree_calls FROM processes WHERE id='root'").fetchone(), (len(launched),))
                (directory / "release").touch()
                if fail_after_cancel:
                    out, err = host.communicate(timeout=45)
                    self.assertNotEqual(host.returncode, 0, (out, err))
                    rows = {row["process"]: row for row in json.loads(out)["workers"]}
                    for role in ("A", "A1"):
                        self.assertEqual(rows[role]["outcome"], "process_cancelled")
                    self.assertEqual(rows["B"]["outcome"], "exit_68")
                    self.assertTrue(all(not alive(worker["pid"]) for worker in workers.values()))
                    self.assertFalse((directory / "root-after.json").exists())
                    self.assertFalse((directory / "B-after.json").exists())
                    return
                for role in ("root", "B"):
                    wait_until((directory / f"{role}-after.json").exists, host, f"{role} lost invocation authority")
                out, err = host.communicate(timeout=45)
                self.assertNotEqual(host.returncode, 0, (out, err))
                report = json.loads(out)
                self.assertFalse(report["complete"])
                rows = {row["process"]: row for row in report["workers"]}
                for role in ("root", "B"):
                    self.assertEqual((rows[role]["state"], rows[role]["attempts"]), ("completed", 1))
                for role in ("A", "A1"):
                    self.assertEqual((rows[role]["state"], rows[role]["attempts"], rows[role]["outcome"]), ("failed", int(role in launched), "process_cancelled"))
                    if role in launched:
                        self.assertGreater(rows[role]["peak_resident_bytes"], 0)
                    else:
                        self.assertEqual((rows[role]["peak_resident_bytes"], rows[role]["cpu_ms"]), (0, 0))
                with sqlite3.connect(state / "process.db") as database:
                    self.assertEqual(database.execute("SELECT tree_calls FROM processes WHERE id='root'").fetchone(), (len(launched) + 2,))
                    self.assertEqual(database.execute("SELECT process_id,COUNT(*) FROM process_calls GROUP BY process_id ORDER BY process_id").fetchall(), sorted((role, 2 if role in ("root", "B") else 1) for role in launched))
                self.assertEqual(
                    [(key, sender, json.loads(payload)) for key, sender, payload in mailbox_effects(state)],
                    sorted(
                        (f"{role}-{stage}", role, {"process": role})
                        for role in launched
                        for stage in (["before", "after"] if role in ("root", "B") else ["before"])
                    ),
                )
                if pending:
                    self.assertFalse((directory / "A1-ready.json").exists())
                self.assertTrue(all(not alive(worker["pid"]) for worker in workers.values()))
            finally:
                if host.poll() is None:
                    host.terminate()
                    try:
                        host.communicate(timeout=15)
                    except subprocess.TimeoutExpired:
                        host.kill()
                        host.communicate(timeout=15)

    def test_independent_failure_keeps_stop_policy(self):
        self.exercise(failure=True)

    def test_subtree_cancellation_preserves_parent_and_sibling(self):
        self.exercise()

    def test_subtree_cancellation_prevents_pending_descendant_launch(self):
        self.exercise(pending=True)

    def test_independent_failure_stops_parent_after_subtree_cancellation(self):
        self.exercise(fail_after_cancel=True)


if __name__ == "__main__":
    if sys.argv[1] == "--worker":
        worker()
    else:
        BINARY = sys.argv.pop(1)
        unittest.main()
