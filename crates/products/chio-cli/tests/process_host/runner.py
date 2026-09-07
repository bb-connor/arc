"""Real native runner, worker crashes, host death, bounded retries and output."""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from chio_process import ProcessClient, WorkerError

HERE = Path(__file__).resolve().parent


def write(path, value):
    with path.open("w") as output:
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())


def worker():
    bootstrap = json.load(sys.stdin)
    assert bootstrap["schema"] == "chio.process.worker-bootstrap.v1"
    connection = bootstrap["connection"]
    data = bootstrap["input"]
    directory = Path(data["directory"])
    role, attempt = connection["process_id"], bootstrap["attempt"]
    client = ProcessClient(connection["socket_path"], connection["credential"])
    write(
        directory / f"{role}-{attempt}-started.json",
        {"pid": os.getpid(), "connection": connection},
    )
    if role == "reader":
        result = client.invoke(
            "handoff",
            "chio-ipc",
            "send_jobs",
            {"message_key": "job", "payload": {"text": "ready"}},
        )
        assert result["verdict"] == "allow", result
        write(directory / f"send-{attempt}.json", result)
        if attempt == 1:
            if data["host_crash"]:
                while True:
                    time.sleep(0.05)
            os._exit(77)
        if data["host_crash"]:
            while not (directory / "continue").exists():
                time.sleep(0.05)
        (directory / "reader-completed").touch()
    else:
        assert (directory / "reader-completed").exists(), "dependency launched early"
        received = client.invoke(
            "read", "chio-ipc", "receive_jobs", {"after_sequence": "0", "limit": 1}
        )
        assert received["output"]["value"]["messages"][0]["payload"] == {
            "text": "ready"
        }
        result = client.invoke(
            "publish", "reports", "append", {"report": "one publication"}
        )
        write(directory / f"publish-{attempt}.json", result)
        assert result["verdict"] == "allow", result
        if attempt == 1:
            os._exit(76)
        assert (
            client.invoke("ack", "chio-ipc", "ack_jobs", {"through_sequence": "1"})[
                "verdict"
            ]
            == "allow"
        )
    print(connection["credential"], flush=True)
    sys.stdout.write("x" * 200_000)


def cancel_worker():
    bootstrap = json.load(sys.stdin)
    connection = bootstrap["connection"]
    client = ProcessClient(connection["socket_path"], connection["credential"])
    client.cancel()
    time.sleep(30)


def count_worker():
    bootstrap = json.load(sys.stdin)
    data = bootstrap["input"]
    with sqlite3.connect(Path(data["directory"]) / "concurrency.db", timeout=10) as db:
        db.execute("UPDATE counts SET active=active+1, peak=MAX(peak,active+1)")
        db.commit()
        deadline = time.monotonic() + 15
        while db.execute("SELECT peak FROM counts").fetchone()[0] < data["parallel"]:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        time.sleep(0.1)
        db.execute("UPDATE counts SET active=active-1")


def command(binary, *args, success=True):
    result = subprocess.run(
        [binary, "process", *map(str, args)], capture_output=True, text=True, timeout=90
    )
    assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
    return result


def wait_for(path, process):
    deadline = time.monotonic() + 45
    while not path.exists():
        assert process.poll() is None, process.communicate()
        assert time.monotonic() < deadline, path
        time.sleep(0.05)
    return json.loads(path.read_text())


def prepare(binary, directory, host_crash=False):
    directory.mkdir(mode=0o700)
    state = directory / "host"
    policy = directory / "policy.yaml"
    policy.write_text("""kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 2
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: reports
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
      - server: chio-ipc
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    host = {
        "schema": "chio.process.host.v1",
        "policy": str(policy),
        "servers": [
            {
                "id": "reports",
                "command": [
                    sys.executable,
                    str(HERE / "recovery.py"),
                    "--mcp",
                    str(directory / "publications.jsonl"),
                ],
            }
        ],
        "mailboxes": [{"id": "jobs"}],
        "limits": {"max_processes": 3, "max_depth": 1, "max_calls": 20},
        "children": [
            {
                "id": "reader",
                "parent": "root",
                "budget_share_bps": 4000,
                "tools": [{"server_id": "chio-ipc", "tool_name": "send_jobs"}],
            },
            {
                "id": "publisher",
                "parent": "root",
                "budget_share_bps": 4000,
                "tools": [
                    {"server_id": "chio-ipc", "tool_name": name}
                    for name in ("receive_jobs", "ack_jobs")
                ]
                + [{"server_id": "reports", "tool_name": "append"}],
            },
        ],
    }
    config = directory / "host.json"
    write(config, host)
    command(binary, "init", "--config", config, "--state", state)
    plan = {
        "schema": "chio.process.run.v1",
        "max_parallel": 1,
        "workers": [
            {
                "process": role,
                "command": [sys.executable, str(Path(__file__).resolve()), "--worker"],
                "cwd": str(directory),
                "input": {"directory": str(directory), "host_crash": host_crash},
                "depends_on": [] if role == "reader" else ["reader"],
                "max_attempts": 3,
                "timeout_seconds": 45,
            }
            for role in ("reader", "publisher")
        ],
    }
    plan_path = directory / "plan.json"
    write(plan_path, plan)
    return state, plan_path, plan


def exercise(binary, directory, host_crash):
    state, path, plan = prepare(binary, directory, host_crash)
    initial = json.loads(command(binary, "status", "--state", state).stdout)
    assert initial["run"] is None and initial["host_lock_held"] is False
    assert not (state / "run-status.json").exists()
    args = [binary, "process", "run", "--state", str(state), "--plan", str(path)]
    if host_crash:
        first = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        try:
            wait_for(directory / "send-1.json", first)
            old = json.loads((directory / "reader-1-started.json").read_text())
            live = json.loads(command(binary, "status", "--state", state).stdout)
            assert live["host_lock_held"] is True
            workers = {w["process"]: w for w in live["run"]["workers"]}
            assert workers["reader"]["state"] == "running"
            assert workers["publisher"]["waiting_on"] == ["reader"]
            assert workers["publisher"]["attempts"] == 0
            assert old["connection"]["credential"] not in json.dumps(live)
            first.kill()
            first.communicate(timeout=15)
            deadline = time.monotonic() + 10
            while True:
                status = Path(f"/proc/{old['pid']}/status")
                try:
                    process_status = status.read_text()
                except (FileNotFoundError, ProcessLookupError):
                    break
                if "\nState:\tZ" in process_status:
                    break
                assert time.monotonic() < deadline, "worker survived host death"
                time.sleep(0.05)
            before = (state / "runner.db").read_bytes()
            stopped = json.loads(command(binary, "status", "--state", state).stdout)
            assert stopped["host_lock_held"] is False
            assert stopped["run"] == live["run"], "inspection reconciled a dead host"
            assert (state / "runner.db").read_bytes() == before
        finally:
            if first.poll() is None:
                first.kill()
                first.communicate(timeout=10)
        resumed = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        try:
            new = wait_for(directory / "reader-2-started.json", resumed)
            observed = json.loads(command(binary, "status", "--state", state).stdout)
            assert observed["host_lock_held"] is True
            assert observed["run"]["run_id"] != live["run"]["run_id"]
            reader = next(
                w for w in observed["run"]["workers"] if w["process"] == "reader"
            )
            assert reader["attempts"] == 2 and reader["max_attempts"] == 3
            stale = ProcessClient(
                new["connection"]["socket_path"], old["connection"]["credential"]
            )
            try:
                stale.inspect()
                raise AssertionError("old credential accepted by resumed host")
            except WorkerError as failure:
                assert failure.code == "unauthenticated"
            (directory / "continue").touch()
            out, err = resumed.communicate(timeout=90)
            assert resumed.returncode == 0, (out, err)
            result = json.loads(out)
        finally:
            if resumed.poll() is None:
                resumed.kill()
                resumed.communicate(timeout=10)
    else:
        result = json.loads(
            command(binary, "run", "--state", state, "--plan", path).stdout
        )
    assert result["complete"]
    assert all(
        w["state"] == "completed" and w["attempts"] == 2 for w in result["workers"]
    )
    assert len((directory / "publications.jsonl").read_text().splitlines()) == 1
    for action in ("send", "publish"):
        first = json.loads((directory / f"{action}-1.json").read_text())
        second = json.loads((directory / f"{action}-2.json").read_text())
        assert first["receipt_json"] == second["receipt_json"]
    repeated = json.loads(
        command(binary, "run", "--state", state, "--plan", path).stdout
    )
    assert repeated == result
    completed = json.loads(command(binary, "status", "--state", state).stdout)
    assert completed["host_lock_held"] is False
    assert all(
        w["state"] == "completed" and not w["waiting_on"]
        for w in completed["run"]["workers"]
    )
    logs = command(
        binary, "logs", "--state", state, "--process", "reader", "--attempt", 2
    )
    assert "[REDACTED]" in json.loads(logs.stdout)["logs"]["stdout"]
    secrets = [
        json.loads(p.read_text())["connection"]["credential"]
        for p in directory.glob("*-started.json")
    ]
    for log in (state / "run-logs").iterdir():
        data = log.read_bytes()
        assert len(data) <= 65_536
        assert all(secret.encode() not in data for secret in secrets)
    assert all(secret not in logs.stdout for secret in secrets)
    plan["max_parallel"] = 2
    write(path, plan)
    rejected = command(binary, "run", "--state", state, "--plan", path, success=False)
    assert "plan or authority changed" in rejected.stderr


def concurrency(binary, directory, parallel):
    state, path, plan = prepare(binary, directory)
    with sqlite3.connect(directory / "concurrency.db") as db:
        db.execute("CREATE TABLE counts(active INTEGER, peak INTEGER)")
        db.execute("INSERT INTO counts VALUES(0,0)")
    plan["workers"][0]["depends_on"] = ["publisher"]
    write(path, plan)
    assert (
        "cycle"
        in command(
            binary, "run", "--state", state, "--plan", path, success=False
        ).stderr
    )
    assert not (state / "runner.db").exists()
    template = plan["workers"][0]
    plan["max_parallel"] = parallel
    plan["workers"] = [
        {
            **template,
            "process": role,
            "depends_on": [],
            "max_attempts": 1,
            "command": [sys.executable, str(Path(__file__).resolve()), "--count"],
            "input": {"directory": str(directory), "parallel": parallel},
        }
        for role in ("root", "reader", "publisher")
    ]
    write(path, plan)
    command(binary, "run", "--state", state, "--plan", path)
    with sqlite3.connect(directory / "concurrency.db") as db:
        assert db.execute("SELECT active,peak FROM counts").fetchone() == (0, parallel)


def unknown(binary, directory):
    state, path, _ = prepare(binary, directory)
    publications = directory / "publications.jsonl"
    publications.with_suffix(".pause").touch()
    process = subprocess.Popen(
        [binary, "process", "run", "--state", str(state), "--plan", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        wait_for(publications, process)
        process.kill()
        process.communicate(timeout=15)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
    publications.with_suffix(".pause").unlink()
    failed = command(binary, "run", "--state", state, "--plan", path, success=False)
    report = json.loads(failed.stdout)
    assert not report["complete"]
    assert (
        next(w for w in report["workers"] if w["process"] == "publisher")["state"]
        == "failed"
    )
    assert len(publications.read_text().splitlines()) == 1, (
        "uncertain effect was redispatched"
    )

    for attempt in (2, 3):
        response = json.loads((directory / f"publish-{attempt}.json").read_text())
        assert response["verdict"] == "deny"
        assert response["output"] is None
        assert "OutcomeUnknownAfterDispatch" in response["reason"]


def cancelled(binary, directory):
    state, path, plan = prepare(binary, directory)
    plan["workers"] = [plan["workers"][0]]
    plan["workers"][0]["command"] = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--cancel",
    ]
    write(path, plan)
    result = command(binary, "run", "--state", state, "--plan", path, success=False)
    assert "cancelled" in result.stderr
    report = json.loads(result.stdout)
    assert report["workers"][0]["outcome"] == "process_cancelled"
    assert report["workers"][0]["attempts"] == 1
    assert report["workers"][0]["state"] == "failed"


def exhausted(binary, directory):
    state, path, plan = prepare(binary, directory)
    plan["workers"] = [plan["workers"][0]]
    plan["workers"][0].update(
        command=[sys.executable, "-c", "import time; time.sleep(30)"],
        timeout_seconds=1,
        max_attempts=1,
    )
    write(path, plan)
    first = command(binary, "run", "--state", state, "--plan", path, success=False)
    report = json.loads(first.stdout)
    assert report["workers"][0] == {
        "process": "reader",
        "state": "failed",
        "attempts": 1,
        "outcome": "timeout",
    }
    assert (
        json.loads(
            command(
                binary, "run", "--state", state, "--plan", path, success=False
            ).stdout
        )
        == report
    )
    with sqlite3.connect(state / "runner.db") as db:
        assert db.execute("SELECT attempts FROM run_workers").fetchone()[0] == 1
    diagnostic = json.loads(command(binary, "status", "--state", state).stdout)
    worker = diagnostic["run"]["workers"][0]
    assert worker["state"] == "failed" and worker["outcome"] == "timeout"
    assert worker["attempts"] == worker["max_attempts"] == 1


def diagnostic_boundaries(binary, directory):
    missing = directory / "absent"
    command(binary, "status", "--state", missing, success=False)
    assert not missing.exists()
    state, path, plan = prepare(binary, directory)
    plan["workers"] = [plan["workers"][0]]
    plan["workers"][0]["command"] = [sys.executable, "-c", "print('diagnostic')"]
    write(path, plan)
    command(binary, "run", "--state", state, "--plan", path)
    snapshot = state / "run-status.json"
    saved = snapshot.read_bytes()
    for value in (b"{", b"x" * (1024 * 1024 + 1), b'{"schema":"unknown"}'):
        snapshot.write_bytes(value)
        command(binary, "status", "--state", state, success=False)
    snapshot.write_bytes(saved)
    snapshot.chmod(0o644)
    command(binary, "status", "--state", state, success=False)
    snapshot.chmod(0o600)
    linked = directory / "linked-status.json"
    snapshot.rename(linked)
    snapshot.symlink_to(linked)
    command(binary, "status", "--state", state, success=False)
    snapshot.unlink()
    linked.rename(snapshot)
    os.link(snapshot, linked)
    command(binary, "status", "--state", state, success=False)
    linked.unlink()
    command(binary, "status", "--state", state)
    stdout = state / "run-logs/reader-1.stdout"
    stdout.unlink()
    stdout.symlink_to(state / "host.json")
    command(
        binary,
        "logs",
        "--state",
        state,
        "--process",
        "reader",
        "--attempt",
        1,
        success=False,
    )
    stdout.unlink()
    os.mkfifo(stdout, mode=0o600)
    # O_NONBLOCK prevents a crafted FIFO from hanging the local observer.
    command(
        binary,
        "logs",
        "--state",
        state,
        "--process",
        "reader",
        "--attempt",
        1,
        success=False,
    )
    stdout.unlink()
    stdout.write_bytes(b"x" * 65_537)
    command(
        binary,
        "logs",
        "--state",
        state,
        "--process",
        "reader",
        "--attempt",
        1,
        success=False,
    )
    command(
        binary,
        "logs",
        "--state",
        state,
        "--process",
        "../../host",
        "--attempt",
        1,
        success=False,
    )


if __name__ == "__main__":
    os.umask(0o077)
    if sys.argv[1] == "--worker":
        worker()
    elif sys.argv[1] == "--count":
        count_worker()
    elif sys.argv[1] == "--cancel":
        cancel_worker()
    else:
        with tempfile.TemporaryDirectory(prefix="chio-run-") as temporary:
            root = Path(temporary)
            exercise(sys.argv[1], root / "automatic", False)
            exercise(sys.argv[1], root / "host-crash", True)
            exhausted(sys.argv[1], root / "exhausted")
            concurrency(sys.argv[1], root / "serial", 1)
            concurrency(sys.argv[1], root / "parallel", 2)
            unknown(sys.argv[1], root / "unknown")
            cancelled(sys.argv[1], root / "cancelled")
            diagnostic_boundaries(sys.argv[1], root / "diagnostics")
        print(
            json.dumps(
                {
                    "automatic_restart": True,
                    "host_crash_recovery": True,
                    "persistent_attempt_limit": True,
                    "concurrency_limit": True,
                    "unknown_effect_not_repeated": True,
                }
            )
        )
