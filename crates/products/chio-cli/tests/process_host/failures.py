"""Qualify independent worker completion after a terminal peer failure."""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from chio_process import ProcessClient

HERE = Path(__file__).resolve()


def write(path, value):
    path.write_text(json.dumps(value))


def worker():
    bootstrap = json.load(sys.stdin)
    data = bootstrap["input"]
    if "configuration" in data:
        data = data["configuration"]
    directory = Path(data["directory"])
    role = data["role"]
    attempt = bootstrap["attempt"]
    write(directory / f"{role}-{attempt}-started.json", {"pid": os.getpid()})
    connection = bootstrap["connection"]
    client = ProcessClient(connection["socket_path"], connection["credential"])
    if role == "first":
        if data.get("cancel"):
            client.cancel()
            time.sleep(30)
        if data.get("concurrent"):
            while not (directory / "independent-1-result.json").exists():
                time.sleep(0.01)
        sys.exit(data.get("exit_code", 1))
    if role == "parent":
        spawned = client.invoke(
            "spawn-failing-child",
            "chio-process",
            "spawn_failing",
            {"input": {}, "budget_share_bps": 1000},
        )
        write(directory / "spawn.json", spawned)
        assert spawned["verdict"] == "allow"
        child = spawned["output"]["value"]["process"]
        joined = client.invoke(
            "join-failing-child",
            "chio-process",
            "wait_children",
            {"children": [child]},
        )
        assert (
            joined["verdict"] == "allow" and not joined["output"]["value"]["complete"]
        )
        write(
            directory / "join.json", {"child": child, "spawn": spawned, "join": joined}
        )
        checkpoint = client.inspect()["checkpoint"]
        client.checkpoint(checkpoint["revision"], {"waiting": child})
        sys.exit(75)
    result = client.invoke(
        "publish-result",
        "chio-ipc",
        "send_results",
        {"message_key": role, "payload": {"worker": role, "complete": True}},
        known_outcome_only=True,
    )
    assert result["verdict"] == "allow"
    write(directory / f"{role}-{attempt}-result.json", result)
    if role == "independent" and data.get("concurrent"):
        while not (directory / "release").exists():
            time.sleep(0.01)
    write(directory / f"{role}-{attempt}-calls.json", client.inspect()["tree_calls"])


def invoke(binary, *arguments, success=True):
    result = subprocess.run(
        [binary, *map(str, arguments)],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert (result.returncode == 0) == success, (
        arguments,
        result.stdout,
        result.stderr,
    )
    return json.loads(result.stdout) if result.stdout.strip() else None


def prepare(
    binary, directory, *, policy=None, concurrent=False, adaptive=False, cancel=False
):
    directory.mkdir(mode=0o700)
    (directory / "policy.yaml").write_text("""kernel:
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
      - server: chio-process
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    routes = [{"server_id": "chio-ipc", "tool_name": "send_results"}]
    definitions = (
        [("parent", []), ("dependent", ["parent"]), ("independent", [])]
        if adaptive
        else [
            ("first", []),
            ("dependent", ["first"]),
            ("transitive", ["dependent"]),
            ("independent", []),
            ("gather", ["independent"]),
        ]
    )
    config = {
        "schema": "chio.process.host.v1",
        "policy": str(directory / "policy.yaml"),
        "servers": [],
        "mailboxes": [{"id": "results"}],
        "limits": {"max_processes": 8, "max_depth": 2, "max_calls": 16},
        "children": [
            {
                "id": role,
                "parent": "root",
                "budget_share_bps": 1800,
                "tools": routes
                + (
                    [
                        {"server_id": "chio-process", "tool_name": name}
                        for name in ("spawn_failing", "wait_children")
                    ]
                    if role == "parent"
                    else []
                ),
            }
            for role, _ in definitions
        ],
    }
    if adaptive:
        config["spawn_templates"] = [
            {"id": "failing", "tools": routes, "max_budget_share_bps": 1000}
        ]
    write(directory / "config.json", config)
    initialized = invoke(
        binary,
        "process",
        "init",
        "--config",
        directory / "config.json",
        "--state",
        directory / "host",
    )
    (directory / "kernel.pub").write_text(initialized["kernel_key"])
    workers = [
        {
            "process": role,
            "command": [sys.executable, str(HERE), "--worker"],
            "cwd": str(directory),
            "input": {
                "directory": str(directory),
                "role": role,
                "concurrent": concurrent,
                "cancel": cancel,
            },
            "depends_on": depends,
            "max_attempts": 2 if role == "independent" else 1,
            "timeout_seconds": 20,
        }
        for role, depends in definitions
    ]
    plan = {
        "schema": "chio.process.run.v1",
        "max_parallel": 2 if concurrent else 1,
        "workers": workers,
    }
    if policy is not None:
        plan["failure_policy"] = policy
    if adaptive:
        plan["templates"] = [
            {
                "id": "failing",
                "command": [sys.executable, str(HERE), "--worker"],
                "cwd": str(directory),
                "input": {"directory": str(directory), "role": "first"},
                "max_attempts": 1,
                "timeout_seconds": 20,
            }
        ]
    write(directory / "plan.json", plan)
    return plan


def run(binary, directory):
    return invoke(
        binary,
        "process",
        "run",
        "--state",
        directory / "host",
        "--plan",
        directory / "plan.json",
        success=False,
    )


def states(report):
    assert report["schema"] == "chio.process.run-report.v1" and not report["complete"]
    assert (
        report["pending_container_records"] == report["abandoned_socket_intents"] == 0
    )
    return {item["process"]: item for item in report["workers"]}


def assert_isolated(report, directory, independent_attempts=1):
    records = states(report)
    assert records["first"]["state"] == "failed" and records["first"]["attempts"] == 1
    assert records["first"]["outcome"] == "exit_1"
    for role in ("dependent", "transitive"):
        assert records[role]["state"] == "failed"
        assert (
            records[role]["outcome"] == "dependency_failed"
            and records[role]["attempts"] == 0
        )
        assert not list(directory.glob(role + "-*-started.json"))
    assert records["independent"]["state"] == records["gather"]["state"] == "completed"
    assert records["independent"]["attempts"] == independent_attempts
    assert records["gather"]["attempts"] == 1
    assert json.loads((directory / "gather-1-calls.json").read_text()) == 2


def verify(binary, directory):
    originals = [
        json.loads(p.read_text())["receipt_json"]
        for p in sorted(directory.glob("*-result.json"))
    ]
    if (directory / "join.json").exists():
        join = json.loads((directory / "join.json").read_text())
        originals.extend(join[name]["receipt_json"] for name in ("spawn", "join"))
    receipts = list(dict.fromkeys(originals))
    (directory / "receipts.ndjson").write_text("\n".join(receipts) + "\n")
    checked = invoke(
        binary,
        "--json",
        "receipt",
        "verify",
        "--input",
        directory / "receipts.ndjson",
        "--trusted-kernel-pubkey",
        directory / "kernel.pub",
    )
    assert checked["receipts_verified"] == len(receipts)
    return checked


def waiting_for_failure(directory, process):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        assert process.poll() is None, process.communicate()
        path = directory / "host/run-status.json"
        if path.exists():
            snapshot = json.loads(path.read_text())
            workers = {w["process"]: w for w in snapshot["workers"]}
            if all(
                workers[role]["state"] == "failed"
                for role in ("first", "dependent", "transitive")
            ):
                assert workers["independent"]["state"] == "running"
                assert (directory / "independent-1-result.json").exists()
                return
        time.sleep(0.02)
    raise AssertionError("Independent worker did not survive terminal peer failure")


def main(binary):
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix="chio-independent-workers-"))
    print(
        "Private worker failure qualification: " + str(root),
        file=sys.stderr,
        flush=True,
    )
    baseline = root / "default"
    plan = prepare(binary, baseline)
    result = states(run(binary, baseline))
    assert (
        result["first"]["state"] == "failed" and result["independent"]["attempts"] == 0
    )
    # An explicit default preserves the old serialized plan binding.
    plan["failure_policy"] = "stop"
    write(baseline / "plan.json", plan)
    assert states(run(binary, baseline)) == result
    plan["failure_policy"] = "continue_independent"
    write(baseline / "plan.json", plan)
    refused = subprocess.run(
        [
            binary,
            "process",
            "run",
            "--state",
            str(baseline / "host"),
            "--plan",
            str(baseline / "plan.json"),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert refused.returncode != 0 and "run plan or authority changed" in refused.stderr
    assert not (baseline / "independent-1-started.json").exists()

    evidence = []
    for concurrent, crash in ((False, False), (True, False), (True, True)):
        directory = root / f"independent-{concurrent}-{crash}"
        prepare(binary, directory, policy="continue_independent", concurrent=concurrent)
        if concurrent:
            process = subprocess.Popen(
                [
                    binary,
                    "process",
                    "run",
                    "--state",
                    str(directory / "host"),
                    "--plan",
                    str(directory / "plan.json"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                waiting_for_failure(directory, process)
                if crash:
                    process.kill()
                    process.communicate(timeout=20)
                (directory / "release").touch()
                if crash:
                    report = run(binary, directory)
                else:
                    stdout, stderr = process.communicate(timeout=30)
                    assert process.returncode != 0, (stdout, stderr)
                    report = json.loads(stdout)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=20)
        else:
            report = run(binary, directory)
        assert_isolated(report, directory, independent_attempts=2 if crash else 1)
        if crash:
            one = json.loads((directory / "independent-1-result.json").read_text())
            two = json.loads((directory / "independent-2-result.json").read_text())
            assert one["receipt_json"] == two["receipt_json"]
        before = {p.name: p.read_bytes() for p in directory.glob("*-started.json")}
        assert states(run(binary, directory)) == states(report)
        assert {
            p.name: p.read_bytes() for p in directory.glob("*-started.json")
        } == before
        evidence.append(
            {
                "concurrent": concurrent,
                "host_crash": crash,
                "report": report,
                "verification": verify(binary, directory),
            }
        )

    directory = root / "adaptive"
    prepare(binary, directory, policy="continue_independent", adaptive=True)
    report = run(binary, directory)
    records = states(report)
    child = json.loads((directory / "join.json").read_text())["child"]
    assert records[child]["state"] == "failed" and records[child]["attempts"] == 1
    assert (
        records["parent"]["outcome"]
        == records["dependent"]["outcome"]
        == "dependency_failed"
    )
    assert records["parent"]["attempts"] == records["parent"]["suspensions"] == 1
    assert records["dependent"]["attempts"] == 0
    assert records["independent"]["state"] == "completed"
    assert states(run(binary, directory)) == records
    evidence.append(
        {
            "adaptive_join_failure": True,
            "report": report,
            "verification": verify(binary, directory),
        }
    )

    directory = root / "cancelled"
    prepare(binary, directory, policy="continue_independent", cancel=True)
    report = states(run(binary, directory))
    assert report["first"]["outcome"] == "process_cancelled"
    assert report["independent"]["attempts"] == 0
    assert not (directory / "independent-1-started.json").exists()

    for i, invalid in enumerate(("ignore", None, False)):
        directory = root / f"invalid-{i}"
        plan = prepare(binary, directory)
        plan["failure_policy"] = invalid
        write(directory / "plan.json", plan)
        refused = subprocess.run(
            [
                binary,
                "process",
                "run",
                "--state",
                str(directory / "host"),
                "--plan",
                str(directory / "plan.json"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert refused.returncode != 0
        assert not (directory / "host/runner.db").exists()
        assert not list(directory.glob("*-started.json"))
    print(
        json.dumps(
            {
                "private_state": str(root),
                "cases": evidence,
                "default_stop_preserved": True,
                "plan_drift_refused": True,
                "cancellation_still_stops_run": True,
                "invalid_policy_refused": True,
            }
        )
    )


if __name__ == "__main__":
    if sys.argv[1] == "--worker":
        worker()
    else:
        main(sys.argv[1])
