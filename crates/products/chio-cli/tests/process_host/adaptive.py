"""Real native fork/join across Python and Node, including host and worker death."""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from runner import command, wait_for, write

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[4]


def route(server, tool):
    return {"server_id": server, "tool_name": tool}


def prepare(binary, directory, **options):
    directory.mkdir(mode=0o700)
    policy = directory / "policy.yaml"
    policy.write_text("""kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 4
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: chio-process
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
      - server: chio-ipc
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    send = route("chio-ipc", "send_results")
    host = {
        "schema": "chio.process.host.v1",
        "policy": str(policy),
        "mailboxes": [{"id": "results"}],
        "limits": {
            "max_processes": 2 if options.get("probe") == "limit" else 8,
            "max_depth": 3,
            "max_calls": 100,
        },
        "spawn_templates": [
            {
                "id": "branch",
                "max_budget_share_bps": 4000,
                "tools": [send]
                + [
                    route("chio-process", tool)
                    for tool in ("spawn_leaf", "spawn_broad", "wait_children")
                ],
            },
            {"id": "leaf", "max_budget_share_bps": 6000, "tools": [send]},
            {
                "id": "broad",
                "max_budget_share_bps": 4000,
                "tools": [route("chio-ipc", "receive_results")],
            },
        ],
    }
    if options.get("probe") == "cycle":
        host["children"] = [
            {
                "id": "dependent",
                "parent": "root",
                "tools": [send],
                "budget_share_bps": 1000,
            }
        ]
    config = directory / "host.json"
    write(config, host)
    state = directory / "host"
    initialized = json.loads(
        command(binary, "init", "--config", config, "--state", state).stdout
    )
    (directory / "kernel.pub").write_text(initialized["kernel_key"] + "\n")
    data = {"directory": str(directory), **options}
    python = [sys.executable, str(HERE / "adaptive_worker.py")]
    node = [
        shutil.which("node"),
        str(HERE / "adaptive_leaf.mjs"),
        (REPOSITORY / "sdks/typescript/packages/process/index.mjs").as_uri(),
    ]
    plan = {
        "schema": "chio.process.run.v1",
        "max_parallel": 1,
        "workers": [
            {
                "process": "root",
                "command": python,
                "cwd": str(directory),
                "input": data,
                "max_attempts": 1 if options.get("probe") == "suspend_limit" else 4,
                "timeout_seconds": 45,
                **(
                    {"max_suspensions": 1}
                    if options.get("probe") == "suspend_limit"
                    else {}
                ),
            }
        ],
        "templates": [
            {
                "id": template,
                "command": python if template == "branch" else node,
                "cwd": str(directory),
                "input": data,
                "max_attempts": 3,
                "timeout_seconds": 30,
            }
            for template in ("branch", "leaf", "broad")
        ],
    }
    if options.get("probe") == "cycle":
        plan["workers"].append(
            {
                "process": "dependent",
                "command": [sys.executable, "-c", "import sys; sys.stdin.read()"],
                "cwd": str(directory),
                "input": {},
                "depends_on": ["root"],
                "max_attempts": 1,
                "timeout_seconds": 10,
            }
        )
    path = directory / "plan.json"
    write(path, plan)
    return state, path, plan


def exercise(binary, directory, host_crash):
    state, path, plan = prepare(binary, directory, recover=True, host_crash=host_crash)
    with sqlite3.connect(state / "process.db") as db:
        assert db.execute("SELECT count(*) FROM processes").fetchone()[0] == 1
    args = [binary, "process", "run", "--state", str(state), "--plan", str(path)]
    if host_crash:
        first = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        try:
            wait_for(directory / "root-branch-1.json", first)
            status = json.loads(command(binary, "status", "--state", state).stdout)
            assert status["host_lock_held"]
            first.kill()
            first.communicate(timeout=15)
        finally:
            if first.poll() is None:
                first.kill()
                first.communicate(timeout=15)
    result = command(binary, "run", "--state", state, "--plan", path)
    report = json.loads(result.stdout)
    assert report["complete"] and len(report["workers"]) == 5, report
    # The root failed once, suspended once and completed on its third launch;
    # the branch suspended once. Suspensions leave the failure budget intact.
    launches = {
        w["process"]: (w["attempts"], w["suspensions"]) for w in report["workers"]
    }
    assert launches["root"] == (3, 1) and launches["dyn_1"] == (2, 1), launches
    status = json.loads(command(binary, "status", "--state", state).stdout)["run"]
    root = next(w for w in status["workers"] if w["process"] == "root")
    assert (root["max_attempts"], root["max_suspensions"]) == (4, 64), root
    assert json.loads((directory / "result.json").read_text()) == {
        "values": [2, 3, 5],
        "total": 10,
    }
    original = json.loads((directory / "root-branch-1.json").read_text())
    replay = json.loads((directory / "root-branch-2.json").read_text())
    assert original["receipt_json"] == replay["receipt_json"]
    with sqlite3.connect(state / "process.db") as db:
        assert db.execute("SELECT count(*) FROM process_child_work").fetchone()[0] == 4
        assert (
            db.execute("SELECT count(*) FROM process_delegation_keys").fetchone()[0]
            == 5
        )
        parents = dict(
            db.execute("SELECT process_id,parent_id FROM process_child_work")
        )
        assert (
            parents["dyn_1"] == "root"
            and list(parents.values()).count("root") == 2
            and list(parents.values()).count("dyn_1") == 2
        ), parents
        retried_child = db.execute(
            "SELECT process_id FROM process_child_work WHERE json_extract(input,'$.value')=2"
        ).fetchone()[0]
    child_send = [
        json.loads((directory / f"{retried_child}-send-{attempt}.json").read_text())
        for attempt in (1, 2)
    ]
    assert child_send[0]["receipt_json"] == child_send[1]["receipt_json"]
    receipts = sorted(
        {
            json.loads(file.read_text())["receipt_json"]
            for file in directory.glob("*.json")
            if "receipt_json" in json.loads(file.read_text())
        }
    )
    receipt_path = directory / "receipts.jsonl"
    receipt_path.write_text("\n".join(receipts) + "\n")
    key_path = directory / "kernel.pub"
    verified = subprocess.run(
        [
            binary,
            "receipt",
            "verify",
            "--input",
            str(receipt_path),
            "--trusted-kernel-pubkey",
            str(key_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert verified.returncode == 0, (verified.stdout, verified.stderr)
    timestamps = {
        file.name: file.stat().st_mtime_ns for file in directory.glob("*-started.json")
    }
    assert json.loads(command(binary, "run", "--state", state, "--plan", path).stdout)[
        "complete"
    ]
    assert timestamps == {
        file.name: file.stat().st_mtime_ns for file in directory.glob("*-started.json")
    }
    plan["templates"][0]["input"]["changed"] = True
    write(path, plan)
    command(binary, "run", "--state", state, "--plan", path, success=False)
    return len(receipts)


def main():
    os.umask(0o077)
    binary = sys.argv[1]
    base = Path(tempfile.mkdtemp(prefix="chio-adaptive-"))
    try:
        counts = [
            exercise(binary, base / mode, mode == "host-death")
            for mode in ("worker-death", "host-death")
        ]
        for probe in ("cycle", "quota", "limit", "cancel", "suspend_limit"):
            directory = base / probe
            state, path, _ = prepare(binary, directory, probe=probe)
            command(
                binary,
                "run",
                "--state",
                state,
                "--plan",
                path,
                success=probe not in ("cancel", "suspend_limit"),
            )
            marker = (
                "probe-entered.json" if probe == "cancel" else "probe-completed.json"
            )
            assert json.loads((directory / marker).read_text())["probe"] == probe
            with sqlite3.connect(state / "process.db") as db:
                assert db.execute("SELECT count(*) FROM process_child_work").fetchone()[
                    0
                ] == (0 if probe == "cycle" else 1)
                if probe == "cancel":
                    assert (
                        db.execute(
                            "SELECT count(*) FROM processes WHERE state='running'"
                        ).fetchone()[0]
                        == 0
                    )
            if probe == "suspend_limit":
                report = json.loads(command(binary, "status", "--state", state).stdout)[
                    "run"
                ]
                root = next(
                    worker
                    for worker in report["workers"]
                    if worker["process"] == "root"
                )
                # One suspension is allowed and resumed; the second exceeds the
                # ceiling while the failure budget of one launch is untouched.
                assert (
                    root["state"] == "failed"
                    and root["attempts"] == 2
                    and root["suspensions"] == 2
                    and root["max_suspensions"] == 1
                    and root["outcome"] == "suspended"
                )
                # The child ran once between the two suspensions; nothing
                # launched after the ceiling failed the root.
                started = sorted(p.name for p in directory.glob("*-started.json"))
                assert started == [
                    "dyn_1-1-started.json",
                    "root-1-started.json",
                    "root-2-started.json",
                ], started
        print(
            json.dumps(
                {
                    "adaptive_children": 4,
                    "max_parallel": 1,
                    "verified_receipts": counts,
                    "probes": ["cycle", "quota", "limit", "cancel", "suspend_limit"],
                }
            )
        )
    except BaseException:
        print(f"Failed qualification state retained at {base}", file=sys.stderr)
        raise
    else:
        shutil.rmtree(base)


if __name__ == "__main__":
    main()
