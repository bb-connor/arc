"""Native model-selected fork/join with bounded worker slots and durable mailbox handoffs."""

import json
import shutil
import sqlite3
import sys

from journal_profiles import provider, requests
from qualify import command, host_death, verify, write
from swarm_server import outputs


def route(server, tool):
    return {"server_id": server, "tool_name": tool}


def prepare(binary, directory, consumer, mode, endpoint):
    (directory / "policy.yaml").write_text("""kernel:
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
      - server: chio-process
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
      - server: chio-ipc
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    write(
        directory / "host.json",
        {
            "schema": "chio.process.host.v1",
            "policy": "policy.yaml",
            "servers": [
                {
                    "id": "reports",
                    "command": [
                        sys.executable,
                        str(consumer / "server.py"),
                        "--database",
                        str(directory / "publications.db"),
                    ],
                }
            ],
            "mailboxes": [
                {
                    "id": "results",
                    "limits": {
                        "max_pending_messages": 2,
                        "max_messages": 2,
                        "max_pending_bytes": 4096,
                        "max_message_bytes": 2048,
                    },
                }
            ],
            "limits": {"max_processes": 3, "max_depth": 1, "max_calls": 100},
            "spawn_templates": [
                {
                    "id": "reader",
                    "max_budget_share_bps": 3000,
                    "tools": [
                        route("reports", "read"),
                        route("chio-ipc", "send_results"),
                    ],
                }
            ],
        },
    )
    initialized = json.loads(
        command(
            [
                binary,
                "process",
                "init",
                "--config",
                directory / "host.json",
                "--state",
                directory / "host",
            ],
            directory,
        ).stdout
    )
    (directory / "kernel.pub").write_text(initialized["kernel_key"] + "\n")
    settings = {"directory": str(directory), "mode": mode, "endpoint": endpoint}
    worker = {
        "command": [shutil.which("node"), str(consumer / "swarm_worker.mjs")],
        "cwd": str(consumer),
        "input": settings,
        "max_attempts": 4,
        "timeout_seconds": 90,
    }
    write(
        directory / "worker-plan.json",
        {
            "schema": "chio.process.run.v1",
            "max_parallel": 2 if mode == "swarm-parallel" else 1,
            "workers": [{"process": "root", **worker}],
            "templates": [{"id": "reader", **worker}],
        },
    )
    return [
        binary,
        "process",
        "run",
        "--state",
        directory / "host",
        "--plan",
        directory / "worker-plan.json",
    ]


def exercise_swarm(binary, destination, temporary, consumer):
    output = destination / "cooperative-swarm"
    output.mkdir()
    profiles = {}
    for mode in (
        "swarm-baseline",
        "swarm-single-slot",
        "swarm-parallel",
        "swarm-host-death",
        "swarm-publication-death",
    ):
        directory = temporary / f"{consumer.name}-{mode}"
        directory.mkdir(mode=0o700)
        with provider(directory, consumer, mode, "swarm_server.py") as endpoint:
            invoke = prepare(binary, directory, consumer, mode, endpoint)
            if mode == "swarm-host-death":
                host_death(invoke, directory)
            success = mode != "swarm-baseline"
            executed = command(invoke, directory, success=success)
            runner = json.loads(executed.stdout)
            with sqlite3.connect(directory / "host/process.db") as db:
                processes = db.execute(
                    "SELECT id,parent_id,checkpoint,capability FROM processes ORDER BY id"
                ).fetchall()
            children = [p for p in processes if p[1] == "root"]
            assert len(processes) == 3 and len(children) == 2
            for child in children:
                grants = json.loads(child[3])["scope"]["grants"]
                assert {(g["server_id"], g["tool_name"]) for g in grants} == {
                    ("reports", "read"),
                    ("chio-ipc", "send_results"),
                }
            with sqlite3.connect(directory / "publications.db") as db:
                tables = {
                    row[0]
                    for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                publications = (
                    db.execute("SELECT report FROM reports").fetchall()
                    if "reports" in tables
                    else []
                )
                reads = (
                    db.execute("SELECT file_index FROM reads ORDER BY file_index").fetchall()
                    if "reads" in tables
                    else []
                )
            calls = requests(directory)
            assert "credential" not in json.dumps([call["request"] for call in calls])
            if success:
                assert not any(
                    name == "chio-process__wait_children" and value.get("complete") is False
                    for call in calls
                    for name, value in outputs(call["request"])
                ), "pending child waits must not reach the model"

            root = next(w for w in runner["workers"] if w["process"] == "root")
            root_state = json.loads(next(p[2] for p in processes if p[0] == "root"))
            if success:
                assert runner["complete"] and reads == [(1,), (2,)] and len(publications) == 1
                assert root["attempts"] == (3 if mode == "swarm-publication-death" else 2)
                assert all(w["attempts"] == 1 for w in runner["workers"] if w["process"] != "root")
                assert len(calls) == 12, [
                    (call["request"]["model"], len(call["request"]["messages"])) for call in calls
                ]
                assert len(json.loads(publications[0][0])["reviews"]) == 2
                waits = root_state["chio.ai-sdk.child-waits.v1"]["waits"]
                assert len(waits) == 1 and next(iter(waits.values()))["poll"] == 1
                if mode == "swarm-parallel":
                    with sqlite3.connect(directory / "provider.db") as db:
                        arrivals = db.execute("SELECT arrived,released FROM arrivals").fetchall()
                    assert len(arrivals) == 2 and max(row[0] for row in arrivals) <= min(
                        row[1] for row in arrivals
                    )
                before = {p.name: p.read_bytes() for p in directory.glob("*-result.json")}
                assert json.loads(command(invoke, directory).stdout) == runner
                assert {p.name: p.read_bytes() for p in directory.glob("*-result.json")} == before
                assert requests(directory) == calls
            else:
                assert root["state"] == "failed" and root["attempts"] == 4 and not publications
                assert "chio.ai-sdk.child-waits.v1" not in root_state
            events = [
                json.loads(line)
                for path in directory.glob("*-receipts.ndjson")
                for line in path.read_text().splitlines()
            ]
            verified = verify(binary, directory, events)["receipts_verified"]
            case = output / mode
            case.mkdir()
            for name in ("receipts.ndjson", "kernel.pub"):
                shutil.copyfile(directory / name, case / name)
            write(case / "runner.json", runner)
            write(case / "root-checkpoint.json", root_state)
            write(case / "provider-requests.json", calls)
            profiles[mode] = {
                "completed": success,
                "children": len(children),
                "reads": len(reads),
                "publications": len(publications),
                "provider_requests": len(calls),
                "root_attempts": root["attempts"],
                "receipts_verified": verified,
            }
            print(
                json.dumps({"sdk": consumer.name, "swarm": mode, **profiles[mode]}),
                flush=True,
            )
    return profiles
