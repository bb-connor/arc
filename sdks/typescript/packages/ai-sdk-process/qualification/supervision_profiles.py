"""Installed AI SDK supervision and fallback without duplicate model planning or publication."""

import json
import shutil
import sqlite3
from pathlib import Path
from urllib.parse import unquote, urlparse

from journal_profiles import provider, requests
from qualify import command, host_death, verify, write
from swarm_profiles import route
from swarm_server import outputs


def prepare(binary, directory, consumer, mode, endpoint):
    (directory / "policy.yaml").write_text("""kernel:
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
      - server: chio-process
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    write(
        directory / "host.json",
        {
            "schema": "chio.process.host.v1",
            "policy": "policy.yaml",
            "mailboxes": [{"id": "results"}, {"id": "final"}],
            "limits": {"max_processes": 3, "max_depth": 1, "max_calls": 30},
            "supervised_children": True,
            "spawn_templates": [
                {
                    "id": role,
                    "max_budget_share_bps": 3000,
                    "tools": [route("chio-ipc", "send_results")],
                }
                for role in ("primary", "fallback")
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
    worker = {
        "command": [shutil.which("node"), str(consumer / "supervision_worker.mjs")],
        "cwd": str(consumer),
        "input": {"directory": str(directory), "mode": mode, "endpoint": endpoint},
        "max_attempts": 2,
        "timeout_seconds": 60,
    }
    write(
        directory / "worker-plan.json",
        {
            "schema": "chio.process.run.v1",
            "failure_policy": "supervised",
            "max_parallel": 1,
            "workers": [worker | {"process": "root"}],
            "templates": [
                worker | {"id": role, "max_attempts": 1 if role == "primary" else 2}
                for role in ("primary", "fallback")
            ],
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


def exercise_supervision(binary, destination, temporary, consumer):
    output = destination / "supervised-children"
    output.mkdir()
    profiles = {}
    for mode in ("baseline", "worker-death", "host-death"):
        directory = temporary / f"{consumer.name}-supervision-{mode}"
        directory.mkdir(mode=0o700)
        with provider(directory, consumer, mode, "supervision_server.py") as endpoint:
            invoke = prepare(binary, directory, consumer, mode, endpoint)
            if mode == "host-death":
                host_death(invoke, directory)
            report = json.loads(command(invoke, directory).stdout)
            states = {w["process"]: w for w in report["workers"]}
            assert report["complete"] and report["schema"] == "chio.process.run-report.v2"
            assert report["pending_container_records"] == report["abandoned_socket_intents"] == 0
            assert states["dyn_1"]["state"] == "failed" and states["dyn_1"]["attempts"] == 1
            assert states["dyn_2"]["state"] == states["root"]["state"] == "completed"
            assert states["root"]["attempts"] == 3 and states["root"]["suspensions"] == 2
            assert states["dyn_2"]["attempts"] == (1 if mode == "baseline" else 2)
            assert not report["unhandled_failures"] and len(report["handled_failures"]) == 1
            calls = requests(directory)
            assert len(calls) == 9
            assert not any(
                name == "chio-process__settle_children" and not value["complete"]
                for call in calls
                for name, value in outputs(call["request"])
            )
            events = [
                json.loads(line)
                for p in directory.glob("*-receipts.ndjson")
                for line in p.read_text().splitlines()
            ]
            original = {}
            for event in events:
                result = event["result"]
                assert (
                    original.setdefault(result["request_id"], result["receipt_json"])
                    == result["receipt_json"]
                )
            assert report["handled_failures"][0]["settlement_request_id"] in original
            publications = [e for e in events if e["tool"]["tool_name"] == "send_results"]
            assert len(publications) == (1 if mode == "baseline" else 2)
            assert len({e["operationKey"] for e in publications}) == 1
            assert len({e["result"]["receipt_json"] for e in publications}) == 1
            with sqlite3.connect(directory / "host/process.db") as db:
                checkpoint = json.loads(
                    db.execute("SELECT checkpoint FROM processes WHERE id='root'").fetchone()[0]
                )
            assert sorted(
                v["poll"] for v in checkpoint["chio.ai-sdk.child-waits.v1"]["waits"].values()
            ) == [1, 1]
            for role in ("root", "dyn_2"):
                result = json.loads((directory / f"{role}-result.json").read_text())
                assert all(
                    Path(unquote(urlparse(url).path))
                    .resolve()
                    .is_relative_to(consumer / "node_modules")
                    for url in result["modules"].values()
                )
            verified = verify(binary, directory, events)["receipts_verified"]
            assert json.loads(command(invoke, directory).stdout) == report
            assert requests(directory) == calls
            case = output / mode
            case.mkdir()
            for name in ("receipts.ndjson", "kernel.pub"):
                shutil.copyfile(directory / name, case / name)
            write(case / "runner.json", report)
            write(case / "provider-requests.json", calls)
            write(case / "root-checkpoint.json", checkpoint)
            profiles[mode] = {
                "completed": True,
                "handled_failures": 1,
                "provider_requests": len(calls),
                "fallback_publications": 1,
                "receipts_verified": verified,
            }
            print(
                json.dumps({"sdk": consumer.name, "supervision": mode, **profiles[mode]}),
                flush=True,
            )
    return profiles
