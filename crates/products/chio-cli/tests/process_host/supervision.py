"""Native one-slot supervision, failure evidence, and durable fallback recovery."""

import json
import os
import sqlite3
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
        data = data["configuration"] | data["task"]
    directory = Path(data["directory"])
    connection = bootstrap["connection"]
    client = ProcessClient(connection["socket_path"], connection["credential"])
    identity = client.inspect()["process_id"]
    attempt = bootstrap["attempt"]
    write(directory / f"{identity}-{attempt}-started.json", {"pid": os.getpid()})

    def invoke(key, tool, arguments, server="chio-process", allow=True):
        result = client.invoke(key, server, tool, arguments, known_outcome_only=True)
        write(directory / f"{identity}-{key}-{attempt}-receipt.json", result)
        assert (result["verdict"] == "allow") == allow, result
        return result["output"]["value"] if allow else result

    def spawn(key, role, budget=1000):
        return invoke(
            key,
            "spawn_work",
            {"input": {"role": role}, "budget_share_bps": budget},
        )["process"]

    def join(key, children, strict=False):
        checkpoint = client.inspect()["checkpoint"]
        state = checkpoint["value"] or {}
        poll = state.get(key, 0)
        value = invoke(
            f"{key}-{poll}",
            "wait_children" if strict else "settle_children",
            {"children": children},
        )
        if not value["complete"]:
            state[key] = poll + 1
            client.checkpoint(checkpoint["revision"], state)
            sys.exit(75)
        return value

    role = data["role"]
    if role == "fail":
        if data["mode"] == "cancelled":
            client.cancel()
            time.sleep(30)
        sys.exit(1)
    if role in ("middle", "successful_middle"):
        child = spawn("spawn-leaf", "fail", 500)
        if role == "successful_middle":
            return
        join("join-leaf", [child], strict=True)
        raise AssertionError("A strict join must fail this middle supervisor")
    if role == "parent":
        child = spawn(
            "spawn-primary",
            "middle"
            if data["mode"] == "nested"
            else "successful_middle"
            if data["mode"] == "unobserved_descendant"
            else "fail",
            2000,
        )
        if data["mode"] == "unobserved":
            return
        if data["mode"] == "pending_only":
            assert not invoke("pending-only", "settle_children", {"children": [child]})[
                "complete"
            ]
            return
        if data["mode"] == "negative_targets":
            for index, children in enumerate(
                (["root"], ["dependent"], ["dyn_128"], [], [child, child])
            ):
                invoke(
                    f"invalid-{index}",
                    "settle_children",
                    {"children": children},
                    allow=False,
                )
        value = join("join-primary", [child], strict=data["mode"] == "strict")
        if data["mode"] == "unobserved_descendant":
            assert value["successful"]
            return
        assert not value["successful"]
        assert value["outcomes"][0]["process"] == child
        assert value["outcomes"][0]["state"] == "failed"
        if data["mode"] == "failed_supervisor":
            sys.exit(1)
        fallback = spawn("spawn-fallback", "fallback")
        assert join("join-fallback", [fallback])["successful"]
    invoke(
        "publish",
        "send_results",
        {"message_key": identity, "payload": {"worker": identity, "role": role}},
        server="chio-ipc",
    )
    if role == "fallback" and data["crash"]:
        (directory / "fallback-published").touch()
        while not (directory / "release").exists():
            time.sleep(0.02)


def command(binary, directory):
    return [
        binary,
        "process",
        "run",
        "--state",
        str(directory / "host"),
        "--plan",
        str(directory / "plan.json"),
    ]


def prepare(binary, directory, mode, crash=False, enabled=True):
    directory.mkdir(mode=0o700)
    (directory / "policy.yaml").write_text("""kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 3
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
    routes = [
        {"server_id": "chio-process", "tool_name": name}
        for name in (
            ["spawn_work", "wait_children", "settle_children"]
            if enabled
            else ["spawn_work", "wait_children"]
        )
    ] + [{"server_id": "chio-ipc", "tool_name": "send_results"}]
    config = {
        "schema": "chio.process.host.v1",
        "policy": str(directory / "policy.yaml"),
        "mailboxes": [{"id": "results"}],
        "limits": {"max_processes": 12, "max_depth": 3, "max_calls": 100},
        "children": [
            {
                "id": "parent",
                "parent": "root",
                "budget_share_bps": 6000,
                "tools": routes,
            },
            {
                "id": "dependent",
                "parent": "root",
                "budget_share_bps": 1000,
                "tools": [routes[-1]],
            },
        ],
        "spawn_templates": [
            {"id": "work", "tools": routes, "max_budget_share_bps": 2500}
        ],
        "supervised_children": enabled,
    }
    write(directory / "config.json", config)
    initialized = subprocess.run(
        [
            binary,
            "process",
            "init",
            "--config",
            str(directory / "config.json"),
            "--state",
            str(directory / "host"),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    (directory / "kernel.pub").write_text(json.loads(initialized.stdout)["kernel_key"])
    worker_config = {
        "command": [sys.executable, str(HERE), "--worker"],
        "cwd": str(directory),
        "input": {"directory": str(directory), "mode": mode, "crash": crash},
        "max_attempts": 2 if crash else 1,
        "timeout_seconds": 30,
    }
    plan = {
        "schema": "chio.process.run.v1",
        "failure_policy": "supervised" if enabled else "stop",
        "max_parallel": 1,
        "workers": [
            worker_config
            | {
                "process": role,
                "input": worker_config["input"] | {"role": role},
                "depends_on": ["parent"] if role == "dependent" else [],
            }
            for role in ("parent", "dependent")
        ],
        "templates": [worker_config | {"id": "work"}],
    }
    write(directory / "plan.json", plan)
    return plan


def run(binary, directory, success):
    result = subprocess.run(
        command(binary, directory),
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert (result.returncode == 0) == success, (
        directory,
        result.stdout,
        result.stderr,
    )
    report = json.loads(result.stdout)
    assert report["complete"] == success
    assert report["schema"] == "chio.process.run-report.v2"
    assert report["failure_policy"] == "supervised"
    assert (
        report["pending_container_records"] == report["abandoned_socket_intents"] == 0
    )
    return report


def verify(binary, directory):
    results = [json.loads(p.read_text()) for p in directory.glob("*-receipt.json")]
    originals = {}
    for result in results:
        if result["verdict"] == "allow":
            previous = originals.setdefault(
                result["request_id"], result["receipt_json"]
            )
            assert previous == result["receipt_json"]
    # Denial observations may have new signed receipts for the same retained
    # unknown request. Known successful effects retain their exact receipt.
    receipts = sorted({result["receipt_json"] for result in results})
    (directory / "receipts.ndjson").write_text("\n".join(receipts) + "\n")
    result = subprocess.run(
        [
            binary,
            "--json",
            "receipt",
            "verify",
            "--input",
            str(directory / "receipts.ndjson"),
            "--trusted-kernel-pubkey",
            str(directory / "kernel.pub"),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    verified = json.loads(result.stdout)
    assert verified["receipts_verified"] == len(receipts)
    return verified, originals


def main(binary):
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix="chio-supervised-children-"))
    print(
        "Private supervision qualification: " + str(root), file=sys.stderr, flush=True
    )
    cases = []
    for mode in (
        "fallback",
        "negative_targets",
        "nested",
        "unobserved",
        "pending_only",
        "unobserved_descendant",
        "failed_supervisor",
        "strict",
        "cancelled",
        "host_death",
        "worker_death",
    ):
        directory = root / mode
        crash = mode in ("host_death", "worker_death")
        prepare(binary, directory, mode, crash=crash)
        if crash:
            process = subprocess.Popen(
                command(binary, directory),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 45
                while not (directory / "fallback-published").exists():
                    assert process.poll() is None, process.communicate()
                    assert time.monotonic() < deadline, "Fallback did not publish"
                    time.sleep(0.02)
                if mode == "host_death":
                    process.kill()
                    process.communicate(timeout=20)
                else:
                    started = json.loads(
                        (directory / "dyn_2-1-started.json").read_text()
                    )
                    os.kill(started["pid"], 9)
                (directory / "release").touch()
                if mode == "worker_death":
                    stdout, stderr = process.communicate(timeout=45)
                    assert process.returncode == 0, (stdout, stderr)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=20)
        success = mode not in (
            "unobserved",
            "pending_only",
            "unobserved_descendant",
            "failed_supervisor",
            "strict",
            "cancelled",
        )
        report = run(binary, directory, success)
        states = {w["process"]: w for w in report["workers"]}
        assert (
            states["dyn_2" if mode == "unobserved_descendant" else "dyn_1"]["state"]
            == "failed"
        )
        if success:
            assert (
                states["parent"]["state"] == states["dependent"]["state"] == "completed"
            )
            assert not report["unhandled_failures"]
            assert len(report["handled_failures"]) == (2 if mode == "nested" else 1)
            assert all(
                item["supervisor"] == "parent" for item in report["handled_failures"]
            )
            if crash:
                assert states["dyn_2"]["attempts"] == 2
        elif mode != "cancelled":
            assert not report["handled_failures"]
            assert ("dyn_2" if mode == "unobserved_descendant" else "dyn_1") in report[
                "unhandled_failures"
            ]
            if mode in ("unobserved", "pending_only", "unobserved_descendant"):
                assert states["parent"]["state"] == "completed"
            else:
                assert states["parent"]["state"] == "failed"
                assert states["dependent"]["attempts"] == 0
        verified, originals = verify(binary, directory)
        assert all(
            item["settlement_request_id"] in originals
            for item in report["handled_failures"]
        )
        before = {p.name: p.read_bytes() for p in directory.glob("*-started.json")}
        assert run(binary, directory, success) == report
        assert {
            p.name: p.read_bytes() for p in directory.glob("*-started.json")
        } == before
        cases.append({"mode": mode, "report": report, "verification": verified})
        if mode == "fallback":
            with sqlite3.connect(directory / "host/runner.db") as db:
                db.execute(
                    "INSERT INTO run_child_settlements VALUES('dependent','dyn_1','forged')"
                )
            refused = subprocess.run(
                command(binary, directory),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            assert (
                refused.returncode != 0
                and "invalid recorded child failure settlement" in refused.stderr
            )
            assert {
                p.name: p.read_bytes() for p in directory.glob("*-started.json")
            } == before
            with sqlite3.connect(directory / "host/runner.db") as db:
                db.execute(
                    "DELETE FROM run_child_settlements WHERE request_id='forged'"
                )

    for enabled in (False, True):
        directory = root / f"mismatch-{enabled}"
        plan = prepare(binary, directory, "fallback", enabled=enabled)
        record = json.loads((directory / "host/host.json").read_text())
        manifest = next(
            m for m in record["manifests"] if m["server_id"] == "chio-process"
        )
        assert any(t["name"] == "settle_children" for t in manifest["tools"]) == enabled
        if not enabled:
            assert "supervised_children" not in record["config"]
        plan["failure_policy"] = "stop" if enabled else "supervised"
        write(directory / "plan.json", plan)
        refused = subprocess.run(
            command(binary, directory),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert refused.returncode != 0 and "enabled together" in refused.stderr
        assert not (directory / "host/runner.db").exists()
        assert not list(directory.glob("*-started.json"))
    print(
        json.dumps({"private_state": str(root), "cases": cases, "feature_opt_in": True})
    )


if __name__ == "__main__":
    if sys.argv[1] == "--worker":
        worker()
    else:
        main(sys.argv[1])
