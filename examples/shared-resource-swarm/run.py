"""Run two live LangGraph workers against one shared document."""

import argparse
import contextlib
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

import store
from assess import assess

HERE = Path(__file__).resolve().parent
ROLES = {"compatibility": ["api", "worker"], "performance": ["search"]}


def write(path, value):
    with path.open("x") as output:
        output.write(store.encoded(value))
        output.flush()
        os.fsync(output.fileno())


def command(arguments, directory):
    result = subprocess.run(
        [str(a) for a in arguments], capture_output=True, timeout=90
    )
    if result.returncode:
        with (directory / "host-error.log").open("ab") as output:
            output.write(result.stderr)
        raise RuntimeError("Chio command failed; inspect host-error.log")
    return result.stdout


def prepare_host(args, directory):
    from chio_process.launch import demo_python, provision_native_demo

    binary = args.chio.resolve(strict=True)
    policy = """kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 2
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: board
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
"""
    (directory / "policy.yaml").write_text(policy)
    server = provision_native_demo(
        binary,
        "board",
        [
            demo_python(),
            str(HERE / "server.py"),
            "--database",
            str(directory / "resource.db"),
        ],
        directory / "launch",
        directory,
    )
    config = {
        "schema": "chio.process.host.v1",
        "policy": "policy.yaml",
        "servers": [server],
        "limits": {"max_processes": 3, "max_depth": 1, "max_calls": 100},
        "children": [
            {
                "id": name,
                "parent": "root",
                "budget_share_bps": 4000,
                "tools": [
                    {"server_id": "board", "tool_name": tool}
                    for tool in ("task", "read", "replace")
                ],
            }
            for name in ROLES
        ],
    }
    write(directory / "host-config.json", config)
    initialized = json.loads(
        command(
            [
                binary,
                "process",
                "init",
                "--config",
                directory / "host-config.json",
                "--state",
                directory / "host",
            ],
            directory,
        )
    )
    (directory / "kernel.pub").write_text(initialized["kernel_key"] + "\n")
    for name in ROLES:
        command(
            [
                binary,
                "process",
                "credential",
                "--state",
                directory / "host",
                "--process",
                name,
                "--socket",
                directory / "worker.sock",
                "--out",
                directory / name / "connection.json",
            ],
            directory,
        )
    return binary, initialized["kernel_key"]


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


@contextlib.contextmanager
def host(binary, key, directory):
    with (directory / "host.log").open("ab") as log:
        process = subprocess.Popen(
            [
                str(binary),
                "process",
                "serve",
                "--state",
                str(directory / "host"),
                "--socket",
                str(directory / "worker.sock"),
            ],
            stdout=subprocess.PIPE,
            stderr=log,
        )
        try:
            if not select.select([process.stdout], [], [], 90)[0]:
                raise RuntimeError("host startup timed out")
            ready = json.loads(process.stdout.readline())
            if ready.get("ready") is not True or ready.get("kernel_key") != key:
                raise RuntimeError("host readiness or signer changed")
            yield
        finally:
            stop(process)
            process.stdout.close()


def workers(args, directory):
    with contextlib.ExitStack() as stack:
        running = []
        for name, services in ROLES.items():
            settings = {
                "backend": args.backend,
                "directory": str(directory / name),
                "database": str(directory / "resource.db"),
                "services": services,
                "model": args.model,
                "thread_id": name,
                "max_rounds": 8,
            }
            bootstrap = {"input": settings}
            if args.backend == "chio":
                bootstrap["connection"] = json.loads(
                    (directory / name / "connection.json").read_text()
                )
            errors = stack.enter_context((directory / name / "stderr.log").open("ab"))
            process = subprocess.Popen(
                [str(args.python), str(HERE / "langgraph_worker.py")],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=errors,
            )
            stack.callback(stop, process)
            stack.callback(process.stdout.close)
            process.stdin.write(store.encoded(bootstrap).encode())
            process.stdin.close()
            process.stdin = None
            running.append((name, process))
        statuses = {}
        deadline = time.monotonic() + 600
        for name, process in running:
            stdout, _ = process.communicate(timeout=max(1, deadline - time.monotonic()))
            (directory / name / "stdout.log").write_bytes(stdout)
            statuses[name] = process.returncode
        return statuses


def report(args, directory, statuses):
    snapshot = store.inspect(directory / "resource.db")
    result = {
        "schema": "chio.shared-resource.live-baseline.v1",
        "backend": args.backend,
        "framework": "langgraph",
        "model": args.model,
        "workers": statuses,
        "resource": snapshot,
        "task": assess(snapshot),
        "model_calls": [],
        "receipts_verified": False,
    }
    receipts, finished = [], True
    for name in ROLES:
        path = directory / name / "result.json"
        if not path.exists():
            finished = False
            continue
        worker = json.loads(path.read_text())
        finished = finished and worker["graph_finished"]
        result["model_calls"].extend(
            {"worker": name, **c} for c in worker["model_calls"]
        )
        for tool in worker["tools"]:
            receipt = (tool.get("artifact") or {}).get("chio", {}).get("receipt_json")
            if receipt:
                receipts.append(receipt)
    if args.backend == "chio" and receipts:
        (directory / "receipts.ndjson").write_text(
            "\n".join(dict.fromkeys(receipts)) + "\n"
        )
        command(
            [
                args.chio,
                "receipt",
                "verify",
                "--input",
                directory / "receipts.ndjson",
                "--trusted-kernel-pubkey",
                directory / "kernel.pub",
            ],
            directory,
        )
        result["receipts_verified"] = True
    calls = result["model_calls"]
    result["live_inference_completed"] = bool(calls) and all(
        c["kind"] == "live_openai" and c["complete"] for c in calls
    )
    result["accepted"] = (
        all(code == 0 for code in statuses.values())
        and finished
        and result["live_inference_completed"]
        and result["task"]["accepted"]
        and (args.backend == "baseline" or result["receipts_verified"])
    )
    write(directory / "report.json", result)
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--backend", choices=("baseline", "chio"), required=True)
    parser.add_argument("--chio", type=Path)
    args = parser.parse_args()
    if args.backend == "chio" and args.chio is None:
        parser.error("--chio is required for the Chio backend")
    # Refuse a partial framework installation before creating workload state.
    subprocess.run(
        [
            str(args.python),
            "-c",
            "from langgraph.checkpoint.sqlite import SqliteSaver; "
            "from langchain_core.messages import AIMessage",
        ],
        check=True,
        timeout=30,
    )
    directory = args.output.resolve()
    directory.mkdir(mode=0o700)
    for name in ROLES:
        (directory / name).mkdir(mode=0o700)
    store.initialize(
        directory / "resource.db", json.loads((HERE / "seed.json").read_text())
    )
    if args.backend == "chio":
        binary, key = prepare_host(args, directory)
        with host(binary, key, directory):
            statuses = workers(args, directory)
    else:
        statuses = workers(args, directory)
    result = report(args, directory, statuses)
    print(
        store.encoded(
            {"accepted": result["accepted"], "report": str(directory / "report.json")}
        )
    )
    if not result["accepted"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
