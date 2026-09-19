"""Run two live LangGraph workers against one shared document."""

import argparse
import contextlib
import hashlib
import json
import os
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path

import store
from assess import assess
from contract import DEFINITIONS, INSTRUCTION, NAMESPACE, ROLES

HERE = Path(__file__).resolve().parent


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


def prepare_host(args, directory, roles=ROLES, *, operator=False):
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
    if operator:
        policy += """      - server: board-admin
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
    servers = [server]
    if operator:
        servers.append(
            provision_native_demo(
                binary,
                "board-admin",
                [
                    demo_python(),
                    str(HERE / "server.py"),
                    "--database",
                    str(directory / "resource.db"),
                    "--operator",
                ],
                directory / "launch-operator",
                directory,
            )
        )
    config = {
        "schema": "chio.process.host.v1",
        "policy": "policy.yaml",
        "servers": servers,
        "limits": {"max_processes": 1 + len(roles), "max_depth": 1, "max_calls": 100},
        "children": [
            {
                "id": name,
                "parent": "root",
                "budget_share_bps": 4000,
                "tools": [
                    {"server_id": "board", "tool_name": tool}
                    for tool in ("task", "snapshot", "replace")
                ],
            }
            for name in roles
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
    if operator:
        (directory / "root").mkdir(mode=0o700)
    for name in ("root", *roles) if operator else roles:
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
def host(binary, key, directory, socket_path=None):
    socket_path = socket_path or directory / "worker.sock"
    with (directory / "host.log").open("ab") as log:
        process = subprocess.Popen(
            [
                str(binary),
                "process",
                "serve",
                "--state",
                str(directory / "host"),
                "--socket",
                str(socket_path),
            ],
            stdout=subprocess.PIPE,
            stderr=log,
        )
        try:
            if not select.select([process.stdout], [], [], 90)[0]:
                raise RuntimeError("host startup timed out")
            line = process.stdout.readline()
            if not line:
                raise RuntimeError("host exited before readiness; inspect host.log")
            ready = json.loads(line)
            if ready.get("ready") is not True or ready.get("kernel_key") != key:
                raise RuntimeError("host readiness or signer changed")
            yield process
        finally:
            stop(process)
            process.stdout.close()


def worker_bootstrap(args, directory, name, services, **extra):
    settings = {
        "backend": args.backend,
        "directory": str(directory / name),
        "database": str(directory / "resource.db"),
        "services": services,
        "model": args.model,
        "provider": args.provider,
        "thread_id": name,
        "max_rounds": 8,
        "crash_after_replace": args.scenario == "worker-after-effect"
        and name == "performance",
    }
    settings.update(extra)
    bootstrap = {"input": settings}
    worker_command = [str(args.python), str(HERE / "langgraph_worker.py")]
    if args.framework == "ai-sdk":
        settings.update(
            consumer=str(args.consumer),
            instruction=INSTRUCTION,
            tools=DEFINITIONS,
            namespace=NAMESPACE,
            worker_sha256=hashlib.sha256(
                (HERE / "ai_sdk_worker.mjs").read_bytes()
            ).hexdigest(),
        )
        worker_command = [
            str(args.node),
            str(args.consumer / "shared-resource-worker.mjs"),
        ]
    if args.backend == "chio":
        bootstrap["connection"] = json.loads(
            (directory / name / "connection.json").read_text()
        )
    return worker_command, bootstrap


def workers(args, directory):
    with contextlib.ExitStack() as stack:

        def launch(command, bootstrap, errors):
            process = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors
            )
            stack.callback(stop, process)
            stack.callback(process.stdout.close)
            process.stdin.write(store.encoded(bootstrap).encode())
            process.stdin.close()
            process.stdin = None
            return process

        running = []
        for name, services in ROLES.items():
            worker_command, bootstrap = worker_bootstrap(
                args, directory, name, services
            )
            errors = stack.enter_context((directory / name / "stderr.log").open("ab"))
            process = launch(worker_command, bootstrap, errors)
            running.append((name, process, worker_command, bootstrap, errors))
        statuses, attempts = {}, {}
        deadline = time.monotonic() + 600
        for name, process, command, bootstrap, errors in running:
            stdout, _ = process.communicate(timeout=max(1, deadline - time.monotonic()))
            attempts[name] = [process.returncode]
            if (
                process.returncode == 77
                and args.scenario == "worker-after-effect"
                and name == "performance"
            ):
                process = launch(command, bootstrap, errors)
                resumed_stdout, _ = process.communicate(
                    timeout=max(1, deadline - time.monotonic())
                )
                stdout += resumed_stdout
                attempts[name].append(process.returncode)
            (directory / name / "stdout.log").write_bytes(stdout)
            statuses[name] = process.returncode
        write(directory / "attempts.json", attempts)
        return statuses


def report(args, directory, statuses, roles=ROLES, assessor=assess):
    snapshot = store.inspect(directory / "resource.db")
    result = {
        "schema": "chio.shared-resource.live-baseline.v1",
        "backend": args.backend,
        "framework": args.framework,
        "scenario": args.scenario,
        "ownership": getattr(args, "ownership", "none"),
        "model": args.model,
        "provider": args.provider,
        "workers": statuses,
        "resource": snapshot,
        "task": assessor(snapshot),
        "model_calls": [],
        "receipts_verified": False,
    }
    result["operator_calls"] = [
        json.loads(path.read_text())
        for path in sorted(directory.glob("operator-*.json"))
    ]
    receipts = [call["response"]["receipt_json"] for call in result["operator_calls"]]
    finished = True
    for name in roles:
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
        c["kind"] == "live_" + args.provider and c["complete"] for c in calls
    )
    result["accepted"] = (
        all(code == 0 for code in statuses.values())
        and finished
        and result["live_inference_completed"]
        and result["task"]["accepted"]
        and (args.backend == "baseline" or result["receipts_verified"])
    )
    attempts_path = directory / "attempts.json"
    result["attempts"] = (
        json.loads(attempts_path.read_text()) if attempts_path.exists() else {}
    )
    marker = directory / "performance" / "fault.json"
    result["fault"] = json.loads(marker.read_text()) if marker.exists() else None
    if args.scenario == "worker-after-effect":
        result["accepted"] = (
            result["accepted"]
            and result["attempts"].get("performance") == [77, 0]
            and result["fault"] is not None
        )
    write(directory / "report.json", result)
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--provider", choices=("openai", "openrouter"), default="openai"
    )
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--backend", choices=("baseline", "chio"), required=True)
    parser.add_argument("--chio", type=Path)
    parser.add_argument(
        "--framework", choices=("langgraph", "ai-sdk"), default="langgraph"
    )
    parser.add_argument("--consumer", type=Path)
    parser.add_argument(
        "--scenario", choices=("normal", "worker-after-effect"), default="normal"
    )
    parser.add_argument(
        "--node", type=Path, default=Path(shutil.which("node") or "node")
    )
    args = parser.parse_args()
    if args.backend == "chio" and args.chio is None:
        parser.error("--chio is required for the Chio backend")
    key_name = args.provider.upper() + "_API_KEY"
    if not os.environ.get(key_name):
        parser.error(f"{key_name} is required in the worker environment")
    if args.framework == "ai-sdk":
        if args.backend != "chio" or args.consumer is None:
            parser.error(
                "the AI SDK integration requires --backend chio and --consumer"
            )
        args.consumer = args.consumer.resolve(strict=True)
        worker = args.consumer / "shared-resource-worker.mjs"
        shutil.copyfile(HERE / "ai_sdk_worker.mjs", worker)
        subprocess.run(
            [str(args.node), str(worker), "--preflight", str(args.consumer)],
            check=True,
            timeout=30,
        )
    # Refuse a partial framework installation before creating workload state.
    if args.framework == "langgraph":
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
