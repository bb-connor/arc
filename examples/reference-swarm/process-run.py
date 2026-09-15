"""Run an initialized governed host with its existing process supervisor.

This exports independently checked worker responses. It does not yet produce
M5's complete terminal/confinement/scenario acceptance artifact.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def run(chio, *args):
    result = subprocess.run(
        [str(chio), *map(str, args)], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--worker-image",
        help="Immutable local Docker image containing /opt/chio/process-worker.py and the Python SDK",
    )
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("native worker supervision requires Linux")
    os.umask(0o077)
    chio, state = args.chio.resolve(strict=True), args.state.resolve(strict=True)
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    calls = json.loads((state / "swarm-calls.json").read_text())
    if calls["schema"] != "chio.process.swarm-calls.v1":
        raise ValueError("unsupported planned calls")
    worker = Path(__file__).with_name("process-worker.py").resolve(strict=True)
    plan = {
        "schema": "chio.process.run.v1",
        "max_parallel": len(calls["calls"]),
        "workers": [
            {
                "process": call["process"],
                "command": [sys.executable, str(worker)],
                "cwd": str(worker.parent),
                "input": call,
                "max_attempts": 3,
                "timeout_seconds": 60,
                "resources": {"max_cpu_seconds": 20, "max_open_files": 64},
            }
            for call in calls["calls"]
        ],
    }
    if args.worker_image:
        for entry in plan["workers"]:
            entry["command"] = ["/usr/local/bin/python3", "/opt/chio/process-worker.py"]
            entry["cwd"] = "/work"
            entry.pop("resources")
            entry["container"] = {"image": args.worker_image}
    plan_path = state / "reference-run-plan.json"
    if plan_path.exists():
        if json.loads(plan_path.read_text()) != plan:
            raise ValueError(
                "retained runner plan differs; resume with the original worker command and calls"
            )
    else:
        write(plan_path, plan)
    report = subprocess.run(
        [str(chio), "process", "run", "--state", str(state), "--plan", str(plan_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    (output / "runner.stdout").write_text(report.stdout)
    (output / "runner.stderr").write_text(report.stderr)
    if report.returncode:
        raise RuntimeError(
            f"runner exited {report.returncode}; inspect {output / 'runner.stderr'}"
        )
    run_report = json.loads(report.stdout)
    if not run_report.get("complete"):
        raise RuntimeError("runner did not complete the planned workers")
    # This pin is read from the operator-owned host state, not from a submitted receipt.
    key = output / "kernel.pub"
    key.write_text((state / "authority.db.kernel.pub").read_text())
    bootstrap = json.loads((state / "swarm-bootstrap.json").read_text())
    capabilities = bootstrap["action"]["parameters"]["capabilities"]
    verified = []
    for call in calls["calls"]:
        folder = output / call["process"]
        folder.mkdir(mode=0o700)
        retained = run(
            chio, "process", "state", "--state", state, "--process", call["process"]
        )
        response = retained["data"]["checkpoint"]["value"]["response"]
        request = {
            field: call[field]
            for field in ["operation_key", "server_id", "tool_name", "arguments"]
        }
        request["known_outcome_only"] = False
        context = {
            "runtime_id": calls["runtime_id"],
            "process_id": call["process"],
            "capability_id": capabilities[call["process"]]["id"],
        }
        for name, value in [
            ("request", request),
            ("context", context),
            ("response", response),
        ]:
            write(folder / f"{name}.json", value)
        verification = run(
            chio,
            "--json",
            "receipt",
            "verify-process-response",
            "--request",
            folder / "request.json",
            "--context",
            folder / "context.json",
            "--response",
            folder / "response.json",
            "--trusted-kernel-pubkey",
            key,
        )
        write(folder / "verification.json", verification)
        verified.append(call["process"])
    artifact = output / "completed-run.json"
    run(
        chio,
        "process",
        "attest-run",
        "--state",
        state,
        "--plan",
        plan_path,
        "--out",
        artifact,
    )
    run_verification = run(
        chio,
        "process",
        "verify-run",
        "--artifact",
        artifact,
        "--trusted-kernel-pubkey",
        key,
        "--runtime-id",
        calls["runtime_id"],
    )
    write(output / "completed-run-verification.json", run_verification)
    result = {
        "schema": "chio.reference-swarm.process-run.v1",
        "runtime_id": calls["runtime_id"],
        "verified_workers": verified,
        "runner": run_report,
        "completed_run": run_verification,
        "m5_acceptance_complete": False,
    }
    write(output / "run.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
