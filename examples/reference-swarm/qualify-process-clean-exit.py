"""Two confined tasks complete their calls and their native launches exit with the host."""

import argparse
import json
import os
import platform
from pathlib import Path

from process_qualification import Harness, write


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["chio", "cage-init", "probe", "output", "receipt-rollback-anchor-root"]:
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--worker-image", required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("requires the supported Linux x86_64 cage profile")
    if os.getuid() == 0 or os.getgid() == 0:
        parser.error("run as a non-root operator")
    os.umask(0o077)
    harness = Harness(args.chio, args.cage_init, args.probe, args.output,
                      args.receipt_rollback_anchor_root, args.worker_image)
    inputs = harness.output / "allowed"
    inputs.mkdir(mode=0o700)
    effects = {}
    planned = []
    for name in ["erin", "frank"]:
        effect = harness.output / f"{name}-effect.txt"
        effect.write_bytes(b"")
        effects[name] = effect
        harness.server(f"{name}-probe", inputs, write_paths=[effect])
        planned.append({
            "process": name, "operation_key": "write-once",
            "server_id": f"{name}-probe", "tool_name": "write_file",
            "arguments": {"path": str(effect)},
        })
    calls = harness.initialize(planned, aggregate_invocations=2)
    plan = harness.output / "run-plan.json"
    write(plan, {
        "schema": "chio.process.run.v1", "max_parallel": 2,
        "workers": [{
            "process": call["process"],
            "input": dict(call, expected_verdict="allow"),
            "command": ["/usr/local/bin/python3", "/opt/chio/process-observe-worker.py"],
            "cwd": "/work", "container": {"image": args.worker_image},
            "max_attempts": 1, "timeout_seconds": 60,
        } for call in calls],
    })
    command = [harness.chio, "process", "run", "--state", harness.state, "--plan", plan]
    report = harness.run("run", command)
    assert report["complete"], report
    assert [worker["attempts"] for worker in report["workers"]] == [1, 1], report
    launches = {}
    for call in calls:
        response = harness.observe(call)
        assert response["verdict"] == "allow", response
        assert effects[call["process"]].read_bytes(), "allowed worker produced no effect"
        receipt = json.loads(response["receipt_json"])
        launches[call["process"]] = receipt["metadata"]["native_launch"]
    result = {
        "schema": "chio.reference-swarm.clean-exit-qualification.v1",
        "completed_workers": sorted(launches), "native_launches": launches,
        "runner": report, "worker_image": args.worker_image,
        "m5_acceptance_complete": False,
        "limits": ["confined calls complete; native launches exit when the host completes",
                   "not a complete scenario artifact"],
    }
    write(harness.output / "qualification.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
