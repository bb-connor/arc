"""Verify durable kernel revocation of an issued, unspent governed task."""

import argparse
import hashlib
import json
import os
import platform
from pathlib import Path

from process_qualification import Harness, write


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in [
        "chio",
        "cage-init",
        "probe",
        "output",
        "receipt-rollback-anchor-root",
    ]:
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--worker-image", required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("requires the supported Linux x86_64 cage profile")
    if os.getuid() == 0 or os.getgid() == 0:
        parser.error("run as a non-root operator")
    os.umask(0o077)
    harness = Harness(
        args.chio,
        args.cage_init,
        args.probe,
        args.output,
        args.receipt_rollback_anchor_root,
        args.worker_image,
    )
    inputs = harness.output / "allowed"
    inputs.mkdir(mode=0o700)
    canary, protected = inputs / "canary.txt", inputs / "revoked-task.txt"
    canary.write_text("allowed-canary\n")
    protected.write_text("revoked-worker-secret-" + os.urandom(32).hex() + "\n")
    before = {path.name: path.read_bytes() for path in inputs.iterdir()}
    harness.server("revocation-probe", inputs)
    calls = harness.initialize(
        [
            {
                "process": name,
                "operation_key": "read-assigned-file",
                "server_id": "revocation-probe",
                "tool_name": "read_file",
                "arguments": {"path": str(path)},
            }
            for name, path in [("canary", canary), ("revoked", protected)]
        ]
    )
    revoked = harness.run(
        "revoke-capability",
        [
            harness.chio,
            "process",
            "revoke-capability",
            "--state",
            harness.state,
            "--process",
            "revoked",
        ],
    )
    bootstrap = json.loads((harness.state / "swarm-bootstrap.json").read_text())
    assert revoked == {
        "process": "revoked",
        "capability_revoked": True,
        "capability_id": bootstrap["action"]["parameters"]["capabilities"]["revoked"][
            "id"
        ],
    }, revoked
    workers = [
        {
            "process": call["process"],
            "input": dict(
                call,
                expected_verdict="deny" if call["process"] == "revoked" else "allow",
            ),
            "command": [
                "/usr/local/bin/python3",
                "/opt/chio/process-observe-worker.py",
            ],
            "cwd": "/work",
            "container": {"image": args.worker_image},
            "max_attempts": 1,
            "timeout_seconds": 60,
        }
        for call in calls
    ]
    plan = harness.output / "run-plan.json"
    write(
        plan, {"schema": "chio.process.run.v1", "max_parallel": 2, "workers": workers}
    )
    report = harness.run(
        "workers",
        [
            harness.chio,
            "process",
            "run",
            "--state",
            harness.state,
            "--plan",
            plan,
        ],
    )
    assert report["complete"], report
    responses = {call["process"]: harness.observe(call) for call in calls}
    assert responses["canary"]["verdict"] == "allow", responses["canary"]
    assert responses["canary"]["output"]["value"]["structuredContent"] == {
        "effect": "succeeded",
        "value": {"bytes_hex": before["canary.txt"].hex()},
    }, responses["canary"]
    denied = responses["revoked"]
    assert denied["verdict"] == "deny" and denied["output"] is None, denied
    assert "revoked" in denied["reason"].lower(), denied
    receipt = json.loads(denied["receipt_json"])
    assert receipt["capability_id"] == revoked["capability_id"], receipt
    assert protected.read_bytes().hex() not in json.dumps(denied), (
        "revoked task leaked its input"
    )
    assert {path.name: path.read_bytes() for path in inputs.iterdir()} == before
    result = {
        "schema": "chio.reference-swarm.revocation-qualification.v1",
        "issued_capability_revoked": revoked,
        "caller_receipt_id": receipt["id"],
        "revocation_survived_host_reopen": True,
        "unspent_planned_call_denied": True,
        "protected_files_unchanged": True,
        "secret_not_returned": True,
        "worker_image": args.worker_image,
        "runner": report,
        "probe_sha256": hashlib.sha256(harness.probe.read_bytes()).hexdigest(),
        "m5_acceptance_complete": False,
        "limits": [
            "operator revocation requires a stopped host",
            "not a complete scenario artifact",
        ],
    }
    write(harness.output / "qualification.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
