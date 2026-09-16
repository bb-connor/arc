"""Exercise governed worker isolation, continuation reuse and worker recovery."""

import argparse
import copy
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
    private, public = inputs / "alice.txt", inputs / "bob.txt"
    private.write_text("alice-only-" + os.urandom(32).hex() + "\n")
    public.write_text("bob-public-input\n")
    before = {path.name: path.read_bytes() for path in inputs.iterdir()}
    harness.server("shared-probe", inputs)
    calls = harness.initialize(
        [
            {
                "process": name,
                "operation_key": "read-assigned-file",
                "server_id": "shared-probe",
                "tool_name": "read_file",
                "arguments": {"path": str(path)},
            }
            for name, path in [("alice", private), ("bob", public)]
        ]
    )
    by_name = {call["process"]: call for call in calls}
    workers = []
    for call in calls:
        name = call["process"]
        peer = by_name["bob" if name == "alice" else "alice"]
        widening = copy.deepcopy(call)
        widening.update(operation_key="scope-widening", tool_name="write_file")
        foreign = copy.deepcopy(peer)
        foreign.update(process=name, operation_key="peer-authority")
        changed = copy.deepcopy(call)
        changed.update(operation_key="changed-intent", arguments=peer["arguments"])
        observed = dict(
            call,
            expected_verdict="allow",
            check_replay=True,
            crash_after_checkpoint=name == "alice",
            probes=[widening, foreign, changed],
        )
        workers.append(
            {
                "process": name,
                "input": observed,
                "command": [
                    "/usr/local/bin/python3",
                    "/opt/chio/process-observe-worker.py",
                ],
                "cwd": "/work",
                "container": {"image": args.worker_image},
                "max_attempts": 2,
                "timeout_seconds": 60,
            }
        )
    plan = harness.output / "run-plan.json"
    write(
        plan, {"schema": "chio.process.run.v1", "max_parallel": 2, "workers": workers}
    )
    command = [harness.chio, "process", "run", "--state", harness.state, "--plan", plan]
    report = harness.run("workers", command)
    assert report["complete"], report
    snapshots = {worker["process"]: worker for worker in report["workers"]}
    assert snapshots["alice"]["attempts"] == 2 and snapshots["bob"]["attempts"] == 1, (
        snapshots
    )
    responses, denials = {}, {}
    for call in calls:
        name = call["process"]
        response = harness.observe(call)
        responses[name] = response
        assert response["verdict"] == "allow", response
        expected = before["alice.txt" if name == "alice" else "bob.txt"].hex()
        assert response["output"]["value"]["structuredContent"] == {
            "effect": "succeeded",
            "value": {"bytes_hex": expected},
        }, response
        checkpoint = json.loads((harness.output / f"state-{name}.stdout").read_text())[
            "data"
        ]["checkpoint"]["value"]
        denials[name] = checkpoint["probes"]
        assert len(denials[name]) == 4, denials[name]
        for index, observed in enumerate(denials[name]):
            denied = observed["response"]
            assert denied["verdict"] == "deny" and denied["output"] is None, denied
            harness.verify_response(
                f"{name}-denial-{index}", observed["request"], denied
            )
        if name == "bob":
            assert private.read_bytes().hex() not in json.dumps(checkpoint), (
                "Alice's file leaked to Bob"
            )
    assert {path.name: path.read_bytes() for path in inputs.iterdir()} == before
    artifact = harness.output / "completed-run.json"
    harness.run(
        "attest",
        [
            harness.chio,
            "process",
            "attest-run",
            "--state",
            harness.state,
            "--plan",
            plan,
            "--out",
            artifact,
        ],
    )
    runtime_id = json.loads((harness.state / "swarm-calls.json").read_text())[
        "runtime_id"
    ]
    verification = harness.run(
        "verify-run",
        [
            harness.chio,
            "process",
            "verify-run",
            "--artifact",
            artifact,
            "--trusted-kernel-pubkey",
            harness.state / "authority.db.kernel.pub",
            "--runtime-id",
            runtime_id,
            "--trusted-launch-policy-signer",
            "shared-probe=" + harness.servers[0]["launch_policy_signer"],
        ],
    )
    assert verification["captured_invocations"] == 2, verification
    assert verification["verified_native_launches"] == 1, verification
    assert "continuation_custody" in verification["checks"], verification
    resumed = harness.run("workers-reopen", command)
    assert resumed["complete"] and resumed["workers"] == report["workers"], resumed
    for name in ["alice", "bob"]:
        retained = harness.run(
            "recovered-state-" + name,
            [
                harness.chio,
                "process",
                "state",
                "--state",
                harness.state,
                "--process",
                name,
            ],
        )
        assert retained["data"]["checkpoint"]["value"]["response"] == responses[name]
    result = {
        "schema": "chio.reference-swarm.authority-qualification.v1",
        "runtime_id": runtime_id,
        "scope_widening_denied": True,
        "peer_authority_denied": True,
        "changed_intent_denied": True,
        "continuation_reuse_denied": True,
        "logical_replay_identical": True,
        "crashed_worker_attempts": 2,
        "protected_files_unchanged": True,
        "captured_invocations": 2,
        "worker_image": args.worker_image,
        "completed_artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "verification": verification,
        "m5_acceptance_complete": False,
        "remaining": [
            "contended budget denial",
            "host death with uncertain effect",
            "revocation",
        ],
    }
    write(harness.output / "qualification.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
