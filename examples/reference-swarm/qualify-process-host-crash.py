"""Kill the host after a real Enforced write, then prove recovery cannot repeat it."""

import argparse
import hashlib
import json
import os
import platform
import select
import signal
import sqlite3
import subprocess
import time
from pathlib import Path

from process_qualification import Harness, write
from process_native_observation import retain_original_launches, verify_original_launch_signatures


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
    canary = inputs / "canary.txt"
    canary.write_text("allowed-before-host-death\n")
    effect = harness.output / "protected-effect.txt"
    effect.write_bytes(b"")
    harness.server("canary-probe", inputs)
    harness.server("effect-probe", inputs, write_paths=[effect])
    calls = harness.initialize(
        [
            {
                "process": "canary",
                "operation_key": "read-canary",
                "server_id": "canary-probe",
                "tool_name": "read_file",
                "arguments": {"path": str(canary)},
            },
            {
                "process": "writer",
                "operation_key": "write-once",
                "server_id": "effect-probe",
                "tool_name": "append_and_wait",
                "arguments": {"path": str(effect)},
            },
        ]
    )
    workers = [
        {
            "process": call["process"],
            "input": dict(
                call,
                expected_verdict="deny" if call["process"] == "writer" else "allow",
            ),
            "command": [
                "/usr/local/bin/python3",
                "/opt/chio/process-observe-worker.py",
            ],
            "cwd": "/work",
            "container": {"image": args.worker_image},
            "max_attempts": 3,
            "timeout_seconds": 60,
        }
        for call in calls
    ]
    plan = harness.output / "run-plan.json"
    write(
        plan, {"schema": "chio.process.run.v1", "max_parallel": 1, "workers": workers}
    )
    command = list(
        map(
            str,
            [harness.chio, "process", "run", "--state", harness.state, "--plan", plan],
        )
    )
    with (
        (harness.output / "interrupted.stdout").open("w") as stdout,
        (harness.output / "interrupted.stderr").open("w") as stderr,
    ):
        host = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        target_pidfds = {}
        try:
            deadline = time.monotonic() + 180
            while not effect.read_bytes():
                assert host.poll() is None, "host exited before the protected effect"
                assert time.monotonic() < deadline, "protected effect was not observed"
                time.sleep(0.05)
            assert effect.read_bytes() == b"probe-effect\n", (
                "effect repeated before host death"
            )
            assert host.poll() is None, "host already finished before crash injection"
            # Pin both actual targets before killing their parent. Polling
            # pidfds observes those processes even if their numeric PIDs are
            # reaped or reused during recovery.
            for task in Path(f"/proc/{host.pid}/task").iterdir():
                for child in (task / "children").read_text().split():
                    try:
                        executable = Path(f"/proc/{child}/exe").resolve(strict=True)
                    except FileNotFoundError:
                        continue
                    if executable == harness.probe:
                        target_pidfds[int(child)] = os.pidfd_open(int(child))
            assert len(target_pidfds) == 2, target_pidfds
            original_launches = retain_original_launches(harness, target_pidfds)
            # The fixture has written once and cannot return an outcome. Kill
            # the real supervisor while its dispatch is still outstanding.
            host.kill()
            assert host.wait(timeout=15) == -signal.SIGKILL
            poller = select.poll()
            for descriptor in target_pidfds.values():
                poller.register(descriptor, select.POLLIN)
            terminated = set()
            deadline = time.monotonic() + 5
            while len(terminated) != len(target_pidfds):
                remaining = deadline - time.monotonic()
                assert remaining > 0, "confined target survived host death"
                for descriptor, event in poller.poll(max(1, int(remaining * 1000))):
                    assert event & select.POLLIN, event
                    terminated.add(descriptor)
                    poller.unregister(descriptor)
        finally:
            if host.poll() is None:
                host.kill()
                host.wait(timeout=15)
            for descriptor in target_pidfds.values():
                os.close(descriptor)
    write(
        harness.output / "host-death.json",
        {
            "pid": host.pid,
            "signal": signal.SIGKILL,
            "command": command,
            "observed_effect_sha256": hashlib.sha256(effect.read_bytes()).hexdigest(),
            "outcome_was_not_returned": True,
            "terminated_target_pids": sorted(target_pidfds),
        },
    )
    verify_original_launch_signatures(harness, original_launches)
    report = harness.run("recover-workers", command)
    assert report["complete"], report
    snapshots = {worker["process"]: worker for worker in report["workers"]}
    assert snapshots["writer"]["attempts"] == 2, snapshots
    responses = {call["process"]: harness.observe(call) for call in calls}
    assert responses["canary"]["verdict"] == "allow", responses["canary"]
    denied = responses["writer"]
    assert denied["verdict"] == "deny" and denied["output"] is None, denied
    receipt = json.loads(denied["receipt_json"])
    projection = receipt["metadata"]["admission_operation"]
    assert projection["projected_state"] == "outcome_unknown_after_dispatch", projection
    assert projection["retained_dispatch_commit"] is not None, projection
    assert (
        projection["tool_outcome_id"] is None
        and projection["tool_outcome_version"] is None
    ), projection
    original = next(call for call in calls if call["process"] == "writer")
    assert projection["request_id"] == denied["request_id"] == original["request_id"], (
        projection
    )
    assert effect.read_bytes() == b"probe-effect\n", (
        "recovery repeated an uncertain effect"
    )
    resumed = harness.run("recover-again", command)
    assert resumed["complete"] and resumed["workers"] == report["workers"], resumed
    assert effect.read_bytes() == b"probe-effect\n", (
        "completed recovery repeated an effect"
    )
    state = harness.run(
        "recovered-writer",
        [
            harness.chio,
            "process",
            "state",
            "--state",
            harness.state,
            "--process",
            "writer",
        ],
    )
    assert state["data"]["checkpoint"]["value"]["response"] == denied
    database = harness.state / "authority.db"
    assert not Path(str(database) + "-wal").exists()
    with sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True) as db:
        quotas = db.execute(
            "SELECT max_invocations, reserved_invocations, captured_invocations FROM budget_invocation_quotas WHERE profile='chio.aggregate-family-invocation.v1'"
        ).fetchall()
        assert quotas == [(2, 0, 2)], quotas
        claims = db.execute(
            "SELECT participant_kind, resource_id FROM runtime_replay_claim_resources WHERE operation_id=?",
            (projection["operation_id"],),
        ).fetchall()
        assert claims == [("swarm_continuation", "continue-writer")], claims
        assert db.execute(
            "SELECT COUNT(*) FROM runtime_replay_claim_releases WHERE operation_id=?",
            (projection["operation_id"],),
        ).fetchone() == (0,)
    result = {
        "schema": "chio.reference-swarm.host-crash-qualification.v1",
        "caller_receipt_id": receipt["id"],
        "operation_id": projection["operation_id"],
        "request_id": projection["request_id"],
        "state": projection["projected_state"],
        "protected_effect_count": 1,
        "confined_targets_terminated_on_host_death": len(target_pidfds),
        "recovered_worker_attempts": 2,
        "original_request_preserved": True,
        "retained_dispatch_commit": projection["retained_dispatch_commit"],
        "aggregate_projection": quotas,
        "custody_projection": claims,
        "original_native_launches": original_launches,
        "worker_image": args.worker_image,
        "runner": report,
        "m5_acceptance_complete": False,
        "limits": [
            "raw store projections are external observations",
            "original launch signatures are checked; PID linkage and death are external observations",
            "not a complete scenario artifact",
        ],
    }
    write(harness.output / "qualification.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
