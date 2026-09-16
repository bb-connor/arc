"""Four independent confined tasks contend for two durable family invocations."""

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
from contextlib import closing
from pathlib import Path

from process_qualification import Harness, write
from process_native_observation import retain_original_launches, verify_original_launch_signatures


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
    for name in ["alice", "bob", "carol", "dave"]:
        effect = harness.output / f"{name}-effect.txt"
        effect.write_bytes(b"")
        effects[name] = effect
        harness.server(f"{name}-probe", inputs, write_paths=[effect])
        planned.append({
            "process": name, "operation_key": "write-once",
            "server_id": f"{name}-probe", "tool_name": "append_and_wait",
            "arguments": {"path": str(effect)},
        })
    calls = harness.initialize(planned, aggregate_invocations=2, plan={
        "schema": "chio.process.swarm-plan.v2", "profile_id": "budget-contention",
        "graphs": [
            {"graph_id": "first", "calls": planned[:2]},
            {"graph_id": "second", "calls": planned[2:]},
        ],
    })
    original_bootstrap = (harness.state / "swarm-bootstrap.json").read_bytes()
    original_profile = (harness.state / "swarm-profile.json").read_bytes()
    plan = harness.output / "run-plan.json"
    write(plan, {
        "schema": "chio.process.run.v1", "max_parallel": 4,
        "workers": [{
            "process": call["process"],
            "input": dict(call, expected_verdict="deny"),
            "command": ["/usr/local/bin/python3", "/opt/chio/process-observe-worker.py"],
            "cwd": "/work", "container": {"image": args.worker_image},
            "max_attempts": 3, "timeout_seconds": 60,
        } for call in calls],
    })
    command = list(map(str, [harness.chio, "process", "run", "--state", harness.state, "--plan", plan]))
    target_pidfds = {}
    before_crash = {}
    with ((harness.output / "interrupted.stdout").open("w") as stdout,
          (harness.output / "interrupted.stderr").open("w") as stderr):
        host = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        try:
            deadline = time.monotonic() + 180
            while True:
                assert host.poll() is None, "host exited before contention was observed"
                written = [name for name, path in effects.items() if path.read_bytes()]
                assert len(written) <= 2, "family quota allowed more than two effects"
                with closing(sqlite3.connect(
                    f"file:{harness.state / 'process.db'}?mode=ro", uri=True
                )) as db:
                    checkpoints = {
                        name: json.loads(raw) for name, raw in db.execute(
                            "SELECT id, checkpoint FROM processes WHERE id != 'root'"
                        ) if raw != "null"
                    }
                if len(written) == 2 and len(checkpoints) == 2:
                    assert set(written).isdisjoint(checkpoints), checkpoints
                    for name, checkpoint in checkpoints.items():
                        response = checkpoint["response"]
                        assert response["verdict"] == "deny" and response["output"] is None, response
                        assert "budget exhausted" in response["reason"], response
                        before_crash[name] = response
                    break
                assert time.monotonic() < deadline, "overlapping budget contention was not observed"
                time.sleep(0.05)
            for name in written:
                assert effects[name].read_bytes() == b"probe-effect\n", "effect repeated"
            # Both admitted tools are still inside append_and_wait, which never
            # returns. The other two workers already retained quota denials.
            # This proves overlap rather than only sequential quota exhaustion.
            # SQLite's connection context commits or rolls back but does not
            # close the reader. A live observer would prevent WAL removal when
            # the host's last writer exits during the recovery check below.
            with closing(sqlite3.connect(
                f"file:{harness.state / 'authority.db'}?mode=ro", uri=True
            )) as db:
                live_quota = db.execute(
                    "SELECT max_invocations, reserved_invocations, captured_invocations "
                    "FROM budget_invocation_quotas WHERE profile='chio.aggregate-family-invocation.v1'"
                ).fetchall()
                assert live_quota == [(2, 0, 2)], live_quota
            write(harness.output / "overlap.json", {
                "external_observation": True, "effect_workers": sorted(written),
                "quota_denials": before_crash, "aggregate_projection": live_quota,
                "admitted_tools_have_not_returned": True,
            })
            for task in Path(f"/proc/{host.pid}/task").iterdir():
                for child in (task / "children").read_text().split():
                    try:
                        executable = Path(f"/proc/{child}/exe").resolve(strict=True)
                    except FileNotFoundError:
                        continue
                    if executable == harness.probe:
                        target_pidfds[int(child)] = os.pidfd_open(int(child))
            assert len(target_pidfds) == 4, target_pidfds
            original_launches = retain_original_launches(harness, target_pidfds)
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
    write(harness.output / "host-death.json", {
        "pid": host.pid, "signal": signal.SIGKILL, "command": command,
        "terminated_target_pids": sorted(target_pidfds),
        "effect_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest()
                          for name, path in effects.items()},
    })
    verify_original_launch_signatures(harness, original_launches)
    report = harness.run("recover-workers", command)
    assert report["complete"], report
    attempts = {worker["process"]: worker["attempts"] for worker in report["workers"]}
    responses = {call["process"]: harness.observe(call) for call in calls}
    for call in calls:
        name = call["process"]
        response = responses[name]
        assert response["verdict"] == "deny" and response["output"] is None, response
        if name in before_crash:
            assert response == before_crash[name], "recovery replaced the quota denial"
            assert attempts[name] == 1, attempts
            assert effects[name].read_bytes() == b"", "denied worker produced an effect"
        else:
            assert attempts[name] == 2, attempts
            assert effects[name].read_bytes() == b"probe-effect\n", "uncertain effect repeated"
            projection = json.loads(response["receipt_json"])["metadata"]["admission_operation"]
            assert projection["projected_state"] == "outcome_unknown_after_dispatch", projection
            assert projection["request_id"] == response["request_id"] == call["request_id"], projection
            assert projection["retained_dispatch_commit"] is not None, projection
            assert projection["tool_outcome_id"] is None and projection["tool_outcome_version"] is None
    replay = harness.run("recover-again", command)
    assert replay["complete"] and replay["workers"] == report["workers"], replay
    assert (harness.state / "swarm-bootstrap.json").read_bytes() == original_bootstrap
    assert (harness.state / "swarm-profile.json").read_bytes() == original_profile
    for name, path in effects.items():
        assert path.read_bytes() == (b"" if name in before_crash else b"probe-effect\n")
    database = harness.state / "authority.db"
    assert not Path(str(database) + "-wal").exists()
    with closing(sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True)) as db:
        quotas = db.execute(
            "SELECT max_invocations, reserved_invocations, captured_invocations "
            "FROM budget_invocation_quotas WHERE profile='chio.aggregate-family-invocation.v1'"
        ).fetchall()
        assert quotas == [(2, 0, 2)], quotas
    result = {
        "schema": "chio.reference-swarm.budget-qualification.v1",
        "independent_graphs": 2, "competing_workers": 4, "family_max_invocations": 2,
        "overlap_observed": True, "quota_denial_workers": sorted(before_crash),
        "uncertain_effect_workers": sorted(set(effects) - set(before_crash)),
        "protected_effect_count": 2, "confined_targets_terminated_on_host_death": 4,
        "aggregate_projection": quotas, "worker_image": args.worker_image, "runner": report,
        "original_native_launches": original_launches,
        "m5_acceptance_complete": False,
        "limits": ["overlap and store projections are external observations",
                   "original launch signatures are checked; PID linkage and death are external observations",
                   "admitted effects have unknown terminal outcomes",
                   "not a complete scenario artifact"],
    }
    write(harness.output / "qualification.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
