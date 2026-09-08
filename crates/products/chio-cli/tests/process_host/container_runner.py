"""Real Docker/native runner crash, ownership, revocation and effect recovery."""

import argparse
import json
import os
import sqlite3
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from chio_process import ProcessClient, WorkerError

HERE = Path(__file__).resolve().parent
DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]


def docker(*args, check=True):
    return subprocess.run([*DOCKER, *args], capture_output=True, text=True, timeout=35, check=check)


def cli(binary, *args, success=True):
    result = subprocess.run(
        [str(binary), "process", *map(str, args)],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
    return result


def prepare(binary, directory, image, mode, *, attempts=2, timeout=60):
    directory.mkdir(mode=0o700)
    state = directory / "state"
    policy = directory / "policy.yaml"
    policy.write_text("""kernel:
  max_capability_ttl: 3600
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: chio-ipc
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    config = directory / "config.json"
    config.write_text(
        json.dumps(
            {
                "schema": "chio.process.host.v1",
                "policy": str(policy),
                "mailboxes": [{"id": "jobs"}],
                "limits": {"max_processes": 1, "max_depth": 0, "max_calls": 12},
            }
        )
    )
    initialized = json.loads(cli(binary, "init", "--config", config, "--state", state).stdout)
    (directory / "kernel.pub").write_text(initialized["kernel_key"])
    plan = directory / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "schema": "chio.process.run.v1",
                "max_parallel": 1,
                "workers": [
                    {
                        "process": "root",
                        "command": [
                            "/usr/local/bin/python",
                            "-u",
                            "-c",
                            (HERE / "container_worker.py").read_text(),
                        ],
                        "cwd": "/work",
                        "container": {"image": image},
                        "input": {"uid": os.getuid(), "state": str(state), "mode": mode},
                        "max_attempts": attempts,
                        "timeout_seconds": timeout,
                    }
                ],
            }
        )
    )
    return state, plan


def launch(binary, state, plan):
    return subprocess.Popen(
        [str(binary), "process", "run", "--state", str(state), "--plan", str(plan)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def ready(state, process, attempt, process_id="root"):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        assert process.poll() is None, process.communicate()
        if (state / "runner.db").exists():
            with sqlite3.connect(state / "runner.db") as db:
                if not db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='run_containers'"
                ).fetchone():
                    time.sleep(0.05)
                    continue
                row = db.execute(
                    "SELECT container_id FROM run_containers WHERE attempt=? AND process=?",
                    (attempt, process_id),
                ).fetchone()
            if row and row[0]:
                result = docker("exec", row[0], "cat", "/work/ready.json", check=False)
                if result.returncode == 0:
                    return row[0], json.loads(result.stdout)
        time.sleep(0.05)
    raise AssertionError("container did not become ready")


def absent(container):
    assert not docker(
        "container", "ls", "--all", "--quiet", "--filter", f"id={container}"
    ).stdout.strip()


def finished(process, success=True):
    stdout, stderr = process.communicate(timeout=90)
    assert (process.returncode == 0) == success, (stdout, stderr)
    return json.loads(stdout) if stdout.strip() else None


def settled(state):
    with sqlite3.connect(state / "runner.db") as db:
        assert db.execute("SELECT COUNT(*) FROM run_containers").fetchone()[0] == 0


def stop(process):
    if process.poll() is None:
        process.kill()
        process.communicate(timeout=15)


def crash_recovery(binary, root, image):
    state, plan = prepare(binary, root / "host-death", image, "host-death")
    host = launch(binary, state, plan)
    old_id = None
    try:
        old_id, first = ready(state, host, 1)
        profile = json.loads(docker("inspect", old_id).stdout)[0]
        assert profile["HostConfig"]["NetworkMode"] == "none"
        assert profile["HostConfig"]["ReadonlyRootfs"]
        assert profile["HostConfig"]["Memory"] == 512 * 1024 * 1024
        assert profile["HostConfig"]["PidsLimit"] == 64
        assert len(profile["Mounts"]) == 1 and not profile["Mounts"][0]["RW"]
        old_socket = Path(profile["Mounts"][0]["Source"])
        assert len(os.fsencode(old_socket)) < 104
        assert profile["Mounts"][0]["Destination"] == "/run/chio/process.sock"
        stop(host)
        assert json.loads(docker("inspect", old_id).stdout)[0]["State"]["Running"]
        export = cli(binary, "export", "--state", state, success=False)
        assert "container ownership is unresolved" in export.stderr

        with sqlite3.connect(state / "runner.db") as db:
            engine = db.execute("SELECT engine FROM run_containers").fetchone()[0]
            db.execute("UPDATE run_containers SET engine='another-engine'")
        refused = launch(binary, state, plan)
        finished(refused, success=False)
        with sqlite3.connect(state / "runner.db") as db:
            assert db.execute("SELECT attempts FROM run_workers").fetchone()[0] == 1
            db.execute("UPDATE run_containers SET engine=?", (engine,))

        # A renamed owned object must block recovery before any replacement.
        docker("rename", old_id, "chio-test-renamed-" + old_id[:12])
        refused = launch(binary, state, plan)
        finished(refused, success=False)
        with sqlite3.connect(state / "runner.db") as db:
            assert db.execute("SELECT attempts FROM run_workers").fetchone()[0] == 1
        impostor = docker(
            "create",
            "--name",
            profile["Name"].lstrip("/"),
            "--label",
            "chio.runner.owner=another-owner",
            image,
        ).stdout.strip()
        try:
            finished(launch(binary, state, plan), success=False)
            assert json.loads(docker("inspect", impostor).stdout)[0]["Id"] == impostor
            with sqlite3.connect(state / "runner.db") as db:
                assert db.execute("SELECT attempts FROM run_workers").fetchone()[0] == 1
        finally:
            docker("rm", "--force", "--volumes", impostor)
        docker("rename", old_id, profile["Name"].lstrip("/"))

        host = launch(binary, state, plan)
        new_id, second = ready(state, host, 2)
        absent(old_id)
        assert new_id != old_id
        assert first["receipt_json"] == second["receipt_json"]
        assert first["connection"]["credential"] != second["connection"]["credential"]
        assert not old_socket.parent.exists(), "old endpoint survived recovery"
        with sqlite3.connect(state / "runner.db") as db:
            name = db.execute("SELECT name FROM run_socket_leases WHERE singleton=1").fetchone()[0]
        socket = Path("/tmp") / name / "process.sock"
        stale = ProcessClient(str(socket), first["connection"]["credential"])
        try:
            stale.inspect()
        except WorkerError as error:
            assert error.code == "unauthenticated", error.code
        else:
            raise AssertionError("old attempt credential was accepted")
        docker("exec", new_id, "touch", "/work/continue")
        report = finished(host)
        assert not socket.parent.exists(), "completed endpoint was not removed"
        assert report["complete"] and report["workers"][0]["attempts"] == 2
        assert report["workers"][0]["resource_accounting"] == "unavailable_container_cgroup"
        absent(new_id)
        settled(state)
        logs = cli(binary, "logs", "--state", state, "--process", "root", "--attempt", 2)
        assert second["connection"]["credential"] not in logs.stdout
        assert "[REDACTED]" in logs.stdout
        receipt = root / "receipt.json"
        receipt.write_text(second["receipt_json"])
        verified = subprocess.run(
            [
                str(binary),
                "--json",
                "receipt",
                "verify",
                "--input",
                str(receipt),
                "--trusted-kernel-pubkey",
                str(state.parent / "kernel.pub"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert verified.returncode == 0, verified.stderr
        again = finished(launch(binary, state, plan))
        assert again["workers"][0]["attempts"] == 2
        cli(binary, "export", "--state", state)
        return {"attempts": 2, "messages": 1, "original_receipt_verified": True}
    finally:
        stop(host)
        # Test cleanup uses only IDs reserved by this fixture's native journal.
        if (state / "runner.db").exists():
            with sqlite3.connect(state / "runner.db") as db:
                ids = (
                    db.execute("SELECT container_id FROM run_containers").fetchall()
                    if db.execute(
                        "SELECT 1 FROM sqlite_master WHERE name='run_containers'"
                    ).fetchone()
                    else []
                )
            for (identifier,) in ids:
                if identifier:
                    docker("rm", "--force", "--volumes", identifier, check=False)


def parallel_shutdown(binary, root, image):
    state, plan = prepare(binary, root / "parallel", image, "parallel")
    # Use a fresh host because its capability tree is immutable after init.
    config = state.parent / "config.json"
    value = json.loads(config.read_text())
    value["limits"].update(max_processes=2, max_depth=1)
    value["children"] = [
        {
            "id": "leaf",
            "parent": "root",
            "budget_share_bps": 4000,
            "tools": [{"server_id": "chio-ipc", "tool_name": "send_jobs"}],
        }
    ]
    config.write_text(json.dumps(value))
    state = state.parent / "parallel-state"
    cli(binary, "init", "--config", config, "--state", state)
    value = json.loads(plan.read_text())
    value["max_parallel"] = 2
    value["workers"].append({**value["workers"][0], "process": "leaf"})
    plan.write_text(json.dumps(value))
    host = launch(binary, state, plan)
    ids = []
    try:
        ids.append(ready(state, host, 1)[0])
        ids.append(ready(state, host, 1, "leaf")[0])
        assert len(set(ids)) == 2
        host.terminate()
        report = finished(host, success=False)
        assert all(worker["attempts"] == 1 for worker in report["workers"])
        settled(state)
        for identifier in ids:
            absent(identifier)
        return {"concurrent_workers": 2, "removed_on_sigterm": True}
    finally:
        stop(host)
        for identifier in ids:
            docker("rm", "--force", "--volumes", identifier, check=False)


def uncertain_create(binary, root, image):
    state, plan = prepare(binary, root / "uncertain", image, "complete")
    assert finished(launch(binary, state, plan))["complete"]
    owner = uuid.uuid4().hex
    name = "chio-run-" + owner
    engine = docker("info", "--format", "{{.ID}}").stdout.strip()
    # Simulate the persisted side of a create whose response was lost. The
    # completed worker must not gain another attempt while this is reconciled.
    with sqlite3.connect(state / "runner.db") as db:
        db.execute(
            "INSERT INTO run_containers(owner,process,attempt,engine) VALUES(?,?,?,?)",
            (owner, "root", 2, engine),
        )
    report = finished(launch(binary, state, plan), success=False)
    assert not report["complete"] and report["workers"][0]["attempts"] == 1
    assert report["pending_container_records"] == 1
    with sqlite3.connect(state / "runner.db") as db:
        assert db.execute("SELECT container_id FROM run_containers").fetchone() == (None,)
    assert (
        "container ownership is unresolved"
        in cli(binary, "export", "--state", state, success=False).stderr
    )
    late = docker(
        "create",
        "--name",
        name,
        "--label",
        "chio.runner.owner=" + owner,
        "--entrypoint",
        "/usr/local/bin/python",
        image,
        "-c",
        "raise SystemExit(99)",
    ).stdout.strip()
    try:
        assert not json.loads(docker("inspect", late).stdout)[0]["State"]["Running"]
        assert finished(launch(binary, state, plan))["complete"]
        absent(late)
        settled(state)
        cli(binary, "export", "--state", state)
    finally:
        docker("rm", "--force", "--volumes", late, check=False)
    return {"absent_intent_retained": True, "late_inert_create_removed": True}


def exhausted_after_host_death(binary, root, image):
    state, plan = prepare(binary, root / "exhausted", image, "host-death", attempts=1)
    host = launch(binary, state, plan)
    container = None
    try:
        container, _ = ready(state, host, 1)
        stop(host)
        report = finished(launch(binary, state, plan), success=False)
        assert report["workers"][0]["attempts"] == 1
        assert report["workers"][0]["state"] == "failed"
        absent(container)
        settled(state)
        return {"attempts": 1, "stale_container_removed_before_budget_refusal": True}
    finally:
        stop(host)
        if container:
            docker("rm", "--force", "--volumes", container, check=False)


def image_volumes(binary, root, image):
    fixture = docker("create", image).stdout.strip()
    derived = None
    try:
        derived = docker("commit", "--change", 'VOLUME ["/unbounded"]', fixture).stdout.strip()
        state, plan = prepare(binary, root / "volumes", derived, "complete")
        report = finished(launch(binary, state, plan), success=False)
        assert report["workers"][0]["attempts"] == 0
        settled(state)
        return True
    finally:
        docker("rm", "--force", "--volumes", fixture, check=False)
        if derived:
            docker("image", "rm", "--no-prune", derived, check=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--image-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists(), args.output
    os.umask(0o077)
    temporary = Path(tempfile.mkdtemp(prefix="chio-native-container-"))
    root = temporary / ("durable-state-" + "x" * 120)
    root.mkdir(mode=0o700)
    assert len(os.fsencode(root)) > 108
    binary = args.chio.resolve()
    image = json.loads(args.image_file.read_text())["image"]
    evidence = {"state_directory": str(root), "image": image}
    evidence["host_death"] = crash_recovery(binary, root, image)
    evidence["exhausted_after_host_death"] = exhausted_after_host_death(binary, root, image)
    evidence["parallel_shutdown"] = parallel_shutdown(binary, root, image)
    evidence["uncertain_create"] = uncertain_create(binary, root, image)
    evidence["image_volumes_refused"] = image_volumes(binary, root, image)
    for mode, expected in [
        ("worker-death", "exit_0"),
        ("timeout", "timeout"),
        ("flood", "output_ceiling"),
    ]:
        state, plan = prepare(
            binary, root / mode, image, mode, timeout=3 if mode == "timeout" else 60
        )
        report = finished(launch(binary, state, plan), success=mode == "worker-death")
        assert report["workers"][0]["outcome"] == expected, report
        assert report["workers"][0]["attempts"] == 2
        settled(state)
        evidence[mode] = report
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence))


if __name__ == "__main__":
    main()
