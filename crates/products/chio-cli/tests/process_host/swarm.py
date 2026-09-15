"""Actual process host, signed task authority, sealed custody and restart."""

import copy
import json
import select
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from chio_process import ProcessClient


def exercise(binary, directory):
    repository = Path(__file__).resolve().parents[5]
    state = directory / "state"
    socket = directory / "host.sock"
    policy = directory / "policy.yaml"
    policy.write_text("""kernel:
  max_capability_ttl: 3600
  durable_admission_mode: all
  require_swarm_admission: true
capabilities:
  default:
    tools:
      - server: chio-ipc
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    children = [
        {
            "id": name,
            "parent": "root",
            "tools": [{"server_id": "chio-ipc", "tool_name": "send_jobs"}],
            "budget_share_bps": 5000,
        }
        for name in ["alice", "bob"]
    ]
    config = directory / "config.json"
    config.write_text(
        json.dumps(
            {
                "schema": "chio.process.host.v1",
                "policy": str(policy),
                "mailboxes": [{"id": "jobs"}],
                "children": children,
                "limits": {"max_processes": 3, "max_depth": 1, "max_calls": 20},
            }
        )
    )
    plan = directory / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "schema": "chio.process.swarm-plan.v1",
                "graph_id": "mailbox-fanout",
                "calls": [
                    {
                        "process": name,
                        "operation_key": "publish",
                        "server_id": "chio-ipc",
                        "tool_name": "send_jobs",
                        "arguments": {"message_key": name, "payload": {"from": name}},
                    }
                    for name in ["alice", "bob"]
                ],
            }
        )
    )

    def cli(*args, success=True):
        result = subprocess.run(
            [binary, "process", *map(str, args)],
            capture_output=True,
            check=False,
            text=True,
            timeout=90,
        )
        assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
        return json.loads(result.stdout) if success else result.stderr

    # Missing authority is refused before creating a host.
    cli("init", "--config", config, "--state", state, success=False)
    assert not state.exists()
    cli(
        "init",
        "--config",
        config,
        "--state",
        state,
        "--aggregate-invocations",
        "2",
        "--swarm-plan",
        plan,
    )
    calls = json.loads((state / "swarm-calls.json").read_text())["calls"]
    bundle = json.loads((state / "swarm-bundle.json").read_text())
    assert bundle["joinReceipts"] == [] and bundle["terminalReceipts"] == []
    bootstrap = json.loads((state / "swarm-bootstrap.json").read_text())
    assert bootstrap["receipt_kind"] == "trace_observation"
    caps = bootstrap["action"]["parameters"]["capabilities"]
    assert (
        caps["alice"]["aggregate_invocation_budget"]
        == caps["bob"]["aggregate_invocation_budget"]
        == caps["root"]["aggregate_invocation_budget"]
    )
    with sqlite3.connect(state / "swarm-runtime.db") as db:
        try:
            db.execute(
                "INSERT INTO runtime_consumed_swarm_continuations VALUES ('forged', 'forged')"
            )
            raise AssertionError("sealed source accepted a legacy continuation write")
        except sqlite3.IntegrityError as failure:
            assert "sealed" in str(failure), failure
    descriptors = {}
    for name in ["alice", "bob"]:
        out = directory / f"{name}.json"
        cli(
            "credential",
            "--state",
            state,
            "--process",
            name,
            "--socket",
            socket,
            "--out",
            out,
        )
        descriptors[name] = json.loads(out.read_text())
    clients = {
        name: ProcessClient(d["socket_path"], d["credential"])
        for name, d in descriptors.items()
    }

    def start():
        host = subprocess.Popen(
            [
                binary,
                "process",
                "serve",
                "--state",
                str(state),
                "--socket",
                str(socket),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert select.select([host.stdout], [], [], 90)[0], "host startup timeout"
        line = host.stdout.readline()
        assert line, host.stderr.read()
        assert json.loads(line)["ready"]
        return host

    def invoke(call, client=None, **overrides):
        fields = {"governed_intent": call["governed_intent"], **overrides}
        return (client or clients[call["process"]]).invoke(
            call["operation_key"],
            call["server_id"],
            call["tool_name"],
            call["arguments"],
            **fields,
        )

    def effects():
        with sqlite3.connect(f"file:{state / 'mailboxes.db'}?mode=ro", uri=True) as db:
            return db.execute(
                "SELECT sender, payload FROM mailbox_messages ORDER BY sequence"
            ).fetchall()

    host = start()
    try:
        no_context = clients["alice"].invoke(
            "missing",
            "chio-ipc",
            "send_jobs",
            {"message_key": "unplanned", "payload": {"bad": True}},
        )
        assert no_context["verdict"] == "deny", no_context
        assert effects() == []
        # A peer's complete context cannot transfer its issued task capability.
        wrong = copy.deepcopy(calls[0])
        wrong["operation_key"] = "wrong-peer"
        denied = invoke(wrong, clients["bob"])
        assert denied["verdict"] == "deny", denied
        assert effects() == []
        first = invoke(calls[0])
        assert first["verdict"] == "allow", first
        assert len(effects()) == 1, effects()
        first_receipt = json.loads(first["receipt_json"])
        assert (
            first_receipt["metadata"]["chio_runtime"]["verified_swarm_request_binding"][
                "capability_sha256"
            ]
            == descriptors["alice"]["caller_capability_sha256"]
        )
        assert first_receipt["metadata"]["route"]["bridge"] == "chio"
        # Retained output survives abrupt host death with its original receipt.
        host.kill()
        host.wait(timeout=20)
        assert socket.exists(), "abrupt death must leave the old endpoint"
        socket = directory / "recovered.sock"
        for name in ["alice", "bob"]:
            out = directory / f"{name}-recovered.json"
            cli(
                "credential",
                "--state",
                state,
                "--process",
                name,
                "--socket",
                socket,
                "--out",
                out,
            )
            descriptors[name] = json.loads(out.read_text())
            clients[name] = ProcessClient(
                descriptors[name]["socket_path"], descriptors[name]["credential"]
            )
        host = start()
        replay = invoke(calls[0])
        assert replay["receipt_json"] == first["receipt_json"], replay
        assert len(effects()) == 1, effects()
        second = invoke(calls[1])
        assert second["verdict"] == "allow", second
        assert [row[0] for row in effects()] == ["alice", "bob"], effects()
        reused = copy.deepcopy(calls[0])
        reused["operation_key"] = "reuse"
        refused = invoke(reused)
        assert refused["verdict"] == "deny", refused
        assert len(effects()) == 2
        # Exercise the shipped worker against real retained outcomes on Unix.
        # Linux below additionally runs the existing native supervisor.
        for call in calls:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(repository / "examples/reference-swarm/process-worker.py"),
                ],
                input=json.dumps(
                    {
                        "schema": "chio.process.worker-bootstrap.v1",
                        "connection": descriptors[call["process"]],
                        "input": call,
                    }
                ),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            assert completed.returncode == 0, (completed.stdout, completed.stderr)
            checkpoint = clients[call["process"]].inspect()["checkpoint"]
            assert checkpoint["value"]["response"]["verdict"] == "allow", checkpoint
        assert len(effects()) == 2
    finally:
        if host.poll() is None:
            host.terminate()
            host.wait(timeout=30)
    if sys.platform == "linux":
        completed = subprocess.run(
            [
                sys.executable,
                str(repository / "examples/reference-swarm/process-run.py"),
                "--chio",
                binary,
                "--state",
                str(state),
                "--output",
                str(directory / "verified-run"),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert completed.returncode == 0, (completed.stdout, completed.stderr)
        report = json.loads(completed.stdout)
        assert report["verified_workers"] == ["alice", "bob"], report
        assert report["runner"]["complete"], report
        assert len(effects()) == 2
    # The host has exited and checkpointed its authority. Inspect that stable
    # snapshot without requesting new WAL sidecars from the hardened VFS.
    assert not (state / "authority.db-wal").exists()
    with sqlite3.connect(
        f"file:{state / 'authority.db'}?mode=ro&immutable=1", uri=True
    ) as db:
        claims = db.execute(
            "SELECT participant_kind, resource_id FROM runtime_replay_claim_resources ORDER BY resource_id"
        ).fetchall()
        assert claims == [
            ("swarm_continuation", "continue-alice"),
            ("swarm_continuation", "continue-bob"),
        ], claims
        assert (
            db.execute(
                "SELECT COUNT(*) FROM runtime_replay_migration_events"
            ).fetchone()[0]
            == 3
        )
        assert (
            db.execute("SELECT COUNT(*) FROM runtime_replay_claim_releases").fetchone()[
                0
            ]
            == 0
        )
    # A missing or altered profile cannot make this policy serve ordinary calls.
    profile_path = state / "swarm-profile.json"
    profile = profile_path.read_bytes()
    profile_path.unlink()
    cli("serve", "--state", state, "--socket", socket, success=False)
    profile_path.write_bytes(profile)
    damaged = json.loads(profile)
    damaged["body"]["routes"]["chio-ipc"]["selected_route"] = "forged"
    profile_path.write_text(json.dumps(damaged))
    failure = cli("serve", "--state", state, "--socket", socket, success=False)
    assert "signature" in failure, failure
    profile_path.write_bytes(profile)
    assert len(effects()) == 2
    return {
        "kernel_key": descriptors["alice"]["kernel_key"],
        "bootstrap": bootstrap,
        "receipts": [first["receipt_json"], second["receipt_json"]],
        "effects": 2,
    }


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="chio-swarm-host-") as temporary:
        print(json.dumps(exercise(sys.argv[1], Path(temporary))))
