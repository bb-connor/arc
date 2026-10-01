"""Independent governed graphs contend for the original durable family quota."""

import concurrent.futures
import json
import select
import sqlite3
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from chio_process import ProcessClient


def exercise(binary, directory):
    state = directory / "state"
    socket = directory / "host.sock"
    names = ["alice", "bob", "carol", "dave"]
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

    def write(path, value):
        path.write_text(json.dumps(value))
        return path

    config = write(directory / "config.json", {
        "schema": "chio.process.host.v1", "policy": str(policy),
        "execution_nonces": True,
        "mailboxes": [{"id": "jobs"}],
        "children": [{
            "id": name, "parent": "root", "budget_share_bps": 2500,
            "tools": [{"server_id": "chio-ipc", "tool_name": "send_jobs"}],
        } for name in names],
        "limits": {"max_processes": 5, "max_depth": 1, "max_calls": 20},
    })
    plan = write(directory / "plan.json", {
        "schema": "chio.process.swarm-plan.v2", "profile_id": "shared-family",
        "graphs": [{
            "graph_id": f"graph-{index}",
            "calls": [{
                "process": name, "operation_key": "publish",
                "server_id": "chio-ipc", "tool_name": "send_jobs",
                "arguments": {"message_key": name, "payload": {"from": name}},
            } for name in group],
        } for index, group in enumerate([names[:2], names[2:]])],
    })

    def cli(*args):
        result = subprocess.run(
            [binary, *map(str, args)], capture_output=True, text=True, timeout=90,
        )
        assert result.returncode == 0, (args, result.stdout, result.stderr)
        return json.loads(result.stdout)

    cli("process", "init", "--config", config, "--state", state,
        "--aggregate-invocations", 2, "--swarm-plan", plan)
    bootstrap = json.loads((state / "swarm-bootstrap.json").read_text())
    caps = bootstrap["action"]["parameters"]["capabilities"]
    family = caps["root"]["aggregate_invocation_budget"]
    assert family["max_invocations"] == 2, family
    assert all(caps[name]["aggregate_invocation_budget"] == family for name in names)
    authorities = json.loads((state / "swarm-bundles.json").read_text())
    assert len(authorities["graphs"]) == 2
    assert not (state / "swarm-bundle.json").exists()
    for authority in authorities["graphs"]:
        assert authority["joinReceipts"] == authority["terminalReceipts"] == []
    with sqlite3.connect(state / "swarm-runtime.db") as db:
        try:
            db.execute("INSERT INTO runtime_consumed_swarm_continuations VALUES ('forged', 'forged')")
            raise AssertionError("sealed source accepted a write")
        except sqlite3.IntegrityError as failure:
            assert "sealed" in str(failure), failure
    original_source = (state / "swarm-profile.json").read_bytes()
    original_bootstrap = (state / "swarm-bootstrap.json").read_bytes()
    calls = json.loads((state / "swarm-calls.json").read_text())
    descriptors = {}
    clients = {}

    def credentials():
        for name in names:
            path = directory / f"{socket.stem}-{name}.json"
            cli("process", "credential", "--state", state, "--process", name,
                "--socket", socket, "--out", path)
            descriptors[name] = json.loads(path.read_text())
            clients[name] = ProcessClient(str(socket), descriptors[name]["credential"])

    def start():
        host = subprocess.Popen(
            [binary, "process", "serve", "--state", str(state), "--socket", str(socket)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            assert select.select([host.stdout], [], [], 90)[0], "host startup timeout"
            line = host.stdout.readline()
            assert line, host.stderr.read()
            assert json.loads(line)["ready"]
            return host
        except BaseException:
            host.kill()
            host.wait(timeout=20)
            raise

    def invoke(call):
        return clients[call["process"]].invoke(
            call["operation_key"], call["server_id"], call["tool_name"],
            call["arguments"], governed_intent=call["governed_intent"],
        )

    def effects():
        with sqlite3.connect(f"file:{state / 'mailboxes.db'}?mode=ro", uri=True) as db:
            return db.execute("SELECT sender, payload FROM mailbox_messages ORDER BY sequence").fetchall()

    def verify(call, response):
        folder = directory / call["process"]
        folder.mkdir(exist_ok=True)
        request = {field: call[field] for field in [
            "operation_key", "server_id", "tool_name", "arguments",
        ]}
        request["known_outcome_only"] = False
        context = {"runtime_id": calls["runtime_id"], "process_id": call["process"],
                   "capability_id": caps[call["process"]]["id"]}
        return cli("--json", "receipt", "verify-process-response",
                   "--request", write(folder / "request.json", request),
                   "--context", write(folder / "context.json", context),
                   "--response", write(folder / "response.json", response),
                   "--trusted-kernel-pubkey", state / "authority.db.kernel.pub")

    credentials()
    host = start()
    try:
        barrier = threading.Barrier(4, timeout=30)

        def contend(call):
            barrier.wait()
            return invoke(call)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(contend, calls["calls"]))
        assert sorted(response["verdict"] for response in responses) == [
            "allow", "allow", "deny", "deny",
        ], responses
        winners = []
        for call, response in zip(calls["calls"], responses):
            verify(call, response)
            if response["verdict"] == "allow":
                winners.append(call["process"])
            else:
                assert "budget exhausted" in response["reason"], response
                assert response["output"] is None, response
        original_effects = effects()
        assert sorted(row[0] for row in original_effects) == sorted(winners), original_effects
        for sender, payload in original_effects:
            assert json.loads(payload) == {"from": sender}, original_effects
        host.kill()
        host.wait(timeout=20)
        socket = directory / "recovered.sock"
        credentials()
        host = start()
        for call, response in zip(calls["calls"], responses):
            recovered = invoke(call)
            verify(call, recovered)
            assert recovered["verdict"] == response["verdict"], recovered
            if response["verdict"] == "allow":
                assert recovered == response, (response, recovered)
        assert effects() == original_effects
        assert (state / "swarm-profile.json").read_bytes() == original_source
        assert (state / "swarm-bootstrap.json").read_bytes() == original_bootstrap
        with sqlite3.connect(f"file:{state / 'authority.db'}?mode=ro", uri=True) as db:
            quotas = db.execute(
                "SELECT max_invocations, reserved_invocations, captured_invocations "
                "FROM budget_invocation_quotas WHERE profile='chio.aggregate-family-invocation.v1'"
            ).fetchall()
            assert quotas == [(2, 0, 2)], quotas
        return {"effects": 2, "graphs": 2, "allowed": sorted(winners),
                "bootstrap": bootstrap,
                "kernel_key": (state / "authority.db.kernel.pub").read_text().strip(),
                "receipts": [response["receipt_json"] for response in responses]}
    finally:
        if host.poll() is None:
            host.kill()
            host.wait(timeout=20)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="chio-shared-family-") as temporary:
        print(json.dumps(exercise(sys.argv[1], Path(temporary))))
