"""Installed workers retain live claims and release them after renewal stops."""

import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from chio_process import ProcessClient

HERE = Path(__file__).resolve()


def write(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value))
    temporary.replace(path)


def client(directory, process):
    connection = json.loads((directory / f"{process}.json").read_text())
    return ProcessClient(connection["socket_path"], connection["credential"])


def invoke(directory, process, key, tool, arguments, allow=True):
    result = client(directory, process).invoke(
        key, "chio-ipc", tool, arguments, known_outcome_only=True
    )
    assert (result["verdict"] == "allow") == allow, result
    with (directory / "receipts.ndjson").open("a") as stream:
        stream.write(json.dumps(result) + "\n")
    return result


def value(result):
    return result["output"]["value"]


def holder(directory, enabled):
    claimed = invoke(
        directory, "holder", "claim", "claim_jobs", {"limit": 1, "lease_ms": 5000}
    )
    message = value(claimed)["messages"][0]
    renewal = None
    if enabled:
        renewal = invoke(
            directory,
            "holder",
            "renew-1",
            "renew_jobs",
            {"sequence": "1", "claim": "1", "lease_ms": 30000},
        )
        assert value(renewal)["lease_expires_at_ms"] > message["lease_expires_at_ms"]
    write(directory / "holder-ready.json", {"claim": claimed, "renewal": renewal})
    # Keep the real worker alive beyond the original lease. The driver can
    # then kill this owned process to verify eventual takeover.
    time.sleep(45)
    raise AssertionError("driver did not stop its holder")


def exercise(binary, directory, mode):
    directory.mkdir(mode=0o700)
    enabled = mode != "baseline"
    state = directory / "host"
    socket = directory / "host.sock"
    (directory / "policy.yaml").write_text("""kernel:
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
    names = ["claim_jobs", "complete_jobs"] + (["renew_jobs"] if enabled else [])
    mailbox = {"id": "jobs"}
    if enabled:
        mailbox["renewable_leases"] = True
    config = {
        "schema": "chio.process.host.v1",
        "policy": str(directory / "policy.yaml"),
        "mailboxes": [mailbox],
        "limits": {"max_processes": 3, "max_depth": 1, "max_calls": 100},
        "children": [
            {
                "id": process,
                "parent": "root",
                "budget_share_bps": 4000,
                "tools": [
                    {"server_id": "chio-ipc", "tool_name": name} for name in names
                ],
            }
            for process in ("holder", "peer")
        ],
    }
    write(directory / "config.json", config)

    def cli(*args):
        result = subprocess.run(
            [binary, "process", *map(str, args)],
            capture_output=True,
            text=True,
            timeout=90,
            check=True,
        )
        return json.loads(result.stdout)

    initialized = cli("init", "--config", directory / "config.json", "--state", state)
    (directory / "kernel.pub").write_text(initialized["kernel_key"])

    def provision(suffix):
        for process in ("root", "holder", "peer"):
            descriptor = directory / f"{process}-{suffix}.json"
            cli(
                "credential",
                "--state",
                state,
                "--process",
                process,
                "--socket",
                socket,
                "--out",
                descriptor,
            )
            write(directory / f"{process}.json", json.loads(descriptor.read_text()))

    provision("initial")

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
        try:
            assert select.select([host.stdout], [], [], 90)[0], "host startup timed out"
            line = host.stdout.readline()
            assert line, host.stderr.read()
            assert json.loads(line)["ready"]
            return host
        except BaseException:
            host.kill()
            host.communicate(timeout=15)
            raise

    host = start()
    worker = None
    try:
        invoke(
            directory,
            "root",
            "send",
            "send_jobs",
            {"message_key": "one", "payload": {"task": 1}},
        )
        with (directory / "holder.log").open("w") as log:
            worker = subprocess.Popen(
                [
                    sys.executable,
                    str(HERE),
                    "--holder",
                    str(directory),
                    str(int(enabled)),
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        deadline = time.monotonic() + 30
        while not (directory / "holder-ready.json").exists():
            assert worker.poll() is None, (directory / "holder.log").read_text()
            assert time.monotonic() < deadline, "holder startup timed out"
            time.sleep(0.02)
        ready = json.loads((directory / "holder-ready.json").read_text())
        original_deadline = value(ready["claim"])["messages"][0]["lease_expires_at_ms"]
        if mode == "host-death":
            host.kill()
            host.communicate(timeout=15)
            socket = directory / "host-restarted.sock"
            provision("restarted")
            host = start()
            replay = invoke(
                directory,
                "holder",
                "renew-1",
                "renew_jobs",
                {"sequence": "1", "claim": "1", "lease_ms": 30000},
            )
            assert replay["receipt_json"] == ready["renewal"]["receipt_json"]
            assert value(replay) == value(ready["renewal"])
        while time.time_ns() // 1_000_000 <= original_deadline:
            time.sleep(0.02)
        assert worker.poll() is None
        competitor = invoke(
            directory, "peer", "claim-1", "claim_jobs", {"limit": 1, "lease_ms": 5000}
        )
        messages = value(competitor)["messages"]
        if enabled:
            assert messages == [], competitor
            final_deadline = value(ready["renewal"])["lease_expires_at_ms"]
            assert final_deadline > time.time_ns() // 1_000_000, (
                "qualification missed the renewed lease"
            )
            worker.kill()
            worker.wait(timeout=15)
            while time.time_ns() // 1_000_000 <= final_deadline:
                time.sleep(0.02)
            invoke(
                directory,
                "holder",
                "expired-renew",
                "renew_jobs",
                {"sequence": "1", "claim": "1", "lease_ms": 30000},
                allow=False,
            )
            takeover = invoke(
                directory,
                "peer",
                "claim-2",
                "claim_jobs",
                {"limit": 1, "lease_ms": 5000},
            )
            messages = value(takeover)["messages"]
        assert len(messages) == 1 and messages[0]["claim"] == "2", messages
        invoke(
            directory,
            "holder",
            "stale-complete",
            "complete_jobs",
            {"sequence": "1", "claim": "1"},
            allow=False,
        )
        completed = invoke(
            directory,
            "peer",
            "complete",
            "complete_jobs",
            {"sequence": "1", "claim": "2"},
        )
        assert value(completed)["status"] == "completed"
    finally:
        if worker is not None and worker.poll() is None:
            worker.kill()
            worker.wait(timeout=15)
        if host.poll() is None:
            host.send_signal(signal.SIGTERM)
        try:
            host.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            host.kill()
            host.communicate(timeout=15)
            raise
    receipts = [
        json.loads(line)
        for line in (directory / "receipts.ndjson").read_text().splitlines()
    ]
    originals = {r["request_id"]: r["receipt_json"] for r in receipts}
    verified_path = directory / "original-receipts.ndjson"
    verified_path.write_text("\n".join(originals.values()) + "\n")
    verified = subprocess.run(
        [
            binary,
            "receipt",
            "verify",
            "--json",
            "--input",
            str(verified_path),
            "--trusted-kernel-pubkey",
            str(directory / "kernel.pub"),
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert json.loads(verified.stdout)["receipts_verified"] == len(originals)
    return {
        "mode": mode,
        "renewal_enabled": enabled,
        "takeover_while_holder_alive": not enabled,
        "receipts_verified": len(originals),
        "state": str(state),
    }


if __name__ == "__main__":
    os.umask(0o077)
    if sys.argv[1] == "--holder":
        holder(Path(sys.argv[2]), bool(int(sys.argv[3])))
    else:
        temporary = Path(tempfile.mkdtemp(prefix="chio-mailbox-renewal-"))
        modes = ["baseline"] if "--baseline" in sys.argv else ["renewal", "host-death"]
        profiles = [exercise(sys.argv[1], temporary / mode, mode) for mode in modes]
        print(json.dumps({"profiles": profiles, "private_state": str(temporary)}))
