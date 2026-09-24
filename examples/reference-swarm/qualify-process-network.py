"""Exercise a real forbidden socket operation through an Enforced process host."""

import argparse
import hashlib
import json
import os
import platform
import signal
import socket
import sqlite3
import subprocess
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
    canary = inputs / "canary.txt"
    canary.write_text("allowed-network-control\n")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(10)
        address = f"127.0.0.1:{listener.getsockname()[1]}"
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "connect_socket",
                "arguments": {"address": address},
            },
        }
        control = subprocess.run(
            [str(harness.probe)],
            input=json.dumps(request) + "\n",
            text=True,
            capture_output=True,
            timeout=30,
            check=True,
        )
        assert (
            json.loads(control.stdout)["result"]["structuredContent"]["effect"]
            == "succeeded"
        )
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(10)
            received = bytearray()
            while chunk := connection.recv(128):
                received.extend(chunk)
            assert received == b"probe-effect\n", received
        write(
            harness.output / "positive-control.json",
            {
                "address": address,
                "connected": True,
                "bytes": len(received),
                "probe_sha256": hashlib.sha256(harness.probe.read_bytes()).hexdigest(),
            },
        )
        # A distinct server lets the useful canary finish even when the forbidden
        # syscall terminates the network tool. Both use the same hashed binary.
        harness.server("canary-probe", inputs)
        harness.server("network-probe", inputs)
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
                    "process": "network",
                    "operation_key": "attempt-network",
                    "server_id": "network-probe",
                    "tool_name": "connect_socket",
                    "arguments": {"address": address},
                },
            ]
        )
        workers = []
        for call in calls:
            call = dict(
                call,
                expected_verdict="deny" if call["process"] == "network" else "allow",
            )
            workers.append(
                {
                    "process": call["process"],
                    "input": call,
                    "command": [
                        "/usr/local/bin/python3",
                        "/opt/chio/process-observe-worker.py",
                    ],
                    "cwd": "/work",
                    "container": {"image": args.worker_image},
                    "max_attempts": 1,
                    "timeout_seconds": 60,
                }
            )
        plan = harness.output / "run-plan.json"
        write(
            plan,
            {"schema": "chio.process.run.v1", "max_parallel": 2, "workers": workers},
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
        content = responses["canary"]["output"]["value"]["structuredContent"]
        assert content == {
            "effect": "succeeded",
            "value": {"bytes_hex": canary.read_bytes().hex()},
        }, content
        denied = responses["network"]
        assert denied["verdict"] == "deny" and denied["output"] is None, denied
        listener.settimeout(0.2)
        try:
            extra, _ = listener.accept()
        except TimeoutError:
            pass
        else:
            extra.close()
            raise AssertionError("forbidden network operation reached the listener")

    receipt = json.loads(denied["receipt_json"])
    reference = receipt["metadata"]["native_launch"]
    launch = harness.output / "network-probe-launch"
    policy = json.loads((launch / "cage-launch-policy.json").read_text())
    database = Path(policy["body"]["receipt"]["database_path"])
    assert not Path(str(database) + "-wal").exists(), (
        "native receipt store is not checkpointed"
    )
    with sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True) as db:
        receipts = [
            json.loads(row[0])
            for row in db.execute(
                "SELECT raw_json FROM chio_tool_receipts ORDER BY seq"
            )
        ]
    enforcement = next(
        item for item in receipts if item["id"] == reference["receipt_id"]
    )
    body = enforcement["metadata"]["cage_receipt"]
    terminals = [
        item
        for item in receipts
        if item["metadata"]["cage_receipt"]["attempt_id"] == body["attempt_id"]
        and item["metadata"]["cage_receipt"]["stage"] == "terminal_exit"
    ]
    assert len(terminals) == 1, terminals
    terminal = terminals[0]
    native = terminal["metadata"]["cage_receipt"]["enforcement_record"]
    assert native["exit"]["signal"] == signal.SIGSYS, native
    assert native["fully_enforced"]["prepared"]["seccomp_status"] == "fully_enforced", (
        native
    )
    assert (
        body["bindings"]["target_binding_digest"]
        == hashlib.sha256(harness.probe.read_bytes()).hexdigest()
    )
    receipts_path = harness.output / "native-receipts.ndjson"
    receipts_path.write_text(
        "\n".join(json.dumps(item) for item in [enforcement, terminal]) + "\n"
    )
    key = harness.output / "native-receipt.pub"
    key.write_text(policy["body"]["receipt"]["trusted_signer_public_key"])
    harness.run(
        "verify-native-receipts",
        [
            harness.chio,
            "--json",
            "receipt",
            "verify",
            "--input",
            receipts_path,
            "--trusted-kernel-pubkey",
            key,
        ],
    )
    result = {
        "schema": "chio.reference-swarm.network-qualification.v1",
        "positive_control_connected": True,
        "confined_connection_absent": True,
        "caller_verdict": denied["verdict"],
        "caller_receipt_id": receipt["id"],
        "native_launch_receipt_id": enforcement["id"],
        "terminal_receipt_id": terminal["id"],
        "exit_signal": native["exit"]["signal"],
        "worker_image": args.worker_image,
        "runner": report,
        "m5_acceptance_complete": False,
        "limits": [
            "not a complete scenario artifact",
            "raw native readback is not an inclusion audit",
        ],
    }
    write(harness.output / "qualification.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
