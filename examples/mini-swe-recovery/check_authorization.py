"""Exercise the worker probe with a real local host and an ungranted mailbox."""

import argparse
import json
import os
import sqlite3
import subprocess
from pathlib import Path

from chio_process import ProcessClient
from probe_worker import authorization_probe
from qualify import serving


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    directory = args.work_dir.resolve()
    directory.mkdir(mode=0o700)
    policy = directory / "policy.yaml"
    policy.write_text("""kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 2
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: chio-ipc
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    config = {
        "schema": "chio.process.host.v1",
        "policy": str(policy),
        "mailboxes": [{"id": "authorization_probe"}],
        "limits": {"max_calls": 4, "max_processes": 2, "max_depth": 1},
        "children": [
            {
                "id": "coder",
                "parent": "root",
                "budget_share_bps": 5000,
                "tools": [{"server_id": "chio-ipc", "tool_name": "receive_authorization_probe"}],
            }
        ],
    }
    config_path = directory / "config.json"
    config_path.write_text(json.dumps(config))

    def command(*arguments):
        result = subprocess.run(
            [str(args.chio), *map(str, arguments)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    initialized = json.loads(
        command("process", "init", "--state", directory / "host", "--config", config_path)
    )
    command(
        "process",
        "credential",
        "--state",
        directory / "host",
        "--process",
        "coder",
        "--socket",
        directory / "worker.sock",
        "--out",
        directory / "connection.json",
    )
    connection = json.loads((directory / "connection.json").read_text())
    with serving(args.chio, directory):
        client = ProcessClient(connection["socket_path"], connection["credential"])
        receipt = authorization_probe(client)
    with sqlite3.connect(directory / "host/mailboxes.db") as db:
        assert db.execute("SELECT count(*) FROM mailbox_messages").fetchone()[0] == 0
        assert db.execute("SELECT last_sequence FROM mailboxes").fetchall() == [(0,)]
    (directory / "denial.ndjson").write_text(receipt + "\n")
    (directory / "kernel.pub").write_text(initialized["kernel_key"])
    verified = json.loads(
        command(
            "--json",
            "receipt",
            "verify",
            "--input",
            directory / "denial.ndjson",
            "--trusted-kernel-pubkey",
            directory / "kernel.pub",
        )
    )
    assert verified["receipts_verified"] == 1
    print(
        json.dumps(
            {
                "ungranted_invoke_denied": True,
                "dispatches": 0,
                "receipts_verified": 1,
            }
        )
    )


if __name__ == "__main__":
    main()
