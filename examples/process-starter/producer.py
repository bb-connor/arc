"""A Python worker with permission to send jobs, but not receive them."""

import importlib.metadata
import json
import os
import sys
from pathlib import Path

import chio_process
from chio_process import ProcessClient


def save(path, value):
    with path.open("w", encoding="utf-8") as output:
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())


def main():
    bootstrap = json.load(sys.stdin)
    if bootstrap["schema"] != "chio.process.worker-bootstrap.v1":
        raise RuntimeError("unsupported worker bootstrap")
    connection = bootstrap["connection"]
    client = ProcessClient(connection["socket_path"], connection["credential"])
    directory = Path(bootstrap["input"]["directory"])
    sent = client.invoke(
        "send-order",
        "chio-ipc",
        "send_jobs",
        {"message_key": "order", "payload": {"items": [2, 3, 5]}},
    )
    if sent["verdict"] != "allow" or sent["output"]["value"]["status"] != "sent":
        raise RuntimeError("handoff did not complete")
    path = directory / f"producer-{bootstrap['attempt']}.json"
    result = {
        "send_receipt": sent["receipt_json"],
        "module_path": chio_process.__file__,
        "version": importlib.metadata.version("chio-process"),
    }
    save(path, result)
    # Attempt numbers never enter the durable operation keys above.
    if bootstrap["input"]["exercise_recovery"] and bootstrap["attempt"] == 1:
        os._exit(77)
    denied = client.invoke(
        "check-receive-scope", "chio-ipc", "receive_jobs", {"after_sequence": "0"}
    )
    if denied["verdict"] != "deny" or denied["output"] is not None:
        raise RuntimeError("producer unexpectedly received mailbox authority")
    save(path, {**result, "scope_receipt": denied["receipt_json"]})


if __name__ == "__main__":
    main()
