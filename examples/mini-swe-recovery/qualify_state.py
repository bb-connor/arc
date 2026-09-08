"""Installed JSON checkpoints: sustained history, lost CAS reply and offline reads."""

import argparse
import hashlib
import importlib.util
import json
import os
import random
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = Path(tempfile.mkdtemp(prefix="chio-json-state-"))
    os.environ["MSWEA_GLOBAL_CONFIG_DIR"] = str(root / "mini-config")
    os.environ["MSWEA_SILENT_STARTUP"] = "1"
    # Configure the fixture before importing upstream's global configuration.
    from chio_mini_swe.operator import AdministrativeState
    from chio_mini_swe.state import SCHEMA, Journal, encode
    from chio_process import ProcessClient, WorkerError
    from chio_process.launch import demo_python, provision_native_demo
    from qualify import command, serving

    binary = args.chio.resolve(strict=True)
    policy = root / "policy.yaml"
    policy.write_text("""kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 8
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: sandbox
        tool: execute
        operations: [invoke, delegate]
        ttl: 3600
""")
    # Discovery supplies a manifest only. No container exists or is executed;
    # the final native call count must remain zero throughout this profile.
    server = provision_native_demo(
        binary,
        "sandbox",
        [demo_python(), str(HERE / "sandbox.py"), "--container", "0" * 64],
        root / "launch",
        root,
    )
    config = {
        "schema": "chio.process.host.v1",
        "policy": str(policy),
        "servers": [server],
        "limits": {"max_calls": 1, "max_processes": 2, "max_depth": 1},
        "children": [
            {
                "id": "coder",
                "parent": "root",
                "budget_share_bps": 9000,
                "tools": [{"server_id": "sandbox", "tool_name": "execute"}],
            }
        ],
    }
    (root / "config.json").write_text(json.dumps(config))
    command(binary, "process", "init", "--config", root / "config.json", "--state", root / "host")
    command(
        binary,
        "process",
        "credential",
        "--state",
        root / "host",
        "--process",
        "coder",
        "--socket",
        root / "worker.sock",
        "--out",
        root / "connection.json",
    )
    connection = json.loads((root / "connection.json").read_text())
    client = ProcessClient(connection["socket_path"], connection["credential"])
    value = {
        "schema": SCHEMA,
        "binding": "synthetic-transcript",
        "phase": "ready",
        "messages": [{"role": "system", "content": "Synthetic state storage qualification"}],
        "n_calls": 0,
        "cost": 0,
        "n_consecutive_format_errors": 0,
        "start_time": 1,
        "receipts": [],
        "model_receipts": [],
    }
    started = time.monotonic()
    with serving(binary, root) as host:
        journal = Journal(client)
        journal.write(value)
        generator = random.Random(0)
        for turn in range(1, 121):
            value["phase"] = "model_pending"
            journal.write(value)
            value["messages"].append({"role": "assistant", "content": f"Inspect step {turn}"})
            value["n_calls"] = turn
            value["cost"] = turn / 10000
            value["model_receipts"].append(f"synthetic-model-{turn}")
            value["phase"] = "tools"
            journal.write(value)
            value["messages"].append(
                {
                    "role": "tool",
                    "tool_call_id": f"call-{turn}",
                    "content": generator.randbytes(2048).hex(),
                }
            )
            value["receipts"].append(f"synthetic-command-{turn}")
            value["phase"] = "ready"
            journal.write(value)
        assert Journal(client).read() == value
        inspected = client.inspect()
        assert inspected["checkpoint"]["revision"] == "361"
        assert inspected["tree_calls"] == 0
        assert inspected["storage"]["limits"] == {"max_bytes": 64 * 1024 * 1024, "max_blobs": 4096}
        assert inspected["storage"]["tree_bytes"] < 8 * 1024 * 1024
        query = {
            "schema": "chio.mini-swe.model-query.v1",
            "model_id": "synthetic-model",
            "turn": 121,
            "messages": value["messages"],
        }
        assert len(encode(query)) <= 512 * 1024
        previous = journal.reference
        checkpoint = client.checkpoint

        def lost_reply(revision, reference):
            checkpoint(revision, reference)
            host.kill()
            host.wait(timeout=15)
            raise WorkerError("transport_error")

        client.checkpoint = lost_reply
        value["phase"] = "model_pending"
        try:
            journal.write(value)
        except WorkerError as error:
            assert error.code == "transport_error"
        else:
            raise AssertionError("Checkpoint reply was not interrupted")
        assert journal.reference == previous and journal.revision == "361"
    (root / "worker.sock").unlink(missing_ok=True)
    with serving(binary, root):
        recovered = Journal(client)
        assert recovered.revision == "362" and recovered.read() == value
        final = client.inspect()
        assert final["tree_calls"] == 0
        assert final["storage"]["tree_bytes"] < 8 * 1024 * 1024
    native_seconds = time.monotonic() - started
    # The filesystem-authorized reader neither starts a host nor needs a worker credential.
    (root / "connection.json").unlink()

    def database_hashes():
        return {
            p.name: {
                "pages": hashlib.sha256(p.read_bytes()).hexdigest(),
                "wal": hashlib.sha256(
                    wal.read_bytes() if (wal := p.with_name(p.name + "-wal")).exists() else b""
                ).hexdigest(),
            }
            for p in (root / "host").glob("*.db")
        }

    # SQLite read-only connections may create an empty WAL and maintain SHM
    # reader bookkeeping. Compare database pages and all WAL bytes; absence
    # and an empty WAL both contain no frames. Do not ignore a nonempty WAL.
    before = database_hashes()
    assert before
    started = time.monotonic()
    administrative = AdministrativeState(root, {"chio": str(binary), "process": "coder"})
    read_blob = administrative.read_blob
    offline_blob_reads = 0

    def counted_read(key):
        nonlocal offline_blob_reads
        offline_blob_reads += 1
        return read_blob(key)

    administrative.read_blob = counted_read
    offline = Journal(administrative)
    assert offline.read() == value
    offline_seconds = time.monotonic() - started
    assert before == database_hashes()
    assert offline_blob_reads <= 64
    result = {
        "schema": "chio.mini-swe.state-qualification.v1",
        "private_state": str(root),
        "synthetic_turns": 120,
        "observation_bytes": 4096,
        "retained_document_bytes": len(encode(value)),
        "modeled_query_bytes": len(encode(query)),
        "storage": final["storage"],
        "native_seconds": native_seconds,
        "offline_seconds": offline_seconds,
        "offline_blob_reads": offline_blob_reads,
        "lost_checkpoint_reply": True,
        "fresh_host_recovered_full_document": True,
        "offline_read_without_credential": True,
        "database_pages_and_wal_bytes_unchanged": True,
        "native_tool_calls": final["tree_calls"],
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "sources_sha256": {
            name: hashlib.sha256(
                Path(importlib.util.find_spec(name).origin).read_bytes()
            ).hexdigest()
            for name in ("chio_mini_swe.state", "chio_process.snapshot", "chio_process")
        },
        "limits": [
            "Synthetic transcript and cost counters; no model, agent or tool invocation",
            "Explicit fixture launch authority; no production-containment claim",
        ],
    }
    (args.output / "qualification.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
