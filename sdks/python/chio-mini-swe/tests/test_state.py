import hashlib

import pytest
from chio_mini_swe.state import SCHEMA, Journal, encode
from chio_process import WorkerError
from chio_process.snapshot import SCHEMA as SNAPSHOT_SCHEMA
from test_recovery import MemoryProcess


def state():
    return {
        "schema": SCHEMA,
        "binding": "same-task",
        "phase": "ready",
        "messages": [{"role": "system", "content": "same prompt"}],
        "n_calls": 0,
        "cost": 0,
        "start_time": 1,
        "n_consecutive_format_errors": 0,
        "receipts": [],
        "model_receipts": [],
    }


def test_legacy_checkpoint_can_be_read_and_advanced_without_changing_task_state():
    client = MemoryProcess()
    value = state()
    data = encode(value)
    key = client.put_blob(data)["sha256"]
    client.checkpoint(
        "0",
        {
            "schema": SCHEMA,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "blobs": [key],
        },
    )
    journal = Journal(client)
    assert journal.read() == value
    journal.write(value)
    assert journal.reference["schema"] == SNAPSHOT_SCHEMA
    assert journal.revision == "2"
    assert Journal(client).read() == value
    assert client.blobs[key] == data


def test_lost_checkpoint_reply_does_not_rewrite_the_committed_document():
    client = MemoryProcess()
    journal = Journal(client)
    value = state()
    journal.write(value)
    previous = journal.reference
    original = client.checkpoint

    def interrupted(revision, reference):
        original(revision, reference)
        raise WorkerError("transport_error")

    client.checkpoint = interrupted
    value["phase"] = "model_pending"
    with pytest.raises(WorkerError, match="transport_error"):
        journal.write(value)
    assert journal.reference == previous
    assert journal.revision == "1"
    resumed = Journal(client)
    assert resumed.revision == "2" and resumed.read() == value
