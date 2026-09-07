"""One process-owned checkpoint, with bounded immutable snapshot blobs."""

import hashlib
import json
import math

from chio_process import MAX_STATE_BLOB_BYTES, ProcessClient

SCHEMA = "chio.mini-swe.v1"
MAX_SNAPSHOT_BYTES = 8 * MAX_STATE_BLOB_BYTES


def encode(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value) -> str:
    return hashlib.sha256(encode(value)).hexdigest()


class Journal:
    def __init__(self, client: ProcessClient):
        self.client = client
        checkpoint = client.inspect()["checkpoint"]
        self.revision = checkpoint["revision"]
        self.reference = checkpoint["value"]

    def read(self):
        if self.reference is None:
            return None
        ref = self.reference
        if (
            not isinstance(ref, dict)
            or ref.get("schema") != SCHEMA
            or not isinstance(ref.get("blobs"), list)
            or not 1 <= len(ref["blobs"]) <= 8
            or type(ref.get("bytes")) is not int
            or not 0 < ref["bytes"] <= MAX_SNAPSHOT_BYTES
        ):
            raise RuntimeError("Invalid mini-SWE checkpoint")
        data = b"".join(self.client.read_blob(key) for key in ref["blobs"])
        if len(data) != ref["bytes"] or hashlib.sha256(data).hexdigest() != ref.get("sha256"):
            raise RuntimeError("Invalid mini-SWE snapshot")
        value = json.loads(data)
        if not isinstance(value, dict) or value.get("schema") != SCHEMA:
            raise RuntimeError("Invalid mini-SWE snapshot schema")
        if (
            not isinstance(value.get("binding"), str)
            or not isinstance(value.get("messages"), list)
            or not value["messages"]
            or any(not isinstance(message, dict) for message in value["messages"])
            or any(
                type(value.get(key)) is not int or value[key] < 0
                for key in ("n_calls", "n_consecutive_format_errors")
            )
            or any(
                type(value.get(key)) not in (int, float)
                or not math.isfinite(value[key])
                or value[key] < 0
                for key in ("cost", "start_time")
            )
            or not isinstance(value.get("receipts"), list)
            or any(not isinstance(receipt, str) or not receipt for receipt in value["receipts"])
            or not isinstance(value.get("model_receipts", []), list)
            or any(
                not isinstance(receipt, str) or not receipt
                for receipt in value.get("model_receipts", [])
            )
        ):
            raise RuntimeError("Invalid mini-SWE snapshot state")
        return value

    def write(self, value):
        data = encode(value)
        if len(data) > MAX_SNAPSHOT_BYTES:
            raise RuntimeError("mini-SWE snapshot exceeds its byte limit")
        reference = {
            "schema": SCHEMA,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "blobs": [
                self.client.put_blob(data[offset : offset + MAX_STATE_BLOB_BYTES])["sha256"]
                for offset in range(0, len(data), MAX_STATE_BLOB_BYTES)
            ],
        }
        committed = self.client.checkpoint(self.revision, reference)
        self.revision = committed["revision"]
        self.reference = reference
