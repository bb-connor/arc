"""One process-owned checkpoint, with bounded immutable snapshot blobs."""

import hashlib
import json
import math

from chio_process import MAX_STATE_BLOB_BYTES, ProcessClient
from chio_process.snapshot import SCHEMA as SNAPSHOT_SCHEMA
from chio_process.snapshot import JsonSnapshot

SCHEMA = "chio.mini-swe.v2"
MAX_SNAPSHOT_BYTES = 8 * MAX_STATE_BLOB_BYTES


def encode(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value) -> str:
    return hashlib.sha256(encode(value)).hexdigest()


class Journal:
    def __init__(self, client: ProcessClient):
        self.client = client
        self.snapshots = JsonSnapshot(client)
        checkpoint = client.inspect()["checkpoint"]
        self.revision = checkpoint["revision"]
        self.reference = checkpoint["value"]

    def read(self):
        if self.reference is None:
            return None
        ref = self.reference
        if not isinstance(ref, dict) or ref.get("schema") != SNAPSHOT_SCHEMA:
            raise RuntimeError("Invalid mini-SWE checkpoint")
        try:
            value = self.snapshots.read(ref)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise RuntimeError("Invalid mini-SWE snapshot") from error
        return self._validate(value)

    @staticmethod
    def _validate(value):
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
        outputs = value.get("command_outputs")
        if not isinstance(outputs, dict) or len(outputs) > len(value["receipts"]):
            raise RuntimeError("Invalid mini-SWE command outputs")
        if outputs:
            try:
                ids = {json.loads(receipt).get("id") for receipt in value["receipts"]}
            except (ValueError, TypeError, AttributeError) as error:
                raise RuntimeError("Invalid mini-SWE command receipts") from error
            if any(
                not isinstance(key, str)
                or not key
                or key not in ids
                or not isinstance(output, dict)
                for key, output in outputs.items()
            ):
                raise RuntimeError("Invalid mini-SWE command output binding")
        return value

    def write(self, value):
        try:
            reference = self.snapshots.write(value)
        except (ValueError, RecursionError) as error:
            raise RuntimeError(
                "mini-SWE snapshot cannot be encoded within its byte limit"
            ) from error
        committed = self.client.checkpoint(self.revision, reference)
        self.revision = committed["revision"]
        self.reference = reference
