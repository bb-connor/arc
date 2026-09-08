"""Bounded JSON snapshots over immutable, process-owned Chio blobs."""

import hashlib
import json
import math
import re

from chio_process import MAX_STATE_BLOB_BYTES, ProcessClient, WorkerError

SCHEMA = "chio.process.json-snapshot.v1"
MAX_SNAPSHOT_BYTES = 8 * MAX_STATE_BLOB_BYTES
MIN_ATOM_BYTES = 16 * 1024
PACKED_BYTES = 16 * 1024
# Keep reader format bounds independent of the writer's packing heuristics.
MAX_PARTS = 16385
MAX_INDEX_BYTES = 2 * MAX_STATE_BLOB_BYTES
MAX_KNOWN_BLOBS = 16384


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def identity(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON snapshot field")
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError("Nonfinite JSON snapshot number")


def finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Nonfinite JSON snapshot number")
    return result


def decode(data):
    return json.loads(
        data,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
        parse_float=finite_float,
    )


def parts(value):
    """Isolate large JSON atoms so insertions do not shift unchanged payloads."""
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), allow_nan=False)
    result, pending = [], bytearray()
    size = 0
    for fragment in encoder.iterencode(value):
        data = fragment.encode()
        size += len(data)
        if size > MAX_SNAPSHOT_BYTES:
            raise ValueError("JSON snapshot exceeds its byte limit")
        if len(data) >= MIN_ATOM_BYTES:
            if pending:
                result.append(bytes(pending))
                pending.clear()
            result.extend(
                data[offset : offset + MAX_STATE_BLOB_BYTES]
                for offset in range(0, len(data), MAX_STATE_BLOB_BYTES)
            )
        else:
            if len(pending) + len(data) > PACKED_BYTES:
                result.append(bytes(pending))
                pending.clear()
            pending.extend(data)
    if pending:
        result.append(bytes(pending))
    if not 1 <= len(result) <= MAX_PARTS:
        raise ValueError("JSON snapshot segment count exceeds its bound")
    return result


class JsonSnapshot:
    """One client's immutable blobs; the caller commits returned references with CAS.

    Successful writes and verified reads can be reused during this instance's
    lifetime because the native API never mutates or deletes blobs. A fresh
    reader verifies every referenced byte. Failed writes remain quota-charged.
    """

    def __init__(self, client: ProcessClient):
        self.client = client
        self._known = set()

    def _remember(self, key):
        if len(self._known) >= MAX_KNOWN_BLOBS:
            self._known.clear()
        self._known.add(key)

    def _put(self, data):
        key = hashlib.sha256(data).hexdigest()
        if key not in self._known:
            result = self.client.put_blob(data)
            if (
                result.get("sha256") != key
                or type(result.get("bytes")) is not int
                or result["bytes"] != len(data)
            ):
                raise WorkerError("invalid_response")
            self._remember(key)
        return key

    def _read(self, key, length):
        data = self.client.read_blob(key)
        if len(data) != length or hashlib.sha256(data).hexdigest() != key:
            raise ValueError("JSON snapshot blob is missing or corrupt")
        self._remember(key)
        return data

    def write(self, value):
        chunks = parts(value)
        hashed = hashlib.sha256()
        size, index = 0, []
        # Validate the entire value and its size before storing any segment.
        for chunk in chunks:
            hashed.update(chunk)
            size += len(chunk)
            index.append([self._put(chunk), len(chunk)])
        encoded = encode(index)
        if len(encoded) > MAX_INDEX_BYTES:
            raise ValueError("JSON snapshot index exceeds its byte limit")
        return {
            "schema": SCHEMA,
            "bytes": size,
            "sha256": hashed.hexdigest(),
            "index": {
                "bytes": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "blobs": [
                    self._put(encoded[offset : offset + MAX_STATE_BLOB_BYTES])
                    for offset in range(0, len(encoded), MAX_STATE_BLOB_BYTES)
                ],
            },
        }

    def read(self, reference):
        if (
            not isinstance(reference, dict)
            or set(reference) != {"schema", "bytes", "sha256", "index"}
            or reference["schema"] != SCHEMA
            or type(reference["bytes"]) is not int
            or not 0 < reference["bytes"] <= MAX_SNAPSHOT_BYTES
            or not identity(reference["sha256"])
        ):
            raise ValueError("Invalid JSON snapshot reference")
        index = reference["index"]
        if (
            not isinstance(index, dict)
            or set(index) != {"bytes", "sha256", "blobs"}
            or type(index["bytes"]) is not int
            or not 0 < index["bytes"] <= MAX_INDEX_BYTES
            or not identity(index["sha256"])
            or not isinstance(index["blobs"], list)
            or len(index["blobs"])
            != (index["bytes"] + MAX_STATE_BLOB_BYTES - 1) // MAX_STATE_BLOB_BYTES
            or any(not identity(key) for key in index["blobs"])
        ):
            raise ValueError("Invalid JSON snapshot index reference")
        remaining = index["bytes"]
        encoded = bytearray()
        for key in index["blobs"]:
            length = min(remaining, MAX_STATE_BLOB_BYTES)
            encoded.extend(self._read(key, length))
            remaining -= length
        if hashlib.sha256(encoded).hexdigest() != index["sha256"]:
            raise ValueError("JSON snapshot index is missing or corrupt")
        chunks = decode(encoded)
        if not isinstance(chunks, list) or not 1 <= len(chunks) <= MAX_PARTS:
            raise ValueError("Invalid JSON snapshot segments")
        size = 0
        for chunk in chunks:
            if (
                not isinstance(chunk, list)
                or len(chunk) != 2
                or not identity(chunk[0])
                or type(chunk[1]) is not int
                or not 0 < chunk[1] <= MAX_STATE_BLOB_BYTES
            ):
                raise ValueError("Invalid JSON snapshot segment")
            size += chunk[1]
            if size > MAX_SNAPSHOT_BYTES:
                raise ValueError("JSON snapshot reconstruction exceeds its bound")
        if size != reference["bytes"]:
            raise ValueError("JSON snapshot index has inconsistent byte counts")
        data = bytearray()
        for key, length in chunks:
            data.extend(self._read(key, length))
        if hashlib.sha256(data).hexdigest() != reference["sha256"]:
            raise ValueError("JSON snapshot is missing or corrupt")
        return decode(data)
