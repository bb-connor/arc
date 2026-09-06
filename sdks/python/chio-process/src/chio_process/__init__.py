"""Synchronous local Chio workers. A transport error can follow a committed effect.

Retry an uncertain invocation with its original key and identical arguments.
Keep receipt_json unchanged for independent Chio verification.
"""

import base64
import binascii
import hashlib
import json
import math
import re
import socket
import time
from typing import Any

PROTOCOL = "chio.process.v1"
MAX_REQUEST_BYTES = 2 * 1024 * 1024
STATE_BLOB_PROTOCOL = "chio.process.blobs.v1"
MAX_STATE_BLOB_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class WorkerError(Exception):
    """A protocol or transport failure. Tool denials retain their signed response."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"Chio worker: {code}")


class ProcessClient:
    """One authenticated process, using a new Unix connection for each operation.

    The host delivers socket_path and credential privately. This client neither
    launches nor sandboxes workers, and never automatically retries effects.
    """

    def __init__(self, socket_path: str, credential: str, *, timeout: float = 60):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        self._socket_path = socket_path
        self._credential = credential
        self._timeout = timeout

    def inspect(self) -> dict[str, Any]:
        return self._call({"op": "inspect"})

    def invoke(
        self, operation_key: str, server_id: str, tool_name: str, arguments: Any
    ) -> dict[str, Any]:
        """Return verdict, output and original receipt_json, including on denial."""
        return self._call(
            {
                "op": "invoke",
                "operation_key": operation_key,
                "server_id": server_id,
                "tool_name": tool_name,
                "arguments": arguments,
            }
        )

    def checkpoint(self, expected_revision: str, value: Any) -> dict[str, Any]:
        """CAS against the decimal revision string returned by inspect/checkpoint."""
        return self._call(
            {
                "op": "checkpoint",
                "expected_revision": expected_revision,
                "value": value,
            }
        )

    def put_blob(self, value: bytes | bytearray | memoryview) -> dict[str, Any]:
        """Store immutable private bytes, charged to this process tree's quota."""
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise TypeError("Invalid state blob")
        size = value.nbytes if isinstance(value, memoryview) else len(value)
        if size > MAX_STATE_BLOB_BYTES:
            raise ValueError("State blob too large")
        data = bytes(value)
        sha256 = hashlib.sha256(data).hexdigest()
        result = self._call(
            {
                "op": "blob_put",
                "sha256": sha256,
                "data_base64": base64.b64encode(data).decode("ascii"),
            }
        )
        if (
            result.get("sha256") != sha256
            or type(result.get("bytes")) is not int
            or result["bytes"] != len(data)
        ):
            raise WorkerError("invalid_response")
        return {"sha256": sha256, "bytes": len(data)}

    def read_blob(self, sha256: str) -> bytes:
        """Read this process's bytes and verify their digest and length."""
        if not isinstance(sha256, str) or re.fullmatch(r"[a-f0-9]{64}", sha256) is None:
            raise ValueError("Invalid state blob digest")
        result = self._call({"op": "blob_read", "sha256": sha256})
        size, encoded = result.get("bytes"), result.get("data_base64")
        if (
            result.get("sha256") != sha256
            or type(size) is not int
            or size < 0
            or size > MAX_STATE_BLOB_BYTES
            or not isinstance(encoded, str)
            or len(encoded) > ((MAX_STATE_BLOB_BYTES + 2) // 3) * 4
        ):
            raise WorkerError("invalid_response")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise WorkerError("invalid_response") from None
        if (
            len(data) != size
            or base64.b64encode(data).decode("ascii") != encoded
            or hashlib.sha256(data).hexdigest() != sha256
        ):
            raise WorkerError("invalid_response")
        return data

    def cancel(self) -> dict[str, Any]:
        """Permanently stop new admissions for this process and its descendants."""
        return self._call({"op": "cancel"})

    def _call(self, operation: dict[str, Any]) -> dict[str, Any]:
        frame = (
            json.dumps(
                {
                    "protocol": PROTOCOL,
                    "credential": self._credential,
                    "operation": operation,
                },
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        if len(frame) > MAX_REQUEST_BYTES:
            raise WorkerError("request_too_large")
        deadline = time.monotonic() + self._timeout
        response = bytearray()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                stream.settimeout(self._remaining(deadline))
                stream.connect(self._socket_path)
                stream.settimeout(self._remaining(deadline))
                stream.sendall(frame)
                while True:
                    stream.settimeout(self._remaining(deadline))
                    chunk = stream.recv(min(8192, MAX_RESPONSE_BYTES + 1 - len(response)))
                    if not chunk:
                        raise WorkerError("truncated_response")
                    end = chunk.find(b"\n")
                    response.extend(chunk if end < 0 else chunk[: end + 1])
                    if len(response) > MAX_RESPONSE_BYTES:
                        raise WorkerError("response_too_large")
                    if end >= 0:
                        break
        except OSError:
            # Do not include paths, request bodies or secrets in error messages.
            raise WorkerError("transport_error") from None
        try:
            decoded = json.loads(response)
        except (ValueError, UnicodeError):
            raise WorkerError("invalid_response") from None
        if not isinstance(decoded, dict) or decoded.get("protocol") != PROTOCOL:
            raise WorkerError("invalid_response")
        if decoded.get("ok") is False:
            error = decoded.get("error")
            if not isinstance(error, dict) or not isinstance(error.get("code"), str):
                raise WorkerError("invalid_response")
            raise WorkerError(error["code"])
        if decoded.get("ok") is not True or not isinstance(decoded.get("result"), dict):
            raise WorkerError("invalid_response")
        return decoded["result"]

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WorkerError("transport_error")
        return remaining
