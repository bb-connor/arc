#!/usr/bin/python3 -I
"""Verifier-side client for root-orchestrated candidate commands."""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path


MAX_HEADER_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
FORWARDED_EXACT = frozenset({"CARGO_TARGET_DIR", "LC_ALL", "RUSTFLAGS"})


def read_line(connection: socket.socket) -> bytes:
    payload = bytearray()
    while True:
        chunk = connection.recv(1)
        if not chunk:
            raise RuntimeError("candidate command broker closed before its response")
        if chunk == b"\n":
            return bytes(payload)
        payload.extend(chunk)
        if len(payload) > MAX_HEADER_BYTES:
            raise RuntimeError("candidate command broker response header is oversized")


def forwarded_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if (
            (key in FORWARDED_EXACT and (key != "LC_ALL" or value == "C"))
            or key.startswith("CHIO_CAGE_")
        )
    }


def main() -> int:
    socket_path = os.environ.get("CHIO_SECURITY_BROKER_SOCKET", "")
    token = os.environ.get("CHIO_SECURITY_BROKER_TOKEN", "")
    if not socket_path.startswith("/baseline/verifier/") or len(token) != 64:
        raise RuntimeError("candidate command broker identity is unavailable")
    executable = Path(sys.argv[0]).name
    if executable not in {"cargo", "cc", "ldd"}:
        raise RuntimeError("candidate command client executable is not authorized")
    request = {
        "arguments": sys.argv[1:],
        "cwd": os.getcwd(),
        "environment": forwarded_environment(),
        "executable": executable,
        "operation": "run",
        "token": token,
    }
    encoded = json.dumps(request, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded) > MAX_HEADER_BYTES:
        raise RuntimeError("candidate command broker request is oversized")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(21_600)
        connection.connect(socket_path)
        connection.sendall(encoded + b"\n")
        response = json.loads(read_line(connection))
        if set(response) != {"length", "returncode"}:
            raise RuntimeError("candidate command broker response shape is invalid")
        length = response["length"]
        returncode = response["returncode"]
        if (
            not isinstance(length, int)
            or not 0 <= length <= MAX_RESPONSE_BYTES
            or not isinstance(returncode, int)
            or not 0 <= returncode <= 255
        ):
            raise RuntimeError("candidate command broker response values are invalid")
        payload = bytearray()
        while len(payload) < length:
            chunk = connection.recv(min(65_536, length - len(payload)))
            if not chunk:
                raise RuntimeError("candidate command broker response was truncated")
            payload.extend(chunk)
        if connection.recv(1):
            raise RuntimeError("candidate command broker response has trailing bytes")
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()
    return returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"candidate command broker failed: {error}", file=sys.stderr)
        raise SystemExit(125)
