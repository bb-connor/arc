"""Private framed repository child selected and supervised by the Rust adapter."""

import json
import sys

from chio_mini_swe.provider_config import reject_constant, unique_object
from chio_mini_swe.repository_store import configuration_digest

MAX_REQUEST = 131072
MAX_RESPONSE = 524288


def frame(stream, value):
    body = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
    if not 0 < len(body) <= MAX_RESPONSE:
        raise ValueError("Repository adapter output exceeds its frame bound")
    stream.write(len(body).to_bytes(4, "big") + body)
    stream.flush()


def exact(stream, size):
    parts = bytearray()
    while len(parts) < size:
        part = stream.read(size - len(parts))
        if not part:
            raise ValueError("Repository adapter input is truncated")
        parts.extend(part)
    return parts


def serve(open_workspace, expected, incoming=None, outgoing=None):
    incoming = sys.stdin.buffer if incoming is None else incoming
    outgoing = sys.stdout.buffer if outgoing is None else outgoing

    def checked(workspace):
        if configuration_digest(workspace.config) != expected:
            raise ValueError("Repository adapter configuration differs from the operator binding")
        if workspace.status()["interrupted"]:
            raise ValueError("Repository requires operator recovery before a new adapter starts")

    # The workspace lock covers each complete command, including its durable
    # result. Idle adapters do not prevent readback or explicit operator recovery.
    with open_workspace() as workspace:
        checked(workspace)
    frame(
        outgoing, {"schema": "chio.repository-adapter-ready.v1", "configuration_sha256": expected}
    )
    while prefix := incoming.read(4):
        if len(prefix) < 4:
            prefix += exact(incoming, 4 - len(prefix))
        size = int.from_bytes(prefix, "big")
        if not 1 <= size <= MAX_REQUEST:
            raise ValueError("Repository adapter request exceeds its frame bound")
        value = json.loads(
            exact(incoming, size), object_pairs_hook=unique_object, parse_constant=reject_constant
        )
        if (
            not isinstance(value, dict)
            or not {"command", "configuration_sha256"}
            <= set(value)
            <= {"command", "tool_call_id", "configuration_sha256"}
            or value["configuration_sha256"] != expected
            or not isinstance(value["command"], str)
            or not 1 <= len(value["command"].encode()) <= 65536
            or "\0" in value["command"]
            or (
                "tool_call_id" in value
                and (
                    not isinstance(value["tool_call_id"], str)
                    or len(value["tool_call_id"].encode()) > 1024
                    or "\0" in value["tool_call_id"]
                )
            )
        ):
            raise ValueError("Invalid repository adapter command")
        with open_workspace() as workspace:
            checked(workspace)
            result = workspace.execute(value["command"])
        frame(outgoing, result)
