"""Bounded MCP result encoding shared by execution, transport and verification."""

import json

MAX_FRAME = 1024 * 1024
MAX_REQUEST_ID = 1024
MAX_COMMAND_BYTES = 65536
MAX_TOOL_CALL_ID_BYTES = 1024

# The schema's 65,536-character command can use at most 12 JSON bytes per
# Unicode scalar (an escaped surrogate pair). Even that 786,432-byte command,
# a 1,024-character escaped tool ID, the byte-limited request ID and the fixed
# tools/call envelope fit the established 1 MiB frame. Extra envelope data and
# whitespace still share this wire bound; command execution separately checks
# its UTF-8 byte ceiling rather than treating schema maxLength as a byte limit.


def read_request_frame(stream):
    """Read one bounded newline frame, discarding only its unfinished tail."""
    line = stream.readline(MAX_FRAME + 1)
    if line and (len(line) > MAX_FRAME or not line.endswith(b"\n")):
        # A boundary-sized read may already include the terminating newline.
        # Draining in that case would discard the following valid request.
        if not line.endswith(b"\n"):
            while tail := stream.readline(MAX_FRAME + 1):
                if tail.endswith(b"\n"):
                    break
        raise ValueError("Repository MCP frame exceeds its bound or is incomplete")
    return line


def command_text(value):
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= MAX_COMMAND_BYTES
        or "\0" in value
    ):
        raise ValueError("Invalid repository command")
    return value


def request_id(value):
    if not (
        (type(value) is int and -(2**63) <= value < 2**64)
        or (isinstance(value, str) and len(value.encode()) <= MAX_REQUEST_ID)
    ):
        raise ValueError("Invalid repository MCP request ID")
    return value


def tool_result(value):
    return {
        "structuredContent": value,
        "content": [{"type": "text", "text": json.dumps(value)}],
        "isError": False,
    }


def response_frame(identifier, result):
    encoded = json.dumps({"jsonrpc": "2.0", "id": request_id(identifier), "result": result})
    if len(encoded.encode()) + 1 > MAX_FRAME:
        raise ValueError("Repository MCP response exceeds its serialized frame bound")
    return encoded


def error_frame(identifier, code, message):
    """A fixed diagnostic can answer invalid frames whose request ID is unknown."""
    encoded = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": None if identifier is None else request_id(identifier),
            "error": {"code": code, "message": message},
        }
    )
    if len(encoded.encode("utf-8")) + 1 > MAX_FRAME:
        raise ValueError("Repository MCP error exceeds its serialized frame bound")
    return encoded


def validate_result(value):
    # Reserve the largest escaped request ID before promoting a workspace.
    # Both structured content and its nested JSON text count toward the host's
    # frame limit, including Unicode and control-character escaping.
    response_frame("\0" * MAX_REQUEST_ID, tool_result(value))
