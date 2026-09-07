"""Bounded MCP result encoding shared by execution, transport and verification."""

import json

MAX_FRAME = 1024 * 1024
MAX_REQUEST_ID = 1024


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


def validate_result(value):
    # Reserve the largest escaped request ID before promoting a workspace.
    # Both structured content and its nested JSON text count toward the host's
    # frame limit, including Unicode and control-character escaping.
    response_frame("\0" * MAX_REQUEST_ID, tool_result(value))
