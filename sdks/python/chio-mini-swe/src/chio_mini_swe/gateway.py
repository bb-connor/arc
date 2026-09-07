"""Operator-side MCP adapter for one pinned upstream mini-SWE model instance."""

import json
import sys

from minisweagent.exceptions import FormatError

from chio_mini_swe.model import MAX_QUERY_BYTES, QUERY_SCHEMA, RESULT_SCHEMA, validate_result
from chio_mini_swe.state import encode


def tool(model_id):
    return {
        "name": "model_infer",
        "description": "Request one model response from the operator-selected coding model.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["schema", "model_id", "turn", "messages"],
            "properties": {
                "schema": {"const": QUERY_SCHEMA},
                "model_id": {"const": model_id},
                "turn": {"type": "integer", "minimum": 1},
                "messages": {"type": "array", "minItems": 1, "items": {"type": "object"}},
            },
        },
        "annotations": {
            "readOnlyHint": False,
            "idempotentHint": False,
            "destructiveHint": False,
            "openWorldHint": True,
        },
    }


def query(model, model_id, arguments):
    if (
        not isinstance(arguments, dict)
        or set(arguments) != {"schema", "model_id", "turn", "messages"}
        or arguments["schema"] != QUERY_SCHEMA
        or arguments["model_id"] != model_id
        or type(arguments["turn"]) is not int
        or arguments["turn"] < 1
        or not isinstance(arguments["messages"], list)
        or not arguments["messages"]
        or any(not isinstance(message, dict) for message in arguments["messages"])
        or len(encode(arguments)) > MAX_QUERY_BYTES
    ):
        raise ValueError("Invalid model query")
    result = {"schema": RESULT_SCHEMA, "model_id": model_id}
    try:
        result.update(kind="message", message=model.query(arguments["messages"]))
    except FormatError as error:
        result.update(kind="format_error", messages=error.messages)
    return validate_result(result, model_id)


def serve(model, *, model_id, input_stream=None, output_stream=None):
    """Serve one configured model. The caller owns provider access and its retry policy.

    This adapter adds no provider retry, model selection or arbitrary call
    overrides. Unknown provider failures become sanitized MCP errors. Run it
    under an admitted Chio tool-server launch policy; never mount its credentials
    or configuration into the agent worker.
    """
    if not isinstance(model_id, str) or not model_id or len(model_id.encode()) > 1024:
        raise ValueError("A pinned model configuration identity is required")
    incoming = sys.stdin.buffer if input_stream is None else input_stream
    outgoing = sys.stdout if output_stream is None else output_stream
    while True:
        line = incoming.readline(MAX_QUERY_BYTES + 8193)
        if not line:
            return
        if len(line) > MAX_QUERY_BYTES + 8192 or not line.endswith(b"\n"):
            raise ValueError("MCP model frame is oversized or incomplete")
        message = json.loads(line)
        if "id" not in message:
            continue
        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": message["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "chio-mini-swe-model", "version": "1"},
            }
        elif method == "tools/list":
            result = {"tools": [tool(model_id)]}
        elif method == "tools/call":
            try:
                if message["params"]["name"] != "model_infer":
                    raise ValueError("Unknown tool")
                value = query(model, model_id, message["params"]["arguments"])
                result = {
                    "structuredContent": value,
                    "content": [{"type": "text", "text": json.dumps(value)}],
                }
            except Exception:
                # Provider errors can include credentials or request bodies.
                result = {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                "Model outcome is incomplete. "
                                "Stop and inspect operator/provider state."
                            ),
                        }
                    ],
                }
        else:
            raise ValueError("Unsupported MCP method")
        print(
            json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}),
            file=outgoing,
            flush=True,
        )
