"""A stdlib-only MCP resource for the shared-resource workload baseline."""

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

import store


def tool(name, description, properties):
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": list(properties),
            "additionalProperties": False,
        },
    }


TOOLS = [
    tool("task", "Read the current task revision and its input digest.", {}),
    tool(
        "snapshot",
        "Read a shared document and its version.",
        {
            "document": {"type": "string"},
        },
    ),
    tool(
        "replace",
        "Replace a document only if its version still matches. "
        "A version conflict has no mutation; read again before planning a new update.",
        {
            "document": {"type": "string"},
            "expected_version": {"type": "integer", "minimum": 0},
            "value": {"type": "object"},
        },
    ),
    tool(
        "outcome",
        "Look up a previously delivered operation and its bound request. "
        "Unknown does not authorize retry under a different identity.",
        {
            "operation_id": {"type": "string"},
        },
    ),
]

ADMIN_TOOLS = [
    tool(
        "assign",
        "Assign a document to a kernel caller and optionally publish new task input in the same transaction. Keep the same operation key and arguments on recovery.",
        {
            "document": {"type": "string"},
            "expected_generation": {"type": ["integer", "null"], "minimum": 0},
            "owner_capability_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "expected_revision": {"type": "integer", "minimum": 0},
            "task": {"type": ["object", "null"]},
        },
    ),
    tool(
        "assignment",
        "Read the current assignment. This does not authorize retry of an uncertain effect under a new key.",
        {"document": {"type": "string"}},
    ),
    TOOLS[-1],
]


def respond(database, request, connection_caller=None, *, operator=False):
    method = request.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "shared-resource", "version": "1"},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": ADMIN_TOOLS if operator else TOOLS}
    elif method == "tools/call":
        try:
            params = request["params"]
            # Metadata comes from the trusted MCP client, never model arguments.
            # The current adapter supplies this from ToolDispatchContext.
            operation_id = params["_meta"]["chioRequestId"]
            value = store.execute(
                database,
                operation_id,
                params["name"],
                params.get("arguments", {}),
                caller=connection_caller
                or params["_meta"].get("chioCallerCapabilitySha256"),
                operator=operator,
            )
            result = {
                "content": [{"type": "text", "text": store.encoded(value)}],
                "structuredContent": value,
                "isError": False,
            }
        except (KeyError, TypeError, ValueError, sqlite3.Error):
            result = {
                "content": [{"type": "text", "text": "Resource request refused"}],
                "isError": True,
            }
    else:
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "error": {"code": -32601, "message": "Unknown method"},
        }
    return {"jsonrpc": "2.0", "id": request["id"], "result": result}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument(
        "--operator",
        action="store_true",
        help="serve only operator assignment tools on this trusted private pipe",
    )
    parser.add_argument(
        "--connection-caller",
        type=store.caller_identity,
        help="trusted baseline client identity bound to this private pipe",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--initialize", type=Path, metavar="SEED_JSON")
    mode.add_argument("--inspect", action="store_true")
    args = parser.parse_args()
    if args.initialize:
        store.initialize(args.database, json.loads(args.initialize.read_text()))
        return
    if args.inspect:
        print(store.encoded(store.inspect(args.database)))
        return
    for line in sys.stdin:
        request = json.loads(line)
        if "id" in request:
            print(
                store.encoded(
                    respond(
                        args.database,
                        request,
                        args.connection_caller,
                        operator=args.operator,
                    )
                ),
                flush=True,
            )


if __name__ == "__main__":
    main()
