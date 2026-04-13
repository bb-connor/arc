#!/usr/bin/env python3

import json
import sys


TOOLS = [
    {
        "name": "echo_text",
        "title": "Echo Text",
        "description": "Return the provided message",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            },
            "required": ["message"]
        },
        "annotations": {
            "readOnlyHint": True
        }
    }
]


def respond(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def read_message():
    while True:
        line = sys.stdin.readline()
        if not line:
            raise EOFError("stdin closed")
        if line.strip():
            return json.loads(line)


while True:
    try:
        message = read_message()
    except EOFError:
        break

    method = message.get("method")

    if method == "initialize":
        respond(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "docker-example-upstream",
                        "version": "0.1.0",
                    },
                },
            }
        )
        continue

    if method == "notifications/initialized":
        continue

    if method == "tools/list":
        respond({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}})
        continue

    if method == "tools/call":
        arguments = message.get("params", {}).get("arguments", {})
        respond(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"echo: {arguments.get('message', '')}",
                        }
                    ],
                    "structuredContent": {
                        "echo": arguments.get("message", "")
                    },
                    "isError": False,
                },
            }
        )
        continue

    if message.get("id") is not None:
        respond(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {
                    "code": -32601,
                    "message": f"unsupported method: {method}",
                },
            }
        )
