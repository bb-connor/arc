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
                "message": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 4096,
                }
            },
            "required": ["message"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
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


def invalid_params(request_id):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32602,
            "message": "echo_text arguments do not match its input schema",
        },
    }


def invalid_request(request_id=None):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32600,
            "message": "request is not a valid JSON-RPC request",
        },
    }


def valid_echo_arguments(arguments):
    if not isinstance(arguments, dict) or set(arguments) != {"message"}:
        return False
    message = arguments["message"]
    return isinstance(message, str) and 1 <= len(message) <= 4096


def handle_message(message):
    if not isinstance(message, dict):
        return invalid_request()
    method = message.get("method")

    if method == "initialize":
        if "id" not in message:
            return invalid_request()
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "docker-example-upstream",
                    "version": "0.1.0",
                },
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        if "id" not in message:
            return invalid_request()
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}}

    if method == "tools/call":
        if "id" not in message:
            return invalid_request()
        params = message.get("params")
        if (
            not isinstance(params, dict)
            or set(params) != {"name", "arguments"}
            or params["name"] != "echo_text"
            or not valid_echo_arguments(params["arguments"])
        ):
            return invalid_params(message["id"])
        arguments = params["arguments"]
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"echo: {arguments['message']}",
                    }
                ],
                "structuredContent": {"echo": arguments["message"]},
                "isError": False,
            },
        }

    if message.get("id") is not None:
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {
                "code": -32601,
                "message": f"unsupported method: {method}",
            },
        }
    return None


def main():
    while True:
        try:
            message = read_message()
        except EOFError:
            break
        response = handle_message(message)
        if response is not None:
            respond(response)


if __name__ == "__main__":
    main()
