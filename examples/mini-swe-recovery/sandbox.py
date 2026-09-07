"""Operator-side MCP bridge to one existing Docker container (stdlib only)."""

import argparse
import json
import os
import re
import selectors
import subprocess
import sys
import time

MAX_OUTPUT_BYTES = 512 * 1024
TOOL = {
    "name": "execute",
    "description": "Execute one bash command in the assigned repository sandbox.",
    "inputSchema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["command"],
        "properties": {
            "command": {"type": "string", "maxLength": 65536},
            "tool_call_id": {"type": "string"},
        },
    },
    "annotations": {
        "readOnlyHint": False,
        "idempotentHint": False,
        "destructiveHint": True,
        "openWorldHint": False,
    },
}


def execute(container, command):
    if not isinstance(command, str) or not command or len(command) > 65536:
        raise ValueError("Invalid command")
    arguments = ["/usr/bin/docker", "exec", "-w", "/workspace", container, "bash", "-lc", command]
    with subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
        output = bytearray()
        deadline = time.monotonic() + 30
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise RuntimeError("Command timed out; outcome may be incomplete")
                    chunk = os.read(process.stdout.fileno(), 8192)
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > MAX_OUTPUT_BYTES:
                        raise RuntimeError(
                            "Command output exceeded its limit; outcome may be incomplete"
                        )
            returncode = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except BaseException:
            process.kill()
            process.wait()
            raise
    return {
        "output": output.decode("utf-8", errors="replace"),
        "returncode": returncode,
        "exception_info": "",
    }


def serve(container):
    for line in sys.stdin:
        message = json.loads(line)
        if "id" not in message:
            continue
        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": message["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mini-swe-sandbox", "version": "1"},
            }
        elif method == "tools/list":
            result = {"tools": [TOOL]}
        elif method == "tools/call":
            try:
                if message["params"]["name"] != "execute":
                    raise ValueError("Unknown tool")
                value = execute(container, message["params"]["arguments"]["command"])
                result = {
                    "structuredContent": value,
                    "content": [{"type": "text", "text": json.dumps(value)}],
                }
            except (ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired):
                result = {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": "Command outcome is incomplete. Stop and inspect the sandbox.",
                        }
                    ],
                }
        else:
            raise ValueError("Unsupported MCP method")
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[a-f0-9]{64}", args.container) is None:
        raise ValueError("The operator must pin a full container id")
    serve(args.container)
