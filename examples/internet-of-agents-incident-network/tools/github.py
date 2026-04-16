#!/usr/bin/env python3
"""MCP server: customer GitHub/git platform.

Provides read-only access to recent commits, diffs, and file contents
for the customer's infrastructure repositories.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

TOOLS = [
    {
        "name": "search_commits",
        "description": (
            "Search recent commits for a service repository. Returns commit "
            "metadata including SHA, author, message, changed files, and PR info."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service/repository name",
                },
                "path": {
                    "type": "string",
                    "description": "Filter by file path prefix (optional)",
                },
                "since_hours": {
                    "type": "integer",
                    "description": "Lookback window in hours (default: 24)",
                    "default": 24,
                },
            },
            "required": ["service"],
        },
    },
    {
        "name": "get_diff",
        "description": (
            "Get the unified diff for a specific commit. Includes file-level "
            "changes with additions, deletions, and context."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service/repository name",
                },
                "commit": {
                    "type": "string",
                    "description": "Commit SHA (short or full)",
                },
            },
            "required": ["service", "commit"],
        },
    },
    {
        "name": "get_file",
        "description": (
            "Read a file from the repository at HEAD. Returns the file "
            "contents as a string."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service/repository name",
                },
                "path": {
                    "type": "string",
                    "description": "File path relative to repo root",
                },
            },
            "required": ["service", "path"],
        },
    },
]

ROOT = Path(__file__).resolve().parents[1]
CUSTOMER_WORKSPACE = Path(
    os.getenv(
        "INCIDENT_NETWORK_CUSTOMER_WORKSPACE",
        str(ROOT / "workspaces" / "customer-lab"),
    )
)


def load_json(relative_path: str) -> dict:
    full_path = CUSTOMER_WORKSPACE / relative_path
    if not full_path.exists():
        return {"error": f"data not found: {relative_path}"}
    return json.loads(full_path.read_text(encoding="utf-8"))


def load_text(relative_path: str) -> str:
    full_path = CUSTOMER_WORKSPACE / relative_path
    if not full_path.exists():
        return f"file not found: {relative_path}"
    return full_path.read_text(encoding="utf-8")


def respond(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def handle_tool_call(name: str, arguments: dict) -> dict:
    if name == "search_commits":
        service = arguments.get("service", "")
        data = load_json(f"git/recent-config-change/{service}.json")
        if "commits" not in data and "commit" in data:
            data = {"commits": [data], "total": 1}
        return data

    if name == "get_diff":
        service = arguments.get("service", "")
        data = load_json(f"git/recent-config-change/{service}.json")
        return {
            "commit": data.get("commit", arguments.get("commit", "")),
            "diff": data.get("diff", data.get("diff_content", "no diff available")),
            "files_changed": data.get("files_changed", []),
        }

    if name == "get_file":
        service = arguments.get("service", "")
        file_path = arguments.get("path", "")
        content = load_text(f"git/files/{service}/{file_path}")
        return {"path": file_path, "content": content}

    return {"error": f"unknown tool: {name}"}


while True:
    line = sys.stdin.readline()
    if not line:
        break
    if not line.strip():
        continue
    message = json.loads(line)
    method = message.get("method")

    if method == "initialize":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mcp-github", "version": "0.2.0"},
            },
        })
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        respond({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}})
    elif method == "tools/call":
        name = message["params"]["name"]
        arguments = message["params"].get("arguments", {})
        structured = handle_tool_call(name, arguments)
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "content": [{"type": "text", "text": json.dumps(structured)}],
                "structuredContent": structured,
                "isError": False,
            },
        })
    else:
        if message.get("id") is not None:
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": -32601, "message": f"unsupported method: {method}"},
            })
