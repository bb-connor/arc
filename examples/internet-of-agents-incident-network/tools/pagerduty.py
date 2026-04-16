#!/usr/bin/env python3
"""MCP server: customer PagerDuty integration.

Provides read-only access to on-call state, incident timeline,
and escalation policy information.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

TOOLS = [
    {
        "name": "get_oncall_state",
        "description": (
            "Get current on-call responder state for an incident, including "
            "primary and secondary responders, escalation level, and status."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": {
                    "type": "string",
                    "description": "Incident identifier",
                },
            },
            "required": ["incident_id"],
        },
    },
    {
        "name": "get_escalation_timeline",
        "description": (
            "Get the full escalation timeline for the current incident: "
            "each event with timestamp, actor, action, and notes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": {
                    "type": "string",
                    "description": "Incident identifier",
                },
            },
            "required": ["incident_id"],
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


def respond(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def handle_tool_call(name: str, arguments: dict) -> dict:
    if name == "get_oncall_state":
        data = load_json("pagerduty/oncall-state.json")
        data["requested_incident_id"] = arguments.get("incident_id", "")
        return data

    if name == "get_escalation_timeline":
        return load_json("pagerduty/escalation-timeline.json")

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
                "serverInfo": {"name": "mcp-pagerduty", "version": "0.2.0"},
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
