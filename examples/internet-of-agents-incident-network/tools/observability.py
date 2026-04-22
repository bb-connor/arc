#!/usr/bin/env python3
"""MCP server: customer observability platform.

Provides read-only access to incident data, distributed traces, deployment
timeline, and SLO status.  Served behind chio mcp serve-http so every tool
call is kernel-mediated with guard evaluation and receipt signing.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

TOOLS = [
    {
        "name": "get_incident_summary",
        "description": (
            "Retrieve the current incident summary including error rates, "
            "affected endpoints, symptom timeline, and error budget burn."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": {
                    "type": "string",
                    "description": "Incident identifier, e.g. INC-20260415-0917",
                },
            },
            "required": ["incident_id"],
        },
    },
    {
        "name": "query_spans",
        "description": (
            "Query distributed trace spans for a service within a time window. "
            "Returns sampled spans with parent-child relationships, latencies, "
            "status codes, and error details."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service name, e.g. inference-gateway",
                },
                "minutes": {
                    "type": "integer",
                    "description": "Lookback window in minutes (default: 15)",
                    "default": 15,
                },
                "status_code": {
                    "type": "integer",
                    "description": "Filter by HTTP status code (optional)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max spans to return (default: 50)",
                    "default": 50,
                },
            },
            "required": ["service"],
        },
    },
    {
        "name": "get_deploy_timeline",
        "description": (
            "List recent deployments for a service including commit SHAs, "
            "deployer, canary status, feature flags, and rollout state."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service name",
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of recent deploys to return (default: 5)",
                    "default": 5,
                },
            },
            "required": ["service"],
        },
    },
    {
        "name": "get_slo_status",
        "description": (
            "Get current SLO burn rate and error budget status for a service. "
            "Includes availability and latency SLO windows."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service name",
                },
            },
            "required": ["service"],
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
    if name == "get_incident_summary":
        data = load_json("observability/incident-summary.json")
        data["requested_incident_id"] = arguments.get("incident_id", "")
        return data

    if name == "query_spans":
        service = arguments.get("service", "")
        data = load_json(f"observability/traces/{service}.json")
        # Apply optional filters
        if arguments.get("status_code") and "spans" in data:
            code = arguments["status_code"]
            data["spans"] = [
                s for s in data["spans"]
                if s.get("status_code") == code
            ]
        limit = arguments.get("limit", 50)
        if "spans" in data:
            data["spans"] = data["spans"][:limit]
            data["returned_count"] = len(data["spans"])
        return data

    if name == "get_deploy_timeline":
        service = arguments.get("service", "")
        data = load_json(f"observability/deploys/{service}.json")
        limit = arguments.get("limit", 5)
        if "deployments" in data:
            data["deployments"] = data["deployments"][:limit]
        return data

    if name == "get_slo_status":
        service = arguments.get("service", "")
        return load_json(f"observability/slo/{service}.json")

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
                "serverInfo": {"name": "mcp-observability", "version": "0.2.0"},
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
