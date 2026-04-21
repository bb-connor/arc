#!/usr/bin/env python3
"""MCP server: provider edge operations.

Write-capable server for managing edge rules on the provider side.
This is the most sensitive tool surface -- it mutates provider
infrastructure.  Served behind chio mcp serve-http with a strict
policy so every operation is kernel-mediated with receipts.
"""
from __future__ import annotations

import difflib
import json
import os
import sys
import time
import uuid
from pathlib import Path

TOOLS = [
    {
        "name": "get_edge_policy",
        "description": (
            "Read the current edge policy for a tenant service. Returns all "
            "rules with their enabled/disabled state and configuration."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service name within the tenant",
                },
            },
            "required": ["service"],
        },
    },
    {
        "name": "disable_edge_rule",
        "description": (
            "Disable a specific edge rule for a tenant service. Creates a "
            "full evidence trail: before/after snapshots, unified diff, and "
            "audit log entry. This is a write operation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service name within the tenant",
                },
                "rule_name": {
                    "type": "string",
                    "description": "Name of the edge rule to disable",
                },
            },
            "required": ["service", "rule_name"],
        },
    },
]

ROOT = Path(__file__).resolve().parents[1]
PROVIDER_WORKSPACE = Path(
    os.getenv(
        "INCIDENT_NETWORK_PROVIDER_WORKSPACE",
        str(ROOT / "workspaces" / "provider-lab"),
    )
)


def policy_path(service: str) -> Path:
    return PROVIDER_WORKSPACE / "tenants" / "MeridianLabs" / "services" / f"{service}.json"


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def append_audit_log(entry: dict) -> None:
    path = PROVIDER_WORKSPACE / "operations" / "audit-log.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
    else:
        payload = []
    payload.append(entry)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def respond(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def handle_get_edge_policy(arguments: dict) -> dict:
    path = policy_path(arguments["service"])
    if not path.exists():
        return {"error": f"no policy found for service: {arguments['service']}"}
    return json.loads(path.read_text(encoding="utf-8"))


def handle_disable_edge_rule(arguments: dict) -> dict:
    path = policy_path(arguments["service"])
    if not path.exists():
        return {"error": f"no policy found for service: {arguments['service']}"}

    before_text = path.read_text(encoding="utf-8")
    policy = json.loads(before_text)
    changed = False

    for rule in policy.get("rules", []):
        if rule.get("name") == arguments["rule_name"]:
            rule["enabled"] = False
            rule["last_operation"] = "disabled_by_provider_executor"
            rule["last_updated_at"] = int(time.time())
            changed = True
            break

    operation_id = f"op-{uuid.uuid4().hex[:10]}"
    after_text = json.dumps(policy, indent=2) + "\n"

    if changed:
        path.write_text(after_text, encoding="utf-8")

    patch = "".join(
        difflib.unified_diff(
            before_text.splitlines(keepends=True),
            after_text.splitlines(keepends=True),
            fromfile=f"before/{path.name}",
            tofile=f"after/{path.name}",
        )
    )

    evidence_root = PROVIDER_WORKSPACE / "operations" / "evidence" / operation_id
    write_text(evidence_root / "before-policy.json", before_text)
    write_text(evidence_root / "after-policy.json", after_text)
    write_text(evidence_root / "provider-policy.diff", patch)

    structured = {
        "operation_id": operation_id,
        "status": "completed" if changed else "noop",
        "service": arguments["service"],
        "rule_name": arguments["rule_name"],
        "action": "disabled" if changed else "already_disabled_or_missing",
        "provider_evidence_path": str(evidence_root / "operation.json"),
        "patch": patch,
        "executed_at": int(time.time()),
    }
    write_json(
        evidence_root / "operation.json",
        {**structured, "workspace": str(PROVIDER_WORKSPACE), "changed": changed},
    )
    append_audit_log({
        "operation_id": operation_id,
        "service": arguments["service"],
        "rule_name": arguments["rule_name"],
        "changed": changed,
        "evidence_path": str(evidence_root / "operation.json"),
        "executed_at": structured["executed_at"],
    })
    return structured


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
                "serverInfo": {"name": "mcp-provider-ops", "version": "0.2.0"},
            },
        })
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        respond({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}})
    elif method == "tools/call":
        name = message["params"]["name"]
        arguments = message["params"].get("arguments", {})
        if name == "get_edge_policy":
            structured = handle_get_edge_policy(arguments)
        elif name == "disable_edge_rule":
            structured = handle_disable_edge_rule(arguments)
        else:
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": -32601, "message": f"unknown tool: {name}"},
            })
            continue
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
