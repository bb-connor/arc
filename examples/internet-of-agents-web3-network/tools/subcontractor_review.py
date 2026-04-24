#!/usr/bin/env python3
"""MCP server for CipherWorks subcontractor specialist review."""
from __future__ import annotations

import hashlib
import json
import sys
from typing import Any

TOOLS = [
    {
        "name": "issue_specialist_review",
        "description": "Issue a specialist evidence-leaf review for a delegated ProofWorks task.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service_order": {"type": "object"},
                "validation_index": {"type": "object"},
                "capability": {"type": "object"},
            },
        },
    },
]


def _digest(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _issue_specialist_review(args: dict[str, Any]) -> dict[str, Any]:
    service_order = args.get("service_order", {})
    validation_index = args.get("validation_index", {})
    capability = args.get("capability", {})
    attestation = {
        "schema": "chio.example.ioa-web3.subcontractor-review-attestation.v1",
        "attestationId": "attestation-cipherworks-specialist-001",
        "orderId": service_order.get("order_id"),
        "provider": "CipherWorks Review Lab",
        "delegatedBy": service_order.get("provider"),
        "validationIndexDigest": _digest(validation_index),
        "capabilityId": capability.get("id"),
        "scope": "base-sepolia-settlement-proof-leaf",
        "verdict": "pass",
        "mainnetBlocked": True,
    }
    attestation["signature"] = _digest(attestation)
    return attestation


def _respond(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


while True:
    line = sys.stdin.readline()
    if not line:
        break
    if not line.strip():
        continue
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        _respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "cipherworks-subcontractor-review", "version": "0.1.0"},
            },
        })
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        _respond({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}})
    elif method == "tools/call":
        name = message["params"]["name"]
        args = message["params"].get("arguments", {})
        if name == "issue_specialist_review":
            structured = _issue_specialist_review(args)
        else:
            _respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": -32601, "message": f"unknown tool: {name}"},
            })
            continue
        _respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "content": [{"type": "text", "text": json.dumps(structured)}],
                "structuredContent": structured,
                "isError": False,
            },
        })
    elif message.get("id") is not None:
        _respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {"code": -32601, "message": f"unsupported method: {method}"},
        })

