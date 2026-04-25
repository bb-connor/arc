#!/usr/bin/env python3
"""MCP server for ProofWorks provider review attestations."""
from __future__ import annotations

import hashlib
import json
import sys
from typing import Any

TOOLS = [
    {
        "name": "inspect_service_order",
        "description": "Inspect an internet-of-agents web3 service order.",
        "inputSchema": {"type": "object", "properties": {"service_order": {"type": "object"}}},
    },
    {
        "name": "evaluate_provider_reputation",
        "description": "Evaluate local provider reputation evidence.",
        "inputSchema": {"type": "object", "properties": {"reputation": {"type": "object"}}},
    },
    {
        "name": "issue_review_attestation",
        "description": "Issue a provider review attestation for the settlement proof package.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service_order": {"type": "object"},
                "validation_index": {"type": "object"},
            },
        },
    },
]


def _digest(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _inspect_service_order(args: dict[str, Any]) -> dict[str, Any]:
    order = args.get("service_order", {})
    return {
        "schema": "chio.example.ioa-web3.provider-review.service-order-inspection.v1",
        "orderId": order.get("order_id"),
        "provider": order.get("provider"),
        "paymentProtocolHint": order.get("payment_requirement", {}).get("protocol_hint"),
        "capabilityRefsPresent": bool(order.get("capabilities")),
        "verdict": "pass" if order.get("capabilities") else "fail",
    }


def _evaluate_provider_reputation(args: dict[str, Any]) -> dict[str, Any]:
    reputation = args.get("reputation", {})
    score = reputation.get("computedScore", 0)
    minimum_score = reputation.get("minimumScore", 0.60)
    return {
        "schema": "chio.example.ioa-web3.provider-review.reputation-evaluation.v1",
        "subject": reputation.get("subject"),
        "computedScore": score,
        "minimumScore": minimum_score,
        "verdict": "pass" if score >= minimum_score else "fail",
    }


def _issue_review_attestation(args: dict[str, Any]) -> dict[str, Any]:
    service_order = args.get("service_order", {})
    validation_index = args.get("validation_index", {})
    attestation = {
        "schema": "chio.example.ioa-web3.provider-review-attestation.v1",
        "attestationId": "attestation-proofworks-web3-review-001",
        "orderId": service_order.get("order_id"),
        "provider": service_order.get("provider"),
        "validationIndexDigest": _digest(validation_index),
        "scope": "web3-settlement-proof-review",
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
                "serverInfo": {"name": "proofworks-provider-review", "version": "0.1.0"},
            },
        })
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        _respond({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}})
    elif method == "tools/call":
        name = message["params"]["name"]
        args = message["params"].get("arguments", {})
        if name == "inspect_service_order":
            structured = _inspect_service_order(args)
        elif name == "evaluate_provider_reputation":
            structured = _evaluate_provider_reputation(args)
        elif name == "issue_review_attestation":
            structured = _issue_review_attestation(args)
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
