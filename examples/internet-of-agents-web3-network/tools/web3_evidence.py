#!/usr/bin/env python3
"""MCP server for read-only web3 validation evidence inspection."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(os.getenv("CHIO_IOA_WEB3_REPO_ROOT", Path(__file__).resolve().parents[3]))

TOOLS = [
    {
        "name": "list_validation_artifacts",
        "description": "List the web3 validation artifacts that gate this example.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "summarize_base_sepolia_smoke",
        "description": "Summarize the Base Sepolia smoke report without exposing secrets.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "build_cutover_readiness",
        "description": "Build a read-only cutover readiness summary from local evidence.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _read(path: Path) -> dict:
    if not path.exists():
        return {"status": "missing", "path": str(path)}
    return json.loads(path.read_text(encoding="utf-8"))


def _artifact_paths() -> dict[str, Path]:
    return {
        "e2e": ROOT / "target/web3-e2e-qualification/partner-qualification.json",
        "promotion": ROOT / "target/web3-promotion-qualification/promotion-qualification.json",
        "ops": ROOT / "target/web3-ops-qualification/incident-audit.json",
        "base_sepolia_smoke": ROOT / "target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json",
        "mainnet_checklist": ROOT / "docs/release/CHIO_WEB3_MAINNET_CUTOVER_CHECKLIST.md",
    }


def _list_validation_artifacts() -> dict:
    return {
        name: {"path": str(path), "exists": path.exists()}
        for name, path in _artifact_paths().items()
    }


def _summarize_base_sepolia_smoke() -> dict:
    smoke = _read(_artifact_paths()["base_sepolia_smoke"])
    if smoke.get("status") == "missing":
        return smoke
    return {
        "status": smoke.get("status"),
        "chain_id": smoke.get("chain_id"),
        "actor": smoke.get("actor"),
        "tx_count": len(smoke.get("transactions", [])),
        "checks": smoke.get("checks", []),
        "transaction_ids": [tx.get("id") for tx in smoke.get("transactions", [])],
    }


def _build_cutover_readiness() -> dict:
    artifacts = _list_validation_artifacts()
    smoke = _summarize_base_sepolia_smoke()
    return {
        "mainnet_blocked": True,
        "local_evidence_present": all(
            artifacts[name]["exists"] for name in ["e2e", "promotion", "ops"]
        ),
        "base_sepolia_smoke_passed": smoke.get("status") == "pass",
        "next_gate": "review live Chainlink mainnet feeds and split signer roles before approval",
    }


def _respond(payload: dict) -> None:
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
                "serverInfo": {"name": "internet-of-agents-web3-evidence", "version": "0.1.0"},
            },
        })
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        _respond({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}})
    elif method == "tools/call":
        name = message["params"]["name"]
        if name == "list_validation_artifacts":
            structured = _list_validation_artifacts()
        elif name == "summarize_base_sepolia_smoke":
            structured = _summarize_base_sepolia_smoke()
        elif name == "build_cutover_readiness":
            structured = _build_cutover_readiness()
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
