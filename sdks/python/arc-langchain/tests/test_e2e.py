"""E2E test: FastAPI + arc-fastapi producing verifiable receipts.

This test simulates the full flow:
1. FastAPI app with @arc_requires decorator
2. Request with capability token
3. Sidecar evaluates and returns signed receipt
4. Receipt is verifiable
5. LangChain tool wrapper produces the same result

The sidecar is mocked via respx to avoid requiring a running instance.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from arc_fastapi.decorators import arc_requires
from arc_fastapi.dependencies import set_arc_client
from arc_langchain.tool import ArcTool, ArcToolkit
from arc_sdk.client import ArcClient, _canonical_json, _sha256_hex
from arc_sdk.models import (
    ArcReceipt,
    ArcScope,
    Decision,
    GuardEvidence,
    HttpReceipt,
    Operation,
    ToolCallAction,
    ToolGrant,
    Verdict,
)


BASE = "http://127.0.0.1:4100"


def _receipt_dict() -> dict:
    return {
        "id": "receipt-e2e",
        "request_id": "req-e2e",
        "route_pattern": "/tools/query",
        "method": "POST",
        "caller_identity_hash": "abc123",
        "verdict": {"verdict": "allow"},
        "evidence": [
            {"guard_name": "CapabilityGuard", "verdict": True},
            {"guard_name": "PathGuard", "verdict": True},
        ],
        "response_status": 200,
        "timestamp": 1700000000,
        "content_hash": "e2e-hash",
        "policy_hash": "e2e-policy",
        "kernel_key": "kernel-pub-e2e",
        "signature": "ed25519-sig-e2e",
    }


def _arc_receipt_dict() -> dict:
    return {
        "id": "arc-receipt-e2e",
        "timestamp": 1700000000,
        "capability_id": "cap-e2e",
        "tool_server": "ai-server",
        "tool_name": "query",
        "action": {
            "parameters": {"prompt": "hello"},
            "parameter_hash": _sha256_hex(_canonical_json({"prompt": "hello"})),
        },
        "decision": {"verdict": "allow"},
        "content_hash": "e2e-content",
        "policy_hash": "e2e-policy",
        "evidence": [
            {"guard_name": "CapabilityGuard", "verdict": True},
        ],
        "kernel_key": "kernel-pub-e2e",
        "signature": "sig-e2e",
    }


class TestE2EFastAPIWithReceipts:
    """End-to-end: FastAPI + @arc_requires producing verifiable receipts."""

    def test_full_flow(self) -> None:
        # 1. Set up FastAPI app with @arc_requires
        app = FastAPI()

        http_receipt = HttpReceipt.model_validate(_receipt_dict())

        mock_client = AsyncMock()
        mock_client.evaluate_http_request = AsyncMock(return_value=http_receipt)
        set_arc_client(mock_client)

        @app.post("/tools/query")
        @arc_requires("ai-server", "query")
        async def query_tool(request: Request) -> dict:
            receipt = getattr(request.state, "arc_receipt", None)
            return {
                "result": "42",
                "receipt_id": receipt.id if receipt else None,
            }

        # 2. Make a request with a capability token
        client = TestClient(app)
        resp = client.post(
            "/tools/query",
            headers={"X-Arc-Capability": "cap-e2e"},
            json={"prompt": "What is the meaning?"},
        )

        # 3. Verify response
        assert resp.status_code == 200
        body = resp.json()
        assert body["result"] == "42"
        assert body["receipt_id"] == "receipt-e2e"

        # 4. Verify the receipt structure
        assert http_receipt.is_allowed
        assert len(http_receipt.evidence) == 2
        assert all(e.verdict for e in http_receipt.evidence)

        # Cleanup
        set_arc_client(None)

    def test_denied_flow(self) -> None:
        """Verify denied requests return proper ARC error responses."""
        app = FastAPI()

        denied_receipt = HttpReceipt(
            id="receipt-denied-e2e",
            request_id="req-denied",
            route_pattern="/tools/dangerous",
            method="POST",
            caller_identity_hash="xyz",
            verdict=Verdict.deny("path /etc/shadow is forbidden", "PathGuard", 403),
            evidence=[
                GuardEvidence(
                    guard_name="PathGuard",
                    verdict=False,
                    details="path /etc/shadow matches forbidden pattern",
                ),
            ],
            response_status=403,
            timestamp=1700000000,
            content_hash="denied-hash",
            policy_hash="denied-policy",
            kernel_key="k",
            signature="s",
        )

        mock_client = AsyncMock()
        mock_client.evaluate_http_request = AsyncMock(return_value=denied_receipt)
        set_arc_client(mock_client)

        @app.post("/tools/dangerous")
        @arc_requires("fs-server", "read_file")
        async def dangerous_tool(request: Request) -> dict:
            return {"data": "should not reach here"}

        client = TestClient(app)
        resp = client.post(
            "/tools/dangerous",
            headers={"X-Arc-Capability": "cap-123"},
            json={"path": "/etc/shadow"},
        )

        assert resp.status_code == 403
        body = resp.json()
        assert body["error"]["code"] == "ARC_GUARD_DENIED"
        assert "PathGuard" in body["error"].get("guard", "")

        set_arc_client(None)


class TestE2ELangChainTool:
    """End-to-end: LangChain tool wrapper producing verifiable receipts."""

    @respx.mock
    async def test_langchain_tool_invocation(self) -> None:
        """Verify a LangChain tool invocation flows through ARC correctly."""

        respx.post(f"{BASE}/v1/evaluate").mock(
            return_value=httpx.Response(200, json=_arc_receipt_dict())
        )

        tool = ArcTool(
            name="query",
            description="Query the AI model",
            server_id="ai-server",
            capability_id="cap-e2e",
            sidecar_url=BASE,
            input_schema_def={
                "type": "object",
                "properties": {
                    "prompt": {"type": "string", "description": "The prompt"},
                },
                "required": ["prompt"],
            },
        )

        # Invoke through LangChain interface
        result = await tool._arun(prompt="hello")
        data = json.loads(result)

        assert data["status"] == "allowed"
        assert data["receipt_id"] == "arc-receipt-e2e"
        assert data["tool_server"] == "ai-server"
        assert data["tool_name"] == "query"

        # Verify receipt stored
        assert tool.last_receipt is not None
        assert tool.last_receipt.is_allowed

    @respx.mock
    async def test_toolkit_creates_tools_from_manifest(self) -> None:
        """Verify ArcToolkit can discover and wrap tools."""
        health_data = {
            "status": "ok",
            "servers": [
                {
                    "server_id": "ai-server",
                    "tools": [
                        {
                            "name": "query",
                            "description": "Query the AI",
                            "input_schema": {
                                "type": "object",
                                "properties": {
                                    "prompt": {"type": "string"},
                                },
                            },
                        },
                    ],
                },
            ],
        }
        respx.get(f"{BASE}/health").mock(
            return_value=httpx.Response(200, json=health_data)
        )

        toolkit = ArcToolkit(capability_id="cap-e2e", sidecar_url=BASE)
        tools = await toolkit.get_tools()

        assert len(tools) == 1
        assert tools[0].name == "query"
        assert tools[0].capability_id == "cap-e2e"
        assert tools[0].server_id == "ai-server"


class TestReceiptChainVerification:
    """Verify receipt chain continuity across multiple invocations."""

    async def test_receipt_chain(self) -> None:
        r1 = ArcReceipt(
            id="r-1",
            timestamp=1000,
            capability_id="cap-1",
            tool_server="srv",
            tool_name="t1",
            action=ToolCallAction(parameters={}, parameter_hash="a"),
            decision=Decision.allow(),
            content_hash="initial",
            policy_hash="p1",
            kernel_key="k",
            signature="s1",
        )

        # Chain: r2's content_hash = SHA-256 of canonical JSON of r1
        r1_canonical = _canonical_json(r1.model_dump(exclude_none=True))
        r1_hash = _sha256_hex(r1_canonical)

        r2 = ArcReceipt(
            id="r-2",
            timestamp=2000,
            capability_id="cap-1",
            tool_server="srv",
            tool_name="t2",
            action=ToolCallAction(parameters={}, parameter_hash="b"),
            decision=Decision.allow(),
            content_hash=r1_hash,
            policy_hash="p2",
            kernel_key="k",
            signature="s2",
        )

        async with ArcClient(BASE) as client:
            assert await client.verify_receipt_chain([r1, r2]) is True

            # Broken chain
            r3 = ArcReceipt(
                id="r-3",
                timestamp=3000,
                capability_id="cap-1",
                tool_server="srv",
                tool_name="t3",
                action=ToolCallAction(parameters={}, parameter_hash="c"),
                decision=Decision.allow(),
                content_hash="wrong-hash",
                policy_hash="p3",
                kernel_key="k",
                signature="s3",
            )
            assert await client.verify_receipt_chain([r2, r3]) is False
