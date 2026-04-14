"""Tests for arc-fastapi decorators."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from arc_fastapi.decorators import arc_requires, arc_approval, arc_budget
from arc_fastapi.dependencies import set_arc_client
from arc_sdk.errors import ArcConnectionError, ArcDeniedError
from arc_sdk.models import HttpReceipt, Verdict


def _make_receipt(allowed: bool = True) -> HttpReceipt:
    verdict = (
        Verdict.allow()
        if allowed
        else Verdict.deny("blocked", "TestGuard", 403)
    )
    return HttpReceipt(
        id="receipt-test",
        request_id="req-1",
        route_pattern="/test",
        method="POST",
        caller_identity_hash="abc",
        verdict=verdict,
        response_status=200 if allowed else 403,
        timestamp=1700000000,
        content_hash="x",
        policy_hash="y",
        kernel_key="k",
        signature="s",
    )


# ---------------------------------------------------------------------------
# arc_requires
# ---------------------------------------------------------------------------


class TestArcRequires:
    def test_missing_capability_returns_401(self) -> None:
        app = FastAPI()

        @app.post("/deploy")
        @arc_requires("deploy-server", "deploy")
        async def deploy(request: Request) -> dict:
            return {"status": "deployed"}

        client = TestClient(app)
        resp = client.post("/deploy")
        assert resp.status_code == 401
        body = resp.json()
        assert body["error"]["code"] == "ARC_CAPABILITY_REQUIRED"

    def test_allowed_request_passes_through(self) -> None:
        app = FastAPI()

        mock_client = AsyncMock()
        mock_client.evaluate_http_request = AsyncMock(
            return_value=_make_receipt(allowed=True)
        )
        set_arc_client(mock_client)

        @app.post("/deploy")
        @arc_requires("deploy-server", "deploy")
        async def deploy(request: Request) -> dict:
            return {"status": "deployed"}

        client = TestClient(app)
        resp = client.post(
            "/deploy",
            headers={"X-Arc-Capability": "cap-123"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "deployed"

        # Cleanup
        set_arc_client(None)

    def test_denied_request_returns_403(self) -> None:
        app = FastAPI()

        mock_client = AsyncMock()
        mock_client.evaluate_http_request = AsyncMock(
            return_value=_make_receipt(allowed=False)
        )
        set_arc_client(mock_client)

        @app.post("/deploy")
        @arc_requires("deploy-server", "deploy")
        async def deploy(request: Request) -> dict:
            return {"status": "deployed"}

        client = TestClient(app)
        resp = client.post(
            "/deploy",
            headers={"X-Arc-Capability": "cap-123"},
        )
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"]["code"] == "ARC_GUARD_DENIED"

        set_arc_client(None)

    def test_sidecar_unavailable_returns_503(self) -> None:
        app = FastAPI()

        mock_client = AsyncMock()
        mock_client.evaluate_http_request = AsyncMock(
            side_effect=ArcConnectionError("connection refused")
        )
        set_arc_client(mock_client)

        @app.post("/deploy")
        @arc_requires("deploy-server", "deploy")
        async def deploy(request: Request) -> dict:
            return {"status": "deployed"}

        client = TestClient(app)
        resp = client.post(
            "/deploy",
            headers={"X-Arc-Capability": "cap-123"},
        )
        assert resp.status_code == 503
        body = resp.json()
        assert body["error"]["code"] == "ARC_SIDECAR_UNAVAILABLE"

        set_arc_client(None)

    def test_metadata_attached(self) -> None:
        @arc_requires("srv", "tool", ["Invoke", "ReadResult"])
        async def handler(request: Request) -> dict:
            return {}

        assert handler._arc_requires == {
            "server_id": "srv",
            "tool_name": "tool",
            "operations": ["Invoke", "ReadResult"],
        }

    def test_capability_from_query_param(self) -> None:
        app = FastAPI()

        mock_client = AsyncMock()
        mock_client.evaluate_http_request = AsyncMock(
            return_value=_make_receipt(allowed=True)
        )
        set_arc_client(mock_client)

        @app.get("/read")
        @arc_requires("read-server", "read")
        async def read_handler(request: Request) -> dict:
            return {"data": "ok"}

        client = TestClient(app)
        resp = client.get("/read?arc_capability=cap-qp")
        assert resp.status_code == 200

        set_arc_client(None)


# ---------------------------------------------------------------------------
# arc_approval
# ---------------------------------------------------------------------------


class TestArcApproval:
    def test_missing_approval_returns_403(self) -> None:
        app = FastAPI()

        @app.post("/transfer")
        @arc_approval(threshold_cents=1000, currency="USD")
        async def transfer(request: Request) -> dict:
            return {"transferred": True}

        client = TestClient(app)
        resp = client.post("/transfer")
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"]["code"] == "ARC_APPROVAL_REQUIRED"
        assert body["error"]["details"]["threshold_cents"] == 1000

    def test_with_approval_passes(self) -> None:
        app = FastAPI()

        @app.post("/transfer")
        @arc_approval(threshold_cents=1000)
        async def transfer(request: Request) -> dict:
            return {"transferred": True}

        client = TestClient(app)
        resp = client.post(
            "/transfer",
            headers={"X-Arc-Approval": "approval-tok-abc"},
        )
        assert resp.status_code == 200
        assert resp.json()["transferred"] is True

    def test_metadata_attached(self) -> None:
        @arc_approval(threshold_cents=5000, currency="EUR")
        async def handler(request: Request) -> dict:
            return {}

        assert handler._arc_approval == {
            "threshold_cents": 5000,
            "currency": "EUR",
        }


# ---------------------------------------------------------------------------
# arc_budget
# ---------------------------------------------------------------------------


class TestArcBudget:
    def test_budget_metadata_attached(self) -> None:
        @arc_budget(max_cost_cents=200, currency="GBP")
        async def handler(request: Request) -> dict:
            return {}

        assert handler._arc_budget == {
            "max_cost_cents": 200,
            "currency": "GBP",
        }

    def test_passes_through(self) -> None:
        app = FastAPI()

        @app.post("/query")
        @arc_budget(max_cost_cents=500)
        async def query(request: Request) -> dict:
            return {"result": "ok"}

        client = TestClient(app)
        resp = client.post("/query")
        assert resp.status_code == 200
        assert resp.json()["result"] == "ok"
