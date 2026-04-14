"""Tests for arc-fastapi dependency injection helpers."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from arc_fastapi.dependencies import (
    get_arc_client,
    get_arc_receipt,
    get_caller_identity,
    set_arc_client,
)
from arc_sdk.client import ArcClient
from arc_sdk.models import HttpReceipt, Verdict


class TestSetArcClient:
    def test_set_and_get(self) -> None:
        mock = AsyncMock(spec=ArcClient)
        set_arc_client(mock)
        # Cleanup
        set_arc_client(None)

    def test_clear(self) -> None:
        set_arc_client(None)


class TestGetCallerIdentity:
    def test_bearer_extraction(self) -> None:
        app = FastAPI()

        @app.get("/test")
        async def handler(request: Request) -> dict:
            caller = await get_caller_identity(request)
            return {
                "subject": caller.subject,
                "method": caller.auth_method.method,
            }

        client = TestClient(app)
        resp = client.get("/test", headers={"Authorization": "Bearer my-token"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["method"] == "bearer"

    def test_api_key_extraction(self) -> None:
        app = FastAPI()

        @app.get("/test")
        async def handler(request: Request) -> dict:
            caller = await get_caller_identity(request)
            return {
                "subject": caller.subject,
                "method": caller.auth_method.method,
            }

        client = TestClient(app)
        resp = client.get("/test", headers={"X-API-Key": "key-123"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["method"] == "api_key"

    def test_anonymous_fallback(self) -> None:
        app = FastAPI()

        @app.get("/test")
        async def handler(request: Request) -> dict:
            caller = await get_caller_identity(request)
            return {
                "subject": caller.subject,
                "method": caller.auth_method.method,
            }

        client = TestClient(app)
        resp = client.get("/test")
        assert resp.status_code == 200
        body = resp.json()
        assert body["method"] == "anonymous"
        assert body["subject"] == "anonymous"


class TestGetArcReceipt:
    def test_no_receipt(self) -> None:
        app = FastAPI()

        @app.get("/test")
        async def handler(request: Request) -> dict:
            receipt = await get_arc_receipt(request)
            return {"has_receipt": receipt is not None}

        client = TestClient(app)
        resp = client.get("/test")
        assert resp.status_code == 200
        assert resp.json()["has_receipt"] is False
