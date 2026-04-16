from __future__ import annotations

import json
import unittest
from copy import deepcopy

import httpx
from fastapi.testclient import TestClient

from app import ProviderReviewClient, create_app


class FakeProvider:
    def __init__(self, *, price_minor: int, approval_required: bool) -> None:
        self.price_minor = price_minor
        self.approval_required = approval_required
        self.executions: list[dict] = []
        self.disputes: list[dict] = []

    def request_quote(self, payload: dict) -> dict:
        return {
            "quote_id": "quote_test_001",
            "request_id": payload["request_id"],
            "service_family": payload["service_family"],
            "offer_id": "release-review",
            "price_minor": self.price_minor,
            "currency": "USD",
            "approval_required": self.approval_required,
            "estimated_delivery_hours": 48,
            "pricing_basis": "test quote",
        }

    def execute_review(self, payload: dict) -> dict:
        self.executions.append(deepcopy(payload))
        return {
            "fulfillment_id": "fulfillment_test_001",
            "job_id": payload["job_id"],
            "service_family": payload["service_family"],
            "deliverables": ["executive-summary.md"],
            "status": "completed_with_findings",
            "severity_summary": {"critical": 0, "high": 1, "medium": 2, "low": 0},
        }

    def open_dispute(self, payload: dict) -> dict:
        self.disputes.append(deepcopy(payload))
        return {
            "dispute_id": "dispute_test_001",
            "job_id": payload["job_id"],
            "reason_code": payload["reason_code"],
            "summary": payload["summary"],
            "status": "opened",
            "requested_resolution": "partial_reversal",
        }


class BuyerApiTests(unittest.TestCase):
    def make_client(self, *, price_minor: int, approval_required: bool) -> tuple[TestClient, FakeProvider]:
        provider = FakeProvider(price_minor=price_minor, approval_required=approval_required)
        return TestClient(create_app(provider=provider)), provider

    def test_quote_request_returns_provider_quote(self) -> None:
        client, _provider = self.make_client(price_minor=45_000, approval_required=False)
        response = client.post(
            "/procurement/quote-requests",
            json={
                "service_family": "security-review",
                "target": "git://lattice.example/payments-api",
                "requested_scope": "hotfix-review",
                "release_window": "2026-05-01T16:00:00Z",
            },
        )
        self.assertEqual(response.status_code, 202)
        body = response.json()
        self.assertEqual(body["status"], "quoted")
        self.assertEqual(body["quote"]["price_minor"], 45_000)

    def test_job_auto_executes_when_approval_not_required(self) -> None:
        client, provider = self.make_client(price_minor=45_000, approval_required=False)
        quote = client.post(
            "/procurement/quote-requests",
            json={
                "service_family": "security-review",
                "target": "git://lattice.example/payments-api",
                "requested_scope": "hotfix-review",
                "release_window": "2026-05-01T16:00:00Z",
            },
        ).json()
        response = client.post(
            "/procurement/jobs",
            json={
                "quote_id": quote["quote"]["quote_id"],
                "provider_id": "vanguard-security",
                "service_family": "security-review",
                "budget_minor": 90_000,
            },
        )
        self.assertEqual(response.status_code, 202)
        body = response.json()
        self.assertEqual(body["status"], "fulfilled")
        self.assertIsNotNone(body["fulfillment"])
        self.assertEqual(len(provider.executions), 1)

    def test_job_waits_for_approval_then_executes(self) -> None:
        client, provider = self.make_client(price_minor=125_000, approval_required=True)
        quote = client.post(
            "/procurement/quote-requests",
            json={
                "service_family": "security-review",
                "target": "git://lattice.example/payments-api",
                "requested_scope": "release-review",
                "release_window": "2026-05-01T16:00:00Z",
            },
        ).json()
        create_response = client.post(
            "/procurement/jobs",
            json={
                "quote_id": quote["quote"]["quote_id"],
                "provider_id": "vanguard-security",
                "service_family": "security-review",
                "budget_minor": 150_000,
            },
        )
        self.assertEqual(create_response.status_code, 202)
        created = create_response.json()
        self.assertEqual(created["status"], "pending_approval")
        self.assertEqual(len(provider.executions), 0)

        approve_response = client.post(
            f"/procurement/jobs/{created['job_id']}/approve",
            json={"approver": "alice@lattice.example", "reason": "release risk accepted"},
        )
        self.assertEqual(approve_response.status_code, 200)
        approved = approve_response.json()
        self.assertEqual(approved["status"], "fulfilled")
        self.assertEqual(len(provider.executions), 1)

    def test_budget_deny_is_recorded_without_execution(self) -> None:
        client, provider = self.make_client(price_minor=125_000, approval_required=False)
        quote = client.post(
            "/procurement/quote-requests",
            json={
                "service_family": "security-review",
                "target": "git://lattice.example/payments-api",
                "requested_scope": "release-review",
                "release_window": "2026-05-01T16:00:00Z",
            },
        ).json()
        response = client.post(
            "/procurement/jobs",
            json={
                "quote_id": quote["quote"]["quote_id"],
                "provider_id": "vanguard-security",
                "service_family": "security-review",
                "budget_minor": 50_000,
            },
        )
        self.assertEqual(response.status_code, 202)
        body = response.json()
        self.assertEqual(body["status"], "denied_budget")
        self.assertEqual(len(provider.executions), 0)

    def test_dispute_updates_job_state(self) -> None:
        client, provider = self.make_client(price_minor=45_000, approval_required=False)
        quote = client.post(
            "/procurement/quote-requests",
            json={
                "service_family": "security-review",
                "target": "git://lattice.example/payments-api",
                "requested_scope": "hotfix-review",
                "release_window": "2026-05-01T16:00:00Z",
            },
        ).json()
        job = client.post(
            "/procurement/jobs",
            json={
                "quote_id": quote["quote"]["quote_id"],
                "provider_id": "vanguard-security",
                "service_family": "security-review",
                "budget_minor": 90_000,
            },
        ).json()
        dispute_response = client.post(
            f"/procurement/jobs/{job['job_id']}/disputes",
            json={"reason_code": "quality_issue", "summary": "Findings lacked repro steps"},
        )
        self.assertEqual(dispute_response.status_code, 202)
        disputed = dispute_response.json()
        self.assertEqual(disputed["status"], "disputed")
        self.assertEqual(disputed["settlement"]["status"], "reversal_pending")
        self.assertEqual(len(provider.disputes), 1)

    def test_provider_review_client_calls_wrapped_mcp_edge(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/admin/sessions/session_test_001/trust":
                return httpx.Response(
                    200,
                    json={"capabilities": [{"capabilityId": "cap_test_001"}]},
                )
            payload = json.loads(request.content.decode("utf-8"))
            session_id = request.headers.get("MCP-Session-Id")
            if payload["method"] == "initialize":
                return httpx.Response(
                    200,
                    headers={"MCP-Session-Id": "session_test_001", "content-type": "text/event-stream"},
                    text='data: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}\n\n',
                )
            if payload["method"] == "notifications/initialized":
                self.assertEqual(session_id, "session_test_001")
                return httpx.Response(202, text="")
            if payload["method"] == "tools/call":
                self.assertEqual(session_id, "session_test_001")
                self.assertEqual(payload["params"]["name"], "request_quote")
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    text=(
                        'data: {"jsonrpc":"2.0","id":2,"result":{"structuredContent":'
                        '{"quote_id":"quote_edge_001","price_minor":125000,"currency":"USD","approval_required":true}}}\n\n'
                    ),
                )
            raise AssertionError(f"unexpected MCP payload: {payload}")

        transport = httpx.MockTransport(handler)
        client = ProviderReviewClient(
            base_url="http://provider-edge.test",
            auth_token="demo-token",
            client=httpx.Client(transport=transport),
        )

        quote = client.request_quote(
            {
                "request_id": "quote_req_test_001",
                "buyer_id": "lattice-platform-security",
                "service_family": "security-review",
                "target": "git://lattice.example/payments-api",
                "requested_scope": "release-review",
            }
        )

        self.assertEqual(quote["quote_id"], "quote_edge_001")
        self.assertEqual(quote["price_minor"], 125000)
        self.assertEqual(client.last_trace["capability_id"], "cap_test_001")


if __name__ == "__main__":
    unittest.main()
