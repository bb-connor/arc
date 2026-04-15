from __future__ import annotations

import json
import os
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any, Protocol

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field


CONTRACTS_DIR = Path(__file__).resolve().parents[1] / "contracts"
PROTOCOL_VERSION = "2025-11-25"
DEFAULT_APPROVAL_THRESHOLD_MINOR = 100_000
DEFAULT_BUDGET_MINOR = 150_000
DEFAULT_BUYER_ID = "acme-platform-security"
DEFAULT_PROVIDER_ID = "contoso-red-team"


def contract_template(name: str) -> dict[str, Any]:
    return json.loads((CONTRACTS_DIR / name).read_text())


def random_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def settlement_for(job: dict[str, Any], *, status: str = "reconciled") -> dict[str, Any]:
    template = deepcopy(contract_template("settlement-reconciliation.json"))
    quoted_amount = job["quote"]["price_minor"]
    template.update(
        {
            "settlement_id": random_id("settlement"),
            "job_id": job["job_id"],
            "quoted_amount_minor": quoted_amount,
            "approved_amount_minor": quoted_amount,
            "settled_amount_minor": 0 if status == "reversal_pending" else quoted_amount,
            "currency": job["quote"]["currency"],
            "status": status,
            "buyer_position": "accepted" if status == "reconciled" else "contested",
            "provider_position": "accepted" if status == "reconciled" else "review_requested",
        }
    )
    return template


class QuoteRequestPayload(BaseModel):
    service_family: str = Field(pattern="^security-review$")
    target: str
    requested_scope: str
    release_window: str | None = None


class CreateJobPayload(BaseModel):
    quote_id: str
    provider_id: str
    service_family: str
    budget_minor: int | None = None


class ApprovalPayload(BaseModel):
    approver: str
    reason: str


class DisputePayload(BaseModel):
    reason_code: str
    summary: str


class ProviderGateway(Protocol):
    def request_quote(self, payload: dict[str, Any]) -> dict[str, Any]:
        ...

    def execute_review(self, payload: dict[str, Any]) -> dict[str, Any]:
        ...

    def open_dispute(self, payload: dict[str, Any]) -> dict[str, Any]:
        ...


class StubProviderGateway:
    def __init__(self, approval_threshold_minor: int) -> None:
        self.approval_threshold_minor = approval_threshold_minor

    def request_quote(self, payload: dict[str, Any]) -> dict[str, Any]:
        template = deepcopy(contract_template("quote-response.json"))
        scope = payload["requested_scope"]
        price_minor = {
            "hotfix-review": 45_000,
            "release-review": 125_000,
            "release-plus-cloud-review": 175_000,
            "full-estate-review": 325_000,
        }.get(scope, template["price_minor"])
        template.update(
            {
                "quote_id": random_id("quote"),
                "request_id": payload["request_id"],
                "service_family": payload["service_family"],
                "price_minor": price_minor,
                "approval_required": price_minor > self.approval_threshold_minor,
                "pricing_basis": f"bounded {scope} for {payload['target']}",
            }
        )
        return template

    def execute_review(self, payload: dict[str, Any]) -> dict[str, Any]:
        template = deepcopy(contract_template("fulfillment-package.json"))
        template.update(
            {
                "fulfillment_id": random_id("fulfillment"),
                "job_id": payload["job_id"],
                "service_family": payload["service_family"],
                "target": payload["target"],
                "status": "completed_with_findings",
            }
        )
        return template

    def open_dispute(self, payload: dict[str, Any]) -> dict[str, Any]:
        template = deepcopy(contract_template("dispute-record.json"))
        template.update(
            {
                "dispute_id": random_id("dispute"),
                "job_id": payload["job_id"],
                "reason_code": payload["reason_code"],
                "summary": payload["summary"],
                "status": "opened",
            }
        )
        return template


class ProviderReviewClient:
    def __init__(
        self,
        *,
        base_url: str,
        auth_token: str,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.client = client or httpx.Client(timeout=timeout)
        self.last_trace: dict[str, Any] | None = None

    def request_quote(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._call_tool("request_quote", payload)

    def execute_review(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._call_tool("execute_review", payload)

    def open_dispute(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._call_tool("open_dispute", payload)

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._initialize_session()
        self._post_mcp(
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            session_id=session_id,
            expect_response=False,
        )
        payload = self._post_mcp(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
            session_id=session_id,
            expect_response=True,
        )
        self.last_trace = {
            "tool_name": name,
            "session_id": session_id,
            "capability_id": self._session_capability_id(session_id),
            "edge_base_url": self.base_url,
        }
        return payload["result"]["structuredContent"]

    def _initialize_session(self) -> str:
        response = self._post_raw(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "agent-commerce-network-buyer",
                        "version": "0.1.0",
                    },
                },
            }
        )
        _ = self._decode_response(response)
        session_id = response.headers.get("MCP-Session-Id")
        if not session_id:
            raise RuntimeError("provider edge did not return MCP-Session-Id")
        return session_id

    def _post_mcp(
        self,
        payload: dict[str, Any],
        *,
        session_id: str | None = None,
        expect_response: bool,
    ) -> dict[str, Any]:
        response = self._post_raw(payload, session_id=session_id)
        if not expect_response or not response.text.strip():
            return {}
        return self._decode_response(response)

    def _post_raw(
        self,
        payload: dict[str, Any],
        *,
        session_id: str | None = None,
    ) -> httpx.Response:
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
        }
        if session_id:
            headers["MCP-Session-Id"] = session_id
        response = self.client.post(f"{self.base_url}/mcp", headers=headers, json=payload)
        response.raise_for_status()
        return response

    def _session_capability_id(self, session_id: str) -> str | None:
        try:
            response = self.client.get(
                f"{self.base_url}/admin/sessions/{session_id}/trust",
                headers={"Authorization": f"Bearer {self.auth_token}"},
            )
            response.raise_for_status()
            payload = response.json()
        except Exception:
            return None
        capabilities = payload.get("capabilities", [])
        if not capabilities:
            return None
        return capabilities[0].get("capabilityId")

    @staticmethod
    def _decode_response(response: httpx.Response) -> dict[str, Any]:
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            return response.json()
        data_lines: list[str] = []
        for raw_line in response.text.splitlines():
            line = raw_line.strip()
            if not line:
                if data_lines:
                    break
                continue
            if line.startswith("data:"):
                data_lines.append(line.split(":", 1)[1].lstrip())
        if not data_lines:
            raise RuntimeError("no JSON-RPC payload received from provider edge")
        return json.loads("\n".join(data_lines))


class ProcurementService:
    def __init__(
        self,
        provider: ProviderGateway,
        *,
        buyer_id: str = DEFAULT_BUYER_ID,
        default_budget_minor: int = DEFAULT_BUDGET_MINOR,
    ) -> None:
        self.provider = provider
        self.buyer_id = buyer_id
        self.default_budget_minor = default_budget_minor
        self.quotes: dict[str, dict[str, Any]] = {}
        self.jobs: dict[str, dict[str, Any]] = {}

    def submit_quote_request(self, payload: QuoteRequestPayload) -> dict[str, Any]:
        request_id = random_id("quote_req")
        quote = self.provider.request_quote(
            {
                "request_id": request_id,
                "buyer_id": self.buyer_id,
                **payload.model_dump(),
            }
        )
        provider_trace = self._provider_trace()
        self.quotes[quote["quote_id"]] = {
            "request_id": request_id,
            "request": payload.model_dump(),
            "quote": quote,
            "provider_trace": provider_trace,
        }
        return {
            "request_id": request_id,
            "status": "quoted",
            "quote": quote,
            "provider_trace": provider_trace,
        }

    def create_job(self, payload: CreateJobPayload) -> dict[str, Any]:
        quote_record = self.quotes.get(payload.quote_id)
        if quote_record is None:
            raise KeyError(f"unknown quote: {payload.quote_id}")
        quote = quote_record["quote"]
        budget_minor = payload.budget_minor or self.default_budget_minor
        job = {
            "job_id": random_id("job"),
            "buyer_id": self.buyer_id,
            "provider_id": payload.provider_id,
            "service_family": payload.service_family,
            "budget_minor": budget_minor,
            "quote": quote,
            "requested_scope": quote_record["request"]["requested_scope"],
            "target": quote_record["request"]["target"],
            "release_window": quote_record["request"]["release_window"],
            "status": "staged",
            "approval_required": quote["approval_required"],
            "approval": None,
            "fulfillment": None,
            "fulfillment_trace": None,
            "settlement": None,
            "disputes": [],
            "quote_provider_trace": quote_record.get("provider_trace"),
        }
        if budget_minor < quote["price_minor"]:
            job["status"] = "denied_budget"
            job["denial_reason"] = "requested work exceeds the buyer budget envelope"
        elif quote["approval_required"]:
            job["status"] = "pending_approval"
        else:
            self._execute_job(job)
        self.jobs[job["job_id"]] = job
        return deepcopy(job)

    def get_job(self, job_id: str) -> dict[str, Any]:
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError(job_id)
        return deepcopy(job)

    def approve_job(self, job_id: str, payload: ApprovalPayload) -> dict[str, Any]:
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError(job_id)
        if job["status"] != "pending_approval":
            raise ValueError("job is not waiting for approval")
        job["approval"] = {
            "approver": payload.approver,
            "reason": payload.reason,
            "status": "approved",
        }
        self._execute_job(job)
        return deepcopy(job)

    def dispute_job(self, job_id: str, payload: DisputePayload) -> dict[str, Any]:
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError(job_id)
        dispute = self.provider.open_dispute(
            {
                "job_id": job["job_id"],
                "reason_code": payload.reason_code,
                "summary": payload.summary,
            }
        )
        job["disputes"].append(
            {
                "record": dispute,
                "provider_trace": self._provider_trace(),
            }
        )
        job["status"] = "disputed"
        if job["settlement"] is not None:
            job["settlement"] = settlement_for(job, status="reversal_pending")
        return deepcopy(job)

    def _execute_job(self, job: dict[str, Any]) -> None:
        fulfillment = self.provider.execute_review(
            {
                "job_id": job["job_id"],
                "quote_id": job["quote"]["quote_id"],
                "service_family": job["service_family"],
                "requested_scope": job["requested_scope"],
                "target": job["target"],
                "release_window": job["release_window"],
            }
        )
        job["fulfillment"] = fulfillment
        job["fulfillment_trace"] = self._provider_trace()
        job["settlement"] = settlement_for(job)
        job["status"] = "fulfilled"

    def _provider_trace(self) -> dict[str, Any] | None:
        trace = getattr(self.provider, "last_trace", None)
        return deepcopy(trace) if trace is not None else None


def provider_from_env() -> ProviderGateway:
    approval_threshold_minor = int(
        os.environ.get("BUYER_APPROVAL_THRESHOLD_MINOR", str(DEFAULT_APPROVAL_THRESHOLD_MINOR))
    )
    provider_base_url = os.environ.get("BUYER_PROVIDER_BASE_URL")
    provider_auth_token = os.environ.get("BUYER_PROVIDER_AUTH_TOKEN", "demo-token")
    if provider_base_url:
        return ProviderReviewClient(
            base_url=provider_base_url,
            auth_token=provider_auth_token,
        )
    return StubProviderGateway(approval_threshold_minor)


def build_service(provider: ProviderGateway | None = None) -> ProcurementService:
    buyer_id = os.environ.get("BUYER_ID", DEFAULT_BUYER_ID)
    default_budget_minor = int(os.environ.get("BUYER_DEFAULT_BUDGET_MINOR", str(DEFAULT_BUDGET_MINOR)))
    return ProcurementService(
        provider or provider_from_env(),
        buyer_id=buyer_id,
        default_budget_minor=default_budget_minor,
    )


def create_app(provider: ProviderGateway | None = None) -> FastAPI:
    app = FastAPI(
        title="Acme Procurement API",
        version="0.1.0",
        description="Tiny buyer-side procurement service for the agent-commerce-network example.",
    )
    app.state.procurement_service = build_service(provider)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        mode = (
            "wrapped-mcp-provider"
            if isinstance(app.state.procurement_service.provider, ProviderReviewClient)
            else "stub-provider"
        )
        return {"status": "ok", "provider_mode": mode}

    @app.post("/procurement/quote-requests", status_code=202)
    def request_quote(payload: QuoteRequestPayload, request: Request) -> dict[str, Any]:
        service: ProcurementService = request.app.state.procurement_service
        return service.submit_quote_request(payload)

    @app.post("/procurement/jobs", status_code=202)
    def create_job(payload: CreateJobPayload, request: Request) -> dict[str, Any]:
        service: ProcurementService = request.app.state.procurement_service
        try:
            return service.create_job(payload)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/procurement/jobs/{job_id}")
    def get_job(job_id: str, request: Request) -> dict[str, Any]:
        service: ProcurementService = request.app.state.procurement_service
        try:
            return service.get_job(job_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"unknown job: {job_id}") from exc

    @app.post("/procurement/jobs/{job_id}/approve")
    def approve_job(job_id: str, payload: ApprovalPayload, request: Request) -> dict[str, Any]:
        service: ProcurementService = request.app.state.procurement_service
        try:
            return service.approve_job(job_id, payload)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"unknown job: {job_id}") from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/procurement/jobs/{job_id}/disputes", status_code=202)
    def dispute_job(job_id: str, payload: DisputePayload, request: Request) -> dict[str, Any]:
        service: ProcurementService = request.app.state.procurement_service
        try:
            return service.dispute_job(job_id, payload)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"unknown job: {job_id}") from exc

    return app


app = create_app()
