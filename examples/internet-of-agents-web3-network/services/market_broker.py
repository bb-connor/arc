#!/usr/bin/env python3
"""Provider marketplace service for the internet-of-agents web3 scenario."""
from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]


class QuoteRequest(BaseModel):
    order_id: str
    provider_id: str
    requested_scope: str
    max_budget_minor_units: int
    currency: str


class RfqRequest(BaseModel):
    rfq_id: str
    order_id: str
    provider_ids: list[str]
    requested_scope: str
    max_budget_minor_units: int
    currency: str


class PaymentRequirementRequest(BaseModel):
    order_id: str
    quote_id: str
    provider_id: str
    amount: dict[str, Any]
    protocol: str = "x402"


class PaymentProofRequest(BaseModel):
    proof_id: str
    order_id: str
    quote_id: str
    capability_id: str
    approval_decision_id: str
    amount: dict[str, Any]
    source_of_truth: str
    receipt: dict[str, Any]


class FulfillmentRequest(BaseModel):
    quote_id: str
    accepted_by: str
    evidence_refs: list[str]


@dataclass(frozen=True)
class ProviderCatalog:
    workspace: Path

    def provider_document(self, provider_id: str) -> dict[str, Any]:
        provider_path = self.workspace / "provider-lab/providers" / f"{provider_id}.json"
        if not provider_path.exists():
            raise HTTPException(status_code=404, detail="provider not found")
        return json.loads(provider_path.read_text(encoding="utf-8"))

    def service_for(self, provider_id: str, service_id: str) -> dict[str, Any]:
        provider = self.provider_document(provider_id)
        for service in provider.get("services", []):
            if service.get("service_id") == service_id:
                return {**service, "provider": provider}
        raise HTTPException(status_code=404, detail="service not offered")


@dataclass(frozen=True)
class MarketLedger:
    state_dir: Path

    def write(self, kind: str, identifier: str, document: dict[str, Any]) -> None:
        path = self.state_dir / kind / f"{identifier}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def read(self, kind: str, identifier: str) -> dict[str, Any]:
        path = self.state_dir / kind / f"{identifier}.json"
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"{kind.rstrip('s')} not found")
        return json.loads(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class MarketBroker:
    catalog: ProviderCatalog
    ledger: MarketLedger

    def rfq(self, request: RfqRequest) -> dict[str, Any]:
        now = int(time.time())
        bids: list[dict[str, Any]] = []
        for provider_id in request.provider_ids:
            service = self.catalog.service_for(provider_id, request.requested_scope)
            provider = service["provider"]
            bids.append({
                "bid_id": f"bid-{provider_id}-{request.order_id}",
                "order_id": request.order_id,
                "provider_id": provider_id,
                "service_id": service["service_id"],
                "price_minor_units": service["price_minor_units"],
                "currency": service["currency"],
                "deliverables": service["deliverables"],
                "requirements": service["requirements"],
                "issued_at": now,
                "expires_at": now + 900,
                "trust": provider.get("trust", {}),
                "risk": provider.get("risk", {}),
            })
        response = {
            "schema": "chio.example.ioa-web3.rfq-response.v1",
            "rfq_id": request.rfq_id,
            "order_id": request.order_id,
            "bids": bids,
            "issued_at": now,
        }
        self.ledger.write("rfqs", request.rfq_id, response)
        return response

    def quote(self, request: QuoteRequest) -> dict[str, Any]:
        service = self.catalog.service_for(request.provider_id, request.requested_scope)
        if service["price_minor_units"] > request.max_budget_minor_units:
            raise HTTPException(status_code=402, detail="quote exceeds budget")
        now = int(time.time())
        quote_doc = {
            "quote_id": f"quote-{uuid.uuid4().hex[:12]}",
            "order_id": request.order_id,
            "provider_id": request.provider_id,
            "service_id": service["service_id"],
            "price_minor_units": service["price_minor_units"],
            "currency": service["currency"],
            "deliverables": service["deliverables"],
            "requirements": service["requirements"],
            "trust": service.get("provider", {}).get("trust", {}),
            "issued_at": now,
            "expires_at": now + 900,
        }
        self.ledger.write("quotes", quote_doc["quote_id"], quote_doc)
        return quote_doc

    def payment_requirements(self, request: PaymentRequirementRequest) -> dict[str, Any]:
        doc = {
            "schema": "x402.payment-required.local.v1",
            "payment_requirement_id": f"x402-required-{request.quote_id}",
            "http_status": 402,
            "order_id": request.order_id,
            "quote_id": request.quote_id,
            "provider_id": request.provider_id,
            "amount": request.amount,
            "protocol": request.protocol,
            "settlement_source_of_truth": "chio",
            "issued_at": int(time.time()),
        }
        self.ledger.write("payment-requirements", doc["payment_requirement_id"], doc)
        return doc

    def payment_proof(self, request: PaymentProofRequest) -> dict[str, Any]:
        doc = {
            "schema": "x402.payment-satisfaction.local.v1",
            "payment_satisfaction_id": f"x402-satisfied-{request.quote_id}",
            "proof_id": request.proof_id,
            "quote_id": request.quote_id,
            "order_id": request.order_id,
            "status": "satisfied",
            "source_of_truth": request.source_of_truth,
            "receipt": request.receipt,
            "accepted_at": int(time.time()),
        }
        self.ledger.write("payment-proofs", request.proof_id, doc)
        return doc

    def fulfill(self, request: FulfillmentRequest) -> dict[str, Any]:
        quote_doc = self.ledger.read("quotes", request.quote_id)
        fulfillment = {
            "fulfillment_id": f"fulfillment-{uuid.uuid4().hex[:12]}",
            "quote_id": request.quote_id,
            "order_id": quote_doc["order_id"],
            "accepted_by": request.accepted_by,
            "provider_id": quote_doc["provider_id"],
            "status": "delivered",
            "evidence_refs": request.evidence_refs,
            "delivered_at": int(time.time()),
        }
        self.ledger.write("fulfillments", fulfillment["fulfillment_id"], fulfillment)
        return fulfillment


def build_app(broker: MarketBroker) -> FastAPI:
    app = FastAPI(title="internet-of-agents-web3-market-broker")

    @app.get("/health")
    def health() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/quotes")
    def quote(payload: QuoteRequest) -> dict[str, Any]:
        return broker.quote(payload)

    @app.post("/rfqs")
    def rfq(payload: RfqRequest) -> dict[str, Any]:
        return broker.rfq(payload)

    @app.post("/payment-requirements")
    def payment_requirements(payload: PaymentRequirementRequest) -> dict[str, Any]:
        return broker.payment_requirements(payload)

    @app.post("/payment-proofs")
    def payment_proof(payload: PaymentProofRequest) -> dict[str, Any]:
        return broker.payment_proof(payload)

    @app.post("/fulfillments")
    def fulfill(payload: FulfillmentRequest) -> dict[str, Any]:
        return broker.fulfill(payload)

    return app


def app_from_environment() -> FastAPI:
    workspace = Path(os.getenv("CHIO_IOA_WEB3_WORKSPACE", ROOT / "workspaces"))
    state_dir = Path(os.getenv("CHIO_IOA_WEB3_MARKET_STATE_DIR", ROOT / "state/market"))
    return build_app(MarketBroker(ProviderCatalog(workspace), MarketLedger(state_dir)))


app = app_from_environment()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8521)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
