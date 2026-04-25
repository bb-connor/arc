#!/usr/bin/env python3
"""Settlement desk service for assembling web3 settlement packets."""
from __future__ import annotations

import argparse
import time
from dataclasses import dataclass
from typing import Any

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel


class SettlementPacketRequest(BaseModel):
    order: dict[str, Any]
    quote: dict[str, Any]
    fulfillment: dict[str, Any]
    validation_index: dict[str, Any]
    rail_selection: dict[str, Any] | None = None


class DisputePacketRequest(BaseModel):
    order: dict[str, Any]
    quote: dict[str, Any]
    weak_deliverable: dict[str, Any]
    requested_resolution: str


@dataclass(frozen=True)
class SettlementPacketAssembler:
    validation_index_ref: str = "web3/validation-index.json"

    def assemble(self, request: SettlementPacketRequest) -> dict[str, Any]:
        base = request.validation_index.get("base_sepolia_live_smoke", {})
        rail_selection = request.rail_selection or {}
        return {
            "packet_id": f"settlement-packet-{request.order['order_id']}",
            "status": "ready" if base.get("status") == "pass" else "qualified_without_live_smoke",
            "order_id": request.order["order_id"],
            "quote_id": request.quote["quote_id"],
            "fulfillment_id": request.fulfillment["fulfillment_id"],
            "chain_id": base.get("chain_id", "eip155:84532"),
            "amount": {
                "units": request.quote["price_minor_units"],
                "currency": request.quote["currency"],
            },
            "evidence": {
                "validation_index": self.validation_index_ref,
                "base_sepolia_tx_count": base.get("tx_count", 0),
                "mainnet_blocked": True,
            },
            "rail_selection": rail_selection,
            "assembled_at": int(time.time()),
        }

    def assemble_dispute(self, request: DisputePacketRequest) -> dict[str, Any]:
        amount = request.quote["price_minor_units"]
        return {
            "packet_id": f"dispute-packet-{request.order['order_id']}",
            "status": "resolved",
            "order_id": request.order["order_id"],
            "quote_id": request.quote["quote_id"],
            "requested_resolution": request.requested_resolution,
            "partial_payment": {
                "units": int(amount * 0.7),
                "currency": request.quote["currency"],
            },
            "refund": {
                "units": amount - int(amount * 0.7),
                "currency": request.quote["currency"],
            },
            "weak_deliverable": request.weak_deliverable,
            "mainnet_blocked": True,
            "assembled_at": int(time.time()),
        }


def build_app(assembler: SettlementPacketAssembler) -> FastAPI:
    app = FastAPI(title="internet-of-agents-web3-settlement-desk")

    @app.get("/health")
    def health() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/settlement-packets")
    def settlement_packet(payload: SettlementPacketRequest) -> dict[str, Any]:
        return assembler.assemble(payload)

    @app.post("/dispute-packets")
    def dispute_packet(payload: DisputePacketRequest) -> dict[str, Any]:
        return assembler.assemble_dispute(payload)

    return app


app = build_app(SettlementPacketAssembler())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8522)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
