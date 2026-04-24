"""Service adapters used by the web3 internet-of-agents scenario."""
from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .artifacts import Json, now_epoch
from .chio import ChioMcpClient, capability_header


class Market(Protocol):
    def request_rfq(self, payload: Json) -> Json:
        ...

    def request_quote(self, payload: Json) -> Json:
        ...

    def payment_requirements(self, payload: Json) -> Json:
        ...

    def submit_payment_proof(self, payload: Json) -> Json:
        ...

    def accept_fulfillment(self, payload: Json) -> Json:
        ...


class SettlementDesk(Protocol):
    def assemble_packet(self, payload: Json) -> Json:
        ...


class EvidenceTool(Protocol):
    def call(self, tool_name: str) -> Json:
        ...


class ProviderReviewTool(Protocol):
    def call(self, tool_name: str, arguments: Json | None = None) -> Json:
        ...


@dataclass(frozen=True)
class JsonHttpClient:
    base_url: str
    capability: Json | None = None
    timeout_seconds: int = 10

    def post(self, path: str, payload: Json) -> Json:
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        headers = {"Content-Type": "application/json"}
        if self.capability:
            headers["X-Chio-Capability"] = capability_header(self.capability)
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"service call failed: {url}: {exc.code}: {body}") from exc


@dataclass(frozen=True)
class HttpMarket:
    http: JsonHttpClient

    def request_rfq(self, payload: Json) -> Json:
        return self.http.post("/rfqs", payload)

    def request_quote(self, payload: Json) -> Json:
        return self.http.post("/quotes", payload)

    def payment_requirements(self, payload: Json) -> Json:
        return self.http.post("/payment-requirements", payload)

    def submit_payment_proof(self, payload: Json) -> Json:
        return self.http.post("/payment-proofs", payload)

    def accept_fulfillment(self, payload: Json) -> Json:
        return self.http.post("/fulfillments", payload)


@dataclass(frozen=True)
class LocalMarket:
    service: Json

    def request_rfq(self, payload: Json) -> Json:
        return {
            "schema": "chio.example.ioa-web3.rfq-response.v1",
            "rfq_id": payload["rfq_id"],
            "order_id": payload["order_id"],
            "bids": [{
                "bid_id": f"bid-{payload['provider_ids'][0]}-{payload['order_id']}",
                "order_id": payload["order_id"],
                "provider_id": payload["provider_ids"][0],
                "service_id": self.service["service_id"],
                "price_minor_units": self.service["price_minor_units"],
                "currency": self.service["currency"],
                "deliverables": self.service["deliverables"],
                "requirements": self.service["requirements"],
                "trust": {
                    "claimed_reputation_score": 0.91,
                    "runtime_tier": "attested",
                    "passport_status": "valid",
                },
            }],
            "issued_at": now_epoch(),
        }

    def request_quote(self, payload: Json) -> Json:
        if self.service["price_minor_units"] > payload["max_budget_minor_units"]:
            raise RuntimeError("quote exceeds budget")
        return {
            "quote_id": f"quote-{payload['order_id']}",
            "order_id": payload["order_id"],
            "provider_id": payload["provider_id"],
            "service_id": self.service["service_id"],
            "price_minor_units": self.service["price_minor_units"],
            "currency": self.service["currency"],
            "deliverables": self.service["deliverables"],
            "requirements": self.service["requirements"],
            "expires_at": now_epoch() + 900,
        }

    def payment_requirements(self, payload: Json) -> Json:
        return {
            "schema": "x402.payment-required.local.v1",
            "payment_requirement_id": f"x402-required-{payload['quote_id']}",
            "order_id": payload["order_id"],
            "quote_id": payload["quote_id"],
            "amount": payload["amount"],
            "protocol": payload.get("protocol", "x402"),
            "settlement_source_of_truth": "chio",
        }

    def submit_payment_proof(self, payload: Json) -> Json:
        return {
            "schema": "x402.payment-satisfaction.local.v1",
            "payment_satisfaction_id": f"x402-satisfied-{payload['quote_id']}",
            "proof_id": payload["proof_id"],
            "quote_id": payload["quote_id"],
            "status": "satisfied",
            "source_of_truth": "chio-budget-and-receipts",
        }

    def accept_fulfillment(self, payload: Json) -> Json:
        return {
            "fulfillment_id": f"fulfillment-{payload['order_id']}",
            "quote_id": payload["quote_id"],
            "order_id": payload["order_id"],
            "provider_id": payload["provider_id"],
            "accepted_by": payload["accepted_by"],
            "status": "delivered",
            "evidence_refs": payload["evidence_refs"],
            "delivered_at": now_epoch(),
        }


@dataclass(frozen=True)
class HttpSettlementDesk:
    http: JsonHttpClient

    def assemble_packet(self, payload: Json) -> Json:
        return self.http.post("/settlement-packets", payload)


@dataclass(frozen=True)
class LocalSettlementDesk:
    def assemble_packet(self, payload: Json) -> Json:
        order = payload["order"]
        quote = payload["quote"]
        fulfillment = payload["fulfillment"]
        base = payload["validation_index"].get("base_sepolia_live_smoke", {})
        rail_selection = payload.get("rail_selection", {})
        return {
            "packet_id": f"settlement-packet-{order['order_id']}",
            "status": "ready" if base.get("status") == "pass" else "qualified_without_live_smoke",
            "order_id": order["order_id"],
            "quote_id": quote["quote_id"],
            "fulfillment_id": fulfillment["fulfillment_id"],
            "chain_id": base.get("chain_id", "eip155:84532"),
            "amount": {"units": quote["price_minor_units"], "currency": quote["currency"]},
            "evidence": {
                "validation_index": "web3/validation-index.json",
                "base_sepolia_tx_count": base.get("tx_count", 0),
                "mainnet_blocked": True,
            },
            "rail_selection": rail_selection,
            "assembled_at": now_epoch(),
        }


@dataclass(frozen=True)
class StdioEvidenceTool:
    repo_root: Path
    script_path: Path
    timeout_seconds: int = 10

    def call(self, tool_name: str) -> Json:
        env = {**os.environ, "CHIO_IOA_WEB3_REPO_ROOT": str(self.repo_root)}
        messages = "\n".join([
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
            json.dumps({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": {}},
            }),
            "",
        ])
        result = subprocess.run(
            ["python3", str(self.script_path)],
            input=messages,
            text=True,
            capture_output=True,
            check=True,
            timeout=self.timeout_seconds,
            env=env,
        )
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            if payload.get("id") == 2:
                if "error" in payload:
                    raise RuntimeError(payload["error"])
                return payload["result"]["structuredContent"]
        raise RuntimeError(f"evidence tool did not return a result: {result.stdout!r}")


@dataclass(frozen=True)
class ChioMcpEvidenceTool:
    url: str
    auth_token: str

    def call(self, tool_name: str) -> Json:
        with ChioMcpClient(self.url, auth_token=self.auth_token) as client:
            return client.call_tool(tool_name, {})


@dataclass(frozen=True)
class ChioMcpProviderReviewTool:
    url: str
    auth_token: str

    def call(self, tool_name: str, arguments: Json | None = None) -> Json:
        with ChioMcpClient(self.url, auth_token=self.auth_token) as client:
            return client.call_tool(tool_name, arguments or {})
