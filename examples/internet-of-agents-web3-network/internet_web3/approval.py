"""Deterministic human approval fixture for high-risk settlement actions."""
from __future__ import annotations

from typing import Any

from .artifacts import ArtifactStore, Json, now_epoch
from .identity import digest


def write_approval_checkpoint(
    *,
    store: ArtifactStore,
    order_request: Json,
    quote_response: Json,
    treasury_identity: Any,
    treasury_capability: Json,
) -> tuple[Json, Json, Json, Json]:
    challenge = {
        "schema": "chio.example.ioa-web3.approval-challenge.v1",
        "challenge_id": f"approval-challenge-{order_request['order_id']}",
        "order_id": order_request["order_id"],
        "required_before": "budget-exposure-or-final-release",
        "risk": {
            "category": "high-risk-web3-settlement",
            "amount": {
                "units": quote_response["price_minor_units"],
                "currency": quote_response["currency"],
            },
            "mainnet_blocked": True,
        },
        "capability_id": treasury_capability["id"],
        "issued_at": now_epoch(),
    }
    decision_body = {
        "challenge_id": challenge["challenge_id"],
        "order_id": order_request["order_id"],
        "decision": "approve",
        "approved_amount": challenge["risk"]["amount"],
    }
    decision = {
        "schema": "chio.example.ioa-web3.approval-decision.v1",
        "decision_id": f"approval-decision-{order_request['order_id']}",
        **decision_body,
        "signer": treasury_identity.public_key,
        "signature": treasury_identity.sign(decision_body),
        "signed_fixture": True,
        "signed_at": now_epoch(),
    }
    receipt = {
        "schema": "chio.example.ioa-web3.approval-receipt.v1",
        "receipt_id": f"rcpt-approval-{order_request['order_id']}",
        "challenge_id": challenge["challenge_id"],
        "decision_id": decision["decision_id"],
        "decision": "allow",
        "signature_digest": digest(decision["signature"]),
    }
    audit = {
        "schema": "chio.example.ioa-web3.approval-audit.v1",
        "status": "signed",
        "challenge": "approvals/high-risk-release-challenge.json",
        "decision": "approvals/high-risk-release-decision.json",
        "receipt": "approvals/high-risk-release-receipt.json",
        "non_interactive": True,
    }
    store.write_json("approvals/high-risk-release-challenge.json", challenge)
    store.write_json("approvals/high-risk-release-decision.json", decision)
    store.write_json("approvals/high-risk-release-receipt.json", receipt)
    store.write_json("approvals/high-risk-release-audit.json", audit)
    return challenge, decision, receipt, audit

