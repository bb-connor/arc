"""Controlled dispute and remediation branch for the web3 service order."""
from __future__ import annotations

from .artifacts import ArtifactStore, Json, now_epoch
from .identity import digest


def write_dispute_workflow(
    *,
    store: ArtifactStore,
    service_order: Json,
    quote_response: Json,
    provider_capability: Json,
    settlement_capability: Json,
) -> Json:
    order_id = service_order["order_id"]
    weak_deliverable = {
        "schema": "chio.example.ioa-web3.weak-deliverable.v1",
        "deliverable_id": f"weak-secondary-review-{order_id}",
        "order_id": order_id,
        "provider_id": quote_response["provider_id"],
        "issue": "secondary evidence appendix was late and missing one proof leaf",
        "severity": "medium",
        "detected_at": now_epoch(),
    }
    partial_payment_units = int(quote_response["price_minor_units"] * 0.7)
    refund_units = quote_response["price_minor_units"] - partial_payment_units
    partial_payment = {
        "schema": "chio.example.ioa-web3.partial-payment.v1",
        "order_id": order_id,
        "capability_id": settlement_capability["id"],
        "amount": {"units": partial_payment_units, "currency": quote_response["currency"]},
        "receipt": {"id": f"rcpt-partial-payment-{order_id}", "decision": "allow"},
    }
    refund = {
        "schema": "chio.example.ioa-web3.refund.v1",
        "order_id": order_id,
        "capability_id": settlement_capability["id"],
        "amount": {"units": refund_units, "currency": quote_response["currency"]},
        "receipt": {"id": f"rcpt-refund-{order_id}", "decision": "allow"},
    }
    reputation_downgrade = {
        "schema": "chio.example.ioa-web3.reputation-downgrade.v1",
        "provider_id": quote_response["provider_id"],
        "before": 0.904,
        "after": 0.872,
        "reason": weak_deliverable["issue"],
        "capability_id": provider_capability["id"],
    }
    passport_drift = {
        "schema": "chio.example.ioa-web3.passport-claim-drift.v1",
        "provider_id": quote_response["provider_id"],
        "claimed_score": 0.91,
        "post_dispute_score": reputation_downgrade["after"],
        "drift": round(0.91 - reputation_downgrade["after"], 4),
        "verdict": "monitor",
    }
    remediation = {
        "schema": "chio.example.ioa-web3.remediation-packet.v1",
        "remediation_id": f"remediation-{order_id}",
        "required_actions": [
            "attach missing proof leaf",
            "publish amended provider review receipt",
            "accept partial refund",
        ],
        "status": "completed",
    }
    dispute_packet = {
        "schema": "chio.example.ioa-web3.dispute-packet.v1",
        "dispute_id": f"dispute-{order_id}",
        "order_id": order_id,
        "weak_deliverable": "disputes/weak-deliverable.json",
        "partial_payment": "disputes/partial-payment.json",
        "refund": "disputes/refund.json",
        "remediation": "disputes/remediation-packet.json",
        "status": "resolved",
    }
    dispute_audit = {
        "schema": "chio.example.ioa-web3.dispute-audit.v1",
        "status": "resolved",
        "dispute_id": dispute_packet["dispute_id"],
        "receipt_ids": [
            partial_payment["receipt"]["id"],
            refund["receipt"]["id"],
            f"rcpt-dispute-resolution-{order_id}",
        ],
        "digest": digest(dispute_packet),
    }
    summary = {
        "schema": "chio.example.ioa-web3.dispute-summary.v1",
        "status": "resolved",
        "partial_payment_units": partial_payment_units,
        "refund_units": refund_units,
        "reputation_after": reputation_downgrade["after"],
        "passport_drift_verdict": passport_drift["verdict"],
    }
    store.write_json("disputes/weak-deliverable.json", weak_deliverable)
    store.write_json("disputes/partial-payment.json", partial_payment)
    store.write_json("disputes/refund.json", refund)
    store.write_json("disputes/reputation-downgrade.json", reputation_downgrade)
    store.write_json("disputes/passport-claim-drift.json", passport_drift)
    store.write_json("disputes/remediation-packet.json", remediation)
    store.write_json("disputes/dispute-packet.json", dispute_packet)
    store.write_json("disputes/dispute-audit.json", dispute_audit)
    store.write_json("disputes/dispute-summary.json", summary)
    return summary

