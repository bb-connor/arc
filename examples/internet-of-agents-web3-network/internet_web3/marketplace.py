"""RFQ selection, historical reputation, and x402 payment artifacts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .artifacts import ArtifactStore, Json, now_epoch
from .identity import digest


TRUSTED_PROVIDER = "proofworks-agent-auditors"
LOW_REPUTATION_PROVIDER = "discount-zk-reviewers"
MALICIOUS_PROVIDER = "overbudget-shadow-settlers"


@dataclass(frozen=True)
class MarketplaceWorkflow:
    rfq_request: Json
    bids: Json
    selection: Json
    history: Json
    scorecards: Json
    drift_report: Json
    passport_verdicts: Json
    federation_verdicts: Json
    payment_required: Json
    payment_proof: Json
    payment_satisfaction: Json


def provider_ids() -> list[str]:
    return [TRUSTED_PROVIDER, LOW_REPUTATION_PROVIDER, MALICIOUS_PROVIDER]


def build_rfq_request(order_request: Json, procurement_capability: Json) -> Json:
    return {
        "schema": "chio.example.ioa-web3.rfq-request.v1",
        "rfq_id": f"rfq-{order_request['order_id']}",
        "order_id": order_request["order_id"],
        "buyer_id": order_request["buyer_id"],
        "requested_scope": order_request["requested_scope"],
        "provider_ids": provider_ids(),
        "max_budget_minor_units": order_request["max_budget_minor_units"],
        "currency": order_request["currency"],
        "capability_id": procurement_capability["id"],
        "issued_at": now_epoch(),
    }


def historical_reputation_jobs() -> list[Json]:
    jobs: list[Json] = []
    outcomes = {
        TRUSTED_PROVIDER: ["pass", "pass", "pass", "remediated", "pass"],
        LOW_REPUTATION_PROVIDER: ["pass", "weak_evidence", "late", "pass", "weak_evidence"],
        MALICIOUS_PROVIDER: ["invoice_tamper", "late", "weak_evidence", "disputed", "budget_violation"],
    }
    for provider_id, provider_outcomes in outcomes.items():
        for index, outcome in enumerate(provider_outcomes, start=1):
            jobs.append({
                "job_id": f"hist-{provider_id}-{index}",
                "provider_id": provider_id,
                "outcome": outcome,
                "receipt_id": f"rcpt-hist-{provider_id}-{index}",
                "settled": outcome in {"pass", "remediated"},
                "disputed": outcome in {"weak_evidence", "late", "invoice_tamper", "disputed", "budget_violation"},
            })
    return jobs


def _score_jobs(jobs: list[Json]) -> float:
    weights = {
        "pass": 1.0,
        "remediated": 0.84,
        "weak_evidence": 0.56,
        "late": 0.52,
        "invoice_tamper": 0.18,
        "disputed": 0.32,
        "budget_violation": 0.12,
    }
    if not jobs:
        return 0.0
    return round(sum(weights[job["outcome"]] for job in jobs) / len(jobs), 4)


def _bid_by_provider(bids: Json, provider_id: str) -> Json:
    for bid in bids["bids"]:
        if bid["provider_id"] == provider_id:
            return bid
    raise RuntimeError(f"missing provider bid: {provider_id}")


def write_reputation_and_admission_artifacts(store: ArtifactStore, bids: Json, max_budget_units: int) -> tuple[Json, Json, Json, Json, Json]:
    jobs = historical_reputation_jobs()
    history = {
        "schema": "chio.example.ioa-web3.reputation-history-ledger.v1",
        "job_count": len(jobs),
        "jobs": jobs,
    }
    scorecards = {
        "schema": "chio.example.ioa-web3.provider-scorecards.v1",
        "providers": [],
    }
    drift_report = {
        "schema": "chio.example.ioa-web3.passport-drift-report.v1",
        "providers": [],
        "status": "pass",
    }
    passport_verdicts = {
        "schema": "chio.example.ioa-web3.provider-passport-verdicts.v1",
        "providers": [],
    }
    federation_verdicts = {
        "schema": "chio.example.ioa-web3.provider-federation-verdicts.v1",
        "providers": [],
    }

    for provider_id in provider_ids():
        provider_jobs = [job for job in jobs if job["provider_id"] == provider_id]
        computed_score = _score_jobs(provider_jobs)
        bid = _bid_by_provider(bids, provider_id)
        claimed_score = float(bid["trust"]["claimed_reputation_score"])
        drift = round(claimed_score - computed_score, 4)
        over_budget = bid["price_minor_units"] > max_budget_units
        runtime_ok = bid["trust"]["runtime_tier"] == "attested"
        reputation_ok = computed_score >= 0.82 and drift <= 0.08
        passport_ok = bid["trust"]["passport_status"] == "valid" and drift <= 0.08
        federation_ok = runtime_ok and reputation_ok and passport_ok and not over_budget

        scorecards["providers"].append({
            "provider_id": provider_id,
            "receipt_count": len(provider_jobs),
            "computed_score": computed_score,
            "budget_reconciled_jobs": sum(1 for job in provider_jobs if job["settled"]),
            "disputed_jobs": sum(1 for job in provider_jobs if job["disputed"]),
            "verdict": "pass" if reputation_ok else "fail",
        })
        drift_report["providers"].append({
            "provider_id": provider_id,
            "computed_score": computed_score,
            "passport_claimed_score": claimed_score,
            "drift": drift,
            "verdict": "pass" if drift <= 0.08 else "fail",
        })
        passport_verdicts["providers"].append({
            "provider_id": provider_id,
            "passport_id": f"passport-{provider_id}",
            "verdict": "pass" if passport_ok else "fail",
            "checks": [
                {"id": "signature", "outcome": "pass"},
                {"id": "claim-drift", "outcome": "pass" if drift <= 0.08 else "fail"},
                {"id": "runtime-tier", "outcome": "pass" if runtime_ok else "fail"},
            ],
        })
        federation_verdicts["providers"].append({
            "provider_id": provider_id,
            "verdict": "pass" if federation_ok else "fail",
            "reasons": [] if federation_ok else [
                reason
                for reason, present in [
                    ("runtime_tier_below_attested", not runtime_ok),
                    ("reputation_below_threshold", computed_score < 0.82),
                    ("passport_claim_drift", drift > 0.08),
                    ("budget_exceeds_policy", over_budget),
                ]
                if present
            ],
        })

    store.write_json("reputation/history-ledger.json", history)
    store.write_json("reputation/provider-scorecards.json", scorecards)
    store.write_json("reputation/passport-drift-report.json", drift_report)
    store.write_json("identity/passports/provider-passport-verdicts.json", passport_verdicts)
    store.write_json("federation/provider-admission-verdicts.json", federation_verdicts)
    return history, scorecards, drift_report, passport_verdicts, federation_verdicts


def select_provider(
    *,
    store: ArtifactStore,
    rfq_request: Json,
    bids: Json,
    scorecards: Json,
    passport_verdicts: Json,
    federation_verdicts: Json,
    max_budget_units: int,
) -> Json:
    scorecard_by_provider = {entry["provider_id"]: entry for entry in scorecards["providers"]}
    passport_by_provider = {entry["provider_id"]: entry for entry in passport_verdicts["providers"]}
    federation_by_provider = {entry["provider_id"]: entry for entry in federation_verdicts["providers"]}
    ranked: list[Json] = []

    for bid in bids["bids"]:
        provider_id = bid["provider_id"]
        reputation = scorecard_by_provider[provider_id]
        passport = passport_by_provider[provider_id]
        federation = federation_by_provider[provider_id]
        reasons = []
        if bid["price_minor_units"] > max_budget_units:
            reasons.append("budget_exceeds_policy")
        if reputation["verdict"] != "pass":
            reasons.append("reputation_below_threshold")
        if passport["verdict"] != "pass":
            reasons.append("passport_claim_drift")
        if federation["verdict"] != "pass":
            reasons.append("federation_admission_failed")
        score = round((reputation["computed_score"] * 100) - (bid["price_minor_units"] / 10_000), 4)
        ranked.append({
            "provider_id": provider_id,
            "bid_id": bid["bid_id"],
            "score": score,
            "admitted": not reasons,
            "reasons": reasons,
        })

    admitted = [entry for entry in ranked if entry["admitted"]]
    winner = max(admitted, key=lambda entry: entry["score"]) if admitted else None
    if not winner:
        raise RuntimeError("RFQ selection found no admitted provider")
    selection = {
        "schema": "chio.example.ioa-web3.provider-selection.v1",
        "rfq_id": rfq_request["rfq_id"],
        "status": "pass",
        "selected_provider_id": winner["provider_id"],
        "selected_bid_id": winner["bid_id"],
        "routing_authority": "Chio policy over passport, reputation, budget, runtime tier, and federation admission",
        "ranked_providers": ranked,
        "rejected_providers": [entry for entry in ranked if not entry["admitted"]],
        "receipt": {
            "id": f"rcpt-rfq-selection-{rfq_request['order_id']}",
            "decision": "allow",
            "digest": digest(ranked),
        },
    }
    store.write_json("market/provider-selection.json", selection)
    return selection


def write_payment_handshake(
    *,
    store: ArtifactStore,
    market: Any,
    order_request: Json,
    quote_response: Json,
    procurement_capability: Json,
    settlement_capability: Json,
    approval_decision: Json,
) -> tuple[Json, Json, Json]:
    payment_required = market.payment_requirements({
        "order_id": order_request["order_id"],
        "quote_id": quote_response["quote_id"],
        "provider_id": quote_response["provider_id"],
        "amount": {
            "units": quote_response["price_minor_units"],
            "currency": quote_response["currency"],
        },
        "protocol": "x402",
    })
    payment_required["http_status"] = 402
    payment_required["capability_id"] = procurement_capability["id"]
    payment_proof = {
        "schema": "chio.example.ioa-web3.x402-payment-proof.v1",
        "proof_id": f"x402-proof-{order_request['order_id']}",
        "order_id": order_request["order_id"],
        "quote_id": quote_response["quote_id"],
        "capability_id": settlement_capability["id"],
        "approval_decision_id": approval_decision["decision_id"],
        "amount": payment_required["amount"],
        "source_of_truth": "chio-budget-and-receipts",
        "receipt": {
            "id": f"rcpt-x402-payment-proof-{order_request['order_id']}",
            "decision": "allow",
            "digest": digest(payment_required),
        },
    }
    payment_satisfaction = market.submit_payment_proof(payment_proof)
    payment_satisfaction["capability_id"] = procurement_capability["id"]
    store.write_json("payments/x402-payment-required.json", payment_required)
    store.write_json("payments/chio-payment-proof.json", payment_proof)
    store.write_json("payments/x402-payment-satisfaction.json", payment_satisfaction)
    return payment_required, payment_proof, payment_satisfaction

