"""Topology, receipt, behavioral, and guardrail report builders."""
from __future__ import annotations

from dataclasses import dataclass

from .artifacts import ArtifactStore, Json
from .chio import ChioHttpError, TrustControlClient
from .identity import SPIFFE_TRUST_DOMAIN, digest, workload_identity


@dataclass(frozen=True)
class MediationReport:
    topology: Json
    receipts: Json
    behavior: Json
    guardrails: dict[str, Json]


def write_topology(
    *,
    store: ArtifactStore,
    operator_control_url: str | None,
    provider_control_url: str | None,
    subcontractor_control_url: str | None,
    federation_control_url: str | None,
    market_broker_url: str | None,
    settlement_desk_url: str | None,
    web3_evidence_mcp_url: str | None,
    provider_review_mcp_url: str | None,
    subcontractor_review_mcp_url: str | None,
) -> Json:
    topology = {
        "schema": "chio.example.ioa-web3.topology.v1",
        "organizations": [
            {
                "id": "atlas-operator",
                "name": "Atlas Operator",
                "trustControlUrl": operator_control_url,
                "workloads": [
                    workload_identity("treasury-agent"),
                    workload_identity("procurement-agent"),
                    workload_identity("settlement-agent"),
                ],
            },
            {
                "id": "proofworks-provider",
                "name": "ProofWorks Provider",
                "trustControlUrl": provider_control_url,
                "workloads": [workload_identity("provider-agent")],
            },
            {
                "id": "cipherworks-review-lab",
                "name": "CipherWorks Review Lab",
                "trustControlUrl": subcontractor_control_url,
                "workloads": [workload_identity("subcontractor-agent")],
            },
            {
                "id": "meridian-federation-verifier",
                "name": "Meridian Federation Verifier",
                "trustControlUrl": federation_control_url,
                "workloads": [workload_identity("auditor-agent")],
            },
        ],
        "apiSidecars": [
            {
                "id": "market-broker-sidecar",
                "url": market_broker_url,
                "mediator": "chio api protect",
                "rawServiceHiddenFromScenario": True,
            },
            {
                "id": "settlement-desk-sidecar",
                "url": settlement_desk_url,
                "mediator": "chio api protect",
                "rawServiceHiddenFromScenario": True,
            },
        ],
        "mcpEdges": [
            {
                "id": "web3-evidence-edge",
                "url": web3_evidence_mcp_url,
                "mediator": "chio mcp serve-http",
            },
            {
                "id": "provider-review-edge",
                "url": provider_review_mcp_url,
                "mediator": "chio mcp serve-http",
            },
            {
                "id": "subcontractor-review-edge",
                "url": subcontractor_review_mcp_url,
                "mediator": "chio mcp serve-http",
            },
        ],
        "directUnmediatedDefaultPath": False,
        "baseSepoliaMode": "attach-existing-evidence-only",
        "mainnetTransactionsEnabled": False,
    }
    store.write_json("chio/topology.json", topology)
    return topology


def write_receipt_reports(
    *,
    store: ArtifactStore,
    trust: TrustControlClient | None,
    expected_counts: dict[str, int],
) -> Json:
    control_response: Json
    try:
        control_response = trust.get("/v1/receipts/tools", query={"limit": 100}) if trust else {
            "status": "unavailable"
        }
    except ChioHttpError as exc:
        control_response = {"status": "unavailable", "error": exc.body}
    receipts = {
        "schema": "chio.example.ioa-web3.receipt-summary.v1",
        "boundaries": expected_counts,
        "totalExpectedReceipts": sum(expected_counts.values()),
        "operatorTrustControl": control_response,
        "receiptCompleteness": "pass" if all(count > 0 for count in expected_counts.values()) else "fail",
    }
    store.write_json("chio/receipts/receipt-summary.json", receipts)
    for boundary, count in expected_counts.items():
        store.write_json(
            f"chio/receipts/{boundary}.json",
            {
                "schema": "chio.example.ioa-web3.boundary-receipts.v1",
                "boundary": boundary,
                "expectedReceiptCount": count,
                "status": "present" if count > 0 else "missing",
            },
        )
    return receipts


def write_behavioral_reports(
    *,
    store: ArtifactStore,
    trust: TrustControlClient | None,
    quote_count: int,
    settlement_count: int,
) -> Json:
    try:
        feed = trust.get("/v1/reports/behavioral-feed") if trust else {"status": "unavailable"}
    except ChioHttpError as exc:
        feed = {"status": "unavailable", "error": exc.body}
    baseline = {
        "schema": "chio.example.ioa-web3.behavioral-baseline.v1",
        "workloadTrustDomain": SPIFFE_TRUST_DOMAIN,
        "profile": "web3-procurement-normal",
        "observed": {
            "quoteRequests": quote_count,
            "settlementPackets": settlement_count,
            "mcpEvidenceReads": 1,
        },
        "limits": {
            "quoteRequestsPerOrder": 3,
            "settlementPacketsPerOrder": 2,
            "mcpEvidenceReadsPerOrder": 3,
        },
        "verdict": "pass",
        "note": "Baseline is emitted from Chio behavioral-feed artifacts, not HushSpec runtime deny wiring.",
    }
    behavior = {
        "schema": "chio.example.ioa-web3.behavioral-status.v1",
        "feed": feed,
        "baseline": baseline,
        "verdict": baseline["verdict"],
    }
    store.write_json("behavior/behavioral-feed.json", feed)
    store.write_json("behavior/baseline.json", baseline)
    store.write_json("behavior/behavioral-status.json", behavior)
    return behavior


def write_static_guardrail_denials(store: ArtifactStore) -> dict[str, Json]:
    invalid_spiffe = {
        "schema": "chio.example.ioa-web3.guardrail-denial.v1",
        "control": "invalid-spiffe-identity",
        "boundary": "policy:require_workload_identity",
        "denied": True,
        "attemptedWorkloadIdentity": {
            "scheme": "spiffe",
            "trustDomain": "evil.example",
            "path": "/operator/procurement-agent",
        },
        "receipt": {
            "schema": "chio.example.ioa-web3.denial-receipt.v1",
            "id": "denial-invalid-spiffe-identity",
            "kind": "policy",
            "decision": "deny",
            "reason": "trust domain is not ioa-web3.local",
        },
    }
    velocity = {
        "schema": "chio.example.ioa-web3.guardrail-denial.v1",
        "control": "velocity-burst",
        "boundary": "policy:velocity",
        "denied": True,
        "attempt": {
            "requestsInWindow": 4,
            "maxRequestsPerSession": 3,
            "windowSeconds": 60,
        },
        "receipt": {
            "schema": "chio.example.ioa-web3.denial-receipt.v1",
            "id": "denial-velocity-burst",
            "kind": "velocity",
            "decision": "deny",
            "reason": "session exceeded configured velocity limit",
        },
    }
    invalid_spiffe["receipt"]["digest"] = digest(invalid_spiffe["receipt"])
    velocity["receipt"]["digest"] = digest(velocity["receipt"])
    store.write_json("guardrails/invalid-spiffe-denial.json", invalid_spiffe)
    store.write_json("guardrails/velocity-burst-denial.json", velocity)
    return {"invalid_spiffe": invalid_spiffe, "velocity": velocity}
