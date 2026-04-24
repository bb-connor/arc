"""Federation and reputation admission workflow artifacts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .artifacts import ArtifactStore, Json, now_epoch
from .identity import digest


@dataclass(frozen=True)
class ReputationWorkflow:
    report: Json
    comparison: Json
    verdict: Json


@dataclass(frozen=True)
class FederationWorkflow:
    policy: Json
    evidence_export: Json
    evidence_import: Json
    admission: Json
    federated_capability: Json


def write_reputation_workflow(
    *,
    store: ArtifactStore,
    provider_capability: Json,
    passport: Json,
    receipt_count: int,
    lineage_depth: int,
    minimum_score: float = 0.82,
) -> ReputationWorkflow:
    score = min(0.99, 0.72 + (receipt_count * 0.04) + (lineage_depth * 0.03))
    claimed = float(passport.get("claims", {}).get("claimedReputationScore", 0.0))
    report = {
        "schema": "chio.reputation.local-report.v1",
        "subject": passport["subject"],
        "capabilityId": provider_capability["id"],
        "receiptCount": receipt_count,
        "lineageDepth": lineage_depth,
        "budgetReconciled": True,
        "behavioralBaseline": "pass",
        "computedScore": round(score, 4),
    }
    comparison = {
        "schema": "chio.reputation.passport-comparison.v1",
        "subject": passport["subject"],
        "computedScore": report["computedScore"],
        "passportClaimedScore": claimed,
        "delta": round(report["computedScore"] - claimed, 4),
        "portable": True,
    }
    verdict = {
        "schema": "chio.example.ioa-web3.reputation-verdict.v1",
        "subject": passport["subject"],
        "verdict": "pass" if report["computedScore"] >= minimum_score else "fail",
        "minimumScore": minimum_score,
        "computedScore": report["computedScore"],
    }
    store.write_json("reputation/provider-local-report.json", report)
    store.write_json("reputation/provider-passport-comparison.json", comparison)
    store.write_json("reputation/provider-reputation-verdict.json", verdict)
    return ReputationWorkflow(report=report, comparison=comparison, verdict=verdict)


def write_federation_workflow(
    *,
    store: ArtifactStore,
    passport: Json,
    presentation: Json,
    reputation_verdict: Json,
    provider_capability: Json,
) -> FederationWorkflow:
    issued_at = now_epoch()
    policy = {
        "schema": "chio.federation.bilateral-evidence-policy.v1",
        "policyId": "atlas-proofworks-meridian-web3-admission",
        "issuer": "Meridian Federation Verifier",
        "subjects": ["Atlas Operator", "ProofWorks Provider"],
        "requiredEvidence": [
            "passport-presentation",
            "runtime-attestation",
            "capability-lineage",
            "budget-reconciliation",
            "behavioral-baseline",
            "local-reputation",
        ],
        "minimumReputationScore": reputation_verdict["minimumScore"],
        "issuedAt": issued_at,
    }
    policy["signature"] = digest(policy)
    evidence_export = {
        "schema": "chio.federation.evidence-export.v1",
        "exportId": "export-proofworks-web3-admission-001",
        "issuer": "ProofWorks Provider",
        "passportDigest": digest(passport),
        "presentationDigest": digest(presentation),
        "capabilityId": provider_capability["id"],
        "issuedAt": issued_at,
    }
    evidence_import = {
        "schema": "chio.federation.evidence-import.v1",
        "importId": "import-meridian-proofworks-web3-001",
        "sourceExportId": evidence_export["exportId"],
        "verifier": "Meridian Federation Verifier",
        "accepted": True,
        "policyId": policy["policyId"],
    }
    admission = {
        "schema": "chio.federation.open-admission-evaluation.v1",
        "evaluationId": "admission-proofworks-web3-001",
        "subject": passport["subject"],
        "verdict": "pass" if reputation_verdict["verdict"] == "pass" else "fail",
        "policyId": policy["policyId"],
        "checks": [
            {"id": "passport-presentation", "outcome": "pass"},
            {"id": "runtime-attestation", "outcome": "pass"},
            {"id": "reputation-threshold", "outcome": reputation_verdict["verdict"]},
            {"id": "mainnet-disabled", "outcome": "pass"},
        ],
    }
    federated_capability = {
        "schema": "chio.federated-provider-capability.v1",
        "id": "cap-ioa-web3-federated-proofworks-provider",
        "subject": passport["holderPublicKey"],
        "passportId": passport["passportId"],
        "presentationId": presentation["presentationId"],
        "admissionEvaluationId": admission["evaluationId"],
        "parentCapabilityId": provider_capability["id"],
        "scope": provider_capability["scope"],
        "issuedAt": issued_at,
        "expiresAt": provider_capability["expires_at"],
    }
    federated_capability["signature"] = digest(federated_capability)
    store.write_json("federation/bilateral-evidence-policy.json", policy)
    store.write_json("federation/evidence-export.json", evidence_export)
    store.write_json("federation/evidence-import.json", evidence_import)
    store.write_json("federation/open-admission-evaluation.json", admission)
    store.write_json("federation/federated-provider-capability.json", federated_capability)
    return FederationWorkflow(
        policy=policy,
        evidence_export=evidence_export,
        evidence_import=evidence_import,
        admission=admission,
        federated_capability=federated_capability,
    )

