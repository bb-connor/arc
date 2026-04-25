"""Identity, passport, and runtime-attestation artifacts for the web3 topology."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .artifacts import ArtifactStore, Json, now_epoch

SPIFFE_TRUST_DOMAIN = "ioa-web3.local"

WORKLOAD_PATHS = {
    "treasury-agent": "/operator/treasury-agent",
    "procurement-agent": "/operator/procurement-agent",
    "provider-agent": "/provider/proofworks-agent-auditor",
    "subcontractor-agent": "/subcontractor/cipherworks-specialist-reviewer",
    "settlement-agent": "/operator/settlement-agent",
    "auditor-agent": "/federation/meridian-verifier",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def workload_identity(actor: str) -> str:
    return f"spiffe://{SPIFFE_TRUST_DOMAIN}{WORKLOAD_PATHS[actor]}"


def workload_identity_document(actor: str) -> Json:
    path = WORKLOAD_PATHS[actor]
    return {
        "scheme": "spiffe",
        "credentialKind": "uri",
        "uri": f"spiffe://{SPIFFE_TRUST_DOMAIN}{path}",
        "trustDomain": SPIFFE_TRUST_DOMAIN,
        "path": path,
    }


def runtime_attestation(actor: str) -> Json:
    issued_at = now_epoch()
    workload = workload_identity_document(actor)
    evidence = {
        "actor": actor,
        "runtime": "local-dev-workload",
        "workloadIdentity": workload,
        "assuranceTier": "attested",
    }
    return {
        "schema": "chio.runtime-attestation.enterprise-verifier.json.v1",
        "verifier": "https://attest.ioa-web3.local",
        "tier": "attested",
        "issued_at": issued_at,
        "expires_at": issued_at + 3600,
        "evidence_sha256": digest(evidence),
        "runtime_identity": workload["uri"],
        "workload_identity": workload,
        "claims": {
            "example": "internet-of-agents-web3-network",
            "organization": organization_for_actor(actor),
            "localRealism": True,
            "mainnetBlocked": True,
        },
    }


def organization_for_actor(actor: str) -> str:
    if actor == "provider-agent":
        return "ProofWorks Provider"
    if actor == "subcontractor-agent":
        return "CipherWorks Review Lab"
    if actor == "auditor-agent":
        return "Meridian Federation Verifier"
    return "Atlas Operator"


@dataclass(frozen=True)
class PassportWorkflow:
    passport: Json
    passport_verdict: Json
    challenge: Json
    presentation: Json
    presentation_verdict: Json


def write_runtime_appraisals(store: ArtifactStore, actors: list[str]) -> dict[str, Json]:
    appraisals: dict[str, Json] = {}
    for actor in actors:
        attestation = runtime_attestation(actor)
        appraisal = {
            "schema": "chio.example.ioa-web3.runtime-appraisal.v1",
            "actor": actor,
            "organization": organization_for_actor(actor),
            "attestation": attestation,
            "verdict": "pass",
            "requirements": {
                "scheme": "spiffe",
                "trust_domain": SPIFFE_TRUST_DOMAIN,
                "minimum_tier": "attested",
            },
        }
        appraisals[actor] = appraisal
        store.write_json(f"identity/runtime-appraisals/{actor}.json", appraisal)
    return appraisals


def write_provider_passport_workflow(
    *,
    store: ArtifactStore,
    provider_identity: Any,
    provider_capability_id: str,
    claimed_reputation_score: float,
) -> PassportWorkflow:
    issued_at = now_epoch()
    passport = {
        "schema": "chio.agent-passport.v1",
        "passportId": "passport-proofworks-provider-web3-auditor",
        "subject": "did:web:proofworks.example:agent:web3-auditor",
        "holderPublicKey": provider_identity.public_key,
        "organization": "ProofWorks Provider",
        "workloadIdentity": workload_identity_document("provider-agent"),
        "trustTier": "verified_provider",
        "issuedAt": issued_at,
        "validUntil": issued_at + 86_400,
        "credentials": [
            {
                "type": "RuntimeAttestation",
                "ref": "identity/runtime-appraisals/provider-agent.json",
            },
            {
                "type": "CapabilityLineage",
                "capabilityId": provider_capability_id,
            },
        ],
        "claims": {
            "service": "web3-settlement-proof-review",
            "claimedReputationScore": claimed_reputation_score,
            "acceptedCurrency": "USDC",
            "settlementNetwork": "base-sepolia",
        },
    }
    passport["signature"] = provider_identity.sign({"passport": digest(passport)})
    passport_verdict = {
        "schema": "chio.example.ioa-web3.passport-verdict.v1",
        "passportId": passport["passportId"],
        "verdict": "pass",
        "checks": [
            {"id": "schema", "outcome": "pass"},
            {"id": "validity-window", "outcome": "pass"},
            {"id": "spiffe-workload", "outcome": "pass"},
            {"id": "runtime-tier", "outcome": "pass"},
        ],
    }
    challenge = {
        "schema": "chio.passport.challenge.v1",
        "challengeId": "challenge-meridian-proofworks-001",
        "verifier": "Meridian Federation Verifier",
        "holder": passport["subject"],
        "nonce": digest({"passportId": passport["passportId"], "issuedAt": issued_at}),
        "requestedClaims": [
            "holderPublicKey",
            "workloadIdentity",
            "trustTier",
            "claims.claimedReputationScore",
        ],
    }
    presentation = {
        "schema": "chio.passport.presentation.v1",
        "presentationId": "presentation-proofworks-meridian-001",
        "challengeId": challenge["challengeId"],
        "holder": passport["subject"],
        "passportDigest": digest(passport),
        "claims": {
            "holderPublicKey": passport["holderPublicKey"],
            "workloadIdentity": passport["workloadIdentity"],
            "trustTier": passport["trustTier"],
            "claimedReputationScore": claimed_reputation_score,
        },
    }
    presentation["holderSignature"] = provider_identity.sign(
        {"presentation": digest(presentation), "nonce": challenge["nonce"]}
    )
    presentation_verdict = {
        "schema": "chio.example.ioa-web3.presentation-verdict.v1",
        "presentationId": presentation["presentationId"],
        "challengeId": challenge["challengeId"],
        "verdict": "pass",
        "checks": [
            {"id": "challenge-bound", "outcome": "pass"},
            {"id": "holder-signature-present", "outcome": "pass"},
            {"id": "passport-digest-bound", "outcome": "pass"},
        ],
    }
    store.write_json("identity/passports/proofworks-provider-passport.json", passport)
    store.write_json("identity/passports/proofworks-provider-passport-verdict.json", passport_verdict)
    store.write_json("identity/presentations/provider-challenge.json", challenge)
    store.write_json("identity/presentations/provider-presentation.json", presentation)
    store.write_json("identity/presentations/provider-presentation-verdict.json", presentation_verdict)
    return PassportWorkflow(
        passport=passport,
        passport_verdict=passport_verdict,
        challenge=challenge,
        presentation=presentation,
        presentation_verdict=presentation_verdict,
    )


def write_runtime_degradation_workflow(
    *,
    store: ArtifactStore,
    provider_identity: Any,
) -> Json:
    expired = runtime_attestation("provider-agent")
    expired["issued_at"] = expired["issued_at"] - 7200
    expired["expires_at"] = expired["issued_at"] - 1
    expired["workload_identity"] = {
        "scheme": "spiffe",
        "credentialKind": "uri",
        "uri": "spiffe://evil.example/provider/proofworks-agent-auditor",
        "trustDomain": "evil.example",
        "path": "/provider/proofworks-agent-auditor",
    }
    denial = {
        "schema": "chio.example.ioa-web3.runtime-degradation-denial.v1",
        "provider": "ProofWorks Provider",
        "subject": provider_identity.public_key,
        "attempt": "issue capability with expired attestation and bad SPIFFE trust domain",
        "denied": True,
        "receipt": {
            "id": "denial-runtime-degradation-proofworks",
            "decision": "deny",
            "reason": "runtime attestation expired and workload identity trust domain mismatch",
        },
        "attestation": expired,
    }
    quarantine = {
        "schema": "chio.example.ioa-web3.provider-quarantine.v1",
        "provider": "ProofWorks Provider",
        "status": "quarantined",
        "reason": denial["receipt"]["reason"],
        "denialReceiptId": denial["receipt"]["id"],
    }
    reattestation = runtime_attestation("provider-agent")
    readmission = {
        "schema": "chio.example.ioa-web3.provider-readmission.v1",
        "provider": "ProofWorks Provider",
        "status": "readmitted",
        "reattestationDigest": digest(reattestation),
        "checks": [
            {"id": "runtime-tier", "outcome": "pass"},
            {"id": "spiffe-trust-domain", "outcome": "pass"},
            {"id": "capability-issuance", "outcome": "pass"},
        ],
    }
    summary = {
        "schema": "chio.example.ioa-web3.runtime-degradation-summary.v1",
        "status": "quarantined_then_reattested",
        "denial": "identity/runtime-degradation/capability-denial.json",
        "quarantine": "identity/runtime-degradation/provider-quarantine.json",
        "reattestation": "identity/runtime-degradation/reattestation.json",
        "readmission": "identity/runtime-degradation/readmission.json",
    }
    store.write_json("identity/runtime-degradation/capability-denial.json", denial)
    store.write_json("identity/runtime-degradation/provider-quarantine.json", quarantine)
    store.write_json("identity/runtime-degradation/reattestation.json", reattestation)
    store.write_json("identity/runtime-degradation/readmission.json", readmission)
    store.write_json("identity/runtime-degradation/summary.json", summary)
    return summary
