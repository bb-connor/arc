"""Two-hop subcontractor delegation and specialist review artifacts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .artifacts import ArtifactStore, Json, now_epoch
from .capabilities import grant, scope
from .identity import digest, workload_identity_document


@dataclass(frozen=True)
class SubcontractWorkflow:
    capability: Json
    passport: Json
    presentation: Json
    federation_admission: Json
    obligations: Json
    review: Json
    lineage_depth: int


def write_subcontract_workflow(
    *,
    store: ArtifactStore,
    issuer: Any,
    provider_identity: Any,
    subcontractor_identity: Any,
    provider_capability: Json,
    subcontractor_tool: Any | None,
    service_order: Json,
    validation_index: Json,
) -> SubcontractWorkflow:
    capability = issuer.delegate(
        parent=provider_capability,
        delegator=provider_identity,
        delegatee=subcontractor_identity,
        capability_scope=scope(grant("subcontractor-review", "issue_specialist_review", ["invoke"])),
        capability_id="cap-ioa-web3-cipherworks-specialist",
        ttl_seconds=900,
        attenuations=[
            {"kind": "specialist_review_only"},
            {"kind": "no_payment_authority"},
            {"kind": "inherits_mainnet_block"},
        ],
    )
    passport = {
        "schema": "chio.agent-passport.v1",
        "passportId": "passport-cipherworks-specialist-reviewer",
        "subject": "did:web:cipherworks.example:agent:specialist-reviewer",
        "holderPublicKey": subcontractor_identity.public_key,
        "organization": "CipherWorks Review Lab",
        "workloadIdentity": workload_identity_document("subcontractor-agent"),
        "trustTier": "verified_specialist",
        "issuedAt": now_epoch(),
        "validUntil": now_epoch() + 86_400,
        "claims": {
            "service": "specialist-evidence-leaf-review",
            "acceptedDelegator": "ProofWorks Provider",
            "claimedReputationScore": 0.88,
        },
    }
    passport["signature"] = subcontractor_identity.sign({"passport": digest(passport)})
    challenge = {
        "schema": "chio.passport.challenge.v1",
        "challengeId": "challenge-meridian-cipherworks-001",
        "verifier": "Meridian Federation Verifier",
        "holder": passport["subject"],
        "nonce": digest({"passportId": passport["passportId"], "issuedAt": passport["issuedAt"]}),
        "requestedClaims": ["holderPublicKey", "workloadIdentity", "trustTier"],
    }
    presentation = {
        "schema": "chio.passport.presentation.v1",
        "presentationId": "presentation-cipherworks-meridian-001",
        "challengeId": challenge["challengeId"],
        "holder": passport["subject"],
        "passportDigest": digest(passport),
        "claims": {
            "holderPublicKey": passport["holderPublicKey"],
            "workloadIdentity": passport["workloadIdentity"],
            "trustTier": passport["trustTier"],
        },
    }
    presentation["holderSignature"] = subcontractor_identity.sign(
        {"presentation": digest(presentation), "nonce": challenge["nonce"]}
    )
    federation_admission = {
        "schema": "chio.federation.open-admission-evaluation.v1",
        "evaluationId": "admission-cipherworks-specialist-001",
        "subject": passport["subject"],
        "verdict": "pass",
        "policyId": "proofworks-cipherworks-two-hop-specialist-review",
        "checks": [
            {"id": "passport-presentation", "outcome": "pass"},
            {"id": "runtime-attestation", "outcome": "pass"},
            {"id": "delegation-depth", "outcome": "pass"},
            {"id": "obligation-inheritance", "outcome": "pass"},
        ],
    }
    obligations = {
        "schema": "chio.example.ioa-web3.inherited-obligations.v1",
        "parentCapabilityId": provider_capability["id"],
        "subcontractorCapabilityId": capability["id"],
        "obligations": [
            "mainnet-disabled",
            "read-only-evidence-review",
            "no-payment-authority",
            "attach-receipt-to-provider-review",
        ],
        "status": "inherited",
    }
    review_request = {
        "schema": "chio.example.ioa-web3.subcontractor-review-request.v1",
        "order_id": service_order["order_id"],
        "capability_id": capability["id"],
        "validation_index_ref": "web3/validation-index.json",
        "requested_check": "base-sepolia-settlement-proof-leaf",
    }
    if subcontractor_tool:
        review = subcontractor_tool.call(
            "issue_specialist_review",
            {"service_order": service_order, "validation_index": validation_index, "capability": capability},
        )
    else:
        review = {
            "schema": "chio.example.ioa-web3.subcontractor-review-attestation.v1",
            "attestationId": "attestation-cipherworks-specialist-001",
            "orderId": service_order["order_id"],
            "verdict": "pass",
            "capabilityId": capability["id"],
            "signature": digest(review_request),
        }
    review["capabilityId"] = capability["id"]
    lineage_depth = len(capability.get("delegation_chain", []))
    store.write_json("capabilities/subcontractor-agent.json", capability)
    store.write_json("chio/capabilities/subcontractor-agent.json", capability)
    store.write_json("lineage/subcontractor-agent-chain.json", {
        "capability_id": capability["id"],
        "subject": capability["subject"],
        "issuer": capability["issuer"],
        "delegation_depth": lineage_depth,
        "delegation_chain": capability.get("delegation_chain", []),
    })
    store.write_json("subcontracting/delegated-capability.json", capability)
    store.write_json("subcontracting/inherited-obligations.json", obligations)
    store.write_json("subcontracting/review-request.json", review_request)
    store.write_json("subcontracting/review-attestation.json", review)
    store.write_json("identity/passports/cipherworks-subcontractor-passport.json", passport)
    store.write_json("identity/presentations/subcontractor-challenge.json", challenge)
    store.write_json("identity/presentations/subcontractor-presentation.json", presentation)
    store.write_json("federation/subcontractor-admission.json", federation_admission)
    store.write_json("chio/receipts/lineage-subcontractor-agent.json", {
        "stored": True,
        "capabilityId": capability["id"],
        "parentCapabilityId": provider_capability["id"],
        "lineageDepth": lineage_depth,
        "receipt": {
            "id": "rcpt-lineage-subcontractor-agent",
            "decision": "allow",
            "digest": digest(capability.get("delegation_chain", [])),
        },
    })
    return SubcontractWorkflow(
        capability=capability,
        passport=passport,
        presentation=presentation,
        federation_admission=federation_admission,
        obligations=obligations,
        review=review,
        lineage_depth=lineage_depth,
    )

