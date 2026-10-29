# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 7c51d7910f0345879134e0bf5bbb042abd7b8dbfdcd23700753b77f6814a0f36
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AffectedDelivery(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpoint_ref: str
    checkpoint_sha256: str
    receipt_id: str
    receipt_sha256: str


class Amount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class DisputeFeeTerminal(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    beneficiary_pool_principal_id: str
    event: str
    fee_schedule_envelope_sha256: str
    payer: str
    rail_destination: str


class DisputeLockRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    class_: str = Field(..., alias="class")
    expiry: int
    fee_schedule_envelope_sha256: str
    lock_id: str


class FailedDelivery(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    failed_delivery_envelope_sha256: str
    failed_delivery_id: str


class Standing(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    failed_delivery: FailedDelivery


class BuyerSubmission(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    challenger: str
    dispute_fee_terminal: DisputeFeeTerminal
    dispute_lock_ref: DisputeLockRef
    standing: Standing


class VenueAudit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    audit_epoch_envelope_sha256: str
    authorization_digest: str
    selection_digest: str


class Authorization(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    buyer_submission: BuyerSubmission | None = None
    venue_audit: VenueAudit | None = None


class DenyCheckpointRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpoint_ref: str
    checkpoint_sha256: str


class DenyReceiptRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    receipt_id: str
    receipt_sha256: str


class DigestMismatch(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    deny_checkpoint_ref: DenyCheckpointRef
    deny_receipt_ref: DenyReceiptRef
    failed_delivery_envelope_sha256: str


class ChallengedCheckpointRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpoint_ref: str
    checkpoint_sha256: str


class ChallengedEvidenceReceiptRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    receipt_id: str
    receipt_sha256: str


class EvidenceInvalid(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    challenged_checkpoint_ref: ChallengedCheckpointRef
    challenged_evidence_receipt_refs: list[ChallengedEvidenceReceiptRef]
    purchase_record_envelope_sha256: str


class Evidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    digest_mismatch: DigestMismatch | None = None
    evidence_invalid: EvidenceInvalid | None = None


class ChioFindingChallengeV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    affected_deliveries: list[AffectedDelivery]
    authorization: Authorization
    backing_envelope_sha256: str
    challenge_id: str
    evidence: Evidence
    filed_at: int
    finding_artifact_sha256: str
    finding_id: str
    listing_id: str
    profile_envelope_sha256: str
    schema_: Literal["chio.finding.challenge.v1"] = Field(..., alias="schema")
    terms_envelope_sha256: str
    venue_admission_envelope_sha256: str
