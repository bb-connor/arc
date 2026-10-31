# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cdaf59925a71448dee294bc7dd11837a988bac5f39ad022834183bd6833707a0
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AuditPool(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_epoch: int
    currency: str
    principal_id: str
    rail_destination: str


class ChallengeAdministrationPool(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_epoch: int
    currency: str
    principal_id: str
    rail_destination: str


class FailedDeliveryAuthority(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_id: str
    key: str
    key_epoch: int
    revocation_status_ref: str
    rotation_policy_ref: str
    valid_from: int
    valid_until: int


class Amount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ParticipationEpoch(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    epoch_index: int


class Event(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    participation_epoch: ParticipationEpoch


class FeeTerminal(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    event: str | Event
    fee_schedule_envelope_sha256: str
    instruction_sha256: str
    observation_sha256: str
    payer: str
    pool_principal_id: str
    rail_destination: str


class PurchaseAuthority(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authority_id: str
    key: str
    key_epoch: int
    revocation_status_ref: str
    rotation_policy_ref: str
    valid_from: int
    valid_until: int


class ChioFindingAdmissionV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    admission_id: str
    audit_pool: AuditPool
    backing_allocation_id: str
    backing_envelope_sha256: str
    capability_scope: str
    challenge_administration_pool: ChallengeAdministrationPool
    community_fund_destination: str
    expires_at: int
    failed_delivery_authority: FailedDeliveryAuthority
    fee_schedule_envelope_sha256: str
    fee_terminals: list[FeeTerminal]
    finding_artifact_sha256: str
    finding_id: str
    issued_at: int
    listing_envelope_sha256: str
    listing_id: str
    metadata_url: str
    payee_destination: str
    pricing_hint_envelope_sha256: str
    profile_envelope_sha256: str
    publisher_operator_id: str
    purchase_authority: PurchaseAuthority
    schema_: Literal["chio.finding.admission.v1"] = Field(..., alias="schema")
    seller_authorization_envelope_sha256: str
    server_id: str
    status_feed_operator_ref: str
    terms_envelope_sha256: str
    venue: str
    venue_id: str
    verifier_report_envelope_sha256: str
    verifier_report_id: str
