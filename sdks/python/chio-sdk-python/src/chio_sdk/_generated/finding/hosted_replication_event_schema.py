# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b55a701e44e8cab56a79619656a773cbb3b9fd63c65594e997f7efc988bc178c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Descriptor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    context_sha256: str
    outcome_class: str
    topic: str


class EvidenceCost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Payload(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bond_ref: str | None = None
    descriptor: Descriptor | None = None
    evidence_checkpoint_ref: str | None = None
    evidence_class: str | None = None
    evidence_cost: EvidenceCost | None = None
    evidence_receipt_ids: list[str] | None = None
    expires_at: int | None = None
    finding_id: str | None = None
    guarantee_class: str | None = None
    invalid: bool | None = None
    issued_at: int | None = None
    issuer: str | None = None
    payload_media_type: str | None = None
    payload_sha256: str | None = None
    schema_: str | None = Field(None, alias="schema")
    signature: str | None = None
    status_feed_ref: str | None = None


class ChioFindingHostedReplicationEventSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    aggregateId: str
    artifactSignerKey: str
    authorityEpoch: int
    committedAt: int
    eventId: str
    eventKind: str
    expectedEventSha256: None
    expectedRevision: int
    payload: Payload
    schema_: Literal["chio.finding.hosted-replication-event.v1"] = Field(
        ..., alias="schema"
    )
    sequence: int
    sourceAuthority: str
    tenantId: str
