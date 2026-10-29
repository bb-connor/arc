# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: cff572cd647726251b5cdb39013d235e07916c80b9a46e5bc035b374e0fd7041
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Disposition(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str


class SettlementState(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    evidence_digest: str | None = None
    kind: str
    settlement_id: str | None = None


class ChioObligationStatusProofV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    authorityId: str
    authorityKeyEpoch: int
    currentCreditorId: str
    currentSettlementDestinationRef: str
    debtorId: str
    disposition: Disposition
    dispositionDigest: str
    dispositionLifecycleFence: int
    dispositionVersion: int
    dueAtUnixMs: int
    expiresAtUnixMs: int
    issuedAtUnixMs: int
    obligationAtomDigest: str
    obligationId: str
    originalCreditorId: str
    proofId: str
    resourceFence: int
    schema_: Literal["chio.obligation.status-proof.v1"] = Field(..., alias="schema")
    settlementLifecycleDigest: str
    settlementLifecycleFence: int
    settlementLifecycleVersion: int
    settlementState: SettlementState
    snapshotVersion: int
