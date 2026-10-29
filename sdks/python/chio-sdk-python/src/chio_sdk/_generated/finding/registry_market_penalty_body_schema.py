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


class EvidenceRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    referenceId: str
    sha256: str | None = None


class PenaltyAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ChioRegistryMarketPenaltyV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    abuseClass: str
    action: str
    activationId: str | None = None
    bondClass: str
    caseId: str
    charterId: str
    evidenceRefs: list[EvidenceRef]
    expiresAt: int | None = None
    feeScheduleId: str
    governingOperatorId: str
    issuedBy: str
    listingId: str
    namespace: str
    openedAt: int
    penaltyAmount: PenaltyAmount
    penaltyId: str
    schema_: Literal["chio.registry.market-penalty.v1"] = Field(..., alias="schema")
    state: str
    subjectOperatorId: str | None = None
    supersedesPenaltyId: str | None = None
    updatedAt: int
