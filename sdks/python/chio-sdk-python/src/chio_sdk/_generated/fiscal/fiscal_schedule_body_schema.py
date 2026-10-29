# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: f98e61fca1094fc6e2763340dae554e56c34e2d18e5720c6f3a7f9b589406726
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Ceiling(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class RequiredAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class BondRequirement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondClass: str
    collateralReferenceKind: str
    requiredAmount: RequiredAmount
    slashable: bool


class DisputeFee(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class MarketParticipationFee(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class PublicationFee(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    allowedActorKinds: list[str]
    allowedAdmissionClasses: list[str]
    allowedListingOperatorIds: list[str]
    namespace: str


class FeeSchedule(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondRequirements: list[BondRequirement]
    disputeFee: DisputeFee
    expiresAt: int
    feeScheduleId: str
    governingOperatorId: str
    issuedAt: int
    issuedBy: str
    marketParticipationFee: MarketParticipationFee
    namespace: str
    publicationFee: PublicationFee
    schema_: str = Field(..., alias="schema")
    scope: Scope


class Params(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    ceilings: list[Ceiling] | None = None
    feeSchedule: FeeSchedule | None = None
    kind: str


class ChioFiscalScheduleV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    charterDigest: str
    charterId: str
    domain: str
    issuedAt: int
    issuedBy: str
    params: Params
    scheduleId: str
    schema_: Literal["chio.fiscal.schedule.v1"] = Field(..., alias="schema")
    sequence: int
    supersedesScheduleId: str | None = None
    validFrom: int
    validUntil: int
