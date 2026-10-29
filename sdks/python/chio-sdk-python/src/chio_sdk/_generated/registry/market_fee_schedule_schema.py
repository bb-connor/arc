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
    allowedActorKinds: list[str] | None = None
    allowedAdmissionClasses: list[str] | None = None
    allowedListingOperatorIds: list[str] | None = None
    namespace: str
    policyReference: str | None = None


class ChioRegistryMarketFeeScheduleSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondRequirements: list[BondRequirement]
    disputeFee: DisputeFee
    expiresAt: int | None = None
    feeScheduleId: str
    governingOperatorId: str
    governingOperatorName: str | None = None
    issuedAt: int
    issuedBy: str
    marketParticipationFee: MarketParticipationFee
    namespace: str
    note: str | None = None
    publicationFee: PublicationFee
    schema_: Literal["chio.registry.market-fee-schedule.v1"] = Field(
        ..., alias="schema"
    )
    scope: Scope
