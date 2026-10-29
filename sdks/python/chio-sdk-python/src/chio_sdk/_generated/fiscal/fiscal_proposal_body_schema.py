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


class Body(BaseModel):
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
    schema_: str = Field(..., alias="schema")
    sequence: int
    supersedesScheduleId: str | None = None
    validFrom: int
    validUntil: int


class Candidate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signerKey: str


class SignerSetItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    keyId: str
    publicKey: str


class Body166(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approvalThreshold: int
    approvalTtlSeconds: int
    charterId: str
    expiresAt: int
    governedDomains: list[str]
    governingOperatorId: str
    issuedAt: int
    issuedBy: str
    predecessorCharterDigest: str
    proposalTtlSeconds: int
    schema_: str = Field(..., alias="schema")
    sequence: int
    signerSet: list[SignerSetItem]
    timelockSeconds: int


class Successor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body166
    signature: str
    signerKey: str


class Target(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    candidate: Candidate | None = None
    kind: str
    successor: Successor | None = None


class ChioFiscalProposalV1SignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    proposalId: str
    proposedAt: int
    proposedBy: str
    rationaleDigest: str
    schema_: Literal["chio.fiscal.proposal.v1"] = Field(..., alias="schema")
    target: Target
