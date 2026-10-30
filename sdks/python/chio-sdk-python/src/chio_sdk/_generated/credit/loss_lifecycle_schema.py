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


class Finding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: str
    description: str


class Amount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Query(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount | None = None
    bondId: str
    eventKind: str


class CurrentDelinquentAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class CurrentRecoveredAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class CurrentReleasedReserveAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class EventAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class OutstandingDelinquentAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ReleaseableReserveAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Summary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    bondId: str
    capabilityId: str | None = None
    currentBondLifecycleState: str
    currentDelinquentAmount: CurrentDelinquentAmount | None = None
    currentRecoveredAmount: CurrentRecoveredAmount | None = None
    currentReleasedReserveAmount: CurrentReleasedReserveAmount | None = None
    eventAmount: EventAmount
    facilityId: str | None = None
    outstandingDelinquentAmount: OutstandingDelinquentAmount | None = None
    projectedBondLifecycleState: str
    releaseableReserveAmount: ReleaseableReserveAmount | None = None
    toolName: str | None = None
    toolServer: str | None = None


class SupportBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    appealWindowSupported: bool
    automaticCapitalExecutionSupported: bool
    bondLifecycleProjectionAuthoritative: bool
    externalClaimAdjudicationSupported: bool
    immutableLifecycleAuthoritative: bool
    reserveControlExecutionSupported: bool


class Report(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    findings: list[Finding] | None = None
    generatedAt: int
    query: Query
    schema_: str = Field(..., alias="schema")
    summary: Summary
    supportBoundary: SupportBoundary


class ChioCreditLossLifecycleSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondId: str
    description: str | None = None
    eventId: str
    eventKind: str
    issuedAt: int
    projectedBondLifecycleState: str
    report: Report
    schema_: Literal["chio.credit.loss-lifecycle.v1"] = Field(..., alias="schema")
