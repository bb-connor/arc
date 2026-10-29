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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Filters(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    decisionLimit: int
    receiptLimit: int


class Position(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activeQuotedPremiumUnits: int
    currency: str
    failedUnits: int
    governedMaxExposureUnits: int
    pendingUnits: int
    provisionalLossUnits: int
    quotedPremiumUnits: int
    recoveredUnits: int
    reservedUnits: int
    settledUnits: int


class Probation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    probationary: bool
    receiptCount: int
    spanDays: int
    targetReceiptCount: int
    targetSpanDays: int


class Reputation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    acceptedImportedSignalCount: int
    effectiveScore: float
    importedSignalCount: int
    probationary: bool


class Summary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    anomalyCount: int
    band: str
    confidence: str
    currencies: list[str]
    matchingDecisions: int
    matchingReceipts: int
    mixedCurrencyBook: bool
    overallScore: float
    probationary: bool
    returnedDecisions: int
    returnedReceipts: int


class SupportBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalAllocationSupported: bool
    crossCurrencyNettingSupported: bool
    facilityPolicySupported: bool
    subjectScopedOnly: bool


class ChioCreditScorecardSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dimensions: list[dict[str, Any]]
    filters: Filters
    generatedAt: int
    positions: list[Position]
    probation: Probation
    reputation: Reputation
    schema_: Literal["chio.credit.scorecard.v1"] = Field(..., alias="schema")
    summary: Summary
    supportBoundary: SupportBoundary
