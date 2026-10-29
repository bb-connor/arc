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


class Filters(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    capabilityId: str | None = None
    decisionLimit: int | None = None
    receiptLimit: int | None = None
    toolName: str | None = None
    toolServer: str | None = None


class EvidenceRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: str
    locator: str
    referenceId: str


class Finding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: str
    description: str
    evidenceRefs: list[EvidenceRef]


class Prerequisites(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certificationMet: bool
    certificationRequired: bool
    manualReviewRequired: bool
    minimumRuntimeAssuranceTier: str
    runtimeAssuranceMet: bool


class Scorecard(BaseModel):
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
    bondExecutionSupported: bool
    crossCurrencyAllocationSupported: bool
    providerNeutralPolicy: bool


class CreditLimit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Terms(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalSource: str
    concentrationCapBps: int
    creditLimit: CreditLimit
    reserveRatioBps: int
    ttlSeconds: int
    utilizationCeilingBps: int


class Report(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disposition: str
    filters: Filters
    findings: list[Finding] | None = None
    generatedAt: int
    prerequisites: Prerequisites
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard
    supportBoundary: SupportBoundary
    terms: Terms | None = None


class ChioCreditFacilitySignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expiresAt: int
    facilityId: str
    issuedAt: int
    lifecycleState: str
    report: Report
    schema_: Literal["chio.credit.facility.v1"] = Field(..., alias="schema")
    supersedesFacilityId: str | None = None
