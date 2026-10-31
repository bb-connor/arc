# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 29f505f3691b4fbfea30cc6f60a7264757030799f7d4c23f1b591e15d011a565
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class MaxCoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ProviderPolicy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    boundCoverageSupported: bool
    claimsSupported: bool
    coverageClass: str
    currency: str
    displayName: str
    jurisdiction: str
    maxCoverageAmount: MaxCoverageAmount
    providerId: str
    providerRecordId: str
    quoteTtlSeconds: int
    requiredEvidence: list[str]


class RequestedCoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Certification(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    required: bool


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


class Summary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actionableReceipts: int
    activeDecisions: int
    currencies: list[str]
    failedSettlementReceipts: int
    matchingDecisions: int
    matchingReceipts: int
    mixedCurrencyBook: bool
    pendingSettlementReceipts: int
    returnedDecisions: int
    returnedReceipts: int
    supersededDecisions: int
    truncatedDecisions: bool
    truncatedReceipts: bool


class SupportBoundary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: str = Field(..., alias="schema")
    summary: Summary
    supportBoundary: SupportBoundary


class Exposure(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signerKey: str


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


class SupportBoundary111(BaseModel):
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


class FacilityReport(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disposition: str
    filters: Filters
    generatedAt: int
    prerequisites: Prerequisites
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard
    supportBoundary: SupportBoundary111
    terms: Terms | None = None


class Filters88(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    decisionLimit: int
    receiptLimit: int
    recentLossLimit: int


class LatestFacility(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    creditLimit: CreditLimit
    disposition: str
    expiresAt: int
    facilityId: str
    issuedAt: int
    lifecycleState: str
    signerKey: str


class Summary71(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    failedSettlementEvents: int
    matchingLossEvents: int
    provisionalLossEvents: int
    recoveredEvents: int
    returnedLossEvents: int


class RecentLossHistory(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    entries: list[dict[str, Any]]
    summary: Summary71


class RuntimeAssurance(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    governedReceipts: int
    highestTier: str
    latestEvidenceSha256: str
    latestSchema: str
    latestVerifier: str
    latestVerifierFamily: str
    observedVerifierFamilies: list[str]
    runtimeAssuranceReceipts: int
    stale: bool


class Filters89(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    decisionLimit: int
    receiptLimit: int


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


class Summary72(BaseModel):
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


class SupportBoundary112(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalAllocationSupported: bool
    crossCurrencyNettingSupported: bool
    facilityPolicySupported: bool
    subjectScopedOnly: bool


class Body196(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dimensions: list[dict[str, Any]]
    filters: Filters89
    generatedAt: int
    positions: list[Position]
    probation: Probation
    reputation: Reputation
    schema_: str = Field(..., alias="schema")
    summary: Summary72
    supportBoundary: SupportBoundary112


class Scorecard44(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body196
    signature: str
    signerKey: str


class SupportBoundary113(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    autonomousPricingSupported: bool
    complianceScoreReferenceSupported: bool
    externalCapitalReviewSupported: bool
    facilityPolicyAuthoritative: bool
    liabilityMarketSupported: bool
    signedExposureAuthoritative: bool
    signedScorecardAuthoritative: bool


class Body194(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certification: Certification
    exposure: Exposure
    facilityReport: FacilityReport
    filters: Filters88
    generatedAt: int
    latestFacility: LatestFacility | None = None
    recentLossHistory: RecentLossHistory
    runtimeAssurance: RuntimeAssurance | None = None
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard44
    subjectKey: str
    supportBoundary: SupportBoundary113


class RiskPackage(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body194
    signature: str
    signerKey: str


class Body193(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    issuedAt: int
    notes: str | None = None
    providerPolicy: ProviderPolicy
    quoteRequestId: str
    requestedCoverageAmount: RequestedCoverageAmount
    requestedEffectiveFrom: int
    requestedEffectiveUntil: int
    riskPackage: RiskPackage
    schema_: str = Field(..., alias="schema")


class QuoteRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body193
    signature: str
    signerKey: str


class QuotedCoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class QuotedDeductibleAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class QuotedPremiumAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class QuotedTerms(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    expiresAt: int
    quotedCoverageAmount: QuotedCoverageAmount
    quotedDeductibleAmount: QuotedDeductibleAmount | None = None
    quotedPremiumAmount: QuotedPremiumAmount


class ChioMarketQuoteResponseSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disposition: str
    issuedAt: int
    providerQuoteRef: str
    quoteRequest: QuoteRequest
    quoteResponseId: str
    quotedTerms: QuotedTerms
    schema_: Literal["chio.market.quote-response.v1"] = Field(..., alias="schema")
    supersedesQuoteResponseId: str | None = None
