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


class Exposure(BaseModel):
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


class Filters(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    capabilityId: str | None = None
    decisionLimit: int
    receiptLimit: int
    toolName: str | None = None
    toolServer: str | None = None


class Prerequisites(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    activeFacilityMet: bool
    activeFacilityRequired: bool
    certificationMet: bool
    certificationRequired: bool
    currencyCoherent: bool
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
    autonomyGatingSupported: bool
    externalEscrowExecutionSupported: bool
    reserveAccountingAuthoritative: bool


class CollateralAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class CreditLimit(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class OutstandingExposureAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ReserveRequirementAmount(BaseModel):
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
    collateralAmount: CollateralAmount
    coverageRatioBps: int
    creditLimit: CreditLimit
    facilityId: str
    outstandingExposureAmount: OutstandingExposureAmount
    reserveRatioBps: int
    reserveRequirementAmount: ReserveRequirementAmount


class Report(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disposition: str
    exposure: Exposure
    filters: Filters
    generatedAt: int
    latestFacilityId: str | None = None
    prerequisites: Prerequisites
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard
    supportBoundary: SupportBoundary
    terms: Terms | None = None


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondId: str
    expiresAt: int
    issuedAt: int
    lifecycleState: str
    report: Report
    schema_: str = Field(..., alias="schema")


class Bond(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: str
    signerKey: str


class CoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


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


class Filters29(BaseModel):
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


class SupportBoundary40(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class Body65(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters29
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: str = Field(..., alias="schema")
    summary: Summary
    supportBoundary: SupportBoundary40


class Exposure11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body65
    signature: str
    signerKey: str


class Prerequisites10(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certificationMet: bool
    certificationRequired: bool
    manualReviewRequired: bool
    minimumRuntimeAssuranceTier: str
    runtimeAssuranceMet: bool


class SupportBoundary41(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondExecutionSupported: bool
    crossCurrencyAllocationSupported: bool
    providerNeutralPolicy: bool


class Terms10(BaseModel):
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
    filters: Filters29
    generatedAt: int
    prerequisites: Prerequisites10
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard
    supportBoundary: SupportBoundary41
    terms: Terms10 | None = None


class Filters31(BaseModel):
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


class Summary23(BaseModel):
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
    summary: Summary23


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


class Filters32(BaseModel):
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


class Summary24(BaseModel):
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


class SupportBoundary42(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalAllocationSupported: bool
    crossCurrencyNettingSupported: bool
    facilityPolicySupported: bool
    subjectScopedOnly: bool


class Body66(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dimensions: list[dict[str, Any]]
    filters: Filters32
    generatedAt: int
    positions: list[Position]
    probation: Probation
    reputation: Reputation
    schema_: str = Field(..., alias="schema")
    summary: Summary24
    supportBoundary: SupportBoundary42


class Scorecard16(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body66
    signature: str
    signerKey: str


class SupportBoundary43(BaseModel):
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


class Body64(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certification: Certification
    exposure: Exposure11
    facilityReport: FacilityReport
    filters: Filters31
    generatedAt: int
    latestFacility: LatestFacility | None = None
    recentLossHistory: RecentLossHistory
    runtimeAssurance: RuntimeAssurance | None = None
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard16
    subjectKey: str
    supportBoundary: SupportBoundary43


class RiskPackage(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body64
    signature: str
    signerKey: str


class Body63(BaseModel):
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
    body: Body63
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


class Body62(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disposition: str
    issuedAt: int
    providerQuoteRef: str
    quoteRequest: QuoteRequest
    quoteResponseId: str
    quotedTerms: QuotedTerms
    schema_: str = Field(..., alias="schema")


class QuoteResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body62
    signature: str
    signerKey: str


class SelectedCoverageAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class SelectedPremiumAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body61(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    effectiveFrom: int
    effectiveUntil: int
    issuedAt: int
    notes: str | None = None
    placementId: str
    placementRef: str | None = None
    quoteResponse: QuoteResponse
    schema_: str = Field(..., alias="schema")
    selectedCoverageAmount: SelectedCoverageAmount
    selectedPremiumAmount: SelectedPremiumAmount


class Placement(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body61
    signature: str
    signerKey: str


class PremiumAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body60(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    boundAt: int
    boundCoverageId: str
    carrierReference: str | None = None
    coverageAmount: CoverageAmount
    effectiveFrom: int
    effectiveUntil: int
    issuedAt: int
    placement: Placement
    policyNumber: str
    premiumAmount: PremiumAmount
    schema_: str = Field(..., alias="schema")


class BoundCoverage(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body60
    signature: str
    signerKey: str


class ClaimAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Summary25(BaseModel):
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


class SupportBoundary44(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class Body67(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters32
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: str = Field(..., alias="schema")
    summary: Summary25
    supportBoundary: SupportBoundary44


class Exposure12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body67
    signature: str
    signerKey: str


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
    amount: Amount
    bondId: str
    eventKind: str


class CurrentDelinquentAmount(BaseModel):
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


class Summary26(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    bondId: str
    capabilityId: str | None = None
    currentBondLifecycleState: str
    currentDelinquentAmount: CurrentDelinquentAmount
    eventAmount: EventAmount
    facilityId: str | None = None
    outstandingDelinquentAmount: OutstandingDelinquentAmount
    projectedBondLifecycleState: str
    releaseableReserveAmount: ReleaseableReserveAmount | None = None
    toolName: str | None = None
    toolServer: str | None = None


class SupportBoundary45(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    appealWindowSupported: bool
    automaticCapitalExecutionSupported: bool
    bondLifecycleProjectionAuthoritative: bool
    externalClaimAdjudicationSupported: bool
    immutableLifecycleAuthoritative: bool
    reserveControlExecutionSupported: bool


class Report8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    generatedAt: int
    query: Query
    schema_: str = Field(..., alias="schema")
    summary: Summary26
    supportBoundary: SupportBoundary45


class Body68(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondId: str
    description: str
    eventId: str
    eventKind: str
    issuedAt: int
    projectedBondLifecycleState: str
    report: Report8
    schema_: str = Field(..., alias="schema")


class LossEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body68
    signature: str
    signerKey: str


class ChioMarketClaimPackageSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bond: Bond
    boundCoverage: BoundCoverage
    claimAmount: ClaimAmount
    claimEventAt: int
    claimId: str
    claimRef: str | None = None
    claimant: str
    exposure: Exposure12
    issuedAt: int
    lossEvent: LossEvent
    narrative: str
    receiptIds: list[str]
    schema_: Literal["chio.market.claim-package.v1"] = Field(..., alias="schema")
