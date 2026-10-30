# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: b6f1812f92935a14019f86d41be473435cc0ec402c6c70767457f18fc119ce8a
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class AwardedAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


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


class Filters17(BaseModel):
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


class SupportBoundary26(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class Body43(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters17
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: str = Field(..., alias="schema")
    summary: Summary
    supportBoundary: SupportBoundary26


class Exposure5(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body43
    signature: str
    signerKey: str


class Prerequisites6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certificationMet: bool
    certificationRequired: bool
    manualReviewRequired: bool
    minimumRuntimeAssuranceTier: str
    runtimeAssuranceMet: bool


class SupportBoundary27(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondExecutionSupported: bool
    crossCurrencyAllocationSupported: bool
    providerNeutralPolicy: bool


class Terms6(BaseModel):
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
    filters: Filters17
    generatedAt: int
    prerequisites: Prerequisites6
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard
    supportBoundary: SupportBoundary27
    terms: Terms6 | None = None


class Filters19(BaseModel):
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


class Summary13(BaseModel):
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
    summary: Summary13


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


class Filters20(BaseModel):
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


class Summary14(BaseModel):
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


class SupportBoundary28(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalAllocationSupported: bool
    crossCurrencyNettingSupported: bool
    facilityPolicySupported: bool
    subjectScopedOnly: bool


class Body44(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dimensions: list[dict[str, Any]]
    filters: Filters20
    generatedAt: int
    positions: list[Position]
    probation: Probation
    reputation: Reputation
    schema_: str = Field(..., alias="schema")
    summary: Summary14
    supportBoundary: SupportBoundary28


class Scorecard10(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body44
    signature: str
    signerKey: str


class SupportBoundary29(BaseModel):
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


class Body42(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certification: Certification
    exposure: Exposure5
    facilityReport: FacilityReport
    filters: Filters19
    generatedAt: int
    latestFacility: LatestFacility | None = None
    recentLossHistory: RecentLossHistory
    runtimeAssurance: RuntimeAssurance | None = None
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard10
    subjectKey: str
    supportBoundary: SupportBoundary29


class RiskPackage(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body42
    signature: str
    signerKey: str


class Body41(BaseModel):
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
    body: Body41
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


class Body40(BaseModel):
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
    body: Body40
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


class Body39(BaseModel):
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
    body: Body39
    signature: str
    signerKey: str


class PremiumAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body38(BaseModel):
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
    body: Body38
    signature: str
    signerKey: str


class ClaimAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Summary15(BaseModel):
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


class SupportBoundary30(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class Body45(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters20
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: str = Field(..., alias="schema")
    summary: Summary15
    supportBoundary: SupportBoundary30


class Exposure6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body45
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


class Summary16(BaseModel):
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


class SupportBoundary31(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    appealWindowSupported: bool
    automaticCapitalExecutionSupported: bool
    bondLifecycleProjectionAuthoritative: bool
    externalClaimAdjudicationSupported: bool
    immutableLifecycleAuthoritative: bool
    reserveControlExecutionSupported: bool


class Report4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    generatedAt: int
    query: Query
    schema_: str = Field(..., alias="schema")
    summary: Summary16
    supportBoundary: SupportBoundary31


class Body46(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondId: str
    description: str
    eventId: str
    eventKind: str
    issuedAt: int
    projectedBondLifecycleState: str
    report: Report4
    schema_: str = Field(..., alias="schema")


class LossEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body46
    signature: str
    signerKey: str


class Body36(BaseModel):
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
    exposure: Exposure6
    issuedAt: int
    lossEvent: LossEvent
    narrative: str
    receiptIds: list[str]
    schema_: str = Field(..., alias="schema")


class Claim(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body36
    signature: str
    signerKey: str


class CoveredAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body35(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claim: Claim
    claimResponseId: str
    coveredAmount: CoveredAmount | None = None
    denialReason: str | None = None
    disposition: str
    issuedAt: int
    providerResponseRef: str
    responseNote: str | None = None
    schema_: str = Field(..., alias="schema")


class ProviderResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body35
    signature: str
    signerKey: str


class Body34(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    disputeId: str
    issuedAt: int
    note: str | None = None
    openedBy: str
    providerResponse: ProviderResponse
    reason: str
    schema_: str = Field(..., alias="schema")


class Dispute(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body34
    signature: str
    signerKey: str


class ChioMarketClaimAdjudicationSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    adjudicationId: str
    adjudicator: str
    awardedAmount: AwardedAmount
    decisionRuleRef: str | None = None
    dispute: Dispute
    issuedAt: int
    note: str | None = None
    outcome: str
    rosterAnchorRef: str | None = None
    schema_: Literal["chio.market.claim-adjudication.v1"] = Field(..., alias="schema")
