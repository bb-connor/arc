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


class Amount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class ObservedExecution(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    amount: Amount
    externalReferenceId: str
    observedAt: int


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


class Filters41(BaseModel):
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


class SupportBoundary55(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class Body96(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters41
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: str = Field(..., alias="schema")
    summary: Summary
    supportBoundary: SupportBoundary55


class Exposure17(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body96
    signature: str
    signerKey: str


class Prerequisites14(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certificationMet: bool
    certificationRequired: bool
    manualReviewRequired: bool
    minimumRuntimeAssuranceTier: str
    runtimeAssuranceMet: bool


class SupportBoundary56(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondExecutionSupported: bool
    crossCurrencyAllocationSupported: bool
    providerNeutralPolicy: bool


class Terms14(BaseModel):
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
    filters: Filters41
    generatedAt: int
    prerequisites: Prerequisites14
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard
    supportBoundary: SupportBoundary56
    terms: Terms14 | None = None


class Filters43(BaseModel):
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


class Summary33(BaseModel):
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
    summary: Summary33


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


class Filters44(BaseModel):
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


class Summary34(BaseModel):
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


class SupportBoundary57(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capitalAllocationSupported: bool
    crossCurrencyNettingSupported: bool
    facilityPolicySupported: bool
    subjectScopedOnly: bool


class Body97(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    dimensions: list[dict[str, Any]]
    filters: Filters44
    generatedAt: int
    positions: list[Position]
    probation: Probation
    reputation: Reputation
    schema_: str = Field(..., alias="schema")
    summary: Summary34
    supportBoundary: SupportBoundary57


class Scorecard22(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body97
    signature: str
    signerKey: str


class SupportBoundary58(BaseModel):
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


class Body95(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    certification: Certification
    exposure: Exposure17
    facilityReport: FacilityReport
    filters: Filters43
    generatedAt: int
    latestFacility: LatestFacility | None = None
    recentLossHistory: RecentLossHistory
    runtimeAssurance: RuntimeAssurance | None = None
    schema_: str = Field(..., alias="schema")
    scorecard: Scorecard22
    subjectKey: str
    supportBoundary: SupportBoundary58


class RiskPackage(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body95
    signature: str
    signerKey: str


class Body94(BaseModel):
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
    body: Body94
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


class Body93(BaseModel):
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
    body: Body93
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


class Body92(BaseModel):
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
    body: Body92
    signature: str
    signerKey: str


class PremiumAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body91(BaseModel):
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
    body: Body91
    signature: str
    signerKey: str


class ClaimAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Summary35(BaseModel):
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


class SupportBoundary59(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    claimAdjudicationSupported: bool
    crossCurrencyNettingSupported: bool
    governedReceiptsAuthoritative: bool
    recoveryLifecycleSupported: bool
    settlementReconciliationAuthoritative: bool
    underwritingDecisionsAuthoritative: bool


class Body98(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    decisions: list[dict[str, Any]]
    filters: Filters44
    generatedAt: int
    positions: list[Position]
    receipts: list[dict[str, Any]]
    schema_: str = Field(..., alias="schema")
    summary: Summary35
    supportBoundary: SupportBoundary59


class Exposure18(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body98
    signature: str
    signerKey: str


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


class Summary36(BaseModel):
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


class SupportBoundary60(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    appealWindowSupported: bool
    automaticCapitalExecutionSupported: bool
    bondLifecycleProjectionAuthoritative: bool
    externalClaimAdjudicationSupported: bool
    immutableLifecycleAuthoritative: bool
    reserveControlExecutionSupported: bool


class Report12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    generatedAt: int
    query: Query
    schema_: str = Field(..., alias="schema")
    summary: Summary36
    supportBoundary: SupportBoundary60


class Body99(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    bondId: str
    description: str
    eventId: str
    eventKind: str
    issuedAt: int
    projectedBondLifecycleState: str
    report: Report12
    schema_: str = Field(..., alias="schema")


class LossEvent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body99
    signature: str
    signerKey: str


class Body89(BaseModel):
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
    exposure: Exposure18
    issuedAt: int
    lossEvent: LossEvent
    narrative: str
    receiptIds: list[str]
    schema_: str = Field(..., alias="schema")


class Claim(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body89
    signature: str
    signerKey: str


class CoveredAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body88(BaseModel):
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
    body: Body88
    signature: str
    signerKey: str


class Body87(BaseModel):
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
    body: Body87
    signature: str
    signerKey: str


class Body86(BaseModel):
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
    schema_: str = Field(..., alias="schema")


class Adjudication(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body86
    signature: str
    signerKey: str


class Body101(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approvedAt: int
    expiresAt: int
    principalId: str
    role: str
    schema_: str = Field(..., alias="schema")


class AuthorityProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body101
    signature: str
    signerKey: str


class AuthorityChainItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    approvedAt: int
    authorityProof: AuthorityProof
    expiresAt: int
    note: str
    principalId: str
    role: str


class ExecutionWindow(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    notAfter: int
    notBefore: int


class Query11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    agentSubject: str
    bondLimit: int
    facilityLimit: int
    lossEventLimit: int
    receiptLimit: int


class Rail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    custodyProviderId: str
    destinationAccountRef: str | None = None
    jurisdiction: str | None = None
    kind: str
    railId: str
    sourceAccountRef: str | None = None


class SupportBoundary61(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    automaticDispatchSupported: bool
    capitalBookAuthoritative: bool
    custodyNeutralInstructionSupported: bool
    externalExecutionAuthoritative: bool


class Body100(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    action: str
    amount: Amount
    authorityChain: list[AuthorityChainItem]
    completionFlowRowId: str | None = None
    counterpartyId: str
    counterpartyRole: str
    description: str
    executionWindow: ExecutionWindow
    governedReceiptId: str | None = None
    instructionId: str
    intendedState: str
    issuedAt: int
    ownerRole: str
    query: Query11
    rail: Rail
    reconciledState: str
    schema_: str = Field(..., alias="schema")
    sourceId: str
    sourceKind: str
    subjectKey: str
    supportBoundary: SupportBoundary61


class CapitalInstruction(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body100
    signature: str
    signerKey: str


class PayoutAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    currency: str
    units: int


class Body85(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    adjudication: Adjudication
    capitalInstruction: CapitalInstruction
    issuedAt: int
    note: str | None = None
    payoutAmount: PayoutAmount
    payoutInstructionId: str
    schema_: str = Field(..., alias="schema")


class PayoutInstruction(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body85
    signature: str
    signerKey: str


class ChioMarketClaimPayoutReceiptSignedBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    issuedAt: int
    note: str | None = None
    observedExecution: ObservedExecution
    payoutInstruction: PayoutInstruction
    payoutReceiptId: str
    payoutReceiptRef: str
    reconciliationState: str
    schema_: Literal["chio.market.claim-payout-receipt.v1"] = Field(..., alias="schema")
