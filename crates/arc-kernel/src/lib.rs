//! ARC Runtime Kernel.
//!
//! The kernel is the trusted computing base (TCB) of the ARC protocol.
//! It sits between the untrusted agent and the sandboxed tool servers,
//! mediating every tool invocation.
//!
//! The kernel's responsibilities:
//!
//! 1. **Capability validation** -- verify signatures, time bounds, revocation
//!    status, scope matching, and invocation budgets.
//! 2. **Guard evaluation** -- run policy guards against the tool call before
//!    forwarding it.
//! 3. **Receipt signing** -- produce a signed receipt for every decision
//!    (allow or deny) and append it to the receipt log.
//! 4. **Tool dispatch** -- forward validated requests to the appropriate tool
//!    server over an authenticated channel.
//!
//! The kernel is architecturally invisible to the agent. The agent communicates
//! through an anonymous pipe or Unix domain socket and never learns the kernel's
//! PID, address, or signing key.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod authority;
pub mod budget_store;
pub mod capability_lineage;
pub mod checkpoint;
pub mod cost_attribution;
pub mod dpop;
pub mod evidence_export;
pub mod operator_report;
pub mod payment;
pub mod receipt_analytics;
pub mod receipt_query;
pub mod receipt_store;
mod receipt_support;
mod request_matching;
pub mod revocation_runtime;
pub mod revocation_store;
pub mod runtime;
pub mod session;
pub mod transport;

use std::collections::HashMap;
use std::future::Future;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_core::appraisal::verifier_family_for_attestation_schema;
use arc_core::canonical::canonical_json_bytes;
use arc_core::capability::{
    ArcScope, AttestationTrustPolicy, CapabilityToken, Constraint, GovernedApprovalDecision,
    GovernedApprovalToken, GovernedAutonomyTier, Operation, PromptGrant, ResourceGrant,
    RuntimeAssuranceTier, ToolGrant,
};
use arc_core::crypto::{sha256_hex, Keypair};
use arc_core::receipt::{
    ArcReceipt, ArcReceiptBody, ChildRequestReceipt, ChildRequestReceiptBody, Decision,
    FinancialReceiptMetadata, GovernedApprovalReceiptMetadata, GovernedAutonomyReceiptMetadata,
    GovernedCommerceReceiptMetadata, GovernedTransactionReceiptMetadata,
    MeteredBillingReceiptMetadata, ReceiptAttributionMetadata, RuntimeAssuranceReceiptMetadata,
    SettlementStatus, ToolCallAction,
};
use arc_core::session::{
    CompleteOperation, CompletionReference, CompletionResult, CreateElicitationOperation,
    CreateElicitationResult, CreateMessageOperation, CreateMessageResult, GetPromptOperation,
    NormalizedRoot, OperationContext, OperationKind, OperationTerminalState, ProgressToken,
    PromptDefinition, PromptResult, ReadResourceOperation, RequestId, ResourceContent,
    ResourceDefinition, ResourceTemplateDefinition, ResourceUriClassification, RootDefinition,
    SessionAuthContext, SessionId, SessionOperation, ToolCallOperation,
};
use arc_link::convert::convert_supported_units;
use arc_link::{PriceOracle, PriceOracleError};
use tracing::{debug, info, warn};

use receipt_support::*;
use request_matching::{
    begin_child_request_in_sessions, begin_session_request_in_sessions, check_subject_binding,
    check_time_bounds, complete_session_request_with_terminal_state_in_sessions,
    nested_child_request_id, resolve_matching_grants, session_from_map, session_mut_from_map,
    validate_elicitation_request_in_sessions, validate_sampling_request_in_sessions,
};
pub use request_matching::{
    capability_matches_prompt_request, capability_matches_request,
    capability_matches_resource_pattern, capability_matches_resource_request,
    capability_matches_resource_subscription,
};

pub use arc_core::credit::{
    CapitalAllocationDecisionArtifact, CapitalAllocationDecisionFinding,
    CapitalAllocationDecisionOutcome, CapitalAllocationDecisionReasonCode,
    CapitalAllocationDecisionSupportBoundary, CapitalAllocationInstructionDraft, CapitalBookEvent,
    CapitalBookEventKind, CapitalBookEvidenceKind, CapitalBookEvidenceReference, CapitalBookQuery,
    CapitalBookReport, CapitalBookRole, CapitalBookSource, CapitalBookSourceKind,
    CapitalBookSummary, CapitalBookSupportBoundary, CapitalExecutionAuthorityStep,
    CapitalExecutionInstructionAction, CapitalExecutionInstructionArtifact,
    CapitalExecutionInstructionSupportBoundary, CapitalExecutionIntendedState,
    CapitalExecutionObservation, CapitalExecutionRail, CapitalExecutionRailKind,
    CapitalExecutionReconciledState, CapitalExecutionRole, CapitalExecutionWindow,
    CreditBacktestQuery, CreditBacktestReasonCode, CreditBacktestReport, CreditBacktestSummary,
    CreditBacktestWindow, CreditBondArtifact, CreditBondDisposition, CreditBondFinding,
    CreditBondLifecycleState, CreditBondListQuery, CreditBondListReport, CreditBondListSummary,
    CreditBondPrerequisites, CreditBondReasonCode, CreditBondReport, CreditBondRow,
    CreditBondSupportBoundary, CreditBondTerms, CreditBondedExecutionControlPolicy,
    CreditBondedExecutionDecision, CreditBondedExecutionEvaluation, CreditBondedExecutionFinding,
    CreditBondedExecutionFindingCode, CreditBondedExecutionSimulationDelta,
    CreditBondedExecutionSimulationQuery, CreditBondedExecutionSimulationReport,
    CreditBondedExecutionSimulationRequest, CreditBondedExecutionSupportBoundary,
    CreditCertificationState, CreditFacilityArtifact, CreditFacilityCapitalSource,
    CreditFacilityDisposition, CreditFacilityFinding, CreditFacilityLifecycleState,
    CreditFacilityListQuery, CreditFacilityListReport, CreditFacilityListSummary,
    CreditFacilityPrerequisites, CreditFacilityReasonCode, CreditFacilityReport, CreditFacilityRow,
    CreditFacilitySupportBoundary, CreditFacilityTerms, CreditLossLifecycleArtifact,
    CreditLossLifecycleEventKind, CreditLossLifecycleFinding, CreditLossLifecycleListQuery,
    CreditLossLifecycleListReport, CreditLossLifecycleListSummary, CreditLossLifecycleQuery,
    CreditLossLifecycleReasonCode, CreditLossLifecycleReport, CreditLossLifecycleRow,
    CreditLossLifecycleSummary, CreditLossLifecycleSupportBoundary, CreditProviderFacilitySnapshot,
    CreditProviderRiskPackage, CreditProviderRiskPackageQuery,
    CreditProviderRiskPackageSupportBoundary, CreditRecentLossEntry, CreditRecentLossHistory,
    CreditRecentLossSummary, CreditReserveControlAppealState, CreditReserveControlExecutionState,
    CreditRuntimeAssuranceState, CreditScorecardAnomaly, CreditScorecardAnomalySeverity,
    CreditScorecardBand, CreditScorecardConfidence, CreditScorecardDimension,
    CreditScorecardDimensionKind, CreditScorecardEvidenceKind, CreditScorecardEvidenceReference,
    CreditScorecardProbationStatus, CreditScorecardReasonCode, CreditScorecardReport,
    CreditScorecardReputationContext, CreditScorecardSummary, CreditScorecardSupportBoundary,
    ExposureLedgerCurrencyPosition, ExposureLedgerDecisionEntry, ExposureLedgerEvidenceKind,
    ExposureLedgerEvidenceReference, ExposureLedgerQuery, ExposureLedgerReceiptEntry,
    ExposureLedgerReport, ExposureLedgerSummary, ExposureLedgerSupportBoundary,
    SignedCapitalAllocationDecision, SignedCapitalBookReport, SignedCapitalExecutionInstruction,
    SignedCreditBond, SignedCreditFacility, SignedCreditLossLifecycle,
    SignedCreditProviderRiskPackage, SignedCreditScorecardReport, SignedExposureLedgerReport,
    CAPITAL_ALLOCATION_DECISION_ARTIFACT_SCHEMA, CAPITAL_BOOK_REPORT_SCHEMA,
    CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA, CREDIT_BACKTEST_REPORT_SCHEMA,
    CREDIT_BONDED_EXECUTION_SIMULATION_REPORT_SCHEMA, CREDIT_BOND_ARTIFACT_SCHEMA,
    CREDIT_BOND_LIST_REPORT_SCHEMA, CREDIT_BOND_REPORT_SCHEMA, CREDIT_FACILITY_ARTIFACT_SCHEMA,
    CREDIT_FACILITY_LIST_REPORT_SCHEMA, CREDIT_FACILITY_REPORT_SCHEMA,
    CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA, CREDIT_LOSS_LIFECYCLE_LIST_REPORT_SCHEMA,
    CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA, CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA,
    CREDIT_SCORECARD_SCHEMA, EXPOSURE_LEDGER_SCHEMA, MAX_CREDIT_BACKTEST_WINDOW_LIMIT,
    MAX_CREDIT_BOND_LIST_LIMIT, MAX_CREDIT_FACILITY_LIST_LIMIT,
    MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT, MAX_CREDIT_PROVIDER_LOSS_LIMIT,
    MAX_EXPOSURE_LEDGER_DECISION_LIMIT, MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT,
};
pub use arc_core::governance::{
    build_generic_governance_case_artifact, build_generic_governance_charter_artifact,
    evaluate_generic_governance_case, GenericGovernanceAuthorityScope,
    GenericGovernanceCaseArtifact, GenericGovernanceCaseEvaluation,
    GenericGovernanceCaseEvaluationRequest, GenericGovernanceCaseIssueRequest,
    GenericGovernanceCaseKind, GenericGovernanceCaseState, GenericGovernanceCharterArtifact,
    GenericGovernanceCharterIssueRequest, GenericGovernanceEffectiveState,
    GenericGovernanceEvidenceKind, GenericGovernanceEvidenceReference, GenericGovernanceFinding,
    GenericGovernanceFindingCode, SignedGenericGovernanceCase, SignedGenericGovernanceCharter,
    GENERIC_GOVERNANCE_CASE_ARTIFACT_SCHEMA, GENERIC_GOVERNANCE_CHARTER_ARTIFACT_SCHEMA,
};
pub use arc_core::listing::{
    aggregate_generic_listing_reports, build_generic_trust_activation_artifact,
    ensure_generic_listing_namespace_consistency, evaluate_generic_trust_activation,
    normalize_namespace, GenericListingActorKind, GenericListingArtifact, GenericListingBoundary,
    GenericListingCompatibilityReference, GenericListingDivergence, GenericListingFreshnessState,
    GenericListingFreshnessWindow, GenericListingQuery, GenericListingReplicaFreshness,
    GenericListingReport, GenericListingSearchError, GenericListingSearchPolicy,
    GenericListingSearchResponse, GenericListingSearchResult, GenericListingStatus,
    GenericListingSubject, GenericListingSummary, GenericNamespaceArtifact,
    GenericNamespaceLifecycleState, GenericNamespaceOwnership, GenericRegistryPublisher,
    GenericRegistryPublisherRole, GenericTrustActivationArtifact,
    GenericTrustActivationDisposition, GenericTrustActivationEligibility,
    GenericTrustActivationEvaluation, GenericTrustActivationEvaluationRequest,
    GenericTrustActivationFinding, GenericTrustActivationFindingCode,
    GenericTrustActivationIssueRequest, GenericTrustActivationReviewContext,
    GenericTrustAdmissionClass, SignedGenericListing, SignedGenericNamespace,
    SignedGenericTrustActivation, DEFAULT_GENERIC_LISTING_REPORT_MAX_AGE_SECS,
    GENERIC_LISTING_ARTIFACT_SCHEMA, GENERIC_LISTING_NETWORK_SEARCH_SCHEMA,
    GENERIC_LISTING_REPORT_SCHEMA, GENERIC_LISTING_SEARCH_ALGORITHM_V1,
    GENERIC_NAMESPACE_ARTIFACT_SCHEMA, GENERIC_TRUST_ACTIVATION_ARTIFACT_SCHEMA,
    MAX_GENERIC_LISTING_LIMIT,
};
pub use arc_core::market::{
    LiabilityAutoBindDecisionArtifact, LiabilityAutoBindDisposition, LiabilityAutoBindFinding,
    LiabilityAutoBindReasonCode, LiabilityBoundCoverageArtifact,
    LiabilityClaimAdjudicationArtifact, LiabilityClaimAdjudicationOutcome,
    LiabilityClaimDisputeArtifact, LiabilityClaimEvidenceKind, LiabilityClaimEvidenceReference,
    LiabilityClaimPackageArtifact, LiabilityClaimPayoutInstructionArtifact,
    LiabilityClaimPayoutReceiptArtifact, LiabilityClaimPayoutReconciliationState,
    LiabilityClaimResponseArtifact, LiabilityClaimResponseDisposition,
    LiabilityClaimSettlementInstructionArtifact, LiabilityClaimSettlementKind,
    LiabilityClaimSettlementReceiptArtifact, LiabilityClaimSettlementReconciliationState,
    LiabilityClaimSettlementRoleBinding, LiabilityClaimSettlementRoleTopology,
    LiabilityClaimWorkflowQuery, LiabilityClaimWorkflowReport, LiabilityClaimWorkflowRow,
    LiabilityClaimWorkflowSummary, LiabilityCoverageClass, LiabilityEvidenceRequirement,
    LiabilityJurisdictionPolicy, LiabilityMarketWorkflowQuery, LiabilityMarketWorkflowReport,
    LiabilityMarketWorkflowRow, LiabilityMarketWorkflowSummary, LiabilityPlacementArtifact,
    LiabilityPricingAuthorityArtifact, LiabilityPricingAuthorityEnvelope,
    LiabilityPricingAuthorityEnvelopeKind, LiabilityProviderArtifact,
    LiabilityProviderLifecycleState, LiabilityProviderListQuery, LiabilityProviderListReport,
    LiabilityProviderListSummary, LiabilityProviderPolicyReference, LiabilityProviderProvenance,
    LiabilityProviderReport, LiabilityProviderResolutionQuery, LiabilityProviderResolutionReport,
    LiabilityProviderRow, LiabilityProviderSupportBoundary, LiabilityProviderType,
    LiabilityQuoteDisposition, LiabilityQuoteRequestArtifact, LiabilityQuoteResponseArtifact,
    LiabilityQuoteTerms, SignedLiabilityAutoBindDecision, SignedLiabilityBoundCoverage,
    SignedLiabilityClaimAdjudication, SignedLiabilityClaimDispute, SignedLiabilityClaimPackage,
    SignedLiabilityClaimPayoutInstruction, SignedLiabilityClaimPayoutReceipt,
    SignedLiabilityClaimResponse, SignedLiabilityClaimSettlementInstruction,
    SignedLiabilityClaimSettlementReceipt, SignedLiabilityPlacement,
    SignedLiabilityPricingAuthority, SignedLiabilityProvider, SignedLiabilityQuoteRequest,
    SignedLiabilityQuoteResponse, LIABILITY_AUTO_BIND_DECISION_ARTIFACT_SCHEMA,
    LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA, LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA, LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_PAYOUT_RECEIPT_ARTIFACT_SCHEMA, LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ARTIFACT_SCHEMA, LIABILITY_CLAIM_WORKFLOW_REPORT_SCHEMA,
    LIABILITY_MARKET_WORKFLOW_REPORT_SCHEMA, LIABILITY_PLACEMENT_ARTIFACT_SCHEMA,
    LIABILITY_PRICING_AUTHORITY_ARTIFACT_SCHEMA, LIABILITY_PROVIDER_ARTIFACT_SCHEMA,
    LIABILITY_PROVIDER_LIST_REPORT_SCHEMA, LIABILITY_PROVIDER_RESOLUTION_REPORT_SCHEMA,
    LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA, LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA,
    MAX_LIABILITY_CLAIM_WORKFLOW_LIMIT, MAX_LIABILITY_MARKET_WORKFLOW_LIMIT,
    MAX_LIABILITY_PROVIDER_LIST_LIMIT,
};
pub use arc_core::open_market::{
    build_open_market_fee_schedule_artifact, build_open_market_penalty_artifact,
    evaluate_open_market_penalty, OpenMarketAbuseClass, OpenMarketBondClass,
    OpenMarketBondRequirement, OpenMarketCollateralReferenceKind, OpenMarketEconomicsScope,
    OpenMarketEvidenceKind, OpenMarketEvidenceReference, OpenMarketFeeScheduleArtifact,
    OpenMarketFeeScheduleIssueRequest, OpenMarketFinding, OpenMarketFindingCode,
    OpenMarketPenaltyAction, OpenMarketPenaltyArtifact, OpenMarketPenaltyEffectiveState,
    OpenMarketPenaltyEvaluation, OpenMarketPenaltyEvaluationRequest, OpenMarketPenaltyIssueRequest,
    OpenMarketPenaltyState, SignedOpenMarketFeeSchedule, SignedOpenMarketPenalty,
    OPEN_MARKET_FEE_SCHEDULE_ARTIFACT_SCHEMA, OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA,
};
pub use arc_core::underwriting::{
    build_underwriting_decision_artifact, evaluate_underwriting_policy_input,
    SignedUnderwritingDecision, SignedUnderwritingPolicyInput, UnderwritingAppealCreateRequest,
    UnderwritingAppealRecord, UnderwritingAppealResolution, UnderwritingAppealResolveRequest,
    UnderwritingAppealStatus, UnderwritingBudgetAction, UnderwritingBudgetRecommendation,
    UnderwritingCertificationEvidence, UnderwritingCertificationState,
    UnderwritingDecisionArtifact, UnderwritingDecisionFinding, UnderwritingDecisionLifecycleState,
    UnderwritingDecisionListReport, UnderwritingDecisionOutcome, UnderwritingDecisionPolicy,
    UnderwritingDecisionQuery, UnderwritingDecisionReasonCode, UnderwritingDecisionReport,
    UnderwritingDecisionRow, UnderwritingDecisionSummary, UnderwritingEvidenceKind,
    UnderwritingEvidenceReference, UnderwritingPolicyInput, UnderwritingPolicyInputQuery,
    UnderwritingPremiumQuote, UnderwritingPremiumState, UnderwritingReasonCode,
    UnderwritingReceiptEvidence, UnderwritingRemediation, UnderwritingReputationEvidence,
    UnderwritingReviewState, UnderwritingRiskClass, UnderwritingRiskTaxonomy,
    UnderwritingRuntimeAssuranceEvidence, UnderwritingSignal, UnderwritingSimulationDelta,
    UnderwritingSimulationReport, UnderwritingSimulationRequest, MAX_UNDERWRITING_DECISION_LIMIT,
    MAX_UNDERWRITING_RECEIPT_LIMIT, UNDERWRITING_APPEAL_SCHEMA,
    UNDERWRITING_DECISION_ARTIFACT_SCHEMA, UNDERWRITING_DECISION_POLICY_SCHEMA,
    UNDERWRITING_DECISION_POLICY_VERSION, UNDERWRITING_DECISION_REPORT_SCHEMA,
    UNDERWRITING_POLICY_INPUT_SCHEMA, UNDERWRITING_RISK_TAXONOMY_VERSION,
    UNDERWRITING_SIMULATION_REPORT_SCHEMA,
};
pub use authority::{
    AuthoritySnapshot, AuthorityStatus, AuthorityStoreError, AuthorityTrustedKeySnapshot,
    CapabilityAuthority, LocalCapabilityAuthority,
};
pub use budget_store::{BudgetStore, BudgetStoreError, BudgetUsageRecord, InMemoryBudgetStore};
pub use capability_lineage::{
    CapabilityLineageError, CapabilitySnapshot, StoredCapabilitySnapshot,
};
pub use checkpoint::{
    build_checkpoint, build_inclusion_proof, is_supported_checkpoint_schema,
    verify_checkpoint_signature, CheckpointError, KernelCheckpoint, KernelCheckpointBody,
    ReceiptInclusionProof, CHECKPOINT_SCHEMA, LEGACY_CHECKPOINT_SCHEMA,
};
pub use cost_attribution::{
    CostAttributionChainHop, CostAttributionQuery, CostAttributionReceiptRow,
    CostAttributionReport, CostAttributionSummary, LeafCostAttributionRow, RootCostAttributionRow,
    MAX_COST_ATTRIBUTION_LIMIT,
};
pub use dpop::{
    is_supported_dpop_schema, verify_dpop_proof, DpopConfig, DpopNonceStore, DpopProof,
    DpopProofBody, DPOP_SCHEMA, LEGACY_DPOP_SCHEMA,
};
pub use evidence_export::{
    EvidenceChildReceiptRecord, EvidenceChildReceiptScope, EvidenceExportBundle,
    EvidenceExportError, EvidenceExportQuery, EvidenceRetentionMetadata, EvidenceToolReceiptRecord,
    EvidenceUncheckpointedReceipt,
};
pub use operator_report::{
    ArcOAuthArtifactBoundary, ArcOAuthAuthorizationDiscoveryMetadata,
    ArcOAuthAuthorizationExampleMapping, ArcOAuthAuthorizationMetadataReport,
    ArcOAuthAuthorizationProfile, ArcOAuthAuthorizationReviewPack,
    ArcOAuthAuthorizationReviewPackRecord, ArcOAuthAuthorizationReviewPackSummary,
    ArcOAuthAuthorizationSupportBoundary, ArcOAuthRequestTimeContract, ArcOAuthResourceBinding,
    ArcOAuthSenderConstraintProfile, AuthorizationContextReport, AuthorizationContextRow,
    AuthorizationContextSenderConstraint, AuthorizationContextSummary,
    BehavioralFeedDecisionSummary, BehavioralFeedGovernedActionSummary,
    BehavioralFeedMeteredBillingRow, BehavioralFeedMeteredBillingSummary,
    BehavioralFeedPrivacyBoundary, BehavioralFeedQuery, BehavioralFeedReceiptRow,
    BehavioralFeedReceiptSelection, BehavioralFeedReport, BehavioralFeedReputationSummary,
    BehavioralFeedSettlementSummary, BudgetDimensionProfile, BudgetDimensionUsage,
    BudgetUtilizationReport, BudgetUtilizationRow, BudgetUtilizationSummary, ComplianceReport,
    GovernedAuthorizationCommerceDetail, GovernedAuthorizationDetail,
    GovernedAuthorizationMeteredBillingDetail, GovernedAuthorizationTransactionContext,
    MeteredBillingEvidenceRecord, MeteredBillingReconciliationReport,
    MeteredBillingReconciliationRow, MeteredBillingReconciliationState,
    MeteredBillingReconciliationSummary, OperatorReport, OperatorReportQuery,
    SettlementReconciliationReport, SettlementReconciliationRow, SettlementReconciliationState,
    SettlementReconciliationSummary, SharedEvidenceQuery, SharedEvidenceReferenceReport,
    SharedEvidenceReferenceRow, SharedEvidenceReferenceSummary, SignedBehavioralFeed,
    ARC_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE, ARC_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA,
    ARC_OAUTH_AUTHORIZATION_METADATA_SCHEMA, ARC_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE,
    ARC_OAUTH_AUTHORIZATION_PROFILE_ID, ARC_OAUTH_AUTHORIZATION_PROFILE_SCHEMA,
    ARC_OAUTH_AUTHORIZATION_REVIEW_PACK_SCHEMA, ARC_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE,
    ARC_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_CLAIM,
    ARC_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_PARAMETER,
    ARC_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_CLAIM,
    ARC_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_PARAMETER,
    ARC_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT, ARC_OAUTH_SENDER_CONSTRAINT_SCHEMA,
    ARC_OAUTH_SENDER_PROOF_ARC_DPOP, BEHAVIORAL_FEED_SCHEMA, MAX_AUTHORIZATION_CONTEXT_LIMIT,
    MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT, MAX_METERED_BILLING_LIMIT, MAX_OPERATOR_BUDGET_LIMIT,
    MAX_SETTLEMENT_BACKLOG_LIMIT, MAX_SHARED_EVIDENCE_LIMIT,
};
pub use payment::{
    AcpPaymentAdapter, CommercePaymentContext, GovernedPaymentContext, PaymentAdapter,
    PaymentAuthorization, PaymentAuthorizeRequest, PaymentError, PaymentResult,
    RailSettlementStatus, ReceiptSettlement, X402PaymentAdapter,
};
pub use receipt_analytics::{
    AgentAnalyticsRow, AnalyticsTimeBucket, ReceiptAnalyticsMetrics, ReceiptAnalyticsQuery,
    ReceiptAnalyticsResponse, TimeAnalyticsRow, ToolAnalyticsRow, MAX_ANALYTICS_GROUP_LIMIT,
};
pub use receipt_query::{ReceiptQuery, ReceiptQueryResult, MAX_QUERY_LIMIT};
pub use receipt_store::{
    FederatedEvidenceShareImport, FederatedEvidenceShareSummary, ReceiptStore, ReceiptStoreError,
    RetentionConfig, StoredChildReceipt, StoredToolReceipt,
};
pub use revocation_runtime::{InMemoryRevocationStore, RevocationStore};
pub use revocation_store::{RevocationRecord, RevocationStoreError};
pub use runtime::{
    NestedFlowBridge, NestedFlowClient, ToolCallChunk, ToolCallOutput, ToolCallRequest,
    ToolCallResponse, ToolCallStream, ToolInvocationCost, ToolServerConnection, ToolServerEvent,
    ToolServerOutput, ToolServerStreamResult, Verdict,
};
pub use session::{
    InflightRegistry, InflightRequest, LateSessionEvent, PeerCapabilities, Session, SessionError,
    SessionOperationResponse, SessionState, SubscriptionRegistry, TerminalRegistry,
};

/// A string-typed agent identifier.
pub type AgentId = String;

/// A string-typed capability identifier.
pub type CapabilityId = String;

/// A string-typed server identifier.
pub type ServerId = String;

#[derive(Debug)]
struct ReceiptContent {
    content_hash: String,
    metadata: Option<serde_json::Value>,
}

/// Errors that can occur during kernel operations.
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("unknown session: {0}")]
    UnknownSession(SessionId),

    #[error("session error: {0}")]
    Session(#[from] SessionError),

    #[error("capability has expired")]
    CapabilityExpired,

    #[error("capability not yet valid")]
    CapabilityNotYetValid,

    #[error("capability has been revoked: {0}")]
    CapabilityRevoked(CapabilityId),

    #[error("capability signature is invalid")]
    InvalidSignature,

    #[error("capability issuer is not a trusted CA")]
    UntrustedIssuer,

    #[error("capability issuance failed: {0}")]
    CapabilityIssuanceFailed(String),

    #[error("capability issuance denied: {0}")]
    CapabilityIssuanceDenied(String),

    #[error("requested tool {tool} on server {server} is not in capability scope")]
    OutOfScope { tool: String, server: String },

    #[error("requested resource {uri} is not in capability scope")]
    OutOfScopeResource { uri: String },

    #[error("requested prompt {prompt} is not in capability scope")]
    OutOfScopePrompt { prompt: String },

    #[error("invocation budget exhausted for capability {0}")]
    BudgetExhausted(CapabilityId),

    #[error("request agent {actual} does not match capability subject {expected}")]
    SubjectMismatch { expected: String, actual: String },

    #[error("delegation chain revoked at ancestor {0}")]
    DelegationChainRevoked(CapabilityId),

    #[error("invalid capability constraint: {0}")]
    InvalidConstraint(String),

    #[error("governed transaction denied: {0}")]
    GovernedTransactionDenied(String),

    #[error("guard denied the request: {0}")]
    GuardDenied(String),

    #[error("tool server error: {0}")]
    ToolServerError(String),

    #[error("request stream incomplete: {0}")]
    RequestIncomplete(String),

    #[error("tool not registered: {0}")]
    ToolNotRegistered(String),

    #[error("resource not registered: {0}")]
    ResourceNotRegistered(String),

    #[error("resource read denied by session roots for {uri}: {reason}")]
    ResourceRootDenied { uri: String, reason: String },

    #[error("prompt not registered: {0}")]
    PromptNotRegistered(String),

    #[error("sampling is disabled by policy")]
    SamplingNotAllowedByPolicy,

    #[error("sampling was not negotiated with the client")]
    SamplingNotNegotiated,

    #[error("sampling context inclusion is not supported by the client")]
    SamplingContextNotSupported,

    #[error("sampling tool use is disabled by policy")]
    SamplingToolUseNotAllowedByPolicy,

    #[error("sampling tool use was not negotiated with the client")]
    SamplingToolUseNotNegotiated,

    #[error("elicitation is disabled by policy")]
    ElicitationNotAllowedByPolicy,

    #[error("elicitation was not negotiated with the client")]
    ElicitationNotNegotiated,

    #[error("elicitation form mode is not supported by the client")]
    ElicitationFormNotSupported,

    #[error("elicitation URL mode was not negotiated with the client")]
    ElicitationUrlNotSupported,

    #[error("{message}")]
    UrlElicitationsRequired {
        message: String,
        elicitations: Vec<CreateElicitationOperation>,
    },

    #[error("roots/list was not negotiated with the client")]
    RootsNotNegotiated,

    #[error("sampling child requests require a ready session-bound parent request")]
    InvalidChildRequestParent,

    #[error("request {request_id} was cancelled: {reason}")]
    RequestCancelled {
        request_id: RequestId,
        reason: String,
    },

    #[error("receipt signing failed: {0}")]
    ReceiptSigningFailed(String),

    #[error("receipt persistence failed: {0}")]
    ReceiptPersistence(#[from] ReceiptStoreError),

    #[error("revocation store error: {0}")]
    RevocationStore(#[from] RevocationStoreError),

    #[error("budget store error: {0}")]
    BudgetStore(#[from] BudgetStoreError),

    #[error(
        "cross-currency budget enforcement failed: no price oracle configured for {base}/{quote}"
    )]
    NoCrossCurrencyOracle { base: String, quote: String },

    #[error("cross-currency budget enforcement failed: {0}")]
    CrossCurrencyOracle(String),

    #[error("web3 evidence prerequisites unavailable: {0}")]
    Web3EvidenceUnavailable(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("DPoP proof verification failed: {0}")]
    DpopVerificationFailed(String),
}

/// A policy guard that the kernel evaluates before forwarding a tool call.
///
/// Guards are the same concept as ClawdStrike's `Guard` trait, adapted for
/// the ARC tool-call context. Each guard inspects the request and returns
/// a verdict.
pub trait Guard: Send + Sync {
    /// Human-readable guard name (e.g., "forbidden-path").
    fn name(&self) -> &str;

    /// Evaluate the guard against a tool call request.
    ///
    /// Returns `Ok(Verdict::Allow)` to pass, `Ok(Verdict::Deny)` to block,
    /// or `Err` on internal failure (which the kernel treats as deny).
    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError>;
}

/// Context passed to guards during evaluation.
pub struct GuardContext<'a> {
    /// The tool call request being evaluated.
    pub request: &'a ToolCallRequest,
    /// The verified capability scope.
    pub scope: &'a ArcScope,
    /// The agent making the request.
    pub agent_id: &'a AgentId,
    /// The target server.
    pub server_id: &'a ServerId,
    /// Session-scoped enforceable filesystem roots, when the request is being
    /// evaluated through the supported session-backed runtime path.
    pub session_filesystem_roots: Option<&'a [String]>,
    /// Index of the matched grant in the capability's scope, populated by
    /// check_and_increment_budget before guards run.
    pub matched_grant_index: Option<usize>,
}

/// Trait representing a resource provider.
pub trait ResourceProvider: Send + Sync {
    /// List the resources this provider exposes.
    fn list_resources(&self) -> Vec<ResourceDefinition>;

    /// List parameterized resource templates.
    fn list_resource_templates(&self) -> Vec<ResourceTemplateDefinition> {
        vec![]
    }

    /// Read a resource by URI. Returns `Ok(None)` when the provider does not own the URI.
    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError>;

    /// Return completions for a resource template or URI reference.
    fn complete_resource_argument(
        &self,
        _uri: &str,
        _argument_name: &str,
        _value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        Ok(None)
    }
}

/// Trait representing a prompt provider.
pub trait PromptProvider: Send + Sync {
    /// List available prompts.
    fn list_prompts(&self) -> Vec<PromptDefinition>;

    /// Retrieve a prompt by name. Returns `Ok(None)` when the provider does not own the prompt.
    fn get_prompt(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, KernelError>;

    /// Return completions for a prompt argument.
    fn complete_prompt_argument(
        &self,
        _name: &str,
        _argument_name: &str,
        _value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        Ok(None)
    }
}

/// In-memory append-only log of signed receipts.
///
/// This remains useful for process-local inspection even when a durable
/// backend is configured.
#[derive(Default)]
pub struct ReceiptLog {
    receipts: Vec<ArcReceipt>,
}

impl ReceiptLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, receipt: ArcReceipt) {
        self.receipts.push(receipt);
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn receipts(&self) -> &[ArcReceipt] {
        &self.receipts
    }

    pub fn get(&self, index: usize) -> Option<&ArcReceipt> {
        self.receipts.get(index)
    }
}

/// In-memory append-only log of signed child-request receipts.
#[derive(Default)]
pub struct ChildReceiptLog {
    receipts: Vec<ChildRequestReceipt>,
}

impl ChildReceiptLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, receipt: ChildRequestReceipt) {
        self.receipts.push(receipt);
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn receipts(&self) -> &[ChildRequestReceipt] {
        &self.receipts
    }

    pub fn get(&self, index: usize) -> Option<&ChildRequestReceipt> {
        self.receipts.get(index)
    }
}

/// Configuration for the ARC Runtime Kernel.
pub struct KernelConfig {
    /// Ed25519 keypair for signing receipts and issuing capabilities.
    pub keypair: Keypair,

    /// Public keys of trusted Capability Authorities.
    pub ca_public_keys: Vec<arc_core::PublicKey>,

    /// Maximum allowed delegation depth.
    pub max_delegation_depth: u32,

    /// SHA-256 hash of the active policy (embedded in receipts).
    pub policy_hash: String,

    /// Whether nested sampling requests are allowed at all.
    pub allow_sampling: bool,

    /// Whether sampling requests may include tool-use affordances.
    pub allow_sampling_tool_use: bool,

    /// Whether nested elicitation requests are allowed.
    pub allow_elicitation: bool,

    /// Maximum total wall-clock duration permitted for one streamed tool result.
    pub max_stream_duration_secs: u64,

    /// Maximum total canonical payload size permitted for one streamed tool result.
    pub max_stream_total_bytes: u64,

    /// Whether durable receipts and kernel-signed checkpoints are mandatory
    /// prerequisites for this deployment.
    pub require_web3_evidence: bool,

    /// Number of receipts between Merkle checkpoint snapshots. Default: 100.
    ///
    /// Set to 0 to disable automatic checkpointing for deployments that do not
    /// require web3 evidence.
    pub checkpoint_batch_size: u64,

    /// Optional receipt retention configuration.
    ///
    /// When `None` (default), retention is disabled and receipts accumulate
    /// indefinitely. When `Some(config)`, the kernel will archive receipts
    /// that exceed the time or size threshold.
    pub retention_config: Option<crate::receipt_store::RetentionConfig>,
}

pub const DEFAULT_MAX_STREAM_DURATION_SECS: u64 = 300;
pub const DEFAULT_MAX_STREAM_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_CHECKPOINT_BATCH_SIZE: u64 = 100;
pub const DEFAULT_RETENTION_DAYS: u64 = 90;
pub const DEFAULT_MAX_SIZE_BYTES: u64 = 10_737_418_240;

/// The ARC Runtime Kernel.
///
/// This is the central component of the ARC protocol. It validates capabilities,
/// runs guards, dispatches tool calls, and signs receipts.
///
/// The kernel is designed to be the sole trusted mediator. It never exposes its
/// signing key, address, or internal state to the agent.
pub struct ArcKernel {
    config: KernelConfig,
    guards: Vec<Box<dyn Guard>>,
    budget_store: Box<dyn BudgetStore>,
    revocation_store: Box<dyn RevocationStore>,
    capability_authority: Box<dyn CapabilityAuthority>,
    tool_servers: HashMap<ServerId, Box<dyn ToolServerConnection>>,
    resource_providers: Vec<Box<dyn ResourceProvider>>,
    prompt_providers: Vec<Box<dyn PromptProvider>>,
    sessions: HashMap<SessionId, Session>,
    receipt_log: ReceiptLog,
    child_receipt_log: ChildReceiptLog,
    receipt_store: Option<Box<dyn ReceiptStore>>,
    payment_adapter: Option<Box<dyn PaymentAdapter>>,
    price_oracle: Option<Box<dyn PriceOracle>>,
    attestation_trust_policy: Option<AttestationTrustPolicy>,
    session_counter: u64,
    /// How many receipts per Merkle checkpoint batch. Default: 100.
    checkpoint_batch_size: u64,
    /// Monotonic counter for checkpoint_seq values.
    checkpoint_seq_counter: u64,
    /// seq of the last receipt included in the previous checkpoint batch.
    last_checkpoint_seq: u64,
    /// Nonce replay store for DPoP proof verification. Required when any grant has dpop_required.
    dpop_nonce_store: Option<dpop::DpopNonceStore>,
    /// Configuration for DPoP proof verification TTLs and clock skew.
    dpop_config: Option<dpop::DpopConfig>,
}

#[derive(Clone, Copy)]
struct MatchingGrant<'a> {
    index: usize,
    grant: &'a ToolGrant,
    specificity: (u8, u8, usize),
}

/// Result of a monetary budget charge attempt.
///
/// Carries the accounting info needed to populate FinancialReceiptMetadata.
struct BudgetChargeResult {
    grant_index: usize,
    cost_charged: u64,
    currency: String,
    budget_total: u64,
    /// Running total cost after this charge (used to compute budget_remaining).
    new_total_cost_charged: u64,
}

struct SessionNestedFlowBridge<'a, C> {
    sessions: &'a mut HashMap<SessionId, Session>,
    child_receipts: &'a mut Vec<ChildRequestReceipt>,
    parent_context: &'a OperationContext,
    allow_sampling: bool,
    allow_sampling_tool_use: bool,
    allow_elicitation: bool,
    policy_hash: &'a str,
    kernel_keypair: &'a Keypair,
    client: &'a mut C,
}

impl<C> SessionNestedFlowBridge<'_, C> {
    fn complete_child_request_with_receipt<T: serde::Serialize>(
        &mut self,
        child_context: &OperationContext,
        operation_kind: OperationKind,
        result: &Result<T, KernelError>,
    ) -> Result<(), KernelError> {
        let terminal_state = child_terminal_state(&child_context.request_id, result);
        complete_session_request_with_terminal_state_in_sessions(
            self.sessions,
            &child_context.session_id,
            &child_context.request_id,
            terminal_state.clone(),
        )?;

        let receipt = build_child_request_receipt(
            self.policy_hash,
            self.kernel_keypair,
            child_context,
            operation_kind,
            terminal_state,
            child_outcome_payload(result)?,
        )?;
        self.child_receipts.push(receipt);
        Ok(())
    }
}

impl<C: NestedFlowClient> NestedFlowBridge for SessionNestedFlowBridge<'_, C> {
    fn parent_request_id(&self) -> &RequestId {
        &self.parent_context.request_id
    }

    fn poll_parent_cancellation(&mut self) -> Result<(), KernelError> {
        self.client.poll_parent_cancellation(self.parent_context)
    }

    fn list_roots(&mut self) -> Result<Vec<RootDefinition>, KernelError> {
        let child_context = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            nested_child_request_id(&self.parent_context.request_id, "roots"),
            OperationKind::ListRoots,
            None,
            false,
        )?;

        let result = (|| {
            let session = session_from_map(self.sessions, &child_context.session_id)?;
            session.validate_context(&child_context)?;
            session.ensure_operation_allowed(OperationKind::ListRoots)?;
            if !session.peer_capabilities().supports_roots {
                return Err(KernelError::RootsNotNegotiated);
            }

            let roots = self
                .client
                .list_roots(self.parent_context, &child_context)?;
            session_mut_from_map(self.sessions, &child_context.session_id)?
                .replace_roots(roots.clone());
            Ok(roots)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_mut_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::ListRoots,
            &result,
        )?;

        result
    }

    fn create_message(
        &mut self,
        operation: CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        let child_context = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            nested_child_request_id(&self.parent_context.request_id, "sample"),
            OperationKind::CreateMessage,
            None,
            true,
        )?;

        let result = (|| {
            validate_sampling_request_in_sessions(
                self.sessions,
                self.allow_sampling,
                self.allow_sampling_tool_use,
                &child_context,
                &operation,
            )?;
            self.client
                .create_message(self.parent_context, &child_context, &operation)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_mut_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::CreateMessage,
            &result,
        )?;

        result
    }

    fn create_elicitation(
        &mut self,
        operation: CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        let child_context = begin_child_request_in_sessions(
            self.sessions,
            self.parent_context,
            nested_child_request_id(&self.parent_context.request_id, "elicit"),
            OperationKind::CreateElicitation,
            None,
            true,
        )?;

        let result = (|| {
            validate_elicitation_request_in_sessions(
                self.sessions,
                self.allow_elicitation,
                &child_context,
                &operation,
            )?;
            self.client
                .create_elicitation(self.parent_context, &child_context, &operation)
        })();
        if matches!(
            &result,
            Err(KernelError::RequestCancelled { request_id, .. })
                if request_id == &child_context.request_id
        ) {
            session_mut_from_map(self.sessions, &child_context.session_id)?
                .request_cancellation(&child_context.request_id)?;
        }
        self.complete_child_request_with_receipt(
            &child_context,
            OperationKind::CreateElicitation,
            &result,
        )?;

        result
    }

    fn notify_elicitation_completed(&mut self, elicitation_id: &str) -> Result<(), KernelError> {
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        self.client
            .notify_elicitation_completed(self.parent_context, elicitation_id)
    }

    fn notify_resource_updated(&mut self, uri: &str) -> Result<(), KernelError> {
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        if !session.is_resource_subscribed(uri) {
            return Ok(());
        }

        self.client
            .notify_resource_updated(self.parent_context, uri)
    }

    fn notify_resources_list_changed(&mut self) -> Result<(), KernelError> {
        let session = session_from_map(self.sessions, &self.parent_context.session_id)?;
        session.validate_context(self.parent_context)?;
        session.ensure_operation_allowed(OperationKind::ToolCall)?;

        self.client
            .notify_resources_list_changed(self.parent_context)
    }
}

impl ArcKernel {
    pub fn new(config: KernelConfig) -> Self {
        info!("initializing ARC kernel");
        let authority_keypair = config.keypair.clone();
        let checkpoint_batch_size = config.checkpoint_batch_size;
        Self {
            config,
            guards: Vec::new(),
            budget_store: Box::new(InMemoryBudgetStore::new()),
            revocation_store: Box::new(InMemoryRevocationStore::new()),
            capability_authority: Box::new(LocalCapabilityAuthority::new(authority_keypair)),
            tool_servers: HashMap::new(),
            resource_providers: Vec::new(),
            prompt_providers: Vec::new(),
            sessions: HashMap::new(),
            receipt_log: ReceiptLog::new(),
            child_receipt_log: ChildReceiptLog::new(),
            receipt_store: None,
            payment_adapter: None,
            price_oracle: None,
            attestation_trust_policy: None,
            session_counter: 0,
            checkpoint_batch_size,
            checkpoint_seq_counter: 0,
            last_checkpoint_seq: 0,
            dpop_nonce_store: None,
            dpop_config: None,
        }
    }

    pub fn set_receipt_store(&mut self, receipt_store: Box<dyn ReceiptStore>) {
        self.receipt_store = Some(receipt_store);
    }

    pub fn set_payment_adapter(&mut self, payment_adapter: Box<dyn PaymentAdapter>) {
        self.payment_adapter = Some(payment_adapter);
    }

    pub fn set_price_oracle(&mut self, price_oracle: Box<dyn PriceOracle>) {
        self.price_oracle = Some(price_oracle);
    }

    pub fn set_attestation_trust_policy(
        &mut self,
        attestation_trust_policy: AttestationTrustPolicy,
    ) {
        self.attestation_trust_policy = Some(attestation_trust_policy);
    }

    pub fn set_revocation_store(&mut self, revocation_store: Box<dyn RevocationStore>) {
        self.revocation_store = revocation_store;
    }

    pub fn set_capability_authority(&mut self, capability_authority: Box<dyn CapabilityAuthority>) {
        self.capability_authority = capability_authority;
    }

    pub fn set_budget_store(&mut self, budget_store: Box<dyn BudgetStore>) {
        self.budget_store = budget_store;
    }

    /// Install a DPoP nonce replay store and verification config.
    ///
    /// Once installed, any invocation whose matched grant has `dpop_required == Some(true)`
    /// must carry a valid `DpopProof` on the `ToolCallRequest`. Requests that lack a proof
    /// or whose proof fails verification are denied fail-closed.
    pub fn set_dpop_store(&mut self, nonce_store: dpop::DpopNonceStore, config: dpop::DpopConfig) {
        self.dpop_nonce_store = Some(nonce_store);
        self.dpop_config = Some(config);
    }

    pub fn requires_web3_evidence(&self) -> bool {
        self.config.require_web3_evidence
    }

    pub fn validate_web3_evidence_prerequisites(&self) -> Result<(), KernelError> {
        if !self.requires_web3_evidence() {
            return Ok(());
        }

        let Some(store) = self.receipt_store.as_deref() else {
            return Err(KernelError::Web3EvidenceUnavailable(
                "web3-enabled deployments require a durable receipt store".to_string(),
            ));
        };

        if self.checkpoint_batch_size == 0 {
            return Err(KernelError::Web3EvidenceUnavailable(
                "web3-enabled deployments require checkpoint_batch_size > 0".to_string(),
            ));
        }

        if !store.supports_kernel_signed_checkpoints() {
            return Err(KernelError::Web3EvidenceUnavailable(
                "web3-enabled deployments require local receipt persistence with kernel-signed checkpoint support; append-only remote receipt mirrors are unsupported".to_string(),
            ));
        }

        Ok(())
    }

    /// Register a policy guard. Guards are evaluated in registration order.
    /// If any guard denies, the request is denied.
    pub fn add_guard(&mut self, guard: Box<dyn Guard>) {
        self.guards.push(guard);
    }

    /// Register a tool server connection.
    pub fn register_tool_server(&mut self, connection: Box<dyn ToolServerConnection>) {
        let id = connection.server_id().to_owned();
        info!(server_id = %id, "registering tool server");
        self.tool_servers.insert(id, connection);
    }

    /// Register a resource provider.
    pub fn register_resource_provider(&mut self, provider: Box<dyn ResourceProvider>) {
        info!("registering resource provider");
        self.resource_providers.push(provider);
    }

    /// Register a prompt provider.
    pub fn register_prompt_provider(&mut self, provider: Box<dyn PromptProvider>) {
        info!("registering prompt provider");
        self.prompt_providers.push(provider);
    }

    /// Open a new logical session for an agent and bind any capabilities that
    /// were issued during setup to that session.
    pub fn open_session(
        &mut self,
        agent_id: AgentId,
        issued_capabilities: Vec<CapabilityToken>,
    ) -> SessionId {
        self.session_counter += 1;
        let session_id = SessionId::new(format!("sess-{}", self.session_counter));

        info!(session_id = %session_id, agent_id = %agent_id, "opening session");
        self.sessions.insert(
            session_id.clone(),
            Session::new(session_id.clone(), agent_id, issued_capabilities),
        );

        session_id
    }

    /// Transition a session into the `ready` state once setup is complete.
    pub fn activate_session(&mut self, session_id: &SessionId) -> Result<(), KernelError> {
        self.validate_web3_evidence_prerequisites()?;
        self.session_mut(session_id)?.activate()?;
        Ok(())
    }

    /// Persist transport/session authentication context for a session.
    pub fn set_session_auth_context(
        &mut self,
        session_id: &SessionId,
        auth_context: SessionAuthContext,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?.set_auth_context(auth_context);
        Ok(())
    }

    /// Persist peer capabilities negotiated at the edge for a session.
    pub fn set_session_peer_capabilities(
        &mut self,
        session_id: &SessionId,
        peer_capabilities: PeerCapabilities,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?
            .set_peer_capabilities(peer_capabilities);
        Ok(())
    }

    /// Replace the session's current root snapshot.
    pub fn replace_session_roots(
        &mut self,
        session_id: &SessionId,
        roots: Vec<RootDefinition>,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?.replace_roots(roots);
        Ok(())
    }

    /// Return the runtime's normalized root view for a session.
    pub fn normalized_session_roots(
        &self,
        session_id: &SessionId,
    ) -> Result<&[NormalizedRoot], KernelError> {
        Ok(self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?
            .normalized_roots())
    }

    /// Return only the enforceable filesystem root paths for a session.
    pub fn enforceable_filesystem_root_paths(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<&str>, KernelError> {
        Ok(self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?
            .enforceable_filesystem_roots()
            .filter_map(NormalizedRoot::normalized_filesystem_path)
            .collect())
    }

    fn session_enforceable_filesystem_root_paths_owned(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<String>, KernelError> {
        Ok(self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?
            .enforceable_filesystem_roots()
            .filter_map(NormalizedRoot::normalized_filesystem_path)
            .map(str::to_string)
            .collect())
    }

    fn resource_path_within_root(candidate: &str, root: &str) -> bool {
        if candidate == root {
            return true;
        }

        if root == "/" {
            return candidate.starts_with('/');
        }

        candidate
            .strip_prefix(root)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
    }

    fn resource_path_matches_session_roots(path: &str, session_roots: &[String]) -> bool {
        if session_roots.is_empty() {
            return false;
        }

        session_roots
            .iter()
            .any(|root| Self::resource_path_within_root(path, root))
    }

    fn enforce_resource_roots(
        &self,
        context: &OperationContext,
        operation: &ReadResourceOperation,
    ) -> Result<(), KernelError> {
        match operation.classify_uri_for_runtime() {
            ResourceUriClassification::NonFileSystem { .. } => Ok(()),
            ResourceUriClassification::EnforceableFileSystem {
                normalized_path, ..
            } => {
                let session_roots =
                    self.session_enforceable_filesystem_root_paths_owned(&context.session_id)?;

                if Self::resource_path_matches_session_roots(&normalized_path, &session_roots) {
                    Ok(())
                } else {
                    let reason = if session_roots.is_empty() {
                        "no enforceable filesystem roots are available for this session".to_string()
                    } else {
                        format!(
                            "filesystem-backed resource path {normalized_path} is outside the negotiated roots"
                        )
                    };

                    Err(KernelError::ResourceRootDenied {
                        uri: operation.uri.clone(),
                        reason,
                    })
                }
            }
            ResourceUriClassification::UnenforceableFileSystem { reason, .. } => {
                Err(KernelError::ResourceRootDenied {
                    uri: operation.uri.clone(),
                    reason: format!(
                        "filesystem-backed resource URI could not be enforced: {reason}"
                    ),
                })
            }
        }
    }

    fn build_resource_read_deny_receipt(
        &mut self,
        operation: &ReadResourceOperation,
        reason: &str,
    ) -> Result<ArcReceipt, KernelError> {
        let receipt_content = receipt_content_for_output(None, None)?;
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "uri": &operation.uri,
        }))
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to hash resource read parameters: {error}"
            ))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &operation.capability.id,
            tool_name: "resources/read",
            server_id: "session",
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "session_roots".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                Some(serde_json::json!({
                    "resource": {
                        "uri": &operation.uri,
                    }
                })),
                receipt_attribution_metadata(&operation.capability, None),
            ),
            timestamp: current_unix_timestamp(),
        })?;

        self.record_arc_receipt(&receipt)?;
        Ok(receipt)
    }

    /// Subscribe the session to update notifications for a concrete resource URI.
    pub fn subscribe_session_resource(
        &mut self,
        session_id: &SessionId,
        capability: &CapabilityToken,
        agent_id: &str,
        uri: &str,
    ) -> Result<(), KernelError> {
        self.validate_non_tool_capability(capability, agent_id)?;

        if !capability_matches_resource_subscription(capability, uri)? {
            return Err(KernelError::OutOfScopeResource {
                uri: uri.to_string(),
            });
        }

        if !self.resource_exists(uri)? {
            return Err(KernelError::ResourceNotRegistered(uri.to_string()));
        }

        self.session_mut(session_id)?
            .subscribe_resource(uri.to_string());
        Ok(())
    }

    /// Remove a session-scoped resource subscription. Missing subscriptions are ignored.
    pub fn unsubscribe_session_resource(
        &mut self,
        session_id: &SessionId,
        uri: &str,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?.unsubscribe_resource(uri);
        Ok(())
    }

    /// Check whether a session currently holds a resource subscription.
    pub fn session_has_resource_subscription(
        &self,
        session_id: &SessionId,
        uri: &str,
    ) -> Result<bool, KernelError> {
        Ok(self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?
            .is_resource_subscribed(uri))
    }

    /// Mark a session as draining. New tool calls are rejected after this point.
    pub fn begin_draining_session(&mut self, session_id: &SessionId) -> Result<(), KernelError> {
        self.session_mut(session_id)?.begin_draining()?;
        Ok(())
    }

    /// Close a session and clear transient session-scoped state.
    pub fn close_session(&mut self, session_id: &SessionId) -> Result<(), KernelError> {
        self.session_mut(session_id)?.close()?;
        Ok(())
    }

    /// Inspect an existing session.
    pub fn session(&self, session_id: &SessionId) -> Option<&Session> {
        self.sessions.get(session_id)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn resource_provider_count(&self) -> usize {
        self.resource_providers.len()
    }

    pub fn prompt_provider_count(&self) -> usize {
        self.prompt_providers.len()
    }

    /// Validate a session-scoped operation and register it as in flight.
    pub fn begin_session_request(
        &mut self,
        context: &OperationContext,
        operation_kind: OperationKind,
        cancellable: bool,
    ) -> Result<(), KernelError> {
        begin_session_request_in_sessions(&mut self.sessions, context, operation_kind, cancellable)
    }

    /// Construct and register a child request under an existing parent request.
    pub fn begin_child_request(
        &mut self,
        parent_context: &OperationContext,
        request_id: RequestId,
        operation_kind: OperationKind,
        progress_token: Option<ProgressToken>,
        cancellable: bool,
    ) -> Result<OperationContext, KernelError> {
        begin_child_request_in_sessions(
            &mut self.sessions,
            parent_context,
            request_id,
            operation_kind,
            progress_token,
            cancellable,
        )
    }

    /// Complete an in-flight session request.
    pub fn complete_session_request(
        &mut self,
        session_id: &SessionId,
        request_id: &RequestId,
    ) -> Result<(), KernelError> {
        self.complete_session_request_with_terminal_state(
            session_id,
            request_id,
            OperationTerminalState::Completed,
        )
    }

    /// Complete an in-flight session request with an explicit terminal state.
    pub fn complete_session_request_with_terminal_state(
        &mut self,
        session_id: &SessionId,
        request_id: &RequestId,
        terminal_state: OperationTerminalState,
    ) -> Result<(), KernelError> {
        complete_session_request_with_terminal_state_in_sessions(
            &mut self.sessions,
            session_id,
            request_id,
            terminal_state,
        )
    }

    /// Mark an in-flight session request as cancelled.
    pub fn request_session_cancellation(
        &mut self,
        session_id: &SessionId,
        request_id: &RequestId,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?
            .request_cancellation(request_id)
            .map_err(KernelError::from)
    }

    /// Validate whether a sampling child request is allowed for this session.
    pub fn validate_sampling_request(
        &self,
        context: &OperationContext,
        operation: &CreateMessageOperation,
    ) -> Result<(), KernelError> {
        validate_sampling_request_in_sessions(
            &self.sessions,
            self.config.allow_sampling,
            self.config.allow_sampling_tool_use,
            context,
            operation,
        )
    }

    /// Validate whether an elicitation child request is allowed for this session.
    pub fn validate_elicitation_request(
        &self,
        context: &OperationContext,
        operation: &CreateElicitationOperation,
    ) -> Result<(), KernelError> {
        validate_elicitation_request_in_sessions(
            &self.sessions,
            self.config.allow_elicitation,
            context,
            operation,
        )
    }

    /// Evaluate a session-scoped tool call while allowing the target tool server to proxy
    /// negotiated nested flows back through a client transport owned by the edge.
    pub fn evaluate_tool_call_operation_with_nested_flow_client<C: NestedFlowClient>(
        &mut self,
        context: &OperationContext,
        operation: &ToolCallOperation,
        client: &mut C,
    ) -> Result<ToolCallResponse, KernelError> {
        self.validate_web3_evidence_prerequisites()?;
        self.begin_session_request(context, OperationKind::ToolCall, true)?;

        let request = ToolCallRequest {
            request_id: context.request_id.to_string(),
            capability: operation.capability.clone(),
            tool_name: operation.tool_name.clone(),
            server_id: operation.server_id.clone(),
            agent_id: context.agent_id.clone(),
            arguments: operation.arguments.clone(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        };

        let result = self.evaluate_tool_call_with_nested_flow_client(context, &request, client);
        let terminal_state = match &result {
            Ok(response) => response.terminal_state.clone(),
            Err(KernelError::RequestCancelled { request_id, reason })
                if request_id == &context.request_id =>
            {
                self.session_mut(&context.session_id)?
                    .request_cancellation(&context.request_id)?;
                OperationTerminalState::Cancelled {
                    reason: reason.clone(),
                }
            }
            _ => OperationTerminalState::Completed,
        };
        self.complete_session_request_with_terminal_state(
            &context.session_id,
            &context.request_id,
            terminal_state,
        )?;
        result
    }

    /// Evaluate a normalized operation against a specific session.
    ///
    /// This is the higher-level entry point that future JSON-RPC or MCP edges
    /// should target. The current stdio loop normalizes raw frames into these
    /// operations before invoking the kernel.
    pub fn evaluate_session_operation(
        &mut self,
        context: &OperationContext,
        operation: &SessionOperation,
    ) -> Result<SessionOperationResponse, KernelError> {
        self.validate_web3_evidence_prerequisites()?;
        let operation_kind = operation.kind();
        let should_track_inflight = matches!(
            operation,
            SessionOperation::ToolCall(_)
                | SessionOperation::ReadResource(_)
                | SessionOperation::GetPrompt(_)
                | SessionOperation::Complete(_)
        );

        if should_track_inflight {
            self.begin_session_request(context, operation_kind, true)?;
        } else {
            let session = self.session_mut(&context.session_id)?;
            session.validate_context(context)?;
            session.ensure_operation_allowed(operation_kind)?;
        }

        let evaluation = match operation {
            SessionOperation::ToolCall(tool_call) => {
                let request = ToolCallRequest {
                    request_id: context.request_id.to_string(),
                    capability: tool_call.capability.clone(),
                    tool_name: tool_call.tool_name.clone(),
                    server_id: tool_call.server_id.clone(),
                    agent_id: context.agent_id.clone(),
                    arguments: tool_call.arguments.clone(),
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                };
                let session_roots =
                    self.session_enforceable_filesystem_root_paths_owned(&context.session_id)?;

                self.evaluate_tool_call_with_session_roots(&request, Some(session_roots.as_slice()))
                    .map(SessionOperationResponse::ToolCall)
            }
            SessionOperation::CreateMessage(_) => Err(KernelError::Internal(
                "sampling/createMessage must be evaluated by an MCP edge with a client transport"
                    .to_string(),
            )),
            SessionOperation::CreateElicitation(_) => Err(KernelError::Internal(
                "elicitation/create must be evaluated by an MCP edge with a client transport"
                    .to_string(),
            )),
            SessionOperation::ListRoots => {
                let roots = self
                    .session(&context.session_id)
                    .ok_or_else(|| KernelError::UnknownSession(context.session_id.clone()))?
                    .roots()
                    .to_vec();
                Ok(SessionOperationResponse::RootList { roots })
            }
            SessionOperation::ListResources => {
                let resources = self
                    .list_resources_for_session(&context.session_id)?
                    .into_iter()
                    .collect();
                Ok(SessionOperationResponse::ResourceList { resources })
            }
            SessionOperation::ReadResource(resource_read) => {
                self.evaluate_resource_read(context, resource_read)
            }
            SessionOperation::ListResourceTemplates => {
                let templates = self.list_resource_templates_for_session(&context.session_id)?;
                Ok(SessionOperationResponse::ResourceTemplateList { templates })
            }
            SessionOperation::ListPrompts => {
                let prompts = self.list_prompts_for_session(&context.session_id)?;
                Ok(SessionOperationResponse::PromptList { prompts })
            }
            SessionOperation::GetPrompt(prompt_get) => self
                .evaluate_prompt_get(context, prompt_get)
                .map(|prompt| SessionOperationResponse::PromptGet { prompt }),
            SessionOperation::Complete(complete) => self
                .evaluate_completion(context, complete)
                .map(|completion| SessionOperationResponse::Completion { completion }),
            SessionOperation::ListCapabilities => {
                let capabilities = self
                    .session(&context.session_id)
                    .ok_or_else(|| KernelError::UnknownSession(context.session_id.clone()))?
                    .capabilities()
                    .to_vec();

                Ok(SessionOperationResponse::CapabilityList { capabilities })
            }
            SessionOperation::Heartbeat => Ok(SessionOperationResponse::Heartbeat),
        };

        if should_track_inflight {
            let terminal_state = match &evaluation {
                Ok(SessionOperationResponse::ToolCall(response)) => response.terminal_state.clone(),
                _ => OperationTerminalState::Completed,
            };
            self.complete_session_request_with_terminal_state(
                &context.session_id,
                &context.request_id,
                terminal_state,
            )?;
        }

        evaluation
    }

    fn list_resources_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<ResourceDefinition>, KernelError> {
        let session = self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;

        let mut resources = Vec::new();
        for provider in &self.resource_providers {
            resources.extend(provider.list_resources().into_iter().filter(|resource| {
                session.capabilities().iter().any(|capability| {
                    capability_matches_resource_request(capability, &resource.uri).unwrap_or(false)
                })
            }));
        }

        Ok(resources)
    }

    fn resource_exists(&self, uri: &str) -> Result<bool, KernelError> {
        for provider in &self.resource_providers {
            if provider
                .list_resources()
                .iter()
                .any(|resource| resource.uri == uri)
            {
                return Ok(true);
            }

            if provider.read_resource(uri)?.is_some() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn list_resource_templates_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<ResourceTemplateDefinition>, KernelError> {
        let session = self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;

        let mut templates = Vec::new();
        for provider in &self.resource_providers {
            templates.extend(
                provider
                    .list_resource_templates()
                    .into_iter()
                    .filter(|template| {
                        session.capabilities().iter().any(|capability| {
                            capability_matches_resource_pattern(capability, &template.uri_template)
                                .unwrap_or(false)
                        })
                    }),
            );
        }

        Ok(templates)
    }

    fn evaluate_resource_read(
        &mut self,
        context: &OperationContext,
        operation: &ReadResourceOperation,
    ) -> Result<SessionOperationResponse, KernelError> {
        self.validate_non_tool_capability(&operation.capability, &context.agent_id)?;

        if !capability_matches_resource_request(&operation.capability, &operation.uri)? {
            return Err(KernelError::OutOfScopeResource {
                uri: operation.uri.clone(),
            });
        }

        match self.enforce_resource_roots(context, operation) {
            Ok(()) => {}
            Err(KernelError::ResourceRootDenied { reason, .. }) => {
                let receipt = self.build_resource_read_deny_receipt(operation, &reason)?;
                return Ok(SessionOperationResponse::ResourceReadDenied { receipt });
            }
            Err(error) => return Err(error),
        }

        for provider in &self.resource_providers {
            if let Some(contents) = provider.read_resource(&operation.uri)? {
                return Ok(SessionOperationResponse::ResourceRead { contents });
            }
        }

        Err(KernelError::ResourceNotRegistered(operation.uri.clone()))
    }

    fn list_prompts_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<PromptDefinition>, KernelError> {
        let session = self
            .session(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;

        let mut prompts = Vec::new();
        for provider in &self.prompt_providers {
            prompts.extend(provider.list_prompts().into_iter().filter(|prompt| {
                session.capabilities().iter().any(|capability| {
                    capability_matches_prompt_request(capability, &prompt.name).unwrap_or(false)
                })
            }));
        }

        Ok(prompts)
    }

    fn evaluate_prompt_get(
        &self,
        context: &OperationContext,
        operation: &GetPromptOperation,
    ) -> Result<PromptResult, KernelError> {
        self.validate_non_tool_capability(&operation.capability, &context.agent_id)?;

        if !capability_matches_prompt_request(&operation.capability, &operation.prompt_name)? {
            return Err(KernelError::OutOfScopePrompt {
                prompt: operation.prompt_name.clone(),
            });
        }

        for provider in &self.prompt_providers {
            if let Some(prompt) =
                provider.get_prompt(&operation.prompt_name, operation.arguments.clone())?
            {
                return Ok(prompt);
            }
        }

        Err(KernelError::PromptNotRegistered(
            operation.prompt_name.clone(),
        ))
    }

    fn evaluate_completion(
        &self,
        context: &OperationContext,
        operation: &CompleteOperation,
    ) -> Result<CompletionResult, KernelError> {
        self.validate_non_tool_capability(&operation.capability, &context.agent_id)?;

        match &operation.reference {
            CompletionReference::Prompt { name } => {
                if !capability_matches_prompt_request(&operation.capability, name)? {
                    return Err(KernelError::OutOfScopePrompt {
                        prompt: name.clone(),
                    });
                }

                for provider in &self.prompt_providers {
                    if let Some(completion) = provider.complete_prompt_argument(
                        name,
                        &operation.argument.name,
                        &operation.argument.value,
                        &operation.context_arguments,
                    )? {
                        return Ok(completion);
                    }
                }

                Err(KernelError::PromptNotRegistered(name.clone()))
            }
            CompletionReference::Resource { uri } => {
                if !capability_matches_resource_pattern(&operation.capability, uri)? {
                    return Err(KernelError::OutOfScopeResource { uri: uri.clone() });
                }

                for provider in &self.resource_providers {
                    if let Some(completion) = provider.complete_resource_argument(
                        uri,
                        &operation.argument.name,
                        &operation.argument.value,
                        &operation.context_arguments,
                    )? {
                        return Ok(completion);
                    }
                }

                Err(KernelError::ResourceNotRegistered(uri.clone()))
            }
        }
    }

    fn validate_non_tool_capability(
        &self,
        capability: &CapabilityToken,
        agent_id: &str,
    ) -> Result<(), KernelError> {
        self.verify_capability_signature(capability)
            .map_err(|_| KernelError::InvalidSignature)?;
        check_time_bounds(capability, current_unix_timestamp())?;
        self.check_revocation(capability)?;
        check_subject_binding(capability, agent_id)?;
        Ok(())
    }

    /// Evaluate a tool call request.
    ///
    /// This is the kernel's main entry point. It performs the full validation
    /// pipeline:
    ///
    /// 1. Verify capability signature against known CA public keys.
    /// 2. Check time bounds (not expired, not-before satisfied).
    /// 3. Check revocation status of the capability and its delegation chain.
    /// 4. Verify the requested tool is within the capability's scope.
    /// 5. Check and decrement invocation budget.
    /// 6. Run all registered guards.
    /// 7. If all pass: forward to tool server, sign allow receipt.
    /// 8. If any fail: sign deny receipt.
    ///
    /// Every call -- whether allowed or denied -- produces exactly one signed
    /// receipt.
    pub fn evaluate_tool_call(
        &mut self,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_with_session_roots(request, None)
    }

    fn evaluate_tool_call_with_session_roots(
        &mut self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.validate_web3_evidence_prerequisites()?;
        let now = current_unix_timestamp();

        debug!(
            request_id = %request.request_id,
            tool = %request.tool_name,
            server = %request.server_id,
            "evaluating tool call"
        );

        let cap = &request.capability;

        if let Err(reason) = self.verify_capability_signature(cap) {
            let msg = format!("signature verification failed: {reason}");
            warn!(request_id = %request.request_id, %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = check_time_bounds(cap, now) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = self.check_revocation(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = check_subject_binding(cap, &request.agent_id) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        let matching_grants = match resolve_matching_grants(
            cap,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
        ) {
            Ok(grants) if !grants.is_empty() => grants,
            Ok(_) => {
                let e = KernelError::OutOfScope {
                    tool: request.tool_name.clone(),
                    server: request.server_id.clone(),
                };
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                return self.build_deny_response(request, &msg, now, None);
            }
            Err(e) => {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                return self.build_deny_response(request, &msg, now, None);
            }
        };

        // DPoP enforcement before budget charge: if any matching grant requires
        // DPoP, verify the proof now so an attacker cannot drain the budget with
        // a valid capability token but missing or invalid DPoP proof.
        if matching_grants
            .iter()
            .any(|m| m.grant.dpop_required == Some(true))
        {
            if let Err(e) = self.verify_dpop_for_request(request, cap) {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "DPoP verification failed");
                return self.build_deny_response(request, &msg, now, None);
            }
        }

        if let Err(e) = self.ensure_registered_tool_target(request) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "tool target not registered");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(error) = self.record_observed_capability_snapshot(cap) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "failed to persist capability lineage");
            return self.build_deny_response(request, &msg, now, None);
        }

        let (matched_grant_index, charge_result) =
            match self.check_and_increment_budget(cap, &matching_grants) {
                Ok(result) => result,
                Err(e) => {
                    let msg = e.to_string();
                    warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                    // For monetary budget exhaustion, build a denial receipt with financial metadata.
                    return self.build_monetary_deny_response(
                        request,
                        &msg,
                        now,
                        &matching_grants,
                        cap,
                    );
                }
            };

        let matched_grant = matching_grants
            .iter()
            .find(|matching| matching.index == matched_grant_index)
            .map(|matching| matching.grant)
            .ok_or_else(|| {
                KernelError::Internal(format!(
                    "matched grant index {matched_grant_index} missing from candidate set"
                ))
            })?;

        if let Err(error) = self.validate_governed_transaction(
            request,
            cap,
            matched_grant,
            charge_result.as_ref(),
            now,
        ) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "governed transaction denied");
            if let Some(ref charge) = charge_result {
                let total_cost_charged_after_release =
                    self.reverse_budget_charge(&cap.id, charge)?;
                return self.build_pre_execution_monetary_deny_response(
                    request,
                    &msg,
                    now,
                    charge,
                    total_cost_charged_after_release,
                    cap,
                );
            }
            return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
        }

        if let Err(e) = self.run_guards(
            request,
            &cap.scope,
            session_filesystem_roots,
            Some(matched_grant_index),
        ) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "guard denied");
            if let Some(ref charge) = charge_result {
                let total_cost_charged_after_release =
                    self.reverse_budget_charge(&cap.id, charge)?;
                return self.build_pre_execution_monetary_deny_response(
                    request,
                    &msg,
                    now,
                    charge,
                    total_cost_charged_after_release,
                    cap,
                );
            }
            return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
        }

        let payment_authorization =
            match self.authorize_payment_if_needed(request, charge_result.as_ref()) {
                Ok(authorization) => authorization,
                Err(error) => {
                    let msg = format!("payment authorization failed: {error}");
                    warn!(request_id = %request.request_id, reason = %msg, "payment denied");
                    if let Some(ref charge) = charge_result {
                        let total_cost_charged_after_release =
                            self.reverse_budget_charge(&cap.id, charge)?;
                        return self.build_pre_execution_monetary_deny_response(
                            request,
                            &msg,
                            now,
                            charge,
                            total_cost_charged_after_release,
                            cap,
                        );
                    }
                    return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
                }
            };

        let tool_started_at = Instant::now();
        let has_monetary = charge_result.is_some();
        let (tool_output, reported_cost) =
            match self.dispatch_tool_call_with_cost(request, has_monetary) {
                Ok(result) => result,
                Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                    self.unwind_aborted_monetary_invocation(
                        request,
                        cap,
                        charge_result.as_ref(),
                        payment_authorization.as_ref(),
                    )?;
                    warn!(
                        request_id = %request.request_id,
                        reason = %error,
                        "tool call requires URL elicitation"
                    );
                    return Err(error);
                }
                Err(KernelError::RequestCancelled { reason, .. }) => {
                    self.unwind_aborted_monetary_invocation(
                        request,
                        cap,
                        charge_result.as_ref(),
                        payment_authorization.as_ref(),
                    )?;
                    warn!(
                        request_id = %request.request_id,
                        reason = %reason,
                        "tool call cancelled"
                    );
                    return self.build_cancelled_response(
                        request,
                        &reason,
                        now,
                        Some(matched_grant_index),
                    );
                }
                Err(KernelError::RequestIncomplete(reason)) => {
                    self.unwind_aborted_monetary_invocation(
                        request,
                        cap,
                        charge_result.as_ref(),
                        payment_authorization.as_ref(),
                    )?;
                    warn!(
                        request_id = %request.request_id,
                        reason = %reason,
                        "tool call incomplete"
                    );
                    return self.build_incomplete_response(
                        request,
                        &reason,
                        now,
                        Some(matched_grant_index),
                    );
                }
                Err(e) => {
                    self.unwind_aborted_monetary_invocation(
                        request,
                        cap,
                        charge_result.as_ref(),
                        payment_authorization.as_ref(),
                    )?;
                    let msg = e.to_string();
                    warn!(request_id = %request.request_id, reason = %msg, "tool server error");
                    return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
                }
            };
        self.finalize_tool_output_with_cost(
            request,
            tool_output,
            tool_started_at.elapsed(),
            now,
            matched_grant_index,
            charge_result,
            reported_cost,
            payment_authorization,
            cap,
        )
    }

    fn evaluate_tool_call_with_nested_flow_client<C: NestedFlowClient>(
        &mut self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
    ) -> Result<ToolCallResponse, KernelError> {
        self.validate_web3_evidence_prerequisites()?;
        let now = current_unix_timestamp();

        debug!(
            request_id = %request.request_id,
            tool = %request.tool_name,
            server = %request.server_id,
            "evaluating tool call with nested-flow bridge"
        );

        let cap = &request.capability;

        if let Err(reason) = self.verify_capability_signature(cap) {
            let msg = format!("signature verification failed: {reason}");
            warn!(request_id = %request.request_id, %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = check_time_bounds(cap, now) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = self.check_revocation(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = check_subject_binding(cap, &request.agent_id) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        let matching_grants = match resolve_matching_grants(
            cap,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
        ) {
            Ok(grants) if !grants.is_empty() => grants,
            Ok(_) => {
                let e = KernelError::OutOfScope {
                    tool: request.tool_name.clone(),
                    server: request.server_id.clone(),
                };
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                return self.build_deny_response(request, &msg, now, None);
            }
            Err(e) => {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                return self.build_deny_response(request, &msg, now, None);
            }
        };

        // DPoP enforcement before budget charge: if any matching grant requires
        // DPoP, verify the proof now so an attacker cannot drain the budget with
        // a valid capability token but missing or invalid DPoP proof.
        if matching_grants
            .iter()
            .any(|m| m.grant.dpop_required == Some(true))
        {
            if let Err(e) = self.verify_dpop_for_request(request, cap) {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "DPoP verification failed");
                return self.build_deny_response(request, &msg, now, None);
            }
        }

        if let Err(e) = self.ensure_registered_tool_target(request) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "tool target not registered");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(error) = self.record_observed_capability_snapshot(cap) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "failed to persist capability lineage");
            return self.build_deny_response(request, &msg, now, None);
        }

        let (matched_grant_index, charge_result) =
            match self.check_and_increment_budget(cap, &matching_grants) {
                Ok(result) => result,
                Err(e) => {
                    let msg = e.to_string();
                    warn!(request_id = %request.request_id, reason = %msg, "capability rejected");
                    return self.build_monetary_deny_response(
                        request,
                        &msg,
                        now,
                        &matching_grants,
                        cap,
                    );
                }
            };

        let matched_grant = matching_grants
            .iter()
            .find(|matching| matching.index == matched_grant_index)
            .map(|matching| matching.grant)
            .ok_or_else(|| {
                KernelError::Internal(format!(
                    "matched grant index {matched_grant_index} missing from candidate set"
                ))
            })?;

        if let Err(error) = self.validate_governed_transaction(
            request,
            cap,
            matched_grant,
            charge_result.as_ref(),
            now,
        ) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "governed transaction denied");
            if let Some(ref charge) = charge_result {
                let total_cost_charged_after_release =
                    self.reverse_budget_charge(&cap.id, charge)?;
                return self.build_pre_execution_monetary_deny_response(
                    request,
                    &msg,
                    now,
                    charge,
                    total_cost_charged_after_release,
                    cap,
                );
            }
            return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
        }

        let session_roots =
            self.session_enforceable_filesystem_root_paths_owned(&parent_context.session_id)?;

        if let Err(e) = self.run_guards(
            request,
            &cap.scope,
            Some(session_roots.as_slice()),
            Some(matched_grant_index),
        ) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %msg, "guard denied");
            if let Some(ref charge) = charge_result {
                let total_cost_charged_after_release =
                    self.reverse_budget_charge(&cap.id, charge)?;
                return self.build_pre_execution_monetary_deny_response(
                    request,
                    &msg,
                    now,
                    charge,
                    total_cost_charged_after_release,
                    cap,
                );
            }
            return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
        }

        let payment_authorization =
            match self.authorize_payment_if_needed(request, charge_result.as_ref()) {
                Ok(authorization) => authorization,
                Err(error) => {
                    let msg = format!("payment authorization failed: {error}");
                    warn!(request_id = %request.request_id, reason = %msg, "payment denied");
                    if let Some(ref charge) = charge_result {
                        let total_cost_charged_after_release =
                            self.reverse_budget_charge(&cap.id, charge)?;
                        return self.build_pre_execution_monetary_deny_response(
                            request,
                            &msg,
                            now,
                            charge,
                            total_cost_charged_after_release,
                            cap,
                        );
                    }
                    return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
                }
            };

        let tool_started_at = Instant::now();
        let mut child_receipts = Vec::new();
        let tool_output_result = {
            let server = self.tool_servers.get(&request.server_id).ok_or_else(|| {
                KernelError::ToolNotRegistered(format!(
                    "server \"{}\" / tool \"{}\"",
                    request.server_id, request.tool_name
                ))
            })?;
            let mut bridge = SessionNestedFlowBridge {
                sessions: &mut self.sessions,
                child_receipts: &mut child_receipts,
                parent_context,
                allow_sampling: self.config.allow_sampling,
                allow_sampling_tool_use: self.config.allow_sampling_tool_use,
                allow_elicitation: self.config.allow_elicitation,
                policy_hash: &self.config.policy_hash,
                kernel_keypair: &self.config.keypair,
                client,
            };

            match server.invoke_stream(
                &request.tool_name,
                request.arguments.clone(),
                Some(&mut bridge),
            ) {
                Ok(Some(stream)) => Ok(ToolServerOutput::Stream(stream)),
                Ok(None) => match server.invoke(
                    &request.tool_name,
                    request.arguments.clone(),
                    Some(&mut bridge),
                ) {
                    Ok(result) => Ok(ToolServerOutput::Value(result)),
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            }
        };
        self.record_child_receipts(child_receipts)?;
        let tool_output = match tool_output_result {
            Ok(output) => output,
            Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                warn!(
                    request_id = %request.request_id,
                    reason = %error,
                    "tool call requires URL elicitation"
                );
                return Err(error);
            }
            Err(KernelError::RequestCancelled { request_id, reason }) => {
                self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                if request_id == parent_context.request_id {
                    self.session_mut(&parent_context.session_id)?
                        .request_cancellation(&parent_context.request_id)?;
                }
                warn!(
                    request_id = %request.request_id,
                    reason = %reason,
                    "tool call cancelled"
                );
                return self.build_cancelled_response(
                    request,
                    &reason,
                    now,
                    Some(matched_grant_index),
                );
            }
            Err(KernelError::RequestIncomplete(reason)) => {
                self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                warn!(
                    request_id = %request.request_id,
                    reason = %reason,
                    "tool call incomplete"
                );
                return self.build_incomplete_response(
                    request,
                    &reason,
                    now,
                    Some(matched_grant_index),
                );
            }
            Err(error) => {
                self.unwind_aborted_monetary_invocation(
                    request,
                    cap,
                    charge_result.as_ref(),
                    payment_authorization.as_ref(),
                )?;
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %msg, "tool server error");
                return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
            }
        };
        self.finalize_tool_output_with_cost(
            request,
            tool_output,
            tool_started_at.elapsed(),
            now,
            matched_grant_index,
            charge_result,
            None,
            payment_authorization,
            cap,
        )
    }

    /// Issue a new capability for an agent.
    ///
    /// The kernel delegates issuance to the configured capability authority.
    pub fn issue_capability(
        &self,
        subject: &arc_core::PublicKey,
        scope: ArcScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        let capability = self
            .capability_authority
            .issue_capability(subject, scope, ttl_seconds)?;

        info!(
            capability_id = %capability.id,
            subject = %subject.to_hex(),
            ttl = ttl_seconds,
            issuer = %capability.issuer.to_hex(),
            "issuing capability"
        );

        Ok(capability)
    }

    /// Revoke a capability and all descendants in its delegation subtree.
    ///
    /// When a root capability is revoked, every capability whose
    /// `delegation_chain` contains the revoked ID will also be rejected
    /// on presentation (the kernel checks all chain entries against the
    /// revocation store).
    pub fn revoke_capability(&mut self, capability_id: &CapabilityId) -> Result<(), KernelError> {
        info!(capability_id = %capability_id, "revoking capability");
        let _ = self.revocation_store.revoke(capability_id)?;
        Ok(())
    }

    /// Read-only access to the receipt log.
    pub fn receipt_log(&self) -> &ReceiptLog {
        &self.receipt_log
    }

    pub fn child_receipt_log(&self) -> &ChildReceiptLog {
        &self.child_receipt_log
    }

    pub fn guard_count(&self) -> usize {
        self.guards.len()
    }

    pub fn drain_tool_server_events(&self) -> Vec<ToolServerEvent> {
        let mut events = Vec::new();
        for (server_id, server) in &self.tool_servers {
            match server.drain_events() {
                Ok(mut server_events) => events.append(&mut server_events),
                Err(error) => warn!(
                    server_id = %server_id,
                    reason = %error,
                    "failed to drain tool server events"
                ),
            }
        }
        events
    }

    pub fn register_session_pending_url_elicitation(
        &mut self,
        session_id: &SessionId,
        elicitation_id: impl Into<String>,
        related_task_id: Option<String>,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?
            .register_pending_url_elicitation(elicitation_id, related_task_id);
        Ok(())
    }

    pub fn register_session_required_url_elicitations(
        &mut self,
        session_id: &SessionId,
        elicitations: &[CreateElicitationOperation],
        related_task_id: Option<&str>,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?
            .register_required_url_elicitations(elicitations, related_task_id);
        Ok(())
    }

    pub fn queue_session_elicitation_completion(
        &mut self,
        session_id: &SessionId,
        elicitation_id: &str,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?
            .queue_elicitation_completion(elicitation_id);
        Ok(())
    }

    pub fn queue_session_late_event(
        &mut self,
        session_id: &SessionId,
        event: LateSessionEvent,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?.queue_late_event(event);
        Ok(())
    }

    pub fn queue_session_tool_server_event(
        &mut self,
        session_id: &SessionId,
        event: ToolServerEvent,
    ) -> Result<(), KernelError> {
        self.session_mut(session_id)?.queue_tool_server_event(event);
        Ok(())
    }

    pub fn queue_session_tool_server_events(
        &mut self,
        session_id: &SessionId,
    ) -> Result<(), KernelError> {
        let events = self.drain_tool_server_events();
        let session = self.session_mut(session_id)?;
        for event in events {
            session.queue_tool_server_event(event);
        }
        Ok(())
    }

    pub fn drain_session_late_events(
        &mut self,
        session_id: &SessionId,
    ) -> Result<Vec<LateSessionEvent>, KernelError> {
        Ok(self.session_mut(session_id)?.take_late_events())
    }

    pub fn ca_count(&self) -> usize {
        self.config.ca_public_keys.len()
    }

    pub fn public_key(&self) -> arc_core::PublicKey {
        self.config.keypair.public_key()
    }

    fn session_mut(&mut self, session_id: &SessionId) -> Result<&mut Session, KernelError> {
        self.sessions
            .get_mut(session_id)
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))
    }

    /// Verify the capability's signature against the trusted CA keys or the
    /// kernel's own key (for locally-issued capabilities).
    fn verify_capability_signature(&self, cap: &CapabilityToken) -> Result<(), String> {
        let kernel_pk = self.config.keypair.public_key();
        let mut trusted = self.config.ca_public_keys.clone();
        for authority_pk in self.capability_authority.trusted_public_keys() {
            if !trusted.contains(&authority_pk) {
                trusted.push(authority_pk);
            }
        }
        if !trusted.contains(&kernel_pk) {
            trusted.push(kernel_pk);
        }

        for pk in &trusted {
            if *pk == cap.issuer {
                return match cap.verify_signature() {
                    Ok(true) => Ok(()),
                    Ok(false) => Err("signature did not verify".to_string()),
                    Err(e) => Err(e.to_string()),
                };
            }
        }

        Err("signer public key not found among trusted CAs".to_string())
    }

    /// Check the revocation store for the capability and its entire
    /// delegation chain. If any ancestor is revoked, the capability is
    /// rejected.
    fn check_revocation(&self, cap: &CapabilityToken) -> Result<(), KernelError> {
        if self.revocation_store.is_revoked(&cap.id)? {
            return Err(KernelError::CapabilityRevoked(cap.id.clone()));
        }
        for link in &cap.delegation_chain {
            if self.revocation_store.is_revoked(&link.capability_id)? {
                return Err(KernelError::DelegationChainRevoked(
                    link.capability_id.clone(),
                ));
            }
        }
        Ok(())
    }

    /// Check and decrement the invocation budget for a capability.
    ///
    /// Returns `(matched_grant_index, Option<BudgetChargeResult>)`.
    /// The charge result is populated only for monetary grants.
    fn check_and_increment_budget(
        &mut self,
        cap: &CapabilityToken,
        matching_grants: &[MatchingGrant<'_>],
    ) -> Result<(usize, Option<BudgetChargeResult>), KernelError> {
        let mut saw_exhausted_budget = false;

        for matching in matching_grants {
            let grant = matching.grant;
            let has_monetary =
                grant.max_cost_per_invocation.is_some() || grant.max_total_cost.is_some();

            if has_monetary {
                // Use worst-case max_cost_per_invocation as the pre-execution debit.
                let cost_units = grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map(|m| m.units)
                    .unwrap_or(0);
                let currency = grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map(|m| m.currency.clone())
                    .or_else(|| grant.max_total_cost.as_ref().map(|m| m.currency.clone()))
                    .unwrap_or_else(|| "USD".to_string());
                let max_total = grant.max_total_cost.as_ref().map(|m| m.units);
                let max_per = grant.max_cost_per_invocation.as_ref().map(|m| m.units);
                let budget_total = max_total.unwrap_or(u64::MAX);

                let ok = self.budget_store.try_charge_cost(
                    &cap.id,
                    matching.index,
                    grant.max_invocations,
                    cost_units,
                    max_per,
                    max_total,
                )?;
                if ok {
                    // Read the new running total from the store so budget_remaining
                    // is computed against cumulative spend, not just this invocation.
                    let new_total_cost_charged = self
                        .budget_store
                        .get_usage(&cap.id, matching.index)
                        .ok()
                        .flatten()
                        .map(|record| record.total_cost_charged)
                        .unwrap_or(cost_units);
                    let charge = BudgetChargeResult {
                        grant_index: matching.index,
                        cost_charged: cost_units,
                        currency,
                        budget_total,
                        new_total_cost_charged,
                    };
                    return Ok((matching.index, Some(charge)));
                }
                saw_exhausted_budget = true;
            } else {
                // Non-monetary path: use try_increment as before.
                if self.budget_store.try_increment(
                    &cap.id,
                    matching.index,
                    grant.max_invocations,
                )? {
                    return Ok((matching.index, None));
                }
                saw_exhausted_budget = saw_exhausted_budget || grant.max_invocations.is_some();
            }
        }

        if saw_exhausted_budget {
            Err(KernelError::BudgetExhausted(cap.id.clone()))
        } else {
            // No matching grant had any limit -- allow with the first grant's index.
            let first_index = matching_grants.first().map(|m| m.index).unwrap_or(0);
            Ok((first_index, None))
        }
    }

    fn reverse_budget_charge(
        &mut self,
        capability_id: &str,
        charge: &BudgetChargeResult,
    ) -> Result<u64, KernelError> {
        self.budget_store.reverse_charge_cost(
            capability_id,
            charge.grant_index,
            charge.cost_charged,
        )?;
        Ok(self
            .budget_store
            .get_usage(capability_id, charge.grant_index)?
            .map(|record| record.total_cost_charged)
            .unwrap_or(0))
    }

    fn reduce_budget_charge_to_actual(
        &mut self,
        capability_id: &str,
        charge: &BudgetChargeResult,
        actual_cost_units: u64,
    ) -> Result<u64, KernelError> {
        if actual_cost_units >= charge.cost_charged {
            return Ok(charge.new_total_cost_charged);
        }

        self.budget_store.reduce_charge_cost(
            capability_id,
            charge.grant_index,
            charge.cost_charged - actual_cost_units,
        )?;
        Ok(self
            .budget_store
            .get_usage(capability_id, charge.grant_index)?
            .map(|record| record.total_cost_charged)
            .unwrap_or(actual_cost_units))
    }

    fn block_on_price_oracle<T>(
        &self,
        future: impl Future<Output = Result<T, PriceOracleError>>,
    ) -> Result<T, KernelError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => match handle.runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(|| {
                    handle
                        .block_on(future)
                        .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))
                }),
                tokio::runtime::RuntimeFlavor::CurrentThread => {
                    Err(KernelError::CrossCurrencyOracle(
                        "current-thread tokio runtime cannot synchronously resolve price oracles"
                            .to_string(),
                    ))
                }
                flavor => Err(KernelError::CrossCurrencyOracle(format!(
                    "unsupported tokio runtime flavor for synchronous oracle resolution: {flavor:?}"
                ))),
            },
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    KernelError::CrossCurrencyOracle(format!(
                        "failed to build synchronous oracle runtime: {error}"
                    ))
                })?
                .block_on(future)
                .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string())),
        }
    }

    fn resolve_cross_currency_cost(
        &self,
        reported_cost: &ToolInvocationCost,
        grant_currency: &str,
        timestamp: u64,
    ) -> Result<(u64, arc_core::web3::OracleConversionEvidence), KernelError> {
        let oracle =
            self.price_oracle
                .as_ref()
                .ok_or_else(|| KernelError::NoCrossCurrencyOracle {
                    base: reported_cost.currency.clone(),
                    quote: grant_currency.to_string(),
                })?;
        let rate =
            self.block_on_price_oracle(oracle.get_rate(&reported_cost.currency, grant_currency))?;
        let converted_units =
            convert_supported_units(reported_cost.units, &rate, rate.conversion_margin_bps)
                .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))?;
        let evidence = rate
            .to_conversion_evidence(
                reported_cost.units,
                reported_cost.currency.clone(),
                grant_currency.to_string(),
                converted_units,
                timestamp,
            )
            .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))?;
        Ok((converted_units, evidence))
    }

    fn ensure_registered_tool_target(&self, request: &ToolCallRequest) -> Result<(), KernelError> {
        self.tool_servers.get(&request.server_id).ok_or_else(|| {
            KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            ))
        })?;
        Ok(())
    }

    fn authorize_payment_if_needed(
        &self,
        request: &ToolCallRequest,
        charge_result: Option<&BudgetChargeResult>,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        let Some(charge) = charge_result else {
            return Ok(None);
        };
        let Some(adapter) = self.payment_adapter.as_ref() else {
            return Ok(None);
        };

        let governed = request
            .governed_intent
            .as_ref()
            .map(|intent| {
                intent
                    .binding_hash()
                    .map(|intent_hash| GovernedPaymentContext {
                        intent_id: intent.id.clone(),
                        intent_hash,
                        purpose: intent.purpose.clone(),
                        server_id: intent.server_id.clone(),
                        tool_name: intent.tool_name.clone(),
                        approval_token_id: request
                            .approval_token
                            .as_ref()
                            .map(|token| token.id.clone()),
                    })
                    .map_err(|error| {
                        PaymentError::RailError(format!(
                            "failed to hash governed intent for payment authorization: {error}"
                        ))
                    })
            })
            .transpose()?;
        let commerce = request.governed_intent.as_ref().and_then(|intent| {
            intent
                .commerce
                .as_ref()
                .map(|commerce| CommercePaymentContext {
                    seller: commerce.seller.clone(),
                    shared_payment_token_id: commerce.shared_payment_token_id.clone(),
                    max_amount: intent.max_amount.clone(),
                })
        });

        adapter
            .authorize(&PaymentAuthorizeRequest {
                amount_units: charge.cost_charged,
                currency: charge.currency.clone(),
                payer: request.agent_id.clone(),
                payee: request.server_id.clone(),
                reference: request.request_id.clone(),
                governed,
                commerce,
            })
            .map(Some)
    }

    fn governed_requirements(
        grant: &ToolGrant,
    ) -> (
        bool,
        Option<u64>,
        Option<String>,
        Option<RuntimeAssuranceTier>,
        Option<GovernedAutonomyTier>,
    ) {
        let mut intent_required = false;
        let mut approval_threshold_units = None;
        let mut seller = None;
        let mut minimum_runtime_assurance = None;
        let mut minimum_autonomy_tier = None;

        for constraint in &grant.constraints {
            match constraint {
                Constraint::GovernedIntentRequired => {
                    intent_required = true;
                }
                Constraint::RequireApprovalAbove { threshold_units } => {
                    approval_threshold_units = Some(
                        approval_threshold_units.map_or(*threshold_units, |current: u64| {
                            current.max(*threshold_units)
                        }),
                    );
                }
                Constraint::SellerExact(expected_seller) => {
                    seller = Some(expected_seller.clone());
                }
                Constraint::MinimumRuntimeAssurance(required_tier) => {
                    minimum_runtime_assurance = Some(
                        minimum_runtime_assurance
                            .map_or(*required_tier, |current: RuntimeAssuranceTier| {
                                current.max(*required_tier)
                            }),
                    );
                }
                Constraint::MinimumAutonomyTier(required_tier) => {
                    minimum_autonomy_tier = Some(
                        minimum_autonomy_tier
                            .map_or(*required_tier, |current: GovernedAutonomyTier| {
                                current.max(*required_tier)
                            }),
                    );
                }
                _ => {}
            }
        }

        (
            intent_required,
            approval_threshold_units,
            seller,
            minimum_runtime_assurance,
            minimum_autonomy_tier,
        )
    }

    fn verify_governed_approval_signature(
        &self,
        approval_token: &GovernedApprovalToken,
    ) -> Result<(), String> {
        let kernel_pk = self.config.keypair.public_key();
        let mut trusted = self.config.ca_public_keys.clone();
        for authority_pk in self.capability_authority.trusted_public_keys() {
            if !trusted.contains(&authority_pk) {
                trusted.push(authority_pk);
            }
        }
        if !trusted.contains(&kernel_pk) {
            trusted.push(kernel_pk);
        }

        for pk in &trusted {
            if *pk == approval_token.approver {
                return match approval_token.verify_signature() {
                    Ok(true) => Ok(()),
                    Ok(false) => Err("signature did not verify".to_string()),
                    Err(error) => Err(error.to_string()),
                };
            }
        }

        Err("approval signer public key not found among trusted authorities".to_string())
    }

    fn resolve_runtime_assurance(
        &self,
        attestation: &arc_core::capability::RuntimeAttestationEvidence,
        now: u64,
    ) -> Result<arc_core::capability::ResolvedRuntimeAssurance, KernelError> {
        attestation
            .resolve_effective_runtime_assurance(self.attestation_trust_policy.as_ref(), now)
            .map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "runtime attestation evidence rejected by trust policy: {error}"
                ))
            })
    }

    fn validate_runtime_assurance(
        &self,
        request: &ToolCallRequest,
        required_tier: RuntimeAssuranceTier,
        now: u64,
    ) -> Result<(), KernelError> {
        let attestation = request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.runtime_attestation.as_ref())
            .ok_or_else(|| {
                KernelError::GovernedTransactionDenied(format!(
                    "runtime attestation tier '{required_tier:?}' required by grant"
                ))
            })?;
        let resolved = self.resolve_runtime_assurance(attestation, now)?;

        if resolved.effective_tier < required_tier {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "runtime attestation tier '{:?}' is below required '{required_tier:?}'",
                resolved.effective_tier
            )));
        }

        Ok(())
    }

    fn validate_governed_approval_token(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        intent_hash: &str,
        approval_token: &GovernedApprovalToken,
        now: u64,
    ) -> Result<(), KernelError> {
        approval_token
            .validate_time(now)
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;

        if approval_token.request_id != request.request_id {
            return Err(KernelError::GovernedTransactionDenied(
                "approval token request binding does not match the tool call".to_string(),
            ));
        }

        if approval_token.governed_intent_hash != intent_hash {
            return Err(KernelError::GovernedTransactionDenied(
                "approval token intent binding does not match the governed intent".to_string(),
            ));
        }

        if approval_token.subject != cap.subject {
            return Err(KernelError::GovernedTransactionDenied(
                "approval token subject does not match the capability subject".to_string(),
            ));
        }

        if approval_token.decision != GovernedApprovalDecision::Approved {
            return Err(KernelError::GovernedTransactionDenied(
                "approval token does not approve the governed transaction".to_string(),
            ));
        }

        self.verify_governed_approval_signature(approval_token)
            .map_err(|reason| {
                KernelError::GovernedTransactionDenied(format!(
                    "approval token verification failed: {reason}"
                ))
            })
    }

    fn validate_metered_billing_context(
        intent: &arc_core::capability::GovernedTransactionIntent,
        charge_result: Option<&BudgetChargeResult>,
        now: u64,
    ) -> Result<(), KernelError> {
        let Some(metered) = intent.metered_billing.as_ref() else {
            return Ok(());
        };

        let quote = &metered.quote;
        if quote.quote_id.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing quote_id must not be empty".to_string(),
            ));
        }
        if quote.provider.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing provider must not be empty".to_string(),
            ));
        }
        if quote.billing_unit.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing unit must not be empty".to_string(),
            ));
        }
        if quote.quoted_units == 0 {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing quoted_units must be greater than zero".to_string(),
            ));
        }
        if quote
            .expires_at
            .is_some_and(|expires_at| expires_at <= quote.issued_at)
        {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing quote expires_at must be after issued_at".to_string(),
            ));
        }
        if quote.expires_at.is_some() && !quote.is_valid_at(now) {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing quote is missing or expired".to_string(),
            ));
        }
        if metered.max_billed_units == Some(0) {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing max_billed_units must be greater than zero when present"
                    .to_string(),
            ));
        }
        if metered
            .max_billed_units
            .is_some_and(|max_billed_units| max_billed_units < quote.quoted_units)
        {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing max_billed_units cannot be lower than quote.quoted_units"
                    .to_string(),
            ));
        }
        if let Some(intent_amount) = intent.max_amount.as_ref() {
            if intent_amount.currency != quote.quoted_cost.currency {
                return Err(KernelError::GovernedTransactionDenied(
                    "metered billing quote currency does not match governed intent currency"
                        .to_string(),
                ));
            }
        }
        if let Some(charge) = charge_result {
            if charge.currency != quote.quoted_cost.currency {
                return Err(KernelError::GovernedTransactionDenied(
                    "metered billing quote currency does not match the grant currency".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn validate_governed_call_chain_context(
        request: &ToolCallRequest,
        intent: &arc_core::capability::GovernedTransactionIntent,
    ) -> Result<(), KernelError> {
        let Some(call_chain) = intent.call_chain.as_ref() else {
            return Ok(());
        };

        if call_chain.chain_id.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.chain_id must not be empty".to_string(),
            ));
        }
        if call_chain.parent_request_id.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.parent_request_id must not be empty".to_string(),
            ));
        }
        if call_chain.parent_request_id == request.request_id {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.parent_request_id must not equal the current request_id"
                    .to_string(),
            ));
        }
        if call_chain.origin_subject.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.origin_subject must not be empty".to_string(),
            ));
        }
        if call_chain.delegator_subject.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.delegator_subject must not be empty".to_string(),
            ));
        }
        if call_chain
            .parent_receipt_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.parent_receipt_id must not be empty when present".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_governed_autonomy_bond(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        bond_id: &str,
        now: u64,
    ) -> Result<(), KernelError> {
        let store = self.receipt_store.as_deref().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "delegation bond lookup unavailable because no receipt store is configured"
                    .to_string(),
            )
        })?;
        let bond_row = store
            .resolve_credit_bond(bond_id)
            .map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "failed to resolve delegation bond `{bond_id}`: {error}"
                ))
            })?
            .ok_or_else(|| {
                KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` was not found"
                ))
            })?;

        let signed_bond = &bond_row.bond;
        let signature_valid = signed_bond.verify_signature().map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` failed signature verification: {error}"
            ))
        })?;
        if !signature_valid {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` failed signature verification"
            )));
        }
        if bond_row.lifecycle_state != CreditBondLifecycleState::Active {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` is not active"
            )));
        }
        if signed_bond.body.expires_at <= now {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` is expired"
            )));
        }

        let report = &signed_bond.body.report;
        if !report.support_boundary.autonomy_gating_supported {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` does not advertise runtime autonomy gating support"
            )));
        }
        if !report.prerequisites.active_facility_met {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` is missing an active granted facility"
            )));
        }
        if !report.prerequisites.runtime_assurance_met {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` was issued without satisfied runtime assurance prerequisites"
            )));
        }
        if report.prerequisites.certification_required && !report.prerequisites.certification_met {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` requires an active certification record"
            )));
        }
        match report.disposition {
            CreditBondDisposition::Lock | CreditBondDisposition::Hold => {}
            CreditBondDisposition::Release => {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` is released and does not back autonomous execution"
                )));
            }
            CreditBondDisposition::Impair => {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` is impaired and does not back autonomous execution"
                )));
            }
        }

        let subject_key = cap.subject.to_hex();
        let mut bound_to_subject_or_capability = false;
        if let Some(bound_subject) = report.filters.agent_subject.as_deref() {
            if bound_subject != subject_key {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` subject binding does not match the capability subject"
                )));
            }
            bound_to_subject_or_capability = true;
        }
        if let Some(bound_capability_id) = report.filters.capability_id.as_deref() {
            if bound_capability_id != cap.id {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` capability binding does not match the executing capability"
                )));
            }
            bound_to_subject_or_capability = true;
        }
        if !bound_to_subject_or_capability {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` must be bound to the current capability or subject"
            )));
        }

        let Some(bound_server) = report.filters.tool_server.as_deref() else {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` must be scoped to the current tool server"
            )));
        };
        if bound_server != request.server_id {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` tool server scope does not match the governed request"
            )));
        }
        if let Some(bound_tool) = report.filters.tool_name.as_deref() {
            if bound_tool != request.tool_name {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` tool scope does not match the governed request"
                )));
            }
        }

        Ok(())
    }

    fn validate_governed_autonomy(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        intent: &arc_core::capability::GovernedTransactionIntent,
        minimum_autonomy_tier: Option<GovernedAutonomyTier>,
        now: u64,
    ) -> Result<(), KernelError> {
        let autonomy = match (intent.autonomy.as_ref(), minimum_autonomy_tier) {
            (None, None) => return Ok(()),
            (Some(autonomy), _) => autonomy,
            (None, Some(required_tier)) => {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "governed autonomy tier '{required_tier:?}' required by grant"
                )));
            }
        };

        if let Some(required_tier) = minimum_autonomy_tier {
            if autonomy.tier < required_tier {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "governed autonomy tier '{:?}' is below required '{required_tier:?}'",
                    autonomy.tier
                )));
            }
        }

        let bond_id = autonomy
            .delegation_bond_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());

        if !autonomy.tier.requires_delegation_bond() {
            if bond_id.is_some() {
                return Err(KernelError::GovernedTransactionDenied(
                    "direct governed autonomy tier must not attach a delegation bond".to_string(),
                ));
            }
            return Ok(());
        }

        if autonomy.tier.requires_call_chain() && intent.call_chain.is_none() {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "governed autonomy tier '{:?}' requires delegated call-chain context",
                autonomy.tier
            )));
        }

        let required_runtime_assurance = autonomy.tier.minimum_runtime_assurance();
        self.validate_runtime_assurance(request, required_runtime_assurance, now)?;

        let bond_id = bond_id.ok_or_else(|| {
            KernelError::GovernedTransactionDenied(format!(
                "governed autonomy tier '{:?}' requires a delegation bond attachment",
                autonomy.tier
            ))
        })?;
        self.validate_governed_autonomy_bond(request, cap, bond_id, now)
    }

    fn validate_governed_transaction(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        grant: &ToolGrant,
        charge_result: Option<&BudgetChargeResult>,
        now: u64,
    ) -> Result<(), KernelError> {
        let (
            intent_required,
            approval_threshold_units,
            required_seller,
            minimum_runtime_assurance,
            minimum_autonomy_tier,
        ) = Self::governed_requirements(grant);
        let governed_request_present =
            request.governed_intent.is_some() || request.approval_token.is_some();

        if !intent_required
            && approval_threshold_units.is_none()
            && required_seller.is_none()
            && minimum_runtime_assurance.is_none()
            && minimum_autonomy_tier.is_none()
            && !governed_request_present
        {
            return Ok(());
        }

        let intent = request.governed_intent.as_ref().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "governed transaction intent required by grant or request".to_string(),
            )
        })?;

        if intent.server_id != request.server_id || intent.tool_name != request.tool_name {
            return Err(KernelError::GovernedTransactionDenied(
                "governed transaction intent target does not match the tool call".to_string(),
            ));
        }

        if let Some(attestation) = intent.runtime_attestation.as_ref() {
            self.resolve_runtime_assurance(attestation, now)?;
        }

        Self::validate_governed_call_chain_context(request, intent)?;

        let intent_hash = intent.binding_hash().map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "failed to hash governed transaction intent: {error}"
            ))
        })?;
        let commerce = intent.commerce.as_ref();

        if let Some(commerce) = commerce {
            if commerce.seller.trim().is_empty() {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed commerce seller scope must not be empty".to_string(),
                ));
            }
            if commerce.shared_payment_token_id.trim().is_empty() {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed commerce approval requires a shared payment token reference"
                        .to_string(),
                ));
            }
            if intent.max_amount.is_none() {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed commerce approval requires an explicit max_amount bound".to_string(),
                ));
            }
        }

        if let Some(required_seller) = required_seller.as_deref() {
            let commerce = commerce.ok_or_else(|| {
                KernelError::GovernedTransactionDenied(
                    "seller-scoped governed request requires commerce approval context".to_string(),
                )
            })?;
            if commerce.seller != required_seller {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed commerce seller does not match the grant seller scope".to_string(),
                ));
            }
        }

        if let Some(required_tier) = minimum_runtime_assurance {
            self.validate_runtime_assurance(request, required_tier, now)?;
        }
        self.validate_governed_autonomy(request, cap, intent, minimum_autonomy_tier, now)?;

        Self::validate_metered_billing_context(intent, charge_result, now)?;

        if let (Some(intent_amount), Some(charge)) = (intent.max_amount.as_ref(), charge_result) {
            if intent_amount.currency != charge.currency {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed intent currency does not match the grant currency".to_string(),
                ));
            }
            if intent_amount.units < charge.cost_charged {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed intent amount is lower than the provisional invocation charge"
                        .to_string(),
                ));
            }
        }

        let requested_units = charge_result
            .map(|charge| charge.cost_charged)
            .or_else(|| intent.max_amount.as_ref().map(|amount| amount.units))
            .unwrap_or(0);
        let approval_required = approval_threshold_units
            .map(|threshold_units| requested_units >= threshold_units)
            .unwrap_or(false);

        if let Some(approval_token) = request.approval_token.as_ref() {
            self.validate_governed_approval_token(request, cap, &intent_hash, approval_token, now)?;
        } else if approval_required {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "approval token required for governed transaction intent {}",
                intent.id
            )));
        }

        Ok(())
    }

    fn unwind_aborted_monetary_invocation(
        &mut self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        charge_result: Option<&BudgetChargeResult>,
        payment_authorization: Option<&PaymentAuthorization>,
    ) -> Result<(), KernelError> {
        let Some(charge) = charge_result else {
            return Ok(());
        };

        if let Some(authorization) = payment_authorization {
            let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "payment authorization present without configured adapter".to_string(),
                )
            })?;
            let unwind_result = if authorization.settled {
                adapter.refund(
                    &authorization.authorization_id,
                    charge.cost_charged,
                    &charge.currency,
                    &request.request_id,
                )
            } else {
                adapter.release(&authorization.authorization_id, &request.request_id)
            };
            if let Err(error) = unwind_result {
                return Err(KernelError::Internal(format!(
                    "failed to unwind payment after aborted tool invocation: {error}"
                )));
            }
        }

        self.reverse_budget_charge(&cap.id, charge)?;
        Ok(())
    }

    fn record_observed_capability_snapshot(
        &mut self,
        capability: &CapabilityToken,
    ) -> Result<(), KernelError> {
        let parent_capability_id = capability
            .delegation_chain
            .last()
            .map(|link| link.capability_id.as_str());
        if let Some(store) = self.receipt_store.as_deref_mut() {
            store.record_capability_snapshot(capability, parent_capability_id)?;
        }
        Ok(())
    }

    /// Verify a DPoP proof carried on the request against the capability.
    ///
    /// Fails closed: if no proof is present, or if the nonce store / config is
    /// absent (misconfigured kernel), or if verification fails, the call is denied.
    fn verify_dpop_for_request(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
    ) -> Result<(), KernelError> {
        let proof = request.dpop_proof.as_ref().ok_or_else(|| {
            KernelError::DpopVerificationFailed(
                "grant requires DPoP proof but none was provided".to_string(),
            )
        })?;

        let nonce_store = self.dpop_nonce_store.as_ref().ok_or_else(|| {
            KernelError::DpopVerificationFailed(
                "kernel DPoP nonce store not configured".to_string(),
            )
        })?;

        let config = self.dpop_config.as_ref().ok_or_else(|| {
            KernelError::DpopVerificationFailed("kernel DPoP config not configured".to_string())
        })?;

        // Compute action hash from the serialized arguments.
        let args_bytes = canonical_json_bytes(&request.arguments).map_err(|e| {
            KernelError::DpopVerificationFailed(format!(
                "failed to serialize arguments for action hash: {e}"
            ))
        })?;
        let action_hash = sha256_hex(&args_bytes);

        dpop::verify_dpop_proof(
            proof,
            cap,
            &request.server_id,
            &request.tool_name,
            &action_hash,
            nonce_store,
            config,
        )
    }

    /// Run all registered guards. Fail-closed: any error from a guard is
    /// treated as a deny.
    fn run_guards(
        &self,
        request: &ToolCallRequest,
        scope: &ArcScope,
        session_filesystem_roots: Option<&[String]>,
        matched_grant_index: Option<usize>,
    ) -> Result<(), KernelError> {
        let ctx = GuardContext {
            request,
            scope,
            agent_id: &request.agent_id,
            server_id: &request.server_id,
            session_filesystem_roots,
            matched_grant_index,
        };

        for guard in &self.guards {
            match guard.evaluate(&ctx) {
                Ok(Verdict::Allow) => {
                    debug!(guard = guard.name(), "guard passed");
                }
                Ok(Verdict::Deny) => {
                    return Err(KernelError::GuardDenied(format!(
                        "guard \"{}\" denied the request",
                        guard.name()
                    )));
                }
                Err(e) => {
                    // Fail closed: guard errors are treated as denials.
                    return Err(KernelError::GuardDenied(format!(
                        "guard \"{}\" error (fail-closed): {e}",
                        guard.name()
                    )));
                }
            }
        }

        Ok(())
    }

    /// Forward the validated request and optionally report actual invocation cost.
    ///
    /// When `has_monetary_grant` is true, calls `invoke_with_cost` so the server
    /// can report the actual cost incurred. For non-monetary grants the standard
    /// dispatch path is used and cost is always None.
    fn dispatch_tool_call_with_cost(
        &self,
        request: &ToolCallRequest,
        has_monetary_grant: bool,
    ) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
        let server = self.tool_servers.get(&request.server_id).ok_or_else(|| {
            KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            ))
        })?;

        // Try streaming first regardless of monetary mode.
        if let Some(stream) =
            server.invoke_stream(&request.tool_name, request.arguments.clone(), None)?
        {
            return Ok((ToolServerOutput::Stream(stream), None));
        }

        if has_monetary_grant {
            let (value, cost) =
                server.invoke_with_cost(&request.tool_name, request.arguments.clone(), None)?;
            Ok((ToolServerOutput::Value(value), cost))
        } else {
            let value = server.invoke(&request.tool_name, request.arguments.clone(), None)?;
            Ok((ToolServerOutput::Value(value), None))
        }
    }

    /// Build a denial response, including FinancialReceiptMetadata when the
    /// denial reason is monetary budget exhaustion.
    fn build_monetary_deny_response(
        &mut self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matching_grants: &[MatchingGrant<'_>],
        cap: &CapabilityToken,
    ) -> Result<ToolCallResponse, KernelError> {
        // Look for a monetary grant among the matching candidates to populate metadata.
        let monetary_grant = matching_grants.iter().find(|m| {
            m.grant.max_cost_per_invocation.is_some() || m.grant.max_total_cost.is_some()
        });

        if let Some(mg) = monetary_grant {
            let grant = mg.grant;
            let currency = grant
                .max_cost_per_invocation
                .as_ref()
                .map(|m| m.currency.clone())
                .or_else(|| grant.max_total_cost.as_ref().map(|m| m.currency.clone()))
                .unwrap_or_else(|| "USD".to_string());
            let budget_total = grant
                .max_total_cost
                .as_ref()
                .map(|m| m.units)
                .unwrap_or(u64::MAX);
            let attempted_cost = grant
                .max_cost_per_invocation
                .as_ref()
                .map(|m| m.units)
                .unwrap_or(0);
            let delegation_depth = cap.delegation_chain.len() as u32;
            let root_budget_holder = cap.issuer.to_hex();
            let (payment_reference, settlement_status) =
                ReceiptSettlement::not_applicable().into_receipt_parts();

            let financial_meta = FinancialReceiptMetadata {
                grant_index: mg.index as u32,
                cost_charged: 0,
                currency,
                budget_remaining: 0,
                budget_total,
                delegation_depth,
                root_budget_holder,
                payment_reference,
                settlement_status,
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost: Some(attempted_cost),
            };

            let metadata = merge_metadata_objects(
                merge_metadata_objects(
                    receipt_attribution_metadata(cap, Some(mg.index)),
                    Some(serde_json::json!({ "financial": financial_meta })),
                ),
                governed_request_metadata(
                    request,
                    self.attestation_trust_policy.as_ref(),
                    timestamp,
                )?,
            );
            let receipt_content = receipt_content_for_output(None, None)?;

            let action =
                ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
                    KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
                })?;

            let receipt = self.build_and_sign_receipt(ReceiptParams {
                capability_id: &cap.id,
                tool_name: &request.tool_name,
                server_id: &request.server_id,
                decision: Decision::Deny {
                    reason: reason.to_string(),
                    guard: "kernel".to_string(),
                },
                action,
                content_hash: receipt_content.content_hash,
                metadata,
                timestamp,
            })?;

            self.record_arc_receipt(&receipt)?;

            return Ok(ToolCallResponse {
                request_id: request.request_id.clone(),
                verdict: Verdict::Deny,
                output: None,
                reason: Some(reason.to_string()),
                terminal_state: OperationTerminalState::Completed,
                receipt,
            });
        }

        // No monetary grant -- standard deny.
        self.build_deny_response(request, reason, timestamp, None)
    }

    fn build_pre_execution_monetary_deny_response(
        &mut self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        charge: &BudgetChargeResult,
        total_cost_charged_after_release: u64,
        cap: &CapabilityToken,
    ) -> Result<ToolCallResponse, KernelError> {
        let delegation_depth = cap.delegation_chain.len() as u32;
        let root_budget_holder = cap.issuer.to_hex();
        let (payment_reference, settlement_status) =
            ReceiptSettlement::not_applicable().into_receipt_parts();
        let budget_remaining = charge
            .budget_total
            .saturating_sub(total_cost_charged_after_release);

        let financial_meta = FinancialReceiptMetadata {
            grant_index: charge.grant_index as u32,
            cost_charged: 0,
            currency: charge.currency.clone(),
            budget_remaining,
            budget_total: charge.budget_total,
            delegation_depth,
            root_budget_holder,
            payment_reference,
            settlement_status,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: Some(charge.cost_charged),
        };

        let receipt_content = receipt_content_for_output(None, None)?;
        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "kernel".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    receipt_attribution_metadata(cap, Some(charge.grant_index)),
                    Some(serde_json::json!({ "financial": financial_meta })),
                ),
                governed_request_metadata(
                    request,
                    self.attestation_trust_policy.as_ref(),
                    timestamp,
                )?,
            ),
            timestamp,
        })?;

        self.record_arc_receipt(&receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Completed,
            receipt,
        })
    }

    fn finalize_tool_output(
        &mut self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
    ) -> Result<ToolCallResponse, KernelError> {
        match self.apply_stream_limits(output, elapsed)? {
            ToolServerOutput::Value(value) => self.build_allow_response(
                request,
                ToolCallOutput::Value(value),
                timestamp,
                Some(matched_grant_index),
            ),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => self
                .build_allow_response(
                    request,
                    ToolCallOutput::Stream(stream),
                    timestamp,
                    Some(matched_grant_index),
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => self
                .build_incomplete_response_with_output(
                    request,
                    Some(ToolCallOutput::Stream(stream)),
                    &reason,
                    timestamp,
                    Some(matched_grant_index),
                ),
        }
    }

    /// Finalize a tool output with optional monetary metadata injected into the receipt.
    #[allow(clippy::too_many_arguments)]
    fn finalize_tool_output_with_cost(
        &mut self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
        charge_result: Option<BudgetChargeResult>,
        reported_cost: Option<ToolInvocationCost>,
        payment_authorization: Option<PaymentAuthorization>,
        cap: &CapabilityToken,
    ) -> Result<ToolCallResponse, KernelError> {
        let Some(charge) = charge_result else {
            // Non-monetary grant: use normal path.
            return self.finalize_tool_output(
                request,
                output,
                elapsed,
                timestamp,
                matched_grant_index,
            );
        };

        let reported_cost_ref = reported_cost.as_ref();
        let mut oracle_evidence = None;
        let mut cross_currency_note = None;
        let (actual_cost, cross_currency_failed) =
            if let Some(cost) = reported_cost_ref.filter(|cost| cost.currency != charge.currency) {
                match self.resolve_cross_currency_cost(cost, &charge.currency, timestamp) {
                    Ok((converted_units, evidence)) => {
                        oracle_evidence = Some(evidence);
                        cross_currency_note = Some(serde_json::json!({
                            "oracle_conversion": {
                                "status": "applied",
                                "reported_currency": cost.currency,
                                "grant_currency": charge.currency,
                                "reported_units": cost.units,
                                "converted_units": converted_units
                            }
                        }));
                        (converted_units, false)
                    }
                    Err(error) => {
                        warn!(
                            request_id = %request.request_id,
                            reported_currency = %cost.currency,
                            charged_currency = %charge.currency,
                            reason = %error,
                            "cross-currency reconciliation failed; keeping provisional charge"
                        );
                        cross_currency_note = Some(serde_json::json!({
                            "oracle_conversion": {
                                "status": "failed",
                                "reported_currency": cost.currency,
                                "grant_currency": charge.currency,
                                "reported_units": cost.units,
                                "provisional_units": charge.cost_charged,
                                "reason": error.to_string()
                            }
                        }));
                        (charge.cost_charged, true)
                    }
                }
            } else {
                (
                    reported_cost_ref
                        .map(|cost| cost.units)
                        .unwrap_or(charge.cost_charged),
                    false,
                )
            };
        let keep_provisional_charge = cross_currency_failed
            || matches!(payment_authorization.as_ref(), Some(authorization) if authorization.settled);
        let cost_overrun =
            !cross_currency_failed && actual_cost > charge.cost_charged && charge.cost_charged > 0;

        if cost_overrun {
            warn!(
                request_id = %request.request_id,
                reported = actual_cost,
                charged = charge.cost_charged,
                "tool server reported cost exceeds max_cost_per_invocation; settlement_status=failed"
            );
        }

        let running_total_cost_charged = if keep_provisional_charge || cost_overrun {
            charge.new_total_cost_charged
        } else {
            self.reduce_budget_charge_to_actual(&cap.id, &charge, actual_cost)?
        };

        let payment_result = if let Some(authorization) = payment_authorization.as_ref() {
            if authorization.settled || cross_currency_failed || cost_overrun {
                None
            } else {
                let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                    KernelError::Internal(
                        "payment authorization present without configured adapter".to_string(),
                    )
                })?;
                Some(if actual_cost == 0 {
                    adapter.release(&authorization.authorization_id, &request.request_id)
                } else {
                    adapter.capture(
                        &authorization.authorization_id,
                        actual_cost,
                        &charge.currency,
                        &request.request_id,
                    )
                })
            }
        } else {
            None
        };

        let settlement = if cross_currency_failed || cost_overrun {
            ReceiptSettlement {
                payment_reference: payment_authorization
                    .as_ref()
                    .map(|authorization| authorization.authorization_id.clone()),
                settlement_status: SettlementStatus::Failed,
            }
        } else if let Some(authorization) = payment_authorization.as_ref() {
            if authorization.settled {
                ReceiptSettlement::from_authorization(authorization)
            } else if let Some(payment_result) = payment_result.as_ref() {
                match payment_result {
                    Ok(result) => ReceiptSettlement::from_payment_result(result),
                    Err(error) => {
                        warn!(
                            request_id = %request.request_id,
                            reason = %error,
                            "post-execution payment settlement failed"
                        );
                        ReceiptSettlement {
                            payment_reference: Some(authorization.authorization_id.clone()),
                            settlement_status: SettlementStatus::Failed,
                        }
                    }
                }
            } else {
                warn!(
                    request_id = %request.request_id,
                    authorization_id = %authorization.authorization_id,
                    "unsettled authorization completed without a payment result"
                );
                ReceiptSettlement {
                    payment_reference: Some(authorization.authorization_id.clone()),
                    settlement_status: SettlementStatus::Failed,
                }
            }
        } else {
            ReceiptSettlement::settled()
        };
        let recorded_cost = if keep_provisional_charge && !cross_currency_failed && !cost_overrun {
            charge.cost_charged
        } else {
            actual_cost
        };

        // Use the running total charged so far (not just this invocation) so that
        // budget_remaining reflects cumulative spend across all prior invocations.
        let budget_remaining = charge
            .budget_total
            .saturating_sub(running_total_cost_charged);
        let delegation_depth = cap.delegation_chain.len() as u32;
        let root_budget_holder = cap.issuer.to_hex();
        let (payment_reference, settlement_status) = settlement.into_receipt_parts();
        let payment_breakdown = payment_authorization.as_ref().map(|authorization| {
            serde_json::json!({
                "payment": {
                    "authorization_id": authorization.authorization_id,
                    "adapter_metadata": authorization.metadata,
                    "preauthorized_units": charge.cost_charged,
                    "recorded_units": recorded_cost
                }
            })
        });

        let financial_meta = FinancialReceiptMetadata {
            grant_index: charge.grant_index as u32,
            cost_charged: recorded_cost,
            currency: charge.currency.clone(),
            budget_remaining,
            budget_total: charge.budget_total,
            delegation_depth,
            root_budget_holder,
            payment_reference,
            settlement_status,
            cost_breakdown: merge_metadata_objects(
                merge_metadata_objects(
                    reported_cost_ref.and_then(|cost| cost.breakdown.clone()),
                    payment_breakdown,
                ),
                cross_currency_note,
            ),
            oracle_evidence,
            attempted_cost: None,
        };

        let limited_output = self.apply_stream_limits(output, elapsed)?;
        let tool_call_output = match &limited_output {
            ToolServerOutput::Value(v) => ToolCallOutput::Value(v.clone()),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(s)) => {
                ToolCallOutput::Stream(s.clone())
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, .. }) => {
                ToolCallOutput::Stream(stream.clone())
            }
        };

        let financial_json = Some(serde_json::json!({ "financial": financial_meta }));

        match limited_output {
            ToolServerOutput::Value(_)
            | ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)) => self
                .build_allow_response_with_metadata(
                    request,
                    tool_call_output,
                    timestamp,
                    Some(charge.grant_index),
                    financial_json,
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { reason, .. }) => self
                .build_incomplete_response_with_output_and_metadata(
                    request,
                    Some(tool_call_output),
                    &reason,
                    timestamp,
                    Some(charge.grant_index),
                    financial_json,
                ),
        }
    }

    fn apply_stream_limits(
        &self,
        output: ToolServerOutput,
        elapsed: Duration,
    ) -> Result<ToolServerOutput, KernelError> {
        let ToolServerOutput::Stream(stream_result) = output else {
            return Ok(output);
        };

        let duration_limit = Duration::from_secs(self.config.max_stream_duration_secs);
        let duration_exceeded =
            self.config.max_stream_duration_secs > 0 && elapsed > duration_limit;

        let (stream, base_reason) = match stream_result {
            ToolServerStreamResult::Complete(stream) => (stream, None),
            ToolServerStreamResult::Incomplete { stream, reason } => (stream, Some(reason)),
        };

        let (stream, total_bytes, truncated) =
            truncate_stream_to_byte_limit(&stream, self.config.max_stream_total_bytes)?;

        let limit_reason = if truncated {
            Some(format!(
                "ARC_SERVER_STREAM_LIMIT: stream exceeded max total bytes of {}",
                self.config.max_stream_total_bytes
            ))
        } else if duration_exceeded {
            Some(format!(
                "ARC_SERVER_STREAM_LIMIT: stream exceeded max duration of {}s",
                self.config.max_stream_duration_secs
            ))
        } else {
            None
        };

        if let Some(reason) = limit_reason {
            warn!(
                request_bytes = total_bytes,
                elapsed_ms = elapsed.as_millis(),
                "stream output exceeded configured limits"
            );
            return Ok(ToolServerOutput::Stream(
                ToolServerStreamResult::Incomplete { stream, reason },
            ));
        }

        if let Some(reason) = base_reason {
            Ok(ToolServerOutput::Stream(
                ToolServerStreamResult::Incomplete { stream, reason },
            ))
        } else {
            Ok(ToolServerOutput::Stream(ToolServerStreamResult::Complete(
                stream,
            )))
        }
    }

    /// Build a denial response with a signed receipt.
    fn build_deny_response(
        &mut self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(None, None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "kernel".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    receipt_content.metadata,
                    governed_request_metadata(
                        request,
                        self.attestation_trust_policy.as_ref(),
                        timestamp,
                    )?,
                ),
                receipt_attribution_metadata(cap, matched_grant_index),
            ),
            timestamp,
        })?;

        self.record_arc_receipt(&receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Completed,
            receipt,
        })
    }

    /// Build a cancellation response with a signed cancelled receipt.
    fn build_cancelled_response(
        &mut self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(None, None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Cancelled {
                reason: reason.to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    receipt_content.metadata,
                    governed_request_metadata(
                        request,
                        self.attestation_trust_policy.as_ref(),
                        timestamp,
                    )?,
                ),
                receipt_attribution_metadata(cap, matched_grant_index),
            ),
            timestamp,
        })?;

        self.record_arc_receipt(&receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Cancelled {
                reason: reason.to_string(),
            },
            receipt,
        })
    }

    /// Build an incomplete response with a signed incomplete receipt.
    fn build_incomplete_response(
        &mut self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_incomplete_response_with_output(
            request,
            None,
            reason,
            timestamp,
            matched_grant_index,
        )
    }

    /// Build an incomplete response with optional partial output and a signed incomplete receipt.
    fn build_incomplete_response_with_output(
        &mut self,
        request: &ToolCallRequest,
        output: Option<ToolCallOutput>,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_incomplete_response_with_output_and_metadata(
            request,
            output,
            reason,
            timestamp,
            matched_grant_index,
            None,
        )
    }

    fn build_incomplete_response_with_output_and_metadata(
        &mut self,
        request: &ToolCallRequest,
        output: Option<ToolCallOutput>,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(output.as_ref(), None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Incomplete {
                reason: reason.to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(
                        receipt_content.metadata,
                        governed_request_metadata(
                            request,
                            self.attestation_trust_policy.as_ref(),
                            timestamp,
                        )?,
                    ),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index),
            ),
            timestamp,
        })?;

        self.record_arc_receipt(&receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Incomplete {
                reason: reason.to_string(),
            },
            receipt,
        })
    }

    fn build_allow_response(
        &mut self,
        request: &ToolCallRequest,
        output: ToolCallOutput,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_allow_response_with_metadata(
            request,
            output,
            timestamp,
            matched_grant_index,
            None,
        )
    }

    fn build_allow_response_with_metadata(
        &mut self,
        request: &ToolCallRequest,
        output: ToolCallOutput,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let expected_chunks = match &output {
            ToolCallOutput::Stream(stream) => Some(stream.chunk_count()),
            ToolCallOutput::Value(_) => None,
        };
        let receipt_content = receipt_content_for_output(Some(&output), expected_chunks)?;

        // Merge extra_metadata (e.g. "financial") into receipt_content.metadata.
        let metadata = merge_metadata_objects(
            merge_metadata_objects(
                merge_metadata_objects(
                    receipt_content.metadata,
                    governed_request_metadata(
                        request,
                        self.attestation_trust_policy.as_ref(),
                        timestamp,
                    )?,
                ),
                extra_metadata,
            ),
            receipt_attribution_metadata(cap, matched_grant_index),
        );

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Allow,
            action,
            content_hash: receipt_content.content_hash,
            metadata,
            timestamp,
        })?;

        self.record_arc_receipt(&receipt)?;

        info!(
            request_id = %request.request_id,
            tool = %request.tool_name,
            receipt_id = %receipt.id,
            "tool call allowed"
        );

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Allow,
            output: Some(output),
            reason: None,
            terminal_state: OperationTerminalState::Completed,
            receipt,
        })
    }

    /// Build and sign a receipt from a `ReceiptParams` descriptor.
    fn build_and_sign_receipt(
        &mut self,
        params: ReceiptParams<'_>,
    ) -> Result<ArcReceipt, KernelError> {
        let body = ArcReceiptBody {
            id: next_receipt_id("rcpt"),
            timestamp: params.timestamp,
            capability_id: params.capability_id.to_string(),
            tool_server: params.server_id.to_string(),
            tool_name: params.tool_name.to_string(),
            action: params.action,
            decision: params.decision,
            content_hash: params.content_hash,
            policy_hash: self.config.policy_hash.clone(),
            evidence: vec![],
            metadata: params.metadata,
            kernel_key: self.config.keypair.public_key(),
        };

        ArcReceipt::sign(body, &self.config.keypair)
            .map_err(|e| KernelError::ReceiptSigningFailed(e.to_string()))
    }

    fn record_arc_receipt(&mut self, receipt: &ArcReceipt) -> Result<(), KernelError> {
        if let Some(store) = self.receipt_store.as_deref_mut() {
            let seq = store
                .append_arc_receipt_returning_seq(receipt)?
                .unwrap_or(0);

            // Trigger a Merkle checkpoint if we've accumulated enough receipts.
            if seq > 0
                && self.checkpoint_batch_size > 0
                && (seq - self.last_checkpoint_seq) >= self.checkpoint_batch_size
            {
                self.maybe_trigger_checkpoint(seq)?;
            }
        }
        self.receipt_log.append(receipt.clone());
        Ok(())
    }

    /// Trigger a Merkle checkpoint for all receipts in [last_checkpoint_seq+1, batch_end_seq].
    fn maybe_trigger_checkpoint(&mut self, batch_end_seq: u64) -> Result<(), KernelError> {
        let batch_start_seq = self.last_checkpoint_seq + 1;

        let Some(store) = self.receipt_store.as_deref_mut() else {
            return Ok(());
        };

        let receipt_bytes_with_seqs = store
            .receipts_canonical_bytes_range(batch_start_seq, batch_end_seq)
            .map_err(KernelError::ReceiptPersistence)?;

        if receipt_bytes_with_seqs.is_empty() {
            return Ok(());
        }

        let receipt_bytes: Vec<Vec<u8>> = receipt_bytes_with_seqs
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect();

        self.checkpoint_seq_counter += 1;
        let checkpoint_seq = self.checkpoint_seq_counter;

        let checkpoint = checkpoint::build_checkpoint(
            checkpoint_seq,
            batch_start_seq,
            batch_end_seq,
            &receipt_bytes,
            &self.config.keypair,
        )
        .map_err(|e| KernelError::Internal(format!("checkpoint build failed: {e}")))?;

        store
            .store_checkpoint(&checkpoint)
            .map_err(KernelError::ReceiptPersistence)?;

        self.last_checkpoint_seq = batch_end_seq;
        Ok(())
    }

    fn record_child_receipts(
        &mut self,
        receipts: Vec<ChildRequestReceipt>,
    ) -> Result<(), KernelError> {
        for receipt in receipts {
            if let Some(store) = self.receipt_store.as_deref_mut() {
                store.append_child_receipt(&receipt)?;
            }
            self.child_receipt_log.append(receipt);
        }
        Ok(())
    }
}

/// Parameters for building a receipt.
struct ReceiptParams<'a> {
    capability_id: &'a str,
    tool_name: &'a str,
    server_id: &'a str,
    decision: Decision,
    action: ToolCallAction,
    content_hash: String,
    metadata: Option<serde_json::Value>,
    timestamp: u64,
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::mpsc;
    use std::thread;

    use arc_core::capability::{
        ArcScope, CapabilityToken, CapabilityTokenBody, Constraint, DelegationLink,
        DelegationLinkBody, GovernedApprovalDecision, GovernedApprovalToken,
        GovernedApprovalTokenBody, GovernedAutonomyContext, GovernedAutonomyTier,
        GovernedTransactionIntent, MonetaryAmount, Operation, PromptGrant, ResourceGrant,
        ToolGrant,
    };
    use arc_core::credit::{
        CreditBondArtifact, CreditBondDisposition, CreditBondLifecycleState,
        CreditBondPrerequisites, CreditBondReport, CreditBondSupportBoundary, CreditScorecardBand,
        CreditScorecardConfidence, CreditScorecardSummary, ExposureLedgerQuery,
        ExposureLedgerSummary, SignedCreditBond, CREDIT_BOND_ARTIFACT_SCHEMA,
        CREDIT_BOND_REPORT_SCHEMA,
    };
    use arc_core::crypto::{Keypair, PublicKey};
    use arc_core::session::{
        CompleteOperation, CompletionArgument, CompletionReference, CreateMessageOperation,
        GetPromptOperation, OperationContext, RequestId, SamplingMessage, SamplingTool,
        SamplingToolChoice, SessionId, SessionOperation, ToolCallOperation,
    };
    use arc_core::{
        PromptArgument, PromptDefinition, PromptMessage, PromptResult, ReadResourceOperation,
        ResourceContent, ResourceDefinition, ResourceTemplateDefinition,
    };
    use arc_link::{ExchangeRate, PriceOracle, PriceOracleError};
    use rusqlite::{params, Connection, OptionalExtension, Row};

    struct SqliteReceiptStore {
        connection: Connection,
    }

    impl SqliteReceiptStore {
        fn open(path: impl AsRef<Path>) -> Result<Self, ReceiptStoreError> {
            let path = path.as_ref();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let connection = Connection::open(path)?;
            connection.execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;

                CREATE TABLE IF NOT EXISTS arc_tool_receipts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    receipt_id TEXT NOT NULL UNIQUE,
                    timestamp INTEGER NOT NULL,
                    capability_id TEXT NOT NULL,
                    raw_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS arc_child_receipts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    receipt_id TEXT NOT NULL UNIQUE,
                    timestamp INTEGER NOT NULL,
                    session_id TEXT NOT NULL,
                    parent_request_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    operation_kind TEXT NOT NULL,
                    terminal_state TEXT NOT NULL,
                    policy_hash TEXT NOT NULL,
                    outcome_hash TEXT NOT NULL,
                    raw_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS kernel_checkpoints (
                    checkpoint_seq INTEGER PRIMARY KEY,
                    raw_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS capability_lineage (
                    capability_id TEXT PRIMARY KEY,
                    subject_key TEXT NOT NULL,
                    issuer_key TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    grants_json TEXT NOT NULL,
                    delegation_depth INTEGER NOT NULL DEFAULT 0,
                    parent_capability_id TEXT
                );

                CREATE TABLE IF NOT EXISTS credit_bonds (
                    bond_id TEXT PRIMARY KEY,
                    lifecycle_state TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    raw_json TEXT NOT NULL
                );
                "#,
            )?;
            Ok(Self { connection })
        }

        fn load_checkpoint_by_seq(
            &self,
            checkpoint_seq: u64,
        ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
            self.connection
                .query_row(
                    "SELECT raw_json FROM kernel_checkpoints WHERE checkpoint_seq = ?1",
                    params![checkpoint_seq as i64],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw_json| serde_json::from_str(&raw_json))
                .transpose()
                .map_err(Into::into)
        }

        fn get_delegation_chain(
            &self,
            capability_id: &str,
        ) -> Result<Vec<CapabilitySnapshot>, CapabilityLineageError> {
            fn snapshot_from_row(row: &Row<'_>) -> rusqlite::Result<CapabilitySnapshot> {
                Ok(CapabilitySnapshot {
                    capability_id: row.get::<_, String>(0)?,
                    subject_key: row.get::<_, String>(1)?,
                    issuer_key: row.get::<_, String>(2)?,
                    issued_at: row.get::<_, i64>(3)?.max(0) as u64,
                    expires_at: row.get::<_, i64>(4)?.max(0) as u64,
                    grants_json: row.get::<_, String>(5)?,
                    delegation_depth: row.get::<_, i64>(6)?.max(0) as u64,
                    parent_capability_id: row.get::<_, Option<String>>(7)?,
                })
            }

            let mut chain = Vec::new();
            let mut current = Some(capability_id.to_string());

            while let Some(current_id) = current.take() {
                let snapshot = self
                    .connection
                    .query_row(
                        r#"
                        SELECT
                            capability_id,
                            subject_key,
                            issuer_key,
                            issued_at,
                            expires_at,
                            grants_json,
                            delegation_depth,
                            parent_capability_id
                        FROM capability_lineage
                        WHERE capability_id = ?1
                        "#,
                        params![current_id],
                        snapshot_from_row,
                    )
                    .optional()?;
                let Some(snapshot) = snapshot else {
                    break;
                };
                current = snapshot.parent_capability_id.clone();
                chain.push(snapshot);
            }

            chain.reverse();
            Ok(chain)
        }

        fn record_credit_bond(
            &mut self,
            bond: &SignedCreditBond,
            lifecycle_state: CreditBondLifecycleState,
        ) -> Result<(), ReceiptStoreError> {
            self.connection.execute(
                "INSERT OR REPLACE INTO credit_bonds (bond_id, lifecycle_state, expires_at, raw_json)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    bond.body.bond_id,
                    match lifecycle_state {
                        CreditBondLifecycleState::Active => "active",
                        CreditBondLifecycleState::Superseded => "superseded",
                        CreditBondLifecycleState::Released => "released",
                        CreditBondLifecycleState::Impaired => "impaired",
                        CreditBondLifecycleState::Expired => "expired",
                    },
                    bond.body.expires_at as i64,
                    serde_json::to_string(bond)?,
                ],
            )?;
            Ok(())
        }
    }

    impl ReceiptStore for SqliteReceiptStore {
        fn append_arc_receipt(&mut self, receipt: &ArcReceipt) -> Result<(), ReceiptStoreError> {
            self.append_arc_receipt_returning_seq(receipt)?;
            Ok(())
        }

        fn supports_kernel_signed_checkpoints(&self) -> bool {
            true
        }

        fn append_arc_receipt_returning_seq(
            &mut self,
            receipt: &ArcReceipt,
        ) -> Result<Option<u64>, ReceiptStoreError> {
            let raw_json = serde_json::to_string(receipt)?;
            let rows = self.connection.execute(
                r#"
                INSERT INTO arc_tool_receipts (
                    receipt_id,
                    timestamp,
                    capability_id,
                    raw_json
                ) VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(receipt_id) DO NOTHING
                "#,
                params![
                    receipt.id,
                    receipt.timestamp as i64,
                    receipt.capability_id,
                    raw_json,
                ],
            )?;
            Ok((rows > 0).then(|| self.connection.last_insert_rowid().max(0) as u64))
        }

        fn append_child_receipt(
            &mut self,
            receipt: &ChildRequestReceipt,
        ) -> Result<(), ReceiptStoreError> {
            let raw_json = serde_json::to_string(receipt)?;
            self.connection.execute(
                r#"
                INSERT INTO arc_child_receipts (
                    receipt_id,
                    timestamp,
                    session_id,
                    parent_request_id,
                    request_id,
                    operation_kind,
                    terminal_state,
                    policy_hash,
                    outcome_hash,
                    raw_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(receipt_id) DO NOTHING
                "#,
                params![
                    receipt.id,
                    receipt.timestamp as i64,
                    receipt.session_id.as_str(),
                    receipt.parent_request_id.as_str(),
                    receipt.request_id.as_str(),
                    receipt.operation_kind.as_str(),
                    match &receipt.terminal_state {
                        OperationTerminalState::Completed => "completed",
                        OperationTerminalState::Cancelled { .. } => "cancelled",
                        OperationTerminalState::Incomplete { .. } => "incomplete",
                    },
                    receipt.policy_hash,
                    receipt.outcome_hash,
                    raw_json,
                ],
            )?;
            Ok(())
        }

        fn receipts_canonical_bytes_range(
            &self,
            start_seq: u64,
            end_seq: u64,
        ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
            let mut statement = self.connection.prepare(
                r#"
                SELECT seq, raw_json
                FROM arc_tool_receipts
                WHERE seq >= ?1 AND seq <= ?2
                ORDER BY seq ASC
                "#,
            )?;
            let rows = statement.query_map(params![start_seq as i64, end_seq as i64], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;

            rows.map(|row| {
                let (seq, raw_json) = row?;
                let value = serde_json::from_str::<serde_json::Value>(&raw_json)?;
                let bytes = canonical_json_bytes(&value)
                    .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
                Ok((seq.max(0) as u64, bytes))
            })
            .collect()
        }

        fn store_checkpoint(
            &mut self,
            checkpoint: &KernelCheckpoint,
        ) -> Result<(), ReceiptStoreError> {
            let raw_json = serde_json::to_string(checkpoint)?;
            self.connection.execute(
                r#"
                INSERT INTO kernel_checkpoints (checkpoint_seq, raw_json)
                VALUES (?1, ?2)
                ON CONFLICT(checkpoint_seq) DO UPDATE SET raw_json = excluded.raw_json
                "#,
                params![checkpoint.body.checkpoint_seq as i64, raw_json],
            )?;
            Ok(())
        }

        fn resolve_credit_bond(
            &self,
            bond_id: &str,
        ) -> Result<Option<CreditBondRow>, ReceiptStoreError> {
            self.connection
                .query_row(
                    "SELECT raw_json, lifecycle_state FROM credit_bonds WHERE bond_id = ?1",
                    params![bond_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
                .map(|(raw_json, lifecycle_state)| {
                    let bond = serde_json::from_str::<SignedCreditBond>(&raw_json)?;
                    let lifecycle_state = match lifecycle_state.as_str() {
                        "active" => CreditBondLifecycleState::Active,
                        "superseded" => CreditBondLifecycleState::Superseded,
                        "released" => CreditBondLifecycleState::Released,
                        "impaired" => CreditBondLifecycleState::Impaired,
                        "expired" => CreditBondLifecycleState::Expired,
                        other => {
                            return Err(ReceiptStoreError::Conflict(format!(
                                "unknown credit bond lifecycle state `{other}`"
                            )))
                        }
                    };
                    Ok(CreditBondRow {
                        bond,
                        lifecycle_state,
                        superseded_by_bond_id: None,
                    })
                })
                .transpose()
        }

        fn record_capability_snapshot(
            &mut self,
            token: &CapabilityToken,
            parent_capability_id: Option<&str>,
        ) -> Result<(), ReceiptStoreError> {
            let grants_json = serde_json::to_string(&token.scope)?;
            let subject_key = token.subject.to_hex();
            let issuer_key = token.issuer.to_hex();
            let delegation_depth = if let Some(parent_id) = parent_capability_id {
                self.connection
                    .query_row(
                        "SELECT delegation_depth FROM capability_lineage WHERE capability_id = ?1",
                        params![parent_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?
                    .map(|depth| depth.max(0) as u64 + 1)
                    .unwrap_or(1)
            } else {
                0
            };

            self.connection.execute(
                r#"
                INSERT OR REPLACE INTO capability_lineage (
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    token.id,
                    subject_key,
                    issuer_key,
                    token.issued_at as i64,
                    token.expires_at as i64,
                    grants_json,
                    delegation_depth as i64,
                    parent_capability_id,
                ],
            )?;
            Ok(())
        }
    }

    struct SqliteRevocationStore {
        path: PathBuf,
    }

    impl SqliteRevocationStore {
        fn open(path: impl AsRef<Path>) -> Result<Self, RevocationStoreError> {
            let path = path.as_ref().to_path_buf();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let connection = rusqlite::Connection::open(&path)?;
            connection.execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;

                CREATE TABLE IF NOT EXISTS revoked_capabilities (
                    capability_id TEXT PRIMARY KEY,
                    revoked_at INTEGER NOT NULL
                );
                "#,
            )?;
            Ok(Self { path })
        }

        fn connection(&self) -> Result<rusqlite::Connection, RevocationStoreError> {
            Ok(rusqlite::Connection::open(&self.path)?)
        }
    }

    impl RevocationStore for SqliteRevocationStore {
        fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
            let connection = self.connection()?;
            let exists = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
                params![capability_id],
                |row| row.get::<_, i64>(0),
            )?;
            Ok(exists != 0)
        }

        fn revoke(&mut self, capability_id: &str) -> Result<bool, RevocationStoreError> {
            let connection = self.connection()?;
            let revoked_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs() as i64)
                .unwrap_or(0);
            let rows = connection.execute(
                r#"
                INSERT INTO revoked_capabilities (capability_id, revoked_at)
                VALUES (?1, ?2)
                ON CONFLICT(capability_id) DO NOTHING
                "#,
                params![capability_id, revoked_at],
            )?;
            Ok(rows > 0)
        }
    }

    fn make_keypair() -> Keypair {
        Keypair::generate()
    }

    fn make_config() -> KernelConfig {
        KernelConfig {
            keypair: make_keypair(),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "test-policy-hash".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        }
    }

    fn unique_receipt_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn make_elicited_content() -> CreateElicitationResult {
        CreateElicitationResult {
            action: arc_core::session::ElicitationAction::Accept,
            content: Some(serde_json::json!({
                "environment": "staging",
            })),
        }
    }

    fn make_grant(server: &str, tool: &str) -> ToolGrant {
        ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }
    }

    fn make_scope(grants: Vec<ToolGrant>) -> ArcScope {
        ArcScope {
            grants,
            ..ArcScope::default()
        }
    }

    fn make_capability(
        kernel: &ArcKernel,
        subject_kp: &Keypair,
        scope: ArcScope,
        ttl: u64,
    ) -> CapabilityToken {
        kernel
            .issue_capability(&subject_kp.public_key(), scope, ttl)
            .unwrap()
    }

    fn make_request(
        request_id: &str,
        cap: &CapabilityToken,
        tool: &str,
        server: &str,
    ) -> ToolCallRequest {
        make_request_with_arguments(
            request_id,
            cap,
            tool,
            server,
            serde_json::json!({"path": "/app/src/main.rs"}),
        )
    }

    fn make_request_with_arguments(
        request_id: &str,
        cap: &CapabilityToken,
        tool: &str,
        server: &str,
        arguments: serde_json::Value,
    ) -> ToolCallRequest {
        ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap.clone(),
            tool_name: tool.to_string(),
            server_id: server.to_string(),
            agent_id: cap.subject.to_hex(),
            arguments,
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        }
    }

    fn make_operation_context(
        session_id: &SessionId,
        request_id: &str,
        agent_id: &str,
    ) -> OperationContext {
        OperationContext::new(
            session_id.clone(),
            RequestId::new(request_id),
            agent_id.to_string(),
        )
    }

    fn session_tool_call(response: SessionOperationResponse) -> Option<ToolCallResponse> {
        if let SessionOperationResponse::ToolCall(response) = response {
            Some(response)
        } else {
            None
        }
    }

    fn session_capability_list(response: SessionOperationResponse) -> Option<Vec<CapabilityToken>> {
        if let SessionOperationResponse::CapabilityList { capabilities } = response {
            Some(capabilities)
        } else {
            None
        }
    }

    fn session_root_list(response: SessionOperationResponse) -> Option<Vec<RootDefinition>> {
        if let SessionOperationResponse::RootList { roots } = response {
            Some(roots)
        } else {
            None
        }
    }

    fn session_resource_list(
        response: SessionOperationResponse,
    ) -> Option<Vec<ResourceDefinition>> {
        if let SessionOperationResponse::ResourceList { resources } = response {
            Some(resources)
        } else {
            None
        }
    }

    fn session_resource_read(response: SessionOperationResponse) -> Option<Vec<ResourceContent>> {
        if let SessionOperationResponse::ResourceRead { contents } = response {
            Some(contents)
        } else {
            None
        }
    }

    fn session_prompt_list(response: SessionOperationResponse) -> Option<Vec<PromptDefinition>> {
        if let SessionOperationResponse::PromptList { prompts } = response {
            Some(prompts)
        } else {
            None
        }
    }

    fn session_prompt_get(response: SessionOperationResponse) -> Option<PromptResult> {
        if let SessionOperationResponse::PromptGet { prompt } = response {
            Some(prompt)
        } else {
            None
        }
    }

    fn session_completion(response: SessionOperationResponse) -> Option<CompletionResult> {
        if let SessionOperationResponse::Completion { completion } = response {
            Some(completion)
        } else {
            None
        }
    }

    fn tool_call_value_output(output: Option<ToolCallOutput>) -> Option<serde_json::Value> {
        if let Some(ToolCallOutput::Value(value)) = output {
            Some(value)
        } else {
            None
        }
    }

    fn tool_call_stream_output(output: Option<ToolCallOutput>) -> Option<ToolCallStream> {
        if let Some(ToolCallOutput::Stream(stream)) = output {
            Some(stream)
        } else {
            None
        }
    }

    fn make_delegation_link(
        capability_id: &str,
        delegator_kp: &Keypair,
        delegatee_kp: &Keypair,
        timestamp: u64,
    ) -> DelegationLink {
        DelegationLink::sign(
            DelegationLinkBody {
                capability_id: capability_id.to_string(),
                delegator: delegator_kp.public_key(),
                delegatee: delegatee_kp.public_key(),
                attenuations: vec![],
                timestamp,
            },
            delegator_kp,
        )
        .unwrap()
    }

    struct EchoServer {
        id: String,
        tools: Vec<String>,
    }

    struct IncompleteServer {
        id: String,
    }

    struct StreamingServer {
        id: String,
        chunks: Vec<serde_json::Value>,
    }

    struct NestedFlowServer {
        id: String,
    }

    struct MockNestedFlowClient {
        roots: Vec<RootDefinition>,
        sampled_message: CreateMessageResult,
        elicited_content: CreateElicitationResult,
        cancel_parent_on_create_message: bool,
        cancel_child_on_create_message: bool,
        completed_elicitation_ids: Vec<String>,
        resource_updates: Vec<String>,
        resources_list_changed_count: u32,
    }

    struct DocsResourceProvider;
    struct FilesystemResourceProvider;
    struct ExamplePromptProvider;
    struct StubPaymentAdapter;
    struct DecliningPaymentAdapter;
    struct PrepaidSettledPaymentAdapter;

    impl EchoServer {
        fn new(id: &str, tools: Vec<&str>) -> Self {
            Self {
                id: id.to_string(),
                tools: tools.into_iter().map(String::from).collect(),
            }
        }
    }

    impl PaymentAdapter for StubPaymentAdapter {
        fn authorize(
            &self,
            _request: &PaymentAuthorizeRequest,
        ) -> Result<PaymentAuthorization, PaymentError> {
            Ok(PaymentAuthorization {
                authorization_id: "auth_stub".to_string(),
                settled: false,
                metadata: serde_json::json!({ "adapter": "stub" }),
            })
        }

        fn capture(
            &self,
            _authorization_id: &str,
            _amount_units: u64,
            _currency: &str,
            _reference: &str,
        ) -> Result<PaymentResult, PaymentError> {
            Ok(PaymentResult {
                transaction_id: "txn_stub".to_string(),
                settlement_status: RailSettlementStatus::Settled,
                metadata: serde_json::json!({ "adapter": "stub" }),
            })
        }

        fn release(
            &self,
            _authorization_id: &str,
            _reference: &str,
        ) -> Result<PaymentResult, PaymentError> {
            Ok(PaymentResult {
                transaction_id: "release_stub".to_string(),
                settlement_status: RailSettlementStatus::Released,
                metadata: serde_json::json!({ "adapter": "stub" }),
            })
        }

        fn refund(
            &self,
            _transaction_id: &str,
            _amount_units: u64,
            _currency: &str,
            _reference: &str,
        ) -> Result<PaymentResult, PaymentError> {
            Ok(PaymentResult {
                transaction_id: "refund_stub".to_string(),
                settlement_status: RailSettlementStatus::Refunded,
                metadata: serde_json::json!({ "adapter": "stub" }),
            })
        }
    }

    impl PaymentAdapter for DecliningPaymentAdapter {
        fn authorize(
            &self,
            _request: &PaymentAuthorizeRequest,
        ) -> Result<PaymentAuthorization, PaymentError> {
            Err(PaymentError::InsufficientFunds)
        }

        fn capture(
            &self,
            _authorization_id: &str,
            _amount_units: u64,
            _currency: &str,
            _reference: &str,
        ) -> Result<PaymentResult, PaymentError> {
            Err(PaymentError::RailError(
                "capture should not run".to_string(),
            ))
        }

        fn release(
            &self,
            _authorization_id: &str,
            _reference: &str,
        ) -> Result<PaymentResult, PaymentError> {
            Err(PaymentError::RailError(
                "release should not run".to_string(),
            ))
        }

        fn refund(
            &self,
            _transaction_id: &str,
            _amount_units: u64,
            _currency: &str,
            _reference: &str,
        ) -> Result<PaymentResult, PaymentError> {
            Err(PaymentError::RailError("refund should not run".to_string()))
        }
    }

    impl PaymentAdapter for PrepaidSettledPaymentAdapter {
        fn authorize(
            &self,
            _request: &PaymentAuthorizeRequest,
        ) -> Result<PaymentAuthorization, PaymentError> {
            Ok(PaymentAuthorization {
                authorization_id: "x402_txn_paid".to_string(),
                settled: true,
                metadata: serde_json::json!({ "adapter": "x402" }),
            })
        }

        fn capture(
            &self,
            authorization_id: &str,
            _amount_units: u64,
            _currency: &str,
            _reference: &str,
        ) -> Result<PaymentResult, PaymentError> {
            Ok(PaymentResult {
                transaction_id: authorization_id.to_string(),
                settlement_status: RailSettlementStatus::Settled,
                metadata: serde_json::json!({ "adapter": "x402" }),
            })
        }

        fn release(
            &self,
            authorization_id: &str,
            _reference: &str,
        ) -> Result<PaymentResult, PaymentError> {
            Ok(PaymentResult {
                transaction_id: authorization_id.to_string(),
                settlement_status: RailSettlementStatus::Released,
                metadata: serde_json::json!({ "adapter": "x402" }),
            })
        }

        fn refund(
            &self,
            transaction_id: &str,
            _amount_units: u64,
            _currency: &str,
            _reference: &str,
        ) -> Result<PaymentResult, PaymentError> {
            Ok(PaymentResult {
                transaction_id: transaction_id.to_string(),
                settlement_status: RailSettlementStatus::Refunded,
                metadata: serde_json::json!({ "adapter": "x402" }),
            })
        }
    }

    impl ToolServerConnection for EchoServer {
        fn server_id(&self) -> &str {
            &self.id
        }
        fn tool_names(&self) -> Vec<String> {
            self.tools.clone()
        }
        fn invoke(
            &self,
            tool_name: &str,
            arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            Ok(serde_json::json!({
                "tool": tool_name,
                "echo": arguments,
            }))
        }
    }

    impl ToolServerConnection for NestedFlowServer {
        fn server_id(&self) -> &str {
            &self.id
        }

        fn tool_names(&self) -> Vec<String> {
            vec![
                "sample_via_client".to_string(),
                "elicit_via_client".to_string(),
                "roots_via_client".to_string(),
                "notify_resources_via_client".to_string(),
            ]
        }

        fn invoke(
            &self,
            tool_name: &str,
            _arguments: serde_json::Value,
            nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            let nested_flow_bridge = nested_flow_bridge.ok_or_else(|| {
                KernelError::Internal("nested-flow bridge is required".to_string())
            })?;

            match tool_name {
                "sample_via_client" => {
                    let message = nested_flow_bridge.create_message(CreateMessageOperation {
                        messages: vec![SamplingMessage {
                            role: "user".to_string(),
                            content: serde_json::json!({
                                "type": "text",
                                "text": "Summarize the roadmap",
                            }),
                            meta: None,
                        }],
                        model_preferences: None,
                        system_prompt: None,
                        include_context: None,
                        temperature: Some(0.2),
                        max_tokens: 128,
                        stop_sequences: vec![],
                        metadata: None,
                        tools: vec![],
                        tool_choice: None,
                    })?;

                    Ok(serde_json::json!({
                        "model": message.model,
                        "content": message.content,
                    }))
                }
                "elicit_via_client" => {
                    let elicitation = nested_flow_bridge.create_elicitation(
                        CreateElicitationOperation::Form {
                            meta: None,
                            message: "Which environment should this run against?".to_string(),
                            requested_schema: serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "environment": {
                                        "type": "string",
                                        "enum": ["staging", "production"]
                                    }
                                },
                                "required": ["environment"]
                            }),
                        },
                    )?;

                    Ok(serde_json::json!({
                        "action": elicitation.action,
                        "content": elicitation.content,
                    }))
                }
                "roots_via_client" => {
                    let roots = nested_flow_bridge.list_roots()?;
                    Ok(serde_json::json!({
                        "roots": roots,
                    }))
                }
                "notify_resources_via_client" => {
                    nested_flow_bridge.notify_resource_updated("repo://docs/roadmap")?;
                    nested_flow_bridge.notify_resource_updated("repo://secret/ops")?;
                    nested_flow_bridge.notify_resources_list_changed()?;
                    Ok(serde_json::json!({
                        "notified": true,
                    }))
                }
                _ => Err(KernelError::ToolNotRegistered(tool_name.to_string())),
            }
        }
    }

    impl ToolServerConnection for IncompleteServer {
        fn server_id(&self) -> &str {
            &self.id
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["drop_stream".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            Err(KernelError::RequestIncomplete(
                "upstream stream closed before tool response completed".to_string(),
            ))
        }
    }

    impl ToolServerConnection for StreamingServer {
        fn server_id(&self) -> &str {
            &self.id
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["stream_file".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            Ok(serde_json::json!({"unused": true}))
        }

        fn invoke_stream(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Option<ToolServerStreamResult>, KernelError> {
            Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
                chunks: self
                    .chunks
                    .iter()
                    .cloned()
                    .map(|data| ToolCallChunk { data })
                    .collect(),
            })))
        }
    }

    impl NestedFlowClient for MockNestedFlowClient {
        fn list_roots(
            &mut self,
            _parent_context: &OperationContext,
            _child_context: &OperationContext,
        ) -> Result<Vec<RootDefinition>, KernelError> {
            Ok(self.roots.clone())
        }

        fn create_message(
            &mut self,
            parent_context: &OperationContext,
            child_context: &OperationContext,
            _operation: &CreateMessageOperation,
        ) -> Result<CreateMessageResult, KernelError> {
            if self.cancel_parent_on_create_message {
                return Err(KernelError::RequestCancelled {
                    request_id: parent_context.request_id.clone(),
                    reason: "client cancelled parent request".to_string(),
                });
            }

            if self.cancel_child_on_create_message {
                return Err(KernelError::RequestCancelled {
                    request_id: child_context.request_id.clone(),
                    reason: "client cancelled nested request".to_string(),
                });
            }

            Ok(self.sampled_message.clone())
        }

        fn create_elicitation(
            &mut self,
            _parent_context: &OperationContext,
            _child_context: &OperationContext,
            _operation: &CreateElicitationOperation,
        ) -> Result<CreateElicitationResult, KernelError> {
            Ok(self.elicited_content.clone())
        }

        fn notify_elicitation_completed(
            &mut self,
            _parent_context: &OperationContext,
            elicitation_id: &str,
        ) -> Result<(), KernelError> {
            self.completed_elicitation_ids
                .push(elicitation_id.to_string());
            Ok(())
        }

        fn notify_resource_updated(
            &mut self,
            _parent_context: &OperationContext,
            uri: &str,
        ) -> Result<(), KernelError> {
            self.resource_updates.push(uri.to_string());
            Ok(())
        }

        fn notify_resources_list_changed(
            &mut self,
            _parent_context: &OperationContext,
        ) -> Result<(), KernelError> {
            self.resources_list_changed_count += 1;
            Ok(())
        }
    }

    impl ResourceProvider for DocsResourceProvider {
        fn list_resources(&self) -> Vec<ResourceDefinition> {
            vec![
                ResourceDefinition {
                    uri: "repo://docs/roadmap".to_string(),
                    name: "Roadmap".to_string(),
                    title: Some("Roadmap".to_string()),
                    description: Some("Project roadmap".to_string()),
                    mime_type: Some("text/markdown".to_string()),
                    size: Some(128),
                    annotations: None,
                    icons: None,
                },
                ResourceDefinition {
                    uri: "repo://secret/ops".to_string(),
                    name: "Ops".to_string(),
                    title: None,
                    description: Some("Hidden".to_string()),
                    mime_type: Some("text/plain".to_string()),
                    size: None,
                    annotations: None,
                    icons: None,
                },
            ]
        }

        fn list_resource_templates(&self) -> Vec<ResourceTemplateDefinition> {
            vec![ResourceTemplateDefinition {
                uri_template: "repo://docs/{slug}".to_string(),
                name: "Doc Template".to_string(),
                title: None,
                description: Some("Template".to_string()),
                mime_type: Some("text/markdown".to_string()),
                annotations: None,
                icons: None,
            }]
        }

        fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
            match uri {
                "repo://docs/roadmap" => Ok(Some(vec![ResourceContent {
                    uri: uri.to_string(),
                    mime_type: Some("text/markdown".to_string()),
                    text: Some("# Roadmap".to_string()),
                    blob: None,
                    annotations: None,
                }])),
                _ => Ok(None),
            }
        }

        fn complete_resource_argument(
            &self,
            uri: &str,
            argument_name: &str,
            value: &str,
            _context: &serde_json::Value,
        ) -> Result<Option<CompletionResult>, KernelError> {
            if uri == "repo://docs/{slug}" && argument_name == "slug" {
                let values = ["roadmap", "architecture", "api"]
                    .into_iter()
                    .filter(|candidate| candidate.starts_with(value))
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                return Ok(Some(CompletionResult {
                    total: Some(values.len() as u32),
                    has_more: false,
                    values,
                }));
            }

            Ok(None)
        }
    }

    #[derive(Default)]
    struct AppendOnlyReceiptStore;

    impl ReceiptStore for AppendOnlyReceiptStore {
        fn append_arc_receipt(&mut self, _receipt: &ArcReceipt) -> Result<(), ReceiptStoreError> {
            Ok(())
        }

        fn append_child_receipt(
            &mut self,
            _receipt: &ChildRequestReceipt,
        ) -> Result<(), ReceiptStoreError> {
            Ok(())
        }
    }

    impl ResourceProvider for FilesystemResourceProvider {
        fn list_resources(&self) -> Vec<ResourceDefinition> {
            vec![
                ResourceDefinition {
                    uri: "file:///workspace/project/docs/roadmap.md".to_string(),
                    name: "Filesystem Roadmap".to_string(),
                    title: Some("Filesystem Roadmap".to_string()),
                    description: Some("In-root file-backed resource".to_string()),
                    mime_type: Some("text/markdown".to_string()),
                    size: Some(64),
                    annotations: None,
                    icons: None,
                },
                ResourceDefinition {
                    uri: "file:///workspace/private/ops.md".to_string(),
                    name: "Filesystem Ops".to_string(),
                    title: None,
                    description: Some("Out-of-root file-backed resource".to_string()),
                    mime_type: Some("text/plain".to_string()),
                    size: Some(32),
                    annotations: None,
                    icons: None,
                },
            ]
        }

        fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
            match uri {
                "file:///workspace/project/docs/roadmap.md" => Ok(Some(vec![ResourceContent {
                    uri: uri.to_string(),
                    mime_type: Some("text/markdown".to_string()),
                    text: Some("# Filesystem Roadmap".to_string()),
                    blob: None,
                    annotations: None,
                }])),
                "file:///workspace/private/ops.md" => Ok(Some(vec![ResourceContent {
                    uri: uri.to_string(),
                    mime_type: Some("text/plain".to_string()),
                    text: Some("ops".to_string()),
                    blob: None,
                    annotations: None,
                }])),
                _ => Ok(None),
            }
        }
    }

    impl PromptProvider for ExamplePromptProvider {
        fn list_prompts(&self) -> Vec<PromptDefinition> {
            vec![
                PromptDefinition {
                    name: "summarize_docs".to_string(),
                    title: Some("Summarize Docs".to_string()),
                    description: Some("Summarize documentation".to_string()),
                    arguments: vec![PromptArgument {
                        name: "topic".to_string(),
                        title: None,
                        description: Some("Topic to summarize".to_string()),
                        required: Some(true),
                    }],
                    icons: None,
                },
                PromptDefinition {
                    name: "ops_secret".to_string(),
                    title: None,
                    description: Some("Hidden".to_string()),
                    arguments: vec![],
                    icons: None,
                },
            ]
        }

        fn get_prompt(
            &self,
            name: &str,
            arguments: serde_json::Value,
        ) -> Result<Option<PromptResult>, KernelError> {
            match name {
                "summarize_docs" => Ok(Some(PromptResult {
                    description: Some("Summarize docs".to_string()),
                    messages: vec![PromptMessage {
                        role: "user".to_string(),
                        content: serde_json::json!({
                            "type": "text",
                            "text": format!(
                                "Summarize {}",
                                arguments["topic"].as_str().unwrap_or("the docs")
                            ),
                        }),
                    }],
                })),
                _ => Ok(None),
            }
        }

        fn complete_prompt_argument(
            &self,
            name: &str,
            argument_name: &str,
            value: &str,
            _context: &serde_json::Value,
        ) -> Result<Option<CompletionResult>, KernelError> {
            if name == "summarize_docs" && argument_name == "topic" {
                let values = ["roadmap", "architecture", "release-plan"]
                    .into_iter()
                    .filter(|candidate| candidate.starts_with(value))
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                return Ok(Some(CompletionResult {
                    total: Some(values.len() as u32),
                    has_more: false,
                    values,
                }));
            }

            Ok(None)
        }
    }

    #[test]
    fn issue_and_use_capability() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);
        let request = make_request("req-1", &cap, "read_file", "srv-a");

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Allow);
        assert!(matches!(response.output, Some(ToolCallOutput::Value(_))));
        assert!(response.reason.is_none());

        // Receipt was logged.
        assert_eq!(kernel.receipt_log().len(), 1);

        // Receipt signature verifies.
        let r = kernel.receipt_log().get(0).unwrap();
        assert!(r.verify_signature().unwrap());
    }

    #[test]
    fn kernel_persists_tool_receipts_to_sqlite_store() {
        let path = unique_receipt_db_path("arc-kernel-tool-receipts");
        let mut kernel = ArcKernel::new(make_config());
        kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);
        let request = make_request("req-sqlite-1", &cap, "read_file", "srv-a");

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Allow);
        drop(kernel);

        let connection = rusqlite::Connection::open(&path).unwrap();
        let (count, distinct_count, receipt_id): (i64, i64, String) = connection
            .query_row(
                "SELECT COUNT(*), COUNT(DISTINCT receipt_id), MIN(receipt_id) FROM arc_tool_receipts",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let child_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM arc_child_receipts", [], |row| {
                row.get(0)
            })
            .unwrap();

        assert_eq!(count, 1);
        assert_eq!(distinct_count, 1);
        assert_eq!(child_count, 0);
        assert!(receipt_id.starts_with("rcpt-"));

        drop(connection);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn kernel_accepts_capabilities_from_configured_authority() {
        let authority_keypair = make_keypair();
        let mut kernel = ArcKernel::new(make_config());
        kernel.set_capability_authority(Box::new(LocalCapabilityAuthority::new(
            authority_keypair.clone(),
        )));
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);
        let request = make_request("req-authority-1", &cap, "read_file", "srv-a");

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(cap.issuer, authority_keypair.public_key());
        assert_eq!(response.verdict, Verdict::Allow);
    }

    #[test]
    fn expired_capability_denied() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        // TTL=0 means it expires at the same second it was issued.
        let cap = make_capability(&kernel, &agent_kp, scope, 0);
        let request = make_request("req-1", &cap, "read_file", "srv-a");

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(reason.contains("expired"), "reason was: {reason}");

        // Denial also produces a receipt.
        assert_eq!(kernel.receipt_log().len(), 1);
        assert!(kernel.receipt_log().get(0).unwrap().is_denied());
    }

    #[test]
    fn revoked_capability_denied() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        kernel.revoke_capability(&cap.id).unwrap();

        let request = make_request("req-1", &cap, "read_file", "srv-a");
        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(reason.contains("revoked"), "reason was: {reason}");
    }

    #[test]
    fn sqlite_revocation_store_survives_kernel_restart() {
        let path = unique_receipt_db_path("arc-kernel-revocations");
        let authority_keypair = make_keypair();
        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);

        let cap = {
            let mut kernel = ArcKernel::new(make_config());
            kernel.set_capability_authority(Box::new(LocalCapabilityAuthority::new(
                authority_keypair.clone(),
            )));
            kernel.set_revocation_store(Box::new(SqliteRevocationStore::open(&path).unwrap()));
            kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

            let cap = make_capability(&kernel, &agent_kp, scope.clone(), 300);
            kernel.revoke_capability(&cap.id).unwrap();
            cap
        };

        let mut restarted = ArcKernel::new(make_config());
        restarted
            .set_capability_authority(Box::new(LocalCapabilityAuthority::new(authority_keypair)));
        restarted.set_revocation_store(Box::new(SqliteRevocationStore::open(&path).unwrap()));
        restarted.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let request = make_request("req-revoked-after-restart", &cap, "read_file", "srv-a");
        let response = restarted.evaluate_tool_call(&request).unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(
            response.reason.as_deref().unwrap_or("").contains("revoked"),
            "reason was: {:?}",
            response.reason
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn out_of_scope_tool_denied() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new(
            "srv-a",
            vec!["read_file", "write_file"],
        )));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        // Request write_file, but capability only grants read_file.
        let request = make_request("req-1", &cap, "write_file", "srv-a");
        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("not in capability scope"),
            "reason was: {reason}"
        );
    }

    #[test]
    fn subject_mismatch_denied() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);
        let mut request = make_request("req-1", &cap, "read_file", "srv-a");
        request.agent_id = make_keypair().public_key().to_hex();

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(reason.contains("does not match capability subject"));
    }

    #[test]
    fn path_prefix_constraint_is_enforced() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = ArcScope {
            grants: vec![ToolGrant {
                server_id: "srv-a".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::PathPrefix("/app/src".to_string())],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ArcScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let allowed = make_request_with_arguments(
            "req-allow",
            &cap,
            "read_file",
            "srv-a",
            serde_json::json!({"path": "/app/src/lib.rs"}),
        );
        let denied = make_request_with_arguments(
            "req-deny",
            &cap,
            "read_file",
            "srv-a",
            serde_json::json!({"path": "/etc/passwd"}),
        );

        assert_eq!(
            kernel.evaluate_tool_call(&allowed).unwrap().verdict,
            Verdict::Allow
        );
        let denied_response = kernel.evaluate_tool_call(&denied).unwrap();
        assert_eq!(denied_response.verdict, Verdict::Deny);
        assert!(denied_response
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("not in capability scope"));
    }

    #[test]
    fn domain_exact_constraint_is_enforced() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["fetch"])));

        let agent_kp = make_keypair();
        let scope = ArcScope {
            grants: vec![ToolGrant {
                server_id: "srv-a".to_string(),
                tool_name: "fetch".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::DomainExact("api.example.com".to_string())],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ArcScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let allowed = make_request_with_arguments(
            "req-allow",
            &cap,
            "fetch",
            "srv-a",
            serde_json::json!({"url": "https://api.example.com/v1/data"}),
        );
        let denied = make_request_with_arguments(
            "req-deny",
            &cap,
            "fetch",
            "srv-a",
            serde_json::json!({"url": "https://evil.example.com/v1/data"}),
        );

        assert_eq!(
            kernel.evaluate_tool_call(&allowed).unwrap().verdict,
            Verdict::Allow
        );
        assert_eq!(
            kernel.evaluate_tool_call(&denied).unwrap().verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn budget_exhaustion() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = ArcScope {
            grants: vec![ToolGrant {
                server_id: "srv-a".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: Some(2),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ArcScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        // First two calls succeed.
        for i in 0..2 {
            let req = make_request(&format!("req-{i}"), &cap, "read_file", "srv-a");
            let resp = kernel.evaluate_tool_call(&req).unwrap();
            assert_eq!(resp.verdict, Verdict::Allow, "call {i} should succeed");
        }

        // Third call is denied.
        let req = make_request("req-2", &cap, "read_file", "srv-a");
        let resp = kernel.evaluate_tool_call(&req).unwrap();
        assert_eq!(resp.verdict, Verdict::Deny);
        let reason = resp.reason.as_deref().unwrap_or("");
        assert!(reason.contains("budget"), "reason was: {reason}");
    }

    #[test]
    fn budgets_are_tracked_per_matching_grant() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new(
            "srv-a",
            vec!["read_file", "write_file"],
        )));

        let agent_kp = make_keypair();
        let scope = ArcScope {
            grants: vec![
                ToolGrant {
                    server_id: "srv-a".to_string(),
                    tool_name: "read_file".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: Some(2),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                },
                ToolGrant {
                    server_id: "srv-a".to_string(),
                    tool_name: "write_file".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: Some(1),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                },
            ],
            ..ArcScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        assert_eq!(
            kernel
                .evaluate_tool_call(&make_request("read-1", &cap, "read_file", "srv-a"))
                .unwrap()
                .verdict,
            Verdict::Allow
        );
        assert_eq!(
            kernel
                .evaluate_tool_call(&make_request("read-2", &cap, "read_file", "srv-a"))
                .unwrap()
                .verdict,
            Verdict::Allow
        );
        assert_eq!(
            kernel
                .evaluate_tool_call(&make_request("write-1", &cap, "write_file", "srv-a"))
                .unwrap()
                .verdict,
            Verdict::Allow
        );

        let denied = kernel
            .evaluate_tool_call(&make_request("write-2", &cap, "write_file", "srv-a"))
            .unwrap();
        assert_eq!(denied.verdict, Verdict::Deny);
        assert!(denied.reason.as_deref().unwrap_or("").contains("budget"));
    }

    #[test]
    fn guard_denies_request() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["dangerous"])));

        struct DenyAll;
        impl Guard for DenyAll {
            fn name(&self) -> &str {
                "deny-all"
            }
            fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
                Ok(Verdict::Deny)
            }
        }
        kernel.add_guard(Box::new(DenyAll));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "dangerous")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);
        let request = make_request("req-1", &cap, "dangerous", "srv-a");

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(reason.contains("deny-all"), "reason was: {reason}");
    }

    #[test]
    fn guard_error_treated_as_deny() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["tool"])));

        struct BrokenGuard;
        impl Guard for BrokenGuard {
            fn name(&self) -> &str {
                "broken"
            }
            fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
                Err(KernelError::Internal("guard crashed".to_string()))
            }
        }
        kernel.add_guard(Box::new(BrokenGuard));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "tool")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);
        let request = make_request("req-1", &cap, "tool", "srv-a");

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(reason.contains("fail-closed"), "reason was: {reason}");
    }

    #[test]
    fn unregistered_server_denied() {
        let mut kernel = ArcKernel::new(make_config());
        // No tool servers registered.

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-missing", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);
        let request = make_request("req-1", &cap, "read_file", "srv-missing");

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(reason.contains("not registered"), "reason was: {reason}");
    }

    #[test]
    fn untrusted_issuer_denied() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let rogue_kp = make_keypair();
        let agent_kp = make_keypair();

        // Sign a capability with the rogue key (not trusted by this kernel).
        let body = CapabilityTokenBody {
            id: "cap-rogue".to_string(),
            issuer: rogue_kp.public_key(),
            subject: agent_kp.public_key(),
            scope: make_scope(vec![make_grant("srv-a", "read_file")]),
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![],
        };
        let cap = CapabilityToken::sign(body, &rogue_kp).unwrap();

        let request = ToolCallRequest {
            request_id: "req-rogue".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: "srv-a".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        };

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("not found among trusted"),
            "reason was: {reason}"
        );
    }

    #[test]
    fn all_calls_produce_verified_receipts() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        // Allowed call.
        let req = make_request("req-1", &cap, "read_file", "srv-a");
        let _ = kernel.evaluate_tool_call(&req).unwrap();

        // Denied call (wrong tool).
        let req2 = make_request("req-2", &cap, "write_file", "srv-a");
        let _ = kernel.evaluate_tool_call(&req2).unwrap();

        assert_eq!(kernel.receipt_log().len(), 2);

        for r in kernel.receipt_log().receipts() {
            assert!(r.verify_signature().unwrap());
        }
    }

    #[test]
    fn wildcard_server_grant_allows_real_server() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("filesystem", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("*", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let request = make_request("req-1", &cap, "read_file", "filesystem");
        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Allow);
    }

    #[test]
    fn revoked_ancestor_capability_denies_descendant() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let parent_kp = make_keypair();
        let child_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let parent = make_capability(&kernel, &parent_kp, scope.clone(), 300);

        let link = make_delegation_link(&parent.id, &kernel.config.keypair, &child_kp, 100);
        let child = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-child".to_string(),
                issuer: kernel.config.keypair.public_key(),
                subject: child_kp.public_key(),
                scope,
                issued_at: current_unix_timestamp(),
                expires_at: current_unix_timestamp() + 300,
                delegation_chain: vec![link],
            },
            &kernel.config.keypair,
        )
        .unwrap();

        kernel.revoke_capability(&parent.id).unwrap();

        let request = make_request("req-1", &child, "read_file", "srv-a");
        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response
            .reason
            .as_deref()
            .unwrap_or("")
            .contains(&parent.id));
    }

    #[test]
    fn delegated_tool_call_records_observed_capability_lineage() {
        let path = unique_receipt_db_path("arc-kernel-observed-lineage");
        let mut seed_store = SqliteReceiptStore::open(&path).unwrap();

        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let parent_kp = make_keypair();
        let child_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let parent = make_capability(&kernel, &parent_kp, scope.clone(), 300);
        seed_store
            .record_capability_snapshot(&parent, None)
            .unwrap();
        drop(seed_store);

        kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

        let link = make_delegation_link(&parent.id, &kernel.config.keypair, &child_kp, 100);
        let child = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-observed-child".to_string(),
                issuer: kernel.config.keypair.public_key(),
                subject: child_kp.public_key(),
                scope,
                issued_at: current_unix_timestamp(),
                expires_at: current_unix_timestamp() + 300,
                delegation_chain: vec![link],
            },
            &kernel.config.keypair,
        )
        .unwrap();

        let response = kernel
            .evaluate_tool_call(&make_request("req-observed", &child, "read_file", "srv-a"))
            .unwrap();
        assert_eq!(response.verdict, Verdict::Allow);

        let reopened = SqliteReceiptStore::open(&path).unwrap();
        let chain = reopened.get_delegation_chain(&child.id).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].capability_id, parent.id);
        assert_eq!(chain[0].delegation_depth, 0);
        assert_eq!(chain[1].capability_id, child.id);
        assert_eq!(
            chain[1].parent_capability_id.as_deref(),
            Some(parent.id.as_str())
        );
        assert_eq!(chain[1].delegation_depth, 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn wildcard_tool_grant_allows_any_tool() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["anything"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "*")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let request = make_request("req-1", &cap, "anything", "srv-a");
        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Allow);
    }

    #[test]
    fn in_memory_revocation_store() {
        let mut store = InMemoryRevocationStore::default();
        assert!(!store.is_revoked("cap-1").unwrap());
        assert!(store.revoke("cap-1").unwrap());
        assert!(store.is_revoked("cap-1").unwrap());
        assert!(!store.revoke("cap-1").unwrap());
    }

    #[test]
    fn receipt_log_basics() {
        let log = ReceiptLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn kernel_guard_registration() {
        let mut kernel = ArcKernel::new(make_config());
        assert_eq!(kernel.guard_count(), 0);
        assert_eq!(kernel.ca_count(), 0);

        struct TestGuard;
        impl Guard for TestGuard {
            fn name(&self) -> &str {
                "test-guard"
            }
            fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
                Ok(Verdict::Allow)
            }
        }

        kernel.add_guard(Box::new(TestGuard));
        assert_eq!(kernel.guard_count(), 1);
    }

    #[test]
    fn session_lifecycle_is_hosted_by_kernel() {
        let mut kernel = ArcKernel::new(make_config());
        let session_id = kernel.open_session("agent-1".to_string(), Vec::new());

        assert_eq!(kernel.session_count(), 1);
        assert_eq!(
            kernel.session(&session_id).map(Session::state),
            Some(SessionState::Initializing)
        );

        kernel.activate_session(&session_id).unwrap();
        assert_eq!(
            kernel.session(&session_id).map(Session::state),
            Some(SessionState::Ready)
        );

        kernel.begin_draining_session(&session_id).unwrap();
        assert_eq!(
            kernel.session(&session_id).map(Session::state),
            Some(SessionState::Draining)
        );

        kernel.close_session(&session_id).unwrap();
        assert_eq!(
            kernel.session(&session_id).map(Session::state),
            Some(SessionState::Closed)
        );
    }

    #[test]
    fn web3_evidence_required_activation_rejects_missing_receipt_store() {
        let mut config = make_config();
        config.require_web3_evidence = true;
        let mut kernel = ArcKernel::new(config);
        let session_id = kernel.open_session("agent-1".to_string(), Vec::new());

        let error = kernel.activate_session(&session_id).unwrap_err();
        assert!(matches!(error, KernelError::Web3EvidenceUnavailable(_)));
        assert!(error.to_string().contains("durable receipt store"));
    }

    #[test]
    fn web3_evidence_required_activation_rejects_checkpoint_disabled() {
        let path = unique_receipt_db_path("web3-evidence-disabled");
        let mut config = make_config();
        config.require_web3_evidence = true;
        config.checkpoint_batch_size = 0;
        let mut kernel = ArcKernel::new(config);
        kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
        let session_id = kernel.open_session("agent-1".to_string(), Vec::new());

        let error = kernel.activate_session(&session_id).unwrap_err();
        assert!(matches!(error, KernelError::Web3EvidenceUnavailable(_)));
        assert!(error.to_string().contains("checkpoint_batch_size > 0"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn web3_evidence_required_activation_rejects_append_only_receipt_store() {
        let mut config = make_config();
        config.require_web3_evidence = true;
        let mut kernel = ArcKernel::new(config);
        kernel.set_receipt_store(Box::new(AppendOnlyReceiptStore));
        let session_id = kernel.open_session("agent-1".to_string(), Vec::new());

        let error = kernel.activate_session(&session_id).unwrap_err();
        assert!(matches!(error, KernelError::Web3EvidenceUnavailable(_)));
        assert!(error
            .to_string()
            .contains("append-only remote receipt mirrors are unsupported"));
    }

    #[test]
    fn web3_evidence_required_activation_allows_checkpoint_capable_store() {
        let path = unique_receipt_db_path("web3-evidence-capable");
        let mut config = make_config();
        config.require_web3_evidence = true;
        let mut kernel = ArcKernel::new(config);
        kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
        let session_id = kernel.open_session("agent-1".to_string(), Vec::new());

        kernel.activate_session(&session_id).unwrap();
        assert_eq!(
            kernel.session(&session_id).map(Session::state),
            Some(SessionState::Ready)
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn session_operation_tool_call_tracks_and_clears_inflight() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
        kernel.activate_session(&session_id).unwrap();

        let context = make_operation_context(&session_id, "req-1", &agent_kp.public_key().to_hex());
        let operation = SessionOperation::ToolCall(ToolCallOperation {
            capability: cap,
            server_id: "srv-a".to_string(),
            tool_name: "read_file".to_string(),
            arguments: serde_json::json!({"path": "/app/src/main.rs"}),
        });

        let response = session_tool_call(
            kernel
                .evaluate_session_operation(&context, &operation)
                .unwrap(),
        )
        .expect("expected tool call response");
        assert_eq!(response.verdict, Verdict::Allow);

        assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
    }

    #[test]
    fn session_operation_capability_list_uses_session_snapshot() {
        let mut kernel = ArcKernel::new(make_config());
        let agent_kp = make_keypair();
        let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap]);
        let context =
            make_operation_context(&session_id, "control-1", &agent_kp.public_key().to_hex());

        let response = kernel
            .evaluate_session_operation(&context, &SessionOperation::ListCapabilities)
            .unwrap();

        let capabilities =
            session_capability_list(response).expect("expected capability list response");
        assert_eq!(capabilities.len(), 1);
    }

    #[test]
    fn session_operation_list_roots_uses_session_snapshot() {
        let mut kernel = ArcKernel::new(make_config());
        let agent_kp = make_keypair();
        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_arc_tool_streaming: false,
                    supports_roots: true,
                    roots_list_changed: true,
                    supports_sampling: false,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: false,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();
        kernel
            .replace_session_roots(
                &session_id,
                vec![RootDefinition {
                    uri: "file:///workspace/project".to_string(),
                    name: Some("Project".to_string()),
                }],
            )
            .unwrap();

        let context =
            make_operation_context(&session_id, "roots-1", &agent_kp.public_key().to_hex());
        let response = kernel
            .evaluate_session_operation(&context, &SessionOperation::ListRoots)
            .unwrap();

        let roots = session_root_list(response).expect("expected root list response");
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].uri, "file:///workspace/project");
    }

    #[test]
    fn kernel_exposes_normalized_session_roots_for_later_enforcement() {
        let mut kernel = ArcKernel::new(make_config());
        let agent_kp = make_keypair();
        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .replace_session_roots(
                &session_id,
                vec![
                    RootDefinition {
                        uri: "file:///workspace/project/../project/src".to_string(),
                        name: Some("Code".to_string()),
                    },
                    RootDefinition {
                        uri: "repo://docs/roadmap".to_string(),
                        name: Some("Roadmap".to_string()),
                    },
                    RootDefinition {
                        uri: "file://remote-host/workspace/project".to_string(),
                        name: Some("Remote".to_string()),
                    },
                ],
            )
            .unwrap();

        let normalized = kernel.normalized_session_roots(&session_id).unwrap();
        assert_eq!(normalized.len(), 3);
        assert!(matches!(
            normalized[0],
            NormalizedRoot::EnforceableFileSystem {
                ref normalized_path,
                ..
            } if normalized_path == "/workspace/project/src"
        ));
        assert!(matches!(
            normalized[1],
            NormalizedRoot::NonFileSystem { ref scheme, .. } if scheme == "repo"
        ));
        assert!(matches!(
            normalized[2],
            NormalizedRoot::UnenforceableFileSystem { ref reason, .. }
                if reason == "non_local_file_authority"
        ));
        assert_eq!(
            kernel
                .enforceable_filesystem_root_paths(&session_id)
                .unwrap(),
            vec!["/workspace/project/src"]
        );
    }

    #[test]
    fn begin_child_request_requires_parent_lineage() {
        let mut kernel = ArcKernel::new(make_config());
        let agent_kp = make_keypair();
        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
        kernel.activate_session(&session_id).unwrap();

        let parent_context =
            make_operation_context(&session_id, "parent-1", &agent_kp.public_key().to_hex());
        kernel
            .begin_session_request(&parent_context, OperationKind::ToolCall, true)
            .unwrap();

        let child_context = kernel
            .begin_child_request(
                &parent_context,
                RequestId::new("child-1"),
                OperationKind::CreateMessage,
                None,
                true,
            )
            .unwrap();

        let child = kernel
            .session(&session_id)
            .unwrap()
            .inflight()
            .get(&child_context.request_id)
            .unwrap();
        assert_eq!(child.parent_request_id, Some(RequestId::new("parent-1")));
    }

    #[test]
    fn sampling_validation_requires_policy_and_negotiation() {
        let mut kernel = ArcKernel::new(make_config());
        let agent_kp = make_keypair();
        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
        kernel.activate_session(&session_id).unwrap();

        let parent_context =
            make_operation_context(&session_id, "parent-1", &agent_kp.public_key().to_hex());
        kernel
            .begin_session_request(&parent_context, OperationKind::ToolCall, true)
            .unwrap();

        let child_context = kernel
            .begin_child_request(
                &parent_context,
                RequestId::new("child-1"),
                OperationKind::CreateMessage,
                None,
                true,
            )
            .unwrap();
        let operation = CreateMessageOperation {
            messages: vec![SamplingMessage {
                role: "user".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "Summarize the diff"
                }),
                meta: None,
            }],
            model_preferences: None,
            system_prompt: None,
            include_context: None,
            temperature: None,
            max_tokens: 256,
            stop_sequences: vec![],
            metadata: None,
            tools: vec![],
            tool_choice: None,
        };

        let denied = kernel.validate_sampling_request(&child_context, &operation);
        assert!(matches!(
            denied,
            Err(KernelError::SamplingNotAllowedByPolicy)
        ));

        kernel.config.allow_sampling = true;
        let denied = kernel.validate_sampling_request(&child_context, &operation);
        assert!(matches!(denied, Err(KernelError::SamplingNotNegotiated)));

        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_arc_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: true,
                    sampling_context: true,
                    sampling_tools: false,
                    supports_elicitation: false,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();
        kernel
            .validate_sampling_request(&child_context, &operation)
            .unwrap();

        let tool_operation = CreateMessageOperation {
            tools: vec![SamplingTool {
                name: "search_docs".to_string(),
                description: Some("Search docs".to_string()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" }
                    }
                }),
            }],
            tool_choice: Some(SamplingToolChoice {
                mode: "auto".to_string(),
            }),
            ..operation
        };
        let denied = kernel.validate_sampling_request(&child_context, &tool_operation);
        assert!(matches!(
            denied,
            Err(KernelError::SamplingToolUseNotAllowedByPolicy)
        ));

        kernel.config.allow_sampling_tool_use = true;
        let denied = kernel.validate_sampling_request(&child_context, &tool_operation);
        assert!(matches!(
            denied,
            Err(KernelError::SamplingToolUseNotNegotiated)
        ));
    }

    #[test]
    fn elicitation_validation_requires_policy_and_form_negotiation() {
        let mut kernel = ArcKernel::new(make_config());
        let agent_kp = make_keypair();
        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
        kernel.activate_session(&session_id).unwrap();

        let parent_context = make_operation_context(
            &session_id,
            "parent-elicit-1",
            &agent_kp.public_key().to_hex(),
        );
        kernel
            .begin_session_request(&parent_context, OperationKind::ToolCall, true)
            .unwrap();

        let child_context = kernel
            .begin_child_request(
                &parent_context,
                RequestId::new("child-elicit-1"),
                OperationKind::CreateElicitation,
                None,
                true,
            )
            .unwrap();
        let operation = CreateElicitationOperation::Form {
            meta: None,
            message: "Which environment should this run against?".to_string(),
            requested_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "environment": {
                        "type": "string",
                        "enum": ["staging", "production"]
                    }
                },
                "required": ["environment"]
            }),
        };

        let denied = kernel.validate_elicitation_request(&child_context, &operation);
        assert!(matches!(
            denied,
            Err(KernelError::ElicitationNotAllowedByPolicy)
        ));

        kernel.config.allow_elicitation = true;
        let denied = kernel.validate_elicitation_request(&child_context, &operation);
        assert!(matches!(denied, Err(KernelError::ElicitationNotNegotiated)));

        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_arc_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: false,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: true,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();
        let denied = kernel.validate_elicitation_request(&child_context, &operation);
        assert!(matches!(
            denied,
            Err(KernelError::ElicitationFormNotSupported)
        ));

        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_arc_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: false,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: true,
                    elicitation_form: true,
                    elicitation_url: false,
                },
            )
            .unwrap();
        kernel
            .validate_elicitation_request(&child_context, &operation)
            .unwrap();

        let url_operation = CreateElicitationOperation::Url {
            meta: None,
            message: "Open the secure enrollment flow".to_string(),
            url: "https://example.test/consent".to_string(),
            elicitation_id: "elicitation-123".to_string(),
        };
        let denied = kernel.validate_elicitation_request(&child_context, &url_operation);
        assert!(matches!(
            denied,
            Err(KernelError::ElicitationUrlNotSupported)
        ));

        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_arc_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: false,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: true,
                    elicitation_form: true,
                    elicitation_url: true,
                },
            )
            .unwrap();
        kernel
            .validate_elicitation_request(&child_context, &url_operation)
            .unwrap();
    }

    #[test]
    fn tool_call_nested_flow_bridge_roundtrips_sampling() {
        let mut config = make_config();
        config.allow_sampling = true;
        let mut kernel = ArcKernel::new(config);
        kernel.register_tool_server(Box::new(NestedFlowServer {
            id: "nested".to_string(),
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("nested", "sample_via_client")]),
            300,
        );
        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_arc_tool_streaming: false,
                    supports_roots: true,
                    roots_list_changed: true,
                    supports_sampling: true,
                    sampling_context: true,
                    sampling_tools: false,
                    supports_elicitation: false,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();

        let mut client = MockNestedFlowClient {
            roots: vec![RootDefinition {
                uri: "file:///workspace/project".to_string(),
                name: Some("Project".to_string()),
            }],
            sampled_message: CreateMessageResult {
                role: "assistant".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "Roadmap summary",
                }),
                model: "gpt-test".to_string(),
                stop_reason: Some("end_turn".to_string()),
            },
            elicited_content: make_elicited_content(),
            cancel_parent_on_create_message: false,
            cancel_child_on_create_message: false,
            completed_elicitation_ids: Vec::new(),
            resource_updates: Vec::new(),
            resources_list_changed_count: 0,
        };
        let context = make_operation_context(
            &session_id,
            "nested-tool-1",
            &agent_kp.public_key().to_hex(),
        );
        let operation = ToolCallOperation {
            capability,
            server_id: "nested".to_string(),
            tool_name: "sample_via_client".to_string(),
            arguments: serde_json::json!({}),
        };

        let response = kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        let value = tool_call_value_output(response.output).expect("expected value output");
        assert_eq!(value["model"], "gpt-test");
        assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
        assert_eq!(kernel.child_receipt_log().len(), 1);
        let child_receipt = kernel.child_receipt_log().get(0).unwrap();
        assert_eq!(child_receipt.parent_request_id, context.request_id);
        assert_eq!(child_receipt.operation_kind, OperationKind::CreateMessage);
        assert_eq!(
            child_receipt.terminal_state,
            OperationTerminalState::Completed
        );
        assert!(child_receipt.verify_signature().unwrap());
        assert_eq!(
            child_receipt.metadata.as_ref().unwrap()["outcome"],
            "result"
        );
    }

    #[test]
    fn kernel_persists_child_receipts_to_sqlite_store() {
        let path = unique_receipt_db_path("arc-kernel-child-receipts");
        let mut config = make_config();
        config.allow_sampling = true;
        let mut kernel = ArcKernel::new(config);
        kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
        kernel.register_tool_server(Box::new(NestedFlowServer {
            id: "nested".to_string(),
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("nested", "sample_via_client")]),
            300,
        );
        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_arc_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: true,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: false,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();

        let mut client = MockNestedFlowClient {
            roots: Vec::new(),
            sampled_message: CreateMessageResult {
                role: "assistant".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "sampled via durable store test",
                }),
                model: "gpt-test".to_string(),
                stop_reason: None,
            },
            elicited_content: make_elicited_content(),
            cancel_parent_on_create_message: false,
            cancel_child_on_create_message: false,
            completed_elicitation_ids: Vec::new(),
            resource_updates: Vec::new(),
            resources_list_changed_count: 0,
        };
        let context = make_operation_context(
            &session_id,
            "nested-tool-sqlite-1",
            &agent_kp.public_key().to_hex(),
        );
        let operation = ToolCallOperation {
            capability,
            server_id: "nested".to_string(),
            tool_name: "sample_via_client".to_string(),
            arguments: serde_json::json!({}),
        };

        let response = kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
            .unwrap();
        assert_eq!(response.verdict, Verdict::Allow);
        drop(kernel);

        let connection = rusqlite::Connection::open(&path).unwrap();
        let tool_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM arc_tool_receipts", [], |row| {
                row.get(0)
            })
            .unwrap();
        let (child_count, distinct_child_count, child_receipt_id): (i64, i64, String) =
            connection
                .query_row(
                    "SELECT COUNT(*), COUNT(DISTINCT receipt_id), MIN(receipt_id) FROM arc_child_receipts",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();

        assert_eq!(tool_count, 1);
        assert_eq!(child_count, 1);
        assert_eq!(distinct_child_count, 1);
        assert!(child_receipt_id.starts_with("child-rcpt-"));

        drop(connection);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tool_call_nested_flow_bridge_roundtrips_elicitation() {
        let mut config = make_config();
        config.allow_elicitation = true;
        let mut kernel = ArcKernel::new(config);
        kernel.register_tool_server(Box::new(NestedFlowServer {
            id: "nested".to_string(),
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("nested", "elicit_via_client")]),
            300,
        );
        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_arc_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: false,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: true,
                    elicitation_form: true,
                    elicitation_url: false,
                },
            )
            .unwrap();

        let mut client = MockNestedFlowClient {
            roots: Vec::new(),
            sampled_message: CreateMessageResult {
                role: "assistant".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "unused",
                }),
                model: "unused".to_string(),
                stop_reason: None,
            },
            elicited_content: make_elicited_content(),
            cancel_parent_on_create_message: false,
            cancel_child_on_create_message: false,
            completed_elicitation_ids: Vec::new(),
            resource_updates: Vec::new(),
            resources_list_changed_count: 0,
        };
        let context = make_operation_context(
            &session_id,
            "nested-tool-elicit-1",
            &agent_kp.public_key().to_hex(),
        );
        let operation = ToolCallOperation {
            capability,
            server_id: "nested".to_string(),
            tool_name: "elicit_via_client".to_string(),
            arguments: serde_json::json!({}),
        };

        let response = kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        let value = tool_call_value_output(response.output).expect("expected value output");
        assert_eq!(value["action"], "accept");
        assert_eq!(value["content"]["environment"], "staging");
        assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
    }

    #[test]
    fn tool_call_nested_flow_bridge_updates_session_roots() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(NestedFlowServer {
            id: "nested".to_string(),
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("nested", "roots_via_client")]),
            300,
        );
        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: false,
                    supports_subscriptions: false,
                    supports_arc_tool_streaming: false,
                    supports_roots: true,
                    roots_list_changed: true,
                    supports_sampling: false,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: false,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();

        let expected_roots = vec![RootDefinition {
            uri: "file:///workspace/project".to_string(),
            name: Some("Project".to_string()),
        }];
        let mut client = MockNestedFlowClient {
            roots: expected_roots.clone(),
            sampled_message: CreateMessageResult {
                role: "assistant".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "unused",
                }),
                model: "unused".to_string(),
                stop_reason: None,
            },
            elicited_content: make_elicited_content(),
            cancel_parent_on_create_message: false,
            cancel_child_on_create_message: false,
            completed_elicitation_ids: Vec::new(),
            resource_updates: Vec::new(),
            resources_list_changed_count: 0,
        };
        let context = make_operation_context(
            &session_id,
            "nested-tool-2",
            &agent_kp.public_key().to_hex(),
        );
        let operation = ToolCallOperation {
            capability,
            server_id: "nested".to_string(),
            tool_name: "roots_via_client".to_string(),
            arguments: serde_json::json!({}),
        };

        let response = kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(kernel.session(&session_id).unwrap().roots(), expected_roots);
    }

    #[test]
    fn tool_call_nested_flow_bridge_propagates_parent_cancellation() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.config.allow_sampling = true;
        kernel.register_tool_server(Box::new(NestedFlowServer {
            id: "nested".to_string(),
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("nested", "sample_via_client")]),
            300,
        );
        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: true,
                    supports_subscriptions: false,
                    supports_arc_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: true,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: false,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();

        let mut client = MockNestedFlowClient {
            roots: Vec::new(),
            sampled_message: CreateMessageResult {
                role: "assistant".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "unused",
                }),
                model: "unused".to_string(),
                stop_reason: None,
            },
            elicited_content: make_elicited_content(),
            cancel_parent_on_create_message: true,
            cancel_child_on_create_message: false,
            completed_elicitation_ids: Vec::new(),
            resource_updates: Vec::new(),
            resources_list_changed_count: 0,
        };
        let context = make_operation_context(
            &session_id,
            "nested-tool-parent-cancel",
            &agent_kp.public_key().to_hex(),
        );
        let operation = ToolCallOperation {
            capability,
            server_id: "nested".to_string(),
            tool_name: "sample_via_client".to_string(),
            arguments: serde_json::json!({}),
        };

        let response = kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
            .unwrap();
        let expected_reason = "client cancelled parent request".to_string();

        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(response.reason.as_deref(), Some(expected_reason.as_str()));
        assert_eq!(
            response.terminal_state,
            OperationTerminalState::Cancelled {
                reason: expected_reason.clone(),
            }
        );
        assert!(response.receipt.is_cancelled());
        assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
        assert_eq!(
            kernel
                .session(&session_id)
                .unwrap()
                .terminal()
                .get(&context.request_id),
            Some(&OperationTerminalState::Cancelled {
                reason: expected_reason,
            })
        );
    }

    #[test]
    fn tool_call_nested_flow_bridge_propagates_child_cancellation() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.config.allow_sampling = true;
        kernel.register_tool_server(Box::new(NestedFlowServer {
            id: "nested".to_string(),
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("nested", "sample_via_client")]),
            300,
        );
        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .set_session_peer_capabilities(
                &session_id,
                PeerCapabilities {
                    supports_progress: false,
                    supports_cancellation: true,
                    supports_subscriptions: false,
                    supports_arc_tool_streaming: false,
                    supports_roots: false,
                    roots_list_changed: false,
                    supports_sampling: true,
                    sampling_context: false,
                    sampling_tools: false,
                    supports_elicitation: false,
                    elicitation_form: false,
                    elicitation_url: false,
                },
            )
            .unwrap();

        let mut client = MockNestedFlowClient {
            roots: Vec::new(),
            sampled_message: CreateMessageResult {
                role: "assistant".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "unused",
                }),
                model: "unused".to_string(),
                stop_reason: None,
            },
            elicited_content: make_elicited_content(),
            cancel_parent_on_create_message: false,
            cancel_child_on_create_message: true,
            completed_elicitation_ids: Vec::new(),
            resource_updates: Vec::new(),
            resources_list_changed_count: 0,
        };
        let context = make_operation_context(
            &session_id,
            "nested-tool-child-cancel",
            &agent_kp.public_key().to_hex(),
        );
        let operation = ToolCallOperation {
            capability,
            server_id: "nested".to_string(),
            tool_name: "sample_via_client".to_string(),
            arguments: serde_json::json!({}),
        };

        let response = kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
            .unwrap();
        let expected_reason = "client cancelled nested request".to_string();

        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(response.reason.as_deref(), Some(expected_reason.as_str()));
        assert_eq!(
            response.terminal_state,
            OperationTerminalState::Cancelled {
                reason: expected_reason.clone(),
            }
        );
        assert!(response.receipt.is_cancelled());
        assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
        assert_eq!(
            kernel
                .session(&session_id)
                .unwrap()
                .terminal()
                .get(&context.request_id),
            Some(&OperationTerminalState::Cancelled {
                reason: expected_reason,
            })
        );
        assert_eq!(kernel.child_receipt_log().len(), 1);
        let child_receipt = kernel.child_receipt_log().get(0).unwrap();
        assert_eq!(child_receipt.parent_request_id, context.request_id);
        assert_eq!(child_receipt.operation_kind, OperationKind::CreateMessage);
        assert_eq!(
            child_receipt.terminal_state,
            OperationTerminalState::Cancelled {
                reason: "client cancelled nested request".to_string(),
            }
        );
        assert!(child_receipt.verify_signature().unwrap());
        assert_eq!(
            kernel
                .session(&session_id)
                .unwrap()
                .terminal()
                .get(&child_receipt.request_id),
            Some(&OperationTerminalState::Cancelled {
                reason: "client cancelled nested request".to_string(),
            })
        );
    }

    #[test]
    fn session_tool_call_records_incomplete_terminal_state() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(IncompleteServer {
            id: "broken".to_string(),
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("broken", "drop_stream")]),
            300,
        );
        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
        kernel.activate_session(&session_id).unwrap();

        let context = make_operation_context(
            &session_id,
            "incomplete-tool-call",
            &agent_kp.public_key().to_hex(),
        );
        let operation = SessionOperation::ToolCall(ToolCallOperation {
            capability,
            server_id: "broken".to_string(),
            tool_name: "drop_stream".to_string(),
            arguments: serde_json::json!({}),
        });

        let response = session_tool_call(
            kernel
                .evaluate_session_operation(&context, &operation)
                .unwrap(),
        )
        .expect("expected tool call response");

        let expected_reason = "upstream stream closed before tool response completed".to_string();
        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(response.reason.as_deref(), Some(expected_reason.as_str()));
        assert_eq!(
            response.terminal_state,
            OperationTerminalState::Incomplete {
                reason: expected_reason.clone(),
            }
        );
        assert!(response.receipt.is_incomplete());
        assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
        assert_eq!(
            kernel
                .session(&session_id)
                .unwrap()
                .terminal()
                .get(&context.request_id),
            Some(&OperationTerminalState::Incomplete {
                reason: expected_reason,
            })
        );
    }

    #[test]
    fn streamed_tool_receipt_records_chunk_hash_metadata() {
        let mut kernel = ArcKernel::new(make_config());
        let chunk_a = serde_json::json!({"delta": "hello"});
        let chunk_b = serde_json::json!({"delta": {"path": "/workspace/README.md"}});
        kernel.register_tool_server(Box::new(StreamingServer {
            id: "stream".to_string(),
            chunks: vec![chunk_a.clone(), chunk_b.clone()],
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("stream", "stream_file")]),
            300,
        );
        let request = make_request_with_arguments(
            "stream-receipt",
            &capability,
            "stream_file",
            "stream",
            serde_json::json!({"path": "/workspace/README.md"}),
        );

        let response = kernel.evaluate_tool_call(&request).unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        let metadata = response.receipt.metadata.as_ref().expect("stream metadata");
        let stream_metadata = metadata.get("stream").expect("stream metadata object");
        assert_eq!(stream_metadata["chunks_expected"].as_u64(), Some(2));
        assert_eq!(stream_metadata["chunks_received"].as_u64(), Some(2));

        let chunk_a_bytes = arc_core::canonical::canonical_json_bytes(&chunk_a).unwrap();
        let chunk_b_bytes = arc_core::canonical::canonical_json_bytes(&chunk_b).unwrap();
        let expected_total_bytes = (chunk_a_bytes.len() + chunk_b_bytes.len()) as u64;
        assert_eq!(
            stream_metadata["total_bytes"].as_u64(),
            Some(expected_total_bytes)
        );

        let chunk_hashes = stream_metadata["chunk_hashes"]
            .as_array()
            .expect("chunk hashes array")
            .iter()
            .map(|value| value.as_str().expect("chunk hash string").to_string())
            .collect::<Vec<_>>();
        let expected_hashes = vec![
            arc_core::crypto::sha256_hex(&chunk_a_bytes),
            arc_core::crypto::sha256_hex(&chunk_b_bytes),
        ];
        assert_eq!(chunk_hashes, expected_hashes);

        let expected_content_hash =
            arc_core::crypto::sha256_hex(expected_hashes.join("").as_bytes());
        assert_eq!(response.receipt.content_hash, expected_content_hash);
    }

    #[test]
    fn streamed_tool_byte_limit_truncates_output_and_marks_receipt_incomplete() {
        let mut config = make_config();
        config.max_stream_total_bytes = 20;
        let mut kernel = ArcKernel::new(config);
        let first_chunk = serde_json::json!({"delta": "ok"});
        let second_chunk =
            serde_json::json!({"delta": "this chunk exceeds the configured byte limit"});
        kernel.register_tool_server(Box::new(StreamingServer {
            id: "stream".to_string(),
            chunks: vec![first_chunk.clone(), second_chunk],
        }));

        let agent_kp = make_keypair();
        let capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("stream", "stream_file")]),
            300,
        );
        let request = make_request_with_arguments(
            "stream-byte-limit",
            &capability,
            "stream_file",
            "stream",
            serde_json::json!({}),
        );

        let response = kernel.evaluate_tool_call(&request).unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.receipt.is_incomplete());
        assert!(matches!(
            response.terminal_state,
            OperationTerminalState::Incomplete { .. }
        ));
        assert!(response
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("max total bytes"));

        let output_stream =
            tool_call_stream_output(response.output).expect("expected stream output");
        assert_eq!(output_stream.chunk_count(), 1);
        assert_eq!(output_stream.chunks[0].data, first_chunk);

        let stream_metadata = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("stream"))
            .expect("stream metadata");
        assert!(stream_metadata["chunks_expected"].is_null());
        assert_eq!(stream_metadata["chunks_received"].as_u64(), Some(1));
    }

    #[test]
    fn apply_stream_limits_marks_duration_exceeded_stream_incomplete() {
        let mut config = make_config();
        config.max_stream_duration_secs = 1;
        let kernel = ArcKernel::new(config);
        let output = ToolServerOutput::Stream(ToolServerStreamResult::Complete(ToolCallStream {
            chunks: vec![ToolCallChunk {
                data: serde_json::json!({"delta": "slow"}),
            }],
        }));

        let limited = kernel
            .apply_stream_limits(output, std::time::Duration::from_secs(2))
            .unwrap();

        let (stream, reason) = match limited {
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => {
                Some((stream, reason))
            }
            _ => None,
        }
        .expect("expected limited incomplete stream");
        assert_eq!(stream.chunk_count(), 1);
        assert!(reason.contains("max duration of 1s"));
    }

    #[test]
    fn tool_call_nested_flow_bridge_filters_resource_notifications_to_session_subscriptions() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_tool_server(Box::new(NestedFlowServer {
            id: "nested".to_string(),
        }));
        kernel.register_resource_provider(Box::new(DocsResourceProvider));

        let agent_kp = make_keypair();
        let tool_capability = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("nested", "notify_resources_via_client")]),
            300,
        );
        let resource_capability = make_capability(
            &kernel,
            &agent_kp,
            ArcScope {
                resource_grants: vec![ResourceGrant {
                    uri_pattern: "repo://docs/*".to_string(),
                    operations: vec![Operation::Read, Operation::Subscribe],
                }],
                ..ArcScope::default()
            },
            300,
        );
        let session_id = kernel.open_session(
            agent_kp.public_key().to_hex(),
            vec![tool_capability.clone(), resource_capability.clone()],
        );
        kernel.activate_session(&session_id).unwrap();
        kernel
            .subscribe_session_resource(
                &session_id,
                &resource_capability,
                &agent_kp.public_key().to_hex(),
                "repo://docs/roadmap",
            )
            .unwrap();

        let mut client = MockNestedFlowClient {
            roots: Vec::new(),
            sampled_message: CreateMessageResult {
                role: "assistant".to_string(),
                content: serde_json::json!({
                    "type": "text",
                    "text": "unused",
                }),
                model: "unused".to_string(),
                stop_reason: None,
            },
            elicited_content: make_elicited_content(),
            cancel_parent_on_create_message: false,
            cancel_child_on_create_message: false,
            completed_elicitation_ids: Vec::new(),
            resource_updates: Vec::new(),
            resources_list_changed_count: 0,
        };
        let context = make_operation_context(
            &session_id,
            "nested-tool-resource-notify",
            &agent_kp.public_key().to_hex(),
        );
        let operation = ToolCallOperation {
            capability: tool_capability,
            server_id: "nested".to_string(),
            tool_name: "notify_resources_via_client".to_string(),
            arguments: serde_json::json!({}),
        };

        let response = kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(
            client.resource_updates,
            vec!["repo://docs/roadmap".to_string()]
        );
        assert_eq!(client.resources_list_changed_count, 1);
    }

    #[test]
    fn session_operation_list_resources_filters_to_session_scope() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_resource_provider(Box::new(DocsResourceProvider));

        let agent_kp = make_keypair();
        let scope = ArcScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read],
            }],
            ..ArcScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap]);
        kernel.activate_session(&session_id).unwrap();
        let context =
            make_operation_context(&session_id, "resources-1", &agent_kp.public_key().to_hex());

        let response = kernel
            .evaluate_session_operation(&context, &SessionOperation::ListResources)
            .unwrap();

        let resources = session_resource_list(response).expect("expected resource list response");
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].uri, "repo://docs/roadmap");
    }

    #[test]
    fn session_operation_read_resource_enforces_scope() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_resource_provider(Box::new(DocsResourceProvider));

        let agent_kp = make_keypair();
        let scope = ArcScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read],
            }],
            ..ArcScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
        kernel.activate_session(&session_id).unwrap();

        let allowed_context = make_operation_context(
            &session_id,
            "resource-read-1",
            &agent_kp.public_key().to_hex(),
        );
        let allowed = kernel
            .evaluate_session_operation(
                &allowed_context,
                &SessionOperation::ReadResource(ReadResourceOperation {
                    capability: cap.clone(),
                    uri: "repo://docs/roadmap".to_string(),
                }),
            )
            .unwrap();
        let contents = session_resource_read(allowed).expect("expected resource read response");
        assert_eq!(contents[0].text.as_deref(), Some("# Roadmap"));

        let denied_context = make_operation_context(
            &session_id,
            "resource-read-2",
            &agent_kp.public_key().to_hex(),
        );
        let denied = kernel.evaluate_session_operation(
            &denied_context,
            &SessionOperation::ReadResource(ReadResourceOperation {
                capability: cap,
                uri: "repo://secret/ops".to_string(),
            }),
        );
        assert!(matches!(
            denied,
            Err(KernelError::OutOfScopeResource { .. })
        ));
    }

    #[test]
    fn session_operation_read_resource_enforces_session_roots_for_filesystem_resources() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_resource_provider(Box::new(FilesystemResourceProvider));

        let agent_kp = make_keypair();
        let scope = ArcScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "file:///workspace/*".to_string(),
                operations: vec![Operation::Read],
            }],
            ..ArcScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .replace_session_roots(
                &session_id,
                vec![RootDefinition {
                    uri: "file:///workspace/project".to_string(),
                    name: Some("Project".to_string()),
                }],
            )
            .unwrap();

        let allowed_context = make_operation_context(
            &session_id,
            "resource-read-file-1",
            &agent_kp.public_key().to_hex(),
        );
        let allowed = kernel
            .evaluate_session_operation(
                &allowed_context,
                &SessionOperation::ReadResource(ReadResourceOperation {
                    capability: cap.clone(),
                    uri: "file:///workspace/project/docs/roadmap.md".to_string(),
                }),
            )
            .unwrap();
        let contents = session_resource_read(allowed).expect("expected resource read response");
        assert_eq!(contents[0].text.as_deref(), Some("# Filesystem Roadmap"));

        let denied_context = make_operation_context(
            &session_id,
            "resource-read-file-2",
            &agent_kp.public_key().to_hex(),
        );
        let denied = kernel.evaluate_session_operation(
            &denied_context,
            &SessionOperation::ReadResource(ReadResourceOperation {
                capability: cap,
                uri: "file:///workspace/private/ops.md".to_string(),
            }),
        );
        let receipt = match denied {
            Ok(SessionOperationResponse::ResourceReadDenied { receipt }) => Some(receipt),
            _ => None,
        }
        .expect("expected signed resource read denial");
        assert!(receipt.verify_signature().unwrap());
        assert!(receipt.is_denied());
        assert_eq!(receipt.tool_name, "resources/read");
        assert_eq!(receipt.tool_server, "session");
        assert_eq!(
            receipt.decision,
            Decision::Deny {
                reason:
                    "filesystem-backed resource path /workspace/private/ops.md is outside the negotiated roots"
                        .to_string(),
                guard: "session_roots".to_string(),
            }
        );
    }

    #[test]
    fn session_operation_read_resource_fails_closed_when_filesystem_roots_are_missing() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_resource_provider(Box::new(FilesystemResourceProvider));

        let agent_kp = make_keypair();
        let scope = ArcScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "file:///workspace/*".to_string(),
                operations: vec![Operation::Read],
            }],
            ..ArcScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
        kernel.activate_session(&session_id).unwrap();

        let context = make_operation_context(
            &session_id,
            "resource-read-file-3",
            &agent_kp.public_key().to_hex(),
        );
        let denied = kernel.evaluate_session_operation(
            &context,
            &SessionOperation::ReadResource(ReadResourceOperation {
                capability: cap,
                uri: "file:///workspace/project/docs/roadmap.md".to_string(),
            }),
        );
        let receipt = match denied {
            Ok(SessionOperationResponse::ResourceReadDenied { receipt }) => Some(receipt),
            _ => None,
        }
        .expect("expected signed resource read denial");
        assert!(receipt.verify_signature().unwrap());
        assert!(receipt.is_denied());
        assert_eq!(
            receipt.decision,
            Decision::Deny {
                reason: "no enforceable filesystem roots are available for this session"
                    .to_string(),
                guard: "session_roots".to_string(),
            }
        );
    }

    #[test]
    fn subscribe_session_resource_requires_subscribe_operation() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_resource_provider(Box::new(DocsResourceProvider));

        let agent_kp = make_keypair();
        let read_only_scope = ArcScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read],
            }],
            ..ArcScope::default()
        };
        let read_only_cap = make_capability(&kernel, &agent_kp, read_only_scope, 300);

        let session_id =
            kernel.open_session(agent_kp.public_key().to_hex(), vec![read_only_cap.clone()]);
        kernel.activate_session(&session_id).unwrap();

        let denied = kernel.subscribe_session_resource(
            &session_id,
            &read_only_cap,
            &agent_kp.public_key().to_hex(),
            "repo://docs/roadmap",
        );
        assert!(matches!(
            denied,
            Err(KernelError::OutOfScopeResource { .. })
        ));

        let subscribe_scope = ArcScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read, Operation::Subscribe],
            }],
            ..ArcScope::default()
        };
        let subscribe_cap = make_capability(&kernel, &agent_kp, subscribe_scope, 300);
        kernel
            .subscribe_session_resource(
                &session_id,
                &subscribe_cap,
                &agent_kp.public_key().to_hex(),
                "repo://docs/roadmap",
            )
            .unwrap();

        assert!(kernel
            .session_has_resource_subscription(&session_id, "repo://docs/roadmap")
            .unwrap());
    }

    #[test]
    fn unsubscribe_session_resource_is_idempotent() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_resource_provider(Box::new(DocsResourceProvider));

        let agent_kp = make_keypair();
        let scope = ArcScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read, Operation::Subscribe],
            }],
            ..ArcScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
        kernel.activate_session(&session_id).unwrap();
        kernel
            .subscribe_session_resource(
                &session_id,
                &cap,
                &agent_kp.public_key().to_hex(),
                "repo://docs/roadmap",
            )
            .unwrap();

        kernel
            .unsubscribe_session_resource(&session_id, "repo://docs/roadmap")
            .unwrap();
        kernel
            .unsubscribe_session_resource(&session_id, "repo://docs/roadmap")
            .unwrap();

        assert!(!kernel
            .session_has_resource_subscription(&session_id, "repo://docs/roadmap")
            .unwrap());
    }

    #[test]
    fn session_operation_get_prompt_enforces_scope() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_prompt_provider(Box::new(ExamplePromptProvider));

        let agent_kp = make_keypair();
        let scope = ArcScope {
            prompt_grants: vec![PromptGrant {
                prompt_name: "summarize_*".to_string(),
                operations: vec![Operation::Get],
            }],
            ..ArcScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
        kernel.activate_session(&session_id).unwrap();

        let list_context =
            make_operation_context(&session_id, "prompts-1", &agent_kp.public_key().to_hex());
        let list_response = kernel
            .evaluate_session_operation(&list_context, &SessionOperation::ListPrompts)
            .unwrap();
        let prompts = session_prompt_list(list_response).expect("expected prompt list response");
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].name, "summarize_docs");

        let get_context =
            make_operation_context(&session_id, "prompts-2", &agent_kp.public_key().to_hex());
        let get_response = kernel
            .evaluate_session_operation(
                &get_context,
                &SessionOperation::GetPrompt(GetPromptOperation {
                    capability: cap.clone(),
                    prompt_name: "summarize_docs".to_string(),
                    arguments: serde_json::json!({"topic": "roadmap"}),
                }),
            )
            .unwrap();
        let prompt = session_prompt_get(get_response).expect("expected prompt get response");
        assert_eq!(prompt.messages[0].content["text"], "Summarize roadmap");

        let denied_context =
            make_operation_context(&session_id, "prompts-3", &agent_kp.public_key().to_hex());
        let denied = kernel.evaluate_session_operation(
            &denied_context,
            &SessionOperation::GetPrompt(GetPromptOperation {
                capability: cap,
                prompt_name: "ops_secret".to_string(),
                arguments: serde_json::json!({}),
            }),
        );
        assert!(matches!(denied, Err(KernelError::OutOfScopePrompt { .. })));
    }

    #[test]
    fn session_operation_completion_returns_candidates_and_enforces_scope() {
        let mut kernel = ArcKernel::new(make_config());
        kernel.register_resource_provider(Box::new(DocsResourceProvider));
        kernel.register_prompt_provider(Box::new(ExamplePromptProvider));

        let agent_kp = make_keypair();
        let scope = ArcScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read],
            }],
            prompt_grants: vec![PromptGrant {
                prompt_name: "summarize_*".to_string(),
                operations: vec![Operation::Get],
            }],
            ..ArcScope::default()
        };
        let cap = make_capability(&kernel, &agent_kp, scope, 300);

        let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
        kernel.activate_session(&session_id).unwrap();

        let prompt_context =
            make_operation_context(&session_id, "complete-1", &agent_kp.public_key().to_hex());
        let prompt_completion = kernel
            .evaluate_session_operation(
                &prompt_context,
                &SessionOperation::Complete(CompleteOperation {
                    capability: cap.clone(),
                    reference: CompletionReference::Prompt {
                        name: "summarize_docs".to_string(),
                    },
                    argument: CompletionArgument {
                        name: "topic".to_string(),
                        value: "r".to_string(),
                    },
                    context_arguments: serde_json::json!({}),
                }),
            )
            .unwrap();
        let completion =
            session_completion(prompt_completion).expect("expected completion response");
        assert_eq!(completion.total, Some(2));
        assert_eq!(completion.values, vec!["roadmap", "release-plan"]);

        let resource_context =
            make_operation_context(&session_id, "complete-2", &agent_kp.public_key().to_hex());
        let resource_completion = kernel
            .evaluate_session_operation(
                &resource_context,
                &SessionOperation::Complete(CompleteOperation {
                    capability: cap.clone(),
                    reference: CompletionReference::Resource {
                        uri: "repo://docs/{slug}".to_string(),
                    },
                    argument: CompletionArgument {
                        name: "slug".to_string(),
                        value: "a".to_string(),
                    },
                    context_arguments: serde_json::json!({}),
                }),
            )
            .unwrap();
        let completion =
            session_completion(resource_completion).expect("expected completion response");
        assert_eq!(completion.total, Some(2));
        assert_eq!(completion.values, vec!["architecture", "api"]);

        let denied_context =
            make_operation_context(&session_id, "complete-3", &agent_kp.public_key().to_hex());
        let denied = kernel.evaluate_session_operation(
            &denied_context,
            &SessionOperation::Complete(CompleteOperation {
                capability: cap,
                reference: CompletionReference::Prompt {
                    name: "ops_secret".to_string(),
                },
                argument: CompletionArgument {
                    name: "topic".to_string(),
                    value: "o".to_string(),
                },
                context_arguments: serde_json::json!({}),
            }),
        );
        assert!(matches!(denied, Err(KernelError::OutOfScopePrompt { .. })));
    }

    /// A tool server that always reports a specific actual cost.
    struct MonetaryCostServer {
        id: String,
        reported_cost: Option<ToolInvocationCost>,
    }

    struct FailingMonetaryServer {
        id: String,
    }

    struct CountingMonetaryServer {
        id: String,
        invocations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    struct StaticPriceOracle {
        rates: std::collections::BTreeMap<(String, String), Result<ExchangeRate, PriceOracleError>>,
    }

    impl StaticPriceOracle {
        fn new(
            rates: impl IntoIterator<Item = ((String, String), Result<ExchangeRate, PriceOracleError>)>,
        ) -> Self {
            Self {
                rates: rates.into_iter().collect(),
            }
        }
    }

    impl PriceOracle for StaticPriceOracle {
        fn get_rate<'a>(
            &'a self,
            base: &'a str,
            quote: &'a str,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = Result<ExchangeRate, PriceOracleError>>
                    + Send
                    + 'a,
            >,
        > {
            let response = self
                .rates
                .get(&(base.to_ascii_uppercase(), quote.to_ascii_uppercase()))
                .cloned()
                .unwrap_or_else(|| {
                    Err(PriceOracleError::NoPairAvailable {
                        base: base.to_ascii_uppercase(),
                        quote: quote.to_ascii_uppercase(),
                    })
                });
            Box::pin(async move { response })
        }

        fn supported_pairs(&self) -> Vec<String> {
            self.rates
                .keys()
                .map(|(base, quote)| format!("{base}/{quote}"))
                .collect()
        }
    }

    impl MonetaryCostServer {
        fn new(id: &str, cost_units: u64, currency: &str) -> Self {
            Self {
                id: id.to_string(),
                reported_cost: Some(ToolInvocationCost {
                    units: cost_units,
                    currency: currency.to_string(),
                    breakdown: None,
                }),
            }
        }

        fn no_cost(id: &str) -> Self {
            Self {
                id: id.to_string(),
                reported_cost: None,
            }
        }
    }

    impl ToolServerConnection for MonetaryCostServer {
        fn server_id(&self) -> &str {
            &self.id
        }

        fn tool_names(&self) -> Vec<String> {
            vec![
                "compute".to_string(),
                "compute-a".to_string(),
                "compute-b".to_string(),
            ]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            Ok(serde_json::json!({"result": "ok"}))
        }

        fn invoke_with_cost(
            &self,
            tool_name: &str,
            arguments: serde_json::Value,
            bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
            let value = self.invoke(tool_name, arguments, bridge)?;
            Ok((value, self.reported_cost.clone()))
        }
    }

    impl ToolServerConnection for FailingMonetaryServer {
        fn server_id(&self) -> &str {
            &self.id
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["compute".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            Err(KernelError::Internal("tool server failure".to_string()))
        }

        fn invoke_with_cost(
            &self,
            tool_name: &str,
            arguments: serde_json::Value,
            bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
            let _ = (tool_name, arguments, bridge);
            Err(KernelError::Internal("tool server failure".to_string()))
        }
    }

    impl ToolServerConnection for CountingMonetaryServer {
        fn server_id(&self) -> &str {
            &self.id
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["compute".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            self.invocations
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(serde_json::json!({"result": "ok"}))
        }

        fn invoke_with_cost(
            &self,
            tool_name: &str,
            arguments: serde_json::Value,
            bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
            let value = self.invoke(tool_name, arguments, bridge)?;
            Ok((value, None))
        }
    }

    fn make_monetary_grant(
        server: &str,
        tool: &str,
        max_cost_per_invocation: u64,
        max_total_cost: u64,
        currency: &str,
    ) -> ToolGrant {
        use arc_core::capability::MonetaryAmount;
        ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: max_cost_per_invocation,
                currency: currency.to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: max_total_cost,
                currency: currency.to_string(),
            }),
            dpop_required: None,
        }
    }

    fn make_monetary_config() -> KernelConfig {
        KernelConfig {
            keypair: make_keypair(),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "monetary-policy-hash".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        }
    }

    fn spawn_payment_test_server(
        status_code: u16,
        body: serde_json::Value,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should expose local address");
        let (request_tx, request_rx) = mpsc::channel();
        let body_text = body.to_string();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("server should accept request");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            let mut header_end = None;
            let mut content_length = 0_usize;

            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("server should configure read timeout");
            loop {
                let read = stream
                    .read(&mut chunk)
                    .expect("server should read request bytes");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);

                if header_end.is_none() {
                    header_end = find_http_header_end(&request);
                    if let Some(end) = header_end {
                        content_length = parse_http_content_length(&request[..end]);
                    }
                }

                if let Some(end) = header_end {
                    if request.len() >= end + content_length {
                        break;
                    }
                }
            }

            request_tx
                .send(String::from_utf8_lossy(&request).into_owned())
                .expect("request should be sent to test");
            let response = format!(
                "HTTP/1.1 {status_code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                http_status_text(status_code),
                body_text.len(),
                body_text
            );
            stream
                .write_all(response.as_bytes())
                .expect("server should write response");
        });

        (format!("http://{address}"), request_rx, handle)
    }

    fn find_http_header_end(request: &[u8]) -> Option<usize> {
        request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
    }

    fn parse_http_content_length(headers: &[u8]) -> usize {
        let text = String::from_utf8_lossy(headers);
        text.lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn http_status_text(status_code: u16) -> &'static str {
        match status_code {
            200 => "OK",
            402 => "Payment Required",
            _ => "Error",
        }
    }

    fn make_governed_monetary_grant(
        server: &str,
        tool: &str,
        max_cost_per_invocation: u64,
        max_total_cost: u64,
        currency: &str,
        approval_threshold_units: u64,
    ) -> ToolGrant {
        let mut grant = make_monetary_grant(
            server,
            tool,
            max_cost_per_invocation,
            max_total_cost,
            currency,
        );
        grant.constraints = vec![
            Constraint::GovernedIntentRequired,
            Constraint::RequireApprovalAbove {
                threshold_units: approval_threshold_units,
            },
        ];
        grant
    }

    fn with_minimum_runtime_assurance(
        mut grant: ToolGrant,
        tier: RuntimeAssuranceTier,
    ) -> ToolGrant {
        grant
            .constraints
            .push(Constraint::MinimumRuntimeAssurance(tier));
        grant
    }

    fn with_minimum_autonomy_tier(mut grant: ToolGrant, tier: GovernedAutonomyTier) -> ToolGrant {
        grant
            .constraints
            .push(Constraint::MinimumAutonomyTier(tier));
        grant
    }

    fn make_governed_acp_monetary_grant(
        server: &str,
        tool: &str,
        seller: &str,
        max_cost_per_invocation: u64,
        max_total_cost: u64,
        currency: &str,
        approval_threshold_units: u64,
    ) -> ToolGrant {
        let mut grant = make_governed_monetary_grant(
            server,
            tool,
            max_cost_per_invocation,
            max_total_cost,
            currency,
            approval_threshold_units,
        );
        grant
            .constraints
            .push(Constraint::SellerExact(seller.to_string()));
        grant
    }

    fn make_governed_intent(
        id: &str,
        server: &str,
        tool: &str,
        purpose: &str,
        units: u64,
        currency: &str,
    ) -> GovernedTransactionIntent {
        GovernedTransactionIntent {
            id: id.to_string(),
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            purpose: purpose.to_string(),
            max_amount: Some(MonetaryAmount {
                units,
                currency: currency.to_string(),
            }),
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({
                "invoice_id": "inv-1001",
                "operator": "finance-ops",
            })),
        }
    }

    fn make_governed_acp_intent(
        id: &str,
        server: &str,
        tool: &str,
        purpose: &str,
        seller: &str,
        shared_payment_token_id: &str,
        units: u64,
        currency: &str,
    ) -> GovernedTransactionIntent {
        GovernedTransactionIntent {
            id: id.to_string(),
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            purpose: purpose.to_string(),
            max_amount: Some(MonetaryAmount {
                units,
                currency: currency.to_string(),
            }),
            commerce: Some(arc_core::capability::GovernedCommerceContext {
                seller: seller.to_string(),
                shared_payment_token_id: shared_payment_token_id.to_string(),
            }),
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({
                "invoice_id": "inv-2002",
                "operator": "commerce-ops",
            })),
        }
    }

    fn make_runtime_attestation(
        tier: RuntimeAssuranceTier,
    ) -> arc_core::capability::RuntimeAttestationEvidence {
        let now = current_unix_timestamp();
        arc_core::capability::RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.v1".to_string(),
            verifier: "verifier.arc".to_string(),
            tier,
            issued_at: now.saturating_sub(1),
            expires_at: now + 300,
            evidence_sha256: format!("digest-{tier:?}"),
            runtime_identity: Some("spiffe://arc/runtime/test".to_string()),
            workload_identity: None,
            claims: None,
        }
    }

    fn make_trusted_azure_runtime_attestation() -> arc_core::capability::RuntimeAttestationEvidence
    {
        let now = current_unix_timestamp();
        arc_core::capability::RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test/".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: now.saturating_sub(5),
            expires_at: now + 300,
            evidence_sha256: "digest-azure-attestation".to_string(),
            runtime_identity: Some("spiffe://arc/runtime/test".to_string()),
            workload_identity: None,
            claims: Some(serde_json::json!({
                "azureMaa": {
                    "attestationType": "sgx"
                }
            })),
        }
    }

    fn make_trusted_google_runtime_attestation() -> arc_core::capability::RuntimeAttestationEvidence
    {
        let now = current_unix_timestamp();
        arc_core::capability::RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: now.saturating_sub(5),
            expires_at: now + 300,
            evidence_sha256: "digest-google-attestation".to_string(),
            runtime_identity: Some(
                "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1"
                    .to_string(),
            ),
            workload_identity: None,
            claims: Some(serde_json::json!({
                "googleAttestation": {
                    "attestationType": "confidential_vm",
                    "hardwareModel": "GCP_AMD_SEV",
                    "secureBoot": "enabled"
                }
            })),
        }
    }

    fn make_attestation_trust_policy() -> arc_core::capability::AttestationTrustPolicy {
        arc_core::capability::AttestationTrustPolicy {
            rules: vec![
                arc_core::capability::AttestationTrustRule {
                    name: "azure-contoso".to_string(),
                    schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
                    verifier: "https://maa.contoso.test".to_string(),
                    effective_tier: RuntimeAssuranceTier::Verified,
                    verifier_family: Some(arc_core::appraisal::AttestationVerifierFamily::AzureMaa),
                    max_evidence_age_seconds: Some(120),
                    allowed_attestation_types: vec!["sgx".to_string()],
                    required_assertions: std::collections::BTreeMap::new(),
                },
                arc_core::capability::AttestationTrustRule {
                    name: "google-confidential".to_string(),
                    schema: "arc.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
                    verifier: "https://confidentialcomputing.googleapis.com".to_string(),
                    effective_tier: RuntimeAssuranceTier::Verified,
                    verifier_family: Some(
                        arc_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
                    ),
                    max_evidence_age_seconds: Some(120),
                    allowed_attestation_types: vec!["confidential_vm".to_string()],
                    required_assertions: std::collections::BTreeMap::from([
                        ("hardwareModel".to_string(), "GCP_AMD_SEV".to_string()),
                        ("secureBoot".to_string(), "enabled".to_string()),
                    ]),
                },
            ],
        }
    }

    fn make_metered_billing_context(
        quote_id: &str,
        provider: &str,
        units: u64,
        currency: &str,
    ) -> arc_core::capability::MeteredBillingContext {
        let now = current_unix_timestamp();
        arc_core::capability::MeteredBillingContext {
            settlement_mode: arc_core::capability::MeteredSettlementMode::AllowThenSettle,
            quote: arc_core::capability::MeteredBillingQuote {
                quote_id: quote_id.to_string(),
                provider: provider.to_string(),
                billing_unit: "1k_tokens".to_string(),
                quoted_units: units,
                quoted_cost: MonetaryAmount {
                    units: 60,
                    currency: currency.to_string(),
                },
                issued_at: now.saturating_sub(5),
                expires_at: Some(now + 300),
            },
            max_billed_units: Some(units + 4),
        }
    }

    fn make_governed_call_chain_context(
        chain_id: &str,
        parent_request_id: &str,
    ) -> arc_core::capability::GovernedCallChainContext {
        arc_core::capability::GovernedCallChainContext {
            chain_id: chain_id.to_string(),
            parent_request_id: parent_request_id.to_string(),
            parent_receipt_id: Some("rc-upstream-1".to_string()),
            origin_subject: "subject-origin".to_string(),
            delegator_subject: "subject-delegator".to_string(),
        }
    }

    fn make_governed_autonomy_context(
        tier: GovernedAutonomyTier,
        bond_id: Option<&str>,
    ) -> GovernedAutonomyContext {
        GovernedAutonomyContext {
            tier,
            delegation_bond_id: bond_id.map(str::to_string),
        }
    }

    fn make_credit_bond(
        signer: &Keypair,
        cap: &CapabilityToken,
        server: &str,
        tool: &str,
        disposition: CreditBondDisposition,
        lifecycle_state: CreditBondLifecycleState,
        expires_at: u64,
        runtime_assurance_met: bool,
    ) -> SignedCreditBond {
        let now = current_unix_timestamp();
        let report = CreditBondReport {
            schema: CREDIT_BOND_REPORT_SCHEMA.to_string(),
            generated_at: now.saturating_sub(1),
            filters: ExposureLedgerQuery {
                capability_id: Some(cap.id.clone()),
                agent_subject: Some(cap.subject.to_hex()),
                tool_server: Some(server.to_string()),
                tool_name: Some(tool.to_string()),
                since: None,
                until: None,
                receipt_limit: Some(10),
                decision_limit: Some(5),
            },
            exposure: ExposureLedgerSummary {
                matching_receipts: 1,
                returned_receipts: 1,
                matching_decisions: 0,
                returned_decisions: 0,
                active_decisions: 0,
                superseded_decisions: 0,
                actionable_receipts: 0,
                pending_settlement_receipts: 0,
                failed_settlement_receipts: 0,
                currencies: vec!["USD".to_string()],
                mixed_currency_book: false,
                truncated_receipts: false,
                truncated_decisions: false,
            },
            scorecard: CreditScorecardSummary {
                matching_receipts: 1,
                returned_receipts: 1,
                matching_decisions: 0,
                returned_decisions: 0,
                currencies: vec!["USD".to_string()],
                mixed_currency_book: false,
                confidence: CreditScorecardConfidence::High,
                band: CreditScorecardBand::Prime,
                overall_score: 0.95,
                anomaly_count: 0,
                probationary: false,
            },
            disposition,
            prerequisites: CreditBondPrerequisites {
                active_facility_required: true,
                active_facility_met: true,
                runtime_assurance_met,
                certification_required: false,
                certification_met: true,
                currency_coherent: true,
            },
            support_boundary: CreditBondSupportBoundary {
                autonomy_gating_supported: true,
                ..CreditBondSupportBoundary::default()
            },
            latest_facility_id: Some("facility-1".to_string()),
            terms: None,
            findings: Vec::new(),
        };
        SignedCreditBond::sign(
            CreditBondArtifact {
                schema: CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
                bond_id: format!("bond-{server}-{tool}-{}", now),
                issued_at: now.saturating_sub(5),
                expires_at,
                lifecycle_state,
                supersedes_bond_id: None,
                report,
            },
            signer,
        )
        .unwrap()
    }

    fn make_governed_approval_token(
        approver: &Keypair,
        subject: &PublicKey,
        intent: &GovernedTransactionIntent,
        request_id: &str,
    ) -> GovernedApprovalToken {
        let now = current_unix_timestamp();
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: format!("approval-{request_id}"),
                approver: approver.public_key(),
                subject: subject.clone(),
                governed_intent_hash: intent.binding_hash().unwrap(),
                request_id: request_id.to_string(),
                issued_at: now.saturating_sub(1),
                expires_at: now + 300,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .unwrap()
    }

    // --- Monetary enforcement tests ---

    #[test]
    fn monetary_denial_exceeds_per_invocation_cap() {
        // Grant max_cost_per_invocation=100; tool server reports actual cost 150 (> cap).
        // The budget check should deny because the worst-case debit (100) passes the cap,
        // but the server reports 150 which exceeds the cap -- actually no: we charge the
        // max_cost_per_invocation as the worst-case DEBIT upfront. The per-invocation check
        // is: cost_units (=max_per) must be <= max_cost_per_invocation. With cost_units=100
        // and max_per=100 that passes. After invocation, server reports 150; we log a warning
        // and set settlement_status=failed. But the invocation is NOT denied before execution.
        //
        // To produce a pre-execution monetary denial, the requested cost must exceed the cap.
        // This happens when we charge cost_units = max_cost_per_invocation but the total budget
        // is already exhausted.
        //
        // Test: accumulated 500 + max_cost_per_invocation=100 exceeds max_total_cost=500 -> deny.
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        let server = MonetaryCostServer::no_cost("cost-srv");
        kernel.register_tool_server(Box::new(server));

        let grant = make_monetary_grant("cost-srv", "compute", 100, 500, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request = |id: &str| ToolCallRequest {
            request_id: id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        };

        // 5 invocations: 5 * 100 = 500 total -- all should pass.
        for i in 0..5 {
            let resp = kernel
                .evaluate_tool_call(&request(&format!("req-{i}")))
                .unwrap();
            assert_eq!(
                resp.verdict,
                Verdict::Allow,
                "invocation {i} should be allowed"
            );
        }

        // 6th invocation would need 600 total, exceeding max_total_cost=500.
        let resp = kernel.evaluate_tool_call(&request("req-6")).unwrap();
        assert_eq!(
            resp.verdict,
            Verdict::Deny,
            "6th invocation should be denied"
        );
    }

    #[test]
    fn monetary_denial_receipt_contains_financial_metadata() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

        let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request = ToolCallRequest {
            request_id: "req-1".to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        };

        // First invocation uses up the entire budget (100 of 100).
        let _allow = kernel.evaluate_tool_call(&request).unwrap();

        // Second invocation should be denied.
        let deny_req = ToolCallRequest {
            request_id: "req-2".to_string(),
            ..request
        };
        let resp = kernel.evaluate_tool_call(&deny_req).unwrap();
        assert_eq!(resp.verdict, Verdict::Deny);

        // Receipt must contain financial metadata.
        let metadata = resp
            .receipt
            .metadata
            .as_ref()
            .expect("should have metadata");
        let financial = metadata
            .get("financial")
            .expect("should have 'financial' key");
        assert_eq!(financial["settlement_status"], "not_applicable");
        assert!(financial["attempted_cost"].as_u64().is_some());
        assert_eq!(financial["currency"], "USD");
        let attribution = metadata
            .get("attribution")
            .expect("should have 'attribution' key");
        assert_eq!(attribution["grant_index"].as_u64(), Some(0));
        assert!(attribution["subject_key"].as_str().is_some());
    }

    #[test]
    fn monetary_guard_denial_releases_budget_and_records_attempted_cost() {
        use std::sync::{Arc, Mutex};

        struct DenyOnceGuard {
            denied: Arc<Mutex<bool>>,
        }

        impl Guard for DenyOnceGuard {
            fn name(&self) -> &str {
                "deny-once"
            }

            fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
                let mut denied = self.denied.lock().unwrap();
                if !*denied {
                    *denied = true;
                    Ok(Verdict::Deny)
                } else {
                    Ok(Verdict::Allow)
                }
            }
        }

        let mut kernel = ArcKernel::new(make_monetary_config());
        kernel.add_guard(Box::new(DenyOnceGuard {
            denied: Arc::new(Mutex::new(false)),
        }));
        kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

        let agent_kp = Keypair::generate();
        let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request = |request_id: &str| ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        };

        let denied_response = kernel.evaluate_tool_call(&request("req-deny")).unwrap();
        assert_eq!(denied_response.verdict, Verdict::Deny);
        let denied_metadata = denied_response
            .receipt
            .metadata
            .as_ref()
            .expect("should have metadata");
        let denied_financial = denied_metadata
            .get("financial")
            .expect("should have financial metadata");
        assert_eq!(denied_financial["cost_charged"].as_u64(), Some(0));
        assert_eq!(denied_financial["attempted_cost"].as_u64(), Some(100));
        assert_eq!(denied_financial["budget_remaining"].as_u64(), Some(100));
        assert_eq!(denied_financial["settlement_status"], "not_applicable");

        let allowed_response = kernel.evaluate_tool_call(&request("req-allow")).unwrap();
        assert_eq!(allowed_response.verdict, Verdict::Allow);
        let allowed_metadata = allowed_response
            .receipt
            .metadata
            .as_ref()
            .expect("should have metadata");
        let allowed_financial = allowed_metadata
            .get("financial")
            .expect("should have financial metadata");
        assert_eq!(allowed_financial["cost_charged"].as_u64(), Some(100));
        assert_eq!(allowed_financial["budget_remaining"].as_u64(), Some(0));
    }

    #[test]
    fn kernel_accepts_optional_payment_adapter_installation() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        assert!(kernel.payment_adapter.is_none());

        kernel.set_payment_adapter(Box::new(StubPaymentAdapter));

        assert!(kernel.payment_adapter.is_some());
    }

    #[test]
    fn monetary_payment_authorization_denial_releases_budget_and_skips_tool_invocation() {
        let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut kernel = ArcKernel::new(make_monetary_config());
        kernel.set_payment_adapter(Box::new(DecliningPaymentAdapter));
        kernel.register_tool_server(Box::new(CountingMonetaryServer {
            id: "cost-srv".to_string(),
            invocations: invocations.clone(),
        }));

        let agent_kp = Keypair::generate();
        let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-payment-deny".to_string(),
                capability: cap.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(
            invocations.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "tool should not run when payment authorization fails"
        );
        let financial = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("financial"))
            .expect("deny receipt should carry financial metadata");
        assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
        assert_eq!(financial["budget_remaining"].as_u64(), Some(1000));
        let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 0);
        assert_eq!(usage.total_cost_charged, 0);
    }

    #[test]
    fn monetary_prepaid_adapter_sets_payment_reference_on_allow_receipt() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        kernel.set_payment_adapter(Box::new(PrepaidSettledPaymentAdapter));
        kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

        let agent_kp = Keypair::generate();
        let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-prepaid".to_string(),
                capability: cap.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        let financial = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("financial"))
            .expect("allow receipt should carry financial metadata");
        assert_eq!(financial["payment_reference"], "x402_txn_paid");
        assert_eq!(financial["settlement_status"], "settled");
        assert_eq!(financial["cost_charged"].as_u64(), Some(100));
        assert_eq!(financial["budget_remaining"].as_u64(), Some(900));
        let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
        assert_eq!(usage.total_cost_charged, 100);
    }

    #[test]
    fn monetary_allow_receipt_contains_financial_metadata() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        // Server reports actual cost of 75 cents (< max 100).
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let resp = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-1".to_string(),
                capability: cap.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
            })
            .unwrap();

        assert_eq!(resp.verdict, Verdict::Allow);

        let metadata = resp
            .receipt
            .metadata
            .as_ref()
            .expect("should have metadata");
        let financial = metadata
            .get("financial")
            .expect("should have 'financial' key");
        // The actual reported cost (75) should be recorded.
        assert_eq!(financial["cost_charged"].as_u64().unwrap(), 75);
        assert_eq!(financial["budget_remaining"].as_u64(), Some(925));
        assert_eq!(financial["settlement_status"], "settled");
        assert_eq!(financial["currency"], "USD");
        let attribution = metadata
            .get("attribution")
            .expect("should have 'attribution' key");
        assert_eq!(attribution["grant_index"].as_u64(), Some(0));

        let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 1);
        assert_eq!(usage.total_cost_charged, 75);
    }

    #[test]
    fn governed_monetary_allow_receipt_contains_approval_metadata() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-allow";
        let intent = make_governed_intent(
            "intent-governed-allow",
            "cost-srv",
            "compute",
            "settle approved invoice",
            100,
            "USD",
        );
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
                dpop_proof: None,
                governed_intent: Some(intent.clone()),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        let metadata = response
            .receipt
            .metadata
            .as_ref()
            .expect("allow receipt should carry metadata");
        let governed = metadata
            .get("governed_transaction")
            .expect("allow receipt should carry governed transaction metadata");
        assert_eq!(governed["intent_id"], intent.id);
        assert_eq!(governed["intent_hash"], intent.binding_hash().unwrap());
        assert_eq!(governed["purpose"], intent.purpose);
        assert_eq!(governed["approval"]["approved"], true);
        assert_eq!(
            governed["approval"]["approver_key"],
            kernel.config.keypair.public_key().to_hex()
        );

        let financial = metadata
            .get("financial")
            .expect("allow receipt should carry financial metadata");
        assert_eq!(financial["cost_charged"].as_u64(), Some(75));
        assert_eq!(financial["budget_remaining"].as_u64(), Some(925));
    }

    #[test]
    fn governed_monetary_allow_receipt_preserves_metered_billing_quote_context() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-metered-allow";
        let mut intent = make_governed_intent(
            "intent-governed-metered-allow",
            "cost-srv",
            "compute",
            "execute governed metered compute",
            100,
            "USD",
        );
        intent.metered_billing = Some(make_metered_billing_context(
            "quote-governed-1",
            "billing.arc",
            12,
            "USD",
        ));
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
                dpop_proof: None,
                governed_intent: Some(intent.clone()),
                approval_token: Some(approval_token),
            })
            .unwrap();

        let governed = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("governed_transaction"))
            .expect("allow receipt should carry governed transaction metadata");
        assert_eq!(
            governed["metered_billing"]["quote"]["quoteId"],
            serde_json::Value::String("quote-governed-1".to_string())
        );
        assert_eq!(
            governed["metered_billing"]["quote"]["provider"],
            serde_json::Value::String("billing.arc".to_string())
        );
        assert_eq!(
            governed["metered_billing"]["settlementMode"],
            serde_json::Value::String("allow_then_settle".to_string())
        );
        assert_eq!(
            governed["metered_billing"]["maxBilledUnits"].as_u64(),
            Some(16)
        );
        assert!(governed["metered_billing"]["usageEvidence"].is_null());
    }

    #[test]
    fn governed_request_rejects_empty_metered_billing_provider() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-metered-invalid";
        let mut intent = make_governed_intent(
            "intent-governed-metered-invalid",
            "cost-srv",
            "compute",
            "execute governed metered compute",
            100,
            "USD",
        );
        intent.metered_billing = Some(make_metered_billing_context(
            "quote-governed-2",
            "",
            8,
            "USD",
        ));
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
                dpop_proof: None,
                governed_intent: Some(intent),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("metered billing provider must not be empty")));

        let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 0);
        assert_eq!(usage.total_cost_charged, 0);
    }

    #[test]
    fn governed_monetary_allow_receipt_preserves_call_chain_context() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-call-chain-allow";
        let mut intent = make_governed_intent(
            "intent-governed-call-chain-allow",
            "cost-srv",
            "compute",
            "execute delegated governed compute",
            100,
            "USD",
        );
        intent.call_chain = Some(make_governed_call_chain_context(
            "chain-ops-1",
            "req-parent-1",
        ));
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
                dpop_proof: None,
                governed_intent: Some(intent.clone()),
                approval_token: Some(approval_token),
            })
            .unwrap();

        let governed = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("governed_transaction"))
            .expect("allow receipt should carry governed transaction metadata");
        assert_eq!(
            governed["call_chain"]["chainId"],
            serde_json::Value::String("chain-ops-1".to_string())
        );
        assert_eq!(
            governed["call_chain"]["parentRequestId"],
            serde_json::Value::String("req-parent-1".to_string())
        );
        assert_eq!(
            governed["intent_hash"],
            serde_json::Value::String(intent.binding_hash().unwrap())
        );
    }

    #[test]
    fn governed_request_rejects_self_referential_call_chain_parent_request() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-call-chain-invalid";
        let mut intent = make_governed_intent(
            "intent-governed-call-chain-invalid",
            "cost-srv",
            "compute",
            "execute delegated governed compute",
            100,
            "USD",
        );
        intent.call_chain = Some(make_governed_call_chain_context("chain-ops-2", request_id));
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
                dpop_proof: None,
                governed_intent: Some(intent),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.reason.as_ref().is_some_and(|reason| {
            reason.contains("call_chain.parent_request_id must not equal the current request_id")
        }));
    }

    #[test]
    fn governed_request_rejects_empty_call_chain_chain_id() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-call-chain-empty";
        let mut intent = make_governed_intent(
            "intent-governed-call-chain-empty",
            "cost-srv",
            "compute",
            "execute delegated governed compute",
            100,
            "USD",
        );
        let mut call_chain = make_governed_call_chain_context("chain-ops-3", "req-parent-3");
        call_chain.chain_id.clear();
        intent.call_chain = Some(call_chain);
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
                dpop_proof: None,
                governed_intent: Some(intent),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response
            .reason
            .as_ref()
            .is_some_and(|reason| reason.contains("call_chain.chain_id must not be empty")));
    }

    #[test]
    fn governed_monetary_denial_without_required_runtime_assurance_releases_budget() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = with_minimum_runtime_assurance(
            make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
            RuntimeAssuranceTier::Attested,
        );
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-assurance-deny";
        let intent = make_governed_intent(
            "intent-governed-assurance-deny",
            "cost-srv",
            "compute",
            "execute governed payout",
            100,
            "USD",
        );
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
                dpop_proof: None,
                governed_intent: Some(intent),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("runtime attestation tier")),
            "denial should explain the missing runtime attestation"
        );
        let financial = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("financial"))
            .expect("deny receipt should carry financial metadata");
        assert_eq!(financial["budget_remaining"].as_u64(), Some(1000));
        let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
        assert_eq!(usage.total_cost_charged, 0);
    }

    #[test]
    fn governed_monetary_allow_records_runtime_assurance_metadata() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = with_minimum_runtime_assurance(
            make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
            RuntimeAssuranceTier::Attested,
        );
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-assurance-allow";
        let mut intent = make_governed_intent(
            "intent-governed-assurance-allow",
            "cost-srv",
            "compute",
            "execute governed payout",
            100,
            "USD",
        );
        intent.runtime_attestation = Some(make_runtime_attestation(RuntimeAssuranceTier::Attested));
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
                dpop_proof: None,
                governed_intent: Some(intent),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        let governed = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("governed_transaction"))
            .expect("allow receipt should carry governed transaction metadata");
        assert_eq!(
            governed["runtime_assurance"]["schema"],
            "arc.runtime-attestation.v1"
        );
        assert_eq!(governed["runtime_assurance"]["tier"], "attested");
        assert_eq!(governed["runtime_assurance"]["verifier"], "verifier.arc");
        assert_eq!(
            governed["runtime_assurance"]["workloadIdentity"]["trustDomain"],
            "arc"
        );
        assert_eq!(
            governed["runtime_assurance"]["workloadIdentity"]["path"],
            "/runtime/test"
        );
    }

    #[test]
    fn governed_request_denies_conflicting_workload_identity_binding() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-workload-identity-deny";
        let mut intent = make_governed_intent(
            "intent-governed-workload-identity-deny",
            "cost-srv",
            "compute",
            "execute governed payout",
            100,
            "USD",
        );
        intent.runtime_attestation = Some(arc_core::capability::RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.v1".to_string(),
            verifier: "verifier.arc".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: current_unix_timestamp().saturating_sub(1),
            expires_at: current_unix_timestamp() + 300,
            evidence_sha256: "digest-invalid-workload".to_string(),
            runtime_identity: Some("spiffe://arc/runtime/test".to_string()),
            workload_identity: Some(arc_core::capability::WorkloadIdentity {
                scheme: arc_core::capability::WorkloadIdentityScheme::Spiffe,
                credential_kind: arc_core::capability::WorkloadCredentialKind::X509Svid,
                uri: "spiffe://other/runtime/test".to_string(),
                trust_domain: "other".to_string(),
                path: "/runtime/test".to_string(),
            }),
            claims: None,
        });
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-1002" }),
                dpop_proof: None,
                governed_intent: Some(intent),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("workload identity is invalid")),
            "denial should explain the workload-identity binding failure"
        );
    }

    #[test]
    fn governed_monetary_allow_rebinds_trusted_attestation_to_verified() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        kernel.set_attestation_trust_policy(make_attestation_trust_policy());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = with_minimum_runtime_assurance(
            make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
            RuntimeAssuranceTier::Verified,
        );
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-assurance-verified";
        let mut intent = make_governed_intent(
            "intent-governed-assurance-verified",
            "cost-srv",
            "compute",
            "execute governed payout",
            100,
            "USD",
        );
        intent.runtime_attestation = Some(make_trusted_azure_runtime_attestation());
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-1003" }),
                dpop_proof: None,
                governed_intent: Some(intent),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        let governed = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("governed_transaction"))
            .expect("allow receipt should carry governed transaction metadata");
        assert_eq!(governed["runtime_assurance"]["tier"], "verified");
        assert_eq!(governed["runtime_assurance"]["verifierFamily"], "azure_maa");
        assert_eq!(
            governed["runtime_assurance"]["workloadIdentity"]["trustDomain"],
            "arc"
        );
    }

    #[test]
    fn governed_request_denies_untrusted_attestation_when_trust_policy_is_configured() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        kernel.set_attestation_trust_policy(make_attestation_trust_policy());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-assurance-untrusted";
        let mut intent = make_governed_intent(
            "intent-governed-assurance-untrusted",
            "cost-srv",
            "compute",
            "execute governed payout",
            100,
            "USD",
        );
        let mut attestation = make_trusted_azure_runtime_attestation();
        attestation.verifier = "https://maa.untrusted.test".to_string();
        intent.runtime_attestation = Some(attestation);
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-1004" }),
                dpop_proof: None,
                governed_intent: Some(intent),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(
            response.reason.as_deref().is_some_and(|reason| {
                reason.contains("rejected by trust policy")
                    && reason.contains("did not match any trusted verifier rule")
            }),
            "denial should explain the trust-policy mismatch"
        );
    }

    #[test]
    fn governed_monetary_allow_rebinds_google_attestation_to_verified() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        kernel.set_attestation_trust_policy(make_attestation_trust_policy());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = with_minimum_runtime_assurance(
            make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
            RuntimeAssuranceTier::Verified,
        );
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-assurance-google-verified";
        let mut intent = make_governed_intent(
            "intent-governed-assurance-google-verified",
            "cost-srv",
            "compute",
            "execute governed payout",
            100,
            "USD",
        );
        intent.runtime_attestation = Some(make_trusted_google_runtime_attestation());
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-1005" }),
                dpop_proof: None,
                governed_intent: Some(intent),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        let governed = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("governed_transaction"))
            .expect("allow receipt should carry governed transaction metadata");
        assert_eq!(governed["runtime_assurance"]["tier"], "verified");
        assert_eq!(
            governed["runtime_assurance"]["verifierFamily"],
            "google_attestation"
        );
    }

    #[test]
    fn governed_request_denies_delegated_autonomy_without_bond_attachment() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = with_minimum_autonomy_tier(
            make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
            GovernedAutonomyTier::Delegated,
        );
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-autonomy-missing-bond";
        let mut intent = make_governed_intent(
            "intent-governed-autonomy-missing-bond",
            "cost-srv",
            "compute",
            "execute delegated bonded payout",
            100,
            "USD",
        );
        intent.runtime_attestation = Some(make_runtime_attestation(RuntimeAssuranceTier::Attested));
        intent.call_chain = Some(make_governed_call_chain_context(
            "chain-bond-1",
            "req-parent-1",
        ));
        intent.autonomy = Some(make_governed_autonomy_context(
            GovernedAutonomyTier::Delegated,
            None,
        ));
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-bond-1" }),
                dpop_proof: None,
                governed_intent: Some(intent),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response
            .reason
            .as_deref()
            .is_some_and(|reason| { reason.contains("requires a delegation bond attachment") }));
    }

    #[test]
    fn governed_request_denies_autonomous_tier_with_weak_runtime_assurance() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

        let grant = with_minimum_autonomy_tier(
            make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
            GovernedAutonomyTier::Autonomous,
        );
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-autonomy-weak-assurance";
        let mut intent = make_governed_intent(
            "intent-governed-autonomy-weak-assurance",
            "cost-srv",
            "compute",
            "execute autonomous bonded payout",
            100,
            "USD",
        );
        intent.runtime_attestation = Some(make_runtime_attestation(RuntimeAssuranceTier::Attested));
        intent.call_chain = Some(make_governed_call_chain_context(
            "chain-bond-2",
            "req-parent-2",
        ));
        intent.autonomy = Some(make_governed_autonomy_context(
            GovernedAutonomyTier::Autonomous,
            Some("bond-required"),
        ));
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-bond-2" }),
                dpop_proof: None,
                governed_intent: Some(intent),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.reason.as_deref().is_some_and(|reason| {
            reason.contains("runtime attestation tier") && reason.contains("Verified")
        }));
    }

    #[test]
    fn governed_request_denies_delegated_autonomy_with_expired_bond() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
        let path = unique_receipt_db_path("kernel-bond-expired");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        let grant = with_minimum_autonomy_tier(
            make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
            GovernedAutonomyTier::Delegated,
        );
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();
        let bond = make_credit_bond(
            &kernel.config.keypair,
            &cap,
            "cost-srv",
            "compute",
            CreditBondDisposition::Hold,
            CreditBondLifecycleState::Active,
            current_unix_timestamp().saturating_sub(1),
            true,
        );
        let bond_id = bond.body.bond_id.clone();
        store
            .record_credit_bond(&bond, CreditBondLifecycleState::Active)
            .unwrap();
        kernel.set_receipt_store(Box::new(store));

        let request_id = "req-governed-autonomy-expired-bond";
        let mut intent = make_governed_intent(
            "intent-governed-autonomy-expired-bond",
            "cost-srv",
            "compute",
            "execute delegated bonded payout",
            100,
            "USD",
        );
        intent.runtime_attestation = Some(make_runtime_attestation(RuntimeAssuranceTier::Attested));
        intent.call_chain = Some(make_governed_call_chain_context(
            "chain-bond-3",
            "req-parent-3",
        ));
        intent.autonomy = Some(make_governed_autonomy_context(
            GovernedAutonomyTier::Delegated,
            Some(&bond_id),
        ));
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-bond-3" }),
                dpop_proof: None,
                governed_intent: Some(intent),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("is expired")));
    }

    #[test]
    fn governed_request_allows_delegated_autonomy_with_active_bond_and_receipt_metadata() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
        let path = unique_receipt_db_path("kernel-bond-active");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        let grant = with_minimum_autonomy_tier(
            make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
            GovernedAutonomyTier::Delegated,
        );
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();
        let bond = make_credit_bond(
            &kernel.config.keypair,
            &cap,
            "cost-srv",
            "compute",
            CreditBondDisposition::Hold,
            CreditBondLifecycleState::Active,
            current_unix_timestamp() + 300,
            true,
        );
        let bond_id = bond.body.bond_id.clone();
        store
            .record_credit_bond(&bond, CreditBondLifecycleState::Active)
            .unwrap();
        kernel.set_receipt_store(Box::new(store));

        let request_id = "req-governed-autonomy-allow";
        let mut intent = make_governed_intent(
            "intent-governed-autonomy-allow",
            "cost-srv",
            "compute",
            "execute delegated bonded payout",
            100,
            "USD",
        );
        intent.runtime_attestation = Some(make_runtime_attestation(RuntimeAssuranceTier::Attested));
        intent.call_chain = Some(make_governed_call_chain_context(
            "chain-bond-4",
            "req-parent-4",
        ));
        intent.autonomy = Some(make_governed_autonomy_context(
            GovernedAutonomyTier::Delegated,
            Some(&bond_id),
        ));
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-bond-4" }),
                dpop_proof: None,
                governed_intent: Some(intent),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        let governed = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("governed_transaction"))
            .expect("allow receipt should carry governed transaction metadata");
        assert_eq!(governed["autonomy"]["tier"], "delegated");
        assert_eq!(governed["autonomy"]["delegationBondId"], bond_id);
    }

    #[test]
    fn governed_monetary_denial_without_approval_releases_budget_and_records_intent() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

        let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let intent = make_governed_intent(
            "intent-governed-deny",
            "cost-srv",
            "compute",
            "execute governed payout",
            100,
            "USD",
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-governed-deny".to_string(),
                capability: cap.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
                dpop_proof: None,
                governed_intent: Some(intent.clone()),
                approval_token: None,
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("approval token required")),
            "denial should explain the missing approval token"
        );

        let metadata = response
            .receipt
            .metadata
            .as_ref()
            .expect("deny receipt should carry metadata");
        let governed = metadata
            .get("governed_transaction")
            .expect("deny receipt should carry governed transaction metadata");
        assert_eq!(governed["intent_id"], intent.id);
        assert!(governed["approval"].is_null());

        let financial = metadata
            .get("financial")
            .expect("deny receipt should carry financial metadata");
        assert_eq!(financial["cost_charged"].as_u64(), Some(0));
        assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
        assert_eq!(financial["budget_remaining"].as_u64(), Some(1000));
        assert_eq!(financial["settlement_status"], "not_applicable");

        let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 0);
        assert_eq!(usage.total_cost_charged, 0);
    }

    #[test]
    fn governed_monetary_incomplete_receipt_keeps_financial_and_governed_metadata() {
        let mut config = make_monetary_config();
        config.max_stream_total_bytes = 1;

        let mut kernel = ArcKernel::new(config);
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(StreamingServer {
            id: "stream".to_string(),
            chunks: vec![serde_json::json!({ "chunk": "governed-stream-payload" })],
        }));

        let grant = make_governed_monetary_grant("stream", "stream_file", 100, 1000, "USD", 50);
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-incomplete";
        let intent = make_governed_intent(
            "intent-governed-incomplete",
            "stream",
            "stream_file",
            "stream governed artifact",
            100,
            "USD",
        );
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "stream_file".to_string(),
                server_id: "stream".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "path": "/tmp/governed.txt" }),
                dpop_proof: None,
                governed_intent: Some(intent.clone()),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(matches!(
            response.terminal_state,
            OperationTerminalState::Incomplete { .. }
        ));

        let metadata = response
            .receipt
            .metadata
            .as_ref()
            .expect("incomplete receipt should carry metadata");
        let governed = metadata
            .get("governed_transaction")
            .expect("incomplete receipt should carry governed transaction metadata");
        assert_eq!(governed["intent_id"], intent.id);
        assert_eq!(governed["approval"]["approved"], true);

        let financial = metadata
            .get("financial")
            .expect("incomplete receipt should retain financial metadata");
        assert_eq!(financial["cost_charged"].as_u64(), Some(100));
        assert_eq!(financial["budget_remaining"].as_u64(), Some(900));

        let stream = match response
            .output
            .expect("partial stream output should be preserved")
        {
            ToolCallOutput::Stream(stream) => Some(stream),
            ToolCallOutput::Value(_) => None,
        }
        .expect("expected streamed partial output");
        assert!(
            stream.chunks.is_empty(),
            "truncated stream should drop chunks once byte limit is exceeded"
        );
    }

    #[test]
    fn governed_x402_prepaid_flow_records_governed_authorization_and_receipt_metadata() {
        let (url, request_rx, handle) = spawn_payment_test_server(
            200,
            serde_json::json!({
                "authorizationId": "x402_txn_governed",
                "settled": true,
                "metadata": {
                    "network": "base",
                    "merchant": "pay-per-api"
                }
            }),
        );

        let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut kernel = ArcKernel::new(make_monetary_config());
        kernel.set_payment_adapter(Box::new(
            X402PaymentAdapter::new(url)
                .with_bearer_token("bridge-token")
                .with_timeout(Duration::from_secs(2)),
        ));
        kernel.register_tool_server(Box::new(CountingMonetaryServer {
            id: "cost-srv".to_string(),
            invocations: invocations.clone(),
        }));

        let agent_kp = Keypair::generate();
        let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-x402";
        let intent = make_governed_intent(
            "intent-governed-x402",
            "cost-srv",
            "compute",
            "purchase premium API result",
            100,
            "USD",
        );
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "sku": "dataset-pro" }),
                dpop_proof: None,
                governed_intent: Some(intent.clone()),
                approval_token: Some(approval_token.clone()),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(
            invocations.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "tool should run after x402 authorization succeeds"
        );

        let request = request_rx.recv().expect("request should be captured");
        assert!(request.starts_with("POST /authorize HTTP/1.1"));
        assert!(request.contains("Authorization: Bearer bridge-token"));
        assert!(request.contains("\"amountUnits\":100"));
        assert!(request.contains("\"reference\":\"req-governed-x402\""));
        assert!(request.contains("\"governed\":{"));
        assert!(request.contains("\"intentId\":\"intent-governed-x402\""));
        assert!(request.contains("\"approvalTokenId\":\"approval-req-governed-x402\""));

        let metadata = response
            .receipt
            .metadata
            .as_ref()
            .expect("allow receipt should carry metadata");
        let financial = metadata
            .get("financial")
            .expect("allow receipt should carry financial metadata");
        assert_eq!(financial["payment_reference"], "x402_txn_governed");
        assert_eq!(financial["settlement_status"], "settled");
        assert_eq!(financial["cost_charged"].as_u64(), Some(100));
        assert_eq!(
            financial["cost_breakdown"]["payment"]["authorization_id"],
            "x402_txn_governed"
        );
        assert_eq!(
            financial["cost_breakdown"]["payment"]["adapter_metadata"]["adapter"],
            "x402"
        );
        assert_eq!(
            financial["cost_breakdown"]["payment"]["adapter_metadata"]["merchant"],
            "pay-per-api"
        );

        let governed = metadata
            .get("governed_transaction")
            .expect("allow receipt should carry governed transaction metadata");
        assert_eq!(governed["intent_id"], intent.id);
        assert_eq!(governed["approval"]["token_id"], approval_token.id);

        handle.join().expect("server thread should exit cleanly");
    }

    #[test]
    fn governed_x402_authorization_failure_denies_before_tool_execution() {
        let (url, request_rx, handle) = spawn_payment_test_server(
            402,
            serde_json::json!({
                "error": "insufficient funds"
            }),
        );

        let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut kernel = ArcKernel::new(make_monetary_config());
        kernel.set_payment_adapter(Box::new(
            X402PaymentAdapter::new(url).with_timeout(Duration::from_secs(2)),
        ));
        kernel.register_tool_server(Box::new(CountingMonetaryServer {
            id: "cost-srv".to_string(),
            invocations: invocations.clone(),
        }));

        let agent_kp = Keypair::generate();
        let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-x402-deny";
        let intent = make_governed_intent(
            "intent-governed-x402-deny",
            "cost-srv",
            "compute",
            "purchase premium API result",
            100,
            "USD",
        );
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "sku": "dataset-pro" }),
                dpop_proof: None,
                governed_intent: Some(intent.clone()),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("payment authorization failed")),
            "denial should explain the x402 authorization failure"
        );
        assert_eq!(
            invocations.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "tool should not run when x402 authorization fails"
        );

        let request = request_rx.recv().expect("request should be captured");
        assert!(request.contains("\"intentId\":\"intent-governed-x402-deny\""));

        let metadata = response
            .receipt
            .metadata
            .as_ref()
            .expect("deny receipt should carry metadata");
        let financial = metadata
            .get("financial")
            .expect("deny receipt should carry financial metadata");
        assert_eq!(financial["cost_charged"].as_u64(), Some(0));
        assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
        assert_eq!(financial["budget_remaining"].as_u64(), Some(1000));
        assert_eq!(financial["settlement_status"], "not_applicable");

        let governed = metadata
            .get("governed_transaction")
            .expect("deny receipt should carry governed transaction metadata");
        assert_eq!(governed["intent_id"], intent.id);

        let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 0);
        assert_eq!(usage.total_cost_charged, 0);

        handle.join().expect("server thread should exit cleanly");
    }

    #[test]
    fn governed_acp_hold_flow_records_commerce_scope_and_payment_metadata() {
        let (url, request_rx, handle) = spawn_payment_test_server(
            200,
            serde_json::json!({
                "authorizationId": "acp_hold_governed",
                "settled": false,
                "metadata": {
                    "provider": "stripe",
                    "seller": "merchant.example"
                }
            }),
        );

        let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut kernel = ArcKernel::new(make_monetary_config());
        kernel.set_payment_adapter(Box::new(
            AcpPaymentAdapter::new(url)
                .with_authorize_path("/commerce/authorize")
                .with_bearer_token("acp-token")
                .with_timeout(Duration::from_secs(2)),
        ));
        kernel.register_tool_server(Box::new(CountingMonetaryServer {
            id: "commerce-srv".to_string(),
            invocations: invocations.clone(),
        }));

        let agent_kp = Keypair::generate();
        let grant = make_governed_acp_monetary_grant(
            "commerce-srv",
            "compute",
            "merchant.example",
            100,
            1000,
            "USD",
            50,
        );
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-acp";
        let intent = make_governed_acp_intent(
            "intent-governed-acp",
            "commerce-srv",
            "compute",
            "purchase seller-bound result",
            "merchant.example",
            "spt_live_governed",
            100,
            "USD",
        );
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "commerce-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "sku": "merchant-result-pro" }),
                dpop_proof: None,
                governed_intent: Some(intent.clone()),
                approval_token: Some(approval_token.clone()),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(
            invocations.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "tool should run after ACP authorization succeeds"
        );

        let request = request_rx.recv().expect("request should be captured");
        assert!(request.starts_with("POST /commerce/authorize HTTP/1.1"));
        assert!(request.contains("Authorization: Bearer acp-token"));
        assert!(request.contains("\"commerce\":{"));
        assert!(request.contains("\"seller\":\"merchant.example\""));
        assert!(request.contains("\"sharedPaymentTokenId\":\"spt_live_governed\""));

        let metadata = response
            .receipt
            .metadata
            .as_ref()
            .expect("allow receipt should carry metadata");
        let financial = metadata
            .get("financial")
            .expect("allow receipt should carry financial metadata");
        assert_eq!(financial["payment_reference"], "acp_hold_governed");
        assert_eq!(financial["settlement_status"], "settled");
        assert_eq!(
            financial["cost_breakdown"]["payment"]["authorization_id"],
            "acp_hold_governed"
        );
        assert_eq!(
            financial["cost_breakdown"]["payment"]["adapter_metadata"]["adapter"],
            "acp"
        );
        assert_eq!(
            financial["cost_breakdown"]["payment"]["adapter_metadata"]["mode"],
            "shared_payment_token_hold"
        );

        let governed = metadata
            .get("governed_transaction")
            .expect("allow receipt should carry governed transaction metadata");
        assert_eq!(governed["intent_id"], intent.id);
        assert_eq!(governed["commerce"]["seller"], "merchant.example");
        assert_eq!(
            governed["commerce"]["shared_payment_token_id"],
            "spt_live_governed"
        );
        assert_eq!(governed["approval"]["token_id"], approval_token.id);

        handle.join().expect("server thread should exit cleanly");
    }

    #[test]
    fn governed_acp_seller_mismatch_denies_before_payment_or_tool_execution() {
        let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut kernel = ArcKernel::new(make_monetary_config());
        kernel.set_payment_adapter(Box::new(
            AcpPaymentAdapter::new("http://127.0.0.1:1").with_timeout(Duration::from_millis(50)),
        ));
        kernel.register_tool_server(Box::new(CountingMonetaryServer {
            id: "commerce-srv".to_string(),
            invocations: invocations.clone(),
        }));

        let agent_kp = Keypair::generate();
        let grant = make_governed_acp_monetary_grant(
            "commerce-srv",
            "compute",
            "merchant.example",
            100,
            1000,
            "USD",
            50,
        );
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request_id = "req-governed-acp-seller-mismatch";
        let intent = make_governed_acp_intent(
            "intent-governed-acp-seller-mismatch",
            "commerce-srv",
            "compute",
            "attempt purchase for wrong seller",
            "wrong-merchant.example",
            "spt_live_wrong",
            100,
            "USD",
        );
        let approval_token = make_governed_approval_token(
            &kernel.config.keypair,
            &agent_kp.public_key(),
            &intent,
            request_id,
        );

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: request_id.to_string(),
                capability: cap.clone(),
                tool_name: "compute".to_string(),
                server_id: "commerce-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "sku": "merchant-result-pro" }),
                dpop_proof: None,
                governed_intent: Some(intent.clone()),
                approval_token: Some(approval_token),
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("seller")),
            "denial should explain the seller-scope mismatch"
        );
        assert_eq!(
            invocations.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "tool should not run when the seller scope does not match"
        );

        let metadata = response
            .receipt
            .metadata
            .as_ref()
            .expect("deny receipt should carry metadata");
        let financial = metadata
            .get("financial")
            .expect("deny receipt should carry financial metadata");
        assert_eq!(financial["cost_charged"].as_u64(), Some(0));
        assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
        assert_eq!(financial["settlement_status"], "not_applicable");

        let governed = metadata
            .get("governed_transaction")
            .expect("deny receipt should carry governed transaction metadata");
        assert_eq!(governed["intent_id"], intent.id);
        assert_eq!(governed["commerce"]["seller"], "wrong-merchant.example");

        let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 0);
        assert_eq!(usage.total_cost_charged, 0);
    }

    #[test]
    fn monetary_allow_receipt_marks_failed_settlement_when_reported_cost_exceeds_charge() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 150, "USD")));

        let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-overrun".to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        let metadata = response
            .receipt
            .metadata
            .as_ref()
            .expect("should have metadata");
        let financial = metadata
            .get("financial")
            .expect("should have 'financial' key");
        assert_eq!(financial["cost_charged"].as_u64(), Some(150));
        assert_eq!(financial["settlement_status"], "failed");
        assert!(financial["payment_reference"].is_null());
    }

    #[test]
    fn monetary_server_not_reporting_cost_charges_max_cost_per_invocation() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        // Server does NOT report cost (returns None).
        kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

        let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let resp = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-1".to_string(),
                capability: cap.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
            })
            .unwrap();

        assert_eq!(resp.verdict, Verdict::Allow);
        let metadata = resp
            .receipt
            .metadata
            .as_ref()
            .expect("should have metadata");
        let financial = metadata
            .get("financial")
            .expect("should have 'financial' key");
        // Worst-case debit: max_cost_per_invocation = 100.
        assert_eq!(financial["cost_charged"].as_u64().unwrap(), 100);
    }

    #[test]
    fn monetary_tool_server_error_releases_precharged_budget() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(FailingMonetaryServer {
            id: "cost-srv".to_string(),
        }));

        let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-tool-error".to_string(),
                capability: cap.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Deny);
        let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 0);
        assert_eq!(usage.total_cost_charged, 0);
    }

    #[test]
    fn monetary_full_pipeline_three_invocations_third_denied() {
        // max_total_cost=250, max_cost_per_invocation=100.
        // Invocation 1: charges 100, total = 100. Allowed.
        // Invocation 2: charges 100, total = 200. Allowed.
        // Invocation 3: would charge 100, total would be 300 > 250. Denied.
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

        let grant = make_monetary_grant("cost-srv", "compute", 100, 250, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let make_req = |id: &str| ToolCallRequest {
            request_id: id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        };

        let r1 = kernel.evaluate_tool_call(&make_req("req-1")).unwrap();
        assert_eq!(r1.verdict, Verdict::Allow, "first invocation should pass");

        let r2 = kernel.evaluate_tool_call(&make_req("req-2")).unwrap();
        assert_eq!(r2.verdict, Verdict::Allow, "second invocation should pass");

        let r3 = kernel.evaluate_tool_call(&make_req("req-3")).unwrap();
        assert_eq!(
            r3.verdict,
            Verdict::Deny,
            "third invocation should be denied"
        );

        // Verify the denial receipt has financial metadata.
        let metadata = r3.receipt.metadata.as_ref().expect("should have metadata");
        assert!(metadata.get("financial").is_some());
    }

    #[test]
    fn multi_grant_budget_remaining_uses_matched_grant_total() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

        let grant_a = make_monetary_grant("cost-srv", "compute-a", 100, 500, "USD");
        let grant_b = make_monetary_grant("cost-srv", "compute-b", 40, 200, "USD");
        let cap = kernel
            .issue_capability(
                &agent_kp.public_key(),
                make_scope(vec![grant_a, grant_b]),
                3600,
            )
            .unwrap();

        let invoke = |request_id: &str, tool_name: &str| ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap.clone(),
            tool_name: tool_name.to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        };

        let _ = kernel
            .evaluate_tool_call(&invoke("req-a", "compute-a"))
            .unwrap();
        let response_b = kernel
            .evaluate_tool_call(&invoke("req-b", "compute-b"))
            .unwrap();

        let metadata = response_b
            .receipt
            .metadata
            .as_ref()
            .expect("should have metadata");
        let financial = metadata
            .get("financial")
            .expect("should have financial metadata");
        assert_eq!(financial["grant_index"].as_u64(), Some(1));
        assert_eq!(financial["cost_charged"].as_u64(), Some(40));
        assert_eq!(financial["budget_total"].as_u64(), Some(200));
        assert_eq!(financial["budget_remaining"].as_u64(), Some(160));
    }

    #[test]
    fn matched_grant_index_populated_in_guard_context() {
        // A guard that records the matched_grant_index from its context.
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct IndexCapturingGuard {
            captured: Arc<Mutex<Option<usize>>>,
        }

        impl Guard for IndexCapturingGuard {
            fn name(&self) -> &str {
                "index-capture"
            }

            fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
                let mut lock = self.captured.lock().unwrap();
                *lock = ctx.matched_grant_index;
                Ok(Verdict::Allow)
            }
        }

        let captured = Arc::new(Mutex::new(None::<usize>));
        let guard = IndexCapturingGuard {
            captured: captured.clone(),
        };

        let mut kernel = ArcKernel::new(make_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["tool1", "tool2"])));
        kernel.add_guard(Box::new(guard));

        // Two grants; first matches "tool1", second matches "tool2".
        let grant0 = ToolGrant {
            server_id: "srv".to_string(),
            tool_name: "tool1".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let grant1 = ToolGrant {
            server_id: "srv".to_string(),
            tool_name: "tool2".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let cap = kernel
            .issue_capability(
                &agent_kp.public_key(),
                make_scope(vec![grant0, grant1]),
                3600,
            )
            .unwrap();

        // Request tool2 -- matched grant should be at index 1.
        let resp = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-1".to_string(),
                capability: cap.clone(),
                tool_name: "tool2".to_string(),
                server_id: "srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
            })
            .unwrap();
        assert_eq!(resp.verdict, Verdict::Allow);

        let idx = *captured.lock().unwrap();
        assert_eq!(
            idx,
            Some(1),
            "guard should see matched_grant_index=Some(1) for tool2 (second grant)"
        );
    }

    #[test]
    fn velocity_guard_denial_produces_signed_deny_receipt_no_panic() {
        // Simulate a velocity-style guard with a simple counter that denies
        // after N invocations. This tests the kernel's handling of guard denials
        // (producing a signed deny receipt without panic) without importing arc-guards.
        use std::sync::{Arc, Mutex};

        struct CountingRateLimitGuard {
            count: Arc<Mutex<u32>>,
            max: u32,
        }

        impl Guard for CountingRateLimitGuard {
            fn name(&self) -> &str {
                "counting-rate-limit"
            }

            fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
                let mut count = self.count.lock().unwrap();
                *count += 1;
                if *count > self.max {
                    Ok(Verdict::Deny)
                } else {
                    Ok(Verdict::Allow)
                }
            }
        }

        let counter = Arc::new(Mutex::new(0u32));
        let guard = CountingRateLimitGuard {
            count: counter.clone(),
            max: 2,
        };

        let mut kernel = ArcKernel::new(make_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
        kernel.add_guard(Box::new(guard));

        let grant = make_grant("srv", "echo");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let make_req = |id: &str| ToolCallRequest {
            request_id: id.to_string(),
            capability: cap.clone(),
            tool_name: "echo".to_string(),
            server_id: "srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        };

        // First two invocations allowed.
        let r1 = kernel.evaluate_tool_call(&make_req("req-1")).unwrap();
        assert_eq!(r1.verdict, Verdict::Allow);
        let r2 = kernel.evaluate_tool_call(&make_req("req-2")).unwrap();
        assert_eq!(r2.verdict, Verdict::Allow);

        // Third invocation should be denied by the counting guard.
        let r3 = kernel.evaluate_tool_call(&make_req("req-3")).unwrap();
        assert_eq!(
            r3.verdict,
            Verdict::Deny,
            "counting guard should deny 3rd invocation"
        );
        // Verify it's a properly signed deny receipt (not a panic/unwrap).
        assert!(
            r3.receipt.id.starts_with("rcpt-"),
            "receipt should have valid id"
        );
        assert!(r3.reason.is_some(), "denial should have a reason");
    }

    #[test]
    fn checkpoint_triggers_at_100_receipts() {
        let path = unique_receipt_db_path("arc-checkpoint-trigger");
        let mut config = make_monetary_config();
        config.checkpoint_batch_size = 10; // Use 10 for speed.

        let mut kernel = ArcKernel::new(config);
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));

        let store = SqliteReceiptStore::open(&path).unwrap();
        kernel.set_receipt_store(Box::new(store));

        let grant = make_grant("srv", "echo");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        for i in 0..10 {
            kernel
                .evaluate_tool_call(&ToolCallRequest {
                    request_id: format!("req-{i}"),
                    capability: cap.clone(),
                    tool_name: "echo".to_string(),
                    server_id: "srv".to_string(),
                    agent_id: agent_kp.public_key().to_hex(),
                    arguments: serde_json::json!({}),
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                })
                .unwrap();
        }

        // Verify a checkpoint was stored in the database.
        let store2 = SqliteReceiptStore::open(&path).unwrap();
        let checkpoint = store2.load_checkpoint_by_seq(1).unwrap();
        assert!(
            checkpoint.is_some(),
            "checkpoint should have been stored after 10 receipts"
        );
        let cp = checkpoint.unwrap();
        assert_eq!(cp.body.checkpoint_seq, 1);
        assert_eq!(cp.body.batch_start_seq, 1);
        assert_eq!(cp.body.batch_end_seq, 10);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inclusion_proof_verifies_against_stored_checkpoint() {
        let path = unique_receipt_db_path("arc-checkpoint-proof");
        let mut config = make_monetary_config();
        config.checkpoint_batch_size = 5;

        let mut kernel = ArcKernel::new(config);
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));

        let store = SqliteReceiptStore::open(&path).unwrap();
        kernel.set_receipt_store(Box::new(store));

        let grant = make_grant("srv", "echo");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        for i in 0..5 {
            kernel
                .evaluate_tool_call(&ToolCallRequest {
                    request_id: format!("req-{i}"),
                    capability: cap.clone(),
                    tool_name: "echo".to_string(),
                    server_id: "srv".to_string(),
                    agent_id: agent_kp.public_key().to_hex(),
                    arguments: serde_json::json!({}),
                    dpop_proof: None,
                    governed_intent: None,
                    approval_token: None,
                })
                .unwrap();
        }

        // Load checkpoint and receipts, build and verify an inclusion proof.
        let store2 = SqliteReceiptStore::open(&path).unwrap();
        let checkpoint = store2
            .load_checkpoint_by_seq(1)
            .unwrap()
            .expect("checkpoint should exist");

        let bytes_range = store2.receipts_canonical_bytes_range(1, 5).unwrap();
        assert_eq!(bytes_range.len(), 5, "should have 5 receipts in range");

        let all_bytes: Vec<Vec<u8>> = bytes_range.iter().map(|(_, b)| b.clone()).collect();
        let tree =
            arc_core::merkle::MerkleTree::from_leaves(&all_bytes).expect("tree build failed");

        // Build proof for receipt at leaf index 2 (seq 3).
        let proof = build_inclusion_proof(&tree, 2, 1, 3).expect("proof build failed");
        assert!(
            proof.verify(&all_bytes[2], &checkpoint.body.merkle_root),
            "inclusion proof for receipt #3 should verify against checkpoint"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tool_invocation_cost_serde_roundtrip() {
        let cost = ToolInvocationCost {
            units: 500,
            currency: "USD".to_string(),
            breakdown: None,
        };
        let json = serde_json::to_string(&cost).unwrap();
        let restored: ToolInvocationCost = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.units, 500);
        assert_eq!(restored.currency, "USD");
        assert!(restored.breakdown.is_none());

        // With breakdown
        let cost_with = ToolInvocationCost {
            units: 200,
            currency: "EUR".to_string(),
            breakdown: Some(serde_json::json!({"compute": 150, "network": 50})),
        };
        let json_with = serde_json::to_string(&cost_with).unwrap();
        let restored_with: ToolInvocationCost = serde_json::from_str(&json_with).unwrap();
        assert_eq!(restored_with.units, 200);
        assert!(restored_with.breakdown.is_some());
    }

    #[test]
    fn cross_currency_reported_cost_attaches_oracle_evidence_and_converted_units() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let mut kernel = ArcKernel::new(make_monetary_config());
        kernel.set_price_oracle(Box::new(StaticPriceOracle::new([(
            ("ETH".to_string(), "USD".to_string()),
            Ok(ExchangeRate {
                base: "ETH".to_string(),
                quote: "USD".to_string(),
                rate_numerator: 300_000,
                rate_denominator: 100,
                updated_at: now.saturating_sub(45),
                fetched_at: now,
                source: "chainlink".to_string(),
                feed_reference: "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70".to_string(),
                max_age_seconds: 600,
                conversion_margin_bps: 200,
                confidence_numerator: None,
                confidence_denominator: None,
            }),
        )])));
        kernel.register_tool_server(Box::new(MonetaryCostServer::new(
            "cost-srv",
            1_000_000_000_000_000,
            "ETH",
        )));

        let agent_kp = Keypair::generate();
        let grant = make_monetary_grant("cost-srv", "compute", 400, 1_000, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-cross-currency-ok".to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        let metadata = response.receipt.metadata.as_ref().expect("metadata");
        let financial = metadata.get("financial").expect("financial");
        assert_eq!(financial["cost_charged"].as_u64(), Some(306));
        assert_eq!(financial["budget_remaining"].as_u64(), Some(694));
        assert_eq!(financial["settlement_status"], "settled");
        assert_eq!(financial["oracle_evidence"]["base"], "ETH");
        assert_eq!(financial["oracle_evidence"]["quote"], "USD");
        assert_eq!(
            financial["oracle_evidence"]["converted_cost_units"].as_u64(),
            Some(306)
        );
        assert_eq!(
            financial["cost_breakdown"]["oracle_conversion"]["status"],
            "applied"
        );
    }

    #[test]
    fn cross_currency_without_oracle_keeps_provisional_charge_and_marks_failed_settlement() {
        let mut kernel = ArcKernel::new(make_monetary_config());
        kernel.register_tool_server(Box::new(MonetaryCostServer::new(
            "cost-srv",
            1_000_000_000_000_000,
            "ETH",
        )));

        let agent_kp = Keypair::generate();
        let grant = make_monetary_grant("cost-srv", "compute", 400, 1_000, "USD");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let response = kernel
            .evaluate_tool_call(&ToolCallRequest {
                request_id: "req-cross-currency-failed".to_string(),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
            })
            .unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        let metadata = response.receipt.metadata.as_ref().expect("metadata");
        let financial = metadata.get("financial").expect("financial");
        assert_eq!(financial["cost_charged"].as_u64(), Some(400));
        assert_eq!(financial["budget_remaining"].as_u64(), Some(600));
        assert_eq!(financial["settlement_status"], "failed");
        assert!(financial.get("oracle_evidence").is_none());
        assert_eq!(
            financial["cost_breakdown"]["oracle_conversion"]["status"],
            "failed"
        );
    }

    #[test]
    fn echo_server_invoke_with_cost_returns_none() {
        let server = EchoServer::new("srv-a", vec!["echo"]);
        let args = serde_json::json!({"msg": "hello"});
        let (value, cost) = server
            .invoke_with_cost("echo", args, None)
            .expect("invoke_with_cost should succeed");
        assert!(cost.is_none(), "EchoServer should return None cost");
        assert!(value.is_object());
    }

    // ---------------------------------------------------------------------------
    // DPoP wiring tests
    // ---------------------------------------------------------------------------

    fn make_dpop_grant(server: &str, tool: &str) -> ToolGrant {
        ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(true),
        }
    }

    /// Build a kernel that has a DPoP store configured and a single DPoP-required grant.
    fn make_dpop_kernel_and_cap(
        agent_kp: &Keypair,
        server: &str,
        tool: &str,
    ) -> (ArcKernel, CapabilityToken) {
        let config = KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "dpop-test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        };
        let mut kernel = ArcKernel::new(config);
        kernel.register_tool_server(Box::new(EchoServer::new(server, vec![tool])));

        let nonce_store = dpop::DpopNonceStore::new(1024, std::time::Duration::from_secs(300));
        kernel.set_dpop_store(nonce_store, dpop::DpopConfig::default());

        let grant = make_dpop_grant(server, tool);
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        (kernel, cap)
    }

    /// Build a valid DPoP proof for a given request context.
    fn make_dpop_proof(
        agent_kp: &Keypair,
        cap: &CapabilityToken,
        server: &str,
        tool: &str,
        arguments: &serde_json::Value,
        nonce: &str,
    ) -> dpop::DpopProof {
        let args_bytes = arc_core::canonical::canonical_json_bytes(arguments)
            .expect("canonical_json_bytes failed");
        let action_hash = arc_core::crypto::sha256_hex(&args_bytes);
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time error")
            .as_secs();
        let body = dpop::DpopProofBody {
            schema: dpop::DPOP_SCHEMA.to_string(),
            capability_id: cap.id.clone(),
            tool_server: server.to_string(),
            tool_name: tool.to_string(),
            action_hash,
            nonce: nonce.to_string(),
            issued_at: now_secs,
            agent_key: agent_kp.public_key(),
        };
        dpop::DpopProof::sign(body, agent_kp).expect("DPoP sign failed")
    }

    #[test]
    fn dpop_required_grant_allows_when_valid_proof_provided() {
        let agent_kp = Keypair::generate();
        let server = "dpop-srv";
        let tool = "secure_op";
        let (mut kernel, cap) = make_dpop_kernel_and_cap(&agent_kp, server, tool);

        let arguments = serde_json::json!({"action": "read"});
        let proof = make_dpop_proof(&agent_kp, &cap, server, tool, &arguments, "nonce-abc-001");

        let request = ToolCallRequest {
            request_id: "req-dpop-allow".to_string(),
            capability: cap,
            tool_name: tool.to_string(),
            server_id: server.to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments,
            dpop_proof: Some(proof),
            governed_intent: None,
            approval_token: None,
        };

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(
            response.verdict,
            Verdict::Allow,
            "valid DPoP proof should allow; reason: {:?}",
            response.reason
        );
    }

    #[test]
    fn dpop_required_grant_denies_when_no_proof_provided() {
        let agent_kp = Keypair::generate();
        let server = "dpop-srv";
        let tool = "secure_op";
        let (mut kernel, cap) = make_dpop_kernel_and_cap(&agent_kp, server, tool);

        let request = ToolCallRequest {
            request_id: "req-dpop-deny-no-proof".to_string(),
            capability: cap,
            tool_name: tool.to_string(),
            server_id: server.to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({"action": "read"}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
        };

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(
            response.verdict,
            Verdict::Deny,
            "missing DPoP proof should deny"
        );
        let reason = response.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("DPoP proof"),
            "denial reason should mention DPoP; got: {reason}"
        );
    }

    #[test]
    fn dpop_required_grant_denies_when_proof_has_wrong_tool_name() {
        let agent_kp = Keypair::generate();
        let server = "dpop-srv";
        let tool = "secure_op";
        let (mut kernel, cap) = make_dpop_kernel_and_cap(&agent_kp, server, tool);

        let arguments = serde_json::json!({"action": "read"});
        // Proof claims wrong tool name -- binding check should fail.
        let proof = make_dpop_proof(
            &agent_kp,
            &cap,
            server,
            "other_tool",
            &arguments,
            "nonce-bad-001",
        );

        let request = ToolCallRequest {
            request_id: "req-dpop-deny-wrong-tool".to_string(),
            capability: cap,
            tool_name: tool.to_string(),
            server_id: server.to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments,
            dpop_proof: Some(proof),
            governed_intent: None,
            approval_token: None,
        };

        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(
            response.verdict,
            Verdict::Deny,
            "proof with wrong tool name should deny"
        );
    }

    #[test]
    fn dpop_not_required_grant_allows_without_proof() {
        // Verify non-DPoP grants are unaffected.
        let mut kernel = ArcKernel::new(make_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));

        let grant = make_grant("srv", "echo");
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();

        let request = make_request("req-no-dpop", &cap, "echo", "srv");
        let response = kernel.evaluate_tool_call(&request).unwrap();
        assert_eq!(
            response.verdict,
            Verdict::Allow,
            "non-DPoP grant should allow without proof"
        );
    }
}
