//! # arc-core
//!
//! Shared vocabulary for the ARC protocol. This crate defines the fundamental
//! types that flow between all ARC components: capability tokens, tool grants,
//! scopes, receipts, and canonical JSON serialization helpers.
//!
//! Nothing in this crate performs I/O or depends on a runtime. It is a pure
//! data-and-crypto crate suitable for use in WASM, embedded, and no-std
//! (with alloc) environments.

pub mod appraisal;
pub mod canonical;
pub mod capability;
pub mod credit;
pub mod crypto;
pub mod error;
pub mod hashing;
pub mod manifest;
pub mod market;
pub mod merkle;
pub mod message;
pub mod receipt;
pub mod session;
pub mod standards;
pub mod underwriting;

pub use appraisal::{
    derive_runtime_attestation_appraisal, verifier_family_for_attestation_schema,
    AttestationVerifierFamily, RuntimeAttestationAppraisal, RuntimeAttestationAppraisalError,
    RuntimeAttestationAppraisalReasonCode, RuntimeAttestationAppraisalReport,
    RuntimeAttestationAppraisalRequest, RuntimeAttestationAppraisalVerdict,
    RuntimeAttestationEvidenceDescriptor, RuntimeAttestationPolicyOutcome,
    SignedRuntimeAttestationAppraisalReport, AWS_NITRO_ATTESTATION_SCHEMA,
    AWS_NITRO_VERIFIER_ADAPTER, AZURE_MAA_ATTESTATION_SCHEMA, AZURE_MAA_VERIFIER_ADAPTER,
    GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA, GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER,
    RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA, RUNTIME_ATTESTATION_APPRAISAL_SCHEMA,
};
pub use canonical::{canonical_json_bytes, canonical_json_string, canonicalize};
pub use capability::{
    ArcScope, Attenuation, AttestationTrustError, AttestationTrustPolicy, AttestationTrustRule,
    CapabilityToken, CapabilityTokenBody, Constraint, DelegationLink, DelegationLinkBody,
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedCallChainContext, GovernedCommerceContext, GovernedTransactionIntent,
    MeteredBillingContext, MeteredBillingQuote, MeteredSettlementMode, MonetaryAmount, Operation,
    PromptGrant, ResolvedRuntimeAssurance, ResourceGrant, RuntimeAssuranceTier,
    RuntimeAttestationEvidence, ToolGrant, WorkloadCredentialKind, WorkloadIdentity,
    WorkloadIdentityError, WorkloadIdentityScheme,
};
pub use credit::{
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
    CreditRecentLossSummary, CreditRuntimeAssuranceState, CreditScorecardAnomaly,
    CreditScorecardAnomalySeverity, CreditScorecardBand, CreditScorecardConfidence,
    CreditScorecardDimension, CreditScorecardDimensionKind, CreditScorecardEvidenceKind,
    CreditScorecardEvidenceReference, CreditScorecardProbationStatus, CreditScorecardReasonCode,
    CreditScorecardReport, CreditScorecardReputationContext, CreditScorecardSummary,
    CreditScorecardSupportBoundary, ExposureLedgerCurrencyPosition, ExposureLedgerDecisionEntry,
    ExposureLedgerEvidenceKind, ExposureLedgerEvidenceReference, ExposureLedgerQuery,
    ExposureLedgerReceiptEntry, ExposureLedgerReport, ExposureLedgerSummary,
    ExposureLedgerSupportBoundary, SignedCreditBond, SignedCreditFacility,
    SignedCreditLossLifecycle, SignedCreditProviderRiskPackage, SignedCreditScorecardReport,
    SignedExposureLedgerReport, CREDIT_BACKTEST_REPORT_SCHEMA,
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
pub use crypto::{sha256_hex, Keypair, PublicKey, Signature};
pub use error::Error;
pub use hashing::{sha256, Hash};
pub use manifest::{ToolAnnotations, ToolDefinition, ToolManifest, ToolManifestBody};
pub use market::{
    LiabilityBoundCoverageArtifact, LiabilityClaimAdjudicationArtifact,
    LiabilityClaimAdjudicationOutcome, LiabilityClaimDisputeArtifact, LiabilityClaimEvidenceKind,
    LiabilityClaimEvidenceReference, LiabilityClaimPackageArtifact, LiabilityClaimResponseArtifact,
    LiabilityClaimResponseDisposition, LiabilityClaimWorkflowQuery, LiabilityClaimWorkflowReport,
    LiabilityClaimWorkflowRow, LiabilityClaimWorkflowSummary, LiabilityCoverageClass,
    LiabilityEvidenceRequirement, LiabilityJurisdictionPolicy, LiabilityMarketWorkflowQuery,
    LiabilityMarketWorkflowReport, LiabilityMarketWorkflowRow, LiabilityMarketWorkflowSummary,
    LiabilityPlacementArtifact, LiabilityProviderArtifact, LiabilityProviderLifecycleState,
    LiabilityProviderListQuery, LiabilityProviderListReport, LiabilityProviderListSummary,
    LiabilityProviderPolicyReference, LiabilityProviderProvenance, LiabilityProviderReport,
    LiabilityProviderResolutionQuery, LiabilityProviderResolutionReport, LiabilityProviderRow,
    LiabilityProviderSupportBoundary, LiabilityProviderType, LiabilityQuoteDisposition,
    LiabilityQuoteRequestArtifact, LiabilityQuoteResponseArtifact, LiabilityQuoteTerms,
    SignedLiabilityBoundCoverage, SignedLiabilityClaimAdjudication, SignedLiabilityClaimDispute,
    SignedLiabilityClaimPackage, SignedLiabilityClaimResponse, SignedLiabilityPlacement,
    SignedLiabilityProvider, SignedLiabilityQuoteRequest, SignedLiabilityQuoteResponse,
    LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA, LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA, LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA, LIABILITY_CLAIM_WORKFLOW_REPORT_SCHEMA,
    LIABILITY_MARKET_WORKFLOW_REPORT_SCHEMA, LIABILITY_PLACEMENT_ARTIFACT_SCHEMA,
    LIABILITY_PROVIDER_ARTIFACT_SCHEMA, LIABILITY_PROVIDER_LIST_REPORT_SCHEMA,
    LIABILITY_PROVIDER_RESOLUTION_REPORT_SCHEMA, LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA,
    LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA, MAX_LIABILITY_CLAIM_WORKFLOW_LIMIT,
    MAX_LIABILITY_MARKET_WORKFLOW_LIMIT, MAX_LIABILITY_PROVIDER_LIST_LIMIT,
};
pub use merkle::{MerkleProof, MerkleTree};
pub use message::{AgentMessage, KernelMessage, ToolCallError, ToolCallResult};
pub use receipt::{
    ArcReceipt, ArcReceiptBody, ChildRequestReceipt, ChildRequestReceiptBody, Decision,
    FinancialReceiptMetadata, GovernedApprovalReceiptMetadata, GovernedCommerceReceiptMetadata,
    GovernedTransactionReceiptMetadata, GuardEvidence, MeteredBillingReceiptMetadata,
    MeteredUsageEvidenceReceiptMetadata, ToolCallAction,
};
pub use session::{
    ArcIdentityAssertion, CompleteOperation, CompletionArgument, CompletionReference,
    CompletionResult, CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, ElicitationAction, EnterpriseFederationMethod, EnterpriseIdentityContext,
    GetPromptOperation, OperationContext, OperationKind, OperationTerminalState, ProgressToken,
    PromptArgument, PromptDefinition, PromptMessage, PromptResult, ReadResourceOperation,
    RequestId, ResourceContent, ResourceDefinition, ResourceTemplateDefinition, RootDefinition,
    SamplingMessage, SamplingTool, SamplingToolChoice, SessionAuthContext, SessionAuthMethod,
    SessionId, SessionOperation, SessionTransport, ToolCallOperation,
};
pub use standards::{
    ArcGovernedAuthorizationBinding, ArcPortableClaimCatalog, ArcPortableIdentityBinding,
    ARC_GOVERNED_AUTH_AUTHORITATIVE_SOURCE, ARC_GOVERNED_AUTH_BINDING_SCHEMA,
    ARC_PORTABLE_CLAIM_CATALOG_SCHEMA, ARC_PORTABLE_IDENTITY_BINDING_SCHEMA,
    ARC_PORTABLE_ISSUER_IDENTITY_HTTPS_JWKS,
    ARC_PORTABLE_SUBJECT_BINDING_DID_ARC_SUBJECT_KEY_THUMBPRINT, ARC_PROVENANCE_ANCHOR_DID_ARC,
};
pub use underwriting::{
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

pub use capability::{validate_attenuation, validate_delegation_chain};

/// Opaque agent identifier. In practice this is a hex-encoded Ed25519 public key
/// or a SPIFFE URI, but the core treats it as an opaque string.
pub type AgentId = String;

/// Opaque tool server identifier.
pub type ServerId = String;

/// UUIDv7 capability identifier (time-ordered).
pub type CapabilityId = String;
