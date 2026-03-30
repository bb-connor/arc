#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_core::appraisal::{
    derive_runtime_attestation_appraisal, RuntimeAttestationAppraisalReport,
    RuntimeAttestationAppraisalRequest, RuntimeAttestationPolicyOutcome,
    SignedRuntimeAttestationAppraisalReport, RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA,
};
use arc_core::capability::{
    ArcScope, CapabilityToken, MonetaryAmount, RuntimeAssuranceTier, RuntimeAttestationEvidence,
};
use arc_core::crypto::{Keypair, PublicKey};
use arc_core::receipt::{ArcReceipt, ChildRequestReceipt, Decision, SettlementStatus};
use arc_core::session::{ArcIdentityAssertion, EnterpriseIdentityContext, OperationTerminalState};
use arc_core::{canonical_json_bytes, sha256_hex, Signature};
use arc_credentials::{
    build_arc_passport_jwt_vc_json_type_metadata, build_arc_passport_sd_jwt_type_metadata,
    build_oid4vp_request_transport, build_portable_jwks,
    build_wallet_exchange_descriptor_for_oid4vp,
    create_passport_presentation_challenge_with_reference,
    default_oid4vci_passport_issuer_metadata_with_signing_key,
    ensure_signed_passport_verifier_policy_active, inspect_arc_passport_sd_jwt_vc_unverified,
    inspect_oid4vp_direct_post_response, verify_oid4vp_direct_post_response_with_any_issuer_key,
    verify_passport_presentation_response_with_policy,
    verify_signed_oid4vp_request_object_with_any_key, verify_signed_passport_verifier_policy,
    AgentPassport, EnterpriseIdentityProvenance, Oid4vciCredentialIssuerMetadata,
    Oid4vciCredentialRequest, Oid4vciCredentialResponse, Oid4vciTokenRequest, Oid4vciTokenResponse,
    Oid4vpPresentationVerification, Oid4vpRequestObject, Oid4vpRequestedCredential,
    Oid4vpVerifierMetadata, PassportLifecycleRecord, PassportLifecycleResolution,
    PassportLifecycleState, PassportPresentationChallenge, PassportPresentationResponse,
    PassportPresentationVerification, PassportStatusDistribution, PassportVerifierPolicy,
    PassportVerifierPolicyReference, PortableJwkSet, SignedPassportVerifierPolicy,
    WalletExchangeDescriptor, WalletExchangeTransactionState,
    ARC_PASSPORT_JWT_VC_JSON_TYPE_METADATA_PATH, ARC_PASSPORT_SD_JWT_VC_FORMAT,
    ARC_PASSPORT_SD_JWT_VC_TYPE, ARC_PASSPORT_SD_JWT_VC_TYPE_METADATA_PATH,
    OID4VCI_ISSUER_METADATA_PATH, OID4VCI_JWKS_PATH, OID4VCI_PASSPORT_CREDENTIAL_PATH,
    OID4VCI_PASSPORT_OFFERS_PATH, OID4VCI_PASSPORT_TOKEN_PATH,
    OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI, OID4VP_OPENID4VP_SCHEME,
    OID4VP_RESPONSE_MODE_DIRECT_POST_JWT, OID4VP_RESPONSE_TYPE_VP_TOKEN,
    OID4VP_VERIFIER_METADATA_PATH,
};
use arc_did::DidArc;
use arc_kernel::{
    ArcOAuthAuthorizationMetadataReport, ArcOAuthAuthorizationReviewPack, AuthoritySnapshot,
    AuthorityStatus, AuthorizationContextReport, BehavioralFeedDecisionSummary,
    BehavioralFeedPrivacyBoundary, BehavioralFeedQuery, BehavioralFeedReport,
    BudgetDimensionProfile, BudgetDimensionUsage, BudgetStore, BudgetStoreError, BudgetUsageRecord,
    BudgetUtilizationReport, BudgetUtilizationRow, BudgetUtilizationSummary, CapabilityAuthority,
    CapabilitySnapshot, CostAttributionQuery, CostAttributionReport, CreditBacktestQuery,
    CreditBacktestReasonCode, CreditBacktestReport, CreditBacktestSummary, CreditBacktestWindow,
    CreditBondArtifact, CreditBondDisposition, CreditBondFinding, CreditBondLifecycleState,
    CreditBondListQuery, CreditBondListReport, CreditBondPrerequisites, CreditBondReasonCode,
    CreditBondReport, CreditBondSupportBoundary, CreditBondTerms,
    CreditBondedExecutionControlPolicy, CreditBondedExecutionDecision,
    CreditBondedExecutionEvaluation, CreditBondedExecutionFinding,
    CreditBondedExecutionFindingCode, CreditBondedExecutionSimulationDelta,
    CreditBondedExecutionSimulationReport, CreditBondedExecutionSimulationRequest,
    CreditBondedExecutionSupportBoundary, CreditCertificationState, CreditFacilityArtifact,
    CreditFacilityCapitalSource, CreditFacilityDisposition, CreditFacilityFinding,
    CreditFacilityLifecycleState, CreditFacilityListQuery, CreditFacilityListReport,
    CreditFacilityPrerequisites, CreditFacilityReasonCode, CreditFacilityReport,
    CreditFacilitySupportBoundary, CreditFacilityTerms, CreditLossLifecycleArtifact,
    CreditLossLifecycleEventKind, CreditLossLifecycleFinding, CreditLossLifecycleListQuery,
    CreditLossLifecycleListReport, CreditLossLifecycleQuery, CreditLossLifecycleReasonCode,
    CreditLossLifecycleReport, CreditLossLifecycleSupportBoundary, CreditProviderFacilitySnapshot,
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
    ExposureLedgerSupportBoundary, LiabilityBoundCoverageArtifact,
    LiabilityClaimAdjudicationArtifact, LiabilityClaimAdjudicationOutcome,
    LiabilityClaimDisputeArtifact, LiabilityClaimEvidenceKind, LiabilityClaimEvidenceReference,
    LiabilityClaimPackageArtifact, LiabilityClaimResponseArtifact,
    LiabilityClaimResponseDisposition, LiabilityClaimWorkflowQuery, LiabilityClaimWorkflowReport,
    LiabilityCoverageClass, LiabilityMarketWorkflowQuery, LiabilityMarketWorkflowReport,
    LiabilityPlacementArtifact, LiabilityProviderArtifact, LiabilityProviderListQuery,
    LiabilityProviderListReport, LiabilityProviderPolicyReference, LiabilityProviderReport,
    LiabilityProviderResolutionQuery, LiabilityProviderResolutionReport, LiabilityQuoteDisposition,
    LiabilityQuoteRequestArtifact, LiabilityQuoteResponseArtifact, LiabilityQuoteTerms,
    LocalCapabilityAuthority, MeteredBillingEvidenceRecord, MeteredBillingReconciliationReport,
    MeteredBillingReconciliationState, OperatorReport, OperatorReportQuery, ReceiptAnalyticsQuery,
    ReceiptAnalyticsResponse, ReceiptQuery, ReceiptStore, ReceiptStoreError, RevocationRecord,
    RevocationStore, RevocationStoreError, SettlementReconciliationReport,
    SettlementReconciliationState, SharedEvidenceQuery, SharedEvidenceReferenceReport,
    SignedBehavioralFeed, SignedCreditBond, SignedCreditFacility, SignedCreditLossLifecycle,
    SignedCreditProviderRiskPackage, SignedCreditScorecardReport, SignedExposureLedgerReport,
    SignedLiabilityBoundCoverage, SignedLiabilityClaimAdjudication, SignedLiabilityClaimDispute,
    SignedLiabilityClaimPackage, SignedLiabilityClaimResponse, SignedLiabilityPlacement,
    SignedLiabilityProvider, SignedLiabilityQuoteRequest, SignedLiabilityQuoteResponse,
    SignedUnderwritingDecision, SignedUnderwritingPolicyInput, StoredCapabilitySnapshot,
    StoredChildReceipt, StoredToolReceipt, UnderwritingAppealCreateRequest,
    UnderwritingAppealRecord, UnderwritingAppealResolveRequest, UnderwritingCertificationEvidence,
    UnderwritingCertificationState, UnderwritingDecisionListReport, UnderwritingDecisionPolicy,
    UnderwritingDecisionQuery, UnderwritingDecisionReport, UnderwritingEvidenceKind,
    UnderwritingEvidenceReference, UnderwritingPolicyInput, UnderwritingPolicyInputQuery,
    UnderwritingReasonCode, UnderwritingReceiptEvidence, UnderwritingReputationEvidence,
    UnderwritingRiskClass, UnderwritingRiskTaxonomy, UnderwritingRuntimeAssuranceEvidence,
    UnderwritingSignal, UnderwritingSimulationDelta, UnderwritingSimulationReport,
    UnderwritingSimulationRequest, BEHAVIORAL_FEED_SCHEMA, CREDIT_BACKTEST_REPORT_SCHEMA,
    CREDIT_BONDED_EXECUTION_SIMULATION_REPORT_SCHEMA, CREDIT_BOND_ARTIFACT_SCHEMA,
    CREDIT_BOND_REPORT_SCHEMA, CREDIT_FACILITY_ARTIFACT_SCHEMA, CREDIT_FACILITY_REPORT_SCHEMA,
    CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA, CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA,
    CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA, CREDIT_SCORECARD_SCHEMA, EXPOSURE_LEDGER_SCHEMA,
    LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA, LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA, LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA,
    LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA, LIABILITY_PLACEMENT_ARTIFACT_SCHEMA,
    LIABILITY_PROVIDER_ARTIFACT_SCHEMA, LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA,
    LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA, MAX_CREDIT_FACILITY_LIST_LIMIT,
    MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT, UNDERWRITING_POLICY_INPUT_SCHEMA,
    UNDERWRITING_SIMULATION_REPORT_SCHEMA,
};
use arc_store_sqlite::{
    SqliteBudgetStore, SqliteCapabilityAuthority, SqliteReceiptStore, SqliteRevocationStore,
};
use axum::extract::Form;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{info, warn};
use ureq::Agent;
use url::form_urlencoded::Serializer as UrlFormSerializer;

use crate::{
    authority_public_key_from_seed_file,
    certify::{
        CertificationConsumptionRequest, CertificationConsumptionResponse,
        CertificationDiscoveryResponse, CertificationDisputeRequest,
        CertificationMarketplaceSearchQuery, CertificationMarketplaceTransparencyQuery,
        CertificationNetworkPublishRequest, CertificationNetworkPublishResponse,
        CertificationPublicMetadata, CertificationPublicSearchQuery,
        CertificationPublicSearchResponse, CertificationRegistry, CertificationRegistryEntry,
        CertificationRegistryListResponse, CertificationRegistryState,
        CertificationResolutionResponse, CertificationResolutionState,
        CertificationRevocationRequest, CertificationTransparencyQuery,
        CertificationTransparencyResponse, SignedCertificationCheck,
    },
    enterprise_federation::{
        CertificationDiscoveryNetwork, EnterpriseProviderRecord, EnterpriseProviderRegistry,
    },
    evidence_export, issuance, load_or_create_authority_keypair,
    passport_verifier::{
        Oid4vpVerifierTransactionStore, PassportIssuanceOfferRecord, PassportIssuanceOfferRegistry,
        PassportStatusListResponse, PassportStatusRegistry, PassportStatusRevocationRequest,
        PassportVerifierChallengeStore, PublishPassportStatusRequest, VerifierPolicyRegistry,
    },
    reputation, rotate_authority_keypair, CliError,
};

// Content Security Policy applied to all responses from the dashboard/API server.
// Restricts resource loading to same-origin only; unsafe-inline is allowed for
// styles because Vite injects inline style tags at build time.
const CSP_VALUE: &str = "default-src 'self'; script-src 'self'; \
    style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:";

const HEALTH_PATH: &str = "/health";
const AUTHORITY_PATH: &str = "/v1/authority";
const ISSUE_CAPABILITY_PATH: &str = "/v1/capabilities/issue";
const FEDERATED_ISSUE_PATH: &str = "/v1/federation/capabilities/issue";
const FEDERATION_PROVIDERS_PATH: &str = "/v1/federation/providers";
const FEDERATION_PROVIDER_PATH: &str = "/v1/federation/providers/{provider_id}";
const CERTIFICATIONS_PATH: &str = "/v1/certifications";
const CERTIFICATION_PATH: &str = "/v1/certifications/{artifact_id}";
const CERTIFICATION_RESOLVE_PATH: &str = "/v1/certifications/resolve/{tool_server_id}";
const CERTIFICATION_REVOKE_PATH: &str = "/v1/certifications/{artifact_id}/revoke";
const CERTIFICATION_DISCOVERY_PATH: &str = "/v1/certifications/discovery/publish";
const CERTIFICATION_DISCOVERY_RESOLVE_PATH: &str =
    "/v1/certifications/discovery/resolve/{tool_server_id}";
const CERTIFICATION_DISCOVERY_SEARCH_PATH: &str = "/v1/certifications/discovery/search";
const CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH: &str = "/v1/certifications/discovery/transparency";
const CERTIFICATION_DISCOVERY_CONSUME_PATH: &str = "/v1/certifications/discovery/consume";
const CERTIFICATION_DISPUTE_PATH: &str = "/v1/certifications/{artifact_id}/dispute";
const PUBLIC_CERTIFICATION_METADATA_PATH: &str = "/v1/public/certifications/metadata";
const PUBLIC_CERTIFICATION_RESOLVE_PATH: &str =
    "/v1/public/certifications/resolve/{tool_server_id}";
const PUBLIC_CERTIFICATION_SEARCH_PATH: &str = "/v1/public/certifications/search";
const PUBLIC_CERTIFICATION_TRANSPARENCY_PATH: &str = "/v1/public/certifications/transparency";
const PASSPORT_ISSUER_METADATA_PATH: &str = OID4VCI_ISSUER_METADATA_PATH;
const PASSPORT_ISSUER_JWKS_PATH: &str = OID4VCI_JWKS_PATH;
const PASSPORT_SD_JWT_TYPE_METADATA_PATH: &str = ARC_PASSPORT_SD_JWT_VC_TYPE_METADATA_PATH;
const PASSPORT_ISSUANCE_OFFERS_PATH: &str = OID4VCI_PASSPORT_OFFERS_PATH;
const PASSPORT_ISSUANCE_TOKEN_PATH: &str = OID4VCI_PASSPORT_TOKEN_PATH;
const PASSPORT_ISSUANCE_CREDENTIAL_PATH: &str = OID4VCI_PASSPORT_CREDENTIAL_PATH;
const PASSPORT_STATUSES_PATH: &str = "/v1/passport/statuses";
const PASSPORT_STATUS_PATH: &str = "/v1/passport/statuses/{passport_id}";
const PASSPORT_STATUS_RESOLVE_PATH: &str = "/v1/passport/statuses/resolve/{passport_id}";
const PUBLIC_PASSPORT_STATUS_RESOLVE_PATH: &str =
    "/v1/public/passport/statuses/resolve/{passport_id}";
const PASSPORT_STATUS_REVOKE_PATH: &str = "/v1/passport/statuses/{passport_id}/revoke";
const PASSPORT_VERIFIER_POLICIES_PATH: &str = "/v1/passport/verifier-policies";
const PASSPORT_VERIFIER_POLICY_PATH: &str = "/v1/passport/verifier-policies/{policy_id}";
const PASSPORT_CHALLENGES_PATH: &str = "/v1/passport/challenges";
const PASSPORT_CHALLENGE_VERIFY_PATH: &str = "/v1/passport/challenges/verify";
const PUBLIC_PASSPORT_CHALLENGE_PATH: &str = "/v1/public/passport/challenges/{challenge_id}";
const PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH: &str = "/v1/public/passport/challenges/verify";
const PASSPORT_OID4VP_REQUESTS_PATH: &str = "/v1/passport/oid4vp/requests";
const PUBLIC_PASSPORT_WALLET_EXCHANGE_PATH: &str =
    "/v1/public/passport/wallet-exchanges/{request_id}";
const PUBLIC_PASSPORT_OID4VP_REQUEST_PATH: &str =
    "/v1/public/passport/oid4vp/requests/{request_id}";
const PUBLIC_PASSPORT_OID4VP_LAUNCH_PATH: &str = "/v1/public/passport/oid4vp/launch/{request_id}";
const PUBLIC_PASSPORT_OID4VP_DIRECT_POST_PATH: &str = "/v1/public/passport/oid4vp/direct-post";
pub const FEDERATED_DELEGATION_POLICY_SCHEMA: &str = "arc.federated-delegation-policy.v1";
const LEGACY_FEDERATED_DELEGATION_POLICY_SCHEMA: &str = "arc.federated-delegation-policy.v1";
const REVOCATIONS_PATH: &str = "/v1/revocations";
const TOOL_RECEIPTS_PATH: &str = "/v1/receipts/tools";
const CHILD_RECEIPTS_PATH: &str = "/v1/receipts/children";
const BUDGETS_PATH: &str = "/v1/budgets";
const BUDGET_INCREMENT_PATH: &str = "/v1/budgets/increment";
const BUDGET_CHARGE_PATH: &str = "/v1/budgets/charge";
const BUDGET_REVERSE_PATH: &str = "/v1/budgets/reverse-charge";
const BUDGET_REDUCE_PATH: &str = "/v1/budgets/reduce-charge";
const INTERNAL_CLUSTER_STATUS_PATH: &str = "/v1/internal/cluster/status";
const INTERNAL_AUTHORITY_SNAPSHOT_PATH: &str = "/v1/internal/authority/snapshot";
const INTERNAL_REVOCATIONS_DELTA_PATH: &str = "/v1/internal/revocations/delta";
const INTERNAL_TOOL_RECEIPTS_DELTA_PATH: &str = "/v1/internal/receipts/tools/delta";
const INTERNAL_CHILD_RECEIPTS_DELTA_PATH: &str = "/v1/internal/receipts/children/delta";
const INTERNAL_BUDGETS_DELTA_PATH: &str = "/v1/internal/budgets/delta";
const INTERNAL_LINEAGE_DELTA_PATH: &str = "/v1/internal/lineage/delta";
const RECEIPT_QUERY_PATH: &str = "/v1/receipts/query";
const RECEIPT_ANALYTICS_PATH: &str = "/v1/receipts/analytics";
const EVIDENCE_EXPORT_PATH: &str = "/v1/evidence/export";
const EVIDENCE_IMPORT_PATH: &str = "/v1/evidence/import";
const FEDERATION_EVIDENCE_SHARES_PATH: &str = "/v1/federation/evidence-shares";
const COST_ATTRIBUTION_PATH: &str = "/v1/reports/cost-attribution";
const OPERATOR_REPORT_PATH: &str = "/v1/reports/operator";
const RUNTIME_ATTESTATION_APPRAISAL_PATH: &str = "/v1/reports/runtime-attestation-appraisal";
const BEHAVIORAL_FEED_PATH: &str = "/v1/reports/behavioral-feed";
const EXPOSURE_LEDGER_PATH: &str = "/v1/reports/exposure-ledger";
const CREDIT_SCORECARD_PATH: &str = "/v1/reports/credit-scorecard";
const CREDIT_FACILITY_REPORT_PATH: &str = "/v1/reports/facility-policy";
const CREDIT_FACILITY_ISSUE_PATH: &str = "/v1/facilities/issue";
const CREDIT_FACILITIES_REPORT_PATH: &str = "/v1/reports/facilities";
const CREDIT_BOND_REPORT_PATH: &str = "/v1/reports/bond-policy";
const CREDIT_BOND_ISSUE_PATH: &str = "/v1/bonds/issue";
const CREDIT_BONDS_REPORT_PATH: &str = "/v1/reports/bonds";
const CREDIT_BONDED_EXECUTION_SIMULATION_PATH: &str = "/v1/reports/bonded-execution-simulation";
const CREDIT_LOSS_LIFECYCLE_REPORT_PATH: &str = "/v1/reports/bond-loss-policy";
const CREDIT_LOSS_LIFECYCLE_ISSUE_PATH: &str = "/v1/bond-losses/issue";
const CREDIT_LOSS_LIFECYCLE_LIST_PATH: &str = "/v1/reports/bond-losses";
const CREDIT_BACKTEST_PATH: &str = "/v1/reports/credit-backtest";
const CREDIT_PROVIDER_RISK_PACKAGE_PATH: &str = "/v1/reports/provider-risk-package";
const LIABILITY_PROVIDER_ISSUE_PATH: &str = "/v1/liability/providers/issue";
const LIABILITY_PROVIDERS_REPORT_PATH: &str = "/v1/reports/liability-providers";
const LIABILITY_PROVIDER_RESOLVE_PATH: &str = "/v1/liability/providers/resolve";
const LIABILITY_QUOTE_REQUEST_ISSUE_PATH: &str = "/v1/liability/quote-requests/issue";
const LIABILITY_QUOTE_RESPONSE_ISSUE_PATH: &str = "/v1/liability/quote-responses/issue";
const LIABILITY_PLACEMENT_ISSUE_PATH: &str = "/v1/liability/placements/issue";
const LIABILITY_BOUND_COVERAGE_ISSUE_PATH: &str = "/v1/liability/bound-coverages/issue";
const LIABILITY_MARKET_WORKFLOW_REPORT_PATH: &str = "/v1/reports/liability-market";
const LIABILITY_CLAIM_PACKAGE_ISSUE_PATH: &str = "/v1/liability/claims/issue";
const LIABILITY_CLAIM_RESPONSE_ISSUE_PATH: &str = "/v1/liability/claim-responses/issue";
const LIABILITY_CLAIM_DISPUTE_ISSUE_PATH: &str = "/v1/liability/disputes/issue";
const LIABILITY_CLAIM_ADJUDICATION_ISSUE_PATH: &str = "/v1/liability/adjudications/issue";
const LIABILITY_CLAIM_WORKFLOW_REPORT_PATH: &str = "/v1/reports/liability-claims";
const SETTLEMENT_REPORT_PATH: &str = "/v1/reports/settlements";
const SETTLEMENT_RECONCILE_PATH: &str = "/v1/settlements/reconcile";
const METERED_BILLING_REPORT_PATH: &str = "/v1/reports/metered-billing";
const METERED_BILLING_RECONCILE_PATH: &str = "/v1/metered-billing/reconcile";
const AUTHORIZATION_CONTEXT_REPORT_PATH: &str = "/v1/reports/authorization-context";
const AUTHORIZATION_PROFILE_METADATA_PATH: &str = "/v1/reports/authorization-profile-metadata";
const AUTHORIZATION_REVIEW_PACK_PATH: &str = "/v1/reports/authorization-review-pack";
const UNDERWRITING_INPUT_PATH: &str = "/v1/reports/underwriting-input";
const UNDERWRITING_DECISION_PATH: &str = "/v1/reports/underwriting-decision";
const UNDERWRITING_SIMULATION_PATH: &str = "/v1/reports/underwriting-simulation";
const UNDERWRITING_DECISIONS_REPORT_PATH: &str = "/v1/reports/underwriting-decisions";
const UNDERWRITING_DECISION_ISSUE_PATH: &str = "/v1/underwriting/decisions/issue";
const UNDERWRITING_APPEALS_PATH: &str = "/v1/underwriting/appeals";
const UNDERWRITING_APPEAL_RESOLVE_PATH: &str = "/v1/underwriting/appeals/resolve";
const LOCAL_REPUTATION_PATH: &str = "/v1/reputation/local/{subject_key}";
const REPUTATION_COMPARE_PATH: &str = "/v1/reputation/compare/{subject_key}";
const LINEAGE_RECORD_PATH: &str = "/v1/lineage";
const LINEAGE_PATH: &str = "/v1/lineage/{capability_id}";
const LINEAGE_CHAIN_PATH: &str = "/v1/lineage/{capability_id}/chain";
const AGENT_RECEIPTS_PATH: &str = "/v1/agents/{subject_key}/receipts";
const DASHBOARD_DIST_DIR: &str = "dashboard/dist";
const DEFAULT_LIST_LIMIT: usize = 50;
const MAX_LIST_LIMIT: usize = 200;
const AUTHORITY_CACHE_TTL: Duration = Duration::from_secs(2);
const PEER_HEALTH_TTL: Duration = Duration::from_secs(3);
const CONTROL_HTTP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct TrustServiceConfig {
    pub listen: SocketAddr,
    pub service_token: String,
    pub receipt_db_path: Option<PathBuf>,
    pub revocation_db_path: Option<PathBuf>,
    pub authority_seed_path: Option<PathBuf>,
    pub authority_db_path: Option<PathBuf>,
    pub budget_db_path: Option<PathBuf>,
    pub enterprise_providers_file: Option<PathBuf>,
    pub verifier_policies_file: Option<PathBuf>,
    pub verifier_challenge_db_path: Option<PathBuf>,
    pub passport_statuses_file: Option<PathBuf>,
    pub passport_issuance_offers_file: Option<PathBuf>,
    pub certification_registry_file: Option<PathBuf>,
    pub certification_discovery_file: Option<PathBuf>,
    pub issuance_policy: Option<crate::policy::ReputationIssuancePolicy>,
    pub runtime_assurance_policy: Option<crate::policy::RuntimeAssuranceIssuancePolicy>,
    pub advertise_url: Option<String>,
    pub certification_public_metadata_ttl_seconds: u64,
    pub peer_urls: Vec<String>,
    pub cluster_sync_interval: Duration,
}

#[derive(Clone)]
struct TrustServiceState {
    config: TrustServiceConfig,
    enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
    verifier_policy_registry: Option<Arc<VerifierPolicyRegistry>>,
    cluster: Option<Arc<Mutex<ClusterRuntimeState>>>,
}

#[derive(Clone)]
pub struct TrustControlClient {
    endpoints: Arc<Vec<String>>,
    preferred_index: Arc<Mutex<usize>>,
    token: Arc<str>,
    http: Agent,
}

struct RemoteCapabilityAuthority {
    client: TrustControlClient,
    cache: Mutex<AuthorityKeyCache>,
}

struct AuthorityKeyCache {
    current: Option<PublicKey>,
    trusted: Vec<PublicKey>,
    refreshed_at: Instant,
}

struct RemoteRevocationStore {
    client: TrustControlClient,
}

struct RemoteReceiptStore {
    client: TrustControlClient,
}

struct RemoteBudgetStore {
    client: TrustControlClient,
}

impl TrustServiceState {
    #[allow(dead_code)]
    fn enterprise_provider_registry(&self) -> Option<&EnterpriseProviderRegistry> {
        self.enterprise_provider_registry.as_deref()
    }

    #[allow(dead_code)]
    fn validated_enterprise_provider(
        &self,
        provider_id: &str,
    ) -> Option<&EnterpriseProviderRecord> {
        self.enterprise_provider_registry()
            .and_then(|registry| registry.validated_provider(provider_id))
    }

    fn verifier_policy_registry(&self) -> Option<&VerifierPolicyRegistry> {
        self.verifier_policy_registry.as_deref()
    }
}

#[derive(Debug, Clone)]
struct ClusterRuntimeState {
    self_url: String,
    peers: HashMap<String, PeerSyncState>,
}

#[derive(Debug, Clone)]
struct PeerSyncState {
    health: PeerHealth,
    last_error: Option<String>,
    tool_seq: u64,
    child_seq: u64,
    lineage_seq: u64,
    revocation_cursor: Option<RevocationCursor>,
    budget_cursor: Option<BudgetCursor>,
}

#[derive(Debug, Clone)]
enum PeerHealth {
    Unknown,
    Healthy,
    Unhealthy(Instant),
}

#[derive(Debug, Clone)]
struct RevocationCursor {
    revoked_at: i64,
    capability_id: String,
}

#[derive(Debug, Clone)]
struct BudgetCursor {
    seq: u64,
    updated_at: i64,
    capability_id: String,
    grant_index: u32,
}

impl Default for PeerSyncState {
    fn default() -> Self {
        Self {
            health: PeerHealth::Unknown,
            last_error: None,
            tool_seq: 0,
            child_seq: 0,
            lineage_seq: 0,
            revocation_cursor: None,
            budget_cursor: None,
        }
    }
}

impl PeerHealth {
    fn is_candidate(&self, now: Instant) -> bool {
        match self {
            Self::Unknown | Self::Healthy => true,
            Self::Unhealthy(at) => now.duration_since(*at) >= PEER_HEALTH_TTL,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Unhealthy(_) => "unhealthy",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustAuthorityStatus {
    pub configured: bool,
    pub backend: Option<String>,
    pub public_key: Option<String>,
    pub generation: Option<u64>,
    pub rotated_at: Option<u64>,
    pub applies_to_future_sessions_only: bool,
    #[serde(default)]
    pub trusted_public_keys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssueCapabilityRequest {
    subject_public_key: String,
    scope: ArcScope,
    ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_attestation: Option<RuntimeAttestationEvidence>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssueCapabilityResponse {
    capability: CapabilityToken,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FederatedIssueRequest {
    pub presentation: PassportPresentationResponse,
    pub expected_challenge: PassportPresentationChallenge,
    pub capability: crate::policy::DefaultCapability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_policy: Option<arc_policy::HushSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_identity: Option<EnterpriseIdentityContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_policy: Option<FederatedDelegationPolicyDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_capability_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FederatedIssueResponse {
    pub subject: String,
    pub subject_public_key: String,
    pub verification: PassportPresentationVerification,
    pub capability: CapabilityToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_identity_provenance: Option<EnterpriseIdentityProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_audit: Option<EnterpriseAdmissionAudit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_anchor_capability_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseAdmissionAudit {
    pub provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_record_id: Option<String>,
    pub provider_kind: String,
    pub federation_method: String,
    pub principal: String,
    pub subject_key: String,
    pub subject_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attribute_sources: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_material_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_origin_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseProviderListResponse {
    pub configured: bool,
    pub count: usize,
    pub providers: Vec<EnterpriseProviderRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseProviderDeleteResponse {
    pub provider_id: String,
    pub deleted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierPolicyListResponse {
    pub configured: bool,
    pub count: usize,
    pub policies: Vec<SignedPassportVerifierPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierPolicyDeleteResponse {
    pub policy_id: String,
    pub deleted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePassportChallengeRequest {
    pub verifier: String,
    pub ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_credentials: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PassportVerifierPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyPassportChallengeRequest {
    pub presentation: PassportPresentationResponse,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_challenge: Option<PassportPresentationChallenge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportPresentationTransport {
    pub challenge_id: String,
    pub challenge_url: String,
    pub submit_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePassportChallengeResponse {
    pub challenge: PassportPresentationChallenge,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<PassportPresentationTransport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateIdentityAssertionRequest {
    pub subject: String,
    pub continuity_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOid4vpRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclosure_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_allowlist: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_assertion: Option<CreateIdentityAssertionRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOid4vpRequestResponse {
    pub request: Oid4vpRequestObject,
    pub transport: arc_credentials::Oid4vpRequestTransport,
    pub wallet_exchange: WalletExchangeStatusResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletExchangeStatusResponse {
    pub descriptor: WalletExchangeDescriptor,
    pub transaction: WalletExchangeTransactionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_assertion: Option<ArcIdentityAssertion>,
}

#[derive(Debug, Deserialize)]
pub struct Oid4vpDirectPostForm {
    pub response: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePassportIssuanceOfferRequest {
    pub passport: AgentPassport,
    pub ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FederatedDelegationPolicyBody {
    pub schema: String,
    pub issuer: String,
    pub partner: String,
    pub verifier: String,
    pub signer_public_key: PublicKey,
    pub created_at: u64,
    pub expires_at: u64,
    pub ttl_seconds: u64,
    pub scope: ArcScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_capability_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FederatedDelegationPolicyDocument {
    pub body: FederatedDelegationPolicyBody,
    pub signature: Signature,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecordCapabilitySnapshotRequest {
    capability: CapabilityToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_capability_id: Option<String>,
}

pub fn verify_federated_delegation_policy(
    policy: &FederatedDelegationPolicyDocument,
) -> Result<(), CliError> {
    if policy.body.schema != FEDERATED_DELEGATION_POLICY_SCHEMA
        && policy.body.schema != LEGACY_FEDERATED_DELEGATION_POLICY_SCHEMA
    {
        return Err(CliError::Other(format!(
            "unsupported federated delegation policy schema: expected {} or {}, got {}",
            FEDERATED_DELEGATION_POLICY_SCHEMA,
            LEGACY_FEDERATED_DELEGATION_POLICY_SCHEMA,
            policy.body.schema
        )));
    }
    if policy.body.created_at > policy.body.expires_at {
        return Err(CliError::Other(
            "federated delegation policy created_at must be less than or equal to expires_at"
                .to_string(),
        ));
    }
    if policy.body.ttl_seconds == 0 {
        return Err(CliError::Other(
            "federated delegation policy ttl_seconds must be greater than zero".to_string(),
        ));
    }
    if !policy
        .body
        .signer_public_key
        .verify_canonical(&policy.body, &policy.signature)?
    {
        return Err(CliError::Other(
            "federated delegation policy signature verification failed".to_string(),
        ));
    }
    Ok(())
}

fn ensure_federated_delegation_policy_active(
    policy: &FederatedDelegationPolicyDocument,
    now: u64,
) -> Result<(), CliError> {
    if now < policy.body.created_at {
        return Err(CliError::Other(
            "federated delegation policy is not yet valid".to_string(),
        ));
    }
    if now > policy.body.expires_at {
        return Err(CliError::Other(
            "federated delegation policy has expired".to_string(),
        ));
    }
    Ok(())
}

fn ensure_requested_capability_within_delegation_policy(
    capability: &crate::policy::DefaultCapability,
    policy: &FederatedDelegationPolicyDocument,
    now: u64,
) -> Result<(), CliError> {
    if !capability.scope.is_subset_of(&policy.body.scope) {
        return Err(CliError::Other(
            "requested capability scope exceeds the signed federated delegation policy ceiling"
                .to_string(),
        ));
    }
    if capability.ttl > policy.body.ttl_seconds {
        return Err(CliError::Other(
            "requested capability ttl exceeds the signed federated delegation policy ceiling"
                .to_string(),
        ));
    }
    let requested_expires_at = now.saturating_add(capability.ttl);
    if requested_expires_at > policy.body.expires_at {
        return Err(CliError::Other(
            "requested capability expires after the federated delegation policy validity window"
                .to_string(),
        ));
    }
    Ok(())
}

fn ensure_requested_capability_within_parent_snapshot(
    capability: &crate::policy::DefaultCapability,
    parent_snapshot: &CapabilitySnapshot,
    now: u64,
) -> Result<(), CliError> {
    let parent_scope: ArcScope = serde_json::from_str(&parent_snapshot.grants_json)?;
    if !capability.scope.is_subset_of(&parent_scope) {
        return Err(CliError::Other(
            "requested capability scope exceeds the imported upstream capability scope".to_string(),
        ));
    }
    let requested_expires_at = now.saturating_add(capability.ttl);
    if requested_expires_at > parent_snapshot.expires_at {
        return Err(CliError::Other(
            "requested capability expires after the imported upstream capability validity window"
                .to_string(),
        ));
    }
    if now >= parent_snapshot.expires_at {
        return Err(CliError::Other(
            "imported upstream capability has already expired".to_string(),
        ));
    }
    Ok(())
}

fn build_capability_snapshot(
    token: &CapabilityToken,
    delegation_depth: u64,
    parent_capability_id: Option<String>,
) -> Result<CapabilitySnapshot, CliError> {
    Ok(CapabilitySnapshot {
        capability_id: token.id.clone(),
        subject_key: token.subject.to_hex(),
        issuer_key: token.issuer.to_hex(),
        issued_at: token.issued_at,
        expires_at: token.expires_at,
        grants_json: serde_json::to_string(&token.scope)?,
        delegation_depth,
        parent_capability_id,
    })
}

fn build_federated_delegation_anchor_snapshot(
    policy: &FederatedDelegationPolicyDocument,
    subject_key: &str,
    challenge: &PassportPresentationChallenge,
    now: u64,
    parent_capability: Option<&CapabilitySnapshot>,
) -> Result<CapabilitySnapshot, CliError> {
    let anchor_descriptor = json!({
        "policySha256": sha256_hex(&canonical_json_bytes(&policy.body)?),
        "subjectKey": subject_key,
        "verifier": challenge.verifier,
        "nonce": challenge.nonce,
        "challengeIssuedAt": challenge.issued_at,
        "challengeExpiresAt": challenge.expires_at,
        "parentCapabilityId": parent_capability.map(|snapshot| snapshot.capability_id.clone()),
    });
    Ok(CapabilitySnapshot {
        capability_id: format!(
            "fed-del-{}",
            sha256_hex(&canonical_json_bytes(&anchor_descriptor)?)
        ),
        subject_key: subject_key.to_string(),
        issuer_key: policy.body.signer_public_key.to_hex(),
        issued_at: now,
        expires_at: parent_capability
            .map(|snapshot| snapshot.expires_at.min(policy.body.expires_at))
            .unwrap_or(policy.body.expires_at),
        grants_json: serde_json::to_string(&policy.body.scope)?,
        delegation_depth: parent_capability
            .map(|snapshot| snapshot.delegation_depth.saturating_add(1))
            .unwrap_or(0),
        parent_capability_id: None,
    })
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ToolReceiptQuery {
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub tool_server: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// HTTP query parameters for the GET /v1/receipts/query endpoint.
/// Supports all 8 filter dimensions plus cursor pagination.
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptQueryHttpQuery {
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub tool_server: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub since: Option<u64>,
    #[serde(default)]
    pub until: Option<u64>,
    #[serde(default)]
    pub min_cost: Option<u64>,
    #[serde(default)]
    pub max_cost: Option<u64>,
    #[serde(default)]
    pub cursor: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub agent_subject: Option<String>,
}

/// Query parameters for GET /v1/agents/:subject_key/receipts.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentReceiptsHttpQuery {
    #[serde(default)]
    pub cursor: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LocalReputationQuery {
    #[serde(default)]
    pub since: Option<u64>,
    #[serde(default)]
    pub until: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReputationCompareRequest {
    pub passport: AgentPassport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_policy: Option<PassportVerifierPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

/// Response body for GET /v1/receipts/query.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptQueryResponse {
    pub total_count: u64,
    pub next_cursor: Option<u64>,
    pub receipts: Vec<Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SettlementReconciliationUpdateRequest {
    pub receipt_id: String,
    pub reconciliation_state: SettlementReconciliationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SettlementReconciliationUpdateResponse {
    pub receipt_id: String,
    pub reconciliation_state: SettlementReconciliationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub updated_at: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingReconciliationUpdateRequest {
    pub receipt_id: String,
    pub adapter_kind: String,
    pub evidence_id: String,
    pub observed_units: u64,
    pub billed_cost: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_sha256: Option<String>,
    pub recorded_at: u64,
    pub reconciliation_state: MeteredBillingReconciliationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingReconciliationUpdateResponse {
    pub receipt_id: String,
    pub evidence: MeteredBillingEvidenceRecord,
    pub reconciliation_state: MeteredBillingReconciliationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub updated_at: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingDecisionIssueRequest {
    pub query: UnderwritingPolicyInputQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_decision_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityIssueRequest {
    pub query: ExposureLedgerQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_facility_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondIssueRequest {
    pub query: ExposureLedgerQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_bond_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleIssueRequest {
    pub query: CreditLossLifecycleQuery,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderIssueRequest {
    pub report: LiabilityProviderReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_provider_record_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityQuoteRequestIssueRequest {
    pub provider_id: String,
    pub jurisdiction: String,
    pub coverage_class: LiabilityCoverageClass,
    pub requested_coverage_amount: MonetaryAmount,
    pub requested_effective_from: u64,
    pub requested_effective_until: u64,
    pub risk_package: SignedCreditProviderRiskPackage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityQuoteResponseIssueRequest {
    pub quote_request: SignedLiabilityQuoteRequest,
    pub provider_quote_ref: String,
    pub disposition: LiabilityQuoteDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_quote_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_terms: Option<LiabilityQuoteTerms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decline_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityPlacementIssueRequest {
    pub quote_response: SignedLiabilityQuoteResponse,
    pub selected_coverage_amount: MonetaryAmount,
    pub selected_premium_amount: MonetaryAmount,
    pub effective_from: u64,
    pub effective_until: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityBoundCoverageIssueRequest {
    pub placement: SignedLiabilityPlacement,
    pub policy_number: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<u64>,
    pub effective_from: u64,
    pub effective_until: u64,
    pub coverage_amount: MonetaryAmount,
    pub premium_amount: MonetaryAmount,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimPackageIssueRequest {
    pub bound_coverage: SignedLiabilityBoundCoverage,
    pub exposure: SignedExposureLedgerReport,
    pub bond: SignedCreditBond,
    pub loss_event: SignedCreditLossLifecycle,
    pub claimant: String,
    pub claim_event_at: u64,
    pub claim_amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ref: Option<String>,
    pub narrative: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipt_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimResponseIssueRequest {
    pub claim: SignedLiabilityClaimPackage,
    pub provider_response_ref: String,
    pub disposition: LiabilityClaimResponseDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimDisputeIssueRequest {
    pub provider_response: SignedLiabilityClaimResponse,
    pub opened_by: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimAdjudicationIssueRequest {
    pub dispute: SignedLiabilityClaimDispute,
    pub adjudicator: String,
    pub outcome: LiabilityClaimAdjudicationOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub awarded_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
struct TrustHttpError {
    status: StatusCode,
    message: String,
}

impl TrustHttpError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    fn into_response(self) -> Response {
        plain_http_error(self.status, &self.message)
    }
}

impl From<TrustHttpError> for CliError {
    fn from(error: TrustHttpError) -> Self {
        CliError::Other(error.message)
    }
}

impl From<ReceiptStoreError> for TrustHttpError {
    fn from(error: ReceiptStoreError) -> Self {
        trust_http_error_from_receipt_store(error)
    }
}

impl From<CliError> for TrustHttpError {
    fn from(error: CliError) -> Self {
        TrustHttpError::internal(error.to_string())
    }
}

fn liability_market_http_error(message: &str) -> Response {
    let status = if message.contains("not found") {
        StatusCode::NOT_FOUND
    } else if message.contains("already")
        || message.contains("stale")
        || message.contains("unsupported")
        || message.contains("not active")
        || message.contains("superseded")
        || message.contains("expires")
        || message.contains("mismatch")
        || message.contains("must match")
        || message.contains("cannot be issued")
    {
        StatusCode::CONFLICT
    } else {
        StatusCode::BAD_REQUEST
    };
    plain_http_error(status, message)
}

#[derive(Debug, Clone)]
enum UnderwritingQuotedExposure {
    None,
    Single(MonetaryAmount),
    MixedCurrencies(BTreeSet<String>),
}

impl UnderwritingQuotedExposure {
    fn amount_for_pricing(&self) -> Option<MonetaryAmount> {
        match self {
            Self::Single(amount) => Some(amount.clone()),
            Self::None | Self::MixedCurrencies(_) => None,
        }
    }

    fn apply_to_artifact(&self, artifact: &mut arc_kernel::UnderwritingDecisionArtifact) {
        let Self::MixedCurrencies(currencies) = self else {
            return;
        };
        if artifact.premium.state != arc_kernel::UnderwritingPremiumState::Quoted {
            return;
        }

        artifact.premium.state = arc_kernel::UnderwritingPremiumState::Withheld;
        artifact.premium.basis_points = None;
        artifact.premium.quoted_amount = None;
        artifact.premium.rationale = format!(
            "premium is withheld because governed exposure spans multiple currencies: {}",
            currencies.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChildReceiptQuery {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub parent_request_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub terminal_state: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RevocationQuery {
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRecordView {
    pub capability_id: String,
    pub revoked_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationListResponse {
    pub configured: bool,
    pub backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    pub count: usize,
    pub revocations: Vec<RevocationRecordView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptListResponse {
    pub configured: bool,
    pub backend: String,
    pub kind: String,
    pub count: usize,
    pub filters: Value,
    pub receipts: Vec<Value>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BudgetQuery {
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetUsageView {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub total_cost_charged: u64,
    pub updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetListResponse {
    pub configured: bool,
    pub backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    pub count: usize,
    pub usages: Vec<BudgetUsageView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClusterStatusResponse {
    self_url: String,
    leader_url: String,
    peers: Vec<PeerStatusView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PeerStatusView {
    peer_url: String,
    health: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
    tool_seq: u64,
    child_seq: u64,
    lineage_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revocation_cursor: Option<RevocationCursorView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_cursor: Option<BudgetCursorView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevocationCursorView {
    revoked_at: i64,
    capability_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BudgetCursorView {
    seq: u64,
    updated_at: i64,
    capability_id: String,
    grant_index: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthoritySnapshotView {
    seed_hex: String,
    public_key_hex: String,
    generation: u64,
    rotated_at: u64,
    trusted_keys: Vec<AuthorityTrustedKeyView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorityTrustedKeyView {
    public_key_hex: String,
    generation: u64,
    activated_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevocationDeltaQuery {
    #[serde(default)]
    after_revoked_at: Option<i64>,
    #[serde(default)]
    after_capability_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevocationDeltaResponse {
    records: Vec<RevocationRecordView>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptDeltaQuery {
    #[serde(default)]
    after_seq: Option<u64>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredReceiptView {
    seq: u64,
    receipt: Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptDeltaResponse {
    records: Vec<StoredReceiptView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredLineageView {
    seq: u64,
    snapshot: CapabilitySnapshot,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LineageDeltaResponse {
    records: Vec<StoredLineageView>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BudgetDeltaQuery {
    #[serde(default)]
    after_seq: Option<u64>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BudgetDeltaResponse {
    records: Vec<BudgetUsageView>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TryIncrementBudgetRequest {
    capability_id: String,
    grant_index: usize,
    max_invocations: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TryIncrementBudgetResponse {
    capability_id: String,
    grant_index: usize,
    allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invocation_count: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TryChargeCostRequest {
    capability_id: String,
    grant_index: usize,
    max_invocations: Option<u32>,
    cost_units: u64,
    max_cost_per_invocation: Option<u64>,
    max_total_cost_units: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TryChargeCostResponse {
    capability_id: String,
    grant_index: usize,
    allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invocation_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_cost_charged: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReverseChargeCostRequest {
    capability_id: String,
    grant_index: usize,
    cost_units: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReverseChargeCostResponse {
    capability_id: String,
    grant_index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invocation_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_cost_charged: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReduceChargeCostRequest {
    capability_id: String,
    grant_index: usize,
    cost_units: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReduceChargeCostResponse {
    capability_id: String,
    grant_index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invocation_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_cost_charged: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeCapabilityRequest {
    capability_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeCapabilityResponse {
    pub capability_id: String,
    pub revoked: bool,
    pub newly_revoked: bool,
}

pub fn serve(config: TrustServiceConfig) -> Result<(), CliError> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| CliError::Other(format!("failed to start async runtime: {error}")))?;
    runtime.block_on(async move { serve_async(config).await })
}

fn load_enterprise_provider_registry(
    path: Option<&std::path::Path>,
    surface: &str,
) -> Result<Option<Arc<EnterpriseProviderRegistry>>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let registry = EnterpriseProviderRegistry::load(path)?;
    for record in registry.providers.values() {
        if !record.validation_errors.is_empty() {
            warn!(
                surface,
                provider_id = %record.provider_id,
                errors = ?record.validation_errors,
                "enterprise provider record is invalid and will stay unavailable for admission"
            );
        }
    }
    Ok(Some(Arc::new(registry)))
}

fn load_verifier_policy_registry(
    path: Option<&std::path::Path>,
    surface: &str,
) -> Result<Option<Arc<VerifierPolicyRegistry>>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let registry = VerifierPolicyRegistry::load(path)?;
    for document in registry.policies.values() {
        if let Err(error) =
            ensure_signed_passport_verifier_policy_active(document, unix_timestamp_now())
        {
            warn!(
                surface,
                policy_id = %document.body.policy_id,
                error = %error,
                "stored verifier policy is structurally valid but currently inactive"
            );
        }
    }
    Ok(Some(Arc::new(registry)))
}

fn configured_enterprise_provider_registry_path(
    config: &TrustServiceConfig,
) -> Result<&Path, CliError> {
    config.enterprise_providers_file.as_deref().ok_or_else(|| {
        CliError::Other(
            "enterprise provider admin requires --enterprise-providers-file on the trust-control service"
                .to_string(),
        )
    })
}

fn configured_verifier_policy_registry_path(
    config: &TrustServiceConfig,
) -> Result<&Path, CliError> {
    config.verifier_policies_file.as_deref().ok_or_else(|| {
        CliError::Other(
            "verifier policy administration requires --verifier-policies-file on the trust-control service"
                .to_string(),
        )
    })
}

fn configured_verifier_challenge_db_path(config: &TrustServiceConfig) -> Result<&Path, CliError> {
    config.verifier_challenge_db_path.as_deref().ok_or_else(|| {
        CliError::Other(
            "remote verifier challenge flows require --verifier-challenge-db on the trust-control service"
                .to_string(),
        )
    })
}

fn configured_passport_status_registry_path(
    config: &TrustServiceConfig,
) -> Result<&Path, CliError> {
    config.passport_statuses_file.as_deref().ok_or_else(|| {
        CliError::Other(
            "passport lifecycle administration requires --passport-statuses-file on the trust-control service"
                .to_string(),
        )
    })
}

fn configured_passport_issuance_registry_path(
    config: &TrustServiceConfig,
) -> Result<&Path, CliError> {
    config.passport_issuance_offers_file.as_deref().ok_or_else(|| {
        CliError::Other(
            "passport issuance requires --passport-issuance-offers-file on the trust-control service"
                .to_string(),
        )
    })
}

fn configured_passport_credential_issuer(
    config: &TrustServiceConfig,
) -> Result<Oid4vciCredentialIssuerMetadata, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::Other(
            "passport issuance requires --advertise-url on the trust-control service".to_string(),
        )
    })?;
    let passport_status_distribution = default_passport_status_distribution(config);
    let portable_signing_public_key =
        if config.authority_seed_path.is_some() || config.authority_db_path.is_some() {
            Some(resolve_oid4vp_verifier_signing_key(config)?.public_key())
        } else {
            None
        };
    default_oid4vci_passport_issuer_metadata_with_signing_key(
        advertise_url,
        passport_status_distribution,
        portable_signing_public_key.as_ref(),
    )
    .map_err(CliError::from)
}

fn configured_certification_registry_path(config: &TrustServiceConfig) -> Result<&Path, CliError> {
    config.certification_registry_file.as_deref().ok_or_else(|| {
        CliError::Other(
            "certification registry administration requires --certification-registry-file on the trust-control service"
                .to_string(),
        )
    })
}

fn configured_certification_discovery_path(config: &TrustServiceConfig) -> Result<&Path, CliError> {
    config.certification_discovery_file.as_deref().ok_or_else(|| {
        CliError::Other(
            "certification discovery requires --certification-discovery-file on the trust-control service"
                .to_string(),
        )
    })
}

fn configured_public_certification_metadata(
    config: &TrustServiceConfig,
) -> Result<CertificationPublicMetadata, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::Other(
            "public certification metadata requires --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    let registry_url = advertise_url.trim_end_matches('/').to_string();
    if registry_url.is_empty() {
        return Err(CliError::Other(
            "public certification metadata requires a non-empty advertise_url".to_string(),
        ));
    }
    let generated_at = unix_timestamp_now();
    Ok(CertificationPublicMetadata {
        schema: "arc.certify.discovery-metadata.v1".to_string(),
        generated_at,
        expires_at: generated_at.saturating_add(config.certification_public_metadata_ttl_seconds),
        publisher: crate::certify::CertificationPublicPublisher {
            publisher_id: registry_url.clone(),
            publisher_name: None,
            registry_url: registry_url.clone(),
        },
        public_resolve_path_template: format!(
            "{registry_url}/v1/public/certifications/resolve/{{tool_server_id}}"
        ),
        public_search_path: format!("{registry_url}{PUBLIC_CERTIFICATION_SEARCH_PATH}"),
        public_transparency_path: format!("{registry_url}{PUBLIC_CERTIFICATION_TRANSPARENCY_PATH}"),
        supported_profiles: vec![crate::certify::CertificationSupportedProfile {
            criteria_profile: "conformance-all-pass-v1".to_string(),
            evidence_profile: "conformance-report-bundle-v1".to_string(),
        }],
        discovery_informational_only: true,
    })
}

fn load_enterprise_provider_registry_for_admin(
    config: &TrustServiceConfig,
) -> Result<(PathBuf, EnterpriseProviderRegistry), CliError> {
    let path = configured_enterprise_provider_registry_path(config)?.to_path_buf();
    let registry = if path.exists() {
        EnterpriseProviderRegistry::load(&path)?
    } else {
        EnterpriseProviderRegistry::default()
    };
    Ok((path, registry))
}

fn load_verifier_policy_registry_for_admin(
    config: &TrustServiceConfig,
) -> Result<(PathBuf, VerifierPolicyRegistry), CliError> {
    let path = configured_verifier_policy_registry_path(config)?.to_path_buf();
    let registry = if path.exists() {
        VerifierPolicyRegistry::load(&path)?
    } else {
        VerifierPolicyRegistry::default()
    };
    Ok((path, registry))
}

fn load_passport_issuance_registry_for_admin(
    config: &TrustServiceConfig,
) -> Result<(PathBuf, PassportIssuanceOfferRegistry), CliError> {
    let path = configured_passport_issuance_registry_path(config)?.to_path_buf();
    let registry = if path.exists() {
        PassportIssuanceOfferRegistry::load(&path)?
    } else {
        PassportIssuanceOfferRegistry::default()
    };
    Ok((path, registry))
}

fn load_passport_status_registry_for_admin(
    config: &TrustServiceConfig,
) -> Result<(PathBuf, PassportStatusRegistry), CliError> {
    let path = configured_passport_status_registry_path(config)?.to_path_buf();
    let registry = if path.exists() {
        PassportStatusRegistry::load(&path)?
    } else {
        PassportStatusRegistry::default()
    };
    Ok((path, registry))
}

fn load_certification_registry_for_admin(
    config: &TrustServiceConfig,
) -> Result<(PathBuf, CertificationRegistry), CliError> {
    let path = configured_certification_registry_path(config)?.to_path_buf();
    let registry = if path.exists() {
        CertificationRegistry::load(&path)?
    } else {
        CertificationRegistry::default()
    };
    Ok((path, registry))
}

fn load_certification_discovery_network_for_admin(
    config: &TrustServiceConfig,
) -> Result<(PathBuf, CertificationDiscoveryNetwork), CliError> {
    let path = configured_certification_discovery_path(config)?.to_path_buf();
    let network = CertificationDiscoveryNetwork::load(&path)?;
    Ok((path, network))
}

fn resolve_verifier_policy_for_challenge(
    registry: Option<&VerifierPolicyRegistry>,
    challenge: &PassportPresentationChallenge,
    now: u64,
) -> Result<(Option<PassportVerifierPolicy>, Option<String>), CliError> {
    if let Some(policy) = challenge.policy.as_ref() {
        return Ok((Some(policy.clone()), Some("embedded".to_string())));
    }
    let Some(reference) = challenge.policy_ref.as_ref() else {
        return Ok((None, None));
    };
    let Some(registry) = registry else {
        return Err(CliError::Other(
            "verifier policy reference requires a configured verifier policy registry".to_string(),
        ));
    };
    let document = registry.active_policy(&reference.policy_id, now)?;
    if document.body.verifier != challenge.verifier {
        return Err(CliError::Other(format!(
            "verifier policy `{}` is bound to verifier `{}` but challenge expects `{}`",
            document.body.policy_id, document.body.verifier, challenge.verifier
        )));
    }
    Ok((
        Some(document.body.policy.clone()),
        Some(format!("registry:{}", document.body.policy_id)),
    ))
}

fn passport_lifecycle_reason(lifecycle: &PassportLifecycleResolution) -> String {
    match lifecycle.state {
        PassportLifecycleState::Active => "passport lifecycle state is active".to_string(),
        PassportLifecycleState::Stale => lifecycle
            .updated_at
            .map(|updated_at| {
                format!("passport lifecycle state is stale: last updated at {updated_at}")
            })
            .unwrap_or_else(|| "passport lifecycle state is stale".to_string()),
        PassportLifecycleState::Superseded => lifecycle
            .superseded_by
            .as_deref()
            .map(|passport_id| format!("passport lifecycle state is superseded by {passport_id}"))
            .unwrap_or_else(|| "passport lifecycle state is superseded".to_string()),
        PassportLifecycleState::Revoked => lifecycle
            .revoked_reason
            .as_deref()
            .map(|reason| format!("passport lifecycle state is revoked: {reason}"))
            .unwrap_or_else(|| "passport lifecycle state is revoked".to_string()),
        PassportLifecycleState::NotFound => "passport lifecycle record was not found".to_string(),
    }
}

fn default_passport_status_distribution(config: &TrustServiceConfig) -> PassportStatusDistribution {
    if config.passport_statuses_file.is_none() {
        return PassportStatusDistribution::default();
    }
    config
        .advertise_url
        .as_deref()
        .map(|advertise_url| PassportStatusDistribution {
            resolve_urls: vec![format!(
                "{advertise_url}/v1/public/passport/statuses/resolve"
            )],
            cache_ttl_secs: Some(300),
        })
        .unwrap_or_default()
}

fn resolve_passport_lifecycle_for_service(
    config: &TrustServiceConfig,
    passport: &AgentPassport,
    at: u64,
) -> Result<Option<PassportLifecycleResolution>, CliError> {
    let Some(_) = config.passport_statuses_file.as_deref() else {
        return Ok(None);
    };
    let (_, registry) = load_passport_status_registry_for_admin(config)?;
    let mut lifecycle = registry.resolve_for_passport(passport, at)?;
    lifecycle.source = Some("registry:trust-control".to_string());
    Ok(Some(lifecycle))
}

fn portable_passport_status_reference_for_service(
    config: &TrustServiceConfig,
    passport: &AgentPassport,
    at: u64,
) -> Result<Option<arc_credentials::Oid4vciArcPassportStatusReference>, CliError> {
    let Some(_) = config.passport_statuses_file.as_deref() else {
        return Ok(None);
    };
    let (_, registry) = load_passport_status_registry_for_admin(config)?;
    registry
        .portable_status_reference_for_passport(passport, at)
        .map(Some)
}

fn passport_presentation_transport_for_service(
    config: &TrustServiceConfig,
    challenge: &PassportPresentationChallenge,
) -> Result<Option<PassportPresentationTransport>, CliError> {
    let Some(advertise_url) = config.advertise_url.as_deref() else {
        return Ok(None);
    };
    let challenge_id = challenge
        .challenge_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Other(
                "public holder transport requires challenges to include a non-empty challenge_id"
                    .to_string(),
            )
        })?;
    Ok(Some(PassportPresentationTransport {
        challenge_id: challenge_id.to_string(),
        challenge_url: format!("{advertise_url}/v1/public/passport/challenges/{challenge_id}"),
        submit_url: format!("{advertise_url}/v1/public/passport/challenges/verify"),
    }))
}

fn consume_challenge_if_configured(
    config: &TrustServiceConfig,
    challenge: &PassportPresentationChallenge,
    now: u64,
) -> Result<Option<String>, CliError> {
    let Some(path) = config.verifier_challenge_db_path.as_deref() else {
        if challenge.policy_ref.is_some() {
            return Err(CliError::Other(
                "stored verifier challenges require --verifier-challenge-db on the trust-control service"
                    .to_string(),
            ));
        }
        return Ok(None);
    };
    let store = PassportVerifierChallengeStore::open(path)?;
    store.consume(challenge, now)?;
    Ok(Some("consumed".to_string()))
}

fn generate_oid4vp_token(prefix: &str, seed: &str) -> String {
    let digest = sha256_hex(seed.as_bytes());
    format!("{prefix}-{}", &digest[..24])
}

fn oid4vp_same_device_url(request_uri: &str) -> String {
    format!(
        "{OID4VP_OPENID4VP_SCHEME}?request_uri={}",
        utf8_percent_encode(request_uri, NON_ALPHANUMERIC)
    )
}

fn oid4vp_wallet_exchange_url(
    config: &TrustServiceConfig,
    request_id: &str,
) -> Result<String, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::Other(
            "wallet exchange descriptor requires --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    Ok(format!(
        "{advertise_url}{}",
        path_with_encoded_param(
            PUBLIC_PASSPORT_WALLET_EXCHANGE_PATH,
            "request_id",
            request_id
        )
    ))
}

fn oid4vp_cross_device_url(
    config: &TrustServiceConfig,
    request_id: &str,
    request_uri: &str,
) -> Result<String, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::Other(
            "OID4VP verifier requests require --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    Ok(format!(
        "{advertise_url}{}?request_uri={}",
        path_with_encoded_param(PUBLIC_PASSPORT_OID4VP_LAUNCH_PATH, "request_id", request_id),
        utf8_percent_encode(request_uri, NON_ALPHANUMERIC)
    ))
}

fn build_oid4vp_wallet_exchange_response(
    config: &TrustServiceConfig,
    request: &Oid4vpRequestObject,
    request_jwt: &str,
    transaction: WalletExchangeTransactionState,
    same_device_url: &str,
    cross_device_url: &str,
) -> Result<WalletExchangeStatusResponse, CliError> {
    let descriptor = build_wallet_exchange_descriptor_for_oid4vp(
        request,
        request_jwt,
        &oid4vp_wallet_exchange_url(config, &request.jti)?,
        same_device_url,
        cross_device_url,
        Some(cross_device_url),
    )
    .map_err(|error| CliError::Other(error.to_string()))?;
    transaction
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(WalletExchangeStatusResponse {
        descriptor,
        transaction,
        identity_assertion: request.identity_assertion.clone(),
    })
}

fn authority_status_for_config(
    config: &TrustServiceConfig,
) -> Result<TrustAuthorityStatus, CliError> {
    if let Some(path) = config.authority_db_path.as_deref() {
        let status = SqliteCapabilityAuthority::open(path)?.status()?;
        return Ok(authority_status_response("sqlite".to_string(), status));
    }

    let Some(path) = config.authority_seed_path.as_deref() else {
        return Err(CliError::Other(
            "OID4VP verifier trust material requires --authority-seed-file or --authority-db"
                .to_string(),
        ));
    };
    match authority_public_key_from_seed_file(path)? {
        Some(public_key) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: Some(public_key.to_hex()),
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![public_key.to_hex()],
        }),
        None => Err(CliError::Other(
            "OID4VP verifier trust material requires a configured authority public key".to_string(),
        )),
    }
}

fn trusted_public_keys_from_status(
    status: &TrustAuthorityStatus,
) -> Result<Vec<PublicKey>, CliError> {
    if !status.configured {
        return Err(CliError::Other(
            "OID4VP verifier trust material requires a configured authority".to_string(),
        ));
    }
    let mut trusted = status
        .trusted_public_keys
        .iter()
        .map(|value| PublicKey::from_hex(value))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(current) = status.public_key.as_deref() {
        let current = PublicKey::from_hex(current)?;
        if !trusted.iter().any(|public_key| public_key == &current) {
            trusted.push(current);
        }
    }
    if trusted.is_empty() {
        return Err(CliError::Other(
            "OID4VP verifier trust material did not publish any signing keys".to_string(),
        ));
    }
    Ok(trusted)
}

fn resolve_oid4vp_verifier_trusted_public_keys(
    config: &TrustServiceConfig,
) -> Result<Vec<PublicKey>, CliError> {
    trusted_public_keys_from_status(&authority_status_for_config(config)?)
}

fn build_oid4vp_verifier_metadata(
    config: &TrustServiceConfig,
) -> Result<Oid4vpVerifierMetadata, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::Other(
            "OID4VP verifier metadata requires --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    let status = authority_status_for_config(config)?;
    let trusted_public_keys = trusted_public_keys_from_status(&status)?;
    let metadata = Oid4vpVerifierMetadata {
        verifier_id: advertise_url.to_string(),
        client_id: advertise_url.to_string(),
        client_id_scheme: OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI.to_string(),
        request_uri_prefix: format!("{advertise_url}/v1/public/passport/oid4vp/requests/"),
        response_uri: format!("{advertise_url}{PUBLIC_PASSPORT_OID4VP_DIRECT_POST_PATH}"),
        same_device_launch_prefix: format!("{OID4VP_OPENID4VP_SCHEME}?request_uri="),
        jwks_uri: format!("{advertise_url}{OID4VCI_JWKS_PATH}"),
        request_object_signing_alg_values_supported: vec!["EdDSA".to_string()],
        response_mode: OID4VP_RESPONSE_MODE_DIRECT_POST_JWT.to_string(),
        response_type: OID4VP_RESPONSE_TYPE_VP_TOKEN.to_string(),
        credential_format: ARC_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
        credential_vct: ARC_PASSPORT_SD_JWT_VC_TYPE.to_string(),
        authority_generation: status.generation,
        authority_rotated_at: status.rotated_at,
        trusted_key_count: trusted_public_keys.len(),
    };
    metadata
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(metadata)
}

fn build_oid4vp_verifier_jwks(config: &TrustServiceConfig) -> Result<PortableJwkSet, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::Other(
            "OID4VP verifier jwks requires --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    let trusted_public_keys = resolve_oid4vp_verifier_trusted_public_keys(config)?;
    build_portable_jwks(advertise_url, &trusted_public_keys)
        .map_err(|error| CliError::Other(error.to_string()))
}

fn build_oid4vp_request_for_service(
    config: &TrustServiceConfig,
    payload: &CreateOid4vpRequest,
    now: u64,
) -> Result<Oid4vpRequestObject, CliError> {
    let advertise_url = config.advertise_url.as_deref().ok_or_else(|| {
        CliError::Other(
            "OID4VP verifier requests require --advertise-url on the trust-control service"
                .to_string(),
        )
    })?;
    let _ = configured_verifier_challenge_db_path(config)?;
    let ttl_seconds = payload.ttl_seconds.unwrap_or(300).clamp(30, 600);
    let entropy = Keypair::generate().public_key().to_hex();
    let request_id = generate_oid4vp_token(
        "oid4vp",
        &format!(
            "{advertise_url}:{now}:{entropy}:{}",
            payload.disclosure_claims.join(",")
        ),
    );
    let nonce = generate_oid4vp_token(
        "nonce",
        &format!(
            "{request_id}:{entropy}:{}",
            payload.issuer_allowlist.join(",")
        ),
    );
    let state = generate_oid4vp_token("state", &format!("{request_id}:{ttl_seconds}:{entropy}"));
    let response_uri = format!("{advertise_url}{PUBLIC_PASSPORT_OID4VP_DIRECT_POST_PATH}");
    let request_uri = format!(
        "{advertise_url}{}",
        path_with_encoded_param(
            PUBLIC_PASSPORT_OID4VP_REQUEST_PATH,
            "request_id",
            &request_id
        )
    );
    let identity_assertion = payload
        .identity_assertion
        .as_ref()
        .map(|assertion| {
            if assertion.subject.trim().is_empty() {
                return Err(CliError::Other(
                    "OID4VP identity assertion subject must not be empty".to_string(),
                ));
            }
            if assertion.continuity_id.trim().is_empty() {
                return Err(CliError::Other(
                    "OID4VP identity assertion continuity_id must not be empty".to_string(),
                ));
            }
            if assertion
                .provider
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(CliError::Other(
                    "OID4VP identity assertion provider must not be empty when present".to_string(),
                ));
            }
            if assertion
                .session_hint
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(CliError::Other(
                    "OID4VP identity assertion session_hint must not be empty when present"
                        .to_string(),
                ));
            }
            let assertion_ttl = assertion.ttl_seconds.unwrap_or(ttl_seconds).clamp(30, 600);
            let identity_assertion = ArcIdentityAssertion {
                verifier_id: advertise_url.to_string(),
                subject: assertion.subject.clone(),
                continuity_id: assertion.continuity_id.clone(),
                issued_at: now,
                expires_at: now
                    .saturating_add(assertion_ttl)
                    .min(now.saturating_add(ttl_seconds)),
                provider: assertion.provider.clone(),
                session_hint: assertion.session_hint.clone(),
                bound_request_id: Some(request_id.clone()),
            };
            identity_assertion
                .validate_at(now)
                .map_err(CliError::Other)?;
            Ok(identity_assertion)
        })
        .transpose()?;
    let request = Oid4vpRequestObject {
        client_id: advertise_url.to_string(),
        client_id_scheme: OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI.to_string(),
        response_uri,
        response_mode: OID4VP_RESPONSE_MODE_DIRECT_POST_JWT.to_string(),
        response_type: OID4VP_RESPONSE_TYPE_VP_TOKEN.to_string(),
        nonce,
        state,
        iat: now,
        exp: now.saturating_add(ttl_seconds),
        jti: request_id,
        request_uri,
        dcql_query: arc_credentials::Oid4vpDcqlQuery {
            credentials: vec![Oid4vpRequestedCredential {
                id: "arc-passport".to_string(),
                format: ARC_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
                vct: ARC_PASSPORT_SD_JWT_VC_TYPE.to_string(),
                claims: payload.disclosure_claims.clone(),
                issuer_allowlist: payload.issuer_allowlist.clone(),
            }],
        },
        identity_assertion,
    };
    request
        .validate(now)
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(request)
}

fn resolve_oid4vp_verifier_signing_key(config: &TrustServiceConfig) -> Result<Keypair, CliError> {
    if let Some(path) = config.authority_db_path.as_deref() {
        let snapshot = SqliteCapabilityAuthority::open(path)?.snapshot()?;
        return Ok(Keypair::from_seed_hex(&snapshot.seed_hex)?);
    }
    let path = config.authority_seed_path.as_deref().ok_or_else(|| {
        CliError::Other(
            "OID4VP verifier requests require a configured authority signing seed".to_string(),
        )
    })?;
    load_or_create_authority_keypair(path)
}

fn resolve_portable_issuer_public_keys(
    config: &TrustServiceConfig,
    issuer: &str,
) -> Result<Vec<PublicKey>, CliError> {
    if config.advertise_url.as_deref() == Some(issuer) {
        return resolve_oid4vp_verifier_trusted_public_keys(config);
    }
    let jwks_url = format!("{issuer}{OID4VCI_JWKS_PATH}");
    let response = ureq::get(&jwks_url).call().map_err(|error| match error {
        ureq::Error::Status(status, response) => {
            let body = response.into_string().unwrap_or_default();
            CliError::Other(format!(
                "failed to fetch portable issuer JWKS from `{jwks_url}` with status {status}: {body}"
            ))
        }
        ureq::Error::Transport(transport) => CliError::Other(format!(
            "failed to fetch portable issuer JWKS from `{jwks_url}`: {transport}"
        )),
    })?;
    let jwks: arc_credentials::PortableJwkSet = serde_json::from_reader(response.into_reader())
        .map_err(|error| {
            CliError::Other(format!(
                "failed to decode portable issuer JWKS from `{jwks_url}`: {error}"
            ))
        })?;
    jwks.keys.first().ok_or_else(|| {
        CliError::Other(format!(
            "portable issuer JWKS at `{jwks_url}` did not publish any keys"
        ))
    })?;
    let mut public_keys = Vec::with_capacity(jwks.keys.len());
    for entry in &jwks.keys {
        public_keys.push(
            entry
                .jwk
                .to_public_key()
                .map_err(|error| CliError::Other(error.to_string()))?,
        );
    }
    if public_keys.is_empty() {
        return Err(CliError::Other(format!(
            "portable issuer JWKS at `{jwks_url}` did not publish any keys"
        )));
    }
    Ok(public_keys)
}

fn resolve_oid4vp_passport_lifecycle(
    config: &TrustServiceConfig,
    passport_id: &str,
    status_ref: Option<&arc_credentials::Oid4vciArcPassportStatusReference>,
) -> Result<Option<PassportLifecycleResolution>, CliError> {
    if let Some(path) = config.passport_statuses_file.as_deref() {
        let registry = PassportStatusRegistry::load(path)?;
        return Ok(Some(registry.resolve_at(passport_id, unix_timestamp_now())));
    }
    let Some(status_ref) = status_ref else {
        return Ok(None);
    };
    let resolve_url = status_ref
        .distribution
        .resolve_urls
        .first()
        .cloned()
        .ok_or_else(|| {
            CliError::Other(
                "OID4VP passport status validation requires at least one resolve URL".to_string(),
            )
        })?;
    let url = format!(
        "{}/{}",
        resolve_url.trim_end_matches('/'),
        utf8_percent_encode(passport_id, NON_ALPHANUMERIC)
    );
    let response = ureq::get(&url).call().map_err(|error| match error {
        ureq::Error::Status(status, response) => {
            let body = response.into_string().unwrap_or_default();
            CliError::Other(format!(
                "failed to resolve portable passport lifecycle from `{url}` with status {status}: {body}"
            ))
        }
        ureq::Error::Transport(transport) => CliError::Other(format!(
            "failed to resolve portable passport lifecycle from `{url}`: {transport}"
        )),
    })?;
    let lifecycle: PassportLifecycleResolution = serde_json::from_reader(response.into_reader())
        .map_err(|error| {
            CliError::Other(format!(
                "failed to decode portable passport lifecycle from `{url}`: {error}"
            ))
        })?;
    lifecycle
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(Some(lifecycle))
}

fn build_enterprise_admission_audit(
    identity: &EnterpriseIdentityContext,
    subject_public_key: &str,
    provider: Option<&EnterpriseProviderRecord>,
) -> EnterpriseAdmissionAudit {
    EnterpriseAdmissionAudit {
        provider_id: identity.provider_id.clone(),
        provider_record_id: identity.provider_record_id.clone(),
        provider_kind: provider
            .map(|record| match &record.kind {
                crate::enterprise_federation::EnterpriseProviderKind::OidcJwks => "oidc_jwks",
                crate::enterprise_federation::EnterpriseProviderKind::OauthIntrospection => {
                    "oauth_introspection"
                }
                crate::enterprise_federation::EnterpriseProviderKind::Scim => "scim",
                crate::enterprise_federation::EnterpriseProviderKind::Saml => "saml",
            })
            .unwrap_or(identity.provider_kind.as_str())
            .to_string(),
        federation_method: match &identity.federation_method {
            arc_core::EnterpriseFederationMethod::Jwt => "jwt",
            arc_core::EnterpriseFederationMethod::Introspection => "introspection",
            arc_core::EnterpriseFederationMethod::Scim => "scim",
            arc_core::EnterpriseFederationMethod::Saml => "saml",
        }
        .to_string(),
        principal: identity.principal.clone(),
        subject_key: identity.subject_key.clone(),
        subject_public_key: subject_public_key.to_string(),
        tenant_id: identity.tenant_id.clone(),
        organization_id: identity.organization_id.clone(),
        groups: identity.groups.clone(),
        roles: identity.roles.clone(),
        attribute_sources: identity.attribute_sources.clone(),
        trust_material_ref: provider
            .and_then(|record| record.provenance.trust_material_ref.clone())
            .or_else(|| identity.trust_material_ref.clone()),
        matched_origin_profile: None,
        decision_reason: None,
    }
}

fn enterprise_origin_context(identity: &EnterpriseIdentityContext) -> arc_policy::OriginContext {
    arc_policy::OriginContext {
        provider: Some(identity.provider_id.clone()),
        tenant_id: identity.tenant_id.clone(),
        organization_id: identity.organization_id.clone(),
        space_id: None,
        space_type: None,
        visibility: None,
        external_participants: None,
        tags: Vec::new(),
        groups: identity.groups.clone(),
        roles: identity.roles.clone(),
        sensitivity: None,
        actor_role: None,
    }
}

fn enterprise_admission_response(
    status: StatusCode,
    message: &str,
    audit: &EnterpriseAdmissionAudit,
) -> Response {
    (
        status,
        Json(json!({
            "error": message,
            "enterpriseAudit": audit,
        })),
    )
        .into_response()
}

async fn serve_async(config: TrustServiceConfig) -> Result<(), CliError> {
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let enterprise_provider_registry = load_enterprise_provider_registry(
        config.enterprise_providers_file.as_deref(),
        "trust_control",
    )?;
    let verifier_policy_registry =
        load_verifier_policy_registry(config.verifier_policies_file.as_deref(), "trust_control")?;
    let cluster = build_cluster_state(&config, local_addr)?;
    let state = TrustServiceState {
        config,
        enterprise_provider_registry,
        verifier_policy_registry,
        cluster,
    };
    if state.cluster.is_some() {
        tokio::spawn(run_cluster_sync_loop(state.clone()));
    }
    let router = Router::new()
        .route(HEALTH_PATH, get(handle_health))
        .route(
            AUTHORITY_PATH,
            get(handle_authority_status).post(handle_rotate_authority),
        )
        .route(ISSUE_CAPABILITY_PATH, post(handle_issue_capability))
        .route(FEDERATED_ISSUE_PATH, post(handle_federated_issue))
        .route(
            FEDERATION_PROVIDERS_PATH,
            get(handle_list_enterprise_providers),
        )
        .route(
            FEDERATION_PROVIDER_PATH,
            get(handle_get_enterprise_provider)
                .put(handle_upsert_enterprise_provider)
                .delete(handle_delete_enterprise_provider),
        )
        .route(
            CERTIFICATIONS_PATH,
            get(handle_list_certifications).post(handle_publish_certification),
        )
        .route(CERTIFICATION_PATH, get(handle_get_certification))
        .route(
            CERTIFICATION_RESOLVE_PATH,
            get(handle_resolve_certification),
        )
        .route(
            CERTIFICATION_DISCOVERY_PATH,
            post(handle_publish_certification_network),
        )
        .route(
            CERTIFICATION_DISCOVERY_RESOLVE_PATH,
            get(handle_discover_certification),
        )
        .route(
            CERTIFICATION_DISCOVERY_SEARCH_PATH,
            get(handle_search_certification_marketplace),
        )
        .route(
            CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH,
            get(handle_transparency_certification_marketplace),
        )
        .route(
            CERTIFICATION_DISCOVERY_CONSUME_PATH,
            post(handle_consume_certification_marketplace),
        )
        .route(CERTIFICATION_REVOKE_PATH, post(handle_revoke_certification))
        .route(
            CERTIFICATION_DISPUTE_PATH,
            post(handle_dispute_certification),
        )
        .route(
            PUBLIC_CERTIFICATION_METADATA_PATH,
            get(handle_public_certification_metadata),
        )
        .route(
            PUBLIC_CERTIFICATION_RESOLVE_PATH,
            get(handle_public_resolve_certification),
        )
        .route(
            PUBLIC_CERTIFICATION_SEARCH_PATH,
            get(handle_public_search_certifications),
        )
        .route(
            PUBLIC_CERTIFICATION_TRANSPARENCY_PATH,
            get(handle_public_certification_transparency),
        )
        .route(
            PASSPORT_ISSUER_METADATA_PATH,
            get(handle_passport_issuer_metadata),
        )
        .route(PASSPORT_ISSUER_JWKS_PATH, get(handle_passport_issuer_jwks))
        .route(
            PASSPORT_SD_JWT_TYPE_METADATA_PATH,
            get(handle_passport_sd_jwt_type_metadata),
        )
        .route(
            ARC_PASSPORT_JWT_VC_JSON_TYPE_METADATA_PATH,
            get(handle_passport_jwt_vc_json_type_metadata),
        )
        .route(
            PASSPORT_ISSUANCE_OFFERS_PATH,
            post(handle_create_passport_issuance_offer),
        )
        .route(
            PASSPORT_ISSUANCE_TOKEN_PATH,
            post(handle_redeem_passport_issuance_token),
        )
        .route(
            PASSPORT_ISSUANCE_CREDENTIAL_PATH,
            post(handle_redeem_passport_issuance_credential),
        )
        .route(
            PASSPORT_STATUSES_PATH,
            get(handle_list_passport_statuses).post(handle_publish_passport_status),
        )
        .route(PASSPORT_STATUS_PATH, get(handle_get_passport_status))
        .route(
            PASSPORT_STATUS_RESOLVE_PATH,
            get(handle_resolve_passport_status),
        )
        .route(
            PUBLIC_PASSPORT_STATUS_RESOLVE_PATH,
            get(handle_public_resolve_passport_status),
        )
        .route(
            PASSPORT_STATUS_REVOKE_PATH,
            post(handle_revoke_passport_status),
        )
        .route(
            PASSPORT_VERIFIER_POLICIES_PATH,
            get(handle_list_verifier_policies),
        )
        .route(
            PASSPORT_VERIFIER_POLICY_PATH,
            get(handle_get_verifier_policy)
                .put(handle_upsert_verifier_policy)
                .delete(handle_delete_verifier_policy),
        )
        .route(
            PASSPORT_CHALLENGES_PATH,
            post(handle_create_passport_challenge),
        )
        .route(
            PASSPORT_CHALLENGE_VERIFY_PATH,
            post(handle_verify_passport_challenge),
        )
        .route(
            PUBLIC_PASSPORT_CHALLENGE_PATH,
            get(handle_public_get_passport_challenge),
        )
        .route(
            PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH,
            post(handle_public_verify_passport_challenge),
        )
        .route(
            OID4VP_VERIFIER_METADATA_PATH,
            get(handle_oid4vp_verifier_metadata),
        )
        .route(
            PASSPORT_OID4VP_REQUESTS_PATH,
            post(handle_create_oid4vp_request),
        )
        .route(
            PUBLIC_PASSPORT_WALLET_EXCHANGE_PATH,
            get(handle_public_get_wallet_exchange),
        )
        .route(
            PUBLIC_PASSPORT_OID4VP_REQUEST_PATH,
            get(handle_public_get_oid4vp_request),
        )
        .route(
            PUBLIC_PASSPORT_OID4VP_LAUNCH_PATH,
            get(handle_public_launch_oid4vp_request),
        )
        .route(
            PUBLIC_PASSPORT_OID4VP_DIRECT_POST_PATH,
            post(handle_public_submit_oid4vp_response),
        )
        .route(
            REVOCATIONS_PATH,
            get(handle_list_revocations).post(handle_revoke_capability),
        )
        .route(
            TOOL_RECEIPTS_PATH,
            get(handle_list_tool_receipts).post(handle_append_tool_receipt),
        )
        .route(
            CHILD_RECEIPTS_PATH,
            get(handle_list_child_receipts).post(handle_append_child_receipt),
        )
        .route(BUDGETS_PATH, get(handle_list_budgets))
        .route(BUDGET_INCREMENT_PATH, post(handle_try_increment_budget))
        .route(BUDGET_CHARGE_PATH, post(handle_try_charge_cost))
        .route(BUDGET_REVERSE_PATH, post(handle_reverse_charge_cost))
        .route(BUDGET_REDUCE_PATH, post(handle_reduce_charge_cost))
        .route(
            INTERNAL_CLUSTER_STATUS_PATH,
            get(handle_internal_cluster_status),
        )
        .route(
            INTERNAL_AUTHORITY_SNAPSHOT_PATH,
            get(handle_internal_authority_snapshot),
        )
        .route(
            INTERNAL_REVOCATIONS_DELTA_PATH,
            get(handle_internal_revocations_delta),
        )
        .route(
            INTERNAL_TOOL_RECEIPTS_DELTA_PATH,
            get(handle_internal_tool_receipts_delta),
        )
        .route(
            INTERNAL_CHILD_RECEIPTS_DELTA_PATH,
            get(handle_internal_child_receipts_delta),
        )
        .route(
            INTERNAL_BUDGETS_DELTA_PATH,
            get(handle_internal_budgets_delta),
        )
        .route(
            INTERNAL_LINEAGE_DELTA_PATH,
            get(handle_internal_lineage_delta),
        )
        .route(RECEIPT_QUERY_PATH, get(handle_query_receipts))
        .route(RECEIPT_ANALYTICS_PATH, get(handle_receipt_analytics))
        .route(EVIDENCE_EXPORT_PATH, post(handle_evidence_export))
        .route(EVIDENCE_IMPORT_PATH, post(handle_evidence_import))
        .route(
            FEDERATION_EVIDENCE_SHARES_PATH,
            get(handle_shared_evidence_report),
        )
        .route(COST_ATTRIBUTION_PATH, get(handle_cost_attribution_report))
        .route(OPERATOR_REPORT_PATH, get(handle_operator_report))
        .route(
            RUNTIME_ATTESTATION_APPRAISAL_PATH,
            post(handle_runtime_attestation_appraisal_report),
        )
        .route(BEHAVIORAL_FEED_PATH, get(handle_behavioral_feed_report))
        .route(EXPOSURE_LEDGER_PATH, get(handle_exposure_ledger_report))
        .route(CREDIT_SCORECARD_PATH, get(handle_credit_scorecard_report))
        .route(
            CREDIT_FACILITY_REPORT_PATH,
            get(handle_credit_facility_report),
        )
        .route(
            CREDIT_FACILITY_ISSUE_PATH,
            post(handle_issue_credit_facility),
        )
        .route(
            CREDIT_FACILITIES_REPORT_PATH,
            get(handle_query_credit_facilities),
        )
        .route(CREDIT_BOND_REPORT_PATH, get(handle_credit_bond_report))
        .route(CREDIT_BOND_ISSUE_PATH, post(handle_issue_credit_bond))
        .route(CREDIT_BONDS_REPORT_PATH, get(handle_query_credit_bonds))
        .route(
            CREDIT_BONDED_EXECUTION_SIMULATION_PATH,
            post(handle_credit_bonded_execution_simulation_report),
        )
        .route(
            CREDIT_LOSS_LIFECYCLE_REPORT_PATH,
            get(handle_credit_loss_lifecycle_report),
        )
        .route(
            CREDIT_LOSS_LIFECYCLE_ISSUE_PATH,
            post(handle_issue_credit_loss_lifecycle),
        )
        .route(
            CREDIT_LOSS_LIFECYCLE_LIST_PATH,
            get(handle_query_credit_loss_lifecycle),
        )
        .route(CREDIT_BACKTEST_PATH, get(handle_credit_backtest_report))
        .route(
            CREDIT_PROVIDER_RISK_PACKAGE_PATH,
            get(handle_credit_provider_risk_package_report),
        )
        .route(
            LIABILITY_PROVIDER_ISSUE_PATH,
            post(handle_issue_liability_provider),
        )
        .route(
            LIABILITY_PROVIDERS_REPORT_PATH,
            get(handle_query_liability_providers),
        )
        .route(
            LIABILITY_PROVIDER_RESOLVE_PATH,
            get(handle_resolve_liability_provider),
        )
        .route(
            LIABILITY_QUOTE_REQUEST_ISSUE_PATH,
            post(handle_issue_liability_quote_request),
        )
        .route(
            LIABILITY_QUOTE_RESPONSE_ISSUE_PATH,
            post(handle_issue_liability_quote_response),
        )
        .route(
            LIABILITY_PLACEMENT_ISSUE_PATH,
            post(handle_issue_liability_placement),
        )
        .route(
            LIABILITY_BOUND_COVERAGE_ISSUE_PATH,
            post(handle_issue_liability_bound_coverage),
        )
        .route(
            LIABILITY_MARKET_WORKFLOW_REPORT_PATH,
            get(handle_query_liability_market_workflows),
        )
        .route(
            LIABILITY_CLAIM_PACKAGE_ISSUE_PATH,
            post(handle_issue_liability_claim_package),
        )
        .route(
            LIABILITY_CLAIM_RESPONSE_ISSUE_PATH,
            post(handle_issue_liability_claim_response),
        )
        .route(
            LIABILITY_CLAIM_DISPUTE_ISSUE_PATH,
            post(handle_issue_liability_claim_dispute),
        )
        .route(
            LIABILITY_CLAIM_ADJUDICATION_ISSUE_PATH,
            post(handle_issue_liability_claim_adjudication),
        )
        .route(
            LIABILITY_CLAIM_WORKFLOW_REPORT_PATH,
            get(handle_query_liability_claim_workflows),
        )
        .route(SETTLEMENT_REPORT_PATH, get(handle_settlement_report))
        .route(
            SETTLEMENT_RECONCILE_PATH,
            post(handle_record_settlement_reconciliation),
        )
        .route(
            METERED_BILLING_REPORT_PATH,
            get(handle_metered_billing_report),
        )
        .route(
            METERED_BILLING_RECONCILE_PATH,
            post(handle_record_metered_billing_reconciliation),
        )
        .route(
            AUTHORIZATION_CONTEXT_REPORT_PATH,
            get(handle_authorization_context_report),
        )
        .route(
            AUTHORIZATION_PROFILE_METADATA_PATH,
            get(handle_authorization_profile_metadata_report),
        )
        .route(
            AUTHORIZATION_REVIEW_PACK_PATH,
            get(handle_authorization_review_pack_report),
        )
        .route(
            UNDERWRITING_INPUT_PATH,
            get(handle_underwriting_policy_input),
        )
        .route(
            UNDERWRITING_DECISION_PATH,
            get(handle_underwriting_decision_report),
        )
        .route(
            UNDERWRITING_SIMULATION_PATH,
            post(handle_underwriting_simulation_report),
        )
        .route(
            UNDERWRITING_DECISIONS_REPORT_PATH,
            get(handle_query_underwriting_decisions),
        )
        .route(
            UNDERWRITING_DECISION_ISSUE_PATH,
            post(handle_issue_underwriting_decision),
        )
        .route(
            UNDERWRITING_APPEALS_PATH,
            post(handle_create_underwriting_appeal),
        )
        .route(
            UNDERWRITING_APPEAL_RESOLVE_PATH,
            post(handle_resolve_underwriting_appeal),
        )
        .route(LOCAL_REPUTATION_PATH, get(handle_local_reputation))
        .route(REPUTATION_COMPARE_PATH, post(handle_reputation_compare))
        .route(LINEAGE_RECORD_PATH, post(handle_record_lineage_snapshot))
        .route(LINEAGE_PATH, get(handle_get_lineage))
        .route(LINEAGE_CHAIN_PATH, get(handle_get_delegation_chain))
        .route(AGENT_RECEIPTS_PATH, get(handle_agent_receipts));

    // Wire the dashboard SPA after all API routes so it acts as a catch-all.
    // API routes registered above take priority over the fallback service.
    // The conditional avoids a hard startup failure when the dashboard has not
    // been built (e.g. in CI or API-only deployments).
    let dashboard_dir = std::path::Path::new(DASHBOARD_DIST_DIR);
    let router = if dashboard_dir.join("index.html").exists() {
        let spa_fallback = ServeFile::new(dashboard_dir.join("index.html"));
        let spa_service = ServeDir::new(dashboard_dir).not_found_service(spa_fallback);
        router.fallback_service(spa_service)
    } else {
        warn!(
            "dashboard/dist/index.html not found -- dashboard UI will not be served. \
             Run 'npm run build' in crates/arc-cli/dashboard/ to enable."
        );
        router
    };

    let router = router.with_state(state);

    // Dashboard SPA is served from the same origin via ServeDir -- no CORS
    // headers needed. If the dashboard is ever served from a separate origin,
    // add tower-http CorsLayer.

    // Apply Content-Security-Policy to every response to restrict resource
    // loading to same-origin and prevent XSS escalation.
    let csp_value = HeaderValue::from_static(CSP_VALUE);
    let router = router.layer(SetResponseHeaderLayer::overriding(
        axum::http::header::CONTENT_SECURITY_POLICY,
        csp_value,
    ));

    info!(listen_addr = %local_addr, "serving ARC trust control service");
    eprintln!("ARC trust control service listening on http://{local_addr}");

    axum::serve(listener, router)
        .await
        .map_err(|error| CliError::Other(format!("trust control service failed: {error}")))
}

pub fn build_client(
    control_url: &str,
    control_token: &str,
) -> Result<TrustControlClient, CliError> {
    let endpoints = control_url
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_end_matches('/').to_string())
        .collect::<Vec<_>>();
    if endpoints.is_empty() {
        return Err(CliError::Other("control URL must not be empty".to_string()));
    }
    let http = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    Ok(TrustControlClient {
        endpoints: Arc::new(endpoints),
        preferred_index: Arc::new(Mutex::new(0)),
        token: Arc::<str>::from(control_token.to_string()),
        http,
    })
}

fn encode_path_segment(segment: &str) -> String {
    utf8_percent_encode(segment, NON_ALPHANUMERIC).to_string()
}

fn path_with_encoded_param(template: &str, param_name: &str, value: &str) -> String {
    template.replace(&format!("{{{param_name}}}"), &encode_path_segment(value))
}

pub fn resolve_public_certification(
    registry_url: &str,
    tool_server_id: &str,
) -> Result<CertificationResolutionResponse, CliError> {
    let endpoint = registry_url.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(CliError::Other(
            "public certification registry URL must not be empty".to_string(),
        ));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    let path = path_with_encoded_param(
        PUBLIC_CERTIFICATION_RESOLVE_PATH,
        "tool_server_id",
        tool_server_id,
    );
    let response = agent
        .get(&format!("{endpoint}{path}"))
        .call()
        .map_err(|error| {
            CliError::Other(format!(
                "failed to query public certification registry {endpoint}: {error}"
            ))
        })?;
    response.into_json().map_err(|error| {
        CliError::Other(format!(
            "failed to parse public certification response from {endpoint}: {error}"
        ))
    })
}

pub fn resolve_public_certification_metadata(
    registry_url: &str,
) -> Result<CertificationPublicMetadata, CliError> {
    public_certification_get_json(registry_url, PUBLIC_CERTIFICATION_METADATA_PATH)
}

pub fn search_public_certifications(
    registry_url: &str,
    query: &CertificationPublicSearchQuery,
) -> Result<CertificationPublicSearchResponse, CliError> {
    public_certification_get_json_with_query(registry_url, PUBLIC_CERTIFICATION_SEARCH_PATH, query)
}

pub fn resolve_public_certification_transparency(
    registry_url: &str,
    query: &CertificationTransparencyQuery,
) -> Result<CertificationTransparencyResponse, CliError> {
    public_certification_get_json_with_query(
        registry_url,
        PUBLIC_CERTIFICATION_TRANSPARENCY_PATH,
        query,
    )
}

fn public_certification_get_json<T: for<'de> Deserialize<'de>>(
    registry_url: &str,
    path: &str,
) -> Result<T, CliError> {
    let endpoint = registry_url.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(CliError::Other(
            "public certification registry URL must not be empty".to_string(),
        ));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    let response = agent
        .get(&format!("{endpoint}{path}"))
        .call()
        .map_err(|error| {
            CliError::Other(format!(
                "failed to query public certification registry {endpoint}: {error}"
            ))
        })?;
    response.into_json().map_err(|error| {
        CliError::Other(format!(
            "failed to parse public certification response from {endpoint}: {error}"
        ))
    })
}

fn public_certification_get_json_with_query<Q: Serialize, T: for<'de> Deserialize<'de>>(
    registry_url: &str,
    path: &str,
    query: &Q,
) -> Result<T, CliError> {
    let endpoint = registry_url.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return Err(CliError::Other(
            "public certification registry URL must not be empty".to_string(),
        ));
    }
    let encoded_query = serde_urlencoded::to_string(query).map_err(|error| {
        CliError::Other(format!(
            "failed to encode public certification query: {error}"
        ))
    })?;
    let url = if encoded_query.is_empty() {
        format!("{endpoint}{path}")
    } else {
        format!("{endpoint}{path}?{encoded_query}")
    };
    let agent = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .build();
    let response = agent.get(&url).call().map_err(|error| {
        CliError::Other(format!(
            "failed to query public certification registry {endpoint}: {error}"
        ))
    })?;
    response.into_json().map_err(|error| {
        CliError::Other(format!(
            "failed to parse public certification response from {endpoint}: {error}"
        ))
    })
}

pub fn build_remote_receipt_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn ReceiptStore>, CliError> {
    Ok(Box::new(RemoteReceiptStore {
        client: build_client(control_url, control_token)?,
    }))
}

pub fn build_remote_budget_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn BudgetStore>, CliError> {
    Ok(Box::new(RemoteBudgetStore {
        client: build_client(control_url, control_token)?,
    }))
}

pub fn build_remote_revocation_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn RevocationStore>, CliError> {
    Ok(Box::new(RemoteRevocationStore {
        client: build_client(control_url, control_token)?,
    }))
}

pub fn build_remote_capability_authority(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn CapabilityAuthority>, CliError> {
    let client = build_client(control_url, control_token)?;
    let status = client.authority_status()?;
    let cache = AuthorityKeyCache::from_status(&status)?;
    Ok(Box::new(RemoteCapabilityAuthority {
        client,
        cache: Mutex::new(cache),
    }))
}

impl TrustControlClient {
    pub fn authority_status(&self) -> Result<TrustAuthorityStatus, CliError> {
        self.get_json(AUTHORITY_PATH)
    }

    pub fn rotate_authority(&self) -> Result<TrustAuthorityStatus, CliError> {
        self.post_json::<Value, TrustAuthorityStatus>(AUTHORITY_PATH, &json!({}))
    }

    pub fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ArcScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, CliError> {
        self.issue_capability_with_attestation(subject, scope, ttl_seconds, None)
    }

    pub fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ArcScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, CliError> {
        let response: IssueCapabilityResponse = self.post_json(
            ISSUE_CAPABILITY_PATH,
            &IssueCapabilityRequest {
                subject_public_key: subject.to_hex(),
                scope,
                ttl_seconds,
                runtime_attestation,
            },
        )?;
        Ok(response.capability)
    }

    pub fn federated_issue(
        &self,
        request: &FederatedIssueRequest,
    ) -> Result<FederatedIssueResponse, CliError> {
        self.post_json(FEDERATED_ISSUE_PATH, request)
    }

    pub fn list_enterprise_providers(&self) -> Result<EnterpriseProviderListResponse, CliError> {
        self.get_json(FEDERATION_PROVIDERS_PATH)
    }

    pub fn get_enterprise_provider(
        &self,
        provider_id: &str,
    ) -> Result<EnterpriseProviderRecord, CliError> {
        self.get_json(&path_with_encoded_param(
            FEDERATION_PROVIDER_PATH,
            "provider_id",
            provider_id,
        ))
    }

    pub fn upsert_enterprise_provider(
        &self,
        provider_id: &str,
        record: &EnterpriseProviderRecord,
    ) -> Result<EnterpriseProviderRecord, CliError> {
        self.put_json(
            &path_with_encoded_param(FEDERATION_PROVIDER_PATH, "provider_id", provider_id),
            record,
        )
    }

    pub fn delete_enterprise_provider(
        &self,
        provider_id: &str,
    ) -> Result<EnterpriseProviderDeleteResponse, CliError> {
        self.delete_json(&path_with_encoded_param(
            FEDERATION_PROVIDER_PATH,
            "provider_id",
            provider_id,
        ))
    }

    pub fn list_certifications(&self) -> Result<CertificationRegistryListResponse, CliError> {
        self.get_json(CERTIFICATIONS_PATH)
    }

    pub fn get_certification(
        &self,
        artifact_id: &str,
    ) -> Result<CertificationRegistryEntry, CliError> {
        self.get_json(&path_with_encoded_param(
            CERTIFICATION_PATH,
            "artifact_id",
            artifact_id,
        ))
    }

    pub fn publish_certification(
        &self,
        artifact: &SignedCertificationCheck,
    ) -> Result<CertificationRegistryEntry, CliError> {
        self.post_json(CERTIFICATIONS_PATH, artifact)
    }

    pub fn resolve_certification(
        &self,
        tool_server_id: &str,
    ) -> Result<CertificationResolutionResponse, CliError> {
        self.get_json(&path_with_encoded_param(
            CERTIFICATION_RESOLVE_PATH,
            "tool_server_id",
            tool_server_id,
        ))
    }

    pub fn discover_certification(
        &self,
        tool_server_id: &str,
    ) -> Result<CertificationDiscoveryResponse, CliError> {
        self.get_json(&path_with_encoded_param(
            CERTIFICATION_DISCOVERY_RESOLVE_PATH,
            "tool_server_id",
            tool_server_id,
        ))
    }

    pub fn publish_certification_network(
        &self,
        request: &CertificationNetworkPublishRequest,
    ) -> Result<CertificationNetworkPublishResponse, CliError> {
        self.post_json("/v1/certifications/discovery/publish", request)
    }

    pub fn search_certification_marketplace(
        &self,
        query: &CertificationMarketplaceSearchQuery,
    ) -> Result<CertificationPublicSearchResponse, CliError> {
        self.get_json(&certification_marketplace_search_path(query))
    }

    pub fn certification_marketplace_transparency(
        &self,
        query: &CertificationMarketplaceTransparencyQuery,
    ) -> Result<CertificationTransparencyResponse, CliError> {
        self.get_json(&certification_marketplace_transparency_path(query))
    }

    pub fn consume_certification_marketplace(
        &self,
        request: &CertificationConsumptionRequest,
    ) -> Result<CertificationConsumptionResponse, CliError> {
        self.post_json(CERTIFICATION_DISCOVERY_CONSUME_PATH, request)
    }

    pub fn revoke_certification(
        &self,
        artifact_id: &str,
        request: &CertificationRevocationRequest,
    ) -> Result<CertificationRegistryEntry, CliError> {
        self.post_json(
            &path_with_encoded_param(CERTIFICATION_REVOKE_PATH, "artifact_id", artifact_id),
            request,
        )
    }

    pub fn dispute_certification(
        &self,
        artifact_id: &str,
        request: &CertificationDisputeRequest,
    ) -> Result<CertificationRegistryEntry, CliError> {
        self.post_json(
            &path_with_encoded_param(CERTIFICATION_DISPUTE_PATH, "artifact_id", artifact_id),
            request,
        )
    }

    pub fn list_passport_statuses(&self) -> Result<PassportStatusListResponse, CliError> {
        self.get_json(PASSPORT_STATUSES_PATH)
    }

    pub fn passport_issuer_metadata(&self) -> Result<Oid4vciCredentialIssuerMetadata, CliError> {
        self.public_get_json(PASSPORT_ISSUER_METADATA_PATH)
    }

    pub fn create_passport_issuance_offer(
        &self,
        request: &CreatePassportIssuanceOfferRequest,
    ) -> Result<PassportIssuanceOfferRecord, CliError> {
        self.post_json(PASSPORT_ISSUANCE_OFFERS_PATH, request)
    }

    pub fn redeem_passport_issuance_token(
        &self,
        request: &Oid4vciTokenRequest,
    ) -> Result<Oid4vciTokenResponse, CliError> {
        self.public_post_json(PASSPORT_ISSUANCE_TOKEN_PATH, request)
    }

    pub fn redeem_passport_issuance_credential(
        &self,
        access_token: &str,
        request: &Oid4vciCredentialRequest,
    ) -> Result<Oid4vciCredentialResponse, CliError> {
        self.bearer_post_json(PASSPORT_ISSUANCE_CREDENTIAL_PATH, access_token, request)
    }

    pub fn get_passport_status(
        &self,
        passport_id: &str,
    ) -> Result<PassportLifecycleRecord, CliError> {
        self.get_json(&path_with_encoded_param(
            PASSPORT_STATUS_PATH,
            "passport_id",
            passport_id,
        ))
    }

    pub fn publish_passport_status(
        &self,
        request: &PublishPassportStatusRequest,
    ) -> Result<PassportLifecycleRecord, CliError> {
        self.post_json(PASSPORT_STATUSES_PATH, request)
    }

    pub fn resolve_passport_status(
        &self,
        passport_id: &str,
    ) -> Result<PassportLifecycleResolution, CliError> {
        self.get_json(&path_with_encoded_param(
            PASSPORT_STATUS_RESOLVE_PATH,
            "passport_id",
            passport_id,
        ))
    }

    pub fn public_resolve_passport_status(
        &self,
        passport_id: &str,
    ) -> Result<PassportLifecycleResolution, CliError> {
        self.public_get_json(&path_with_encoded_param(
            PUBLIC_PASSPORT_STATUS_RESOLVE_PATH,
            "passport_id",
            passport_id,
        ))
    }

    pub fn revoke_passport_status(
        &self,
        passport_id: &str,
        request: &PassportStatusRevocationRequest,
    ) -> Result<PassportLifecycleRecord, CliError> {
        self.post_json(
            &path_with_encoded_param(PASSPORT_STATUS_REVOKE_PATH, "passport_id", passport_id),
            request,
        )
    }

    pub fn list_verifier_policies(&self) -> Result<VerifierPolicyListResponse, CliError> {
        self.get_json(PASSPORT_VERIFIER_POLICIES_PATH)
    }

    pub fn get_verifier_policy(
        &self,
        policy_id: &str,
    ) -> Result<SignedPassportVerifierPolicy, CliError> {
        self.get_json(&path_with_encoded_param(
            PASSPORT_VERIFIER_POLICY_PATH,
            "policy_id",
            policy_id,
        ))
    }

    pub fn upsert_verifier_policy(
        &self,
        policy_id: &str,
        document: &SignedPassportVerifierPolicy,
    ) -> Result<SignedPassportVerifierPolicy, CliError> {
        self.put_json(
            &path_with_encoded_param(PASSPORT_VERIFIER_POLICY_PATH, "policy_id", policy_id),
            document,
        )
    }

    pub fn delete_verifier_policy(
        &self,
        policy_id: &str,
    ) -> Result<VerifierPolicyDeleteResponse, CliError> {
        self.delete_json(&path_with_encoded_param(
            PASSPORT_VERIFIER_POLICY_PATH,
            "policy_id",
            policy_id,
        ))
    }

    pub fn create_passport_challenge(
        &self,
        request: &CreatePassportChallengeRequest,
    ) -> Result<CreatePassportChallengeResponse, CliError> {
        self.post_json(PASSPORT_CHALLENGES_PATH, request)
    }

    pub fn verify_passport_challenge(
        &self,
        request: &VerifyPassportChallengeRequest,
    ) -> Result<PassportPresentationVerification, CliError> {
        self.post_json(PASSPORT_CHALLENGE_VERIFY_PATH, request)
    }

    pub fn public_get_passport_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<PassportPresentationChallenge, CliError> {
        self.public_get_json(&path_with_encoded_param(
            PUBLIC_PASSPORT_CHALLENGE_PATH,
            "challenge_id",
            challenge_id,
        ))
    }

    pub fn public_verify_passport_challenge(
        &self,
        request: &VerifyPassportChallengeRequest,
    ) -> Result<PassportPresentationVerification, CliError> {
        self.public_post_json(PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH, request)
    }

    pub fn create_oid4vp_request(
        &self,
        request: &CreateOid4vpRequest,
    ) -> Result<CreateOid4vpRequestResponse, CliError> {
        self.post_json(PASSPORT_OID4VP_REQUESTS_PATH, request)
    }

    pub fn public_get_oid4vp_request(&self, request_id: &str) -> Result<String, CliError> {
        self.public_get_text(&path_with_encoded_param(
            PUBLIC_PASSPORT_OID4VP_REQUEST_PATH,
            "request_id",
            request_id,
        ))
    }

    pub fn public_get_wallet_exchange(
        &self,
        request_id: &str,
    ) -> Result<WalletExchangeStatusResponse, CliError> {
        self.public_get_json(&path_with_encoded_param(
            PUBLIC_PASSPORT_WALLET_EXCHANGE_PATH,
            "request_id",
            request_id,
        ))
    }

    pub fn public_submit_oid4vp_response(
        &self,
        response_jwt: &str,
    ) -> Result<Oid4vpPresentationVerification, CliError> {
        self.public_post_form(
            PUBLIC_PASSPORT_OID4VP_DIRECT_POST_PATH,
            &[("response", response_jwt)],
        )
    }

    pub fn list_revocations(
        &self,
        query: &RevocationQuery,
    ) -> Result<RevocationListResponse, CliError> {
        self.get_json_with_query(REVOCATIONS_PATH, query)
    }

    pub fn revoke_capability(
        &self,
        capability_id: &str,
    ) -> Result<RevokeCapabilityResponse, CliError> {
        self.post_json(
            REVOCATIONS_PATH,
            &RevokeCapabilityRequest {
                capability_id: capability_id.to_string(),
            },
        )
    }

    pub fn list_tool_receipts(
        &self,
        query: &ToolReceiptQuery,
    ) -> Result<ReceiptListResponse, CliError> {
        self.get_json_with_query(TOOL_RECEIPTS_PATH, query)
    }

    pub fn list_child_receipts(
        &self,
        query: &ChildReceiptQuery,
    ) -> Result<ReceiptListResponse, CliError> {
        self.get_json_with_query(CHILD_RECEIPTS_PATH, query)
    }

    pub fn query_receipts(
        &self,
        query: &ReceiptQueryHttpQuery,
    ) -> Result<ReceiptQueryResponse, CliError> {
        self.get_json_with_query(RECEIPT_QUERY_PATH, query)
    }

    pub fn export_evidence(
        &self,
        request: &evidence_export::RemoteEvidenceExportRequest,
    ) -> Result<evidence_export::RemoteEvidenceExportResponse, CliError> {
        self.post_json(EVIDENCE_EXPORT_PATH, request)
    }

    pub fn import_evidence(
        &self,
        request: &evidence_export::RemoteEvidenceImportRequest,
    ) -> Result<evidence_export::RemoteEvidenceImportResponse, CliError> {
        self.post_json(EVIDENCE_IMPORT_PATH, request)
    }

    pub fn shared_evidence_report(
        &self,
        query: &SharedEvidenceQuery,
    ) -> Result<SharedEvidenceReferenceReport, CliError> {
        self.get_json_with_query(FEDERATION_EVIDENCE_SHARES_PATH, query)
    }

    #[allow(dead_code)]
    pub fn cost_attribution_report(
        &self,
        query: &CostAttributionQuery,
    ) -> Result<CostAttributionReport, CliError> {
        self.get_json_with_query(COST_ATTRIBUTION_PATH, query)
    }

    #[allow(dead_code)]
    pub fn operator_report(&self, query: &OperatorReportQuery) -> Result<OperatorReport, CliError> {
        self.get_json_with_query(OPERATOR_REPORT_PATH, query)
    }

    pub fn behavioral_feed(
        &self,
        query: &BehavioralFeedQuery,
    ) -> Result<SignedBehavioralFeed, CliError> {
        self.get_json_with_query(BEHAVIORAL_FEED_PATH, query)
    }

    pub fn exposure_ledger(
        &self,
        query: &ExposureLedgerQuery,
    ) -> Result<SignedExposureLedgerReport, CliError> {
        self.get_json_with_query(EXPOSURE_LEDGER_PATH, query)
    }

    pub fn credit_scorecard(
        &self,
        query: &ExposureLedgerQuery,
    ) -> Result<SignedCreditScorecardReport, CliError> {
        self.get_json_with_query(CREDIT_SCORECARD_PATH, query)
    }

    pub fn credit_facility_report(
        &self,
        query: &ExposureLedgerQuery,
    ) -> Result<CreditFacilityReport, CliError> {
        self.get_json_with_query(CREDIT_FACILITY_REPORT_PATH, query)
    }

    pub fn issue_credit_facility(
        &self,
        request: &CreditFacilityIssueRequest,
    ) -> Result<SignedCreditFacility, CliError> {
        self.post_json(CREDIT_FACILITY_ISSUE_PATH, request)
    }

    pub fn list_credit_facilities(
        &self,
        query: &CreditFacilityListQuery,
    ) -> Result<CreditFacilityListReport, CliError> {
        self.get_json_with_query(CREDIT_FACILITIES_REPORT_PATH, query)
    }

    pub fn credit_bond_report(
        &self,
        query: &ExposureLedgerQuery,
    ) -> Result<CreditBondReport, CliError> {
        self.get_json_with_query(CREDIT_BOND_REPORT_PATH, query)
    }

    pub fn issue_credit_bond(
        &self,
        request: &CreditBondIssueRequest,
    ) -> Result<SignedCreditBond, CliError> {
        self.post_json(CREDIT_BOND_ISSUE_PATH, request)
    }

    pub fn list_credit_bonds(
        &self,
        query: &CreditBondListQuery,
    ) -> Result<CreditBondListReport, CliError> {
        self.get_json_with_query(CREDIT_BONDS_REPORT_PATH, query)
    }

    pub fn simulate_credit_bonded_execution(
        &self,
        request: &CreditBondedExecutionSimulationRequest,
    ) -> Result<CreditBondedExecutionSimulationReport, CliError> {
        self.post_json(CREDIT_BONDED_EXECUTION_SIMULATION_PATH, request)
    }

    pub fn credit_loss_lifecycle_report(
        &self,
        query: &CreditLossLifecycleQuery,
    ) -> Result<CreditLossLifecycleReport, CliError> {
        self.get_json_with_query(CREDIT_LOSS_LIFECYCLE_REPORT_PATH, query)
    }

    pub fn issue_credit_loss_lifecycle(
        &self,
        request: &CreditLossLifecycleIssueRequest,
    ) -> Result<SignedCreditLossLifecycle, CliError> {
        self.post_json(CREDIT_LOSS_LIFECYCLE_ISSUE_PATH, request)
    }

    pub fn list_credit_loss_lifecycle(
        &self,
        query: &CreditLossLifecycleListQuery,
    ) -> Result<CreditLossLifecycleListReport, CliError> {
        self.get_json_with_query(CREDIT_LOSS_LIFECYCLE_LIST_PATH, query)
    }

    pub fn credit_backtest(
        &self,
        query: &CreditBacktestQuery,
    ) -> Result<CreditBacktestReport, CliError> {
        self.get_json_with_query(CREDIT_BACKTEST_PATH, query)
    }

    pub fn credit_provider_risk_package(
        &self,
        query: &CreditProviderRiskPackageQuery,
    ) -> Result<SignedCreditProviderRiskPackage, CliError> {
        self.get_json_with_query(CREDIT_PROVIDER_RISK_PACKAGE_PATH, query)
    }

    pub fn issue_liability_provider(
        &self,
        request: &LiabilityProviderIssueRequest,
    ) -> Result<SignedLiabilityProvider, CliError> {
        self.post_json(LIABILITY_PROVIDER_ISSUE_PATH, request)
    }

    pub fn list_liability_providers(
        &self,
        query: &LiabilityProviderListQuery,
    ) -> Result<LiabilityProviderListReport, CliError> {
        self.get_json_with_query(LIABILITY_PROVIDERS_REPORT_PATH, query)
    }

    pub fn resolve_liability_provider(
        &self,
        query: &LiabilityProviderResolutionQuery,
    ) -> Result<LiabilityProviderResolutionReport, CliError> {
        self.get_json_with_query(LIABILITY_PROVIDER_RESOLVE_PATH, query)
    }

    pub fn issue_liability_quote_request(
        &self,
        request: &LiabilityQuoteRequestIssueRequest,
    ) -> Result<SignedLiabilityQuoteRequest, CliError> {
        self.post_json(LIABILITY_QUOTE_REQUEST_ISSUE_PATH, request)
    }

    pub fn issue_liability_quote_response(
        &self,
        request: &LiabilityQuoteResponseIssueRequest,
    ) -> Result<SignedLiabilityQuoteResponse, CliError> {
        self.post_json(LIABILITY_QUOTE_RESPONSE_ISSUE_PATH, request)
    }

    pub fn issue_liability_placement(
        &self,
        request: &LiabilityPlacementIssueRequest,
    ) -> Result<SignedLiabilityPlacement, CliError> {
        self.post_json(LIABILITY_PLACEMENT_ISSUE_PATH, request)
    }

    pub fn issue_liability_bound_coverage(
        &self,
        request: &LiabilityBoundCoverageIssueRequest,
    ) -> Result<SignedLiabilityBoundCoverage, CliError> {
        self.post_json(LIABILITY_BOUND_COVERAGE_ISSUE_PATH, request)
    }

    pub fn liability_market_workflows(
        &self,
        query: &LiabilityMarketWorkflowQuery,
    ) -> Result<LiabilityMarketWorkflowReport, CliError> {
        self.get_json_with_query(LIABILITY_MARKET_WORKFLOW_REPORT_PATH, query)
    }

    pub fn issue_liability_claim_package(
        &self,
        request: &LiabilityClaimPackageIssueRequest,
    ) -> Result<SignedLiabilityClaimPackage, CliError> {
        self.post_json(LIABILITY_CLAIM_PACKAGE_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_response(
        &self,
        request: &LiabilityClaimResponseIssueRequest,
    ) -> Result<SignedLiabilityClaimResponse, CliError> {
        self.post_json(LIABILITY_CLAIM_RESPONSE_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_dispute(
        &self,
        request: &LiabilityClaimDisputeIssueRequest,
    ) -> Result<SignedLiabilityClaimDispute, CliError> {
        self.post_json(LIABILITY_CLAIM_DISPUTE_ISSUE_PATH, request)
    }

    pub fn issue_liability_claim_adjudication(
        &self,
        request: &LiabilityClaimAdjudicationIssueRequest,
    ) -> Result<SignedLiabilityClaimAdjudication, CliError> {
        self.post_json(LIABILITY_CLAIM_ADJUDICATION_ISSUE_PATH, request)
    }

    pub fn liability_claim_workflows(
        &self,
        query: &LiabilityClaimWorkflowQuery,
    ) -> Result<LiabilityClaimWorkflowReport, CliError> {
        self.get_json_with_query(LIABILITY_CLAIM_WORKFLOW_REPORT_PATH, query)
    }

    pub fn runtime_attestation_appraisal(
        &self,
        request: &RuntimeAttestationAppraisalRequest,
    ) -> Result<SignedRuntimeAttestationAppraisalReport, CliError> {
        self.post_json(RUNTIME_ATTESTATION_APPRAISAL_PATH, request)
    }

    pub fn metered_billing_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<MeteredBillingReconciliationReport, CliError> {
        self.get_json_with_query(METERED_BILLING_REPORT_PATH, query)
    }

    pub fn authorization_context_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<AuthorizationContextReport, CliError> {
        self.get_json_with_query(AUTHORIZATION_CONTEXT_REPORT_PATH, query)
    }

    pub fn authorization_profile_metadata(
        &self,
    ) -> Result<ArcOAuthAuthorizationMetadataReport, CliError> {
        self.get_json(AUTHORIZATION_PROFILE_METADATA_PATH)
    }

    pub fn authorization_review_pack(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<ArcOAuthAuthorizationReviewPack, CliError> {
        self.get_json_with_query(AUTHORIZATION_REVIEW_PACK_PATH, query)
    }

    pub fn underwriting_policy_input(
        &self,
        query: &UnderwritingPolicyInputQuery,
    ) -> Result<SignedUnderwritingPolicyInput, CliError> {
        self.get_json_with_query(UNDERWRITING_INPUT_PATH, query)
    }

    pub fn underwriting_decision(
        &self,
        query: &UnderwritingPolicyInputQuery,
    ) -> Result<UnderwritingDecisionReport, CliError> {
        self.get_json_with_query(UNDERWRITING_DECISION_PATH, query)
    }

    pub fn simulate_underwriting_decision(
        &self,
        request: &UnderwritingSimulationRequest,
    ) -> Result<UnderwritingSimulationReport, CliError> {
        self.post_json(UNDERWRITING_SIMULATION_PATH, request)
    }

    pub fn issue_underwriting_decision(
        &self,
        request: &UnderwritingDecisionIssueRequest,
    ) -> Result<SignedUnderwritingDecision, CliError> {
        self.post_json(UNDERWRITING_DECISION_ISSUE_PATH, request)
    }

    pub fn list_underwriting_decisions(
        &self,
        query: &UnderwritingDecisionQuery,
    ) -> Result<UnderwritingDecisionListReport, CliError> {
        self.get_json_with_query(UNDERWRITING_DECISIONS_REPORT_PATH, query)
    }

    pub fn create_underwriting_appeal(
        &self,
        request: &UnderwritingAppealCreateRequest,
    ) -> Result<UnderwritingAppealRecord, CliError> {
        self.post_json(UNDERWRITING_APPEALS_PATH, request)
    }

    pub fn resolve_underwriting_appeal(
        &self,
        request: &UnderwritingAppealResolveRequest,
    ) -> Result<UnderwritingAppealRecord, CliError> {
        self.post_json(UNDERWRITING_APPEAL_RESOLVE_PATH, request)
    }

    pub fn record_metered_billing_reconciliation(
        &self,
        request: &MeteredBillingReconciliationUpdateRequest,
    ) -> Result<MeteredBillingReconciliationUpdateResponse, CliError> {
        self.post_json(METERED_BILLING_RECONCILE_PATH, request)
    }

    pub fn local_reputation(
        &self,
        subject_key: &str,
        query: &LocalReputationQuery,
    ) -> Result<issuance::LocalReputationInspection, CliError> {
        self.get_json_with_query(
            &path_with_encoded_param(LOCAL_REPUTATION_PATH, "subject_key", subject_key),
            query,
        )
    }

    pub fn reputation_compare(
        &self,
        subject_key: &str,
        request: &ReputationCompareRequest,
    ) -> Result<reputation::PortableReputationComparison, CliError> {
        self.post_json(
            &path_with_encoded_param(REPUTATION_COMPARE_PATH, "subject_key", subject_key),
            request,
        )
    }

    pub fn append_tool_receipt(&self, receipt: &ArcReceipt) -> Result<(), CliError> {
        let _: Value = self.post_json(TOOL_RECEIPTS_PATH, receipt)?;
        Ok(())
    }

    pub fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), CliError> {
        let _: Value = self.post_json(CHILD_RECEIPTS_PATH, receipt)?;
        Ok(())
    }

    pub fn record_capability_snapshot(
        &self,
        capability: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), CliError> {
        let _: Value = self.post_json(
            LINEAGE_RECORD_PATH,
            &RecordCapabilitySnapshotRequest {
                capability: capability.clone(),
                parent_capability_id: parent_capability_id.map(ToOwned::to_owned),
            },
        )?;
        Ok(())
    }

    pub fn list_budgets(&self, query: &BudgetQuery) -> Result<BudgetListResponse, CliError> {
        self.get_json_with_query(BUDGETS_PATH, query)
    }

    fn try_increment_budget(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<TryIncrementBudgetResponse, CliError> {
        self.post_json(
            BUDGET_INCREMENT_PATH,
            &TryIncrementBudgetRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                max_invocations,
            },
        )
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<TryChargeCostResponse, CliError> {
        self.post_json(
            BUDGET_CHARGE_PATH,
            &TryChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
            },
        )
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<ReverseChargeCostResponse, CliError> {
        self.post_json(
            BUDGET_REVERSE_PATH,
            &ReverseChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                cost_units,
            },
        )
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.post_json(
            BUDGET_REDUCE_PATH,
            &ReduceChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                cost_units,
            },
        )
    }

    fn cluster_status(&self) -> Result<ClusterStatusResponse, CliError> {
        self.get_json(INTERNAL_CLUSTER_STATUS_PATH)
    }

    fn authority_snapshot(&self) -> Result<AuthoritySnapshotView, CliError> {
        self.get_json(INTERNAL_AUTHORITY_SNAPSHOT_PATH)
    }

    fn revocation_deltas(
        &self,
        query: &RevocationDeltaQuery,
    ) -> Result<RevocationDeltaResponse, CliError> {
        self.get_json_with_query(INTERNAL_REVOCATIONS_DELTA_PATH, query)
    }

    fn tool_receipt_deltas(
        &self,
        query: &ReceiptDeltaQuery,
    ) -> Result<ReceiptDeltaResponse, CliError> {
        self.get_json_with_query(INTERNAL_TOOL_RECEIPTS_DELTA_PATH, query)
    }

    fn child_receipt_deltas(
        &self,
        query: &ReceiptDeltaQuery,
    ) -> Result<ReceiptDeltaResponse, CliError> {
        self.get_json_with_query(INTERNAL_CHILD_RECEIPTS_DELTA_PATH, query)
    }

    fn lineage_deltas(&self, query: &ReceiptDeltaQuery) -> Result<LineageDeltaResponse, CliError> {
        self.get_json_with_query(INTERNAL_LINEAGE_DELTA_PATH, query)
    }

    fn budget_deltas(&self, query: &BudgetDeltaQuery) -> Result<BudgetDeltaResponse, CliError> {
        self.get_json_with_query(INTERNAL_BUDGETS_DELTA_PATH, query)
    }

    fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, CliError> {
        self.request_json(
            |client, url, token| {
                client
                    .get(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call()
            },
            path,
        )
    }

    fn public_get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, CliError> {
        self.request_json_without_service_auth(|client, url| client.get(url).call(), path)
    }

    fn public_get_text(&self, path: &str) -> Result<String, CliError> {
        self.request_text_without_service_auth(|client, url| client.get(url).call(), path)
    }

    fn get_json_with_query<Q: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &Q,
    ) -> Result<T, CliError> {
        let encoded_query = serde_urlencoded::to_string(query).map_err(|error| {
            CliError::Other(format!("failed to encode trust control query: {error}"))
        })?;
        let url = if encoded_query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{encoded_query}")
        };
        self.request_json(
            |client, base_url, token| {
                client
                    .get(&format!("{base_url}{url}"))
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call()
            },
            "",
        )
    }

    fn post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::Other(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json(
            |client, url, token| {
                client
                    .post(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .send_json(json.clone())
            },
            path,
        )
    }

    fn public_post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::Other(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json_without_service_auth(
            |client, url| client.post(url).send_json(json.clone()),
            path,
        )
    }

    fn public_post_form<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &[(&str, &str)],
    ) -> Result<T, CliError> {
        self.request_json_without_service_auth(|client, url| client.post(url).send_form(body), path)
    }

    fn bearer_post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        bearer_token: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::Other(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json_with_bearer(
            |client, url| {
                client
                    .post(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {bearer_token}"))
                    .send_json(json.clone())
            },
            path,
        )
    }

    fn put_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let json = serde_json::to_value(body).map_err(|error| {
            CliError::Other(format!(
                "failed to serialize trust control request: {error}"
            ))
        })?;
        self.request_json(
            |client, url, token| {
                client
                    .put(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .send_json(json.clone())
            },
            path,
        )
    }

    fn delete_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, CliError> {
        self.request_json(
            |client, url, token| {
                client
                    .delete(url)
                    .set(AUTHORIZATION.as_str(), &format!("Bearer {token}"))
                    .call()
            },
            path,
        )
    }

    fn request_json<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&Agent, &str, &str) -> Result<ureq::Response, ureq::Error>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            match request(&self.http, &url, &self.token) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return serde_json::from_reader(response.into_reader()).map_err(|error| {
                        CliError::Other(format!(
                            "failed to decode trust control service response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(status, response)) if should_retry_status(status) => {
                    last_error = Some(CliError::Other(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Status(status, response)) => {
                    return Err(CliError::Other(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(CliError::Other(format!(
                        "trust control service transport failed: {error}"
                    )));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            CliError::Other("trust control service request failed with no endpoints".to_string())
        }))
    }

    fn request_json_without_service_auth<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&Agent, &str) -> Result<ureq::Response, ureq::Error>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            match request(&self.http, &url) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return serde_json::from_reader(response.into_reader()).map_err(|error| {
                        CliError::Other(format!(
                            "failed to decode trust control service response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(status, response)) if should_retry_status(status) => {
                    last_error = Some(CliError::Other(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Status(status, response)) => {
                    return Err(CliError::Other(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(CliError::Other(format!(
                        "trust control service transport failed: {error}"
                    )));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            CliError::Other("trust control service request failed with no endpoints".to_string())
        }))
    }

    fn request_text_without_service_auth<F>(
        &self,
        request: F,
        path: &str,
    ) -> Result<String, CliError>
    where
        F: Fn(&Agent, &str) -> Result<ureq::Response, ureq::Error>,
    {
        let endpoint_order = self.endpoint_order();
        let mut last_error = None;
        for index in endpoint_order {
            let url = format!("{}{}", self.endpoints[index], path);
            match request(&self.http, &url) {
                Ok(response) => {
                    self.mark_preferred(index);
                    return response.into_string().map_err(|error| {
                        CliError::Other(format!(
                            "failed to decode trust control text response body: {error}"
                        ))
                    });
                }
                Err(ureq::Error::Status(status, response)) if should_retry_status(status) => {
                    last_error = Some(CliError::Other(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Status(status, response)) => {
                    return Err(CliError::Other(format!(
                        "trust control service request failed with {status}: {}",
                        response.into_string().unwrap_or_default()
                    )));
                }
                Err(ureq::Error::Transport(error)) => {
                    last_error = Some(CliError::Other(format!(
                        "trust control service transport failed: {error}"
                    )));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            CliError::Other("trust control service request failed with no endpoints".to_string())
        }))
    }

    fn request_json_with_bearer<T, F>(&self, request: F, path: &str) -> Result<T, CliError>
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&Agent, &str) -> Result<ureq::Response, ureq::Error>,
    {
        self.request_json_without_service_auth(request, path)
    }

    fn endpoint_order(&self) -> Vec<usize> {
        let preferred = match self.preferred_index.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        };
        let total = self.endpoints.len();
        (0..total)
            .map(|offset| (preferred + offset) % total)
            .collect()
    }

    fn mark_preferred(&self, index: usize) {
        match self.preferred_index.lock() {
            Ok(mut guard) => *guard = index,
            Err(poisoned) => *poisoned.into_inner() = index,
        }
    }
}

fn certification_marketplace_search_path(query: &CertificationMarketplaceSearchQuery) -> String {
    let mut serializer = UrlFormSerializer::new(String::new());
    if let Some(tool_server_id) = query.filters.tool_server_id.as_deref() {
        serializer.append_pair("toolServerId", tool_server_id);
    }
    if let Some(criteria_profile) = query.filters.criteria_profile.as_deref() {
        serializer.append_pair("criteriaProfile", criteria_profile);
    }
    if let Some(evidence_profile) = query.filters.evidence_profile.as_deref() {
        serializer.append_pair("evidenceProfile", evidence_profile);
    }
    if let Some(status) = query.filters.status {
        serializer.append_pair("status", status.label());
    }
    if let Some(operator_ids) = query.operator_ids.as_deref() {
        serializer.append_pair("operatorIds", operator_ids);
    }
    let encoded = serializer.finish();
    if encoded.is_empty() {
        CERTIFICATION_DISCOVERY_SEARCH_PATH.to_string()
    } else {
        format!("{CERTIFICATION_DISCOVERY_SEARCH_PATH}?{encoded}")
    }
}

fn certification_marketplace_transparency_path(
    query: &CertificationMarketplaceTransparencyQuery,
) -> String {
    let mut serializer = UrlFormSerializer::new(String::new());
    if let Some(tool_server_id) = query.filters.tool_server_id.as_deref() {
        serializer.append_pair("toolServerId", tool_server_id);
    }
    if let Some(operator_ids) = query.operator_ids.as_deref() {
        serializer.append_pair("operatorIds", operator_ids);
    }
    let encoded = serializer.finish();
    if encoded.is_empty() {
        CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH.to_string()
    } else {
        format!("{CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH}?{encoded}")
    }
}

impl RemoteCapabilityAuthority {
    pub fn refresh_status(&self) -> Result<(), CliError> {
        let status = self.client.authority_status()?;
        let cache = AuthorityKeyCache::from_status(&status)?;
        match self.cache.lock() {
            Ok(mut guard) => *guard = cache,
            Err(poisoned) => *poisoned.into_inner() = cache,
        }
        Ok(())
    }

    fn refresh_status_if_stale(&self) {
        let should_refresh = match self.cache.lock() {
            Ok(guard) => guard.refreshed_at.elapsed() >= AUTHORITY_CACHE_TTL,
            Err(poisoned) => poisoned.into_inner().refreshed_at.elapsed() >= AUTHORITY_CACHE_TTL,
        };
        if should_refresh {
            let _ = self.refresh_status();
        }
    }
}

impl CapabilityAuthority for RemoteCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.refresh_status_if_stale();
        match self.cache.lock() {
            Ok(guard) => match &guard.current {
                Some(public_key) => public_key.clone(),
                None => unreachable!("remote capability authority cache missing current key"),
            },
            Err(poisoned) => match &poisoned.into_inner().current {
                Some(public_key) => public_key.clone(),
                None => unreachable!("remote capability authority cache missing current key"),
            },
        }
    }

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        self.refresh_status_if_stale();
        match self.cache.lock() {
            Ok(guard) => guard.trusted.clone(),
            Err(poisoned) => poisoned.into_inner().trusted.clone(),
        }
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ArcScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, arc_kernel::KernelError> {
        self.issue_capability_with_attestation(subject, scope, ttl_seconds, None)
    }

    fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ArcScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, arc_kernel::KernelError> {
        let capability = self
            .client
            .issue_capability_with_attestation(subject, scope, ttl_seconds, runtime_attestation)
            .map_err(|error| {
                arc_kernel::KernelError::CapabilityIssuanceFailed(error.to_string())
            })?;
        match self.cache.lock() {
            Ok(mut guard) => {
                guard.current = Some(capability.issuer.clone());
                if !guard.trusted.contains(&capability.issuer) {
                    guard.trusted.push(capability.issuer.clone());
                }
                guard.refreshed_at = Instant::now();
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.current = Some(capability.issuer.clone());
                if !guard.trusted.contains(&capability.issuer) {
                    guard.trusted.push(capability.issuer.clone());
                }
                guard.refreshed_at = Instant::now();
            }
        }
        Ok(capability)
    }
}

impl RevocationStore for RemoteRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        self.client
            .list_revocations(&RevocationQuery {
                capability_id: Some(capability_id.to_string()),
                limit: Some(1),
            })
            .map(|response| response.revoked.unwrap_or(false))
            .map_err(into_revocation_store_error)
    }

    fn revoke(&mut self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        self.client
            .revoke_capability(capability_id)
            .map(|response| response.newly_revoked)
            .map_err(into_revocation_store_error)
    }
}

impl ReceiptStore for RemoteReceiptStore {
    fn append_arc_receipt(&mut self, receipt: &ArcReceipt) -> Result<(), ReceiptStoreError> {
        self.client
            .append_tool_receipt(receipt)
            .map_err(into_receipt_store_error)
    }

    fn append_child_receipt(
        &mut self,
        receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        self.client
            .append_child_receipt(receipt)
            .map_err(into_receipt_store_error)
    }

    fn record_capability_snapshot(
        &mut self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        self.client
            .record_capability_snapshot(token, parent_capability_id)
            .map_err(into_receipt_store_error)
    }

    fn resolve_credit_bond(
        &self,
        bond_id: &str,
    ) -> Result<Option<arc_kernel::CreditBondRow>, ReceiptStoreError> {
        self.client
            .list_credit_bonds(&CreditBondListQuery {
                bond_id: Some(bond_id.to_string()),
                facility_id: None,
                capability_id: None,
                agent_subject: None,
                tool_server: None,
                tool_name: None,
                disposition: None,
                lifecycle_state: None,
                limit: Some(1),
            })
            .map(|report| report.bonds.into_iter().next())
            .map_err(into_receipt_store_error)
    }
}

impl BudgetStore for RemoteBudgetStore {
    fn try_increment(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.client
            .try_increment_budget(capability_id, grant_index, max_invocations)
            .map(|response| response.allowed)
            .map_err(into_budget_store_error)
    }

    fn try_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.client
            .try_charge_cost(
                capability_id,
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
            )
            .map(|response| response.allowed)
            .map_err(into_budget_store_error)
    }

    fn reverse_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.client
            .reverse_charge_cost(capability_id, grant_index, cost_units)
            .map(|_| ())
            .map_err(into_budget_store_error)
    }

    fn reduce_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.client
            .reduce_charge_cost(capability_id, grant_index, cost_units)
            .map(|_| ())
            .map_err(into_budget_store_error)
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.client
            .list_budgets(&BudgetQuery {
                capability_id: capability_id.map(ToOwned::to_owned),
                limit: Some(limit),
            })
            .map(|response| {
                response
                    .usages
                    .into_iter()
                    .map(|usage| BudgetUsageRecord {
                        capability_id: usage.capability_id,
                        grant_index: usage.grant_index,
                        invocation_count: usage.invocation_count,
                        updated_at: usage.updated_at,
                        seq: usage.seq.unwrap_or(0),
                        total_cost_charged: usage.total_cost_charged,
                    })
                    .collect()
            })
            .map_err(into_budget_store_error)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.list_usages(MAX_LIST_LIMIT, Some(capability_id))
            .map(|usages| {
                usages
                    .into_iter()
                    .find(|usage| usage.grant_index == grant_index as u32)
            })
    }
}

impl AuthorityKeyCache {
    fn from_status(status: &TrustAuthorityStatus) -> Result<Self, CliError> {
        if !status.configured {
            return Err(CliError::Other(
                "trust control service does not have an authority configured".to_string(),
            ));
        }
        let current = status
            .public_key
            .as_deref()
            .map(PublicKey::from_hex)
            .transpose()?;
        if current.is_none() {
            return Err(CliError::Other(
                "trust control service returned no current authority public key".to_string(),
            ));
        }
        let trusted = status
            .trusted_public_keys
            .iter()
            .map(|value| PublicKey::from_hex(value))
            .collect::<Result<Vec<_>, _>>()?;
        let mut trusted = trusted;
        if let Some(current) = current.as_ref() {
            if !trusted.iter().any(|public_key| public_key == current) {
                trusted.push(current.clone());
            }
        }
        Ok(Self {
            current,
            trusted,
            refreshed_at: Instant::now(),
        })
    }
}

fn should_retry_status(status: u16) -> bool {
    matches!(status, 500 | 502 | 503 | 504)
}

fn into_receipt_store_error(error: CliError) -> ReceiptStoreError {
    ReceiptStoreError::Io(std::io::Error::other(error.to_string()))
}

fn into_revocation_store_error(error: CliError) -> RevocationStoreError {
    RevocationStoreError::Io(std::io::Error::other(error.to_string()))
}

fn into_budget_store_error(error: CliError) -> BudgetStoreError {
    BudgetStoreError::Io(std::io::Error::other(error.to_string()))
}

async fn handle_health(State(state): State<TrustServiceState>) -> Response {
    let leader_url = current_leader_url(&state);
    let self_url = cluster_self_url(&state);
    Json(json!({
        "ok": true,
        "leaderUrl": leader_url.clone(),
        "selfUrl": self_url.clone(),
        "clustered": state.cluster.is_some(),
        "authority": trust_authority_health_snapshot(&state.config),
        "stores": trust_store_health_snapshot(&state.config),
        "federation": trust_federation_health_snapshot(&state),
        "cluster": trust_cluster_health_snapshot(&state, leader_url, self_url),
    }))
    .into_response()
}

fn trust_authority_health_snapshot(config: &TrustServiceConfig) -> Value {
    let backend_hint = if config.authority_db_path.is_some() {
        Some("sqlite")
    } else if config.authority_seed_path.is_some() {
        Some("seed_file")
    } else {
        None
    };
    match load_authority_status(config) {
        Ok(status) => json!({
            "configured": status.configured,
            "available": true,
            "backend": status.backend,
            "publicKey": status.public_key,
            "generation": status.generation,
            "rotatedAt": status.rotated_at,
            "appliesToFutureSessionsOnly": status.applies_to_future_sessions_only,
            "trustedKeyCount": status.trusted_public_keys.len(),
        }),
        Err(_) => json!({
            "configured": backend_hint.is_some(),
            "available": false,
            "backend": backend_hint,
            "publicKey": Value::Null,
            "generation": Value::Null,
            "rotatedAt": Value::Null,
            "appliesToFutureSessionsOnly": true,
            "trustedKeyCount": 0,
        }),
    }
}

fn trust_store_health_snapshot(config: &TrustServiceConfig) -> Value {
    json!({
        "receiptsConfigured": config.receipt_db_path.is_some(),
        "revocationsConfigured": config.revocation_db_path.is_some(),
        "budgetsConfigured": config.budget_db_path.is_some(),
        "verifierChallengesConfigured": config.verifier_challenge_db_path.is_some(),
    })
}

fn trust_federation_health_snapshot(state: &TrustServiceState) -> Value {
    let loaded_enterprise_provider_summary = state
        .enterprise_provider_registry()
        .map(|registry| {
            let enabled_count = registry
                .providers
                .values()
                .filter(|record| record.enabled)
                .count();
            let validated_count = registry
                .providers
                .values()
                .filter(|record| record.is_validated_enabled())
                .count();
            let invalid_count = registry
                .providers
                .values()
                .filter(|record| !record.validation_errors.is_empty())
                .count();
            (
                registry.providers.len(),
                enabled_count,
                validated_count,
                invalid_count,
            )
        })
        .unwrap_or((0, 0, 0, 0));

    let enterprise_provider_summary =
        if let Some(path) = state.config.enterprise_providers_file.as_deref() {
            match EnterpriseProviderRegistry::load(path) {
                Ok(registry) => {
                    let enabled_count = registry
                        .providers
                        .values()
                        .filter(|record| record.enabled)
                        .count();
                    let validated_count = registry
                        .providers
                        .values()
                        .filter(|record| record.is_validated_enabled())
                        .count();
                    let invalid_count = registry
                        .providers
                        .values()
                        .filter(|record| !record.validation_errors.is_empty())
                        .count();
                    json!({
                        "configured": true,
                        "available": true,
                        "count": registry.providers.len(),
                        "enabledCount": enabled_count,
                        "validatedCount": validated_count,
                        "invalidCount": invalid_count,
                        "loadedCount": loaded_enterprise_provider_summary.0,
                        "loadedValidatedCount": loaded_enterprise_provider_summary.2,
                    })
                }
                Err(_) => json!({
                    "configured": true,
                    "available": false,
                    "count": 0,
                    "enabledCount": 0,
                    "validatedCount": 0,
                    "invalidCount": 0,
                    "loadedCount": loaded_enterprise_provider_summary.0,
                    "loadedValidatedCount": loaded_enterprise_provider_summary.2,
                }),
            }
        } else {
            json!({
                "configured": false,
                "available": false,
                "count": 0,
                "enabledCount": 0,
                "validatedCount": 0,
                "invalidCount": 0,
                "loadedCount": 0,
                "loadedValidatedCount": 0,
            })
        };

    let loaded_verifier_policy_summary = state
        .verifier_policy_registry()
        .map(|registry| {
            let now = unix_timestamp_now();
            let active_count = registry
                .policies
                .values()
                .filter(|document| {
                    ensure_signed_passport_verifier_policy_active(document, now).is_ok()
                })
                .count();
            (registry.policies.len(), active_count)
        })
        .unwrap_or((0, 0));

    let verifier_policy_summary = if let Some(path) = state.config.verifier_policies_file.as_deref()
    {
        match VerifierPolicyRegistry::load(path) {
            Ok(registry) => {
                let now = unix_timestamp_now();
                let active_count = registry
                    .policies
                    .values()
                    .filter(|document| {
                        ensure_signed_passport_verifier_policy_active(document, now).is_ok()
                    })
                    .count();
                json!({
                    "configured": true,
                    "available": true,
                    "count": registry.policies.len(),
                    "activeCount": active_count,
                    "loadedCount": loaded_verifier_policy_summary.0,
                    "loadedActiveCount": loaded_verifier_policy_summary.1,
                })
            }
            Err(_) => json!({
                "configured": true,
                "available": false,
                "count": 0,
                "activeCount": 0,
                "loadedCount": loaded_verifier_policy_summary.0,
                "loadedActiveCount": loaded_verifier_policy_summary.1,
            }),
        }
    } else {
        json!({
            "configured": false,
            "available": false,
            "count": 0,
            "activeCount": 0,
            "loadedCount": 0,
            "loadedActiveCount": 0,
        })
    };

    let certification_summary =
        if let Some(path) = state.config.certification_registry_file.as_deref() {
            match CertificationRegistry::load(path) {
                Ok(registry) => {
                    let active_count = registry
                        .artifacts
                        .values()
                        .filter(|entry| entry.status == CertificationRegistryState::Active)
                        .count();
                    let superseded_count = registry
                        .artifacts
                        .values()
                        .filter(|entry| entry.status == CertificationRegistryState::Superseded)
                        .count();
                    let revoked_count = registry
                        .artifacts
                        .values()
                        .filter(|entry| entry.status == CertificationRegistryState::Revoked)
                        .count();
                    json!({
                        "configured": true,
                        "available": true,
                        "count": registry.artifacts.len(),
                        "activeCount": active_count,
                        "supersededCount": superseded_count,
                        "revokedCount": revoked_count,
                    })
                }
                Err(_) => json!({
                    "configured": true,
                    "available": false,
                    "count": 0,
                    "activeCount": 0,
                    "supersededCount": 0,
                    "revokedCount": 0,
                }),
            }
        } else {
            json!({
                "configured": false,
                "available": false,
                "count": 0,
                "activeCount": 0,
                "supersededCount": 0,
                "revokedCount": 0,
            })
        };

    let certification_discovery_summary =
        if let Some(path) = state.config.certification_discovery_file.as_deref() {
            match CertificationDiscoveryNetwork::load(path) {
                Ok(network) => {
                    let validated_count = network
                        .operators
                        .values()
                        .filter(|operator| operator.validation_errors.is_empty())
                        .count();
                    let publish_enabled_count = network
                        .operators
                        .values()
                        .filter(|operator| {
                            operator.validation_errors.is_empty() && operator.allow_publish
                        })
                        .count();
                    json!({
                        "configured": true,
                        "available": true,
                        "count": network.operators.len(),
                        "validatedCount": validated_count,
                        "publishEnabledCount": publish_enabled_count,
                    })
                }
                Err(_) => json!({
                    "configured": true,
                    "available": false,
                    "count": 0,
                    "validatedCount": 0,
                    "publishEnabledCount": 0,
                }),
            }
        } else {
            json!({
                "configured": false,
                "available": false,
                "count": 0,
                "validatedCount": 0,
                "publishEnabledCount": 0,
            })
        };

    json!({
        "enterpriseProviders": enterprise_provider_summary,
        "verifierPolicies": verifier_policy_summary,
        "certifications": certification_summary,
        "certificationDiscovery": certification_discovery_summary,
        "issuancePolicyConfigured": state.config.issuance_policy.is_some(),
        "runtimeAssurancePolicyConfigured": state.config.runtime_assurance_policy.is_some(),
    })
}

fn trust_cluster_health_snapshot(
    state: &TrustServiceState,
    leader_url: Option<String>,
    self_url: Option<String>,
) -> Value {
    let Some(cluster) = state.cluster.as_ref() else {
        return json!({
            "peerCount": 0,
            "healthyPeers": 0,
            "unhealthyPeers": 0,
            "unknownPeers": 0,
            "lastErrorCount": 0,
            "leaderUrl": leader_url,
            "selfUrl": self_url,
        });
    };

    let peers = match cluster.lock() {
        Ok(guard) => guard.peers.clone(),
        Err(poisoned) => poisoned.into_inner().peers.clone(),
    };

    let mut healthy = 0usize;
    let mut unhealthy = 0usize;
    let mut unknown = 0usize;
    let mut last_error_count = 0usize;
    for peer in peers.values() {
        match peer.health {
            PeerHealth::Healthy => healthy += 1,
            PeerHealth::Unhealthy(_) => unhealthy += 1,
            PeerHealth::Unknown => unknown += 1,
        }
        if peer.last_error.is_some() {
            last_error_count += 1;
        }
    }

    json!({
        "peerCount": peers.len(),
        "healthyPeers": healthy,
        "unhealthyPeers": unhealthy,
        "unknownPeers": unknown,
        "lastErrorCount": last_error_count,
        "leaderUrl": leader_url,
        "selfUrl": self_url,
    })
}

async fn handle_authority_status(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match load_authority_status(&state.config) {
        Ok(status) => Json(status).into_response(),
        Err(response) => response,
    }
}

async fn handle_rotate_authority(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, AUTHORITY_PATH, &json!({})).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    match rotate_authority(&state.config) {
        Ok(status) => respond_after_leader_visible_write(
            &state,
            "rotated authority was not visible on the leader after write",
            || {
                let visible_status = load_authority_status(&state.config)?;
                if visible_status.generation == status.generation
                    && visible_status.public_key == status.public_key
                {
                    Ok(Some(visible_status))
                } else {
                    Ok(None)
                }
            },
        ),
        Err(response) => response,
    }
}

async fn handle_issue_capability(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<IssueCapabilityRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, ISSUE_CAPABILITY_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let subject = match PublicKey::from_hex(&payload.subject_public_key) {
        Ok(subject) => subject,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Some(runtime_attestation) = payload.runtime_attestation.as_ref() {
        if let Err(error) = runtime_attestation.validate_workload_identity_binding() {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                &format!("runtime attestation workload identity is invalid: {error}"),
            );
        }
    }
    match load_capability_authority(&state.config) {
        Ok(authority) => {
            match authority.issue_capability_with_attestation(
                &subject,
                payload.scope,
                payload.ttl_seconds,
                payload.runtime_attestation,
            ) {
                Ok(capability) => Json(IssueCapabilityResponse { capability }).into_response(),
                Err(arc_kernel::KernelError::CapabilityIssuanceDenied(error)) => {
                    plain_http_error(StatusCode::FORBIDDEN, &error)
                }
                Err(error) => {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                }
            }
        }
        Err(response) => response,
    }
}

async fn handle_list_enterprise_providers(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match load_enterprise_provider_registry_for_admin(&state.config) {
        Ok((_, registry)) => Json(EnterpriseProviderListResponse {
            configured: true,
            count: registry.providers.len(),
            providers: registry.providers.into_values().collect(),
        })
        .into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_get_enterprise_provider(
    State(state): State<TrustServiceState>,
    AxumPath(provider_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_enterprise_provider_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match registry.providers.get(&provider_id) {
        Some(record) => Json(record.clone()).into_response(),
        None => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("enterprise provider `{provider_id}` was not found"),
        ),
    }
}

async fn handle_upsert_enterprise_provider(
    State(state): State<TrustServiceState>,
    AxumPath(provider_id): AxumPath<String>,
    headers: HeaderMap,
    Json(mut record): Json<EnterpriseProviderRecord>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_enterprise_provider_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    record.provider_id = provider_id.clone();
    registry.upsert(record);
    let Some(saved) = registry.providers.get(&provider_id).cloned() else {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "enterprise provider upsert did not persist the requested record",
        );
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(saved).into_response()
}

async fn handle_delete_enterprise_provider(
    State(state): State<TrustServiceState>,
    AxumPath(provider_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_enterprise_provider_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let deleted = registry.remove(&provider_id);
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(EnterpriseProviderDeleteResponse {
        provider_id,
        deleted,
    })
    .into_response()
}

async fn handle_list_certifications(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match load_certification_registry_for_admin(&state.config) {
        Ok((_, registry)) => Json(CertificationRegistryListResponse {
            configured: true,
            count: registry.artifacts.len(),
            artifacts: registry.artifacts.into_values().collect(),
        })
        .into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_get_certification(
    State(state): State<TrustServiceState>,
    AxumPath(artifact_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_certification_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match registry.get(&artifact_id) {
        Some(entry) => Json(entry.clone()).into_response(),
        None => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("certification artifact `{artifact_id}` was not found"),
        ),
    }
}

async fn handle_publish_certification(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(artifact): Json<SignedCertificationCheck>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_certification_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let entry = match registry.publish(artifact) {
        Ok(entry) => entry,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(entry).into_response()
}

async fn handle_resolve_certification(
    State(state): State<TrustServiceState>,
    AxumPath(tool_server_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_certification_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(registry.resolve(&tool_server_id)).into_response()
}

async fn handle_public_resolve_certification(
    State(state): State<TrustServiceState>,
    AxumPath(tool_server_id): AxumPath<String>,
) -> Response {
    let registry = match load_certification_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(registry.resolve(&tool_server_id)).into_response()
}

async fn handle_public_certification_metadata(State(state): State<TrustServiceState>) -> Response {
    match configured_public_certification_metadata(&state.config) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_public_search_certifications(
    State(state): State<TrustServiceState>,
    Query(query): Query<CertificationPublicSearchQuery>,
) -> Response {
    let registry = match load_certification_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let metadata = match configured_public_certification_metadata(&state.config) {
        Ok(metadata) => metadata,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(registry.search_public(&metadata.publisher, metadata.expires_at, &query)).into_response()
}

async fn handle_public_certification_transparency(
    State(state): State<TrustServiceState>,
    Query(query): Query<CertificationTransparencyQuery>,
) -> Response {
    let registry = match load_certification_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let metadata = match configured_public_certification_metadata(&state.config) {
        Ok(metadata) => metadata,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(registry.transparency(&metadata.publisher, &query)).into_response()
}

async fn handle_passport_issuer_metadata(State(state): State<TrustServiceState>) -> Response {
    match configured_passport_credential_issuer(&state.config) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_oid4vp_verifier_metadata(State(state): State<TrustServiceState>) -> Response {
    match build_oid4vp_verifier_metadata(&state.config) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_passport_issuer_jwks(State(state): State<TrustServiceState>) -> Response {
    match build_oid4vp_verifier_jwks(&state.config) {
        Ok(jwks) => Json(jwks).into_response(),
        Err(error) => {
            let status = if error.to_string().contains("configured authority")
                || error
                    .to_string()
                    .contains("did not publish any signing keys")
            {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            };
            plain_http_error(status, &error.to_string())
        }
    }
}

async fn handle_passport_sd_jwt_type_metadata(State(state): State<TrustServiceState>) -> Response {
    let Some(advertise_url) = state.config.advertise_url.as_deref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "portable credential type metadata requires --advertise-url on the trust-control service",
        );
    };
    if state.config.authority_seed_path.is_none() && state.config.authority_db_path.is_none() {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "portable credential type metadata is unavailable because no authority signing key is configured",
        );
    }
    match build_arc_passport_sd_jwt_type_metadata(advertise_url) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_passport_jwt_vc_json_type_metadata(
    State(state): State<TrustServiceState>,
) -> Response {
    let Some(advertise_url) = state.config.advertise_url.as_deref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "portable credential type metadata requires --advertise-url on the trust-control service",
        );
    };
    if state.config.authority_seed_path.is_none() && state.config.authority_db_path.is_none() {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "portable credential type metadata is unavailable because no authority signing key is configured",
        );
    }
    match build_arc_passport_jwt_vc_json_type_metadata(advertise_url) {
        Ok(metadata) => Json(metadata).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_create_passport_issuance_offer(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CreatePassportIssuanceOfferRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, PASSPORT_ISSUANCE_OFFERS_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let (path, mut registry) = match load_passport_issuance_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let metadata = match configured_passport_credential_issuer(&state.config) {
        Ok(metadata) => metadata,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if state.config.passport_statuses_file.is_some() {
        if let Err(error) = portable_passport_status_reference_for_service(
            &state.config,
            &payload.passport,
            unix_timestamp_now(),
        ) {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
    }
    let record = match registry.issue_offer(
        &metadata,
        payload.passport,
        payload.credential_configuration_id.as_deref(),
        payload.ttl_seconds,
        unix_timestamp_now(),
    ) {
        Ok(record) => record,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(record).into_response()
}

async fn handle_redeem_passport_issuance_token(
    State(state): State<TrustServiceState>,
    Json(payload): Json<Oid4vciTokenRequest>,
) -> Response {
    let (path, mut registry) = match load_passport_issuance_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let metadata = match configured_passport_credential_issuer(&state.config) {
        Ok(metadata) => metadata,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let response =
        match registry.redeem_pre_authorized_code(&metadata, &payload, unix_timestamp_now(), 300) {
            Ok(response) => response,
            Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
        };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(response).into_response()
}

async fn handle_redeem_passport_issuance_credential(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<Oid4vciCredentialRequest>,
) -> Response {
    let access_token = match bearer_token_from_headers(&headers) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let (path, mut registry) = match load_passport_issuance_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let metadata = match configured_passport_credential_issuer(&state.config) {
        Ok(metadata) => metadata,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let portable_signing_keypair =
        if state.config.authority_seed_path.is_some() || state.config.authority_db_path.is_some() {
            match resolve_oid4vp_verifier_signing_key(&state.config) {
                Ok(keypair) => Some(keypair),
                Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
            }
        } else {
            None
        };
    let portable_status_registry = match state.config.passport_statuses_file.as_deref() {
        Some(path) => match PassportStatusRegistry::load(path) {
            Ok(registry) => Some(registry),
            Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
        },
        None => None,
    };
    let response = match registry.redeem_credential(
        &metadata,
        &access_token,
        &payload,
        unix_timestamp_now(),
        portable_signing_keypair.as_ref(),
        portable_status_registry.as_ref(),
    ) {
        Ok(response) => response,
        Err(error) if error.to_string().contains("access token") => {
            return plain_http_error(StatusCode::UNAUTHORIZED, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(response).into_response()
}

async fn handle_publish_certification_network(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CertificationNetworkPublishRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (_, network) = match load_certification_discovery_network_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match crate::certify::publish_certification_across_network(
        &network,
        &request.artifact,
        &request.operator_ids,
    ) {
        Ok(response) => Json(response).into_response(),
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

async fn handle_discover_certification(
    State(state): State<TrustServiceState>,
    AxumPath(tool_server_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (_, network) = match load_certification_discovery_network_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let response =
        crate::certify::discover_certifications_across_network(&network, &tool_server_id);
    Json(response).into_response()
}

async fn handle_search_certification_marketplace(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Query(query): Query<CertificationMarketplaceSearchQuery>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (_, network) = match load_certification_discovery_network_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(crate::certify::search_public_certifications_across_network(
        &network, &query,
    ))
    .into_response()
}

async fn handle_transparency_certification_marketplace(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Query(query): Query<CertificationMarketplaceTransparencyQuery>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (_, network) = match load_certification_discovery_network_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(crate::certify::transparency_public_certifications_across_network(&network, &query))
        .into_response()
}

async fn handle_consume_certification_marketplace(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CertificationConsumptionRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (_, network) = match load_certification_discovery_network_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(crate::certify::consume_public_certification_across_network(
        &network, &request,
    ))
    .into_response()
}

async fn handle_revoke_certification(
    State(state): State<TrustServiceState>,
    AxumPath(artifact_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<CertificationRevocationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_certification_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let entry = match registry.revoke(&artifact_id, request.reason.as_deref(), request.revoked_at) {
        Ok(entry) => entry,
        Err(error) if error.to_string().contains("was not found") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(entry).into_response()
}

async fn handle_dispute_certification(
    State(state): State<TrustServiceState>,
    AxumPath(artifact_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<CertificationDisputeRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_certification_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let entry = match registry.dispute(&artifact_id, &request) {
        Ok(entry) => entry,
        Err(error) if error.to_string().contains("was not found") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(entry).into_response()
}

async fn handle_list_passport_statuses(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match load_passport_status_registry_for_admin(&state.config) {
        Ok((_, registry)) => Json(PassportStatusListResponse {
            configured: true,
            count: registry.passports.len(),
            passports: registry.passports.into_values().collect(),
        })
        .into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_get_passport_status(
    State(state): State<TrustServiceState>,
    AxumPath(passport_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_passport_status_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match registry.get(&passport_id) {
        Some(record) => Json(record.clone()).into_response(),
        None => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("passport `{passport_id}` was not found in the lifecycle registry"),
        ),
    }
}

async fn handle_publish_passport_status(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(mut request): Json<PublishPassportStatusRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_passport_status_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if request.distribution.resolve_urls.is_empty() {
        request.distribution = default_passport_status_distribution(&state.config);
    }
    let record = match registry.publish(
        &request.passport,
        unix_timestamp_now(),
        request.distribution,
    ) {
        Ok(record) => record,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(record).into_response()
}

async fn handle_resolve_passport_status(
    State(state): State<TrustServiceState>,
    AxumPath(passport_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_passport_status_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let mut resolution = registry.resolve_at(&passport_id, unix_timestamp_now());
    resolution.source = Some("registry:trust-control".to_string());
    match resolution.validate() {
        Ok(()) => Json(resolution).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_public_resolve_passport_status(
    State(state): State<TrustServiceState>,
    AxumPath(passport_id): AxumPath<String>,
) -> Response {
    let registry = match load_passport_status_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let mut resolution = registry.resolve_at(&passport_id, unix_timestamp_now());
    resolution.source = Some("registry:trust-control".to_string());
    match resolution.validate() {
        Ok(()) => Json(resolution).into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_revoke_passport_status(
    State(state): State<TrustServiceState>,
    AxumPath(passport_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<PassportStatusRevocationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_passport_status_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let record = match registry.revoke(&passport_id, request.reason.as_deref(), request.revoked_at)
    {
        Ok(record) => record,
        Err(error) if error.to_string().contains("was not found") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(record).into_response()
}

async fn handle_list_verifier_policies(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match load_verifier_policy_registry_for_admin(&state.config) {
        Ok((_, registry)) => Json(VerifierPolicyListResponse {
            configured: true,
            count: registry.policies.len(),
            policies: registry.policies.into_values().collect(),
        })
        .into_response(),
        Err(error) => plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    }
}

async fn handle_get_verifier_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let registry = match load_verifier_policy_registry_for_admin(&state.config) {
        Ok((_, registry)) => registry,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match registry.policies.get(&policy_id) {
        Some(document) => Json(document.clone()).into_response(),
        None => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("verifier policy `{policy_id}` was not found"),
        ),
    }
}

async fn handle_upsert_verifier_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
    Json(mut document): Json<SignedPassportVerifierPolicy>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_verifier_policy_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    document.body.policy_id = policy_id.clone();
    if let Err(error) = verify_signed_passport_verifier_policy(&document) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    if let Err(error) = registry.upsert(document.clone()) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(document).into_response()
}

async fn handle_delete_verifier_policy(
    State(state): State<TrustServiceState>,
    AxumPath(policy_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let (path, mut registry) = match load_verifier_policy_registry_for_admin(&state.config) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let deleted = registry.remove(&policy_id);
    if let Err(error) = registry.save(&path) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    Json(VerifierPolicyDeleteResponse { policy_id, deleted }).into_response()
}

async fn handle_create_passport_challenge(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CreatePassportChallengeRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, PASSPORT_CHALLENGES_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let challenge_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if payload.policy_id.is_some() && payload.policy.is_some() {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "challenge creation accepts either policy_id or policy, not both",
        );
    }
    let now = unix_timestamp_now();
    let (policy_ref, policy) = if let Some(policy_id) = payload.policy_id.as_deref() {
        let Some(registry) = state.verifier_policy_registry() else {
            return plain_http_error(
                StatusCode::CONFLICT,
                "trust service is missing --verifier-policies-file for policy references",
            );
        };
        let document = match registry.active_policy(policy_id, now) {
            Ok(document) => document,
            Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
        };
        if document.body.verifier != payload.verifier {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "stored verifier policy verifier must match the requested challenge verifier",
            );
        }
        (
            Some(PassportVerifierPolicyReference {
                policy_id: document.body.policy_id.clone(),
            }),
            None,
        )
    } else {
        (None, payload.policy.clone())
    };
    let challenge = match create_passport_presentation_challenge_with_reference(
        payload.verifier,
        Some(Keypair::generate().public_key().to_hex()),
        Keypair::generate().public_key().to_hex(),
        now,
        now.saturating_add(payload.ttl_seconds),
        arc_credentials::PassportPresentationOptions {
            issuer_allowlist: payload.issuers.into_iter().collect::<BTreeSet<_>>(),
            max_credentials: payload.max_credentials,
        },
        policy_ref,
        policy,
    ) {
        Ok(challenge) => challenge,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let store = match PassportVerifierChallengeStore::open(challenge_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if let Err(error) = store.register(&challenge) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let transport = match passport_presentation_transport_for_service(&state.config, &challenge) {
        Ok(transport) => transport,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    Json(CreatePassportChallengeResponse {
        challenge,
        transport,
    })
    .into_response()
}

fn verify_passport_challenge_payload(
    state: &TrustServiceState,
    payload: &VerifyPassportChallengeRequest,
    expected_challenge: Option<&PassportPresentationChallenge>,
    consume: bool,
) -> Result<PassportPresentationVerification, Response> {
    if let Err(error) = configured_verifier_challenge_db_path(&state.config) {
        return Err(plain_http_error(StatusCode::CONFLICT, &error.to_string()));
    }
    let now = unix_timestamp_now();
    let challenge = expected_challenge.unwrap_or(&payload.presentation.challenge);
    let (resolved_policy, policy_source) = match resolve_verifier_policy_for_challenge(
        state.verifier_policy_registry(),
        challenge,
        now,
    ) {
        Ok(values) => values,
        Err(error) => {
            return Err(plain_http_error(
                StatusCode::BAD_REQUEST,
                &error.to_string(),
            ))
        }
    };
    if resolved_policy
        .as_ref()
        .is_some_and(|policy| policy.require_active_lifecycle)
        && state.config.passport_statuses_file.is_none()
    {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "passport verifier policy requires active lifecycle enforcement, but the trust-control service is missing --passport-statuses-file",
        ));
    }
    let mut verification = match verify_passport_presentation_response_with_policy(
        &payload.presentation,
        expected_challenge,
        now,
        resolved_policy.as_ref(),
        policy_source,
    ) {
        Ok(verification) => verification,
        Err(error) => return Err(plain_http_error(StatusCode::FORBIDDEN, &error.to_string())),
    };
    match resolve_passport_lifecycle_for_service(&state.config, &payload.presentation.passport, now)
    {
        Ok(lifecycle) => {
            verification.passport_lifecycle = lifecycle.clone();
            if let Some(policy_evaluation) = verification.policy_evaluation.as_mut() {
                if policy_evaluation.policy.require_active_lifecycle {
                    if let Some(lifecycle) = lifecycle {
                        if lifecycle.state != PassportLifecycleState::Active {
                            let reason = passport_lifecycle_reason(&lifecycle);
                            policy_evaluation.accepted = false;
                            policy_evaluation.matched_credential_indexes.clear();
                            policy_evaluation.matched_issuers.clear();
                            if !policy_evaluation
                                .passport_reasons
                                .iter()
                                .any(|existing| existing == &reason)
                            {
                                policy_evaluation.passport_reasons.push(reason);
                            }
                            verification.accepted = false;
                        }
                    }
                }
            }
        }
        Err(error) => return Err(plain_http_error(StatusCode::FORBIDDEN, &error.to_string())),
    }
    if consume {
        match consume_challenge_if_configured(&state.config, challenge, now) {
            Ok(replay_state) => verification.replay_state = replay_state,
            Err(error) => return Err(plain_http_error(StatusCode::FORBIDDEN, &error.to_string())),
        }
    }
    Ok(verification)
}

async fn handle_verify_passport_challenge(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyPassportChallengeRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, PASSPORT_CHALLENGE_VERIFY_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    match verify_passport_challenge_payload(
        &state,
        &payload,
        payload.expected_challenge.as_ref(),
        true,
    ) {
        Ok(verification) => Json(verification).into_response(),
        Err(response) => response,
    }
}

async fn handle_public_get_passport_challenge(
    State(state): State<TrustServiceState>,
    AxumPath(challenge_id): AxumPath<String>,
) -> Response {
    let challenge_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match PassportVerifierChallengeStore::open(challenge_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match store.fetch_active(&challenge_id, unix_timestamp_now()) {
        Ok(challenge) => Json(challenge).into_response(),
        Err(error) if error.to_string().contains("not registered") => {
            plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

async fn handle_public_verify_passport_challenge(
    State(state): State<TrustServiceState>,
    Json(payload): Json<VerifyPassportChallengeRequest>,
) -> Response {
    match forward_post_to_leader(&state, PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let challenge_id = match payload
        .presentation
        .challenge
        .challenge_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(challenge_id) => challenge_id.to_string(),
        None => {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "public holder submission requires a non-empty challenge_id",
            )
        }
    };
    let challenge_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match PassportVerifierChallengeStore::open(challenge_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let stored_challenge = match store.fetch_active(&challenge_id, unix_timestamp_now()) {
        Ok(challenge) => challenge,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Some(expected_challenge) = payload.expected_challenge.as_ref() {
        if canonical_json_bytes(expected_challenge).ok()
            != canonical_json_bytes(&stored_challenge).ok()
        {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "provided expected challenge does not match the stored verifier challenge",
            );
        }
    }
    match verify_passport_challenge_payload(&state, &payload, Some(&stored_challenge), true) {
        Ok(verification) => Json(verification).into_response(),
        Err(response) => response,
    }
}

async fn handle_create_oid4vp_request(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<CreateOid4vpRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, PASSPORT_OID4VP_REQUESTS_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let now = unix_timestamp_now();
    let request = match build_oid4vp_request_for_service(&state.config, &payload, now) {
        Ok(request) => request,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let signing_key = match resolve_oid4vp_verifier_signing_key(&state.config) {
        Ok(keypair) => keypair,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let mut transport = match build_oid4vp_request_transport(&request, &signing_key) {
        Ok(transport) => transport,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    transport.same_device_url = oid4vp_same_device_url(&request.request_uri);
    transport.cross_device_url =
        match oid4vp_cross_device_url(&state.config, &request.jti, &request.request_uri) {
            Ok(url) => url,
            Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
        };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if let Err(error) = store.register(&request, &transport.request_jwt) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let wallet_exchange = match build_oid4vp_wallet_exchange_response(
        &state.config,
        &request,
        &transport.request_jwt,
        WalletExchangeTransactionState::issued(
            &request.jti,
            &request.jti,
            request.iat,
            request.exp,
        ),
        &transport.same_device_url,
        &transport.cross_device_url,
    ) {
        Ok(wallet_exchange) => wallet_exchange,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(CreateOid4vpRequestResponse {
        request,
        transport,
        wallet_exchange,
    })
    .into_response()
}

async fn handle_public_get_wallet_exchange(
    State(state): State<TrustServiceState>,
    AxumPath(request_id): AxumPath<String>,
) -> Response {
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let snapshot = match store.snapshot(&request_id, unix_timestamp_now()) {
        Ok(snapshot) => snapshot,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    let same_device_url = oid4vp_same_device_url(&snapshot.request.request_uri);
    let cross_device_url = match oid4vp_cross_device_url(
        &state.config,
        &snapshot.request.jti,
        &snapshot.request.request_uri,
    ) {
        Ok(url) => url,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    match build_oid4vp_wallet_exchange_response(
        &state.config,
        &snapshot.request,
        &snapshot.request_jwt,
        snapshot.transaction,
        &same_device_url,
        &cross_device_url,
    ) {
        Ok(response) => Json::<WalletExchangeStatusResponse>(response).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_public_get_oid4vp_request(
    State(state): State<TrustServiceState>,
    AxumPath(request_id): AxumPath<String>,
) -> Response {
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let (request, request_jwt) = match store.fetch_active(&request_id, unix_timestamp_now()) {
        Ok(values) => values,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let trusted_public_keys = match resolve_oid4vp_verifier_trusted_public_keys(&state.config) {
        Ok(keys) => keys,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    if let Err(error) = verify_signed_oid4vp_request_object_with_any_key(
        &request_jwt,
        &trusted_public_keys,
        unix_timestamp_now(),
    ) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    if request.jti != request_id {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored OID4VP request payload did not match its request_id",
        );
    }
    let mut response = request_jwt.into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/oauth-authz-req+jwt"),
    );
    response
}

async fn handle_public_launch_oid4vp_request(
    State(state): State<TrustServiceState>,
    AxumPath(request_id): AxumPath<String>,
) -> Response {
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let (request, _) = match store.fetch_active(&request_id, unix_timestamp_now()) {
        Ok(values) => values,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    Redirect::temporary(&oid4vp_same_device_url(&request.request_uri)).into_response()
}

async fn handle_public_submit_oid4vp_response(
    State(state): State<TrustServiceState>,
    Form(payload): Form<Oid4vpDirectPostForm>,
) -> Response {
    let unverified_response = match inspect_oid4vp_direct_post_response(&payload.response) {
        Ok(response) => response,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let request_id = unverified_response.presentation_submission.id.clone();
    if request_id.trim().is_empty() {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "OID4VP direct-post response requires a non-empty presentation_submission.id",
        );
    }
    let request_db_path = match configured_verifier_challenge_db_path(&state.config) {
        Ok(path) => path,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let store = match Oid4vpVerifierTransactionStore::open(request_db_path) {
        Ok(store) => store,
        Err(error) => return plain_http_error(StatusCode::CONFLICT, &error.to_string()),
    };
    let now = unix_timestamp_now();
    let (request, request_jwt) = match store.fetch_active(&request_id, now) {
        Ok(values) => values,
        Err(error) if error.to_string().contains("not registered") => {
            return plain_http_error(StatusCode::NOT_FOUND, &error.to_string())
        }
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let credential = match inspect_arc_passport_sd_jwt_vc_unverified(&unverified_response.vp_token)
    {
        Ok(credential) => credential,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let issuer_public_keys =
        match resolve_portable_issuer_public_keys(&state.config, &credential.issuer) {
            Ok(keys) => keys,
            Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
        };
    let mut verification = match verify_oid4vp_direct_post_response_with_any_issuer_key(
        &payload.response,
        &request,
        &issuer_public_keys,
        now,
    ) {
        Ok(verification) => verification,
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    };
    let lifecycle = match resolve_oid4vp_passport_lifecycle(
        &state.config,
        &verification.passport_id,
        verification.passport_status.as_ref(),
    ) {
        Ok(lifecycle) => lifecycle,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if let Some(lifecycle) = lifecycle.as_ref() {
        if lifecycle.state != PassportLifecycleState::Active {
            return plain_http_error(StatusCode::FORBIDDEN, &passport_lifecycle_reason(lifecycle));
        }
    }
    if let Err(error) = store.consume(&request, &request_jwt, now) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    verification.exchange_transaction = Some(WalletExchangeTransactionState::consumed(
        &request.jti,
        &request.jti,
        request.iat,
        request.exp,
        now,
    ));
    verification.identity_assertion = request.identity_assertion.clone();
    Json(verification).into_response()
}

async fn handle_federated_issue(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<FederatedIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, FEDERATED_ISSUE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    if let Some(advertise_url) = state.config.advertise_url.as_deref() {
        if payload.expected_challenge.verifier != advertise_url {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "expected challenge verifier must match the trust-control service advertise URL",
            );
        }
    }
    let now = unix_timestamp_now();
    if let Some(policy) = payload.delegation_policy.as_ref() {
        if let Err(error) = verify_federated_delegation_policy(policy)
            .and_then(|_| ensure_federated_delegation_policy_active(policy, now))
        {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
        if policy.body.verifier != payload.expected_challenge.verifier {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "federated delegation policy verifier must match the expected passport challenge verifier",
            );
        }
        if let Some(advertise_url) = state.config.advertise_url.as_deref() {
            if policy.body.verifier != advertise_url {
                return plain_http_error(
                    StatusCode::BAD_REQUEST,
                    "federated delegation policy verifier must match the trust-control service advertise URL",
                );
            }
        }
        if let Err(error) =
            ensure_requested_capability_within_delegation_policy(&payload.capability, policy, now)
        {
            return plain_http_error(StatusCode::FORBIDDEN, &error.to_string());
        }
    }
    if let Some(upstream_capability_id) = payload.upstream_capability_id.as_deref() {
        match payload
            .delegation_policy
            .as_ref()
            .and_then(|policy| policy.body.parent_capability_id.as_deref())
        {
            Some(parent_capability_id) if parent_capability_id == upstream_capability_id => {}
            _ => {
                return plain_http_error(
                    StatusCode::BAD_REQUEST,
                    "multi-hop federated issuance requires a delegation policy bound to the exact upstream capability id",
                );
            }
        }
    } else if payload
        .delegation_policy
        .as_ref()
        .and_then(|policy| policy.body.parent_capability_id.as_deref())
        .is_some()
    {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "delegation policy parent_capability_id requires --upstream-capability-id on the issuance request",
        );
    }

    let (resolved_policy, policy_source) = match resolve_verifier_policy_for_challenge(
        state.verifier_policy_registry(),
        &payload.expected_challenge,
        now,
    ) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    if resolved_policy.is_none() {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "federated issuance requires an embedded or stored verifier policy",
        );
    }
    if resolved_policy
        .as_ref()
        .is_some_and(|policy| policy.require_active_lifecycle)
        && state.config.passport_statuses_file.is_none()
    {
        return plain_http_error(
            StatusCode::CONFLICT,
            "passport verifier policy requires active lifecycle enforcement, but the trust-control service is missing --passport-statuses-file",
        );
    }

    let mut verification = match verify_passport_presentation_response_with_policy(
        &payload.presentation,
        Some(&payload.expected_challenge),
        now,
        resolved_policy.as_ref(),
        policy_source,
    ) {
        Ok(verification) => verification,
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    };
    match resolve_passport_lifecycle_for_service(&state.config, &payload.presentation.passport, now)
    {
        Ok(lifecycle) => {
            verification.passport_lifecycle = lifecycle.clone();
            if let Some(policy_evaluation) = verification.policy_evaluation.as_mut() {
                if policy_evaluation.policy.require_active_lifecycle {
                    if let Some(lifecycle) = lifecycle {
                        if lifecycle.state != PassportLifecycleState::Active {
                            let reason = passport_lifecycle_reason(&lifecycle);
                            policy_evaluation.accepted = false;
                            policy_evaluation.matched_credential_indexes.clear();
                            policy_evaluation.matched_issuers.clear();
                            if !policy_evaluation
                                .passport_reasons
                                .iter()
                                .any(|existing| existing == &reason)
                            {
                                policy_evaluation.passport_reasons.push(reason);
                            }
                            verification.accepted = false;
                        }
                    }
                }
            }
        }
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    }
    match consume_challenge_if_configured(&state.config, &payload.expected_challenge, now) {
        Ok(replay_state) => verification.replay_state = replay_state,
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    }
    if !verification.accepted {
        return plain_http_error(
            StatusCode::FORBIDDEN,
            "passport presentation did not satisfy the verifier policy",
        );
    }
    let subject_did = match DidArc::from_str(&verification.subject) {
        Ok(subject_did) => subject_did,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let subject_public_key = subject_did.public_key();
    let subject_public_key_hex = subject_public_key.to_hex();
    let mut enterprise_audit = None;
    if let Some(identity) = payload.enterprise_identity.as_ref() {
        let validated_provider = identity
            .provider_record_id
            .as_deref()
            .and_then(|provider_id| state.validated_enterprise_provider(provider_id));
        let lane_active = identity.provider_record_id.is_some();
        let mut audit =
            build_enterprise_admission_audit(identity, &subject_public_key_hex, validated_provider);
        if identity.provider_id.trim().is_empty() {
            audit.decision_reason = Some("enterprise identity is missing provider_id".to_string());
            return enterprise_admission_response(
                StatusCode::FORBIDDEN,
                "enterprise-provider admission requires provider_id",
                &audit,
            );
        }
        if identity.principal.trim().is_empty() {
            audit.decision_reason = Some("enterprise identity is missing principal".to_string());
            return enterprise_admission_response(
                StatusCode::FORBIDDEN,
                "enterprise-provider admission requires principal",
                &audit,
            );
        }
        if identity.subject_key.trim().is_empty() {
            audit.decision_reason = Some("enterprise identity is missing subject_key".to_string());
            return enterprise_admission_response(
                StatusCode::FORBIDDEN,
                "enterprise-provider admission requires subject_key",
                &audit,
            );
        }
        if lane_active {
            let Some(_provider) = validated_provider else {
                audit.decision_reason = Some(
                    "enterprise-provider lane is active but provider_record_id is not validated"
                        .to_string(),
                );
                return enterprise_admission_response(
                    StatusCode::FORBIDDEN,
                    "enterprise-provider lane requires a validated provider record",
                    &audit,
                );
            };
            let Some(policy) = payload.admission_policy.as_ref() else {
                audit.decision_reason = Some(
                    "enterprise-provider lane is active but no admission policy was provided"
                        .to_string(),
                );
                return enterprise_admission_response(
                    StatusCode::FORBIDDEN,
                    "enterprise-provider lane requires an admission policy with enterprise origin rules",
                    &audit,
                );
            };
            let Some(profile_id) = arc_policy::selected_origin_profile_id(
                policy,
                &enterprise_origin_context(identity),
            ) else {
                audit.decision_reason = Some(
                    "enterprise identity did not match any configured enterprise origin profile"
                        .to_string(),
                );
                return enterprise_admission_response(
                    StatusCode::FORBIDDEN,
                    "enterprise identity did not satisfy any configured origin profile",
                    &audit,
                );
            };
            audit.matched_origin_profile = Some(profile_id);
            audit.decision_reason = Some(
                "enterprise-provider lane matched the configured enterprise origin profile"
                    .to_string(),
            );
        } else {
            audit.decision_reason = Some(
                "enterprise observability is present but no validated provider-admin record activated the enterprise-provider lane"
                    .to_string(),
            );
        }
        enterprise_audit = Some(audit);
    }
    let mut store =
        if payload.delegation_policy.is_some() || payload.upstream_capability_id.is_some() {
            match open_receipt_store(&state.config) {
                Ok(store) => Some(store),
                Err(response) => return response,
            }
        } else {
            None
        };
    let upstream_parent = if let Some(upstream_capability_id) =
        payload.upstream_capability_id.as_deref()
    {
        let Some(store) = store.as_ref() else {
            return plain_http_error(
                StatusCode::CONFLICT,
                "multi-hop federated issuance requires --receipt-db so imported upstream evidence can be resolved",
            );
        };
        match store.get_federated_share_for_capability(upstream_capability_id) {
            Ok(Some((share, snapshot))) => {
                if let Some(policy) = payload.delegation_policy.as_ref() {
                    if share.signer_public_key != policy.body.signer_public_key.to_hex() {
                        return plain_http_error(
                            StatusCode::FORBIDDEN,
                            "delegation policy signer must match the signer that shared the imported upstream evidence package",
                        );
                    }
                }
                if let Err(error) = ensure_requested_capability_within_parent_snapshot(
                    &payload.capability,
                    &snapshot,
                    now,
                ) {
                    return plain_http_error(StatusCode::FORBIDDEN, &error.to_string());
                }
                Some((share.share_id, snapshot))
            }
            Ok(None) => {
                return plain_http_error(
                    StatusCode::NOT_FOUND,
                    "imported upstream capability was not found in the local federated evidence-share index",
                );
            }
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        }
    } else {
        None
    };
    match load_capability_authority(&state.config) {
        Ok(authority) => {
            if let Some(policy) = payload.delegation_policy.as_ref() {
                if !authority
                    .trusted_public_keys()
                    .iter()
                    .any(|key| key == &policy.body.signer_public_key)
                {
                    return plain_http_error(
                        StatusCode::FORBIDDEN,
                        "federated delegation policy signer is not trusted by the local capability authority",
                    );
                }
            }
            match authority.issue_capability(
                subject_public_key,
                payload.capability.scope.clone(),
                payload.capability.ttl,
            ) {
                Ok(capability) => {
                    let mut delegation_anchor_capability_id = None;
                    if let Some(policy) = payload.delegation_policy.as_ref() {
                        let Some(store) = store.as_mut() else {
                            return plain_http_error(
                                StatusCode::CONFLICT,
                                "federated delegation issuance requires --receipt-db so the lineage anchor can be persisted",
                            );
                        };
                        let anchor_snapshot = match build_federated_delegation_anchor_snapshot(
                            policy,
                            &subject_public_key_hex,
                            &payload.expected_challenge,
                            now,
                            upstream_parent.as_ref().map(|(_, snapshot)| snapshot),
                        ) {
                            Ok(snapshot) => snapshot,
                            Err(error) => {
                                return plain_http_error(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    &error.to_string(),
                                )
                            }
                        };
                        let child_snapshot = match build_capability_snapshot(
                            &capability,
                            anchor_snapshot.delegation_depth.saturating_add(1),
                            Some(anchor_snapshot.capability_id.clone()),
                        ) {
                            Ok(snapshot) => snapshot,
                            Err(error) => {
                                return plain_http_error(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    &error.to_string(),
                                )
                            }
                        };
                        if let Err(error) = store.upsert_capability_snapshot(&anchor_snapshot) {
                            return plain_http_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &error.to_string(),
                            );
                        }
                        if let Some((share_id, parent_snapshot)) = upstream_parent.as_ref() {
                            if let Err(error) = store.record_federated_lineage_bridge(
                                &anchor_snapshot.capability_id,
                                &parent_snapshot.capability_id,
                                Some(share_id.as_str()),
                            ) {
                                return plain_http_error(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    &error.to_string(),
                                );
                            }
                        }
                        if let Err(error) = store.upsert_capability_snapshot(&child_snapshot) {
                            return plain_http_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &error.to_string(),
                            );
                        }
                        delegation_anchor_capability_id = Some(anchor_snapshot.capability_id);
                    }
                    Json(FederatedIssueResponse {
                        subject: verification.subject.clone(),
                        subject_public_key: subject_public_key_hex,
                        verification,
                        capability,
                        enterprise_identity_provenance: payload
                            .enterprise_identity
                            .as_ref()
                            .map(EnterpriseIdentityProvenance::from),
                        enterprise_audit,
                        delegation_anchor_capability_id,
                    })
                    .into_response()
                }
                Err(arc_kernel::KernelError::CapabilityIssuanceDenied(error)) => {
                    if let Some(audit) = enterprise_audit.as_ref() {
                        enterprise_admission_response(StatusCode::FORBIDDEN, &error, audit)
                    } else {
                        plain_http_error(StatusCode::FORBIDDEN, &error)
                    }
                }
                Err(error) => {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                }
            }
        }
        Err(response) => response,
    }
}

async fn handle_list_revocations(
    State(state): State<TrustServiceState>,
    Query(query): Query<RevocationQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_revocation_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let revocations =
        match store.list_revocations(list_limit(query.limit), query.capability_id.as_deref()) {
            Ok(revocations) => revocations,
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            }
        };
    let revoked = query
        .capability_id
        .as_deref()
        .map(|capability_id| store.is_revoked(capability_id))
        .transpose();
    let revoked = match revoked {
        Ok(value) => value,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(revocation_list_response(
        query.capability_id,
        revoked,
        revocations,
    ))
    .into_response()
}

async fn handle_revoke_capability(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<RevokeCapabilityRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, REVOCATIONS_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_revocation_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.revoke(&payload.capability_id) {
        Ok(newly_revoked) => respond_after_leader_visible_write(
            &state,
            "revocation was not visible on the leader after write",
            || {
                let revoked = store.is_revoked(&payload.capability_id).map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?;
                if revoked {
                    Ok(Some(RevokeCapabilityResponse {
                        capability_id: payload.capability_id.clone(),
                        revoked: true,
                        newly_revoked,
                    }))
                } else {
                    Ok(None)
                }
            },
        ),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_list_tool_receipts(
    State(state): State<TrustServiceState>,
    Query(query): Query<ToolReceiptQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let receipts = match store.list_tool_receipts(
        list_limit(query.limit),
        query.capability_id.as_deref(),
        query.tool_server.as_deref(),
        query.tool_name.as_deref(),
        query.decision.as_deref(),
    ) {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    let receipts = match receipts
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };

    Json(ReceiptListResponse {
        configured: true,
        backend: "sqlite".to_string(),
        kind: "tool".to_string(),
        count: receipts.len(),
        filters: json!({
            "capabilityId": query.capability_id,
            "toolServer": query.tool_server,
            "toolName": query.tool_name,
            "decision": query.decision,
        }),
        receipts,
    })
    .into_response()
}

async fn handle_append_tool_receipt(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(receipt): Json<ArcReceipt>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, TOOL_RECEIPTS_PATH, &receipt).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.append_arc_receipt(&receipt) {
        Ok(()) => respond_after_leader_visible_write(
            &state,
            "tool receipt was not visible on the leader after write",
            || {
                let receipts = store
                    .list_tool_receipts(
                        MAX_LIST_LIMIT,
                        Some(&receipt.capability_id),
                        Some(&receipt.tool_server),
                        Some(&receipt.tool_name),
                        Some(decision_kind(&receipt.decision)),
                    )
                    .map_err(|error| {
                        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                    })?;
                if receipts
                    .into_iter()
                    .any(|candidate| candidate.id == receipt.id)
                {
                    Ok(Some(json!({
                        "stored": true,
                        "receiptId": receipt.id.clone(),
                    })))
                } else {
                    Ok(None)
                }
            },
        ),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_list_child_receipts(
    State(state): State<TrustServiceState>,
    Query(query): Query<ChildReceiptQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let receipts = match store.list_child_receipts(
        list_limit(query.limit),
        query.session_id.as_deref(),
        query.parent_request_id.as_deref(),
        query.request_id.as_deref(),
        query.operation_kind.as_deref(),
        query.terminal_state.as_deref(),
    ) {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    let receipts = match receipts
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };

    Json(ReceiptListResponse {
        configured: true,
        backend: "sqlite".to_string(),
        kind: "child".to_string(),
        count: receipts.len(),
        filters: json!({
            "sessionId": query.session_id,
            "parentRequestId": query.parent_request_id,
            "requestId": query.request_id,
            "operationKind": query.operation_kind,
            "terminalState": query.terminal_state,
        }),
        receipts,
    })
    .into_response()
}

async fn handle_query_receipts(
    State(state): State<TrustServiceState>,
    Query(query): Query<ReceiptQueryHttpQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let kernel_query = ReceiptQuery {
        capability_id: query.capability_id.clone(),
        tool_server: query.tool_server.clone(),
        tool_name: query.tool_name.clone(),
        outcome: query.outcome.clone(),
        since: query.since,
        until: query.until,
        min_cost: query.min_cost,
        max_cost: query.max_cost,
        cursor: query.cursor,
        limit: list_limit(query.limit),
        agent_subject: query.agent_subject.clone(),
    };
    let result = match store.query_receipts(&kernel_query) {
        Ok(result) => result,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    let receipts = match result
        .receipts
        .into_iter()
        .map(|stored| serde_json::to_value(stored.receipt))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(ReceiptQueryResponse {
        total_count: result.total_count,
        next_cursor: result.next_cursor,
        receipts,
    })
    .into_response()
}

async fn handle_receipt_analytics(
    State(state): State<TrustServiceState>,
    Query(query): Query<ReceiptAnalyticsQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.query_receipt_analytics(&query) {
        Ok(response) => Json::<ReceiptAnalyticsResponse>(response).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_evidence_export(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<evidence_export::RemoteEvidenceExportRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let prepared = match evidence_export::prepare_evidence_export(
        request.query,
        request.require_proofs,
        request.federation_policy,
    ) {
        Ok(prepared) => prepared,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let bundle = match store.build_evidence_export_bundle(&prepared.query) {
        Ok(bundle) => bundle,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    if let Err(error) =
        evidence_export::validate_evidence_bundle_requirements(&bundle, prepared.require_proofs)
    {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    Json(evidence_export::RemoteEvidenceExportResponse {
        bundle,
        federation_policy: prepared.federation_policy,
    })
    .into_response()
}

async fn handle_evidence_import(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<evidence_export::RemoteEvidenceImportRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, EVIDENCE_IMPORT_PATH, &request).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    if let Err(error) = evidence_export::validate_import_package_data(&request.package) {
        return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    let share_import = match evidence_export::build_federated_share_import(&request.package) {
        Ok(share) => share,
        Err(error) => {
            return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string());
        }
    };
    let mut store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.import_federated_evidence_share(&share_import) {
        Ok(share) => Json(evidence_export::RemoteEvidenceImportResponse { share }).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_cost_attribution_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<CostAttributionQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.query_cost_attribution_report(&query) {
        Ok(report) => Json::<CostAttributionReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_shared_evidence_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<SharedEvidenceQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.query_shared_evidence_report(&query) {
        Ok(report) => Json::<SharedEvidenceReferenceReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_operator_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let budget_store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_operator_report(&receipt_store, &budget_store, &query) {
        Ok(report) => Json::<OperatorReport>(report).into_response(),
        Err(response) => response,
    }
}

async fn handle_behavioral_feed_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<BehavioralFeedQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "behavioral feed export requires --receipt-db on the trust-control service",
            );
        }
    };

    match build_signed_behavioral_feed(
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &query,
    ) {
        Ok(feed) => Json::<SignedBehavioralFeed>(feed).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_exposure_ledger_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let keypair = match load_behavioral_feed_signing_keypair(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
    ) {
        Ok(keypair) => keypair,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };

    match build_exposure_ledger_report(&receipt_store, &query) {
        Ok(report) => match SignedExposureLedgerReport::sign(report, &keypair) {
            Ok(signed) => Json::<SignedExposureLedgerReport>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

async fn handle_credit_scorecard_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "credit scorecard export requires --receipt-db on the trust-control service",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let keypair = match load_behavioral_feed_signing_keypair(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
    ) {
        Ok(keypair) => keypair,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };

    match build_credit_scorecard_report(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.issuance_policy.as_ref(),
        &query,
    ) {
        Ok(report) => match SignedCreditScorecardReport::sign(report, &keypair) {
            Ok(signed) => Json::<SignedCreditScorecardReport>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

async fn handle_credit_facility_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "credit facility evaluation requires --receipt-db on the trust-control service",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_credit_facility_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        state.config.issuance_policy.as_ref(),
        &query,
    ) {
        Ok(report) => Json::<CreditFacilityReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_issue_credit_facility(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CreditFacilityIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "credit facility issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_credit_facility_detailed(
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        state.config.issuance_policy.as_ref(),
        &request.query,
        request.supersedes_facility_id.as_deref(),
    ) {
        Ok(facility) => Json::<SignedCreditFacility>(facility).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_query_credit_facilities(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditFacilityListQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_credit_facilities(&query) {
        Ok(report) => Json::<CreditFacilityListReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_credit_bond_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<ExposureLedgerQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "credit bond evaluation requires --receipt-db on the trust-control service",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_credit_bond_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        state.config.issuance_policy.as_ref(),
        &query,
    ) {
        Ok(report) => Json::<CreditBondReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_issue_credit_bond(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CreditBondIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "credit bond issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_credit_bond_detailed(
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        state.config.issuance_policy.as_ref(),
        &request.query,
        request.supersedes_bond_id.as_deref(),
    ) {
        Ok(bond) => Json::<SignedCreditBond>(bond).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_query_credit_bonds(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditBondListQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_credit_bonds(&query) {
        Ok(report) => Json::<CreditBondListReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_credit_bonded_execution_simulation_report(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CreditBondedExecutionSimulationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_credit_bonded_execution_simulation_report_from_store(&receipt_store, &request) {
        Ok(report) => Json::<CreditBondedExecutionSimulationReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_credit_loss_lifecycle_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditLossLifecycleQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_credit_loss_lifecycle_report_from_store(&receipt_store, &query) {
        Ok(report) => Json::<CreditLossLifecycleReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_issue_credit_loss_lifecycle(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<CreditLossLifecycleIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "credit loss lifecycle issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_credit_loss_lifecycle_detailed(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request.query,
    ) {
        Ok(event) => Json::<SignedCreditLossLifecycle>(event).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_query_credit_loss_lifecycle(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditLossLifecycleListQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_credit_loss_lifecycle(&query) {
        Ok(report) => Json::<CreditLossLifecycleListReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_credit_backtest_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditBacktestQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "credit backtests require --receipt-db on the trust-control service",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_credit_backtest_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        state.config.issuance_policy.as_ref(),
        &query,
    ) {
        Ok(report) => Json::<CreditBacktestReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_credit_provider_risk_package_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<CreditProviderRiskPackageQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "provider risk package export requires --receipt-db on the trust-control service",
            );
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let keypair = match load_behavioral_feed_signing_keypair(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
    ) {
        Ok(keypair) => keypair,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };

    match build_credit_provider_risk_package_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        state.config.issuance_policy.as_ref(),
        &keypair,
        &query,
    ) {
        Ok(report) => match SignedCreditProviderRiskPackage::sign(report, &keypair) {
            Ok(signed) => Json::<SignedCreditProviderRiskPackage>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

async fn handle_issue_liability_provider(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityProviderIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability provider issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_provider(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request.report,
        request.supersedes_provider_record_id.as_deref(),
    ) {
        Ok(provider) => Json::<SignedLiabilityProvider>(provider).into_response(),
        Err(CliError::Other(message)) => plain_http_error(StatusCode::BAD_REQUEST, &message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_query_liability_providers(
    State(state): State<TrustServiceState>,
    Query(query): Query<LiabilityProviderListQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match receipt_store.query_liability_providers(&query) {
        Ok(report) => Json::<LiabilityProviderListReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_resolve_liability_provider(
    State(state): State<TrustServiceState>,
    Query(query): Query<LiabilityProviderResolutionQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match receipt_store.resolve_liability_provider(&query) {
        Ok(report) => Json::<LiabilityProviderResolutionReport>(report).into_response(),
        Err(error) => trust_http_error_from_receipt_store(error).into_response(),
    }
}

async fn handle_issue_liability_quote_request(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityQuoteRequestIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability quote request issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_quote_request(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityQuoteRequest>(artifact).into_response(),
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_quote_response(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityQuoteResponseIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability quote response issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_quote_response(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityQuoteResponse>(artifact).into_response(),
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_placement(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityPlacementIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability placement issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_placement(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityPlacement>(artifact).into_response(),
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_bound_coverage(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityBoundCoverageIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability bound coverage issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_bound_coverage(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityBoundCoverage>(artifact).into_response(),
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_query_liability_market_workflows(
    State(state): State<TrustServiceState>,
    Query(query): Query<LiabilityMarketWorkflowQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match receipt_store.query_liability_market_workflows(&query) {
        Ok(report) => Json::<LiabilityMarketWorkflowReport>(report).into_response(),
        Err(error) => trust_http_error_from_receipt_store(error).into_response(),
    }
}

async fn handle_issue_liability_claim_package(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityClaimPackageIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability claim package issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_claim_package(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityClaimPackage>(artifact).into_response(),
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_claim_response(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityClaimResponseIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability claim response issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_claim_response(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityClaimResponse>(artifact).into_response(),
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_claim_dispute(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityClaimDisputeIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability claim dispute issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_claim_dispute(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityClaimDispute>(artifact).into_response(),
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_liability_claim_adjudication(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<LiabilityClaimAdjudicationIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::CONFLICT,
                "liability claim adjudication issuance requires --receipt-db on the trust-control service",
            );
        }
    };

    match issue_signed_liability_claim_adjudication(
        receipt_db_path,
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        &request,
    ) {
        Ok(artifact) => Json::<SignedLiabilityClaimAdjudication>(artifact).into_response(),
        Err(CliError::Other(message)) => liability_market_http_error(&message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_query_liability_claim_workflows(
    State(state): State<TrustServiceState>,
    Query(query): Query<LiabilityClaimWorkflowQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match receipt_store.query_liability_claim_workflows(&query) {
        Ok(report) => Json::<LiabilityClaimWorkflowReport>(report).into_response(),
        Err(error) => trust_http_error_from_receipt_store(error).into_response(),
    }
}

async fn handle_runtime_attestation_appraisal_report(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<RuntimeAttestationAppraisalRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    match build_signed_runtime_attestation_appraisal_report(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        state.config.runtime_assurance_policy.as_ref(),
        &request.runtime_attestation,
    ) {
        Ok(report) => Json::<SignedRuntimeAttestationAppraisalReport>(report).into_response(),
        Err(CliError::Other(message)) => plain_http_error(StatusCode::BAD_REQUEST, &message),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_settlement_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_settlement_reconciliation_report(&query) {
        Ok(report) => Json::<SettlementReconciliationReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_record_settlement_reconciliation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<SettlementReconciliationUpdateRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.upsert_settlement_reconciliation(
        &request.receipt_id,
        request.reconciliation_state,
        request.note.as_deref(),
    ) {
        Ok(updated_at) => Json(SettlementReconciliationUpdateResponse {
            receipt_id: request.receipt_id,
            reconciliation_state: request.reconciliation_state,
            note: request.note,
            updated_at: updated_at as u64,
        })
        .into_response(),
        Err(ReceiptStoreError::NotFound(message)) => {
            plain_http_error(StatusCode::NOT_FOUND, &message)
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_metered_billing_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_metered_billing_reconciliation_report(&query) {
        Ok(report) => Json::<MeteredBillingReconciliationReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_authorization_context_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_authorization_context_report(&query) {
        Ok(report) => Json::<AuthorizationContextReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_authorization_profile_metadata_report(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    Json::<ArcOAuthAuthorizationMetadataReport>(
        receipt_store.authorization_profile_metadata_report(),
    )
    .into_response()
}

async fn handle_authorization_review_pack_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<OperatorReportQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_authorization_review_pack(&query) {
        Ok(report) => Json::<ArcOAuthAuthorizationReviewPack>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_underwriting_policy_input(
    State(state): State<TrustServiceState>,
    Query(query): Query<UnderwritingPolicyInputQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trust service is missing receipt_db_path for underwriting input queries",
            )
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let keypair = match load_behavioral_feed_signing_keypair(
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
    ) {
        Ok(keypair) => keypair,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };

    match build_underwriting_policy_input(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &query,
    ) {
        Ok(report) => match SignedUnderwritingPolicyInput::sign(report, &keypair) {
            Ok(signed) => Json::<SignedUnderwritingPolicyInput>(signed).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error.into_response(),
    }
}

async fn handle_underwriting_decision_report(
    State(state): State<TrustServiceState>,
    Query(query): Query<UnderwritingPolicyInputQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trust service is missing receipt_db_path for underwriting decision queries",
            )
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_underwriting_decision_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &query,
    ) {
        Ok(report) => Json::<UnderwritingDecisionReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_underwriting_simulation_report(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<UnderwritingSimulationRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trust service is missing receipt_db_path for underwriting simulation queries",
            )
        }
    };
    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match build_underwriting_simulation_report_from_store(
        &receipt_store,
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &request,
    ) {
        Ok(report) => Json::<UnderwritingSimulationReport>(report).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_query_underwriting_decisions(
    State(state): State<TrustServiceState>,
    Query(query): Query<UnderwritingDecisionQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };

    match receipt_store.query_underwriting_decisions(&query) {
        Ok(report) => Json::<UnderwritingDecisionListReport>(report).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_issue_underwriting_decision(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<UnderwritingDecisionIssueRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let receipt_db_path = match state.config.receipt_db_path.as_deref() {
        Some(path) => path,
        None => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trust service is missing receipt_db_path for underwriting decision issuance",
            )
        }
    };

    match issue_signed_underwriting_decision_detailed(
        receipt_db_path,
        state.config.budget_db_path.as_deref(),
        state.config.authority_seed_path.as_deref(),
        state.config.authority_db_path.as_deref(),
        state.config.certification_registry_file.as_deref(),
        &request.query,
        request.supersedes_decision_id.as_deref(),
    ) {
        Ok(decision) => Json::<SignedUnderwritingDecision>(decision).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_create_underwriting_appeal(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<UnderwritingAppealCreateRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let mut receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match receipt_store.create_underwriting_appeal(&request) {
        Ok(record) => Json::<UnderwritingAppealRecord>(record).into_response(),
        Err(ReceiptStoreError::NotFound(message)) => {
            plain_http_error(StatusCode::NOT_FOUND, &message)
        }
        Err(ReceiptStoreError::Conflict(message)) => {
            plain_http_error(StatusCode::CONFLICT, &message)
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_resolve_underwriting_appeal(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<UnderwritingAppealResolveRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let mut receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match receipt_store.resolve_underwriting_appeal(&request) {
        Ok(record) => Json::<UnderwritingAppealRecord>(record).into_response(),
        Err(ReceiptStoreError::NotFound(message)) => {
            plain_http_error(StatusCode::NOT_FOUND, &message)
        }
        Err(ReceiptStoreError::Conflict(message)) => {
            plain_http_error(StatusCode::CONFLICT, &message)
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_record_metered_billing_reconciliation(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<MeteredBillingReconciliationUpdateRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Err(message) = validate_metered_billing_reconciliation_request(&request) {
        return plain_http_error(StatusCode::BAD_REQUEST, &message);
    }

    let receipt_store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let evidence = MeteredBillingEvidenceRecord {
        usage_evidence: arc_core::receipt::MeteredUsageEvidenceReceiptMetadata {
            evidence_kind: request.adapter_kind.clone(),
            evidence_id: request.evidence_id.clone(),
            observed_units: request.observed_units,
            evidence_sha256: request.evidence_sha256.clone(),
        },
        billed_cost: request.billed_cost.clone(),
        recorded_at: request.recorded_at,
    };

    match receipt_store.upsert_metered_billing_reconciliation(
        &request.receipt_id,
        &evidence,
        request.reconciliation_state,
        request.note.as_deref(),
    ) {
        Ok(updated_at) => Json(MeteredBillingReconciliationUpdateResponse {
            receipt_id: request.receipt_id,
            evidence,
            reconciliation_state: request.reconciliation_state,
            note: request.note,
            updated_at: updated_at as u64,
        })
        .into_response(),
        Err(ReceiptStoreError::NotFound(message)) => {
            plain_http_error(StatusCode::NOT_FOUND, &message)
        }
        Err(ReceiptStoreError::Conflict(message)) => {
            plain_http_error(StatusCode::CONFLICT, &message)
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_local_reputation(
    State(state): State<TrustServiceState>,
    AxumPath(subject_key): AxumPath<String>,
    Query(query): Query<LocalReputationQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if state.config.receipt_db_path.is_none() {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "trust service is missing receipt_db_path for local reputation queries",
        );
    }

    match issuance::inspect_local_reputation(
        &subject_key,
        state.config.receipt_db_path.as_deref(),
        state.config.budget_db_path.as_deref(),
        query.since,
        query.until,
        state.config.issuance_policy.as_ref(),
    ) {
        Ok(mut inspection) => {
            if let Some(receipt_db_path) = state.config.receipt_db_path.as_deref() {
                match reputation::build_imported_trust_report(
                    receipt_db_path,
                    &inspection.subject_key,
                    inspection.since,
                    inspection.until,
                    unix_timestamp_now(),
                    &inspection.scoring,
                ) {
                    Ok(report) => inspection.imported_trust = Some(report),
                    Err(error) => {
                        return plain_http_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &error.to_string(),
                        );
                    }
                }
            }
            Json(inspection).into_response()
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_reputation_compare(
    State(state): State<TrustServiceState>,
    AxumPath(subject_key): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<ReputationCompareRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if state.config.receipt_db_path.is_none() {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "trust service is missing receipt_db_path for reputation compare queries",
        );
    }

    let local = match issuance::inspect_local_reputation(
        &subject_key,
        state.config.receipt_db_path.as_deref(),
        state.config.budget_db_path.as_deref(),
        request.since,
        request.until,
        state.config.issuance_policy.as_ref(),
    ) {
        Ok(local) => local,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let shared_evidence = {
        let store = match open_receipt_store(&state.config) {
            Ok(store) => store,
            Err(response) => return response,
        };
        match store.query_shared_evidence_report(&SharedEvidenceQuery {
            agent_subject: Some(local.subject_key.clone()),
            since: request.since,
            until: request.until,
            ..SharedEvidenceQuery::default()
        }) {
            Ok(report) => report,
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        }
    };
    let imported_trust = match state.config.receipt_db_path.as_deref() {
        Some(receipt_db_path) => match reputation::build_imported_trust_report(
            receipt_db_path,
            &local.subject_key,
            local.since,
            local.until,
            unix_timestamp_now(),
            &local.scoring,
        ) {
            Ok(report) => Some(report),
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
            }
        },
        None => None,
    };
    match reputation::build_reputation_comparison(
        local,
        &request.passport,
        request.verifier_policy.as_ref(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0),
        shared_evidence,
        imported_trust,
    ) {
        Ok(comparison) => {
            Json::<reputation::PortableReputationComparison>(comparison).into_response()
        }
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_record_lineage_snapshot(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<RecordCapabilitySnapshotRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, LINEAGE_RECORD_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    if let Err(error) = store
        .record_capability_snapshot(&payload.capability, payload.parent_capability_id.as_deref())
    {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    respond_after_leader_visible_write(
        &state,
        "capability lineage was not visible on the leader after write",
        || {
            let visible = store
                .get_lineage(&payload.capability.id)
                .map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?
                .is_some();
            if visible {
                Ok(Some(json!({
                    "stored": true,
                    "capabilityId": payload.capability.id.clone(),
                })))
            } else {
                Ok(None)
            }
        },
    )
}

/// GET /v1/lineage/:capability_id
///
/// Returns the CapabilitySnapshot for the given capability ID, or 404 if not found.
async fn handle_get_lineage(
    State(state): State<TrustServiceState>,
    AxumPath(capability_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.get_combined_lineage(&capability_id) {
        Ok(Some(snapshot)) => Json(snapshot).into_response(),
        Ok(None) => plain_http_error(
            StatusCode::NOT_FOUND,
            &format!("capability not found: {capability_id}"),
        ),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

/// GET /v1/lineage/:capability_id/chain
///
/// Returns the full delegation chain for the given capability ID, root-first.
async fn handle_get_delegation_chain(
    State(state): State<TrustServiceState>,
    AxumPath(capability_id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.get_combined_delegation_chain(&capability_id) {
        Ok(chain) => Json(chain).into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

/// GET /v1/agents/:subject_key/receipts
///
/// Convenience endpoint: returns receipts for a given agent subject key.
/// Delegates to the same query_receipts call as GET /v1/receipts/query with
/// agentSubject set, passing through limit and cursor from query params.
async fn handle_agent_receipts(
    State(state): State<TrustServiceState>,
    AxumPath(subject_key): AxumPath<String>,
    Query(query): Query<AgentReceiptsHttpQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let kernel_query = ReceiptQuery {
        agent_subject: Some(subject_key),
        cursor: query.cursor,
        limit: list_limit(query.limit),
        ..Default::default()
    };
    let result = match store.query_receipts(&kernel_query) {
        Ok(result) => result,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    let receipts = match result
        .receipts
        .into_iter()
        .map(|stored| serde_json::to_value(stored.receipt))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(ReceiptQueryResponse {
        total_count: result.total_count,
        next_cursor: result.next_cursor,
        receipts,
    })
    .into_response()
}

async fn handle_append_child_receipt(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(receipt): Json<ChildRequestReceipt>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, CHILD_RECEIPTS_PATH, &receipt).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match store.append_child_receipt(&receipt) {
        Ok(()) => respond_after_leader_visible_write(
            &state,
            "child receipt was not visible on the leader after write",
            || {
                let receipts = store
                    .list_child_receipts(
                        MAX_LIST_LIMIT,
                        Some(receipt.session_id.as_str()),
                        Some(receipt.parent_request_id.as_str()),
                        Some(receipt.request_id.as_str()),
                        Some(receipt.operation_kind.as_str()),
                        Some(terminal_state_kind(&receipt.terminal_state)),
                    )
                    .map_err(|error| {
                        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                    })?;
                if receipts
                    .into_iter()
                    .any(|candidate| candidate.id == receipt.id)
                {
                    Ok(Some(json!({
                        "stored": true,
                        "receiptId": receipt.id.clone(),
                    })))
                } else {
                    Ok(None)
                }
            },
        ),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_list_budgets(
    State(state): State<TrustServiceState>,
    Query(query): Query<BudgetQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let usages = match store.list_usages(list_limit(query.limit), query.capability_id.as_deref()) {
        Ok(usages) => usages,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };

    Json(BudgetListResponse {
        configured: true,
        backend: "sqlite".to_string(),
        capability_id: query.capability_id,
        count: usages.len(),
        usages: usages
            .into_iter()
            .map(|usage| BudgetUsageView {
                capability_id: usage.capability_id,
                grant_index: usage.grant_index,
                invocation_count: usage.invocation_count,
                total_cost_charged: usage.total_cost_charged,
                updated_at: usage.updated_at,
                seq: None,
            })
            .collect(),
    })
    .into_response()
}

async fn handle_try_increment_budget(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<TryIncrementBudgetRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_INCREMENT_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let allowed = match store.try_increment(
        &payload.capability_id,
        payload.grant_index,
        payload.max_invocations,
    ) {
        Ok(allowed) => allowed,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    respond_after_leader_visible_write(
        &state,
        "budget state was not visible on the leader after write",
        || {
            let invocation_count = store
                .get_usage(&payload.capability_id, payload.grant_index)
                .map(|usage| usage.map(|usage| usage.invocation_count))
                .map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?;
            if budget_visibility_matches(allowed, invocation_count, payload.max_invocations) {
                Ok(Some(TryIncrementBudgetResponse {
                    capability_id: payload.capability_id.clone(),
                    grant_index: payload.grant_index,
                    allowed,
                    invocation_count,
                }))
            } else {
                Ok(None)
            }
        },
    )
}

async fn handle_try_charge_cost(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<TryChargeCostRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_CHARGE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let allowed = match store.try_charge_cost(
        &payload.capability_id,
        payload.grant_index,
        payload.max_invocations,
        payload.cost_units,
        payload.max_cost_per_invocation,
        payload.max_total_cost_units,
    ) {
        Ok(allowed) => allowed,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    respond_after_leader_visible_write(
        &state,
        "monetary budget state was not visible on the leader after write",
        || {
            let usage = store
                .get_usage(&payload.capability_id, payload.grant_index)
                .map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?;
            let invocation_count = usage.as_ref().map(|usage| usage.invocation_count);
            let total_cost_charged = usage.as_ref().map(|usage| usage.total_cost_charged);
            let visible = if allowed { usage.is_some() } else { true };
            if visible {
                Ok(Some(TryChargeCostResponse {
                    capability_id: payload.capability_id.clone(),
                    grant_index: payload.grant_index,
                    allowed,
                    invocation_count,
                    total_cost_charged,
                }))
            } else {
                Ok(None)
            }
        },
    )
}

async fn handle_reverse_charge_cost(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<ReverseChargeCostRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_REVERSE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    if let Err(error) = store.reverse_charge_cost(
        &payload.capability_id,
        payload.grant_index,
        payload.cost_units,
    ) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    respond_after_leader_visible_write(
        &state,
        "reversed monetary budget state was not visible on the leader after write",
        || {
            let usage = store
                .get_usage(&payload.capability_id, payload.grant_index)
                .map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?;
            Ok(Some(ReverseChargeCostResponse {
                capability_id: payload.capability_id.clone(),
                grant_index: payload.grant_index,
                invocation_count: usage.as_ref().map(|usage| usage.invocation_count),
                total_cost_charged: usage.as_ref().map(|usage| usage.total_cost_charged),
            }))
        },
    )
}

async fn handle_reduce_charge_cost(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(payload): Json<ReduceChargeCostRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    match forward_post_to_leader(&state, BUDGET_REDUCE_PATH, &payload).await {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let mut store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    if let Err(error) = store.reduce_charge_cost(
        &payload.capability_id,
        payload.grant_index,
        payload.cost_units,
    ) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    respond_after_leader_visible_write(
        &state,
        "reduced monetary budget state was not visible on the leader after write",
        || {
            let usage = store
                .get_usage(&payload.capability_id, payload.grant_index)
                .map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })?;
            Ok(Some(ReduceChargeCostResponse {
                capability_id: payload.capability_id.clone(),
                grant_index: payload.grant_index,
                invocation_count: usage.as_ref().map(|usage| usage.invocation_count),
                total_cost_charged: usage.as_ref().map(|usage| usage.total_cost_charged),
            }))
        },
    )
}

async fn handle_internal_cluster_status(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }

    let Some(cluster) = state.cluster.as_ref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "cluster replication is not configured",
        );
    };
    let leader_url = current_leader_url(&state).unwrap_or_else(|| {
        cluster
            .lock()
            .map(|guard| guard.self_url.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().self_url.clone())
    });
    let peers = match cluster.lock() {
        Ok(guard) => guard
            .peers
            .iter()
            .map(|(peer_url, peer_state)| PeerStatusView {
                peer_url: peer_url.clone(),
                health: peer_state.health.label().to_string(),
                last_error: peer_state.last_error.clone(),
                tool_seq: peer_state.tool_seq,
                child_seq: peer_state.child_seq,
                lineage_seq: peer_state.lineage_seq,
                revocation_cursor: peer_state
                    .revocation_cursor
                    .clone()
                    .map(revocation_cursor_view),
                budget_cursor: peer_state.budget_cursor.clone().map(budget_cursor_view),
            })
            .collect::<Vec<_>>(),
        Err(poisoned) => poisoned
            .into_inner()
            .peers
            .iter()
            .map(|(peer_url, peer_state)| PeerStatusView {
                peer_url: peer_url.clone(),
                health: peer_state.health.label().to_string(),
                last_error: peer_state.last_error.clone(),
                tool_seq: peer_state.tool_seq,
                child_seq: peer_state.child_seq,
                lineage_seq: peer_state.lineage_seq,
                revocation_cursor: peer_state
                    .revocation_cursor
                    .clone()
                    .map(revocation_cursor_view),
                budget_cursor: peer_state.budget_cursor.clone().map(budget_cursor_view),
            })
            .collect::<Vec<_>>(),
    };

    let self_url = cluster_self_url(&state).unwrap_or_default();
    Json(ClusterStatusResponse {
        self_url,
        leader_url,
        peers,
    })
    .into_response()
}

async fn handle_internal_authority_snapshot(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    if let Some(path) = state.config.authority_db_path.as_deref() {
        let authority = match SqliteCapabilityAuthority::open(path) {
            Ok(authority) => authority,
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            }
        };
        let snapshot = match authority.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            }
        };
        return Json(authority_snapshot_view(snapshot)).into_response();
    }

    plain_http_error(
        StatusCode::CONFLICT,
        "clustered authority replication requires --authority-db",
    )
}

async fn handle_internal_revocations_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<RevocationDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_revocation_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let records = match store.list_revocations_after(
        list_limit(query.limit),
        query.after_revoked_at,
        query.after_capability_id.as_deref(),
    ) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(RevocationDeltaResponse {
        records: records
            .into_iter()
            .map(|record| RevocationRecordView {
                capability_id: record.capability_id,
                revoked_at: record.revoked_at,
            })
            .collect(),
    })
    .into_response()
}

async fn handle_internal_tool_receipts_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<ReceiptDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let records = match store
        .list_tool_receipts_after_seq(query.after_seq.unwrap_or(0), list_limit(query.limit))
    {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    let records = match stored_tool_receipt_views(records) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(ReceiptDeltaResponse { records }).into_response()
}

async fn handle_internal_child_receipts_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<ReceiptDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let records = match store
        .list_child_receipts_after_seq(query.after_seq.unwrap_or(0), list_limit(query.limit))
    {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    let records = match stored_child_receipt_views(records) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(ReceiptDeltaResponse { records }).into_response()
}

async fn handle_internal_budgets_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<BudgetDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_budget_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let records = match store.list_usages_after(list_limit(query.limit), query.after_seq) {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(BudgetDeltaResponse {
        records: records
            .into_iter()
            .map(|usage| BudgetUsageView {
                capability_id: usage.capability_id,
                grant_index: usage.grant_index,
                invocation_count: usage.invocation_count,
                total_cost_charged: usage.total_cost_charged,
                updated_at: usage.updated_at,
                seq: Some(usage.seq),
            })
            .collect(),
    })
    .into_response()
}

async fn handle_internal_lineage_delta(
    State(state): State<TrustServiceState>,
    Query(query): Query<ReceiptDeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let store = match open_receipt_store(&state.config) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let records = match store
        .list_capability_snapshots_after_seq(query.after_seq.unwrap_or(0), list_limit(query.limit))
    {
        Ok(records) => records,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };
    Json(LineageDeltaResponse {
        records: stored_lineage_views(records),
    })
    .into_response()
}

async fn run_cluster_sync_loop(state: TrustServiceState) {
    loop {
        let sync_state = state.clone();
        match tokio::task::spawn_blocking(move || sync_cluster_once(&sync_state)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                warn!(error = %error, "trust-control cluster sync failed");
            }
            Err(error) => {
                warn!(error = %error, "trust-control cluster sync task panicked");
            }
        }
        tokio::time::sleep(state.config.cluster_sync_interval).await;
    }
}

fn sync_cluster_once(state: &TrustServiceState) -> Result<(), CliError> {
    let Some(cluster) = state.cluster.as_ref() else {
        return Ok(());
    };
    let peers = match cluster.lock() {
        Ok(guard) => guard.peers.keys().cloned().collect::<Vec<_>>(),
        Err(poisoned) => poisoned
            .into_inner()
            .peers
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
    };
    for peer_url in peers {
        let _ = sync_peer(state, &peer_url);
    }
    Ok(())
}

fn sync_peer(state: &TrustServiceState, peer_url: &str) -> Result<(), CliError> {
    let client = build_client(peer_url, &state.config.service_token)?;
    if let Err(error) = client.cluster_status() {
        update_peer_failure(state, peer_url, error.to_string());
        return Err(error);
    }
    update_peer_reachable(state, peer_url);
    if let Err(error) = sync_peer_authority(state, &client) {
        update_peer_sync_error(state, peer_url, error.to_string());
        return Err(error);
    }
    if let Err(error) = sync_peer_revocations(state, &client, peer_url) {
        update_peer_sync_error(state, peer_url, error.to_string());
        return Err(error);
    }
    if let Err(error) = sync_peer_tool_receipts(state, &client, peer_url) {
        update_peer_sync_error(state, peer_url, error.to_string());
        return Err(error);
    }
    if let Err(error) = sync_peer_child_receipts(state, &client, peer_url) {
        update_peer_sync_error(state, peer_url, error.to_string());
        return Err(error);
    }
    if let Err(error) = sync_peer_lineage(state, &client, peer_url) {
        update_peer_sync_error(state, peer_url, error.to_string());
        return Err(error);
    }
    if let Err(error) = sync_peer_budgets(state, &client, peer_url) {
        update_peer_sync_error(state, peer_url, error.to_string());
        return Err(error);
    }
    update_peer_success(state, peer_url);
    Ok(())
}

fn sync_peer_authority(
    state: &TrustServiceState,
    client: &TrustControlClient,
) -> Result<(), CliError> {
    let Some(path) = state.config.authority_db_path.as_deref() else {
        return Ok(());
    };
    let authority = SqliteCapabilityAuthority::open(path)?;
    let snapshot = authority_snapshot_from_view(client.authority_snapshot()?);
    authority.apply_snapshot(&snapshot)?;
    Ok(())
}

fn sync_peer_revocations(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
) -> Result<(), CliError> {
    let Some(path) = state.config.revocation_db_path.as_deref() else {
        return Ok(());
    };
    let mut store = SqliteRevocationStore::open(path)?;
    loop {
        let cursor = peer_revocation_cursor(state, peer_url);
        let response = client.revocation_deltas(&RevocationDeltaQuery {
            after_revoked_at: cursor.as_ref().map(|value| value.revoked_at),
            after_capability_id: cursor.as_ref().map(|value| value.capability_id.clone()),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        let mut last_cursor = None;
        for record in response.records {
            store.upsert_revocation(&RevocationRecord {
                capability_id: record.capability_id.clone(),
                revoked_at: record.revoked_at,
            })?;
            last_cursor = Some(RevocationCursor {
                revoked_at: record.revoked_at,
                capability_id: record.capability_id,
            });
        }
        if let Some(cursor) = last_cursor {
            update_peer_revocation_cursor(state, peer_url, cursor);
        }
    }
    Ok(())
}

fn sync_peer_tool_receipts(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
) -> Result<(), CliError> {
    let Some(path) = state.config.receipt_db_path.as_deref() else {
        return Ok(());
    };
    let mut store = SqliteReceiptStore::open(path)?;
    loop {
        let after_seq = peer_tool_seq(state, peer_url);
        let response = client.tool_receipt_deltas(&ReceiptDeltaQuery {
            after_seq: Some(after_seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        let mut last_seq = after_seq;
        for record in response.records {
            let receipt: ArcReceipt = serde_json::from_value(record.receipt)?;
            store.append_arc_receipt(&receipt)?;
            last_seq = record.seq;
        }
        update_peer_tool_seq(state, peer_url, last_seq);
    }
    Ok(())
}

fn sync_peer_child_receipts(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
) -> Result<(), CliError> {
    let Some(path) = state.config.receipt_db_path.as_deref() else {
        return Ok(());
    };
    let mut store = SqliteReceiptStore::open(path)?;
    loop {
        let after_seq = peer_child_seq(state, peer_url);
        let response = client.child_receipt_deltas(&ReceiptDeltaQuery {
            after_seq: Some(after_seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        let mut last_seq = after_seq;
        for record in response.records {
            let receipt: ChildRequestReceipt = serde_json::from_value(record.receipt)?;
            store.append_child_receipt(&receipt)?;
            last_seq = record.seq;
        }
        update_peer_child_seq(state, peer_url, last_seq);
    }
    Ok(())
}

fn sync_peer_budgets(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
) -> Result<(), CliError> {
    let Some(path) = state.config.budget_db_path.as_deref() else {
        return Ok(());
    };
    let mut store = SqliteBudgetStore::open(path)?;
    loop {
        let cursor = peer_budget_cursor(state, peer_url);
        let response = client.budget_deltas(&BudgetDeltaQuery {
            after_seq: cursor.as_ref().map(|value| value.seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        let mut last_cursor = None;
        for record in response.records {
            let seq = record.seq.ok_or_else(|| {
                CliError::Other(
                    "trust control budget delta response missing monotonic seq".to_string(),
                )
            })?;
            store.upsert_usage(&BudgetUsageRecord {
                capability_id: record.capability_id.clone(),
                grant_index: record.grant_index,
                invocation_count: record.invocation_count,
                updated_at: record.updated_at,
                seq,
                total_cost_charged: 0,
            })?;
            last_cursor = Some(BudgetCursor {
                seq,
                updated_at: record.updated_at,
                capability_id: record.capability_id,
                grant_index: record.grant_index,
            });
        }
        if let Some(cursor) = last_cursor {
            update_peer_budget_cursor(state, peer_url, cursor);
        }
    }
    Ok(())
}

fn sync_peer_lineage(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
) -> Result<(), CliError> {
    let Some(path) = state.config.receipt_db_path.as_deref() else {
        return Ok(());
    };
    let mut store = SqliteReceiptStore::open(path)?;
    loop {
        let after_seq = peer_lineage_seq(state, peer_url);
        let response = client.lineage_deltas(&ReceiptDeltaQuery {
            after_seq: Some(after_seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        let mut last_seq = after_seq;
        for record in response.records {
            store
                .upsert_capability_snapshot(&record.snapshot)
                .map_err(|error| CliError::Other(error.to_string()))?;
            last_seq = record.seq;
        }
        update_peer_lineage_seq(state, peer_url, last_seq);
    }
    Ok(())
}

fn build_cluster_state(
    config: &TrustServiceConfig,
    local_addr: SocketAddr,
) -> Result<Option<Arc<Mutex<ClusterRuntimeState>>>, CliError> {
    if !config.peer_urls.is_empty() && config.authority_seed_path.is_some() {
        return Err(CliError::Other(
            "clustered trust control requires --authority-db instead of --authority-seed-file"
                .to_string(),
        ));
    }

    if config.peer_urls.is_empty() && config.advertise_url.is_none() {
        return Ok(None);
    }

    let self_url = normalize_cluster_url(
        config
            .advertise_url
            .as_deref()
            .unwrap_or(&format!("http://{local_addr}")),
    )?;
    let mut peers = HashMap::new();
    for peer_url in &config.peer_urls {
        let peer_url = normalize_cluster_url(peer_url)?;
        if peer_url != self_url {
            peers.insert(peer_url, PeerSyncState::default());
        }
    }
    if peers.is_empty() {
        return Ok(None);
    }
    Ok(Some(Arc::new(Mutex::new(ClusterRuntimeState {
        self_url,
        peers,
    }))))
}

fn cluster_self_url(state: &TrustServiceState) -> Option<String> {
    let cluster = state.cluster.as_ref()?;
    Some(match cluster.lock() {
        Ok(guard) => guard.self_url.clone(),
        Err(poisoned) => poisoned.into_inner().self_url.clone(),
    })
}

fn current_leader_url(state: &TrustServiceState) -> Option<String> {
    let cluster = state.cluster.as_ref()?;
    let now = Instant::now();
    let (self_url, peers) = match cluster.lock() {
        Ok(guard) => (guard.self_url.clone(), guard.peers.clone()),
        Err(poisoned) => {
            let guard = poisoned.into_inner();
            (guard.self_url.clone(), guard.peers.clone())
        }
    };
    let mut candidates = vec![self_url];
    for (peer_url, peer_state) in peers {
        if peer_state.health.is_candidate(now) {
            candidates.push(peer_url);
        }
    }
    candidates.sort();
    candidates.into_iter().next()
}

fn respond_after_leader_visible_write<T, F>(
    state: &TrustServiceState,
    failure_message: &'static str,
    verify: F,
) -> Response
where
    T: Serialize,
    F: FnOnce() -> Result<Option<T>, Response>,
{
    let Some(payload) = (match verify() {
        Ok(payload) => payload,
        Err(response) => return response,
    }) else {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, failure_message);
    };
    json_response_with_leader_visibility(state, payload)
}

fn json_response_with_leader_visibility<T: Serialize>(
    state: &TrustServiceState,
    payload: T,
) -> Response {
    let mut value = match serde_json::to_value(payload) {
        Ok(value) => value,
        Err(error) => {
            return plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to serialize trust control response: {error}"),
            )
        }
    };
    let Value::Object(map) = &mut value else {
        return plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "trust control success responses must be JSON objects",
        );
    };
    if let Some(leader_url) = cluster_self_url(state) {
        map.insert("handledBy".to_string(), Value::String(leader_url.clone()));
        map.insert("leaderUrl".to_string(), Value::String(leader_url));
        map.insert("visibleAtLeader".to_string(), Value::Bool(true));
    }
    Json(value).into_response()
}

fn update_peer_success(state: &TrustServiceState, peer_url: &str) {
    if let Some(cluster) = state.cluster.as_ref() {
        match cluster.lock() {
            Ok(mut guard) => {
                if let Some(peer) = guard.peers.get_mut(peer_url) {
                    peer.health = PeerHealth::Healthy;
                    peer.last_error = None;
                }
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                if let Some(peer) = guard.peers.get_mut(peer_url) {
                    peer.health = PeerHealth::Healthy;
                    peer.last_error = None;
                }
            }
        }
    }
}

fn update_peer_reachable(state: &TrustServiceState, peer_url: &str) {
    update_peer_state(state, peer_url, |peer| {
        peer.health = PeerHealth::Healthy;
    });
}

fn update_peer_failure(state: &TrustServiceState, peer_url: &str, error: String) {
    if let Some(cluster) = state.cluster.as_ref() {
        match cluster.lock() {
            Ok(mut guard) => {
                if let Some(peer) = guard.peers.get_mut(peer_url) {
                    peer.health = PeerHealth::Unhealthy(Instant::now());
                    peer.last_error = Some(error.clone());
                }
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                if let Some(peer) = guard.peers.get_mut(peer_url) {
                    peer.health = PeerHealth::Unhealthy(Instant::now());
                    peer.last_error = Some(error);
                }
            }
        }
    }
}

fn update_peer_sync_error(state: &TrustServiceState, peer_url: &str, error: String) {
    update_peer_state(state, peer_url, |peer| {
        peer.health = PeerHealth::Healthy;
        peer.last_error = Some(error);
    });
}

fn peer_revocation_cursor(state: &TrustServiceState, peer_url: &str) -> Option<RevocationCursor> {
    with_peer_state(state, peer_url, |peer| peer.revocation_cursor.clone()).flatten()
}

fn peer_budget_cursor(state: &TrustServiceState, peer_url: &str) -> Option<BudgetCursor> {
    with_peer_state(state, peer_url, |peer| peer.budget_cursor.clone()).flatten()
}

fn peer_tool_seq(state: &TrustServiceState, peer_url: &str) -> u64 {
    with_peer_state(state, peer_url, |peer| peer.tool_seq).unwrap_or(0)
}

fn peer_child_seq(state: &TrustServiceState, peer_url: &str) -> u64 {
    with_peer_state(state, peer_url, |peer| peer.child_seq).unwrap_or(0)
}

fn peer_lineage_seq(state: &TrustServiceState, peer_url: &str) -> u64 {
    with_peer_state(state, peer_url, |peer| peer.lineage_seq).unwrap_or(0)
}

fn update_peer_revocation_cursor(
    state: &TrustServiceState,
    peer_url: &str,
    cursor: RevocationCursor,
) {
    update_peer_state(state, peer_url, |peer| {
        peer.revocation_cursor = Some(cursor)
    });
}

fn update_peer_budget_cursor(state: &TrustServiceState, peer_url: &str, cursor: BudgetCursor) {
    update_peer_state(state, peer_url, |peer| peer.budget_cursor = Some(cursor));
}

fn update_peer_tool_seq(state: &TrustServiceState, peer_url: &str, seq: u64) {
    update_peer_state(state, peer_url, |peer| peer.tool_seq = seq);
}

fn update_peer_child_seq(state: &TrustServiceState, peer_url: &str, seq: u64) {
    update_peer_state(state, peer_url, |peer| peer.child_seq = seq);
}

fn update_peer_lineage_seq(state: &TrustServiceState, peer_url: &str, seq: u64) {
    update_peer_state(state, peer_url, |peer| peer.lineage_seq = seq);
}

fn with_peer_state<T, F>(state: &TrustServiceState, peer_url: &str, map: F) -> Option<T>
where
    F: FnOnce(&PeerSyncState) -> T,
{
    let cluster = state.cluster.as_ref()?;
    match cluster.lock() {
        Ok(guard) => guard.peers.get(peer_url).map(map),
        Err(poisoned) => poisoned.into_inner().peers.get(peer_url).map(map),
    }
}

fn update_peer_state<F>(state: &TrustServiceState, peer_url: &str, update: F)
where
    F: FnOnce(&mut PeerSyncState),
{
    if let Some(cluster) = state.cluster.as_ref() {
        match cluster.lock() {
            Ok(mut guard) => {
                if let Some(peer) = guard.peers.get_mut(peer_url) {
                    update(peer);
                }
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                if let Some(peer) = guard.peers.get_mut(peer_url) {
                    update(peer);
                }
            }
        }
    }
}

fn authority_snapshot_view(snapshot: AuthoritySnapshot) -> AuthoritySnapshotView {
    AuthoritySnapshotView {
        seed_hex: snapshot.seed_hex,
        public_key_hex: snapshot.public_key_hex,
        generation: snapshot.generation,
        rotated_at: snapshot.rotated_at,
        trusted_keys: snapshot
            .trusted_keys
            .into_iter()
            .map(|trusted_key| AuthorityTrustedKeyView {
                public_key_hex: trusted_key.public_key_hex,
                generation: trusted_key.generation,
                activated_at: trusted_key.activated_at,
            })
            .collect(),
    }
}

fn revocation_cursor_view(cursor: RevocationCursor) -> RevocationCursorView {
    RevocationCursorView {
        revoked_at: cursor.revoked_at,
        capability_id: cursor.capability_id,
    }
}

fn budget_cursor_view(cursor: BudgetCursor) -> BudgetCursorView {
    BudgetCursorView {
        seq: cursor.seq,
        updated_at: cursor.updated_at,
        capability_id: cursor.capability_id,
        grant_index: cursor.grant_index,
    }
}

fn authority_snapshot_from_view(view: AuthoritySnapshotView) -> AuthoritySnapshot {
    AuthoritySnapshot {
        seed_hex: view.seed_hex,
        public_key_hex: view.public_key_hex,
        generation: view.generation,
        rotated_at: view.rotated_at,
        trusted_keys: view
            .trusted_keys
            .into_iter()
            .map(|trusted_key| arc_kernel::AuthorityTrustedKeySnapshot {
                public_key_hex: trusted_key.public_key_hex,
                generation: trusted_key.generation,
                activated_at: trusted_key.activated_at,
            })
            .collect(),
    }
}

fn stored_tool_receipt_views(
    records: Vec<StoredToolReceipt>,
) -> Result<Vec<StoredReceiptView>, serde_json::Error> {
    records
        .into_iter()
        .map(|record| {
            Ok(StoredReceiptView {
                seq: record.seq,
                receipt: serde_json::to_value(record.receipt)?,
            })
        })
        .collect()
}

fn stored_child_receipt_views(
    records: Vec<StoredChildReceipt>,
) -> Result<Vec<StoredReceiptView>, serde_json::Error> {
    records
        .into_iter()
        .map(|record| {
            Ok(StoredReceiptView {
                seq: record.seq,
                receipt: serde_json::to_value(record.receipt)?,
            })
        })
        .collect()
}

fn stored_lineage_views(records: Vec<StoredCapabilitySnapshot>) -> Vec<StoredLineageView> {
    records
        .into_iter()
        .map(|record| StoredLineageView {
            seq: record.seq,
            snapshot: record.snapshot,
        })
        .collect()
}

fn decision_kind(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny { .. } => "deny",
        Decision::Cancelled { .. } => "cancelled",
        Decision::Incomplete { .. } => "incomplete",
    }
}

fn terminal_state_kind(state: &OperationTerminalState) -> &'static str {
    match state {
        OperationTerminalState::Completed => "completed",
        OperationTerminalState::Cancelled { .. } => "cancelled",
        OperationTerminalState::Incomplete { .. } => "incomplete",
    }
}

fn budget_visibility_matches(
    allowed: bool,
    invocation_count: Option<u32>,
    max_invocations: Option<u32>,
) -> bool {
    match (allowed, invocation_count, max_invocations) {
        (true, Some(_), _) => true,
        (true, None, _) => false,
        (false, Some(count), Some(max)) => count >= max,
        (false, Some(_), None) => true,
        (false, None, Some(0)) => true,
        (false, None, Some(_)) => false,
        (false, None, None) => false,
    }
}

fn normalize_cluster_url(value: &str) -> Result<String, CliError> {
    let normalized = value.trim().trim_end_matches('/');
    if normalized.is_empty() {
        return Err(CliError::Other("cluster URL must not be empty".to_string()));
    }
    Ok(normalized.to_string())
}

async fn forward_post_to_leader<B: Serialize>(
    state: &TrustServiceState,
    path: &str,
    body: &B,
) -> Result<Option<Response>, Response> {
    let Some(self_url) = cluster_self_url(state) else {
        return Ok(None);
    };
    let Some(mut leader_url) = current_leader_url(state) else {
        return Ok(None);
    };
    if leader_url == self_url {
        return Ok(None);
    }

    for _ in 0..2 {
        let client = build_client(&leader_url, &state.config.service_token).map_err(|error| {
            plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        })?;
        match client.post_json::<_, Value>(path, body) {
            Ok(value) => return Ok(Some(Json(value).into_response())),
            Err(error) => {
                update_peer_failure(state, &leader_url, error.to_string());
                let Some(next_leader) = current_leader_url(state) else {
                    return Ok(None);
                };
                if next_leader == self_url {
                    return Ok(None);
                }
                if next_leader == leader_url {
                    return Err(plain_http_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!("failed to forward control-plane write to leader: {error}"),
                    ));
                }
                leader_url = next_leader;
            }
        }
    }

    Err(plain_http_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "failed to forward control-plane write to cluster leader",
    ))
}

fn bearer_token_from_headers(headers: &HeaderMap) -> Result<String, Response> {
    let header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let provided = header.strip_prefix("Bearer ").unwrap_or_default();
    if !provided.is_empty() {
        return Ok(provided.to_string());
    }
    let mut response = plain_http_error(
        StatusCode::UNAUTHORIZED,
        "missing or invalid issuance bearer token",
    );
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"arc-passport-issuance\""),
    );
    Err(response)
}

fn validate_service_auth(headers: &HeaderMap, service_token: &str) -> Result<(), Response> {
    let header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let provided = header.strip_prefix("Bearer ").unwrap_or_default();
    if provided == service_token {
        return Ok(());
    }
    let mut response = plain_http_error(
        StatusCode::UNAUTHORIZED,
        "missing or invalid control bearer token",
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    Err(response)
}

fn validate_metered_billing_reconciliation_request(
    request: &MeteredBillingReconciliationUpdateRequest,
) -> Result<(), String> {
    if request.receipt_id.trim().is_empty() {
        return Err("receiptId must not be empty".to_string());
    }
    if request.adapter_kind.trim().is_empty() {
        return Err("adapterKind must not be empty".to_string());
    }
    if request.evidence_id.trim().is_empty() {
        return Err("evidenceId must not be empty".to_string());
    }
    if request.observed_units == 0 {
        return Err("observedUnits must be greater than zero".to_string());
    }
    if request.billed_cost.units == 0 {
        return Err("billedCost.units must be greater than zero".to_string());
    }
    if request.billed_cost.currency.trim().is_empty() {
        return Err("billedCost.currency must not be empty".to_string());
    }
    if request.recorded_at == 0 {
        return Err("recordedAt must be greater than zero".to_string());
    }
    if request
        .evidence_sha256
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err("evidenceSha256 must not be empty when provided".to_string());
    }
    Ok(())
}

fn load_capability_authority(
    config: &TrustServiceConfig,
) -> Result<Box<dyn CapabilityAuthority>, Response> {
    match (config.authority_seed_path.as_deref(), config.authority_db_path.as_deref()) {
        (Some(_), Some(_)) => Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires either --authority-seed-file or --authority-db, not both",
        )),
        (Some(path), None) => {
            let keypair = load_or_create_authority_keypair(path)
                .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
            Ok(issuance::wrap_capability_authority(
                Box::new(LocalCapabilityAuthority::new(keypair)),
                config.issuance_policy.clone(),
                config.runtime_assurance_policy.clone(),
                config.receipt_db_path.as_deref(),
                config.budget_db_path.as_deref(),
            ))
        }
        (None, Some(path)) => SqliteCapabilityAuthority::open(path)
            .map(|authority| {
                issuance::wrap_capability_authority(
                    Box::new(authority),
                    config.issuance_policy.clone(),
                    config.runtime_assurance_policy.clone(),
                    config.receipt_db_path.as_deref(),
                    config.budget_db_path.as_deref(),
                )
            })
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            }),
        (None, None) => Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires --authority-seed-file or --authority-db",
        )),
    }
}

fn load_authority_status(config: &TrustServiceConfig) -> Result<TrustAuthorityStatus, Response> {
    if let Some(path) = config.authority_db_path.as_deref() {
        let status = SqliteCapabilityAuthority::open(path)
            .and_then(|authority| authority.status())
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?;
        return Ok(authority_status_response("sqlite".to_string(), status));
    }

    let Some(path) = config.authority_seed_path.as_deref() else {
        return Ok(TrustAuthorityStatus {
            configured: false,
            backend: None,
            public_key: None,
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: Vec::new(),
        });
    };
    match authority_public_key_from_seed_file(path) {
        Ok(Some(public_key)) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: Some(public_key.to_hex()),
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![public_key.to_hex()],
        }),
        Ok(None) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: None,
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: Vec::new(),
        }),
        Err(error) => Err(plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &error.to_string(),
        )),
    }
}

fn rotate_authority(config: &TrustServiceConfig) -> Result<TrustAuthorityStatus, Response> {
    if let Some(path) = config.authority_db_path.as_deref() {
        let status = SqliteCapabilityAuthority::open(path)
            .and_then(|authority| authority.rotate())
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?;
        return Ok(authority_status_response("sqlite".to_string(), status));
    }

    let Some(path) = config.authority_seed_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires --authority-seed-file or --authority-db",
        ));
    };
    match rotate_authority_keypair(path) {
        Ok(public_key) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: Some(public_key.to_hex()),
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![public_key.to_hex()],
        }),
        Err(error) => Err(plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &error.to_string(),
        )),
    }
}

fn authority_status_response(backend: String, status: AuthorityStatus) -> TrustAuthorityStatus {
    TrustAuthorityStatus {
        configured: true,
        backend: Some(backend),
        public_key: Some(status.public_key.to_hex()),
        generation: Some(status.generation),
        rotated_at: Some(status.rotated_at),
        applies_to_future_sessions_only: true,
        trusted_public_keys: status
            .trusted_public_keys
            .into_iter()
            .map(|public_key| public_key.to_hex())
            .collect(),
    }
}

#[derive(Default)]
struct ResolvedBudgetGrant {
    tool_server: Option<String>,
    tool_name: Option<String>,
    max_invocations: Option<u32>,
    max_total_cost_units: Option<u64>,
    currency: Option<String>,
    scope_resolved: bool,
    scope_resolution_error: Option<String>,
}

fn build_operator_report(
    receipt_store: &SqliteReceiptStore,
    budget_store: &SqliteBudgetStore,
    query: &OperatorReportQuery,
) -> Result<OperatorReport, Response> {
    let activity = receipt_store
        .query_receipt_analytics(&query.to_receipt_analytics_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let cost_attribution = receipt_store
        .query_cost_attribution_report(&query.to_cost_attribution_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let budget_utilization = build_budget_utilization_report(receipt_store, budget_store, query)?;
    let compliance = receipt_store
        .query_compliance_report(query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let settlement_reconciliation = receipt_store
        .query_settlement_reconciliation_report(query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let metered_billing_reconciliation = receipt_store
        .query_metered_billing_reconciliation_report(query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let authorization_context = receipt_store
        .query_authorization_context_report(query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let shared_evidence = receipt_store
        .query_shared_evidence_report(&query.to_shared_evidence_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;

    Ok(OperatorReport {
        generated_at: unix_timestamp_now(),
        filters: query.clone(),
        activity,
        cost_attribution,
        budget_utilization,
        compliance,
        settlement_reconciliation,
        metered_billing_reconciliation,
        authorization_context,
        shared_evidence,
    })
}

pub fn build_signed_behavioral_feed(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    query: &BehavioralFeedQuery,
) -> Result<SignedBehavioralFeed, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let report =
        build_behavioral_feed_report(&receipt_store, receipt_db_path, budget_db_path, query)
            .map_err(|response| CliError::Other(response_status_text(&response)))?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedBehavioralFeed::sign(report, &keypair).map_err(Into::into)
}

pub fn build_signed_runtime_attestation_appraisal_report(
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    runtime_assurance_policy: Option<&crate::policy::RuntimeAssuranceIssuancePolicy>,
    evidence: &RuntimeAttestationEvidence,
) -> Result<SignedRuntimeAttestationAppraisalReport, CliError> {
    let report = build_runtime_attestation_appraisal_report(runtime_assurance_policy, evidence)
        .map_err(|response| CliError::Other(response_status_text(&response)))?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedRuntimeAttestationAppraisalReport::sign(report, &keypair).map_err(Into::into)
}

fn build_runtime_attestation_appraisal_report(
    runtime_assurance_policy: Option<&crate::policy::RuntimeAssuranceIssuancePolicy>,
    evidence: &RuntimeAttestationEvidence,
) -> Result<RuntimeAttestationAppraisalReport, Response> {
    let appraisal = derive_runtime_attestation_appraisal(evidence)
        .map_err(|error| plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()))?;
    let generated_at = unix_timestamp_now();
    let trust_policy =
        runtime_assurance_policy.and_then(|policy| policy.attestation_trust_policy.as_ref());
    let policy_outcome = match trust_policy {
        Some(policy) => {
            match evidence.resolve_effective_runtime_assurance(Some(policy), generated_at) {
                Ok(resolved) => RuntimeAttestationPolicyOutcome {
                    trust_policy_configured: true,
                    accepted: true,
                    effective_tier: resolved.effective_tier,
                    reason: None,
                },
                Err(error) => RuntimeAttestationPolicyOutcome {
                    trust_policy_configured: true,
                    accepted: false,
                    effective_tier: RuntimeAssuranceTier::None,
                    reason: Some(error.to_string()),
                },
            }
        }
        None => RuntimeAttestationPolicyOutcome {
            trust_policy_configured: false,
            accepted: true,
            effective_tier: evidence.tier,
            reason: None,
        },
    };

    Ok(RuntimeAttestationAppraisalReport {
        schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
        generated_at,
        appraisal,
        policy_outcome,
    })
}

fn build_behavioral_feed_report(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    query: &BehavioralFeedQuery,
) -> Result<BehavioralFeedReport, Response> {
    let normalized_query = query.normalized();
    let operator_query = normalized_query.to_operator_report_query();
    let activity = receipt_store
        .query_receipt_analytics(&operator_query.to_receipt_analytics_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let compliance = receipt_store
        .query_compliance_report(&operator_query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let shared_evidence = receipt_store
        .query_shared_evidence_report(&operator_query.to_shared_evidence_query())
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let (settlements, governed_actions, metered_billing, selection) = receipt_store
        .query_behavioral_feed_receipts(&normalized_query)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let generated_at = unix_timestamp_now();
    let reputation = match normalized_query.agent_subject.as_deref() {
        Some(subject_key) => Some(
            reputation::build_behavioral_feed_reputation_summary(
                receipt_db_path,
                budget_db_path,
                subject_key,
                normalized_query.since,
                normalized_query.until,
                generated_at,
            )
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?,
        ),
        None => None,
    };

    Ok(BehavioralFeedReport {
        schema: BEHAVIORAL_FEED_SCHEMA.to_string(),
        generated_at,
        filters: normalized_query,
        privacy: BehavioralFeedPrivacyBoundary {
            matching_receipts: selection.matching_receipts,
            returned_receipts: selection.receipts.len() as u64,
            direct_evidence_export_supported: compliance.direct_evidence_export_supported,
            child_receipt_scope: compliance.child_receipt_scope,
            proofs_complete: compliance.proofs_complete,
            export_query: compliance.export_query,
            export_scope_note: compliance.export_scope_note,
        },
        decisions: BehavioralFeedDecisionSummary {
            allow_count: activity.summary.allow_count,
            deny_count: activity.summary.deny_count,
            cancelled_count: activity.summary.cancelled_count,
            incomplete_count: activity.summary.incomplete_count,
        },
        settlements,
        governed_actions,
        metered_billing,
        reputation,
        shared_evidence: shared_evidence.summary,
        receipts: selection.receipts,
    })
}

pub fn build_signed_exposure_ledger_report(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    query: &ExposureLedgerQuery,
) -> Result<SignedExposureLedgerReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let report = build_exposure_ledger_report(&receipt_store, query).map_err(CliError::from)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedExposureLedgerReport::sign(report, &keypair).map_err(Into::into)
}

fn build_exposure_ledger_report(
    receipt_store: &SqliteReceiptStore,
    query: &ExposureLedgerQuery,
) -> Result<ExposureLedgerReport, TrustHttpError> {
    let normalized_query = query.normalized();
    if let Err(message) = normalized_query.validate() {
        return Err(TrustHttpError::bad_request(message));
    }

    let behavioral_query = BehavioralFeedQuery {
        capability_id: normalized_query.capability_id.clone(),
        agent_subject: normalized_query.agent_subject.clone(),
        tool_server: normalized_query.tool_server.clone(),
        tool_name: normalized_query.tool_name.clone(),
        since: normalized_query.since,
        until: normalized_query.until,
        receipt_limit: normalized_query.receipt_limit,
    };
    let (_, _, _, selection) = receipt_store
        .query_behavioral_feed_receipts(&behavioral_query)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let decision_report = receipt_store
        .query_underwriting_decisions(&UnderwritingDecisionQuery {
            decision_id: None,
            capability_id: normalized_query.capability_id.clone(),
            agent_subject: normalized_query.agent_subject.clone(),
            tool_server: normalized_query.tool_server.clone(),
            tool_name: normalized_query.tool_name.clone(),
            outcome: None,
            lifecycle_state: None,
            appeal_status: None,
            limit: normalized_query.decision_limit,
        })
        .map_err(trust_http_error_from_receipt_store)?;

    let mut positions_by_currency = BTreeMap::<String, ExposureLedgerCurrencyPosition>::new();
    let mut receipts = Vec::with_capacity(selection.receipts.len());
    let mut actionable_receipts = 0_u64;
    let mut pending_settlement_receipts = 0_u64;
    let mut failed_settlement_receipts = 0_u64;

    for receipt in &selection.receipts {
        let entry = build_exposure_ledger_receipt_entry(receipt)?;
        let settlement_status = entry.settlement_status.clone();
        if entry.action_required {
            actionable_receipts += 1;
        }
        match &settlement_status {
            SettlementStatus::Pending => pending_settlement_receipts += 1,
            SettlementStatus::Failed => failed_settlement_receipts += 1,
            SettlementStatus::NotApplicable | SettlementStatus::Settled => {}
        }
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.governed_max_amount.as_ref(),
            |position, amount| {
                position.governed_max_exposure_units = position
                    .governed_max_exposure_units
                    .saturating_add(amount.units);
            },
        );
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.reserve_required_amount.as_ref(),
            |position, amount| {
                position.reserved_units = position.reserved_units.saturating_add(amount.units);
            },
        );
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.provisional_loss_amount.as_ref(),
            |position, amount| {
                position.provisional_loss_units =
                    position.provisional_loss_units.saturating_add(amount.units);
            },
        );
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.recovered_amount.as_ref(),
            |position, amount| {
                position.recovered_units = position.recovered_units.saturating_add(amount.units);
            },
        );
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.financial_amount.as_ref(),
            |position, amount| match settlement_status {
                SettlementStatus::Settled => {
                    position.settled_units = position.settled_units.saturating_add(amount.units);
                }
                SettlementStatus::Pending => {
                    position.pending_units = position.pending_units.saturating_add(amount.units);
                }
                SettlementStatus::Failed => {
                    position.failed_units = position.failed_units.saturating_add(amount.units);
                }
                SettlementStatus::NotApplicable => {}
            },
        );
        receipts.push(entry);
    }

    let mut decisions = Vec::with_capacity(decision_report.decisions.len());
    for row in &decision_report.decisions {
        let entry = build_exposure_ledger_decision_entry(row);
        accumulate_exposure_position(
            &mut positions_by_currency,
            entry.quoted_premium_amount.as_ref(),
            |position, amount| {
                position.quoted_premium_units =
                    position.quoted_premium_units.saturating_add(amount.units);
                if entry.lifecycle_state == arc_kernel::UnderwritingDecisionLifecycleState::Active {
                    position.active_quoted_premium_units = position
                        .active_quoted_premium_units
                        .saturating_add(amount.units);
                }
            },
        );
        decisions.push(entry);
    }

    let currencies = positions_by_currency.keys().cloned().collect::<Vec<_>>();
    Ok(ExposureLedgerReport {
        schema: EXPOSURE_LEDGER_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        filters: normalized_query,
        support_boundary: ExposureLedgerSupportBoundary::default(),
        summary: ExposureLedgerSummary {
            matching_receipts: selection.matching_receipts,
            returned_receipts: receipts.len() as u64,
            matching_decisions: decision_report.summary.matching_decisions,
            returned_decisions: decisions.len() as u64,
            active_decisions: decision_report.summary.active_decisions,
            superseded_decisions: decision_report.summary.superseded_decisions,
            actionable_receipts,
            pending_settlement_receipts,
            failed_settlement_receipts,
            currencies: currencies.clone(),
            mixed_currency_book: currencies.len() > 1,
            truncated_receipts: selection.matching_receipts > receipts.len() as u64,
            truncated_decisions: decision_report.summary.matching_decisions
                > decisions.len() as u64,
        },
        positions: positions_by_currency.into_values().collect(),
        receipts,
        decisions,
    })
}

pub fn build_signed_credit_scorecard_report(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    query: &ExposureLedgerQuery,
) -> Result<SignedCreditScorecardReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let report =
        build_credit_scorecard_report(&receipt_store, receipt_db_path, budget_db_path, None, query)
            .map_err(CliError::from)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedCreditScorecardReport::sign(report, &keypair).map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
pub fn build_credit_facility_report(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
) -> Result<CreditFacilityReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    build_credit_facility_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        query,
    )
    .map_err(CliError::from)
}

#[allow(clippy::too_many_arguments)]
pub fn issue_signed_credit_facility(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
    supersedes_facility_id: Option<&str>,
) -> Result<SignedCreditFacility, CliError> {
    issue_signed_credit_facility_detailed(
        receipt_db_path,
        budget_db_path,
        authority_seed_path,
        authority_db_path,
        certification_registry_file,
        issuance_policy,
        query,
        supersedes_facility_id,
    )
    .map_err(CliError::from)
}

pub fn list_credit_facilities(
    receipt_db_path: &Path,
    query: &CreditFacilityListQuery,
) -> Result<CreditFacilityListReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .query_credit_facilities(query)
        .map_err(|error| CliError::Other(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub fn build_credit_bond_report(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
) -> Result<CreditBondReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    build_credit_bond_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        query,
    )
    .map_err(CliError::from)
}

#[allow(clippy::too_many_arguments)]
pub fn issue_signed_credit_bond(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
    supersedes_bond_id: Option<&str>,
) -> Result<SignedCreditBond, CliError> {
    issue_signed_credit_bond_detailed(
        receipt_db_path,
        budget_db_path,
        authority_seed_path,
        authority_db_path,
        certification_registry_file,
        issuance_policy,
        query,
        supersedes_bond_id,
    )
    .map_err(CliError::from)
}

pub fn list_credit_bonds(
    receipt_db_path: &Path,
    query: &CreditBondListQuery,
) -> Result<CreditBondListReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .query_credit_bonds(query)
        .map_err(|error| CliError::Other(error.to_string()))
}

pub fn build_credit_bonded_execution_simulation_report(
    receipt_db_path: &Path,
    request: &CreditBondedExecutionSimulationRequest,
) -> Result<CreditBondedExecutionSimulationReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    build_credit_bonded_execution_simulation_report_from_store(&receipt_store, request)
        .map_err(CliError::from)
}

pub fn build_credit_loss_lifecycle_report(
    receipt_db_path: &Path,
    query: &CreditLossLifecycleQuery,
) -> Result<CreditLossLifecycleReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    build_credit_loss_lifecycle_report_from_store(&receipt_store, query).map_err(CliError::from)
}

pub fn issue_signed_credit_loss_lifecycle(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    query: &CreditLossLifecycleQuery,
) -> Result<SignedCreditLossLifecycle, CliError> {
    issue_signed_credit_loss_lifecycle_detailed(
        receipt_db_path,
        authority_seed_path,
        authority_db_path,
        query,
    )
    .map_err(CliError::from)
}

pub fn list_credit_loss_lifecycle(
    receipt_db_path: &Path,
    query: &CreditLossLifecycleListQuery,
) -> Result<CreditLossLifecycleListReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .query_credit_loss_lifecycle(query)
        .map_err(|error| CliError::Other(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub fn build_credit_backtest_report(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &CreditBacktestQuery,
) -> Result<CreditBacktestReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    build_credit_backtest_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        query,
    )
    .map_err(CliError::from)
}

#[allow(clippy::too_many_arguments)]
pub fn build_signed_credit_provider_risk_package(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &CreditProviderRiskPackageQuery,
) -> Result<SignedCreditProviderRiskPackage, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let package = build_credit_provider_risk_package_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        &keypair,
        query,
    )
    .map_err(CliError::from)?;
    SignedCreditProviderRiskPackage::sign(package, &keypair).map_err(Into::into)
}

pub fn issue_signed_liability_provider(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    report: &LiabilityProviderReport,
    supersedes_provider_record_id: Option<&str>,
) -> Result<SignedLiabilityProvider, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    report.validate().map_err(CliError::Other)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_provider_artifact(
        report.clone(),
        issued_at,
        supersedes_provider_record_id.map(ToOwned::to_owned),
    )?;
    let signed = SignedLiabilityProvider::sign(artifact, &keypair).map_err(|error| {
        CliError::Other(format!(
            "failed to sign liability provider artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_provider(&signed)
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(signed)
}

pub fn list_liability_providers(
    receipt_db_path: &Path,
    query: &LiabilityProviderListQuery,
) -> Result<LiabilityProviderListReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .query_liability_providers(query)
        .map_err(|error| CliError::Other(error.to_string()))
}

pub fn resolve_liability_provider(
    receipt_db_path: &Path,
    query: &LiabilityProviderResolutionQuery,
) -> Result<LiabilityProviderResolutionReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .resolve_liability_provider(query)
        .map_err(|error| CliError::Other(error.to_string()))
}

fn build_liability_provider_artifact(
    report: LiabilityProviderReport,
    issued_at: u64,
    supersedes_provider_record_id: Option<String>,
) -> Result<LiabilityProviderArtifact, CliError> {
    report.validate().map_err(CliError::Other)?;
    let lifecycle_state = report.lifecycle_state;
    let provider_record_id_input = canonical_json_bytes(&(
        LIABILITY_PROVIDER_ARTIFACT_SCHEMA,
        issued_at,
        lifecycle_state,
        &supersedes_provider_record_id,
        &report,
    ))
    .map_err(|error| CliError::Other(error.to_string()))?;
    let provider_record_id = format!("lpr-{}", sha256_hex(&provider_record_id_input));
    Ok(LiabilityProviderArtifact {
        schema: LIABILITY_PROVIDER_ARTIFACT_SCHEMA.to_string(),
        provider_record_id,
        issued_at,
        lifecycle_state,
        supersedes_provider_record_id,
        report,
    })
}

pub fn issue_signed_liability_quote_request(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityQuoteRequestIssueRequest,
) -> Result<SignedLiabilityQuoteRequest, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request.provider_id.clone(),
            jurisdiction: request.jurisdiction.clone(),
            coverage_class: request.coverage_class,
            currency: request.requested_coverage_amount.currency.clone(),
        })
        .map_err(|error| CliError::Other(error.to_string()))?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_quote_request_artifact(request, &resolution, issued_at)?;
    let signed = SignedLiabilityQuoteRequest::sign(artifact, &keypair).map_err(|error| {
        CliError::Other(format!(
            "failed to sign liability quote request artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_quote_request(&signed)
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_quote_response(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityQuoteResponseIssueRequest,
) -> Result<SignedLiabilityQuoteResponse, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request
                .quote_request
                .body
                .provider_policy
                .provider_id
                .clone(),
            jurisdiction: request
                .quote_request
                .body
                .provider_policy
                .jurisdiction
                .clone(),
            coverage_class: request.quote_request.body.provider_policy.coverage_class,
            currency: request.quote_request.body.provider_policy.currency.clone(),
        })
        .map_err(|error| CliError::Other(error.to_string()))?;
    if resolution.provider.body.provider_record_id
        != request
            .quote_request
            .body
            .provider_policy
            .provider_record_id
    {
        return Err(CliError::Other(format!(
            "liability quote request `{}` references stale provider record `{}`",
            request.quote_request.body.quote_request_id,
            request
                .quote_request
                .body
                .provider_policy
                .provider_record_id
        )));
    }
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_quote_response_artifact(request, issued_at)?;
    let signed = SignedLiabilityQuoteResponse::sign(artifact, &keypair).map_err(|error| {
        CliError::Other(format!(
            "failed to sign liability quote response artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_quote_response(&signed)
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_placement(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityPlacementIssueRequest,
) -> Result<SignedLiabilityPlacement, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_id
                .clone(),
            jurisdiction: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .jurisdiction
                .clone(),
            coverage_class: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .coverage_class,
            currency: request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .currency
                .clone(),
        })
        .map_err(|error| CliError::Other(error.to_string()))?;
    if resolution.provider.body.provider_record_id
        != request
            .quote_response
            .body
            .quote_request
            .body
            .provider_policy
            .provider_record_id
    {
        return Err(CliError::Other(format!(
            "liability quote request `{}` references stale provider record `{}`",
            request
                .quote_response
                .body
                .quote_request
                .body
                .quote_request_id,
            request
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_record_id
        )));
    }
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_placement_artifact(request, issued_at)?;
    let signed = SignedLiabilityPlacement::sign(artifact, &keypair).map_err(|error| {
        CliError::Other(format!(
            "failed to sign liability placement artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_placement(&signed)
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_bound_coverage(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityBoundCoverageIssueRequest,
) -> Result<SignedLiabilityBoundCoverage, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let resolution = receipt_store
        .resolve_liability_provider(&LiabilityProviderResolutionQuery {
            provider_id: request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_id
                .clone(),
            jurisdiction: request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .jurisdiction
                .clone(),
            coverage_class: request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .coverage_class,
            currency: request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .currency
                .clone(),
        })
        .map_err(|error| CliError::Other(error.to_string()))?;
    if resolution.provider.body.provider_record_id
        != request
            .placement
            .body
            .quote_response
            .body
            .quote_request
            .body
            .provider_policy
            .provider_record_id
    {
        return Err(CliError::Other(format!(
            "liability quote request `{}` references stale provider record `{}`",
            request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .quote_request_id,
            request
                .placement
                .body
                .quote_response
                .body
                .quote_request
                .body
                .provider_policy
                .provider_record_id
        )));
    }
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_bound_coverage_artifact(request, issued_at)?;
    let signed = SignedLiabilityBoundCoverage::sign(artifact, &keypair).map_err(|error| {
        CliError::Other(format!(
            "failed to sign liability bound coverage artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_bound_coverage(&signed)
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(signed)
}

pub fn list_liability_market_workflows(
    receipt_db_path: &Path,
    query: &LiabilityMarketWorkflowQuery,
) -> Result<LiabilityMarketWorkflowReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .query_liability_market_workflows(query)
        .map_err(|error| CliError::Other(error.to_string()))
}

pub fn issue_signed_liability_claim_package(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimPackageIssueRequest,
) -> Result<SignedLiabilityClaimPackage, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_claim_package_artifact(request, issued_at)?;
    let signed = SignedLiabilityClaimPackage::sign(artifact, &keypair).map_err(|error| {
        CliError::Other(format!(
            "failed to sign liability claim package artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_claim_package(&signed)
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_response(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimResponseIssueRequest,
) -> Result<SignedLiabilityClaimResponse, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_claim_response_artifact(request, issued_at)?;
    let signed = SignedLiabilityClaimResponse::sign(artifact, &keypair).map_err(|error| {
        CliError::Other(format!(
            "failed to sign liability claim response artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_claim_response(&signed)
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_dispute(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimDisputeIssueRequest,
) -> Result<SignedLiabilityClaimDispute, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_claim_dispute_artifact(request, issued_at)?;
    let signed = SignedLiabilityClaimDispute::sign(artifact, &keypair).map_err(|error| {
        CliError::Other(format!(
            "failed to sign liability claim dispute artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_claim_dispute(&signed)
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_adjudication(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimAdjudicationIssueRequest,
) -> Result<SignedLiabilityClaimAdjudication, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = unix_timestamp_now();
    let artifact = build_liability_claim_adjudication_artifact(request, issued_at)?;
    let signed = SignedLiabilityClaimAdjudication::sign(artifact, &keypair).map_err(|error| {
        CliError::Other(format!(
            "failed to sign liability claim adjudication artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_claim_adjudication(&signed)
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(signed)
}

pub fn list_liability_claim_workflows(
    receipt_db_path: &Path,
    query: &LiabilityClaimWorkflowQuery,
) -> Result<LiabilityClaimWorkflowReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .query_liability_claim_workflows(query)
        .map_err(|error| CliError::Other(error.to_string()))
}

fn build_liability_provider_policy_reference(
    resolution: &LiabilityProviderResolutionReport,
) -> LiabilityProviderPolicyReference {
    LiabilityProviderPolicyReference {
        provider_id: resolution.provider.body.report.provider_id.clone(),
        provider_record_id: resolution.provider.body.provider_record_id.clone(),
        display_name: resolution.provider.body.report.display_name.clone(),
        jurisdiction: resolution.matched_policy.jurisdiction.clone(),
        coverage_class: resolution.query.coverage_class,
        currency: resolution.query.currency.clone(),
        required_evidence: resolution.matched_policy.required_evidence.clone(),
        max_coverage_amount: resolution.matched_policy.max_coverage_amount.clone(),
        claims_supported: resolution.matched_policy.claims_supported,
        quote_ttl_seconds: resolution.matched_policy.quote_ttl_seconds,
        bound_coverage_supported: resolution.support_boundary.bound_coverage_supported,
    }
}

fn build_liability_quote_request_artifact(
    request: &LiabilityQuoteRequestIssueRequest,
    resolution: &LiabilityProviderResolutionReport,
    issued_at: u64,
) -> Result<LiabilityQuoteRequestArtifact, CliError> {
    let artifact = LiabilityQuoteRequestArtifact {
        schema: LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA.to_string(),
        quote_request_id: format!(
            "lqqr-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.provider_id,
                    &request.jurisdiction,
                    request.coverage_class,
                    &request.requested_coverage_amount,
                    request.requested_effective_from,
                    request.requested_effective_until,
                    &request.risk_package.body.subject_key,
                ))
                .map_err(|error| CliError::Other(error.to_string()))?
            )
        ),
        issued_at,
        provider_policy: build_liability_provider_policy_reference(resolution),
        requested_coverage_amount: request.requested_coverage_amount.clone(),
        requested_effective_from: request.requested_effective_from,
        requested_effective_until: request.requested_effective_until,
        risk_package: request.risk_package.clone(),
        notes: request.notes.clone(),
    };
    artifact.validate().map_err(CliError::Other)?;
    Ok(artifact)
}

fn build_liability_quote_response_artifact(
    request: &LiabilityQuoteResponseIssueRequest,
    issued_at: u64,
) -> Result<LiabilityQuoteResponseArtifact, CliError> {
    let disposition = request.disposition.clone();
    let artifact = LiabilityQuoteResponseArtifact {
        schema: LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA.to_string(),
        quote_response_id: format!(
            "lqqs-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.quote_request.body.quote_request_id,
                    &request.provider_quote_ref,
                    &disposition,
                    &request.supersedes_quote_response_id,
                    &request.quoted_terms,
                    &request.decline_reason,
                ))
                .map_err(|error| CliError::Other(error.to_string()))?
            )
        ),
        issued_at,
        quote_request: request.quote_request.clone(),
        provider_quote_ref: request.provider_quote_ref.clone(),
        disposition,
        supersedes_quote_response_id: request.supersedes_quote_response_id.clone(),
        quoted_terms: request.quoted_terms.clone(),
        decline_reason: request.decline_reason.clone(),
    };
    artifact.validate().map_err(CliError::Other)?;
    Ok(artifact)
}

fn build_liability_placement_artifact(
    request: &LiabilityPlacementIssueRequest,
    issued_at: u64,
) -> Result<LiabilityPlacementArtifact, CliError> {
    let artifact = LiabilityPlacementArtifact {
        schema: LIABILITY_PLACEMENT_ARTIFACT_SCHEMA.to_string(),
        placement_id: format!(
            "lqpl-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_PLACEMENT_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.quote_response.body.quote_response_id,
                    &request.selected_coverage_amount,
                    &request.selected_premium_amount,
                    request.effective_from,
                    request.effective_until,
                    &request.placement_ref,
                ))
                .map_err(|error| CliError::Other(error.to_string()))?
            )
        ),
        issued_at,
        quote_response: request.quote_response.clone(),
        selected_coverage_amount: request.selected_coverage_amount.clone(),
        selected_premium_amount: request.selected_premium_amount.clone(),
        effective_from: request.effective_from,
        effective_until: request.effective_until,
        placement_ref: request.placement_ref.clone(),
        notes: request.notes.clone(),
    };
    artifact.validate().map_err(CliError::Other)?;
    Ok(artifact)
}

fn build_liability_bound_coverage_artifact(
    request: &LiabilityBoundCoverageIssueRequest,
    issued_at: u64,
) -> Result<LiabilityBoundCoverageArtifact, CliError> {
    let bound_at = request.bound_at.unwrap_or(issued_at);
    let artifact = LiabilityBoundCoverageArtifact {
        schema: LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA.to_string(),
        bound_coverage_id: format!(
            "lqbc-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.placement.body.placement_id,
                    &request.policy_number,
                    &request.carrier_reference,
                    bound_at,
                    request.effective_from,
                    request.effective_until,
                    &request.coverage_amount,
                    &request.premium_amount,
                ))
                .map_err(|error| CliError::Other(error.to_string()))?
            )
        ),
        issued_at,
        placement: request.placement.clone(),
        policy_number: request.policy_number.clone(),
        carrier_reference: request.carrier_reference.clone(),
        bound_at,
        effective_from: request.effective_from,
        effective_until: request.effective_until,
        coverage_amount: request.coverage_amount.clone(),
        premium_amount: request.premium_amount.clone(),
    };
    artifact.validate().map_err(CliError::Other)?;
    Ok(artifact)
}

fn build_liability_claim_evidence_refs(
    request: &LiabilityClaimPackageIssueRequest,
) -> Vec<LiabilityClaimEvidenceReference> {
    let mut refs = Vec::with_capacity(request.receipt_ids.len() + 4);
    refs.push(LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::BoundCoverage,
        reference_id: request.bound_coverage.body.bound_coverage_id.clone(),
        observed_at: Some(request.bound_coverage.body.issued_at),
        locator: Some(format!(
            "policy:{}",
            request.bound_coverage.body.policy_number
        )),
    });
    refs.push(LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::ExposureLedger,
        reference_id: format!(
            "{}:{}",
            request.exposure.body.schema, request.exposure.body.generated_at
        ),
        observed_at: Some(request.exposure.body.generated_at),
        locator: request.exposure.body.filters.agent_subject.clone(),
    });
    refs.push(LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::CreditBond,
        reference_id: request.bond.body.bond_id.clone(),
        observed_at: Some(request.bond.body.issued_at),
        locator: request.bond.body.report.filters.agent_subject.clone(),
    });
    refs.push(LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::CreditLossLifecycle,
        reference_id: request.loss_event.body.event_id.clone(),
        observed_at: Some(request.loss_event.body.issued_at),
        locator: Some(format!("{:?}", request.loss_event.body.event_kind)),
    });
    refs.extend(request.receipt_ids.iter().cloned().map(|receipt_id| {
        LiabilityClaimEvidenceReference {
            kind: LiabilityClaimEvidenceKind::Receipt,
            reference_id: receipt_id,
            observed_at: None,
            locator: None,
        }
    }));
    refs
}

fn build_liability_claim_package_artifact(
    request: &LiabilityClaimPackageIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimPackageArtifact, CliError> {
    let evidence_refs = build_liability_claim_evidence_refs(request);
    let artifact = LiabilityClaimPackageArtifact {
        schema: LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA.to_string(),
        claim_id: format!(
            "lcp-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.bound_coverage.body.bound_coverage_id,
                    &request.claimant,
                    request.claim_event_at,
                    &request.claim_amount,
                    &request.claim_ref,
                    &request.narrative,
                    &request.receipt_ids,
                    &request.bond.body.bond_id,
                    &request.loss_event.body.event_id,
                ))
                .map_err(|error| CliError::Other(error.to_string()))?
            )
        ),
        issued_at,
        bound_coverage: request.bound_coverage.clone(),
        exposure: request.exposure.clone(),
        bond: request.bond.clone(),
        loss_event: request.loss_event.clone(),
        claimant: request.claimant.clone(),
        claim_event_at: request.claim_event_at,
        claim_amount: request.claim_amount.clone(),
        claim_ref: request.claim_ref.clone(),
        narrative: request.narrative.clone(),
        receipt_ids: request.receipt_ids.clone(),
        evidence_refs,
    };
    artifact.validate().map_err(CliError::Other)?;
    Ok(artifact)
}

fn build_liability_claim_response_artifact(
    request: &LiabilityClaimResponseIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimResponseArtifact, CliError> {
    let evidence_refs = vec![LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::BoundCoverage,
        reference_id: request
            .claim
            .body
            .bound_coverage
            .body
            .bound_coverage_id
            .clone(),
        observed_at: Some(request.claim.body.bound_coverage.body.issued_at),
        locator: Some(request.claim.body.claim_id.clone()),
    }];
    let artifact = LiabilityClaimResponseArtifact {
        schema: LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA.to_string(),
        claim_response_id: format!(
            "lcr-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.claim.body.claim_id,
                    &request.provider_response_ref,
                    request.disposition,
                    &request.covered_amount,
                    &request.response_note,
                    &request.denial_reason,
                ))
                .map_err(|error| CliError::Other(error.to_string()))?
            )
        ),
        issued_at,
        claim: request.claim.clone(),
        provider_response_ref: request.provider_response_ref.clone(),
        disposition: request.disposition,
        covered_amount: request.covered_amount.clone(),
        response_note: request.response_note.clone(),
        denial_reason: request.denial_reason.clone(),
        evidence_refs,
    };
    artifact.validate().map_err(CliError::Other)?;
    Ok(artifact)
}

fn build_liability_claim_dispute_artifact(
    request: &LiabilityClaimDisputeIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimDisputeArtifact, CliError> {
    let evidence_refs = vec![LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::ClaimResponse,
        reference_id: request.provider_response.body.claim_response_id.clone(),
        observed_at: Some(request.provider_response.body.issued_at),
        locator: Some(request.provider_response.body.claim.body.claim_id.clone()),
    }];
    let artifact = LiabilityClaimDisputeArtifact {
        schema: LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA.to_string(),
        dispute_id: format!(
            "lcd-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.provider_response.body.claim_response_id,
                    &request.opened_by,
                    &request.reason,
                    &request.note,
                ))
                .map_err(|error| CliError::Other(error.to_string()))?
            )
        ),
        issued_at,
        provider_response: request.provider_response.clone(),
        opened_by: request.opened_by.clone(),
        reason: request.reason.clone(),
        note: request.note.clone(),
        evidence_refs,
    };
    artifact.validate().map_err(CliError::Other)?;
    Ok(artifact)
}

fn build_liability_claim_adjudication_artifact(
    request: &LiabilityClaimAdjudicationIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimAdjudicationArtifact, CliError> {
    let evidence_refs = vec![LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::ClaimDispute,
        reference_id: request.dispute.body.dispute_id.clone(),
        observed_at: Some(request.dispute.body.issued_at),
        locator: Some(
            request
                .dispute
                .body
                .provider_response
                .body
                .claim
                .body
                .claim_id
                .clone(),
        ),
    }];
    let artifact = LiabilityClaimAdjudicationArtifact {
        schema: LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA.to_string(),
        adjudication_id: format!(
            "lca-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.dispute.body.dispute_id,
                    &request.adjudicator,
                    request.outcome,
                    &request.awarded_amount,
                    &request.note,
                ))
                .map_err(|error| CliError::Other(error.to_string()))?
            )
        ),
        issued_at,
        dispute: request.dispute.clone(),
        adjudicator: request.adjudicator.clone(),
        outcome: request.outcome,
        awarded_amount: request.awarded_amount.clone(),
        note: request.note.clone(),
        evidence_refs,
    };
    artifact.validate().map_err(CliError::Other)?;
    Ok(artifact)
}

#[allow(clippy::too_many_arguments)]
fn build_credit_backtest_report_from_store(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &CreditBacktestQuery,
) -> Result<CreditBacktestReport, TrustHttpError> {
    let normalized = query.normalized();
    if let Err(message) = normalized.validate() {
        return Err(TrustHttpError::bad_request(message));
    }

    let window_count = normalized.window_count_or_default();
    let window_seconds = normalized.window_seconds_or_default();
    let stale_after_seconds = normalized.stale_after_seconds_or_default();
    let end_anchor = normalized.until.unwrap_or_else(unix_timestamp_now);
    let earliest_start = normalized.since.unwrap_or_else(|| {
        end_anchor.saturating_sub(window_seconds.saturating_mul(window_count as u64))
    });
    let mut windows = Vec::new();
    let mut previous_band = None;
    let mut previous_disposition = None;
    let mut drift_windows = 0_u64;
    let mut score_band_changes = 0_u64;
    let mut facility_disposition_changes = 0_u64;
    let mut manual_review_windows = 0_u64;
    let mut denied_windows = 0_u64;
    let mut stale_evidence_windows = 0_u64;
    let mut mixed_currency_windows = 0_u64;
    let mut over_utilized_windows = 0_u64;

    for offset_index in (0..window_count).rev() {
        let window_end = end_anchor.saturating_sub((offset_index as u64) * window_seconds);
        if window_end < earliest_start {
            continue;
        }
        let window_start = window_end
            .saturating_sub(window_seconds.saturating_sub(1))
            .max(earliest_start);
        let exposure_query = CreditBacktestQuery {
            since: Some(window_start),
            until: Some(window_end),
            ..normalized.clone()
        }
        .exposure_query()
        .normalized();
        let exposure = match build_exposure_ledger_report(receipt_store, &exposure_query) {
            Ok(report) => report,
            Err(error) if error.status == StatusCode::CONFLICT => continue,
            Err(error) => return Err(error),
        };
        let scorecard = build_credit_scorecard_report(
            receipt_store,
            receipt_db_path,
            budget_db_path,
            issuance_policy,
            &exposure_query,
        )?;
        let facility = build_credit_facility_report_from_store(
            receipt_store,
            receipt_db_path,
            budget_db_path,
            certification_registry_file,
            issuance_policy,
            &exposure_query,
        )?;
        let simulated_terms = facility
            .terms
            .clone()
            .or_else(|| build_credit_facility_terms(&scorecard));
        let newest_receipt_at = exposure.receipts.iter().map(|row| row.timestamp).max();
        let stale_evidence = newest_receipt_at
            .is_none_or(|timestamp| window_end.saturating_sub(timestamp) > stale_after_seconds);
        let utilization_bps =
            credit_backtest_utilization_bps(&exposure.positions, simulated_terms.as_ref());
        let over_utilized = utilization_bps.is_some_and(|bps| {
            simulated_terms.as_ref().map_or(bps > 10_000, |terms| {
                bps > u32::from(terms.utilization_ceiling_bps)
            })
        });
        let expected_band = previous_band;
        let expected_disposition = previous_disposition;
        let mut reason_codes = Vec::new();
        if expected_band.is_some_and(|band| band != scorecard.summary.band) {
            reason_codes.push(CreditBacktestReasonCode::ScoreBandShift);
            score_band_changes += 1;
        }
        if expected_disposition.is_some_and(|disposition| disposition != facility.disposition) {
            reason_codes.push(CreditBacktestReasonCode::FacilityDispositionShift);
            facility_disposition_changes += 1;
        }
        if exposure.summary.mixed_currency_book {
            reason_codes.push(CreditBacktestReasonCode::MixedCurrencyBook);
            mixed_currency_windows += 1;
        }
        if stale_evidence {
            reason_codes.push(CreditBacktestReasonCode::StaleEvidence);
            stale_evidence_windows += 1;
        }
        if over_utilized {
            reason_codes.push(CreditBacktestReasonCode::FacilityOverUtilization);
            over_utilized_windows += 1;
        }
        if credit_facility_has_reason(
            &scorecard,
            CreditScorecardReasonCode::PendingSettlementBacklog,
        ) {
            reason_codes.push(CreditBacktestReasonCode::PendingSettlementBacklog);
        }
        if credit_facility_has_reason(
            &scorecard,
            CreditScorecardReasonCode::FailedSettlementBacklog,
        ) {
            reason_codes.push(CreditBacktestReasonCode::FailedSettlementBacklog);
        }
        if !facility.prerequisites.runtime_assurance_met {
            reason_codes.push(CreditBacktestReasonCode::MissingRuntimeAssurance);
        }
        if facility.prerequisites.certification_required
            && !facility.prerequisites.certification_met
        {
            reason_codes.push(CreditBacktestReasonCode::CertificationNotActive);
        }
        if !reason_codes.is_empty() {
            drift_windows += 1;
        }
        match facility.disposition {
            CreditFacilityDisposition::Grant => {}
            CreditFacilityDisposition::ManualReview => manual_review_windows += 1,
            CreditFacilityDisposition::Deny => denied_windows += 1,
        }

        windows.push(CreditBacktestWindow {
            index: windows.len() as u64,
            window_started_at: window_start,
            window_ended_at: window_end,
            newest_receipt_at,
            expected_band,
            expected_disposition,
            simulated_scorecard: scorecard.summary.clone(),
            simulated_disposition: facility.disposition,
            simulated_terms,
            stale_evidence,
            utilization_bps,
            reason_codes,
        });

        previous_band = Some(scorecard.summary.band);
        previous_disposition = Some(facility.disposition);
    }

    if windows.is_empty() {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "credit backtest requires at least one historical window with matching governed receipts"
                .to_string(),
        ));
    }

    Ok(CreditBacktestReport {
        schema: CREDIT_BACKTEST_REPORT_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        query: normalized,
        summary: CreditBacktestSummary {
            windows_evaluated: windows.len() as u64,
            drift_windows,
            score_band_changes,
            facility_disposition_changes,
            manual_review_windows,
            denied_windows,
            stale_evidence_windows,
            mixed_currency_windows,
            over_utilized_windows,
        },
        windows,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_credit_provider_risk_package_from_store(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    keypair: &Keypair,
    query: &CreditProviderRiskPackageQuery,
) -> Result<CreditProviderRiskPackage, TrustHttpError> {
    let normalized = query.normalized();
    if let Err(message) = normalized.validate() {
        return Err(TrustHttpError::bad_request(message));
    }

    let subject_key = normalized.agent_subject.clone().ok_or_else(|| {
        TrustHttpError::bad_request("provider risk packages require subject scope")
    })?;
    let behavioral_query = BehavioralFeedQuery {
        capability_id: normalized.capability_id.clone(),
        agent_subject: normalized.agent_subject.clone(),
        tool_server: normalized.tool_server.clone(),
        tool_name: normalized.tool_name.clone(),
        since: normalized.since,
        until: normalized.until,
        receipt_limit: normalized.receipt_limit,
    };
    let (matching_loss_events, recent_loss_receipts) = receipt_store
        .query_recent_credit_loss_receipts(
            &behavioral_query,
            normalized.recent_loss_limit_or_default(),
        )
        .map_err(trust_http_error_from_receipt_store)?;
    let exposure_query = normalized.exposure_query().normalized();
    let exposure_report = build_exposure_ledger_report(receipt_store, &exposure_query)?;
    let signed_exposure = SignedExposureLedgerReport::sign(exposure_report.clone(), keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let scorecard_report = build_credit_scorecard_report(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        issuance_policy,
        &exposure_query,
    )?;
    let signed_scorecard = SignedCreditScorecardReport::sign(scorecard_report.clone(), keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let facility_report = build_credit_facility_report_from_store(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        &exposure_query,
    )?;
    let underwriting_input = build_underwriting_policy_input(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        &underwriting_input_query_from_exposure_query(&exposure_query),
    )?;
    let latest_facility = latest_credit_facility_snapshot(
        receipt_store,
        normalized.capability_id.as_deref(),
        normalized.agent_subject.as_deref(),
        normalized.tool_server.as_deref(),
        normalized.tool_name.as_deref(),
    )?;
    let stale_runtime_evidence = exposure_report
        .receipts
        .iter()
        .map(|row| row.timestamp)
        .max()
        .is_none_or(|timestamp| {
            unix_timestamp_now().saturating_sub(timestamp)
                > UnderwritingDecisionPolicy::default().maximum_receipt_age_seconds
        });

    let evidence_refs =
        collect_credit_provider_risk_evidence(&scorecard_report, &underwriting_input);

    Ok(CreditProviderRiskPackage {
        schema: CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        subject_key,
        filters: normalized.clone(),
        support_boundary: CreditProviderRiskPackageSupportBoundary::default(),
        exposure: signed_exposure,
        scorecard: signed_scorecard,
        facility_report,
        latest_facility,
        runtime_assurance: underwriting_input
            .runtime_assurance
            .as_ref()
            .map(|runtime| CreditRuntimeAssuranceState {
                governed_receipts: runtime.governed_receipts,
                runtime_assurance_receipts: runtime.runtime_assurance_receipts,
                highest_tier: runtime.highest_tier,
                stale: stale_runtime_evidence,
            }),
        certification: CreditCertificationState {
            required: normalized.tool_server.is_some(),
            state: underwriting_input
                .certification
                .as_ref()
                .map(|certification| certification.state.clone()),
            artifact_id: underwriting_input
                .certification
                .as_ref()
                .and_then(|certification| certification.artifact_id.clone()),
            checked_at: underwriting_input
                .certification
                .as_ref()
                .and_then(|certification| certification.checked_at),
            published_at: underwriting_input
                .certification
                .as_ref()
                .and_then(|certification| certification.published_at),
        },
        recent_loss_history: build_credit_recent_loss_history(
            matching_loss_events,
            &recent_loss_receipts,
            normalized.recent_loss_limit_or_default(),
        )?,
        evidence_refs,
    })
}

fn build_credit_scorecard_report(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
) -> Result<CreditScorecardReport, TrustHttpError> {
    let normalized_query = query.normalized();
    if let Err(message) = normalized_query.validate() {
        return Err(TrustHttpError::bad_request(message));
    }
    let subject_key = normalized_query.agent_subject.clone().ok_or_else(|| {
        TrustHttpError::bad_request(
            "credit scorecard queries require --agent-subject because scorecards are subject-scoped"
                .to_string(),
        )
    })?;

    let exposure = build_exposure_ledger_report(receipt_store, &normalized_query)?;
    if exposure.summary.matching_receipts == 0 {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "credit scorecard requires at least one matching governed receipt".to_string(),
        ));
    }

    let mut inspection = issuance::inspect_local_reputation(
        &subject_key,
        Some(receipt_db_path),
        budget_db_path,
        normalized_query.since,
        normalized_query.until,
        issuance_policy,
    )
    .map_err(|error| TrustHttpError::internal(error.to_string()))?;

    inspection.imported_trust = Some(
        reputation::build_imported_trust_report(
            receipt_db_path,
            &inspection.subject_key,
            inspection.since,
            inspection.until,
            unix_timestamp_now(),
            &inspection.scoring,
        )
        .map_err(|error| TrustHttpError::internal(error.to_string()))?,
    );

    let exposure_units =
        credit_scorecard_position_denominator(&exposure.positions).ok_or_else(|| {
            TrustHttpError::new(
                StatusCode::CONFLICT,
                "credit scorecard requires monetary exposure in the requested window".to_string(),
            )
        })?;
    let confidence = resolve_credit_scorecard_confidence(&inspection);
    let probation = build_credit_scorecard_probation(&inspection, confidence);
    let dimensions = build_credit_scorecard_dimensions(
        &subject_key,
        &exposure,
        &inspection,
        exposure_units as f64,
    );
    let overall_score = compute_credit_scorecard_overall_score(&dimensions).ok_or_else(|| {
        TrustHttpError::new(
            StatusCode::CONFLICT,
            "credit scorecard could not compute a deterministic score from the requested evidence"
                .to_string(),
        )
    })?;
    let anomalies =
        build_credit_scorecard_anomalies(&subject_key, &exposure, &inspection, exposure_units);
    let band = resolve_credit_scorecard_band(overall_score, probation.probationary);
    let imported_trust = inspection.imported_trust.as_ref();

    Ok(CreditScorecardReport {
        schema: CREDIT_SCORECARD_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        filters: normalized_query,
        support_boundary: CreditScorecardSupportBoundary::default(),
        summary: CreditScorecardSummary {
            matching_receipts: exposure.summary.matching_receipts,
            returned_receipts: exposure.summary.returned_receipts,
            matching_decisions: exposure.summary.matching_decisions,
            returned_decisions: exposure.summary.returned_decisions,
            currencies: exposure.summary.currencies.clone(),
            mixed_currency_book: exposure.summary.mixed_currency_book,
            confidence,
            band,
            overall_score: round_credit_score_value(overall_score),
            anomaly_count: anomalies.len() as u64,
            probationary: probation.probationary,
        },
        reputation: CreditScorecardReputationContext {
            effective_score: round_credit_score_value(inspection.effective_score),
            probationary: inspection.probationary,
            resolved_tier: inspection
                .resolved_tier
                .as_ref()
                .map(|tier| tier.name.clone()),
            imported_signal_count: imported_trust.map_or(0, |report| report.signal_count),
            accepted_imported_signal_count: imported_trust
                .map_or(0, |report| report.accepted_count),
        },
        positions: exposure.positions,
        probation,
        dimensions,
        anomalies,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_credit_facility_report_from_store(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
) -> Result<CreditFacilityReport, TrustHttpError> {
    let scorecard = build_credit_scorecard_report(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        issuance_policy,
        query,
    )?;
    let underwriting_input = build_underwriting_policy_input(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        &underwriting_input_query_from_exposure_query(&scorecard.filters),
    )?;
    let minimum_runtime_assurance_tier =
        credit_facility_minimum_runtime_assurance_tier(scorecard.summary.band);
    let runtime_assurance_met = underwriting_input
        .runtime_assurance
        .as_ref()
        .and_then(|runtime| runtime.highest_tier)
        .is_some_and(|tier| tier >= minimum_runtime_assurance_tier);
    let certification_required = scorecard.filters.tool_server.is_some();
    let certification_met = !certification_required
        || underwriting_input
            .certification
            .as_ref()
            .is_some_and(|certification| {
                certification.state == UnderwritingCertificationState::Active
            });
    let mixed_currency_book = scorecard.summary.mixed_currency_book;
    let probationary = scorecard.summary.probationary;
    let restricted = scorecard.summary.band == CreditScorecardBand::Restricted;
    let failed_backlog = credit_facility_has_reason(
        &scorecard,
        CreditScorecardReasonCode::FailedSettlementBacklog,
    );
    let pending_backlog = credit_facility_has_reason(
        &scorecard,
        CreditScorecardReasonCode::PendingSettlementBacklog,
    );

    let disposition =
        if restricted || !runtime_assurance_met || (certification_required && !certification_met) {
            CreditFacilityDisposition::Deny
        } else if mixed_currency_book || failed_backlog || probationary || pending_backlog {
            CreditFacilityDisposition::ManualReview
        } else {
            CreditFacilityDisposition::Grant
        };

    let prerequisites = CreditFacilityPrerequisites {
        minimum_runtime_assurance_tier,
        runtime_assurance_met,
        certification_required,
        certification_met,
        manual_review_required: disposition == CreditFacilityDisposition::ManualReview,
    };
    let terms = if disposition == CreditFacilityDisposition::Grant {
        build_credit_facility_terms(&scorecard)
    } else {
        None
    };
    let findings = build_credit_facility_findings(
        &scorecard,
        &underwriting_input,
        &prerequisites,
        disposition,
    );

    Ok(CreditFacilityReport {
        schema: CREDIT_FACILITY_REPORT_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        filters: scorecard.filters.clone(),
        scorecard: scorecard.summary,
        disposition,
        prerequisites,
        support_boundary: CreditFacilitySupportBoundary::default(),
        terms,
        findings,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_credit_bond_report_from_store(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
) -> Result<CreditBondReport, TrustHttpError> {
    let scorecard = build_credit_scorecard_report(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        issuance_policy,
        query,
    )?;
    let exposure = build_exposure_ledger_report(receipt_store, &scorecard.filters)?;
    if exposure.summary.mixed_currency_book || exposure.positions.len() != 1 {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "credit bond evaluation requires one coherent currency book because ARC does not auto-net reserve accounting across currencies"
                .to_string(),
        ));
    }
    let underwriting_input = build_underwriting_policy_input(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        &underwriting_input_query_from_exposure_query(&scorecard.filters),
    )?;

    let facility_policy = build_credit_facility_report_from_store(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        &scorecard.filters,
    )?;
    let latest_facility = latest_active_granted_credit_facility(
        receipt_store,
        scorecard.filters.capability_id.as_deref(),
        scorecard.filters.agent_subject.as_deref(),
        scorecard.filters.tool_server.as_deref(),
        scorecard.filters.tool_name.as_deref(),
    )?;
    let position = exposure.positions.first().ok_or_else(|| {
        TrustHttpError::new(
            StatusCode::CONFLICT,
            "credit bond evaluation requires one monetary exposure position".to_string(),
        )
    })?;

    let pending_backlog = underwriting_input.receipts.pending_settlement_receipts > 0
        || credit_facility_has_reason(
            &scorecard,
            CreditScorecardReasonCode::PendingSettlementBacklog,
        );
    let failed_backlog = underwriting_input.receipts.failed_settlement_receipts > 0
        || credit_facility_has_reason(
            &scorecard,
            CreditScorecardReasonCode::FailedSettlementBacklog,
        );
    let net_provisional_loss_units = position
        .provisional_loss_units
        .saturating_sub(position.recovered_units);
    let outstanding_exposure_units = credit_bond_outstanding_units(position);
    let active_facility_required =
        outstanding_exposure_units > 0 || pending_backlog || failed_backlog;
    let active_facility_met = latest_facility.is_some();

    let prerequisites = CreditBondPrerequisites {
        active_facility_required,
        active_facility_met,
        runtime_assurance_met: facility_policy.prerequisites.runtime_assurance_met,
        certification_required: facility_policy.prerequisites.certification_required,
        certification_met: facility_policy.prerequisites.certification_met,
        currency_coherent: true,
    };

    let (disposition, terms, under_collateralized) = match latest_facility.as_ref() {
        Some(facility) => {
            let facility_terms = facility.body.report.terms.as_ref().ok_or_else(|| {
                TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "credit facility `{}` is missing grant terms required for bond accounting",
                        facility.body.facility_id
                    ),
                )
            })?;
            if facility_terms.credit_limit.currency != position.currency {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "credit bond evaluation cannot mix facility currency `{}` with exposure currency `{}`",
                        facility_terms.credit_limit.currency, position.currency
                    ),
                ));
            }
            let terms = build_credit_bond_terms(
                position,
                facility_terms,
                facility.body.facility_id.clone(),
            );
            let under_collateralized = terms.coverage_ratio_bps < 10_000;
            let disposition =
                if failed_backlog || net_provisional_loss_units > 0 || under_collateralized {
                    CreditBondDisposition::Impair
                } else if outstanding_exposure_units > 0 || pending_backlog {
                    CreditBondDisposition::Lock
                } else {
                    CreditBondDisposition::Hold
                };
            (disposition, Some(terms), under_collateralized)
        }
        None => {
            let disposition = if active_facility_required {
                CreditBondDisposition::Impair
            } else {
                CreditBondDisposition::Release
            };
            (disposition, None, false)
        }
    };
    let findings = build_credit_bond_findings(
        &scorecard,
        &exposure,
        &prerequisites,
        disposition,
        pending_backlog,
        failed_backlog,
        under_collateralized,
    );

    Ok(CreditBondReport {
        schema: CREDIT_BOND_REPORT_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        filters: scorecard.filters.clone(),
        exposure: exposure.summary,
        scorecard: scorecard.summary,
        disposition,
        prerequisites,
        support_boundary: CreditBondSupportBoundary {
            autonomy_gating_supported: true,
            ..CreditBondSupportBoundary::default()
        },
        latest_facility_id: latest_facility
            .as_ref()
            .map(|facility| facility.body.facility_id.clone()),
        terms,
        findings,
    })
}

#[allow(clippy::too_many_arguments)]
fn issue_signed_credit_bond_detailed(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
    supersedes_bond_id: Option<&str>,
) -> Result<SignedCreditBond, TrustHttpError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let report = build_credit_bond_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        query,
    )?;
    let latest_facility_expires_at = latest_active_granted_credit_facility(
        &receipt_store,
        report.filters.capability_id.as_deref(),
        report.filters.agent_subject.as_deref(),
        report.filters.tool_server.as_deref(),
        report.filters.tool_name.as_deref(),
    )?
    .map(|facility| facility.body.expires_at);
    let issued_at = unix_timestamp_now();
    let artifact = build_credit_bond_artifact(
        report,
        issued_at,
        supersedes_bond_id.map(ToOwned::to_owned),
        latest_facility_expires_at,
    )?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let signed = SignedCreditBond::sign(artifact, &keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    receipt_store
        .record_credit_bond(&signed)
        .map_err(trust_http_error_from_receipt_store)?;
    Ok(signed)
}

fn build_credit_bond_artifact(
    report: CreditBondReport,
    issued_at: u64,
    supersedes_bond_id: Option<String>,
    latest_facility_expires_at: Option<u64>,
) -> Result<CreditBondArtifact, TrustHttpError> {
    let lifecycle_state = match report.disposition {
        CreditBondDisposition::Lock | CreditBondDisposition::Hold => {
            CreditBondLifecycleState::Active
        }
        CreditBondDisposition::Release => CreditBondLifecycleState::Released,
        CreditBondDisposition::Impair => CreditBondLifecycleState::Impaired,
    };
    let expires_at = latest_facility_expires_at
        .unwrap_or_else(|| issued_at.saturating_add(credit_bond_ttl_seconds(&report)));
    let bond_id_input = canonical_json_bytes(&(
        CREDIT_BOND_ARTIFACT_SCHEMA,
        issued_at,
        expires_at,
        lifecycle_state,
        &supersedes_bond_id,
        &report,
    ))
    .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let bond_id = format!("cbd-{}", sha256_hex(&bond_id_input));

    Ok(CreditBondArtifact {
        schema: CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
        bond_id,
        issued_at,
        expires_at,
        lifecycle_state,
        supersedes_bond_id,
        report,
    })
}

fn build_credit_bonded_execution_simulation_report_from_store(
    receipt_store: &SqliteReceiptStore,
    request: &CreditBondedExecutionSimulationRequest,
) -> Result<CreditBondedExecutionSimulationReport, TrustHttpError> {
    request
        .query
        .validate()
        .map_err(TrustHttpError::bad_request)?;

    let bond_row = receipt_store
        .resolve_credit_bond(&request.query.bond_id)
        .map_err(trust_http_error_from_receipt_store)?
        .ok_or_else(|| {
            TrustHttpError::new(
                StatusCode::NOT_FOUND,
                format!("credit bond `{}` not found", request.query.bond_id),
            )
        })?;
    let lifecycle_history = receipt_store
        .query_credit_loss_lifecycle(&CreditLossLifecycleListQuery {
            event_id: None,
            bond_id: Some(request.query.bond_id.clone()),
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            event_kind: None,
            limit: Some(MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT),
        })
        .map_err(trust_http_error_from_receipt_store)?;
    let support_boundary = CreditBondedExecutionSupportBoundary {
        external_escrow_execution_supported: bond_row
            .bond
            .body
            .report
            .support_boundary
            .external_escrow_execution_supported,
        ..CreditBondedExecutionSupportBoundary::default()
    };
    let default_evaluation = evaluate_credit_bonded_execution(
        &bond_row,
        &lifecycle_history,
        &request.query,
        &CreditBondedExecutionControlPolicy::default(),
        &support_boundary,
    )?;
    let simulated_evaluation = evaluate_credit_bonded_execution(
        &bond_row,
        &lifecycle_history,
        &request.query,
        &request.policy,
        &support_boundary,
    )?;

    Ok(CreditBondedExecutionSimulationReport {
        schema: CREDIT_BONDED_EXECUTION_SIMULATION_REPORT_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        query: request.query.clone(),
        policy: request.policy.clone(),
        support_boundary,
        bond: bond_row.bond,
        default_evaluation: default_evaluation.clone(),
        simulated_evaluation: simulated_evaluation.clone(),
        delta: build_credit_bonded_execution_simulation_delta(
            &default_evaluation,
            &simulated_evaluation,
        ),
    })
}

fn evaluate_credit_bonded_execution(
    bond_row: &arc_kernel::CreditBondRow,
    lifecycle_history: &CreditLossLifecycleListReport,
    query: &arc_kernel::CreditBondedExecutionSimulationQuery,
    policy: &CreditBondedExecutionControlPolicy,
    support_boundary: &CreditBondedExecutionSupportBoundary,
) -> Result<CreditBondedExecutionEvaluation, TrustHttpError> {
    let outstanding_delinquency_amount =
        credit_bonded_execution_outstanding_delinquency_amount(&bond_row.bond, lifecycle_history)?;
    let outstanding_delinquency_refs =
        credit_bonded_execution_loss_evidence(&bond_row.bond, lifecycle_history);
    let bond_refs = credit_bonded_execution_bond_evidence(&bond_row.bond);
    let mut findings = Vec::new();

    if policy.kill_switch {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::KillSwitchEnabled,
            description:
                "operator control policy kill-switch is enabled, so ARC denies bonded execution"
                    .to_string(),
            evidence_refs: bond_refs.clone(),
        });
    }

    if !bond_row
        .bond
        .body
        .report
        .support_boundary
        .autonomy_gating_supported
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::AutonomyGatingUnsupported,
            description:
                "the bond report does not claim autonomy gating support, so ARC fails closed"
                    .to_string(),
            evidence_refs: bond_refs.clone(),
        });
    }

    if policy.deny_if_bond_not_active
        && bond_row.lifecycle_state != CreditBondLifecycleState::Active
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::BondNotActive,
            description: format!(
                "bond `{}` is {:?}, so ARC denies reserve-backed execution",
                bond_row.bond.body.bond_id, bond_row.lifecycle_state
            ),
            evidence_refs: bond_refs.clone(),
        });
    }

    if !matches!(
        bond_row.bond.body.report.disposition,
        CreditBondDisposition::Lock | CreditBondDisposition::Hold
    ) {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::BondDispositionUnsupported,
            description: format!(
                "bond disposition {:?} does not support reserve-backed execution",
                bond_row.bond.body.report.disposition
            ),
            evidence_refs: bond_refs.clone(),
        });
    }

    if bond_row
        .bond
        .body
        .report
        .prerequisites
        .active_facility_required
        && !bond_row.bond.body.report.prerequisites.active_facility_met
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::ActiveFacilityUnavailable,
            description:
                "reserve-backed execution requires an active granted facility for this bond"
                    .to_string(),
            evidence_refs: bond_refs.clone(),
        });
    }

    if !bond_row
        .bond
        .body
        .report
        .prerequisites
        .runtime_assurance_met
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::RuntimePrerequisiteUnmet,
            description:
                "bond prerequisites do not meet the runtime-assurance floor required for reserve-backed execution"
                    .to_string(),
            evidence_refs: bond_refs.clone(),
        });
    }

    if bond_row
        .bond
        .body
        .report
        .prerequisites
        .certification_required
        && !bond_row.bond.body.report.prerequisites.certification_met
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::CertificationPrerequisiteUnmet,
            description:
                "bond prerequisites require an active certification record before reserve-backed execution"
                    .to_string(),
            evidence_refs: bond_refs.clone(),
        });
    }

    let minimum_autonomy_runtime = query.autonomy_tier.minimum_runtime_assurance();
    if query.runtime_assurance_tier < minimum_autonomy_runtime {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::RuntimeAssuranceBelowAutonomyMinimum,
            description: format!(
                "requested runtime assurance {:?} is below the {:?} floor for autonomy tier {:?}",
                query.runtime_assurance_tier, minimum_autonomy_runtime, query.autonomy_tier
            ),
            evidence_refs: bond_refs.clone(),
        });
    }

    if let Some(policy_minimum) = policy.minimum_runtime_assurance_tier {
        if query.runtime_assurance_tier < policy_minimum {
            findings.push(CreditBondedExecutionFinding {
                code: CreditBondedExecutionFindingCode::RuntimeAssuranceBelowPolicyMinimum,
                description: format!(
                    "operator control policy requires runtime assurance {:?}, but the request supplied {:?}",
                    policy_minimum, query.runtime_assurance_tier
                ),
                evidence_refs: bond_refs.clone(),
            });
        }
    }

    if let Some(maximum_autonomy_tier) = policy.maximum_autonomy_tier {
        if query.autonomy_tier > maximum_autonomy_tier {
            findings.push(CreditBondedExecutionFinding {
                code: CreditBondedExecutionFindingCode::AutonomyTierAbovePolicyMaximum,
                description: format!(
                    "operator control policy caps bonded execution at {:?}, but the request asked for {:?}",
                    maximum_autonomy_tier, query.autonomy_tier
                ),
                evidence_refs: bond_refs.clone(),
            });
        }
    }

    if policy.require_delegated_call_chain
        && query.autonomy_tier.requires_call_chain()
        && !query.call_chain_present
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::MissingDelegatedCallChain,
            description: "delegated or autonomous bonded execution requires call-chain context"
                .to_string(),
            evidence_refs: bond_refs.clone(),
        });
    }

    if policy.require_locked_reserve
        && bond_row.bond.body.report.disposition != CreditBondDisposition::Lock
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::ReserveNotLocked,
            description:
                "operator control policy requires a locked reserve posture before execution"
                    .to_string(),
            evidence_refs: bond_refs.clone(),
        });
    }

    if lifecycle_history.summary.matching_events > lifecycle_history.summary.returned_events {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::LossLifecycleHistoryTruncated,
            description:
                "bonded execution simulation requires complete loss lifecycle history, but the returned page was truncated"
                    .to_string(),
            evidence_refs: outstanding_delinquency_refs.clone(),
        });
    }

    if policy.deny_if_outstanding_delinquency
        && outstanding_delinquency_amount
            .as_ref()
            .is_some_and(|amount| amount.units > 0)
    {
        findings.push(CreditBondedExecutionFinding {
            code: CreditBondedExecutionFindingCode::OutstandingDelinquency,
            description:
                "outstanding delinquent bonded loss remains unresolved, so ARC denies execution"
                    .to_string(),
            evidence_refs: outstanding_delinquency_refs,
        });
    }

    let decision = if findings.is_empty() {
        CreditBondedExecutionDecision::Allow
    } else {
        CreditBondedExecutionDecision::Deny
    };
    let sandbox_integration_ready = decision == CreditBondedExecutionDecision::Allow
        && support_boundary.sandbox_simulation_supported
        && bond_row
            .bond
            .body
            .report
            .support_boundary
            .autonomy_gating_supported;

    Ok(CreditBondedExecutionEvaluation {
        decision,
        autonomy_tier: query.autonomy_tier,
        runtime_assurance_tier: query.runtime_assurance_tier,
        bond_lifecycle_state: bond_row.lifecycle_state,
        bond_disposition: bond_row.bond.body.report.disposition,
        sandbox_integration_ready,
        outstanding_delinquency_amount,
        findings,
    })
}

fn credit_bonded_execution_outstanding_delinquency_amount(
    bond: &SignedCreditBond,
    lifecycle_history: &CreditLossLifecycleListReport,
) -> Result<Option<MonetaryAmount>, TrustHttpError> {
    let currency = bond
        .body
        .report
        .terms
        .as_ref()
        .map(|terms| terms.credit_limit.currency.clone())
        .or_else(|| {
            lifecycle_history.events.iter().find_map(|row| {
                row.event
                    .body
                    .report
                    .summary
                    .event_amount
                    .as_ref()
                    .map(|amount| amount.currency.clone())
            })
        });
    let Some(currency) = currency else {
        return Ok(None);
    };
    let accounting = compute_credit_loss_lifecycle_accounting(&currency, lifecycle_history)
        .map_err(|message| TrustHttpError::new(StatusCode::CONFLICT, message))?;
    Ok(amount_if_nonzero(
        accounting.outstanding_delinquent_units(),
        &currency,
    ))
}

fn credit_bonded_execution_bond_evidence(
    bond: &SignedCreditBond,
) -> Vec<CreditScorecardEvidenceReference> {
    vec![CreditScorecardEvidenceReference {
        kind: CreditScorecardEvidenceKind::CreditBond,
        reference_id: bond.body.bond_id.clone(),
        observed_at: Some(bond.body.issued_at),
        locator: Some(format!("credit-bond:{}", bond.body.bond_id)),
    }]
}

fn credit_bonded_execution_loss_evidence(
    bond: &SignedCreditBond,
    lifecycle_history: &CreditLossLifecycleListReport,
) -> Vec<CreditScorecardEvidenceReference> {
    let mut evidence_refs = credit_bonded_execution_bond_evidence(bond);
    let mut seen = BTreeSet::from([format!("credit-bond:{}", bond.body.bond_id)]);
    for row in &lifecycle_history.events {
        let key = format!("credit-loss-lifecycle:{}", row.event.body.event_id);
        if seen.insert(key.clone()) {
            evidence_refs.push(CreditScorecardEvidenceReference {
                kind: CreditScorecardEvidenceKind::CreditLossLifecycle,
                reference_id: row.event.body.event_id.clone(),
                observed_at: Some(row.event.body.issued_at),
                locator: Some(key),
            });
        }
    }
    evidence_refs
}

fn build_credit_bonded_execution_simulation_delta(
    default_evaluation: &CreditBondedExecutionEvaluation,
    simulated_evaluation: &CreditBondedExecutionEvaluation,
) -> CreditBondedExecutionSimulationDelta {
    let default_reasons = credit_bonded_execution_reason_keys(default_evaluation);
    let simulated_reasons = credit_bonded_execution_reason_keys(simulated_evaluation);

    CreditBondedExecutionSimulationDelta {
        decision_changed: default_evaluation.decision != simulated_evaluation.decision,
        sandbox_integration_changed: default_evaluation.sandbox_integration_ready
            != simulated_evaluation.sandbox_integration_ready,
        added_reasons: simulated_reasons
            .iter()
            .filter(|reason| !default_reasons.contains(reason))
            .cloned()
            .collect(),
        removed_reasons: default_reasons
            .iter()
            .filter(|reason| !simulated_reasons.contains(reason))
            .cloned()
            .collect(),
    }
}

fn credit_bonded_execution_reason_keys(
    evaluation: &CreditBondedExecutionEvaluation,
) -> Vec<String> {
    let mut reasons = Vec::new();
    for reason in evaluation
        .findings
        .iter()
        .map(|finding| credit_bonded_execution_reason_key(finding.code).to_string())
    {
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }
    reasons
}

fn credit_bonded_execution_reason_key(code: CreditBondedExecutionFindingCode) -> &'static str {
    match code {
        CreditBondedExecutionFindingCode::KillSwitchEnabled => "kill_switch_enabled",
        CreditBondedExecutionFindingCode::AutonomyGatingUnsupported => {
            "autonomy_gating_unsupported"
        }
        CreditBondedExecutionFindingCode::BondNotActive => "bond_not_active",
        CreditBondedExecutionFindingCode::BondDispositionUnsupported => {
            "bond_disposition_unsupported"
        }
        CreditBondedExecutionFindingCode::ActiveFacilityUnavailable => {
            "active_facility_unavailable"
        }
        CreditBondedExecutionFindingCode::RuntimePrerequisiteUnmet => "runtime_prerequisite_unmet",
        CreditBondedExecutionFindingCode::CertificationPrerequisiteUnmet => {
            "certification_prerequisite_unmet"
        }
        CreditBondedExecutionFindingCode::RuntimeAssuranceBelowAutonomyMinimum => {
            "runtime_assurance_below_autonomy_minimum"
        }
        CreditBondedExecutionFindingCode::RuntimeAssuranceBelowPolicyMinimum => {
            "runtime_assurance_below_policy_minimum"
        }
        CreditBondedExecutionFindingCode::MissingDelegatedCallChain => {
            "missing_delegated_call_chain"
        }
        CreditBondedExecutionFindingCode::AutonomyTierAbovePolicyMaximum => {
            "autonomy_tier_above_policy_maximum"
        }
        CreditBondedExecutionFindingCode::ReserveNotLocked => "reserve_not_locked",
        CreditBondedExecutionFindingCode::OutstandingDelinquency => "outstanding_delinquency",
        CreditBondedExecutionFindingCode::LossLifecycleHistoryTruncated => {
            "loss_lifecycle_history_truncated"
        }
    }
}

#[derive(Debug, Clone)]
struct CreditLossLifecycleAccountingState {
    currency: String,
    delinquent_units: u64,
    recovered_units: u64,
    reserve_released_units: u64,
    written_off_units: u64,
}

impl CreditLossLifecycleAccountingState {
    fn outstanding_delinquent_units(&self) -> u64 {
        self.delinquent_units
            .saturating_sub(self.recovered_units.saturating_add(self.written_off_units))
    }
}

fn build_credit_loss_lifecycle_report_from_store(
    receipt_store: &SqliteReceiptStore,
    query: &CreditLossLifecycleQuery,
) -> Result<CreditLossLifecycleReport, TrustHttpError> {
    query.validate().map_err(TrustHttpError::bad_request)?;

    let bond_row = receipt_store
        .resolve_credit_bond(&query.bond_id)
        .map_err(trust_http_error_from_receipt_store)?
        .ok_or_else(|| {
            TrustHttpError::new(
                StatusCode::NOT_FOUND,
                format!("credit bond `{}` not found", query.bond_id),
            )
        })?;
    let bond = &bond_row.bond;
    let terms = bond.body.report.terms.as_ref().ok_or_else(|| {
        TrustHttpError::new(
            StatusCode::CONFLICT,
            format!(
                "credit bond `{}` is missing terms required for loss lifecycle accounting",
                query.bond_id
            ),
        )
    })?;
    let currency = terms.collateral_amount.currency.clone();

    let lifecycle_history = receipt_store
        .query_credit_loss_lifecycle(&CreditLossLifecycleListQuery {
            event_id: None,
            bond_id: Some(query.bond_id.clone()),
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            event_kind: None,
            limit: Some(MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT),
        })
        .map_err(trust_http_error_from_receipt_store)?;
    let accounting = compute_credit_loss_lifecycle_accounting(&currency, &lifecycle_history)
        .map_err(|message| TrustHttpError::new(StatusCode::CONFLICT, message))?;
    let loss_query = BehavioralFeedQuery {
        capability_id: bond.body.report.filters.capability_id.clone(),
        agent_subject: bond.body.report.filters.agent_subject.clone(),
        tool_server: bond.body.report.filters.tool_server.clone(),
        tool_name: bond.body.report.filters.tool_name.clone(),
        since: bond.body.report.filters.since,
        until: bond.body.report.filters.until,
        receipt_limit: Some(arc_kernel::MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT),
    };
    let (_, recent_loss_receipts) = receipt_store
        .query_recent_credit_loss_receipts(
            &loss_query,
            arc_kernel::MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT,
        )
        .map_err(trust_http_error_from_receipt_store)?;
    let (current_outstanding_loss_units, current_loss_evidence_refs) =
        build_credit_loss_lifecycle_outstanding_loss_state(&recent_loss_receipts, &currency)?;

    let exposure = build_exposure_ledger_report(receipt_store, &bond.body.report.filters)?;
    if exposure.summary.mixed_currency_book {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "credit loss lifecycle requires one coherent currency book because ARC does not auto-net lifecycle accounting across currencies"
                .to_string(),
        ));
    }
    let position = exposure
        .positions
        .iter()
        .find(|position| position.currency == currency)
        .cloned()
        .unwrap_or_else(|| empty_exposure_position(&currency));
    let outstanding_delinquent_units = accounting.outstanding_delinquent_units();
    let releaseable_reserve_units = terms
        .reserve_requirement_amount
        .units
        .saturating_sub(accounting.reserve_released_units);
    let current_outstanding_exposure_units =
        credit_bond_outstanding_units(&position).max(current_outstanding_loss_units);
    let recordable_delinquency_units =
        current_outstanding_loss_units.saturating_sub(accounting.delinquent_units);
    let unresolved_live_exposure_units =
        current_outstanding_exposure_units.saturating_sub(accounting.delinquent_units);

    let (event_amount, projected_bond_lifecycle_state, findings) = match query.event_kind {
        CreditLossLifecycleEventKind::Delinquency => {
            if bond_row.lifecycle_state != CreditBondLifecycleState::Active {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "credit loss delinquency requires active bond `{}`",
                        query.bond_id
                    ),
                ));
            }
            if recordable_delinquency_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit loss delinquency requires new outstanding failed or delinquent bonded exposure"
                        .to_string(),
                ));
            }
            let event_amount = match query.amount.as_ref() {
                Some(amount) => {
                    ensure_credit_loss_lifecycle_currency(amount, &currency)?;
                    if amount.units > recordable_delinquency_units {
                        return Err(TrustHttpError::new(
                            StatusCode::CONFLICT,
                            format!(
                                "credit loss delinquency amount {} exceeds recordable outstanding loss {}",
                                amount.units, recordable_delinquency_units
                            ),
                        ));
                    }
                    amount.clone()
                }
                None => MonetaryAmount {
                    units: recordable_delinquency_units,
                    currency: currency.clone(),
                },
            };

            (
                Some(event_amount),
                CreditBondLifecycleState::Impaired,
                vec![CreditLossLifecycleFinding {
                    code: CreditLossLifecycleReasonCode::DelinquencyRecorded,
                    description:
                        "new outstanding bonded loss has been recorded as delinquent against the bond"
                            .to_string(),
                    evidence_refs: current_loss_evidence_refs,
                }],
            )
        }
        CreditLossLifecycleEventKind::Recovery => {
            if outstanding_delinquent_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit recovery requires outstanding delinquent amount".to_string(),
                ));
            }
            let amount = query.amount.as_ref().ok_or_else(|| {
                TrustHttpError::bad_request(
                    "credit recovery requires --amount-units and --amount-currency",
                )
            })?;
            ensure_credit_loss_lifecycle_currency(amount, &currency)?;
            if amount.units > outstanding_delinquent_units {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "credit recovery amount {} exceeds outstanding delinquent amount {}",
                        amount.units, outstanding_delinquent_units
                    ),
                ));
            }
            (
                Some(amount.clone()),
                bond_row.lifecycle_state,
                vec![CreditLossLifecycleFinding {
                    code: CreditLossLifecycleReasonCode::RecoveryRecorded,
                    description:
                        "recovery has been recorded against previously delinquent bonded exposure"
                            .to_string(),
                    evidence_refs: credit_loss_lifecycle_transition_evidence(
                        bond,
                        &lifecycle_history,
                        CreditLossLifecycleEventKind::Delinquency,
                    ),
                }],
            )
        }
        CreditLossLifecycleEventKind::ReserveRelease => {
            if outstanding_delinquent_units > 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve release requires outstanding delinquency to be cleared first"
                        .to_string(),
                ));
            }
            if unresolved_live_exposure_units > 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve release requires no unbooked outstanding exposure to remain"
                        .to_string(),
                ));
            }
            if releaseable_reserve_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve release is unavailable because the reserve is already fully released"
                        .to_string(),
                ));
            }
            let event_amount = match query.amount.as_ref() {
                Some(amount) => {
                    ensure_credit_loss_lifecycle_currency(amount, &currency)?;
                    if amount.units > releaseable_reserve_units {
                        return Err(TrustHttpError::new(
                            StatusCode::CONFLICT,
                            format!(
                                "credit reserve release amount {} exceeds releasable reserve {}",
                                amount.units, releaseable_reserve_units
                            ),
                        ));
                    }
                    amount.clone()
                }
                None => MonetaryAmount {
                    units: releaseable_reserve_units,
                    currency: currency.clone(),
                },
            };
            (
                Some(event_amount),
                CreditBondLifecycleState::Released,
                vec![CreditLossLifecycleFinding {
                    code: CreditLossLifecycleReasonCode::ReserveReleased,
                    description:
                        "reserve backing has been explicitly released after delinquency was cleared"
                            .to_string(),
                    evidence_refs: credit_loss_lifecycle_transition_evidence(
                        bond,
                        &lifecycle_history,
                        CreditLossLifecycleEventKind::Recovery,
                    ),
                }],
            )
        }
        CreditLossLifecycleEventKind::WriteOff => {
            if outstanding_delinquent_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit write-off requires outstanding delinquent amount".to_string(),
                ));
            }
            let amount = query.amount.as_ref().ok_or_else(|| {
                TrustHttpError::bad_request(
                    "credit write-off requires --amount-units and --amount-currency",
                )
            })?;
            ensure_credit_loss_lifecycle_currency(amount, &currency)?;
            if amount.units > outstanding_delinquent_units {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "credit write-off amount {} exceeds outstanding delinquent amount {}",
                        amount.units, outstanding_delinquent_units
                    ),
                ));
            }
            (
                Some(amount.clone()),
                CreditBondLifecycleState::Impaired,
                vec![CreditLossLifecycleFinding {
                    code: CreditLossLifecycleReasonCode::WriteOffRecorded,
                    description: "outstanding delinquent exposure has been explicitly written off"
                        .to_string(),
                    evidence_refs: credit_loss_lifecycle_transition_evidence(
                        bond,
                        &lifecycle_history,
                        CreditLossLifecycleEventKind::Delinquency,
                    ),
                }],
            )
        }
    };

    Ok(CreditLossLifecycleReport {
        schema: CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        query: query.clone(),
        summary: arc_kernel::CreditLossLifecycleSummary {
            bond_id: bond.body.bond_id.clone(),
            facility_id: bond.body.report.latest_facility_id.clone(),
            capability_id: bond.body.report.filters.capability_id.clone(),
            agent_subject: bond.body.report.filters.agent_subject.clone(),
            tool_server: bond.body.report.filters.tool_server.clone(),
            tool_name: bond.body.report.filters.tool_name.clone(),
            current_bond_lifecycle_state: bond_row.lifecycle_state,
            projected_bond_lifecycle_state,
            current_delinquent_amount: amount_if_nonzero(accounting.delinquent_units, &currency),
            current_recovered_amount: amount_if_nonzero(accounting.recovered_units, &currency),
            current_written_off_amount: amount_if_nonzero(accounting.written_off_units, &currency),
            current_released_reserve_amount: amount_if_nonzero(
                accounting.reserve_released_units,
                &currency,
            ),
            outstanding_delinquent_amount: amount_if_nonzero(
                outstanding_delinquent_units,
                &currency,
            ),
            releaseable_reserve_amount: amount_if_nonzero(releaseable_reserve_units, &currency),
            event_amount,
        },
        support_boundary: CreditLossLifecycleSupportBoundary::default(),
        findings,
    })
}

fn issue_signed_credit_loss_lifecycle_detailed(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    query: &CreditLossLifecycleQuery,
) -> Result<SignedCreditLossLifecycle, TrustHttpError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let report = build_credit_loss_lifecycle_report_from_store(&receipt_store, query)?;
    let issued_at = unix_timestamp_now();
    let event_id_input =
        canonical_json_bytes(&(CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA, issued_at, &report))
            .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let event = CreditLossLifecycleArtifact {
        schema: CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA.to_string(),
        event_id: format!("cll-{}", sha256_hex(&event_id_input)),
        issued_at,
        bond_id: report.query.bond_id.clone(),
        event_kind: report.query.event_kind,
        projected_bond_lifecycle_state: report.summary.projected_bond_lifecycle_state,
        report,
    };
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let signed = SignedCreditLossLifecycle::sign(event, &keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    receipt_store
        .record_credit_loss_lifecycle(&signed)
        .map_err(trust_http_error_from_receipt_store)?;
    Ok(signed)
}

#[allow(clippy::too_many_arguments)]
fn issue_signed_credit_facility_detailed(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
    supersedes_facility_id: Option<&str>,
) -> Result<SignedCreditFacility, TrustHttpError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let report = build_credit_facility_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        query,
    )?;
    let issued_at = unix_timestamp_now();
    let artifact = build_credit_facility_artifact(
        report,
        issued_at,
        supersedes_facility_id.map(ToOwned::to_owned),
    )?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let signed = SignedCreditFacility::sign(artifact, &keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    receipt_store
        .record_credit_facility(&signed)
        .map_err(trust_http_error_from_receipt_store)?;
    Ok(signed)
}

fn build_credit_facility_artifact(
    report: CreditFacilityReport,
    issued_at: u64,
    supersedes_facility_id: Option<String>,
) -> Result<CreditFacilityArtifact, TrustHttpError> {
    let lifecycle_state = if report.disposition == CreditFacilityDisposition::Deny {
        CreditFacilityLifecycleState::Denied
    } else {
        CreditFacilityLifecycleState::Active
    };
    let expires_at = issued_at.saturating_add(credit_facility_ttl_seconds(&report));
    let facility_id_input = canonical_json_bytes(&(
        CREDIT_FACILITY_ARTIFACT_SCHEMA,
        issued_at,
        expires_at,
        lifecycle_state,
        &supersedes_facility_id,
        &report,
    ))
    .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let facility_id = format!("cfd-{}", sha256_hex(&facility_id_input));

    Ok(CreditFacilityArtifact {
        schema: CREDIT_FACILITY_ARTIFACT_SCHEMA.to_string(),
        facility_id,
        issued_at,
        expires_at,
        lifecycle_state,
        supersedes_facility_id,
        report,
    })
}

fn underwriting_input_query_from_exposure_query(
    query: &ExposureLedgerQuery,
) -> UnderwritingPolicyInputQuery {
    UnderwritingPolicyInputQuery {
        capability_id: query.capability_id.clone(),
        agent_subject: query.agent_subject.clone(),
        tool_server: query.tool_server.clone(),
        tool_name: query.tool_name.clone(),
        since: query.since,
        until: query.until,
        receipt_limit: query.receipt_limit,
    }
}

fn credit_facility_minimum_runtime_assurance_tier(
    band: CreditScorecardBand,
) -> RuntimeAssuranceTier {
    match band {
        CreditScorecardBand::Prime
        | CreditScorecardBand::Standard
        | CreditScorecardBand::Guarded => RuntimeAssuranceTier::Attested,
        CreditScorecardBand::Probationary | CreditScorecardBand::Restricted => {
            RuntimeAssuranceTier::Verified
        }
    }
}

fn build_credit_facility_terms(scorecard: &CreditScorecardReport) -> Option<CreditFacilityTerms> {
    let position = match scorecard.positions.as_slice() {
        [position] => position,
        _ => return None,
    };
    let base_units = position.governed_max_exposure_units.max(
        position
            .settled_units
            .saturating_add(position.pending_units),
    );
    if base_units == 0 {
        return None;
    }

    let band_factor = match scorecard.summary.band {
        CreditScorecardBand::Prime => 1.0,
        CreditScorecardBand::Standard => 0.85,
        CreditScorecardBand::Guarded => 0.65,
        CreditScorecardBand::Probationary => 0.40,
        CreditScorecardBand::Restricted => 0.0,
    };
    let confidence_factor = match scorecard.summary.confidence {
        CreditScorecardConfidence::High => 1.0,
        CreditScorecardConfidence::Medium => 0.9,
        CreditScorecardConfidence::Low => 0.75,
    };
    let credit_limit_units = ((base_units as f64) * band_factor * confidence_factor).floor() as u64;
    if credit_limit_units == 0 {
        return None;
    }

    let (utilization_ceiling_bps, reserve_ratio_bps, concentration_cap_bps, ttl_seconds) =
        match scorecard.summary.band {
            CreditScorecardBand::Prime => (9_000, 1_000, 3_500, 30 * 86_400),
            CreditScorecardBand::Standard => (8_000, 1_500, 3_000, 14 * 86_400),
            CreditScorecardBand::Guarded => (6_500, 2_500, 2_000, 7 * 86_400),
            CreditScorecardBand::Probationary | CreditScorecardBand::Restricted => return None,
        };

    Some(CreditFacilityTerms {
        credit_limit: MonetaryAmount {
            units: credit_limit_units,
            currency: position.currency.clone(),
        },
        utilization_ceiling_bps,
        reserve_ratio_bps,
        concentration_cap_bps,
        ttl_seconds,
        capital_source: CreditFacilityCapitalSource::OperatorInternal,
    })
}

fn build_credit_facility_findings(
    scorecard: &CreditScorecardReport,
    underwriting_input: &UnderwritingPolicyInput,
    prerequisites: &CreditFacilityPrerequisites,
    disposition: CreditFacilityDisposition,
) -> Vec<CreditFacilityFinding> {
    let mut findings = Vec::new();
    if scorecard.summary.band == CreditScorecardBand::Restricted {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::ScoreRestricted,
            description: "scorecard band is restricted, so ARC denies facility allocation"
                .to_string(),
            evidence_refs: credit_facility_reputation_evidence(scorecard),
        });
    }
    if scorecard.summary.probationary {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::ProbationaryScore,
            description:
                "scorecard remains probationary, so ARC requires provider review before allocation"
                    .to_string(),
            evidence_refs: credit_facility_reputation_evidence(scorecard),
        });
    }
    if scorecard.summary.confidence == CreditScorecardConfidence::Low {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::LowConfidence,
            description:
                "scorecard confidence is low, so ARC will not auto-allocate external capital"
                    .to_string(),
            evidence_refs: credit_facility_reputation_evidence(scorecard),
        });
    }
    if scorecard.summary.mixed_currency_book {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::MixedCurrencyBook,
            description:
                "matching governed history spans multiple currencies, which ARC does not auto-net"
                    .to_string(),
            evidence_refs: credit_facility_evidence_for_reason(
                scorecard,
                CreditScorecardReasonCode::MixedCurrencyBook,
            ),
        });
    }
    if !prerequisites.runtime_assurance_met {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::MissingRuntimeAssurance,
            description: format!(
                "runtime assurance evidence did not satisfy the {:?} minimum required for this score band",
                prerequisites.minimum_runtime_assurance_tier
            ),
            evidence_refs: credit_facility_receipt_refs_from_underwriting(underwriting_input),
        });
    }
    if prerequisites.certification_required && !prerequisites.certification_met {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::CertificationNotActive,
            description:
                "tool-server-scoped facility allocation requires an active certification record"
                    .to_string(),
            evidence_refs: Vec::new(),
        });
    }
    if credit_facility_has_reason(
        scorecard,
        CreditScorecardReasonCode::FailedSettlementBacklog,
    ) {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::FailedSettlementBacklog,
            description:
                "failed settlement exposure remains unresolved in the requested evidence window"
                    .to_string(),
            evidence_refs: credit_facility_evidence_for_reason(
                scorecard,
                CreditScorecardReasonCode::FailedSettlementBacklog,
            ),
        });
    }
    if credit_facility_has_reason(
        scorecard,
        CreditScorecardReasonCode::PendingSettlementBacklog,
    ) {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::PendingSettlementBacklog,
            description:
                "pending settlement exposure remains open in the requested evidence window"
                    .to_string(),
            evidence_refs: credit_facility_evidence_for_reason(
                scorecard,
                CreditScorecardReasonCode::PendingSettlementBacklog,
            ),
        });
    }
    if disposition == CreditFacilityDisposition::Grant {
        findings.push(CreditFacilityFinding {
            code: CreditFacilityReasonCode::FacilityGranted,
            description:
                "score, runtime assurance, and bounded exposure satisfied ARC auto-allocation policy"
                    .to_string(),
            evidence_refs: credit_facility_reputation_evidence(scorecard),
        });
    }
    findings
}

fn credit_facility_ttl_seconds(report: &CreditFacilityReport) -> u64 {
    report
        .terms
        .as_ref()
        .map(|terms| terms.ttl_seconds)
        .unwrap_or_else(|| match report.disposition {
            CreditFacilityDisposition::Grant => 7 * 86_400,
            CreditFacilityDisposition::ManualReview => 7 * 86_400,
            CreditFacilityDisposition::Deny => 86_400,
        })
}

fn credit_facility_has_reason(
    scorecard: &CreditScorecardReport,
    reason: CreditScorecardReasonCode,
) -> bool {
    scorecard
        .anomalies
        .iter()
        .any(|anomaly| anomaly.code == reason)
}

fn credit_facility_evidence_for_reason(
    scorecard: &CreditScorecardReport,
    reason: CreditScorecardReasonCode,
) -> Vec<CreditScorecardEvidenceReference> {
    scorecard
        .anomalies
        .iter()
        .find(|anomaly| anomaly.code == reason)
        .map(|anomaly| anomaly.evidence_refs.clone())
        .unwrap_or_default()
}

fn credit_facility_reputation_evidence(
    scorecard: &CreditScorecardReport,
) -> Vec<CreditScorecardEvidenceReference> {
    scorecard
        .dimensions
        .iter()
        .find(|dimension| dimension.kind == CreditScorecardDimensionKind::ReputationSupport)
        .map(|dimension| dimension.evidence_refs.clone())
        .unwrap_or_default()
}

fn credit_facility_receipt_refs_from_underwriting(
    underwriting_input: &UnderwritingPolicyInput,
) -> Vec<CreditScorecardEvidenceReference> {
    underwriting_input
        .receipts
        .receipt_refs
        .iter()
        .filter_map(|reference| match reference.kind {
            UnderwritingEvidenceKind::Receipt => Some(CreditScorecardEvidenceReference {
                kind: CreditScorecardEvidenceKind::Receipt,
                reference_id: reference.reference_id.clone(),
                observed_at: reference.observed_at,
                locator: reference.locator.clone(),
            }),
            UnderwritingEvidenceKind::SettlementReconciliation => {
                Some(CreditScorecardEvidenceReference {
                    kind: CreditScorecardEvidenceKind::SettlementReconciliation,
                    reference_id: reference.reference_id.clone(),
                    observed_at: reference.observed_at,
                    locator: reference.locator.clone(),
                })
            }
            UnderwritingEvidenceKind::ReputationInspection
            | UnderwritingEvidenceKind::CertificationArtifact
            | UnderwritingEvidenceKind::RuntimeAssuranceEvidence
            | UnderwritingEvidenceKind::SharedEvidenceReference
            | UnderwritingEvidenceKind::MeteredBillingReconciliation => None,
        })
        .collect()
}

fn credit_backtest_utilization_bps(
    positions: &[ExposureLedgerCurrencyPosition],
    terms: Option<&CreditFacilityTerms>,
) -> Option<u32> {
    let [position] = positions else {
        return None;
    };
    if terms.is_some_and(|terms| position.currency != terms.credit_limit.currency) {
        return None;
    }
    let denominator = terms.map_or_else(
        || {
            position.governed_max_exposure_units.max(
                position
                    .settled_units
                    .saturating_add(position.pending_units),
            )
        },
        |terms| terms.credit_limit.units,
    );
    if denominator == 0 {
        return None;
    }
    let utilized_units = position
        .reserved_units
        .saturating_add(position.pending_units)
        .saturating_add(position.failed_units)
        .saturating_add(position.provisional_loss_units)
        .saturating_sub(position.recovered_units);
    Some(((utilized_units as u128) * 10_000 / (denominator as u128)).min(u32::MAX as u128) as u32)
}

fn latest_credit_facility_snapshot(
    receipt_store: &SqliteReceiptStore,
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
) -> Result<Option<CreditProviderFacilitySnapshot>, TrustHttpError> {
    let report = receipt_store
        .query_credit_facilities(&CreditFacilityListQuery {
            facility_id: None,
            capability_id: capability_id.map(ToOwned::to_owned),
            agent_subject: agent_subject.map(ToOwned::to_owned),
            tool_server: tool_server.map(ToOwned::to_owned),
            tool_name: tool_name.map(ToOwned::to_owned),
            disposition: None,
            lifecycle_state: None,
            limit: Some(MAX_CREDIT_FACILITY_LIST_LIMIT),
        })
        .map_err(trust_http_error_from_receipt_store)?;
    Ok(report
        .facilities
        .into_iter()
        .next()
        .map(|row| CreditProviderFacilitySnapshot {
            facility_id: row.facility.body.facility_id,
            issued_at: row.facility.body.issued_at,
            expires_at: row.facility.body.expires_at,
            disposition: row.facility.body.report.disposition,
            lifecycle_state: row.lifecycle_state,
            credit_limit: row
                .facility
                .body
                .report
                .terms
                .as_ref()
                .map(|terms| terms.credit_limit.clone()),
            supersedes_facility_id: row.facility.body.supersedes_facility_id,
            signer_key: row.facility.signer_key.to_hex(),
        }))
}

fn latest_active_granted_credit_facility(
    receipt_store: &SqliteReceiptStore,
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
) -> Result<Option<SignedCreditFacility>, TrustHttpError> {
    let report = receipt_store
        .query_credit_facilities(&CreditFacilityListQuery {
            facility_id: None,
            capability_id: capability_id.map(ToOwned::to_owned),
            agent_subject: agent_subject.map(ToOwned::to_owned),
            tool_server: tool_server.map(ToOwned::to_owned),
            tool_name: tool_name.map(ToOwned::to_owned),
            disposition: Some(CreditFacilityDisposition::Grant),
            lifecycle_state: Some(CreditFacilityLifecycleState::Active),
            limit: Some(1),
        })
        .map_err(trust_http_error_from_receipt_store)?;
    Ok(report.facilities.into_iter().next().map(|row| row.facility))
}

fn build_credit_bond_terms(
    position: &ExposureLedgerCurrencyPosition,
    facility_terms: &CreditFacilityTerms,
    facility_id: String,
) -> CreditBondTerms {
    let outstanding_exposure_units = credit_bond_outstanding_units(position);
    let collateral_units = credit_bond_reserve_units(
        facility_terms.credit_limit.units,
        facility_terms.reserve_ratio_bps,
    );
    let reserve_requirement_units = collateral_units.max(credit_bond_reserve_units(
        outstanding_exposure_units,
        facility_terms.reserve_ratio_bps,
    ));
    let coverage_ratio_bps = if reserve_requirement_units == 0 {
        10_000
    } else {
        (((collateral_units as u128) * 10_000) / (reserve_requirement_units as u128))
            .min(u16::MAX as u128) as u16
    };

    CreditBondTerms {
        facility_id,
        credit_limit: facility_terms.credit_limit.clone(),
        collateral_amount: MonetaryAmount {
            units: collateral_units,
            currency: position.currency.clone(),
        },
        reserve_requirement_amount: MonetaryAmount {
            units: reserve_requirement_units,
            currency: position.currency.clone(),
        },
        outstanding_exposure_amount: MonetaryAmount {
            units: outstanding_exposure_units,
            currency: position.currency.clone(),
        },
        reserve_ratio_bps: facility_terms.reserve_ratio_bps,
        coverage_ratio_bps,
        capital_source: facility_terms.capital_source,
    }
}

fn build_credit_bond_findings(
    scorecard: &CreditScorecardReport,
    exposure: &ExposureLedgerReport,
    prerequisites: &CreditBondPrerequisites,
    disposition: CreditBondDisposition,
    pending_backlog: bool,
    failed_backlog: bool,
    under_collateralized: bool,
) -> Vec<CreditBondFinding> {
    let mut findings = Vec::new();
    if prerequisites.active_facility_required && !prerequisites.active_facility_met {
        findings.push(CreditBondFinding {
            code: CreditBondReasonCode::ActiveFacilityMissing,
            description:
                "reserve-backed autonomy requires an active granted facility for the requested exposure"
                    .to_string(),
            evidence_refs: credit_bond_receipt_evidence_from_exposure(exposure, |receipt| {
                receipt.action_required
                    || receipt.settlement_status == SettlementStatus::Pending
                    || receipt.settlement_status == SettlementStatus::Failed
            }),
        });
    }
    if pending_backlog {
        findings.push(CreditBondFinding {
            code: CreditBondReasonCode::PendingSettlementBacklog,
            description:
                "pending settlement exposure remains open, so ARC keeps reserve state locked"
                    .to_string(),
            evidence_refs: if credit_facility_has_reason(
                scorecard,
                CreditScorecardReasonCode::PendingSettlementBacklog,
            ) {
                credit_facility_evidence_for_reason(
                    scorecard,
                    CreditScorecardReasonCode::PendingSettlementBacklog,
                )
            } else {
                credit_bond_receipt_evidence_from_exposure(exposure, |receipt| {
                    receipt.settlement_status == SettlementStatus::Pending
                })
            },
        });
    }
    if failed_backlog {
        findings.push(CreditBondFinding {
            code: CreditBondReasonCode::FailedSettlementBacklog,
            description:
                "failed settlement exposure remains unresolved, so ARC marks the bond impaired"
                    .to_string(),
            evidence_refs: if credit_facility_has_reason(
                scorecard,
                CreditScorecardReasonCode::FailedSettlementBacklog,
            ) {
                credit_facility_evidence_for_reason(
                    scorecard,
                    CreditScorecardReasonCode::FailedSettlementBacklog,
                )
            } else {
                credit_bond_receipt_evidence_from_exposure(exposure, |receipt| {
                    receipt.settlement_status == SettlementStatus::Failed
                })
            },
        });
    }
    let provisional_loss_refs = credit_bond_receipt_evidence_from_exposure(exposure, |receipt| {
        receipt
            .provisional_loss_amount
            .as_ref()
            .is_some_and(|amount| amount.units > 0)
    });
    if !provisional_loss_refs.is_empty() || failed_backlog {
        findings.push(CreditBondFinding {
            code: CreditBondReasonCode::ProvisionalLossOutstanding,
            description: "provisional loss remains outstanding in the selected exposure window"
                .to_string(),
            evidence_refs: if provisional_loss_refs.is_empty() {
                credit_bond_receipt_evidence_from_exposure(exposure, |receipt| {
                    receipt.settlement_status == SettlementStatus::Failed
                })
            } else {
                provisional_loss_refs
            },
        });
    }
    if under_collateralized {
        findings.push(CreditBondFinding {
            code: CreditBondReasonCode::UnderCollateralized,
            description: "required reserve exceeded the collateral held by the active facility"
                .to_string(),
            evidence_refs: credit_bond_receipt_evidence_from_exposure(exposure, |receipt| {
                receipt.action_required
            }),
        });
    }
    let disposition_finding = match disposition {
        CreditBondDisposition::Lock => Some((
            CreditBondReasonCode::ReserveLocked,
            "outstanding exposure is present, so ARC locks the reserve against the active facility",
        )),
        CreditBondDisposition::Hold => Some((
            CreditBondReasonCode::ReserveHeld,
            "the facility remains active with no current outstanding exposure, so ARC holds reserve state",
        )),
        CreditBondDisposition::Release => Some((
            CreditBondReasonCode::ReserveReleased,
            "no active facility-backed exposure remains, so ARC releases the reserve state",
        )),
        CreditBondDisposition::Impair => None,
    };
    if let Some((code, description)) = disposition_finding {
        findings.push(CreditBondFinding {
            code,
            description: description.to_string(),
            evidence_refs: credit_bond_receipt_evidence_from_exposure(exposure, |_| true),
        });
    }

    findings
}

fn credit_bond_receipt_evidence_from_exposure<F>(
    exposure: &ExposureLedgerReport,
    predicate: F,
) -> Vec<CreditScorecardEvidenceReference>
where
    F: Fn(&ExposureLedgerReceiptEntry) -> bool,
{
    let mut evidence_refs = Vec::new();
    for receipt in &exposure.receipts {
        if !predicate(receipt) {
            continue;
        }
        for reference in &receipt.evidence_refs {
            let kind = match reference.kind {
                ExposureLedgerEvidenceKind::Receipt => CreditScorecardEvidenceKind::Receipt,
                ExposureLedgerEvidenceKind::SettlementReconciliation => {
                    CreditScorecardEvidenceKind::SettlementReconciliation
                }
                ExposureLedgerEvidenceKind::MeteredBillingReconciliation => continue,
                ExposureLedgerEvidenceKind::UnderwritingDecision => {
                    CreditScorecardEvidenceKind::UnderwritingDecision
                }
            };
            evidence_refs.push(CreditScorecardEvidenceReference {
                kind,
                reference_id: reference.reference_id.clone(),
                observed_at: reference.observed_at,
                locator: reference.locator.clone(),
            });
        }
    }
    evidence_refs
}

fn compute_credit_loss_lifecycle_accounting(
    currency: &str,
    lifecycle_history: &CreditLossLifecycleListReport,
) -> Result<CreditLossLifecycleAccountingState, String> {
    let mut state = CreditLossLifecycleAccountingState {
        currency: currency.to_string(),
        delinquent_units: 0,
        recovered_units: 0,
        reserve_released_units: 0,
        written_off_units: 0,
    };

    for row in &lifecycle_history.events {
        let Some(amount) = row.event.body.report.summary.event_amount.as_ref() else {
            continue;
        };
        if amount.currency != state.currency {
            return Err(format!(
                "credit loss lifecycle `{}` mixes currency `{}` with `{}`",
                row.event.body.event_id, amount.currency, state.currency
            ));
        }
        match row.event.body.event_kind {
            CreditLossLifecycleEventKind::Delinquency => {
                state.delinquent_units = state.delinquent_units.saturating_add(amount.units);
            }
            CreditLossLifecycleEventKind::Recovery => {
                state.recovered_units = state.recovered_units.saturating_add(amount.units);
            }
            CreditLossLifecycleEventKind::ReserveRelease => {
                state.reserve_released_units =
                    state.reserve_released_units.saturating_add(amount.units);
            }
            CreditLossLifecycleEventKind::WriteOff => {
                state.written_off_units = state.written_off_units.saturating_add(amount.units);
            }
        }
    }

    Ok(state)
}

fn ensure_credit_loss_lifecycle_currency(
    amount: &MonetaryAmount,
    currency: &str,
) -> Result<(), TrustHttpError> {
    if amount.currency != currency {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            format!(
                "credit loss lifecycle currency `{}` does not match bond currency `{}`",
                amount.currency, currency
            ),
        ));
    }
    Ok(())
}

fn amount_if_nonzero(units: u64, currency: &str) -> Option<MonetaryAmount> {
    (units > 0).then(|| MonetaryAmount {
        units,
        currency: currency.to_string(),
    })
}

fn empty_exposure_position(currency: &str) -> ExposureLedgerCurrencyPosition {
    ExposureLedgerCurrencyPosition {
        currency: currency.to_string(),
        governed_max_exposure_units: 0,
        reserved_units: 0,
        settled_units: 0,
        pending_units: 0,
        failed_units: 0,
        provisional_loss_units: 0,
        recovered_units: 0,
        quoted_premium_units: 0,
        active_quoted_premium_units: 0,
    }
}

fn build_credit_loss_lifecycle_outstanding_loss_state(
    receipts: &[arc_kernel::BehavioralFeedReceiptRow],
    currency: &str,
) -> Result<(u64, Vec<CreditScorecardEvidenceReference>), TrustHttpError> {
    let mut outstanding_units = 0_u64;
    let mut evidence_refs = Vec::new();
    let mut seen = BTreeSet::new();

    for row in receipts {
        let entry = build_exposure_ledger_receipt_entry(row)?;
        let Some(loss_amount) = entry
            .provisional_loss_amount
            .as_ref()
            .filter(|amount| amount.currency == currency && amount.units > 0)
        else {
            continue;
        };
        outstanding_units = outstanding_units.saturating_add(loss_amount.units);
        for reference in &entry.evidence_refs {
            let kind = match reference.kind {
                ExposureLedgerEvidenceKind::Receipt => CreditScorecardEvidenceKind::Receipt,
                ExposureLedgerEvidenceKind::SettlementReconciliation => {
                    CreditScorecardEvidenceKind::SettlementReconciliation
                }
                ExposureLedgerEvidenceKind::MeteredBillingReconciliation
                | ExposureLedgerEvidenceKind::UnderwritingDecision => continue,
            };
            let key = format!(
                "{kind:?}|{}|{:?}|{:?}",
                reference.reference_id, reference.observed_at, reference.locator
            );
            if seen.insert(key) {
                evidence_refs.push(CreditScorecardEvidenceReference {
                    kind,
                    reference_id: reference.reference_id.clone(),
                    observed_at: reference.observed_at,
                    locator: reference.locator.clone(),
                });
            }
        }
    }

    Ok((outstanding_units, evidence_refs))
}

fn credit_loss_lifecycle_transition_evidence(
    bond: &SignedCreditBond,
    lifecycle_history: &CreditLossLifecycleListReport,
    event_kind: CreditLossLifecycleEventKind,
) -> Vec<CreditScorecardEvidenceReference> {
    let mut evidence_refs = vec![CreditScorecardEvidenceReference {
        kind: CreditScorecardEvidenceKind::CreditBond,
        reference_id: bond.body.bond_id.clone(),
        observed_at: Some(bond.body.issued_at),
        locator: Some(format!("credit-bond:{}", bond.body.bond_id)),
    }];
    for row in &lifecycle_history.events {
        if row.event.body.event_kind != event_kind {
            continue;
        }
        evidence_refs.push(CreditScorecardEvidenceReference {
            kind: CreditScorecardEvidenceKind::CreditLossLifecycle,
            reference_id: row.event.body.event_id.clone(),
            observed_at: Some(row.event.body.issued_at),
            locator: Some(format!("credit-loss-lifecycle:{}", row.event.body.event_id)),
        });
    }
    evidence_refs
}

fn credit_bond_outstanding_units(position: &ExposureLedgerCurrencyPosition) -> u64 {
    let unsettled_units = position.pending_units.saturating_add(position.failed_units);
    let net_provisional_loss_units = position
        .provisional_loss_units
        .saturating_sub(position.recovered_units);
    position
        .reserved_units
        .max(unsettled_units)
        .max(net_provisional_loss_units)
}

fn credit_bond_reserve_units(units: u64, ratio_bps: u16) -> u64 {
    if units == 0 || ratio_bps == 0 {
        0
    } else {
        (((units as u128) * (ratio_bps as u128)).div_ceil(10_000_u128)).min(u64::MAX as u128) as u64
    }
}

fn credit_bond_ttl_seconds(report: &CreditBondReport) -> u64 {
    match report.disposition {
        CreditBondDisposition::Lock | CreditBondDisposition::Hold => 7 * 86_400,
        CreditBondDisposition::Release | CreditBondDisposition::Impair => 86_400,
    }
}

fn build_credit_recent_loss_history(
    matching_loss_events: u64,
    receipts: &[arc_kernel::BehavioralFeedReceiptRow],
    limit: usize,
) -> Result<CreditRecentLossHistory, TrustHttpError> {
    let mut entries = receipts
        .iter()
        .map(|row| {
            let entry = build_exposure_ledger_receipt_entry(row)?;
            Ok::<CreditRecentLossEntry, TrustHttpError>(CreditRecentLossEntry {
                receipt_id: entry.receipt_id,
                observed_at: entry.timestamp,
                settlement_status: entry.settlement_status,
                financial_amount: entry.financial_amount,
                provisional_loss_amount: entry.provisional_loss_amount,
                recovered_amount: entry.recovered_amount,
                evidence_refs: entry.evidence_refs,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by(|left, right| {
        right
            .observed_at
            .cmp(&left.observed_at)
            .then_with(|| left.receipt_id.cmp(&right.receipt_id))
    });
    entries.truncate(limit);
    let summary = CreditRecentLossSummary {
        matching_loss_events,
        returned_loss_events: entries.len() as u64,
        failed_settlement_events: entries
            .iter()
            .filter(|entry| entry.settlement_status == SettlementStatus::Failed)
            .count() as u64,
        provisional_loss_events: entries
            .iter()
            .filter(|entry| entry.provisional_loss_amount.is_some())
            .count() as u64,
        recovered_events: entries
            .iter()
            .filter(|entry| entry.recovered_amount.is_some())
            .count() as u64,
    };
    Ok(CreditRecentLossHistory { summary, entries })
}

fn collect_credit_provider_risk_evidence(
    scorecard: &CreditScorecardReport,
    underwriting_input: &UnderwritingPolicyInput,
) -> Vec<CreditScorecardEvidenceReference> {
    let mut seen = BTreeSet::<String>::new();
    let mut refs = Vec::new();
    let mut push_ref = |reference: CreditScorecardEvidenceReference| {
        let key = format!(
            "{:?}|{}|{:?}|{:?}",
            reference.kind, reference.reference_id, reference.observed_at, reference.locator
        );
        if seen.insert(key) {
            refs.push(reference);
        }
    };

    for reference in scorecard
        .dimensions
        .iter()
        .flat_map(|dimension| dimension.evidence_refs.iter())
        .chain(
            scorecard
                .anomalies
                .iter()
                .flat_map(|anomaly| anomaly.evidence_refs.iter()),
        )
    {
        push_ref(reference.clone());
    }
    for reference in credit_facility_receipt_refs_from_underwriting(underwriting_input) {
        push_ref(reference);
    }
    refs
}

fn build_credit_scorecard_dimensions(
    subject_key: &str,
    exposure: &ExposureLedgerReport,
    inspection: &issuance::LocalReputationInspection,
    exposure_units: f64,
) -> Vec<CreditScorecardDimension> {
    let settlement_penalty = credit_scorecard_penalty_ratio(
        credit_scorecard_total_units(&exposure.positions, |position| {
            position.failed_units.saturating_mul(2) + position.pending_units
        }) as f64
            / 2.0,
        exposure_units,
    );
    let loss_penalty = credit_scorecard_penalty_ratio(
        credit_scorecard_total_units(&exposure.positions, |position| {
            position.provisional_loss_units
        }) as f64,
        exposure_units,
    );
    let reserve_penalty = credit_scorecard_penalty_ratio(
        credit_scorecard_total_units(&exposure.positions, |position| position.reserved_units)
            as f64,
        exposure_units,
    );

    vec![
        CreditScorecardDimension {
            kind: CreditScorecardDimensionKind::ReputationSupport,
            score: Some(round_credit_score_value(inspection.effective_score)),
            weight: 0.40,
            description: "effective local reputation score carried into credit posture".to_string(),
            evidence_refs: vec![credit_scorecard_reputation_ref(subject_key)],
        },
        CreditScorecardDimension {
            kind: CreditScorecardDimensionKind::SettlementDiscipline,
            score: Some(round_credit_score_value(1.0 - settlement_penalty)),
            weight: 0.25,
            description:
                "penalizes pending and failed settlement exposure relative to the governed book"
                    .to_string(),
            evidence_refs: credit_scorecard_receipt_refs(
                &exposure.receipts,
                |row| {
                    matches!(
                        row.settlement_status,
                        SettlementStatus::Pending | SettlementStatus::Failed
                    )
                },
                CreditScorecardEvidenceKind::SettlementReconciliation,
            ),
        },
        CreditScorecardDimension {
            kind: CreditScorecardDimensionKind::LossPressure,
            score: Some(round_credit_score_value(1.0 - loss_penalty)),
            weight: 0.20,
            description:
                "penalizes provisional-loss exposure relative to the governed maximum exposure"
                    .to_string(),
            evidence_refs: credit_scorecard_receipt_refs(
                &exposure.receipts,
                |row| row.provisional_loss_amount.is_some(),
                CreditScorecardEvidenceKind::Receipt,
            ),
        },
        CreditScorecardDimension {
            kind: CreditScorecardDimensionKind::ExposureStewardship,
            score: Some(round_credit_score_value(1.0 - reserve_penalty)),
            weight: 0.15,
            description: "penalizes reserve-heavy exposure that still requires operator follow-up"
                .to_string(),
            evidence_refs: credit_scorecard_receipt_refs(
                &exposure.receipts,
                |row| row.reserve_required_amount.is_some(),
                CreditScorecardEvidenceKind::Receipt,
            ),
        },
    ]
}

fn round_credit_score_value(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

fn build_credit_scorecard_probation(
    inspection: &issuance::LocalReputationInspection,
    confidence: CreditScorecardConfidence,
) -> CreditScorecardProbationStatus {
    let mut reasons = Vec::new();
    if inspection.probationary_status.below_receipt_target {
        reasons.push(CreditScorecardReasonCode::SparseReceiptHistory);
    }
    if inspection.probationary_status.below_day_target {
        reasons.push(CreditScorecardReasonCode::SparseDayHistory);
    }
    if confidence == CreditScorecardConfidence::Low {
        reasons.push(CreditScorecardReasonCode::LowConfidence);
    }

    CreditScorecardProbationStatus {
        probationary: inspection.probationary || confidence == CreditScorecardConfidence::Low,
        reasons,
        receipt_count: inspection.scorecard.history_depth.receipt_count as u64,
        span_days: inspection.scorecard.history_depth.span_days,
        target_receipt_count: inspection.probationary_receipt_count,
        target_span_days: inspection.probationary_min_days,
    }
}

fn build_credit_scorecard_anomalies(
    subject_key: &str,
    exposure: &ExposureLedgerReport,
    inspection: &issuance::LocalReputationInspection,
    exposure_units: u64,
) -> Vec<CreditScorecardAnomaly> {
    let mut anomalies = Vec::new();

    if exposure.summary.pending_settlement_receipts > 0 {
        anomalies.push(CreditScorecardAnomaly {
            code: CreditScorecardReasonCode::PendingSettlementBacklog,
            severity: CreditScorecardAnomalySeverity::Warning,
            description: format!(
                "credit window contains {} pending settlement receipt(s)",
                exposure.summary.pending_settlement_receipts
            ),
            evidence_refs: credit_scorecard_receipt_refs(
                &exposure.receipts,
                |row| row.settlement_status == SettlementStatus::Pending,
                CreditScorecardEvidenceKind::SettlementReconciliation,
            ),
        });
    }

    if exposure.summary.failed_settlement_receipts > 0 {
        anomalies.push(CreditScorecardAnomaly {
            code: CreditScorecardReasonCode::FailedSettlementBacklog,
            severity: CreditScorecardAnomalySeverity::Critical,
            description: format!(
                "credit window contains {} failed settlement receipt(s)",
                exposure.summary.failed_settlement_receipts
            ),
            evidence_refs: credit_scorecard_receipt_refs(
                &exposure.receipts,
                |row| row.settlement_status == SettlementStatus::Failed,
                CreditScorecardEvidenceKind::SettlementReconciliation,
            ),
        });
    }

    let provisional_loss_units = credit_scorecard_total_units(&exposure.positions, |position| {
        position.provisional_loss_units
    });
    if provisional_loss_units > 0 && provisional_loss_units.saturating_mul(10) >= exposure_units {
        anomalies.push(CreditScorecardAnomaly {
            code: CreditScorecardReasonCode::ProvisionalLossPressure,
            severity: if provisional_loss_units.saturating_mul(4) >= exposure_units {
                CreditScorecardAnomalySeverity::Critical
            } else {
                CreditScorecardAnomalySeverity::Warning
            },
            description: format!(
                "provisional-loss exposure totals {} unit(s) across the requested book",
                provisional_loss_units
            ),
            evidence_refs: credit_scorecard_receipt_refs(
                &exposure.receipts,
                |row| row.provisional_loss_amount.is_some(),
                CreditScorecardEvidenceKind::Receipt,
            ),
        });
    }

    if exposure.summary.mixed_currency_book {
        anomalies.push(CreditScorecardAnomaly {
            code: CreditScorecardReasonCode::MixedCurrencyBook,
            severity: CreditScorecardAnomalySeverity::Info,
            description: "credit book spans multiple currencies and is not netted across them"
                .to_string(),
            evidence_refs: vec![CreditScorecardEvidenceReference {
                kind: CreditScorecardEvidenceKind::ExposureLedger,
                reference_id: subject_key.to_string(),
                observed_at: Some(exposure.generated_at),
                locator: Some(format!("exposure-ledger:{}", subject_key)),
            }],
        });
    }

    if inspection.effective_score < 0.40 {
        anomalies.push(CreditScorecardAnomaly {
            code: CreditScorecardReasonCode::LowReputation,
            severity: CreditScorecardAnomalySeverity::Warning,
            description: format!(
                "effective local reputation score {:.4} is below the guarded credit baseline",
                inspection.effective_score
            ),
            evidence_refs: vec![credit_scorecard_reputation_ref(subject_key)],
        });
    }

    if inspection
        .imported_trust
        .as_ref()
        .is_some_and(|report| report.accepted_count > 0)
    {
        let accepted = inspection
            .imported_trust
            .as_ref()
            .map(|report| report.accepted_count)
            .unwrap_or(0);
        anomalies.push(CreditScorecardAnomaly {
            code: CreditScorecardReasonCode::ImportedTrustDependency,
            severity: CreditScorecardAnomalySeverity::Info,
            description: format!(
                "credit posture depends on {} accepted imported-trust signal(s)",
                accepted
            ),
            evidence_refs: vec![credit_scorecard_reputation_ref(subject_key)],
        });
    }

    if exposure.summary.matching_decisions == 0 {
        anomalies.push(CreditScorecardAnomaly {
            code: CreditScorecardReasonCode::MissingDecisionCoverage,
            severity: CreditScorecardAnomalySeverity::Info,
            description: "no persisted underwriting decisions matched the requested credit window"
                .to_string(),
            evidence_refs: vec![CreditScorecardEvidenceReference {
                kind: CreditScorecardEvidenceKind::ExposureLedger,
                reference_id: subject_key.to_string(),
                observed_at: Some(exposure.generated_at),
                locator: Some(format!("exposure-ledger:{}", subject_key)),
            }],
        });
    }

    anomalies
}

fn resolve_credit_scorecard_confidence(
    inspection: &issuance::LocalReputationInspection,
) -> CreditScorecardConfidence {
    let receipt_count = inspection.scorecard.history_depth.receipt_count as u64;
    let span_days = inspection.scorecard.history_depth.span_days;
    let mut confidence = if receipt_count >= 100 && span_days >= 30 {
        CreditScorecardConfidence::High
    } else if receipt_count >= 25 && span_days >= 7 {
        CreditScorecardConfidence::Medium
    } else {
        CreditScorecardConfidence::Low
    };

    if inspection.scorecard.effective_weight_sum < 0.60 {
        confidence = match confidence {
            CreditScorecardConfidence::High => CreditScorecardConfidence::Medium,
            CreditScorecardConfidence::Medium | CreditScorecardConfidence::Low => {
                CreditScorecardConfidence::Low
            }
        };
    }

    confidence
}

fn resolve_credit_scorecard_band(overall_score: f64, probationary: bool) -> CreditScorecardBand {
    if probationary {
        CreditScorecardBand::Probationary
    } else if overall_score >= 0.85 {
        CreditScorecardBand::Prime
    } else if overall_score >= 0.70 {
        CreditScorecardBand::Standard
    } else if overall_score >= 0.50 {
        CreditScorecardBand::Guarded
    } else {
        CreditScorecardBand::Restricted
    }
}

fn compute_credit_scorecard_overall_score(dimensions: &[CreditScorecardDimension]) -> Option<f64> {
    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;
    for dimension in dimensions {
        if let Some(score) = dimension.score {
            weighted_sum += score.clamp(0.0, 1.0) * dimension.weight;
            total_weight += dimension.weight;
        }
    }
    (total_weight > 0.0).then_some((weighted_sum / total_weight).clamp(0.0, 1.0))
}

fn credit_scorecard_penalty_ratio(units: f64, denominator: f64) -> f64 {
    if denominator <= 0.0 {
        return 1.0;
    }
    (units / denominator).clamp(0.0, 1.0)
}

fn credit_scorecard_position_denominator(
    positions: &[ExposureLedgerCurrencyPosition],
) -> Option<u64> {
    let governed =
        credit_scorecard_total_units(positions, |position| position.governed_max_exposure_units);
    let settled = credit_scorecard_total_units(positions, |position| position.settled_units);
    let pending = credit_scorecard_total_units(positions, |position| position.pending_units);
    let failed = credit_scorecard_total_units(positions, |position| position.failed_units);
    let denominator = governed.max(settled.saturating_add(pending).saturating_add(failed));
    (denominator > 0).then_some(denominator)
}

fn credit_scorecard_total_units<F>(positions: &[ExposureLedgerCurrencyPosition], units: F) -> u64
where
    F: Fn(&ExposureLedgerCurrencyPosition) -> u64,
{
    positions.iter().map(units).sum()
}

fn credit_scorecard_reputation_ref(subject_key: &str) -> CreditScorecardEvidenceReference {
    CreditScorecardEvidenceReference {
        kind: CreditScorecardEvidenceKind::ReputationInspection,
        reference_id: subject_key.to_string(),
        observed_at: None,
        locator: Some(format!("reputation:{}", subject_key)),
    }
}

fn credit_scorecard_receipt_refs<F>(
    receipts: &[ExposureLedgerReceiptEntry],
    predicate: F,
    kind: CreditScorecardEvidenceKind,
) -> Vec<CreditScorecardEvidenceReference>
where
    F: Fn(&ExposureLedgerReceiptEntry) -> bool,
{
    receipts
        .iter()
        .filter(|row| predicate(row))
        .take(8)
        .map(|row| CreditScorecardEvidenceReference {
            kind,
            reference_id: row.receipt_id.clone(),
            observed_at: Some(row.timestamp),
            locator: Some(format!("receipt:{}", row.receipt_id)),
        })
        .collect()
}

pub fn build_signed_underwriting_policy_input(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    query: &UnderwritingPolicyInputQuery,
) -> Result<SignedUnderwritingPolicyInput, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let report = build_underwriting_policy_input(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        query,
    )
    .map_err(CliError::from)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedUnderwritingPolicyInput::sign(report, &keypair).map_err(Into::into)
}

pub fn build_underwriting_decision_report(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    query: &UnderwritingPolicyInputQuery,
) -> Result<UnderwritingDecisionReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    build_underwriting_decision_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        query,
    )
    .map_err(CliError::from)
}

fn build_underwriting_decision_report_from_store(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    query: &UnderwritingPolicyInputQuery,
) -> Result<UnderwritingDecisionReport, TrustHttpError> {
    let input = build_underwriting_policy_input(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        query,
    )?;
    let policy = UnderwritingDecisionPolicy::default();
    arc_kernel::evaluate_underwriting_policy_input(input, &policy)
        .map_err(TrustHttpError::bad_request)
}

pub fn build_underwriting_simulation_report(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    request: &UnderwritingSimulationRequest,
) -> Result<UnderwritingSimulationReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    build_underwriting_simulation_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        request,
    )
    .map_err(CliError::from)
}

fn build_underwriting_simulation_report_from_store(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    request: &UnderwritingSimulationRequest,
) -> Result<UnderwritingSimulationReport, TrustHttpError> {
    let input = build_underwriting_policy_input(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        &request.query,
    )?;
    let default_evaluation = arc_kernel::evaluate_underwriting_policy_input(
        input.clone(),
        &UnderwritingDecisionPolicy::default(),
    )
    .map_err(TrustHttpError::bad_request)?;
    let simulated_evaluation =
        arc_kernel::evaluate_underwriting_policy_input(input.clone(), &request.policy)
            .map_err(TrustHttpError::bad_request)?;

    Ok(UnderwritingSimulationReport {
        schema: UNDERWRITING_SIMULATION_REPORT_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        input,
        delta: build_underwriting_simulation_delta(&default_evaluation, &simulated_evaluation),
        default_evaluation,
        simulated_evaluation,
    })
}

pub fn issue_signed_underwriting_decision(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    query: &UnderwritingPolicyInputQuery,
    supersedes_decision_id: Option<&str>,
) -> Result<SignedUnderwritingDecision, CliError> {
    issue_signed_underwriting_decision_detailed(
        receipt_db_path,
        budget_db_path,
        authority_seed_path,
        authority_db_path,
        certification_registry_file,
        query,
        supersedes_decision_id,
    )
    .map_err(CliError::from)
}

fn issue_signed_underwriting_decision_detailed(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    query: &UnderwritingPolicyInputQuery,
    supersedes_decision_id: Option<&str>,
) -> Result<SignedUnderwritingDecision, TrustHttpError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let report = build_underwriting_decision_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        query,
    )
    .map_err(TrustHttpError::from)?;
    let quoted_exposure =
        build_underwriting_quoted_exposure(&receipt_store, query).map_err(TrustHttpError::from)?;
    let mut artifact = arc_kernel::build_underwriting_decision_artifact(
        report,
        unix_timestamp_now(),
        supersedes_decision_id.map(ToOwned::to_owned),
        quoted_exposure.amount_for_pricing(),
    )
    .map_err(TrustHttpError::bad_request)?;
    quoted_exposure.apply_to_artifact(&mut artifact);
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let signed = SignedUnderwritingDecision::sign(artifact, &keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    receipt_store
        .record_underwriting_decision(&signed)
        .map_err(trust_http_error_from_receipt_store)?;
    Ok(signed)
}

pub fn list_underwriting_decisions(
    receipt_db_path: &Path,
    query: &UnderwritingDecisionQuery,
) -> Result<UnderwritingDecisionListReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .query_underwriting_decisions(query)
        .map_err(|error| CliError::Other(error.to_string()))
}

pub fn create_underwriting_appeal(
    receipt_db_path: &Path,
    request: &UnderwritingAppealCreateRequest,
) -> Result<UnderwritingAppealRecord, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .create_underwriting_appeal(request)
        .map_err(|error| CliError::Other(error.to_string()))
}

pub fn resolve_underwriting_appeal(
    receipt_db_path: &Path,
    request: &UnderwritingAppealResolveRequest,
) -> Result<UnderwritingAppealRecord, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .resolve_underwriting_appeal(request)
        .map_err(|error| CliError::Other(error.to_string()))
}

fn build_exposure_ledger_receipt_entry(
    receipt: &arc_kernel::BehavioralFeedReceiptRow,
) -> Result<ExposureLedgerReceiptEntry, TrustHttpError> {
    let governed_max_amount = receipt
        .governed
        .as_ref()
        .and_then(|governed| governed.max_amount.clone());
    let financial_amount = exposure_ledger_financial_amount(receipt);
    if let (Some(governed), Some(financial)) = (&governed_max_amount, &financial_amount) {
        if governed.currency != financial.currency {
            return Err(TrustHttpError::new(
                StatusCode::CONFLICT,
                format!(
                    "receipt `{}` cannot project one exposure row across multiple currencies (`{}` vs `{}`)",
                    receipt.receipt_id, governed.currency, financial.currency
                ),
            ));
        }
    }

    let reserve_required_amount = if receipt.action_required {
        governed_max_amount
            .clone()
            .or_else(|| financial_amount.clone())
    } else {
        None
    };
    let provisional_loss_amount =
        if receipt.settlement_status == SettlementStatus::Failed && receipt.action_required {
            financial_amount
                .clone()
                .or_else(|| governed_max_amount.clone())
        } else {
            None
        };
    let metered_action_required = receipt
        .metered_reconciliation
        .as_ref()
        .is_some_and(|row| row.action_required);
    let mut evidence_refs = vec![ExposureLedgerEvidenceReference {
        kind: ExposureLedgerEvidenceKind::Receipt,
        reference_id: receipt.receipt_id.clone(),
        observed_at: Some(receipt.timestamp),
        locator: Some(format!("receipt:{}", receipt.receipt_id)),
    }];
    if receipt.settlement_status != SettlementStatus::NotApplicable || receipt.action_required {
        evidence_refs.push(ExposureLedgerEvidenceReference {
            kind: ExposureLedgerEvidenceKind::SettlementReconciliation,
            reference_id: receipt.receipt_id.clone(),
            observed_at: Some(receipt.timestamp),
            locator: Some(format!("settlement:{}", receipt.receipt_id)),
        });
    }
    if metered_action_required {
        evidence_refs.push(ExposureLedgerEvidenceReference {
            kind: ExposureLedgerEvidenceKind::MeteredBillingReconciliation,
            reference_id: receipt.receipt_id.clone(),
            observed_at: Some(receipt.timestamp),
            locator: Some(format!("metered-billing:{}", receipt.receipt_id)),
        });
    }

    Ok(ExposureLedgerReceiptEntry {
        receipt_id: receipt.receipt_id.clone(),
        timestamp: receipt.timestamp,
        capability_id: receipt.capability_id.clone(),
        subject_key: receipt.subject_key.clone(),
        issuer_key: receipt.issuer_key.clone(),
        tool_server: receipt.tool_server.clone(),
        tool_name: receipt.tool_name.clone(),
        decision: receipt.decision.clone(),
        settlement_status: receipt.settlement_status.clone(),
        action_required: receipt.action_required,
        governed_max_amount,
        financial_amount,
        reserve_required_amount,
        provisional_loss_amount,
        recovered_amount: None,
        metered_action_required,
        evidence_refs,
    })
}

fn build_exposure_ledger_decision_entry(
    row: &arc_kernel::UnderwritingDecisionRow,
) -> ExposureLedgerDecisionEntry {
    let filters = &row.decision.body.evaluation.input.filters;
    let decision_id = row.decision.body.decision_id.clone();
    ExposureLedgerDecisionEntry {
        decision_id: decision_id.clone(),
        issued_at: row.decision.body.issued_at,
        capability_id: filters.capability_id.clone(),
        agent_subject: filters.agent_subject.clone(),
        tool_server: filters.tool_server.clone(),
        tool_name: filters.tool_name.clone(),
        outcome: row.decision.body.evaluation.outcome,
        lifecycle_state: row.lifecycle_state,
        review_state: row.decision.body.review_state,
        risk_class: row.decision.body.evaluation.risk_class,
        supersedes_decision_id: row.decision.body.supersedes_decision_id.clone(),
        quoted_premium_amount: row.decision.body.premium.quoted_amount.clone(),
        evidence_refs: vec![ExposureLedgerEvidenceReference {
            kind: ExposureLedgerEvidenceKind::UnderwritingDecision,
            reference_id: decision_id.clone(),
            observed_at: Some(row.decision.body.issued_at),
            locator: Some(format!("underwriting-decision:{decision_id}")),
        }],
    }
}

fn exposure_ledger_financial_amount(
    receipt: &arc_kernel::BehavioralFeedReceiptRow,
) -> Option<MonetaryAmount> {
    let units = receipt
        .cost_charged
        .filter(|units| *units > 0)
        .or_else(|| receipt.attempted_cost.filter(|units| *units > 0))?;
    Some(MonetaryAmount {
        units,
        currency: receipt.currency.clone()?,
    })
}

fn accumulate_exposure_position<F>(
    positions_by_currency: &mut BTreeMap<String, ExposureLedgerCurrencyPosition>,
    amount: Option<&MonetaryAmount>,
    update: F,
) where
    F: FnOnce(&mut ExposureLedgerCurrencyPosition, &MonetaryAmount),
{
    let Some(amount) = amount else {
        return;
    };
    let position = positions_by_currency
        .entry(amount.currency.clone())
        .or_insert_with(|| ExposureLedgerCurrencyPosition {
            currency: amount.currency.clone(),
            governed_max_exposure_units: 0,
            reserved_units: 0,
            settled_units: 0,
            pending_units: 0,
            failed_units: 0,
            provisional_loss_units: 0,
            recovered_units: 0,
            quoted_premium_units: 0,
            active_quoted_premium_units: 0,
        });
    update(position, amount);
}

fn build_underwriting_quoted_exposure(
    receipt_store: &SqliteReceiptStore,
    query: &UnderwritingPolicyInputQuery,
) -> Result<UnderwritingQuotedExposure, TrustHttpError> {
    let normalized_query = query.normalized();
    if let Err(message) = normalized_query.validate() {
        return Err(TrustHttpError::bad_request(message));
    }

    let behavioral_query = BehavioralFeedQuery {
        capability_id: normalized_query.capability_id,
        agent_subject: normalized_query.agent_subject,
        tool_server: normalized_query.tool_server,
        tool_name: normalized_query.tool_name,
        since: normalized_query.since,
        until: normalized_query.until,
        receipt_limit: normalized_query.receipt_limit,
    };
    let (_, _, _, selection) = receipt_store
        .query_behavioral_feed_receipts(&behavioral_query)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;

    let mut max_by_currency = BTreeMap::<String, MonetaryAmount>::new();
    for amount in selection
        .receipts
        .into_iter()
        .filter_map(|receipt| receipt.governed.and_then(|governed| governed.max_amount))
    {
        max_by_currency
            .entry(amount.currency.clone())
            .and_modify(|current| {
                if amount.units > current.units {
                    *current = amount.clone();
                }
            })
            .or_insert(amount);
    }

    Ok(match max_by_currency.len() {
        0 => UnderwritingQuotedExposure::None,
        1 => UnderwritingQuotedExposure::Single(
            max_by_currency
                .into_values()
                .next()
                .expect("single currency entry"),
        ),
        _ => UnderwritingQuotedExposure::MixedCurrencies(max_by_currency.into_keys().collect()),
    })
}

fn build_underwriting_simulation_delta(
    default_evaluation: &UnderwritingDecisionReport,
    simulated_evaluation: &UnderwritingDecisionReport,
) -> UnderwritingSimulationDelta {
    let default_reasons = underwriting_simulation_reason_keys(default_evaluation);
    let simulated_reasons = underwriting_simulation_reason_keys(simulated_evaluation);

    UnderwritingSimulationDelta {
        outcome_changed: default_evaluation.outcome != simulated_evaluation.outcome,
        risk_class_changed: default_evaluation.risk_class != simulated_evaluation.risk_class,
        added_reasons: simulated_reasons
            .iter()
            .filter(|reason| !default_reasons.contains(reason))
            .cloned()
            .collect(),
        removed_reasons: default_reasons
            .iter()
            .filter(|reason| !simulated_reasons.contains(reason))
            .cloned()
            .collect(),
        default_ceiling_factor: default_evaluation.suggested_ceiling_factor,
        simulated_ceiling_factor: simulated_evaluation.suggested_ceiling_factor,
    }
}

fn underwriting_simulation_reason_keys(report: &UnderwritingDecisionReport) -> Vec<String> {
    let mut reasons = Vec::new();
    for reason in report
        .findings
        .iter()
        .map(underwriting_simulation_reason_key)
    {
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }
    reasons
}

fn underwriting_runtime_family_label(
    family: arc_core::appraisal::AttestationVerifierFamily,
) -> &'static str {
    match family {
        arc_core::appraisal::AttestationVerifierFamily::AzureMaa => "azure_maa",
        arc_core::appraisal::AttestationVerifierFamily::AwsNitro => "aws_nitro",
        arc_core::appraisal::AttestationVerifierFamily::GoogleAttestation => "google_attestation",
    }
}

fn underwriting_simulation_reason_key(finding: &arc_kernel::UnderwritingDecisionFinding) -> String {
    if let Some(reason) = finding.signal_reason {
        serde_json::to_string(&reason)
            .unwrap_or_else(|_| format!("{reason:?}"))
            .trim_matches('"')
            .to_string()
    } else {
        serde_json::to_string(&finding.reason)
            .unwrap_or_else(|_| format!("{:?}", finding.reason))
            .trim_matches('"')
            .to_string()
    }
}

fn build_underwriting_policy_input(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    query: &UnderwritingPolicyInputQuery,
) -> Result<UnderwritingPolicyInput, TrustHttpError> {
    let normalized_query = query.normalized();
    if let Err(message) = normalized_query.validate() {
        return Err(TrustHttpError::bad_request(message));
    }

    let behavioral_query = BehavioralFeedQuery {
        capability_id: normalized_query.capability_id.clone(),
        agent_subject: normalized_query.agent_subject.clone(),
        tool_server: normalized_query.tool_server.clone(),
        tool_name: normalized_query.tool_name.clone(),
        since: normalized_query.since,
        until: normalized_query.until,
        receipt_limit: normalized_query.receipt_limit,
    };
    let operator_query = behavioral_query.to_operator_report_query();
    let activity = receipt_store
        .query_receipt_analytics(&operator_query.to_receipt_analytics_query())
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let shared_evidence = receipt_store
        .query_shared_evidence_report(&operator_query.to_shared_evidence_query())
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let (settlements, governed_actions, metered_billing, selection) = receipt_store
        .query_behavioral_feed_receipts(&behavioral_query)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let generated_at = unix_timestamp_now();
    let reputation = match normalized_query.agent_subject.as_deref() {
        Some(subject_key) => Some(
            reputation::build_behavioral_feed_reputation_summary(
                receipt_db_path,
                budget_db_path,
                subject_key,
                normalized_query.since,
                normalized_query.until,
                generated_at,
            )
            .map(underwriting_reputation_from_behavioral_summary)
            .map_err(|error| TrustHttpError::internal(error.to_string()))?,
        ),
        None => None,
    };
    let certification = normalized_query
        .tool_server
        .as_deref()
        .map(|tool_server| {
            resolve_underwriting_certification_evidence(certification_registry_file, tool_server)
        })
        .transpose()
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let receipts = build_underwriting_receipt_evidence(
        &activity,
        &settlements,
        &governed_actions,
        &metered_billing,
        &shared_evidence,
        &selection,
    );
    let runtime_assurance = build_underwriting_runtime_assurance_evidence(
        &selection,
        governed_actions.governed_receipts,
    );
    let signals = derive_underwriting_signals(
        &normalized_query,
        &receipts,
        &selection,
        reputation.as_ref(),
        certification.as_ref(),
        runtime_assurance.as_ref(),
    );

    Ok(UnderwritingPolicyInput {
        schema: UNDERWRITING_POLICY_INPUT_SCHEMA.to_string(),
        generated_at,
        filters: normalized_query,
        taxonomy: UnderwritingRiskTaxonomy::default(),
        receipts,
        reputation,
        certification,
        runtime_assurance,
        signals,
    })
}

fn underwriting_reputation_from_behavioral_summary(
    summary: arc_kernel::BehavioralFeedReputationSummary,
) -> UnderwritingReputationEvidence {
    UnderwritingReputationEvidence {
        subject_key: summary.subject_key,
        effective_score: summary.effective_score,
        probationary: summary.probationary,
        resolved_tier: summary.resolved_tier,
        imported_signal_count: summary.imported_signal_count,
        accepted_imported_signal_count: summary.accepted_imported_signal_count,
    }
}

fn resolve_underwriting_certification_evidence(
    certification_registry_file: Option<&Path>,
    tool_server_id: &str,
) -> Result<UnderwritingCertificationEvidence, CliError> {
    let Some(path) = certification_registry_file else {
        return Ok(UnderwritingCertificationEvidence {
            tool_server_id: tool_server_id.to_string(),
            state: UnderwritingCertificationState::Unavailable,
            artifact_id: None,
            verdict: None,
            checked_at: None,
            published_at: None,
        });
    };

    let registry = CertificationRegistry::load(path)?;
    let resolution = registry.resolve(tool_server_id);
    let current = resolution.current;
    let verdict = current
        .as_ref()
        .map(|entry| entry.verdict.label().to_string());
    Ok(UnderwritingCertificationEvidence {
        tool_server_id: resolution.tool_server_id,
        state: match resolution.state {
            CertificationResolutionState::Active => UnderwritingCertificationState::Active,
            CertificationResolutionState::Superseded => UnderwritingCertificationState::Superseded,
            CertificationResolutionState::Revoked => UnderwritingCertificationState::Revoked,
            CertificationResolutionState::NotFound => UnderwritingCertificationState::NotFound,
        },
        artifact_id: current.as_ref().map(|entry| entry.artifact_id.clone()),
        verdict,
        checked_at: current.as_ref().map(|entry| entry.checked_at),
        published_at: current.as_ref().map(|entry| entry.published_at),
    })
}

fn build_underwriting_receipt_evidence(
    activity: &ReceiptAnalyticsResponse,
    settlements: &arc_kernel::BehavioralFeedSettlementSummary,
    governed_actions: &arc_kernel::BehavioralFeedGovernedActionSummary,
    metered_billing: &arc_kernel::BehavioralFeedMeteredBillingSummary,
    shared_evidence: &SharedEvidenceReferenceReport,
    selection: &arc_kernel::BehavioralFeedReceiptSelection,
) -> UnderwritingReceiptEvidence {
    let runtime_assurance_receipts = selection
        .receipts
        .iter()
        .filter(|receipt| {
            receipt
                .governed
                .as_ref()
                .and_then(|governed| governed.runtime_assurance.as_ref())
                .is_some()
        })
        .count() as u64;
    let call_chain_receipts = selection
        .receipts
        .iter()
        .filter(|receipt| {
            receipt
                .governed
                .as_ref()
                .and_then(|governed| governed.call_chain.as_ref())
                .is_some()
        })
        .count() as u64;

    UnderwritingReceiptEvidence {
        matching_receipts: selection.matching_receipts,
        returned_receipts: selection.receipts.len() as u64,
        allow_count: activity.summary.allow_count,
        deny_count: activity.summary.deny_count,
        cancelled_count: activity.summary.cancelled_count,
        incomplete_count: activity.summary.incomplete_count,
        governed_receipts: governed_actions.governed_receipts,
        approval_receipts: governed_actions.approval_receipts,
        approved_receipts: governed_actions.approved_receipts,
        call_chain_receipts,
        runtime_assurance_receipts,
        pending_settlement_receipts: settlements.pending_receipts,
        failed_settlement_receipts: settlements.failed_receipts,
        actionable_settlement_receipts: settlements.actionable_receipts,
        metered_receipts: metered_billing.metered_receipts,
        actionable_metered_receipts: metered_billing.actionable_receipts,
        shared_evidence_reference_count: shared_evidence.summary.matching_references,
        shared_evidence_proof_required_count: shared_evidence.summary.proof_required_shares,
        receipt_refs: selection
            .receipts
            .iter()
            .map(|receipt| UnderwritingEvidenceReference {
                kind: UnderwritingEvidenceKind::Receipt,
                reference_id: receipt.receipt_id.clone(),
                observed_at: Some(receipt.timestamp),
                digest_sha256: None,
                locator: Some(format!("receipt:{}", receipt.receipt_id)),
            })
            .collect(),
    }
}

fn build_underwriting_runtime_assurance_evidence(
    selection: &arc_kernel::BehavioralFeedReceiptSelection,
    governed_receipts: u64,
) -> Option<UnderwritingRuntimeAssuranceEvidence> {
    let mut highest_tier: Option<RuntimeAssuranceTier> = None;
    let mut latest_observed = None;
    let mut runtime_assurance_receipts = 0_u64;

    for receipt in &selection.receipts {
        let Some(runtime_assurance) = receipt
            .governed
            .as_ref()
            .and_then(|governed| governed.runtime_assurance.as_ref())
        else {
            continue;
        };
        runtime_assurance_receipts += 1;
        highest_tier = Some(match highest_tier {
            Some(current) => current.max(runtime_assurance.tier),
            None => runtime_assurance.tier,
        });
        if latest_observed
            .as_ref()
            .is_none_or(|(_, timestamp)| receipt.timestamp > *timestamp)
        {
            latest_observed = Some((runtime_assurance.clone(), receipt.timestamp));
        }
    }

    if governed_receipts == 0 && runtime_assurance_receipts == 0 {
        return None;
    }

    let latest = latest_observed.map(|(value, _)| value);
    Some(UnderwritingRuntimeAssuranceEvidence {
        governed_receipts,
        runtime_assurance_receipts,
        highest_tier,
        latest_schema: latest.as_ref().map(|value| value.schema.clone()),
        latest_verifier_family: latest.as_ref().and_then(|value| value.verifier_family),
        latest_verifier: latest.as_ref().map(|value| value.verifier.clone()),
        latest_evidence_sha256: latest.as_ref().map(|value| value.evidence_sha256.clone()),
    })
}

fn derive_underwriting_signals(
    query: &UnderwritingPolicyInputQuery,
    receipts: &UnderwritingReceiptEvidence,
    selection: &arc_kernel::BehavioralFeedReceiptSelection,
    reputation: Option<&UnderwritingReputationEvidence>,
    certification: Option<&UnderwritingCertificationEvidence>,
    runtime_assurance: Option<&UnderwritingRuntimeAssuranceEvidence>,
) -> Vec<UnderwritingSignal> {
    let mut signals = Vec::new();

    if let Some(reputation) = reputation {
        let reputation_ref = UnderwritingEvidenceReference {
            kind: UnderwritingEvidenceKind::ReputationInspection,
            reference_id: reputation.subject_key.clone(),
            observed_at: None,
            digest_sha256: None,
            locator: Some(format!("reputation:{}", reputation.subject_key)),
        };
        if reputation.probationary {
            signals.push(UnderwritingSignal {
                class: UnderwritingRiskClass::Guarded,
                reason: UnderwritingReasonCode::ProbationaryHistory,
                description: "local reputation is still probationary for the requested window"
                    .to_string(),
                evidence_refs: vec![reputation_ref.clone()],
            });
        }
        if reputation.effective_score < 0.4 {
            signals.push(UnderwritingSignal {
                class: UnderwritingRiskClass::Elevated,
                reason: UnderwritingReasonCode::LowReputation,
                description: format!(
                    "effective local reputation score {:.4} is below the baseline threshold",
                    reputation.effective_score
                ),
                evidence_refs: vec![reputation_ref.clone()],
            });
        }
        if reputation.accepted_imported_signal_count > 0 {
            signals.push(UnderwritingSignal {
                class: UnderwritingRiskClass::Guarded,
                reason: UnderwritingReasonCode::ImportedTrustDependency,
                description: format!(
                    "underwriting input includes {} accepted imported-trust signal(s)",
                    reputation.accepted_imported_signal_count
                ),
                evidence_refs: vec![reputation_ref],
            });
        }
    }

    if let Some(certification) = certification {
        let certification_ref =
            certification
                .artifact_id
                .as_ref()
                .map(|artifact_id| UnderwritingEvidenceReference {
                    kind: UnderwritingEvidenceKind::CertificationArtifact,
                    reference_id: artifact_id.clone(),
                    observed_at: certification.published_at,
                    digest_sha256: certification.artifact_id.clone(),
                    locator: Some(format!("certification:{}", certification.tool_server_id)),
                });
        match certification.state {
            UnderwritingCertificationState::Unavailable
            | UnderwritingCertificationState::NotFound => {
                signals.push(UnderwritingSignal {
                    class: UnderwritingRiskClass::Elevated,
                    reason: UnderwritingReasonCode::MissingCertification,
                    description: format!(
                        "no active certification evidence is available for tool server `{}`",
                        certification.tool_server_id
                    ),
                    evidence_refs: certification_ref.into_iter().collect(),
                });
            }
            UnderwritingCertificationState::Revoked => {
                signals.push(UnderwritingSignal {
                    class: UnderwritingRiskClass::Critical,
                    reason: UnderwritingReasonCode::RevokedCertification,
                    description: format!(
                        "current certification evidence for tool server `{}` is revoked",
                        certification.tool_server_id
                    ),
                    evidence_refs: certification_ref.into_iter().collect(),
                });
            }
            UnderwritingCertificationState::Active
                if certification.verdict.as_deref() == Some("fail") =>
            {
                signals.push(UnderwritingSignal {
                    class: UnderwritingRiskClass::Critical,
                    reason: UnderwritingReasonCode::FailedCertification,
                    description: format!(
                        "active certification evidence for tool server `{}` has fail verdict",
                        certification.tool_server_id
                    ),
                    evidence_refs: certification_ref.into_iter().collect(),
                });
            }
            UnderwritingCertificationState::Superseded => {
                signals.push(UnderwritingSignal {
                    class: UnderwritingRiskClass::Guarded,
                    reason: UnderwritingReasonCode::MissingCertification,
                    description: format!(
                        "only superseded certification evidence is available for tool server `{}`",
                        certification.tool_server_id
                    ),
                    evidence_refs: certification_ref.into_iter().collect(),
                });
            }
            UnderwritingCertificationState::Active => {}
        }
    } else if query.tool_server.is_some() {
        signals.push(UnderwritingSignal {
            class: UnderwritingRiskClass::Elevated,
            reason: UnderwritingReasonCode::MissingCertification,
            description: "tool-scoped underwriting input is missing certification evidence"
                .to_string(),
            evidence_refs: Vec::new(),
        });
    }

    if let Some(runtime_assurance) = runtime_assurance {
        let runtime_ref =
            runtime_assurance
                .latest_evidence_sha256
                .as_ref()
                .map(|evidence_sha256| UnderwritingEvidenceReference {
                    kind: UnderwritingEvidenceKind::RuntimeAssuranceEvidence,
                    reference_id: evidence_sha256.clone(),
                    observed_at: None,
                    digest_sha256: Some(evidence_sha256.clone()),
                    locator: runtime_assurance
                        .latest_verifier
                        .as_ref()
                        .map(|verifier| format!("runtime-assurance:{verifier}")),
                });
        if runtime_assurance.governed_receipts > 0
            && runtime_assurance.runtime_assurance_receipts == 0
        {
            signals.push(UnderwritingSignal {
                class: UnderwritingRiskClass::Elevated,
                reason: UnderwritingReasonCode::MissingRuntimeAssurance,
                description:
                    "governed receipts were observed without any bound runtime-assurance evidence"
                        .to_string(),
                evidence_refs: runtime_ref.clone().into_iter().collect(),
            });
        } else if matches!(
            runtime_assurance.highest_tier,
            Some(RuntimeAssuranceTier::None | RuntimeAssuranceTier::Basic)
        ) {
            let family_suffix = runtime_assurance
                .latest_verifier_family
                .map(underwriting_runtime_family_label)
                .map(|family| format!(" from {family}"))
                .unwrap_or_default();
            signals.push(UnderwritingSignal {
                class: UnderwritingRiskClass::Guarded,
                reason: UnderwritingReasonCode::WeakRuntimeAssurance,
                description: format!(
                    "runtime-assurance evidence{family_suffix} is present but does not exceed the basic tier"
                ),
                evidence_refs: runtime_ref.into_iter().collect(),
            });
        }
    }

    if receipts.pending_settlement_receipts > 0 {
        signals.push(UnderwritingSignal {
            class: UnderwritingRiskClass::Guarded,
            reason: UnderwritingReasonCode::PendingSettlementExposure,
            description: format!(
                "{} receipt(s) still have pending settlement exposure",
                receipts.pending_settlement_receipts
            ),
            evidence_refs: settlement_signal_evidence_refs(selection, SettlementStatus::Pending),
        });
    }
    if receipts.failed_settlement_receipts > 0 {
        signals.push(UnderwritingSignal {
            class: UnderwritingRiskClass::Critical,
            reason: UnderwritingReasonCode::FailedSettlementExposure,
            description: format!(
                "{} receipt(s) have failed settlement state",
                receipts.failed_settlement_receipts
            ),
            evidence_refs: settlement_signal_evidence_refs(selection, SettlementStatus::Failed),
        });
    }
    if receipts.actionable_metered_receipts > 0 {
        signals.push(UnderwritingSignal {
            class: UnderwritingRiskClass::Elevated,
            reason: UnderwritingReasonCode::MeteredBillingMismatch,
            description: format!(
                "{} metered receipt(s) require reconciliation or exceed quoted bounds",
                receipts.actionable_metered_receipts
            ),
            evidence_refs: metered_signal_evidence_refs(selection),
        });
    }
    if receipts.call_chain_receipts > 0 {
        signals.push(UnderwritingSignal {
            class: UnderwritingRiskClass::Guarded,
            reason: UnderwritingReasonCode::DelegatedCallChain,
            description: format!(
                "{} receipt(s) include delegated call-chain context",
                receipts.call_chain_receipts
            ),
            evidence_refs: call_chain_signal_evidence_refs(selection),
        });
    }
    if receipts.shared_evidence_proof_required_count > 0 {
        signals.push(UnderwritingSignal {
            class: UnderwritingRiskClass::Guarded,
            reason: UnderwritingReasonCode::SharedEvidenceProofRequired,
            description: format!(
                "{} shared-evidence reference(s) still require proof handling",
                receipts.shared_evidence_proof_required_count
            ),
            evidence_refs: vec![UnderwritingEvidenceReference {
                kind: UnderwritingEvidenceKind::SharedEvidenceReference,
                reference_id: format!(
                    "shared-evidence:{}",
                    query
                        .agent_subject
                        .as_deref()
                        .or(query.capability_id.as_deref())
                        .or(query.tool_server.as_deref())
                        .unwrap_or("scoped-query")
                ),
                observed_at: None,
                digest_sha256: None,
                locator: Some("shared-evidence-report".to_string()),
            }],
        });
    }

    signals
}

fn trust_http_error_from_receipt_store(error: ReceiptStoreError) -> TrustHttpError {
    match error {
        ReceiptStoreError::NotFound(message) => TrustHttpError::new(StatusCode::NOT_FOUND, message),
        ReceiptStoreError::Conflict(message) => TrustHttpError::new(StatusCode::CONFLICT, message),
        other => TrustHttpError::internal(other.to_string()),
    }
}

fn settlement_signal_evidence_refs(
    selection: &arc_kernel::BehavioralFeedReceiptSelection,
    status: SettlementStatus,
) -> Vec<UnderwritingEvidenceReference> {
    selection
        .receipts
        .iter()
        .filter(|receipt| receipt.settlement_status == status)
        .map(|receipt| UnderwritingEvidenceReference {
            kind: UnderwritingEvidenceKind::SettlementReconciliation,
            reference_id: receipt.receipt_id.clone(),
            observed_at: Some(receipt.timestamp),
            digest_sha256: None,
            locator: Some(format!("settlement:{}", receipt.receipt_id)),
        })
        .collect()
}

fn metered_signal_evidence_refs(
    selection: &arc_kernel::BehavioralFeedReceiptSelection,
) -> Vec<UnderwritingEvidenceReference> {
    selection
        .receipts
        .iter()
        .filter(|receipt| {
            receipt
                .metered_reconciliation
                .as_ref()
                .is_some_and(|row| row.action_required)
        })
        .map(|receipt| UnderwritingEvidenceReference {
            kind: UnderwritingEvidenceKind::MeteredBillingReconciliation,
            reference_id: receipt.receipt_id.clone(),
            observed_at: Some(receipt.timestamp),
            digest_sha256: receipt
                .metered_reconciliation
                .as_ref()
                .and_then(|row| row.evidence.as_ref())
                .and_then(|evidence| evidence.usage_evidence.evidence_sha256.clone()),
            locator: Some(format!("metered-billing:{}", receipt.receipt_id)),
        })
        .collect()
}

fn call_chain_signal_evidence_refs(
    selection: &arc_kernel::BehavioralFeedReceiptSelection,
) -> Vec<UnderwritingEvidenceReference> {
    selection
        .receipts
        .iter()
        .filter(|receipt| {
            receipt
                .governed
                .as_ref()
                .and_then(|governed| governed.call_chain.as_ref())
                .is_some()
        })
        .map(|receipt| UnderwritingEvidenceReference {
            kind: UnderwritingEvidenceKind::Receipt,
            reference_id: receipt.receipt_id.clone(),
            observed_at: Some(receipt.timestamp),
            digest_sha256: None,
            locator: Some(format!("receipt:{}", receipt.receipt_id)),
        })
        .collect()
}

fn load_behavioral_feed_signing_keypair(
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
) -> Result<Keypair, CliError> {
    match (authority_seed_path, authority_db_path) {
        (Some(_), Some(_)) => Err(CliError::Other(
            "behavioral feed export requires either --authority-seed-file or --authority-db, not both"
                .to_string(),
        )),
        (Some(path), None) => load_or_create_authority_keypair(path),
        (None, Some(path)) => {
            let snapshot = SqliteCapabilityAuthority::open(path)?.snapshot()?;
            Ok(Keypair::from_seed_hex(snapshot.seed_hex.trim())?)
        }
        (None, None) => Err(CliError::Other(
            "behavioral feed export requires --authority-seed-file or --authority-db so the export can be signed"
                .to_string(),
        )),
    }
}

fn response_status_text(response: &Response) -> String {
    format!("request failed with status {}", response.status())
}

fn build_budget_utilization_report(
    receipt_store: &SqliteReceiptStore,
    budget_store: &SqliteBudgetStore,
    query: &OperatorReportQuery,
) -> Result<BudgetUtilizationReport, Response> {
    let usages = if let Some(capability_id) = query.capability_id.as_deref() {
        budget_store
            .list_usages(usize::MAX, Some(capability_id))
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?
    } else {
        budget_store.list_all_usages().map_err(|error| {
            plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        })?
    };

    let mut snapshot_cache = HashMap::<String, Option<CapabilitySnapshot>>::new();
    let mut distinct_capabilities = HashSet::<String>::new();
    let mut distinct_subjects = HashSet::<String>::new();
    let mut rows = Vec::new();
    let mut matching_grants = 0_u64;
    let mut total_invocations = 0_u64;
    let mut total_cost_charged = 0_u64;
    let mut near_limit_count = 0_u64;
    let mut exhausted_count = 0_u64;
    let mut rows_missing_scope = 0_u64;
    let mut rows_missing_lineage = 0_u64;
    let row_limit = query.budget_limit_or_default();

    for usage in usages {
        let snapshot = match snapshot_cache.get(&usage.capability_id) {
            Some(cached) => cached.clone(),
            None => {
                let loaded = receipt_store
                    .get_lineage(&usage.capability_id)
                    .map_err(|error| {
                        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                    })?;
                snapshot_cache.insert(usage.capability_id.clone(), loaded.clone());
                loaded
            }
        };

        let subject_key = snapshot.as_ref().map(|value| value.subject_key.clone());
        if let Some(agent_subject) = query.agent_subject.as_deref() {
            if subject_key.as_deref() != Some(agent_subject) {
                continue;
            }
        }

        let resolved = match snapshot.as_ref() {
            Some(snapshot) => resolve_budget_grant(snapshot, usage.grant_index),
            None => ResolvedBudgetGrant {
                scope_resolution_error: Some(
                    "capability lineage snapshot not found for budget row".to_string(),
                ),
                ..ResolvedBudgetGrant::default()
            },
        };

        if let Some(tool_server) = query.tool_server.as_deref() {
            if resolved.tool_server.as_deref() != Some(tool_server) {
                continue;
            }
        }
        if let Some(tool_name) = query.tool_name.as_deref() {
            if resolved.tool_name.as_deref() != Some(tool_name) {
                continue;
            }
        }

        let invocation_utilization_rate = resolved
            .max_invocations
            .and_then(|max| ratio_option(usage.invocation_count as u64, max as u64));
        let cost_utilization_rate = resolved
            .max_total_cost_units
            .and_then(|max| ratio_option(usage.total_cost_charged, max));
        let remaining_invocations = resolved
            .max_invocations
            .map(|max| max.saturating_sub(usage.invocation_count));
        let remaining_cost_units = resolved
            .max_total_cost_units
            .map(|max| max.saturating_sub(usage.total_cost_charged));
        let exhausted = resolved
            .max_invocations
            .is_some_and(|max| usage.invocation_count >= max)
            || resolved
                .max_total_cost_units
                .is_some_and(|max| usage.total_cost_charged >= max);
        let near_limit = exhausted
            || invocation_utilization_rate.is_some_and(|rate| rate >= 0.8)
            || cost_utilization_rate.is_some_and(|rate| rate >= 0.8);

        matching_grants = matching_grants.saturating_add(1);
        total_invocations = total_invocations.saturating_add(usage.invocation_count as u64);
        total_cost_charged = total_cost_charged.saturating_add(usage.total_cost_charged);
        distinct_capabilities.insert(usage.capability_id.clone());
        if let Some(subject_key) = subject_key.clone() {
            distinct_subjects.insert(subject_key);
        }
        if snapshot.is_none() {
            rows_missing_lineage = rows_missing_lineage.saturating_add(1);
        }
        if !resolved.scope_resolved {
            rows_missing_scope = rows_missing_scope.saturating_add(1);
        }
        if near_limit {
            near_limit_count = near_limit_count.saturating_add(1);
        }
        if exhausted {
            exhausted_count = exhausted_count.saturating_add(1);
        }

        if rows.len() < row_limit {
            rows.push(BudgetUtilizationRow {
                capability_id: usage.capability_id,
                grant_index: usage.grant_index,
                subject_key,
                tool_server: resolved.tool_server,
                tool_name: resolved.tool_name,
                invocation_count: usage.invocation_count,
                max_invocations: resolved.max_invocations,
                total_cost_charged: usage.total_cost_charged,
                currency: resolved.currency,
                max_total_cost_units: resolved.max_total_cost_units,
                remaining_cost_units,
                invocation_utilization_rate,
                cost_utilization_rate,
                near_limit,
                exhausted,
                updated_at: usage.updated_at,
                scope_resolved: resolved.scope_resolved,
                scope_resolution_error: resolved.scope_resolution_error,
                dimensions: Some(BudgetDimensionProfile {
                    invocations: resolved.max_invocations.map(|max| {
                        let exhausted = usage.invocation_count >= max;
                        let near_limit = exhausted
                            || invocation_utilization_rate.is_some_and(|rate| rate >= 0.8);
                        BudgetDimensionUsage {
                            used: usage.invocation_count as u64,
                            limit: max as u64,
                            remaining: remaining_invocations.unwrap_or(0) as u64,
                            utilization_rate: invocation_utilization_rate,
                            near_limit,
                            exhausted,
                        }
                    }),
                    money: resolved.max_total_cost_units.map(|max| {
                        let exhausted = usage.total_cost_charged >= max;
                        let near_limit =
                            exhausted || cost_utilization_rate.is_some_and(|rate| rate >= 0.8);
                        BudgetDimensionUsage {
                            used: usage.total_cost_charged,
                            limit: max,
                            remaining: remaining_cost_units.unwrap_or(0),
                            utilization_rate: cost_utilization_rate,
                            near_limit,
                            exhausted,
                        }
                    }),
                }),
            });
        }
    }

    Ok(BudgetUtilizationReport {
        summary: BudgetUtilizationSummary {
            matching_grants,
            returned_grants: rows.len() as u64,
            distinct_capabilities: distinct_capabilities.len() as u64,
            distinct_subjects: distinct_subjects.len() as u64,
            total_invocations,
            total_cost_charged,
            near_limit_count,
            exhausted_count,
            rows_missing_scope,
            rows_missing_lineage,
            truncated: matching_grants > rows.len() as u64,
        },
        rows,
    })
}

fn resolve_budget_grant(snapshot: &CapabilitySnapshot, grant_index: u32) -> ResolvedBudgetGrant {
    let scope = match serde_json::from_str::<ArcScope>(&snapshot.grants_json) {
        Ok(scope) => scope,
        Err(error) => {
            return ResolvedBudgetGrant {
                scope_resolution_error: Some(format!(
                    "failed to parse grants_json for capability {}: {error}",
                    snapshot.capability_id
                )),
                ..ResolvedBudgetGrant::default()
            }
        }
    };

    let Some(grant) = scope.grants.get(grant_index as usize) else {
        return ResolvedBudgetGrant {
            scope_resolution_error: Some(format!(
                "grant_index {} is out of bounds for capability {}",
                grant_index, snapshot.capability_id
            )),
            ..ResolvedBudgetGrant::default()
        };
    };

    ResolvedBudgetGrant {
        tool_server: Some(grant.server_id.clone()),
        tool_name: Some(grant.tool_name.clone()),
        max_invocations: grant.max_invocations,
        max_total_cost_units: grant.max_total_cost.as_ref().map(|value| value.units),
        currency: grant
            .max_total_cost
            .as_ref()
            .map(|value| value.currency.clone())
            .or_else(|| {
                grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map(|value| value.currency.clone())
            }),
        scope_resolved: true,
        scope_resolution_error: None,
    }
}

fn ratio_option(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn open_receipt_store(config: &TrustServiceConfig) -> Result<SqliteReceiptStore, Response> {
    let Some(path) = config.receipt_db_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires --receipt-db",
        ));
    };
    SqliteReceiptStore::open(path)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))
}

fn open_revocation_store(config: &TrustServiceConfig) -> Result<SqliteRevocationStore, Response> {
    let Some(path) = config.revocation_db_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires --revocation-db",
        ));
    };
    SqliteRevocationStore::open(path)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))
}

fn open_budget_store(config: &TrustServiceConfig) -> Result<SqliteBudgetStore, Response> {
    let Some(path) = config.budget_db_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires --budget-db",
        ));
    };
    SqliteBudgetStore::open(path)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))
}

fn revocation_list_response(
    capability_id: Option<String>,
    revoked: Option<bool>,
    revocations: Vec<RevocationRecord>,
) -> RevocationListResponse {
    RevocationListResponse {
        configured: true,
        backend: "sqlite".to_string(),
        capability_id,
        revoked,
        count: revocations.len(),
        revocations: revocations
            .into_iter()
            .map(|entry| RevocationRecordView {
                capability_id: entry.capability_id,
                revoked_at: entry.revoked_at,
            })
            .collect(),
    }
}

fn list_limit(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT)
}

fn plain_http_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}
