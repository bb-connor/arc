#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pact_core::capability::{CapabilityToken, PactScope};
use pact_core::crypto::{Keypair, PublicKey};
use pact_core::receipt::{ChildRequestReceipt, Decision, PactReceipt};
use pact_core::session::{EnterpriseIdentityContext, OperationTerminalState};
use pact_core::{canonical_json_bytes, sha256_hex, Signature};
use pact_credentials::{
    create_passport_presentation_challenge_with_reference,
    ensure_signed_passport_verifier_policy_active,
    verify_passport_presentation_response_with_policy, verify_signed_passport_verifier_policy,
    AgentPassport, PassportPresentationChallenge, PassportPresentationResponse,
    PassportPresentationVerification, PassportVerifierPolicy, PassportVerifierPolicyReference,
    SignedPassportVerifierPolicy,
};
use pact_did::DidPact;
use pact_kernel::{
    AuthoritySnapshot, AuthorityStatus, BudgetStore, BudgetStoreError, BudgetUsageRecord,
    BudgetUtilizationReport, BudgetUtilizationRow, BudgetUtilizationSummary, CapabilityAuthority,
    CapabilitySnapshot, CostAttributionQuery, CostAttributionReport, LocalCapabilityAuthority,
    OperatorReport, OperatorReportQuery, ReceiptAnalyticsQuery, ReceiptAnalyticsResponse,
    ReceiptQuery, ReceiptStore, ReceiptStoreError, RevocationRecord, RevocationStore,
    RevocationStoreError, SharedEvidenceQuery, SharedEvidenceReferenceReport, SqliteBudgetStore,
    SqliteCapabilityAuthority, SqliteReceiptStore, SqliteRevocationStore, StoredCapabilitySnapshot,
    StoredChildReceipt, StoredToolReceipt,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{info, warn};
use ureq::Agent;

use crate::{
    authority_public_key_from_seed_file,
    certify::{
        CertificationRegistry, CertificationRegistryEntry, CertificationRegistryListResponse,
        CertificationResolutionResponse, CertificationRevocationRequest, SignedCertificationCheck,
    },
    enterprise_federation::{EnterpriseProviderRecord, EnterpriseProviderRegistry},
    evidence_export, issuance, load_or_create_authority_keypair,
    passport_verifier::{PassportVerifierChallengeStore, VerifierPolicyRegistry},
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
const PASSPORT_VERIFIER_POLICIES_PATH: &str = "/v1/passport/verifier-policies";
const PASSPORT_VERIFIER_POLICY_PATH: &str = "/v1/passport/verifier-policies/{policy_id}";
const PASSPORT_CHALLENGES_PATH: &str = "/v1/passport/challenges";
const PASSPORT_CHALLENGE_VERIFY_PATH: &str = "/v1/passport/challenges/verify";
const FEDERATED_DELEGATION_POLICY_SCHEMA: &str = "pact.federated-delegation-policy.v1";
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
    pub certification_registry_file: Option<PathBuf>,
    pub issuance_policy: Option<crate::policy::ReputationIssuancePolicy>,
    pub advertise_url: Option<String>,
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
    scope: PactScope,
    ttl_seconds: u64,
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
    pub admission_policy: Option<pact_policy::HushSpec>,
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
    pub scope: PactScope,
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
    if policy.body.schema != FEDERATED_DELEGATION_POLICY_SCHEMA {
        return Err(CliError::Other(format!(
            "unsupported federated delegation policy schema: {}",
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
    let parent_scope: PactScope = serde_json::from_str(&parent_snapshot.grants_json)?;
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

fn configured_certification_registry_path(config: &TrustServiceConfig) -> Result<&Path, CliError> {
    config.certification_registry_file.as_deref().ok_or_else(|| {
        CliError::Other(
            "certification registry administration requires --certification-registry-file on the trust-control service"
                .to_string(),
        )
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
            pact_core::EnterpriseFederationMethod::Jwt => "jwt",
            pact_core::EnterpriseFederationMethod::Introspection => "introspection",
            pact_core::EnterpriseFederationMethod::Scim => "scim",
            pact_core::EnterpriseFederationMethod::Saml => "saml",
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

fn enterprise_origin_context(identity: &EnterpriseIdentityContext) -> pact_policy::OriginContext {
    pact_policy::OriginContext {
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
        .route(CERTIFICATIONS_PATH, get(handle_list_certifications).post(handle_publish_certification))
        .route(CERTIFICATION_PATH, get(handle_get_certification))
        .route(CERTIFICATION_RESOLVE_PATH, get(handle_resolve_certification))
        .route(CERTIFICATION_REVOKE_PATH, post(handle_revoke_certification))
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
             Run 'npm run build' in crates/pact-cli/dashboard/ to enable."
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

    info!(listen_addr = %local_addr, "serving PACT trust control service");
    eprintln!("PACT trust control service listening on http://{local_addr}");

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
        scope: PactScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, CliError> {
        let response: IssueCapabilityResponse = self.post_json(
            ISSUE_CAPABILITY_PATH,
            &IssueCapabilityRequest {
                subject_public_key: subject.to_hex(),
                scope,
                ttl_seconds,
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
        self.get_json(&format!("{FEDERATION_PROVIDERS_PATH}/{provider_id}"))
    }

    pub fn upsert_enterprise_provider(
        &self,
        provider_id: &str,
        record: &EnterpriseProviderRecord,
    ) -> Result<EnterpriseProviderRecord, CliError> {
        self.put_json(
            &format!("{FEDERATION_PROVIDERS_PATH}/{provider_id}"),
            record,
        )
    }

    pub fn delete_enterprise_provider(
        &self,
        provider_id: &str,
    ) -> Result<EnterpriseProviderDeleteResponse, CliError> {
        self.delete_json(&format!("{FEDERATION_PROVIDERS_PATH}/{provider_id}"))
    }

    pub fn list_certifications(&self) -> Result<CertificationRegistryListResponse, CliError> {
        self.get_json(CERTIFICATIONS_PATH)
    }

    pub fn get_certification(
        &self,
        artifact_id: &str,
    ) -> Result<CertificationRegistryEntry, CliError> {
        self.get_json(&format!("/v1/certifications/{artifact_id}"))
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
        self.get_json(&format!("/v1/certifications/resolve/{tool_server_id}"))
    }

    pub fn revoke_certification(
        &self,
        artifact_id: &str,
        request: &CertificationRevocationRequest,
    ) -> Result<CertificationRegistryEntry, CliError> {
        self.post_json(&format!("/v1/certifications/{artifact_id}/revoke"), request)
    }

    pub fn list_verifier_policies(&self) -> Result<VerifierPolicyListResponse, CliError> {
        self.get_json(PASSPORT_VERIFIER_POLICIES_PATH)
    }

    pub fn get_verifier_policy(
        &self,
        policy_id: &str,
    ) -> Result<SignedPassportVerifierPolicy, CliError> {
        self.get_json(&format!("{PASSPORT_VERIFIER_POLICIES_PATH}/{policy_id}"))
    }

    pub fn upsert_verifier_policy(
        &self,
        policy_id: &str,
        document: &SignedPassportVerifierPolicy,
    ) -> Result<SignedPassportVerifierPolicy, CliError> {
        self.put_json(
            &format!("{PASSPORT_VERIFIER_POLICIES_PATH}/{policy_id}"),
            document,
        )
    }

    pub fn delete_verifier_policy(
        &self,
        policy_id: &str,
    ) -> Result<VerifierPolicyDeleteResponse, CliError> {
        self.delete_json(&format!("{PASSPORT_VERIFIER_POLICIES_PATH}/{policy_id}"))
    }

    pub fn create_passport_challenge(
        &self,
        request: &CreatePassportChallengeRequest,
    ) -> Result<PassportPresentationChallenge, CliError> {
        self.post_json(PASSPORT_CHALLENGES_PATH, request)
    }

    pub fn verify_passport_challenge(
        &self,
        request: &VerifyPassportChallengeRequest,
    ) -> Result<PassportPresentationVerification, CliError> {
        self.post_json(PASSPORT_CHALLENGE_VERIFY_PATH, request)
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

    pub fn local_reputation(
        &self,
        subject_key: &str,
        query: &LocalReputationQuery,
    ) -> Result<issuance::LocalReputationInspection, CliError> {
        self.get_json_with_query(&format!("/v1/reputation/local/{subject_key}"), query)
    }

    pub fn reputation_compare(
        &self,
        subject_key: &str,
        request: &ReputationCompareRequest,
    ) -> Result<reputation::PortableReputationComparison, CliError> {
        self.post_json(&format!("/v1/reputation/compare/{subject_key}"), request)
    }

    pub fn append_tool_receipt(&self, receipt: &PactReceipt) -> Result<(), CliError> {
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
        scope: PactScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, pact_kernel::KernelError> {
        let capability = self
            .client
            .issue_capability(subject, scope, ttl_seconds)
            .map_err(|error| {
                pact_kernel::KernelError::CapabilityIssuanceFailed(error.to_string())
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
    fn append_pact_receipt(&mut self, receipt: &PactReceipt) -> Result<(), ReceiptStoreError> {
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
    Json(json!({
        "ok": true,
        "leaderUrl": leader_url,
        "selfUrl": cluster_self_url(&state),
        "clustered": state.cluster.is_some(),
    }))
    .into_response()
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
    match load_capability_authority(&state.config) {
        Ok(authority) => {
            match authority.issue_capability(&subject, payload.scope, payload.ttl_seconds) {
                Ok(capability) => Json(IssueCapabilityResponse { capability }).into_response(),
                Err(pact_kernel::KernelError::CapabilityIssuanceDenied(error)) => {
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
    let entry = match registry.revoke(
        &artifact_id,
        request.reason.as_deref(),
        request.revoked_at,
    ) {
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
        pact_credentials::PassportPresentationOptions {
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
    Json(challenge).into_response()
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
    if let Err(error) = configured_verifier_challenge_db_path(&state.config) {
        return plain_http_error(StatusCode::CONFLICT, &error.to_string());
    }
    let now = unix_timestamp_now();
    let challenge = payload
        .expected_challenge
        .as_ref()
        .unwrap_or(&payload.presentation.challenge);
    let (resolved_policy, policy_source) = match resolve_verifier_policy_for_challenge(
        state.verifier_policy_registry(),
        challenge,
        now,
    ) {
        Ok(values) => values,
        Err(error) => return plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let mut verification = match verify_passport_presentation_response_with_policy(
        &payload.presentation,
        payload.expected_challenge.as_ref(),
        now,
        resolved_policy.as_ref(),
        policy_source,
    ) {
        Ok(verification) => verification,
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    };
    match consume_challenge_if_configured(&state.config, challenge, now) {
        Ok(replay_state) => verification.replay_state = replay_state,
        Err(error) => return plain_http_error(StatusCode::FORBIDDEN, &error.to_string()),
    }
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
    let subject_did = match DidPact::from_str(&verification.subject) {
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
            let Some(profile_id) = pact_policy::selected_origin_profile_id(
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
                &subject_public_key,
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
                        enterprise_audit,
                        delegation_anchor_capability_id,
                    })
                    .into_response()
                }
                Err(pact_kernel::KernelError::CapabilityIssuanceDenied(error)) => {
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
    Json(receipt): Json<PactReceipt>,
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
    match store.append_pact_receipt(&receipt) {
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
        Ok(inspection) => Json(inspection).into_response(),
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
    match reputation::build_reputation_comparison(
        local,
        &request.passport,
        request.verifier_policy.as_ref(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0),
        shared_evidence,
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
            let receipt: PactReceipt = serde_json::from_value(record.receipt)?;
            store.append_pact_receipt(&receipt)?;
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
            .map(|trusted_key| pact_kernel::AuthorityTrustedKeySnapshot {
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
                config.receipt_db_path.as_deref(),
                config.budget_db_path.as_deref(),
            ))
        }
        (None, Some(path)) => SqliteCapabilityAuthority::open(path)
            .map(|authority| {
                issuance::wrap_capability_authority(
                    Box::new(authority),
                    config.issuance_policy.clone(),
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
        shared_evidence,
    })
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
    let scope = match serde_json::from_str::<PactScope>(&snapshot.grants_json) {
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
