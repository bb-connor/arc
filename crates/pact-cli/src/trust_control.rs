#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pact_core::capability::{CapabilityToken, PactScope};
use pact_core::crypto::PublicKey;
use pact_core::receipt::{ChildRequestReceipt, Decision, PactReceipt};
use pact_core::session::OperationTerminalState;
use pact_kernel::{
    AuthoritySnapshot, AuthorityStatus, BudgetStore, BudgetStoreError, BudgetUsageRecord,
    CapabilityAuthority, LocalCapabilityAuthority, ReceiptQuery, ReceiptStore, ReceiptStoreError,
    RevocationRecord, RevocationStore, RevocationStoreError, SqliteBudgetStore,
    SqliteCapabilityAuthority, SqliteReceiptStore, SqliteRevocationStore, StoredChildReceipt,
    StoredToolReceipt,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{info, warn};
use ureq::Agent;

use crate::{
    authority_public_key_from_seed_file, load_or_create_authority_keypair,
    rotate_authority_keypair, CliError,
};

// Content Security Policy applied to all responses from the dashboard/API server.
// Restricts resource loading to same-origin only; unsafe-inline is allowed for
// styles because Vite injects inline style tags at build time.
const CSP_VALUE: &str = "default-src 'self'; script-src 'self'; \
    style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:";

const HEALTH_PATH: &str = "/health";
const AUTHORITY_PATH: &str = "/v1/authority";
const ISSUE_CAPABILITY_PATH: &str = "/v1/capabilities/issue";
const REVOCATIONS_PATH: &str = "/v1/revocations";
const TOOL_RECEIPTS_PATH: &str = "/v1/receipts/tools";
const CHILD_RECEIPTS_PATH: &str = "/v1/receipts/children";
const BUDGETS_PATH: &str = "/v1/budgets";
const BUDGET_INCREMENT_PATH: &str = "/v1/budgets/increment";
const INTERNAL_CLUSTER_STATUS_PATH: &str = "/v1/internal/cluster/status";
const INTERNAL_AUTHORITY_SNAPSHOT_PATH: &str = "/v1/internal/authority/snapshot";
const INTERNAL_REVOCATIONS_DELTA_PATH: &str = "/v1/internal/revocations/delta";
const INTERNAL_TOOL_RECEIPTS_DELTA_PATH: &str = "/v1/internal/receipts/tools/delta";
const INTERNAL_CHILD_RECEIPTS_DELTA_PATH: &str = "/v1/internal/receipts/children/delta";
const INTERNAL_BUDGETS_DELTA_PATH: &str = "/v1/internal/budgets/delta";
const RECEIPT_QUERY_PATH: &str = "/v1/receipts/query";
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
    pub advertise_url: Option<String>,
    pub peer_urls: Vec<String>,
    pub cluster_sync_interval: Duration,
}

#[derive(Clone)]
struct TrustServiceState {
    config: TrustServiceConfig,
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

async fn serve_async(config: TrustServiceConfig) -> Result<(), CliError> {
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let cluster = build_cluster_state(&config, local_addr)?;
    let state = TrustServiceState { config, cluster };
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
        .route(RECEIPT_QUERY_PATH, get(handle_query_receipts))
        .route(LINEAGE_PATH, get(handle_get_lineage))
        .route(LINEAGE_CHAIN_PATH, get(handle_get_delegation_chain))
        .route(AGENT_RECEIPTS_PATH, get(handle_agent_receipts));

    // Wire the dashboard SPA after all API routes so it acts as a catch-all.
    // API routes registered above take priority over the nest_service wildcard.
    // The conditional avoids a hard startup failure when the dashboard has not
    // been built (e.g. in CI or API-only deployments).
    let dashboard_dir = std::path::Path::new(DASHBOARD_DIST_DIR);
    let router = if dashboard_dir.join("index.html").exists() {
        let spa_fallback = ServeFile::new(dashboard_dir.join("index.html"));
        let spa_service = ServeDir::new(dashboard_dir).not_found_service(spa_fallback);
        router.nest_service("/", spa_service)
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

    pub fn append_tool_receipt(&self, receipt: &PactReceipt) -> Result<(), CliError> {
        let _: Value = self.post_json(TOOL_RECEIPTS_PATH, receipt)?;
        Ok(())
    }

    pub fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), CliError> {
        let _: Value = self.post_json(CHILD_RECEIPTS_PATH, receipt)?;
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
        _capability_id: &str,
        _grant_index: usize,
        _max_invocations: Option<u32>,
        _cost_units: u64,
        _max_cost_per_invocation: Option<u64>,
        _max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        // Remote monetary cost charging is not yet implemented.
        // Fall back to allowing the request (cost tracking happens on the authority node).
        Ok(true)
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
                        total_cost_charged: 0,
                    })
                    .collect()
            })
            .map_err(into_budget_store_error)
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
                Ok(capability) => {
                    // Record the capability snapshot in the lineage index immediately after
                    // issuance. This is best-effort: if the receipt DB is not configured or
                    // the write fails, we log a warning but still return the capability.
                    if let Some(path) = state.config.receipt_db_path.as_deref() {
                        match SqliteReceiptStore::open(path) {
                            Ok(mut store) => {
                                if let Err(e) = store.record_capability_snapshot(&capability, None)
                                {
                                    warn!(
                                        capability_id = %capability.id,
                                        error = %e,
                                        "failed to record capability lineage snapshot"
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    capability_id = %capability.id,
                                    error = %e,
                                    "failed to open receipt store for capability lineage"
                                );
                            }
                        }
                    }
                    Json(IssueCapabilityResponse { capability }).into_response()
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
    match store.get_lineage(&capability_id) {
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
    match store.get_delegation_chain(&capability_id) {
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
                .list_usages(MAX_LIST_LIMIT, Some(&payload.capability_id))
                .map(|usages| {
                    usages
                        .into_iter()
                        .find(|usage| usage.grant_index == payload.grant_index as u32)
                        .map(|usage| usage.invocation_count)
                })
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
                updated_at: usage.updated_at,
                seq: Some(usage.seq),
            })
            .collect(),
    })
    .into_response()
}

async fn run_cluster_sync_loop(state: TrustServiceState) {
    loop {
        if let Err(error) = sync_cluster_once(&state) {
            warn!(error = %error, "trust-control cluster sync failed");
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
            Ok(Box::new(LocalCapabilityAuthority::new(keypair)))
        }
        (None, Some(path)) => SqliteCapabilityAuthority::open(path)
            .map(|authority| Box::new(authority) as Box<dyn CapabilityAuthority>)
            .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())),
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
