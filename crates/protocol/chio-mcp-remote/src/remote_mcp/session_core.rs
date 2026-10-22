#[cfg(test)]
use chio_mcp_adapter::edge::ingress::McpInboxReceiver;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::thread;
use std::time::Duration;

use async_stream::stream;
use axum::extract::{Form, Path as AxumPath, Query, Request, State};
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, ORIGIN, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::{sha256_hex, Keypair, PublicKey, Signature as Ed25519Signature};
use chio_core::session::{
    ChioIdentityAssertion, EnterpriseFederationMethod, EnterpriseIdentityContext,
    OAuthBearerFederatedClaims, RequestOwnershipSnapshot, SessionAuthContext, SessionAuthMethod,
    SessionId,
};
use chio_egress_contract::{
    client_builder_with_contract, send_with_contract, ContractClient, HttpEgressContract,
};
use chio_kernel::operator_report::{
    CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_CLAIM,
    CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_CLAIM,
};
use chio_kernel::{
    ChioKernel, ChioOAuthAuthorizationProfile, GovernedAuthorizationDetail,
    GovernedAuthorizationTransactionContext, KernelError, PeerCapabilities, RevocationStore,
    ToolServerConnection, CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE,
    CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE, CHIO_OAUTH_AUTHORIZATION_PROFILE_ID,
    CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA, CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE,
    CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT,
};
use chio_mcp_adapter::adapter::{McpAdapter, McpAdapterConfig};
use chio_mcp_adapter::edge::ingress::{
    mcp_inbox, AccountedMessage, McpInboxSender, McpRequestGeneration, McpResponseContext,
};
use chio_mcp_adapter::edge::{AdapterError, ChioMcpEdge, McpEdgeConfig, McpTransport};
use chio_mcp_adapter::server::AdaptedMcpServer;
use chio_mcp_adapter::transport::StdioMcpTransport;
use hmac::{Hmac, Mac};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use rsa::pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey as RsaPkcs1v15VerifyingKey};
use rsa::pss::{Signature as RsaPssSignature, VerifyingKey as RsaPssVerifyingKey};
use rsa::signature::Verifier as _;
use rsa::{BigUint, RsaPublicKey as JwtRsaPublicKey};
use serde::de::{DeserializeOwned, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use chio_control_plane::policy::{load_policy, LoadedPolicy};
use chio_control_plane::trust_control::service_runtime::remote_authority::build_pinned_remote_capability_authority_with_clock;
use chio_control_plane::trust_control::{
    self, ChildReceiptQuery, RevocationQuery, ToolReceiptQuery,
};
use chio_control_plane::{
    authority_public_key_from_seed_file, configure_budget_store, configure_capability_authority,
    configure_receipt_store, configure_revocation_store, durable_admission_sidecar_path,
    enterprise_federation::{
        EnterpriseProviderKind, EnterpriseProviderRecord, EnterpriseProviderRegistry,
    },
    issue_default_capabilities, load_or_create_authority_keypair, open_durable_admission_runtime,
    require_control_token, rotate_authority_keypair, validate_distinct_database_paths,
    validate_durable_admission_participant_paths, DurableAdmissionRuntime,
};

const MCP_ENDPOINT_PATH: &str = "/mcp";
const ADMIN_HEALTH_PATH: &str = "/admin/health";
const ADMIN_AUTHORITY_PATH: &str = "/admin/authority";
const ADMIN_TOOL_RECEIPTS_PATH: &str = "/admin/receipts/tools";
const ADMIN_CHILD_RECEIPTS_PATH: &str = "/admin/receipts/children";
const ADMIN_REVOCATIONS_PATH: &str = "/admin/revocations";
const ADMIN_BUDGETS_PATH: &str = "/admin/budgets";
const ADMIN_SESSIONS_PATH: &str = "/admin/sessions";
const ADMIN_EMERGENCY_STOP_PATH: &str = "/admin/emergency-stop";
const ADMIN_EMERGENCY_RESUME_PATH: &str = "/admin/emergency-resume";
const ADMIN_EMERGENCY_STATUS_PATH: &str = "/admin/emergency-status";
const AUTHORIZATION_SERVER_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
const LOCAL_AUTHORIZATION_PATH: &str = "/oauth/authorize";
const LOCAL_TOKEN_PATH: &str = "/oauth/token";
const LOCAL_JWKS_PATH: &str = "/oauth/jwks.json";
const DPOP_HEADER: &str = "dpop";
const CHIO_MTLS_THUMBPRINT_HEADER: &str = "x-chio-mtls-thumbprint-sha256";
const CHIO_RUNTIME_ATTESTATION_HEADER: &str = "x-chio-runtime-attestation-sha256";
const CHIO_SENDER_DPOP_PUBLIC_KEY_PARAMETER: &str = "chio_sender_dpop_public_key";
const CHIO_SENDER_MTLS_THUMBPRINT_PARAMETER: &str = "chio_sender_mtls_thumbprint_sha256";
const CHIO_SENDER_ATTESTATION_PARAMETER: &str = "chio_sender_attestation_sha256";
const ADMIN_SESSION_TRUST_PATH: &str = "/admin/sessions/{session_id}/trust";
const ADMIN_SESSION_DRAIN_PATH: &str = "/admin/sessions/{session_id}/drain";
const ADMIN_SESSION_SHUTDOWN_PATH: &str = "/admin/sessions/{session_id}/shutdown";
const PROTECTED_RESOURCE_METADATA_ROOT_PATH: &str = "/.well-known/oauth-protected-resource";
const PROTECTED_RESOURCE_METADATA_MCP_PATH: &str = "/.well-known/oauth-protected-resource/mcp";
const MCP_SESSION_ID_HEADER: &str = "mcp-session-id";
const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
const CHIO_RESPONSE_MODE_HEADER: &str = "x-chio-mcp-response-mode";
const CHIO_TOOL_STREAMING_CAPABILITY_KEY: &str = "chioToolStreaming";
const DEFAULT_STREAM_RETRY_MILLIS: u64 = 1_000;
const DEFAULT_NOTIFICATION_REPLAY_WINDOW: usize = 64;
const DEFAULT_SHARED_NOTIFICATION_POLL_MILLIS: u64 = 25;
const DEFAULT_ADMIN_LIST_LIMIT: usize = 50;
const MAX_ADMIN_LIST_LIMIT: usize = 200;
const DEFAULT_SESSION_IDLE_EXPIRY_MILLIS: u64 = 15 * 60 * 1000;
const DEFAULT_SESSION_DRAIN_GRACE_MILLIS: u64 = 5 * 1000;
const DEFAULT_SESSION_REAPER_INTERVAL_MILLIS: u64 = 250;
const DEFAULT_SESSION_TOMBSTONE_RETENTION_MILLIS: u64 = 30 * 60 * 1000;
const DEFAULT_REQUEST_RESPONSE_TIMEOUT_MILLIS: u64 = 15 * 60 * 1000;
const IDENTITY_PROVIDER_FETCH_TIMEOUT_SECS: u64 = 5;
const TOKEN_INTROSPECTION_TIMEOUT_SECS: u64 = 5;
const IDENTITY_FEDERATION_DERIVATION_LABEL: &[u8] = b"chio.identity_federation.v1";
const REMOTE_SESSION_RESUME_RECORD_HMAC_LABEL: &[u8] = b"chio.remote_mcp.resume_record_hmac.v1";
const REMOTE_SESSION_TOMBSTONE_HMAC_LABEL: &[u8] = b"chio.remote_mcp.terminal_tombstone_hmac.v1";
const REMOTE_SESSION_TERMINAL_FENCE_HMAC_LABEL: &[u8] = b"chio.remote_mcp.terminal_fence_hmac.v1";
const REMOTE_SESSION_HMAC_KEYRING_SCHEMA: &str = "chio.remote-mcp.resume-hmac-keyring.v1";
const MAX_REMOTE_SESSION_HMAC_PREVIOUS_KEYS: usize = 4;
const MAX_REMOTE_SESSION_HMAC_GRACE_MILLIS: u64 = 7 * 24 * 60 * 60 * 1_000;
const SESSION_IDLE_EXPIRY_ENV: &str = "CHIO_MCP_SESSION_IDLE_EXPIRY_MILLIS";
const SESSION_DRAIN_GRACE_ENV: &str = "CHIO_MCP_SESSION_DRAIN_GRACE_MILLIS";
const SESSION_REAPER_INTERVAL_ENV: &str = "CHIO_MCP_SESSION_REAPER_INTERVAL_MILLIS";
const SESSION_TOMBSTONE_RETENTION_ENV: &str = "CHIO_MCP_SESSION_TOMBSTONE_RETENTION_MILLIS";
const REQUEST_RESPONSE_TIMEOUT_ENV: &str = "CHIO_MCP_REQUEST_RESPONSE_TIMEOUT_MILLIS";
const SESSION_TOUCH_PERSIST_INTERVAL_MILLIS: u64 = 5_000;

type NotificationTapQueue = Arc<StdMutex<VecDeque<Value>>>;
type NotificationTapWeak = Weak<StdMutex<VecDeque<Value>>>;
type NotificationSubscriberList = Arc<StdMutex<Vec<NotificationTapWeak>>>;

/// One `--auth-client CLIENT_ID=REDIRECT_URI` registration for the embedded
/// authorization server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthClientRegistration {
    pub client_id: String,
    pub redirect_uri: String,
}

impl std::str::FromStr for OAuthClientRegistration {
    type Err = String;

    /// Parses `CLIENT_ID=REDIRECT_URI`, splitting at the first `=`.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (client_id, redirect_uri) = value
            .split_once('=')
            .ok_or_else(|| format!("expected CLIENT_ID=REDIRECT_URI, got `{value}`"))?;
        Ok(Self {
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
        })
    }
}

#[derive(Clone)]
pub struct RemoteServeHttpConfig {
    /// Activated DPoP replay authority loaded from
    /// `CHIO_DPOP_REPLAY_AUTHORITY_FILE`; required when the policy requires DPoP.
    pub dpop_replay_authority: Option<chio_kernel::dpop::authority::DpopReplayAuthority>,
    pub clock: RemoteClock,
    pub listen: SocketAddr,
    /// Listener confidentiality and explicit plaintext policy.
    pub transport: chio_http_serve::ServerTransportConfig,
    /// Explicit authenticated proxy trust for TLS and attestation binding evidence.
    pub trusted_proxy: Option<TrustedProxyConfig>,
    pub auth_token: Option<String>,
    pub auth_jwt_public_key: Option<String>,
    pub auth_jwt_discovery_url: Option<String>,
    pub auth_introspection_url: Option<String>,
    pub auth_introspection_client_id: Option<String>,
    pub auth_introspection_client_secret: Option<String>,
    pub auth_jwt_provider_profile: Option<JwtProviderProfile>,
    pub auth_server_seed_path: Option<PathBuf>,
    pub identity_federation_seed_path: Option<PathBuf>,
    pub enterprise_providers_file: Option<PathBuf>,
    pub auth_jwt_issuer: Option<String>,
    pub auth_jwt_audience: Option<String>,
    pub admin_token: Option<String>,
    /// Explicit operator principals and activated native approval replay custody.
    pub approval: Option<RemoteApprovalConfig>,
    pub control_url: Option<String>,
    pub control_token: Option<String>,
    /// Dedicated trust-control bearer used only for remote capability issuance.
    pub remote_authority_workload_token: Option<String>,
    /// Exact current capability-authority key expected from trust-control.
    pub control_authority_public_key: Option<PublicKey>,
    /// Exact trusted capability-authority key set expected from trust-control.
    pub control_authority_trusted_public_keys: Vec<PublicKey>,
    pub public_base_url: Option<String>,
    pub auth_servers: Vec<String>,
    pub auth_authorization_endpoint: Option<String>,
    pub auth_token_endpoint: Option<String>,
    pub auth_registration_endpoint: Option<String>,
    pub auth_jwks_uri: Option<String>,
    pub auth_scopes: Vec<String>,
    /// Clients the embedded authorization server accepts, each with one exact
    /// redirect URI. A client with several redirect URIs appears once per URI.
    pub auth_clients: Vec<OAuthClientRegistration>,
    pub auth_subject: String,
    pub auth_code_ttl_secs: u64,
    pub auth_access_token_ttl_secs: u64,
    pub receipt_db_path: Option<PathBuf>,
    pub revocation_db_path: Option<PathBuf>,
    pub authority_seed_path: Option<PathBuf>,
    pub authority_db_path: Option<PathBuf>,
    pub budget_db_path: Option<PathBuf>,
    pub session_db_path: Option<PathBuf>,
    /// Dedicated, operator-managed HMAC keyring for durable session records.
    /// This keyring must remain independent from authority and bearer secrets.
    pub resume_hmac_keyring_path: Option<PathBuf>,
    pub policy_path: PathBuf,
    pub server_id: String,
    pub server_name: String,
    pub server_version: String,
    pub signed_manifest_path: Option<PathBuf>,
    pub manifest_public_key: Option<String>,
    /// Pinned authority that prepares every native launch. The factory must
    /// fail closed when its policy, migration state, or manifest binding no
    /// longer authorizes the exact subprocess.
    #[cfg(test)]
    pub(crate) test_transport: Option<Arc<dyn McpTransport>>,
    #[cfg(test)]
    pub(crate) test_lifecycle_policy: Option<SessionLifecyclePolicy>,
    /// A session output line bound below the production bound.
    #[cfg(test)]
    pub(crate) test_session_line_bytes: Option<usize>,
    pub native_launch_factory: Arc<dyn chio_mcp_adapter::transport::NativeMcpLaunchFactory>,
    pub page_size: usize,
    pub tools_list_changed: bool,
    pub shared_hosted_owner: bool,
    pub wrapped_command: String,
    pub wrapped_args: Vec<String>,
    /// Typed HTTP egress contract that gates outbound HTTP from the remote
    /// MCP runtime (most prominently the OAuth introspection endpoint).
    /// Production deployments must populate this; absence falls back to
    /// substrate fail-closed at dispatch.
    pub egress_contract: Option<HttpEgressContract>,
}

#[derive(Clone)]
struct RemoteAppState {
    sessions: Arc<RemoteSessionLedger>,
    factory: Arc<RemoteSessionFactory>,
    auth_mode: Arc<RemoteAuthMode>,
    enterprise_provider_registry: Option<EnterpriseProviderRegistryFile>,
    admin_token: Option<Arc<str>>,
    protected_resource_metadata: Option<Arc<ProtectedResourceMetadata>>,
    authorization_server_metadata: Option<Arc<AuthorizationServerMetadata>>,
    local_auth_server: Option<Arc<LocalAuthorizationServer>>,
}

struct RemoteSessionFactory {
    config: RemoteServeHttpConfig,
    manifest_registry: Arc<chio_manifest::VerifiedManifestRegistry>,
    runtime_contract_fingerprint: String,
    durable_admission: Option<DurableAdmissionRuntime>,
    session_store_lease: Option<Arc<RemoteSessionStoreLifecycleLease>>,
    resume_hmac_keyring: Option<Arc<RemoteSessionHmacKeyring>>,
    /// The configured provider registry, bound into every auth contract.
    enterprise_provider_registry: Option<EnterpriseProviderRegistryFile>,
    shared_upstream_owner: Arc<StdMutex<Option<Arc<SharedUpstreamOwner>>>>,
    lifecycle_policy: SessionLifecyclePolicy,
    /// One stop for every session kernel this edge constructs.
    stop: chio_kernel::stop::StopControl,
}

#[derive(Clone, Debug)]
struct SessionLifecyclePolicy {
    idle_expiry_millis: u64,
    drain_grace_millis: u64,
    reaper_interval_millis: u64,
    tombstone_retention_millis: u64,
    /// Bound on a dispatched request's wait for its terminal response.
    request_response_timeout_millis: u64,
}

impl Default for SessionLifecyclePolicy {
    fn default() -> Self {
        Self {
            idle_expiry_millis: DEFAULT_SESSION_IDLE_EXPIRY_MILLIS,
            drain_grace_millis: DEFAULT_SESSION_DRAIN_GRACE_MILLIS,
            reaper_interval_millis: DEFAULT_SESSION_REAPER_INTERVAL_MILLIS,
            tombstone_retention_millis: DEFAULT_SESSION_TOMBSTONE_RETENTION_MILLIS,
            request_response_timeout_millis: DEFAULT_REQUEST_RESPONSE_TIMEOUT_MILLIS,
        }
    }
}

impl SessionLifecyclePolicy {
    fn from_env() -> Result<Self, CliError> {
        Self::from_lookup(|name| std::env::var_os(name))
    }

    /// An unset variable takes its default. A set variable must be a positive
    /// decimal integer of milliseconds; anything else refuses the policy.
    fn from_lookup(
        lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
    ) -> Result<Self, CliError> {
        let read = |name: &str, default: u64| -> Result<u64, CliError> {
            let Some(raw) = lookup(name) else {
                return Ok(default);
            };
            raw.to_str()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    CliError::cli_other_error(format!(
                        "{name} must be a positive integer number of milliseconds"
                    ))
                })
        };
        Ok(Self {
            idle_expiry_millis: read(
                SESSION_IDLE_EXPIRY_ENV,
                DEFAULT_SESSION_IDLE_EXPIRY_MILLIS,
            )?,
            drain_grace_millis: read(SESSION_DRAIN_GRACE_ENV, DEFAULT_SESSION_DRAIN_GRACE_MILLIS)?,
            reaper_interval_millis: read(
                SESSION_REAPER_INTERVAL_ENV,
                DEFAULT_SESSION_REAPER_INTERVAL_MILLIS,
            )?,
            tombstone_retention_millis: read(
                SESSION_TOMBSTONE_RETENTION_ENV,
                DEFAULT_SESSION_TOMBSTONE_RETENTION_MILLIS,
            )?,
            request_response_timeout_millis: read(
                REQUEST_RESPONSE_TIMEOUT_ENV,
                DEFAULT_REQUEST_RESPONSE_TIMEOUT_MILLIS,
            )?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RemoteSessionDiagnosticRecord {
    session_id: String,
    auth_context: SessionAuthContext,
    capabilities: Vec<RemoteSessionCapability>,
    lifecycle: RemoteSessionLifecycleSnapshot,
    protocol_version: Option<String>,
    ownership: RemoteSessionOwnershipSnapshot,
    terminal_at: u64,
    terminal_reason: Option<TerminalReason>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RemoteSessionResumeRecord {
    session_id: String,
    agent_id: String,
    auth_context: SessionAuthContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_mode_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_fingerprint: Option<String>,
    runtime_contract_fingerprint: String,
    hosted_isolation: RemoteHostedIsolationMode,
    lifecycle: RemoteSessionLifecycleSnapshot,
    protocol_version: Option<String>,
    peer_capabilities: PeerCapabilities,
    initialize_params: Value,
    issued_capabilities: Vec<CapabilityToken>,
    subscriptions: Vec<PersistedSubscription>,
    resume_generation: u64,
    resume_integrity: RemoteSessionIntegrityTag,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RemoteSessionIntegrityTag {
    key_id: String,
    key_version: u64,
    tag: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RemoteSessionTombstoneRecord {
    record: RemoteSessionDiagnosticRecord,
    resume_generation: u64,
    terminal_epoch: u64,
    resume_integrity: RemoteSessionIntegrityTag,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RemoteSessionTerminalFence {
    session_id: String,
    terminal_at: u64,
    terminal_state: RemoteSessionState,
    terminal_reason: TerminalReason,
    resume_generation: u64,
    terminal_epoch: u64,
    resume_integrity: RemoteSessionIntegrityTag,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RemoteSessionHmacKeyringFile {
    schema: String,
    current: RemoteSessionHmacKeyFile,
    #[serde(default)]
    previous: Vec<RemoteSessionPreviousHmacKeyFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RemoteSessionHmacKeyFile {
    key_id: String,
    version: u64,
    key_base64: String,
}

impl Drop for RemoteSessionHmacKeyFile {
    fn drop(&mut self) {
        self.key_base64.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RemoteSessionPreviousHmacKeyFile {
    key_id: String,
    version: u64,
    key_base64: String,
    verify_until_millis: u64,
}

impl Drop for RemoteSessionPreviousHmacKeyFile {
    fn drop(&mut self) {
        self.key_base64.zeroize();
    }
}

struct RemoteSessionHmacKey {
    key_id: String,
    version: u64,
    key: Zeroizing<[u8; 32]>,
    verify_until_millis: Option<u64>,
}

struct RemoteSessionHmacKeyring {
    current: RemoteSessionHmacKey,
    previous: Vec<RemoteSessionHmacKey>,
}

impl std::fmt::Debug for RemoteSessionHmacKeyring {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteSessionHmacKeyring")
            .field("current_key_id", &self.current.key_id)
            .field("current_version", &self.current.version)
            .field("previous_key_count", &self.previous.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
enum RemoteSessionEntry {
    Active(Arc<RemoteSession>),
    Terminal(Arc<RemoteSessionDiagnosticRecord>),
}

#[derive(Clone)]
struct RemoteSessionLedger {
    clock: RemoteClock,
    // A session leaves `active` only in the same critical section that makes
    // it visible in `terminal`. Code holding both guards takes `active` first.
    active: Arc<Mutex<HashMap<String, Arc<RemoteSession>>>>,
    terminal: Arc<Mutex<HashMap<String, Arc<RemoteSessionDiagnosticRecord>>>>,
    lifecycle_policy: SessionLifecyclePolicy,
    tombstone_db_path: Option<PathBuf>,
    resume_hmac_keyring: Option<Arc<RemoteSessionHmacKeyring>>,
}

#[derive(Clone)]
struct SharedUpstreamToolServer {
    upstream: Arc<AdaptedMcpServer>,
    server_id: String,
    tool_names: Vec<String>,
}

struct SharedUpstreamOwner {
    upstream_server: Arc<AdaptedMcpServer>,
    notification_subscribers: NotificationSubscriberList,
    notification_stats: Arc<SharedUpstreamNotificationStats>,
    notification_pump_stop: Arc<AtomicBool>,
    notification_pump_thread: StdMutex<Option<thread::JoinHandle<()>>>,
}

struct SharedUpstreamNotificationTap {
    queue: NotificationTapQueue,
}

#[derive(Default)]
struct SharedUpstreamNotificationStats {
    fanout_batches: AtomicU64,
    fanout_notifications: AtomicU64,
    fanout_targets: AtomicU64,
    pruned_subscribers: AtomicU64,
    queue_lock_skips: AtomicU64,
    subscriber_lock_failures: AtomicU64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SharedUpstreamNotificationStatsSnapshot {
    fanout_batches: u64,
    fanout_notifications: u64,
    fanout_targets: u64,
    pruned_subscribers: u64,
    queue_lock_skips: u64,
    subscriber_lock_failures: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RetainedRemoteSessionEvent {
    seq: u64,
    event_id: String,
    message: Value,
}

#[derive(Clone, Debug)]
struct RemoteSessionEvent {
    seq: u64,
    event_id: String,
    kind: RemoteSessionEventKind,
    request_generation: Option<McpRequestGeneration>,
    message: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemoteSessionEventKind {
    Notification,
    StandaloneRequest,
    RequestCorrelated,
}

impl RemoteSessionEventKind {
    fn is_session_owned(self) -> bool {
        matches!(self, Self::Notification | Self::StandaloneRequest)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum RemoteSessionState {
    Initializing,
    Ready,
    Draining,
    Deleted,
    Expired,
    Closed,
}

impl RemoteSessionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::Ready => "ready",
            Self::Draining => "draining",
            Self::Deleted => "deleted",
            Self::Expired => "expired",
            Self::Closed => "closed",
        }
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Deleted | Self::Expired | Self::Closed)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RemoteSessionLifecycleSnapshot {
    #[serde(skip)]
    deadline: Option<AuthorityDeadline>,
    state: RemoteSessionState,
    created_at: u64,
    last_seen_at: u64,
    idle_expires_at: u64,
    drain_deadline_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemoteRequestStreamOwner {
    ExclusiveRequestStream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemoteNotificationStreamOwner {
    SessionNotificationStream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemoteNotificationDelivery {
    PostResponseFallback,
    GetSse,
}

/// Upstream process ownership for hosted sessions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemoteHostedIsolationMode {
    /// Each session owns its own upstream process.
    DedicatedPerSession,
    /// One upstream process serves every session of the edge.
    SharedHostedOwner,
}

/// Strength of the identity binding between a session and its upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RemoteHostedIdentityProfile {
    /// The upstream process sees only this session's authenticated principal.
    StrongDedicatedSession,
    /// The upstream process is shared, so the session snapshot omits the
    /// bearer token fingerprint and upstream state is not per-principal.
    WeakSharedHostedOwner,
}

impl RemoteHostedIsolationMode {
    fn identity_profile(self) -> RemoteHostedIdentityProfile {
        match self {
            Self::DedicatedPerSession => RemoteHostedIdentityProfile::StrongDedicatedSession,
            Self::SharedHostedOwner => {
                RemoteHostedIdentityProfile::WeakSharedHostedOwner
            }
        }
    }

    fn snapshot_auth_context(self, auth_context: SessionAuthContext) -> SessionAuthContext {
        match (self, auth_context) {
            (
                Self::SharedHostedOwner,
                SessionAuthContext {
                    transport,
                    method,
                    origin,
                },
            ) if matches!(
                transport,
                chio_core::session::SessionTransport::StreamableHttp
            ) =>
            {
                match method {
                    SessionAuthMethod::OAuthBearer {
                        principal,
                        issuer,
                        subject,
                        audience,
                        scopes,
                        federated_claims,
                        enterprise_identity,
                        ..
                    } => SessionAuthContext {
                        transport,
                        method: SessionAuthMethod::OAuthBearer {
                            principal,
                            issuer,
                            subject,
                            audience,
                            scopes,
                            federated_claims,
                            enterprise_identity,
                            token_fingerprint: None,
                        },
                        origin,
                    },
                    other_method => SessionAuthContext {
                        transport,
                        method: other_method,
                        origin,
                    },
                }
            }
            (_, auth_context) => auth_context,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteSessionOwnershipSnapshot {
    request_ownership: RequestOwnershipSnapshot,
    hosted_isolation: RemoteHostedIsolationMode,
    hosted_identity_profile: RemoteHostedIdentityProfile,
    request_stream_owner: RemoteRequestStreamOwner,
    notification_stream_owner: RemoteNotificationStreamOwner,
    notification_delivery: RemoteNotificationDelivery,
    request_stream_active: bool,
    notification_stream_attached: bool,
}

impl Default for RemoteSessionOwnershipSnapshot {
    fn default() -> Self {
        Self {
            request_ownership: RequestOwnershipSnapshot::request_owned(),
            hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
            hosted_identity_profile: RemoteHostedIdentityProfile::StrongDedicatedSession,
            request_stream_owner: RemoteRequestStreamOwner::ExclusiveRequestStream,
            notification_stream_owner: RemoteNotificationStreamOwner::SessionNotificationStream,
            notification_delivery: RemoteNotificationDelivery::PostResponseFallback,
            request_stream_active: false,
            notification_stream_attached: false,
        }
    }
}

#[derive(Debug)]
struct RemoteSession {
    clock: RemoteClock,
    session_id: String,
    agent_id: String,
    capabilities: Vec<RemoteSessionCapability>,
    issued_capabilities: Vec<CapabilityToken>,
    auth_context: SessionAuthContext,
    auth_mode_fingerprint: String,
    policy_fingerprint: String,
    runtime_contract_fingerprint: String,
    hosted_isolation: RemoteHostedIsolationMode,
    lifecycle_policy: SessionLifecyclePolicy,
    protocol_version: StdMutex<Option<String>>,
    peer_capabilities: StdMutex<Option<PeerCapabilities>>,
    initialize_params: StdMutex<Option<Value>>,
    lifecycle: StdMutex<RemoteSessionLifecycleSnapshot>,
    input_tx: McpInboxSender,
    event_tx: broadcast::Sender<RemoteSessionEvent>,
    retained_notification_events: Arc<StdMutex<VecDeque<RetainedRemoteSessionEvent>>>,
    active_request_stream: Arc<Mutex<()>>,
    worker_serving_closed: tokio::sync::watch::Sender<bool>,
    notification_stream_attached: Arc<AtomicBool>,
    next_event_id: Arc<AtomicU64>,
    session_db_path: Option<PathBuf>,
    approval_redemption: Option<remote_mcp_approvals::ApprovalRedemption>,
    session_store_lease: Option<Arc<RemoteSessionStoreLifecycleLease>>,
    resume_hmac_keyring: Option<Arc<RemoteSessionHmacKeyring>>,
    resume_generation: AtomicU64,
    /// Standard resource subscriptions by URI, mapped to their capability id.
    subscriptions: StdMutex<BTreeMap<String, String>>,
    subscription_deadline: StdMutex<session_core_session::SubscriptionDeadline>,
    /// A terminal reason latched before the terminal transition runs.
    terminal_reason_latch: std::sync::OnceLock<TerminalReason>,
    terminalization: Mutex<()>,
    upstream_transport: RemoteSessionUpstreamTransport,
}

struct RemoteSessionUpstreamTransport {
    inner: Arc<dyn McpTransport>,
}

impl std::fmt::Debug for RemoteSessionUpstreamTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteSessionUpstreamTransport")
            .finish_non_exhaustive()
    }
}

struct RemoteSessionInit {
    clock: RemoteClock,
    session_id: String,
    agent_id: String,
    capabilities: Vec<RemoteSessionCapability>,
    issued_capabilities: Vec<CapabilityToken>,
    auth_context: SessionAuthContext,
    auth_mode_fingerprint: String,
    policy_fingerprint: String,
    runtime_contract_fingerprint: String,
    hosted_isolation: RemoteHostedIsolationMode,
    lifecycle_policy: SessionLifecyclePolicy,
    protocol_version: Option<String>,
    peer_capabilities: Option<PeerCapabilities>,
    initialize_params: Option<Value>,
    lifecycle_snapshot: Option<RemoteSessionLifecycleSnapshot>,
    input_tx: McpInboxSender,
    event_tx: broadcast::Sender<RemoteSessionEvent>,
    retained_notification_events: Arc<StdMutex<VecDeque<RetainedRemoteSessionEvent>>>,
    next_event_id: Arc<AtomicU64>,
    session_db_path: Option<PathBuf>,
    approval_redemption: Option<remote_mcp_approvals::ApprovalRedemption>,
    session_store_lease: Option<Arc<RemoteSessionStoreLifecycleLease>>,
    resume_hmac_keyring: Option<Arc<RemoteSessionHmacKeyring>>,
    resume_generation: u64,
    upstream_transport: Arc<dyn McpTransport>,
}

struct NotificationStreamAttachment {
    session: Arc<RemoteSession>,
}

impl Drop for NotificationStreamAttachment {
    fn drop(&mut self) {
        self.session.detach_notification_stream();
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone)]
enum RemoteAuthMode {
    StaticBearer {
        token: Arc<str>,
    },
    JwtBearer {
        verifier: Arc<JwtBearerVerifier>,
    },
    IntrospectionBearer {
        verifier: Arc<IntrospectionBearerVerifier>,
    },
}

impl std::fmt::Debug for RemoteAuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaticBearer { .. } => f.write_str("StaticBearer"),
            Self::JwtBearer { .. } => f.write_str("JwtBearer"),
            Self::IntrospectionBearer { .. } => f.write_str("IntrospectionBearer"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JwtSignatureAlgorithm {
    EdDsa,
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
}

#[derive(Clone, Debug)]
enum JwtVerificationKeySource {
    Static(PublicKey),
    Jwks(JwtJwksKeySet),
}

#[derive(Clone)]
struct JwtBearerVerifier {
    clock: RemoteClock,
    key_source: JwtVerificationKeySource,
    issuer: Option<String>,
    audience: Option<String>,
    required_scopes: Vec<String>,
    provider_profile: JwtProviderProfile,
    enterprise_provider_registry: Option<EnterpriseProviderRegistryFile>,
}

#[derive(Clone)]
struct IntrospectionBearerVerifier {
    clock: RemoteClock,
    client: ContractClient,
    introspection_url: Url,
    client_id: Option<String>,
    client_secret: Option<String>,
    issuer: Option<String>,
    audience: Option<String>,
    required_scopes: Vec<String>,
    provider_profile: JwtProviderProfile,
    enterprise_provider_registry: Option<EnterpriseProviderRegistryFile>,
    /// Typed HTTP egress contract that gates every introspection-endpoint
    /// dispatch. Production deployments must populate this; without a
    /// contract the verifier substrate will fail closed if introspection is
    /// invoked.
    egress_contract: Option<HttpEgressContract>,
}

#[derive(Clone)]
struct ProtectedResourceMetadata {
    resource: String,
    resource_metadata_url: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
    chio_authorization_profile: Value,
}

#[derive(Clone)]
struct AuthorizationServerMetadata {
    metadata_path: String,
    document: Value,
}

#[derive(Clone)]
struct LocalAuthorizationServer {
    clock: RemoteClock,
    signing_key: Keypair,
    issuer: String,
    default_audience: String,
    supported_scopes: Vec<String>,
    subject: String,
    code_ttl_secs: u64,
    access_token_ttl_secs: u64,
    codes: Arc<StdMutex<HashMap<String, AuthorizationCodeGrant>>>,
    consents: Arc<StdMutex<HashMap<String, PendingConsent>>>,
    /// Registered client ids and the exact redirect URIs each may use.
    clients: Arc<HashMap<String, HashSet<String>>>,
}

/// An authorization request whose consent page was rendered and not yet
/// answered, keyed by the single-use nonce embedded in that page.
#[derive(Clone, Debug)]
struct PendingConsent {
    deadline: AuthorityDeadline,
    request: AuthorizationRequest,
}

#[derive(Clone, Debug)]
struct AuthorizationCodeGrant {
    deadline: AuthorityDeadline,
    client_id: String,
    redirect_uri: String,
    resource: String,
    scopes: Vec<String>,
    subject: String,
    code_challenge: String,
    code_challenge_method: String,
    expires_at: u64,
    authorization_details: Option<Vec<GovernedAuthorizationDetail>>,
    transaction_context: Option<GovernedAuthorizationTransactionContext>,
    sender_constraint: Option<ChioSenderConstraintClaims>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    rename_all = "camelCase",
    try_from = "sender_constraint::ConfirmationWire"
)]
struct ChioSenderConstraintClaims {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "chioSenderKey"
    )]
    chio_sender_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "x5t#S256")]
    mtls_thumbprint_sha256: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "chioAttestationSha256"
    )]
    chio_attestation_sha256: Option<String>,
}

impl ChioSenderConstraintClaims {
    fn is_empty(&self) -> bool {
        self.chio_sender_key.is_none()
            && self.mtls_thumbprint_sha256.is_none()
            && self.chio_attestation_sha256.is_none()
    }
}

#[derive(Clone, Debug)]
struct JwtJwksKeySet {
    keys_by_kid: HashMap<String, JwtResolvedJwkPublicKey>,
    anonymous_keys: Vec<JwtResolvedJwkPublicKey>,
}

#[derive(Clone, Debug)]
struct DiscoveredIdentityProvider {
    issuer: String,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    registration_endpoint: Option<String>,
    jwks_uri: Option<String>,
    jwks_keys: Option<JwtJwksKeySet>,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    aud: Option<JwtAudience>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scp: Vec<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    oid: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    appid: Option<String>,
    #[serde(default)]
    tid: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_vec")]
    groups: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_vec")]
    roles: Vec<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    authorization_details: Option<Value>,
    #[serde(default)]
    chio_transaction_context: Option<Value>,
    #[serde(
        default,
        deserialize_with = "sender_constraint::deserialize_confirmation"
    )]
    cnf: Option<ChioSenderConstraintClaims>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum JwtAudience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    issuer: String,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    registration_endpoint: Option<String>,
    #[serde(default)]
    jwks_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuthIntrospectionResponse {
    active: bool,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(flatten)]
    claims: JwtClaims,
}

#[derive(Debug, Deserialize)]
struct JwksDocument {
    #[serde(default)]
    keys: Vec<JwkDocumentKey>,
}

#[derive(Debug, Deserialize)]
struct JwkDocumentKey {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    key_use: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Clone, Debug)]
struct JwtResolvedJwkPublicKey {
    key: JwtResolvedPublicKey,
    alg_hint: Option<String>,
}

#[derive(Clone, Debug)]
enum JwtResolvedPublicKey {
    Ed25519(PublicKey),
    Rsa(JwtRsaPublicKey),
    P256(P256VerifyingKey),
    P384(P384VerifyingKey),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RemoteSessionCapability {
    id: String,
    issuer_public_key: String,
    subject_public_key: String,
}

#[path = "session_core/authority_mode.rs"]
mod session_core_authority_mode;
#[path = "session_core/factory.rs"]
mod session_core_factory;
#[path = "session_core/ledger.rs"]
mod session_core_ledger;
#[path = "session_core/session.rs"]
mod session_core_session;

#[path = "session_core/subscription.rs"]
mod session_core_subscription;
use session_core_subscription::PersistedSubscription;
#[path = "session_core/terminal_reason.rs"]
mod session_core_terminal_reason;
use session_core_terminal_reason::{
    sign_terminal_session_records, validate_terminal_fence_integrity,
    validate_terminal_tombstone_integrity, TerminalReason,
};

#[path = "session_core/writer.rs"]
mod session_core_writer;
use session_core_writer::BroadcastJsonRpcWriter;

impl RemoteServeHttpConfig {
    fn lifecycle_policy(&self) -> Result<SessionLifecyclePolicy, CliError> {
        #[cfg(test)]
        if let Some(policy) = &self.test_lifecycle_policy {
            return Ok(policy.clone());
        }
        SessionLifecyclePolicy::from_env()
    }
}
