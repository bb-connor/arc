use super::*;

pub(super) const MCP_ENDPOINT_PATH: &str = "/mcp";
pub(super) const ADMIN_HEALTH_PATH: &str = "/admin/health";
pub(super) const ADMIN_AUTHORITY_PATH: &str = "/admin/authority";
pub(super) const ADMIN_TOOL_RECEIPTS_PATH: &str = "/admin/receipts/tools";
pub(super) const ADMIN_CHILD_RECEIPTS_PATH: &str = "/admin/receipts/children";
pub(super) const ADMIN_REVOCATIONS_PATH: &str = "/admin/revocations";
pub(super) const ADMIN_BUDGETS_PATH: &str = "/admin/budgets";
pub(super) const ADMIN_SESSIONS_PATH: &str = "/admin/sessions";
pub(super) const AUTHORIZATION_SERVER_METADATA_PATH: &str =
    "/.well-known/oauth-authorization-server";
pub(super) const LOCAL_AUTHORIZATION_PATH: &str = "/oauth/authorize";
pub(super) const LOCAL_TOKEN_PATH: &str = "/oauth/token";
pub(super) const LOCAL_JWKS_PATH: &str = "/oauth/jwks.json";
pub(super) const DPOP_HEADER: &str = "dpop";
pub(super) const HTTP_DPOP_ACTION_HASH_EMPTY: &[u8] = b"";
pub(super) const CHIO_MTLS_THUMBPRINT_HEADER: &str = "x-chio-mtls-thumbprint-sha256";
pub(super) const CHIO_RUNTIME_ATTESTATION_HEADER: &str = "x-chio-runtime-attestation-sha256";
pub(super) const CHIO_SENDER_DPOP_PUBLIC_KEY_PARAMETER: &str = "chio_sender_dpop_public_key";
pub(super) const CHIO_SENDER_MTLS_THUMBPRINT_PARAMETER: &str = "chio_sender_mtls_thumbprint_sha256";
pub(super) const CHIO_SENDER_ATTESTATION_PARAMETER: &str = "chio_sender_attestation_sha256";
pub(super) const ADMIN_SESSION_TRUST_PATH: &str = "/admin/sessions/{session_id}/trust";
pub(super) const ADMIN_SESSION_DRAIN_PATH: &str = "/admin/sessions/{session_id}/drain";
pub(super) const ADMIN_SESSION_SHUTDOWN_PATH: &str = "/admin/sessions/{session_id}/shutdown";
pub(super) const PROTECTED_RESOURCE_METADATA_ROOT_PATH: &str =
    "/.well-known/oauth-protected-resource";
pub(super) const PROTECTED_RESOURCE_METADATA_MCP_PATH: &str =
    "/.well-known/oauth-protected-resource/mcp";
pub(super) const MCP_SESSION_ID_HEADER: &str = "mcp-session-id";
pub(super) const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
pub(super) const CHIO_RESPONSE_MODE_HEADER: &str = "x-chio-mcp-response-mode";
pub(super) const CHIO_TOOL_STREAMING_CAPABILITY_KEY: &str = "chioToolStreaming";
pub(super) const DEFAULT_STREAM_RETRY_MILLIS: u64 = 1_000;
pub(super) const DEFAULT_NOTIFICATION_REPLAY_WINDOW: usize = 64;
pub(super) const DEFAULT_SHARED_NOTIFICATION_POLL_MILLIS: u64 = 25;
pub(super) const DEFAULT_ADMIN_LIST_LIMIT: usize = 50;
pub(super) const MAX_ADMIN_LIST_LIMIT: usize = 200;
pub(super) const DEFAULT_SESSION_IDLE_EXPIRY_MILLIS: u64 = 15 * 60 * 1000;
pub(super) const DEFAULT_SESSION_DRAIN_GRACE_MILLIS: u64 = 5 * 1000;
pub(super) const DEFAULT_SESSION_REAPER_INTERVAL_MILLIS: u64 = 250;
pub(super) const DEFAULT_SESSION_TOMBSTONE_RETENTION_MILLIS: u64 = 30 * 60 * 1000;
pub(super) const IDENTITY_PROVIDER_FETCH_TIMEOUT_SECS: u64 = 5;
pub(super) const TOKEN_INTROSPECTION_TIMEOUT_SECS: u64 = 5;
pub(super) const IDENTITY_FEDERATION_DERIVATION_LABEL: &[u8] = b"chio.identity_federation.v1";
pub(super) const REMOTE_SESSION_RESUME_RECORD_HMAC_LABEL: &[u8] =
    b"chio.remote_mcp.resume_record_hmac.v2";
pub(super) const REMOTE_SESSION_TOMBSTONE_HMAC_LABEL: &[u8] =
    b"chio.remote_mcp.terminal_tombstone_hmac.v2";
pub(super) const REMOTE_SESSION_TERMINAL_FENCE_HMAC_LABEL: &[u8] =
    b"chio.remote_mcp.terminal_fence_hmac.v2";
pub(super) const REMOTE_SESSION_HMAC_KEYRING_SCHEMA: &str =
    "chio.remote-mcp.resume-hmac-keyring.v1";
pub(super) const MAX_REMOTE_SESSION_HMAC_PREVIOUS_KEYS: usize = 4;
pub(super) const MAX_REMOTE_SESSION_HMAC_GRACE_MILLIS: u64 = 7 * 24 * 60 * 60 * 1_000;
pub(super) const SESSION_IDLE_EXPIRY_ENV: &str = "CHIO_MCP_SESSION_IDLE_EXPIRY_MILLIS";
pub(super) const SESSION_DRAIN_GRACE_ENV: &str = "CHIO_MCP_SESSION_DRAIN_GRACE_MILLIS";
pub(super) const SESSION_REAPER_INTERVAL_ENV: &str = "CHIO_MCP_SESSION_REAPER_INTERVAL_MILLIS";
pub(super) const SESSION_TOMBSTONE_RETENTION_ENV: &str =
    "CHIO_MCP_SESSION_TOMBSTONE_RETENTION_MILLIS";
pub(super) const SESSION_TOUCH_PERSIST_INTERVAL_MILLIS: u64 = 5_000;

pub(super) type NotificationTapQueue = Arc<StdMutex<VecDeque<Value>>>;
pub(super) type NotificationTapWeak = Weak<StdMutex<VecDeque<Value>>>;
pub(super) type NotificationSubscriberList = Arc<StdMutex<Vec<NotificationTapWeak>>>;

#[derive(Clone)]
pub struct RemoteServeHttpConfig {
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
pub(super) struct RemoteAppState {
    pub(super) sessions: Arc<RemoteSessionLedger>,
    pub(super) factory: Arc<RemoteSessionFactory>,
    pub(super) auth_mode: Arc<RemoteAuthMode>,
    pub(super) enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
    pub(super) admin_token: Option<Arc<str>>,
    pub(super) protected_resource_metadata: Option<Arc<ProtectedResourceMetadata>>,
    pub(super) authorization_server_metadata: Option<Arc<AuthorizationServerMetadata>>,
    pub(super) local_auth_server: Option<Arc<LocalAuthorizationServer>>,
}

pub(super) struct RemoteSessionFactory {
    pub(super) config: RemoteServeHttpConfig,
    pub(super) manifest_registry: Arc<chio_manifest::VerifiedManifestRegistry>,
    pub(super) runtime_contract_fingerprint: String,
    pub(super) durable_admission: Option<DurableAdmissionRuntime>,
    pub(super) session_store_lease: Option<Arc<RemoteSessionStoreLifecycleLease>>,
    pub(super) resume_hmac_keyring: Option<Arc<RemoteSessionHmacKeyring>>,
    pub(super) shared_upstream_owner: Arc<StdMutex<Option<Arc<SharedUpstreamOwner>>>>,
    pub(super) lifecycle_policy: SessionLifecyclePolicy,
}

#[derive(Clone, Debug)]
pub(super) struct SessionLifecyclePolicy {
    pub(super) idle_expiry_millis: u64,
    pub(super) drain_grace_millis: u64,
    pub(super) reaper_interval_millis: u64,
    pub(super) tombstone_retention_millis: u64,
}

impl SessionLifecyclePolicy {
    pub(super) fn from_env() -> Self {
        read_session_lifecycle_policy()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct RemoteSessionDiagnosticRecord {
    pub(super) session_id: String,
    pub(super) auth_context: SessionAuthContext,
    pub(super) capabilities: Vec<RemoteSessionCapability>,
    pub(super) lifecycle: RemoteSessionLifecycleSnapshot,
    pub(super) protocol_version: Option<String>,
    #[serde(default)]
    pub(super) ownership: RemoteSessionOwnershipSnapshot,
    pub(super) terminal_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct RemoteSessionResumeRecord {
    pub(super) session_id: String,
    pub(super) agent_id: String,
    pub(super) auth_context: SessionAuthContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) auth_mode_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) policy_fingerprint: Option<String>,
    pub(super) runtime_contract_fingerprint: String,
    pub(super) hosted_isolation: RemoteHostedIsolationMode,
    pub(super) lifecycle: RemoteSessionLifecycleSnapshot,
    pub(super) protocol_version: Option<String>,
    pub(super) peer_capabilities: PeerCapabilities,
    pub(super) initialize_params: Value,
    pub(super) issued_capabilities: Vec<CapabilityToken>,
    pub(super) resume_generation: u64,
    pub(super) resume_integrity: RemoteSessionIntegrityTag,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct RemoteSessionIntegrityTag {
    pub(super) key_id: String,
    pub(super) key_version: u64,
    pub(super) tag: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct RemoteSessionTombstoneRecord {
    pub(super) record: RemoteSessionDiagnosticRecord,
    pub(super) resume_generation: u64,
    pub(super) terminal_epoch: u64,
    pub(super) resume_integrity: RemoteSessionIntegrityTag,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct RemoteSessionTerminalFence {
    pub(super) session_id: String,
    pub(super) terminal_at: u64,
    pub(super) terminal_state: RemoteSessionState,
    pub(super) resume_generation: u64,
    pub(super) terminal_epoch: u64,
    pub(super) resume_integrity: RemoteSessionIntegrityTag,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RemoteSessionHmacKeyringFile {
    pub(super) schema: String,
    pub(super) current: RemoteSessionHmacKeyFile,
    #[serde(default)]
    pub(super) previous: Vec<RemoteSessionPreviousHmacKeyFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RemoteSessionHmacKeyFile {
    pub(super) key_id: String,
    pub(super) version: u64,
    pub(super) key_base64: String,
}

impl Drop for RemoteSessionHmacKeyFile {
    fn drop(&mut self) {
        self.key_base64.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RemoteSessionPreviousHmacKeyFile {
    pub(super) key_id: String,
    pub(super) version: u64,
    pub(super) key_base64: String,
    pub(super) verify_until_millis: u64,
}

impl Drop for RemoteSessionPreviousHmacKeyFile {
    fn drop(&mut self) {
        self.key_base64.zeroize();
    }
}

pub(super) struct RemoteSessionHmacKey {
    pub(super) key_id: String,
    pub(super) version: u64,
    pub(super) key: Zeroizing<[u8; 32]>,
    pub(super) verify_until_millis: Option<u64>,
}

pub(super) struct RemoteSessionHmacKeyring {
    pub(super) current: RemoteSessionHmacKey,
    pub(super) previous: Vec<RemoteSessionHmacKey>,
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
pub(super) enum RemoteSessionEntry {
    Active(Arc<RemoteSession>),
    Terminal(Arc<RemoteSessionDiagnosticRecord>),
}

pub(super) struct TerminalIntent {
    pub(super) record: RemoteSessionDiagnosticRecord,
    pub(super) terminal_at: u64,
    pub(super) durable_tombstone: Option<RemoteSessionTombstoneRecord>,
}

#[derive(Clone)]
pub(super) struct RemoteSessionLedger {
    pub(super) clock: RemoteClock,
    pub(super) active: Arc<Mutex<HashMap<String, Arc<RemoteSession>>>>,
    pub(super) terminal: Arc<Mutex<HashMap<String, Arc<RemoteSessionDiagnosticRecord>>>>,
    pub(super) lifecycle_policy: SessionLifecyclePolicy,
    pub(super) tombstone_db_path: Option<PathBuf>,
    pub(super) resume_hmac_keyring: Option<Arc<RemoteSessionHmacKeyring>>,
}

#[derive(Clone)]
pub(super) struct SharedUpstreamToolServer {
    pub(super) upstream: Arc<AdaptedMcpServer>,
    pub(super) server_id: String,
    pub(super) tool_names: Vec<String>,
}

pub(super) struct SharedUpstreamOwner {
    pub(super) upstream_server: Arc<AdaptedMcpServer>,
    pub(super) notification_subscribers: NotificationSubscriberList,
    pub(super) notification_stats: Arc<SharedUpstreamNotificationStats>,
    pub(super) notification_pump_stop: Arc<AtomicBool>,
    pub(super) notification_pump_thread: StdMutex<Option<thread::JoinHandle<()>>>,
}

pub(super) struct SharedUpstreamNotificationTap {
    pub(super) queue: NotificationTapQueue,
}

#[derive(Default)]
pub(super) struct SharedUpstreamNotificationStats {
    pub(super) fanout_batches: AtomicU64,
    pub(super) fanout_notifications: AtomicU64,
    pub(super) fanout_targets: AtomicU64,
    pub(super) pruned_subscribers: AtomicU64,
    pub(super) queue_lock_skips: AtomicU64,
    pub(super) subscriber_lock_failures: AtomicU64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SharedUpstreamNotificationStatsSnapshot {
    pub(super) fanout_batches: u64,
    pub(super) fanout_notifications: u64,
    pub(super) fanout_targets: u64,
    pub(super) pruned_subscribers: u64,
    pub(super) queue_lock_skips: u64,
    pub(super) subscriber_lock_failures: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct RetainedRemoteSessionEvent {
    pub(super) seq: u64,
    pub(super) event_id: String,
    pub(super) message: Value,
}

#[derive(Clone, Debug)]
pub(super) struct RemoteSessionEvent {
    pub(super) seq: u64,
    pub(super) event_id: String,
    pub(super) kind: RemoteSessionEventKind,
    pub(super) request_generation: Option<McpRequestGeneration>,
    pub(super) message: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RemoteSessionEventKind {
    Notification,
    StandaloneRequest,
    RequestCorrelated,
}

impl RemoteSessionEventKind {
    pub(super) fn is_session_owned(self) -> bool {
        matches!(self, Self::Notification | Self::StandaloneRequest)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum RemoteSessionState {
    Initializing,
    Ready,
    Draining,
    Deleted,
    Expired,
    Closed,
}

impl RemoteSessionState {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::Ready => "ready",
            Self::Draining => "draining",
            Self::Deleted => "deleted",
            Self::Expired => "expired",
            Self::Closed => "closed",
        }
    }

    pub(super) fn is_terminal(self) -> bool {
        matches!(self, Self::Deleted | Self::Expired | Self::Closed)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct RemoteSessionLifecycleSnapshot {
    #[serde(skip)]
    pub(super) deadline: Option<AuthorityDeadline>,
    pub(super) state: RemoteSessionState,
    pub(super) created_at: u64,
    pub(super) last_seen_at: u64,
    pub(super) idle_expires_at: u64,
    pub(super) drain_deadline_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RemoteRequestStreamOwner {
    ExclusiveRequestStream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RemoteNotificationStreamOwner {
    SessionNotificationStream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RemoteNotificationDelivery {
    PostResponseFallback,
    GetSse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub(super) enum RemoteHostedIsolationMode {
    #[default]
    DedicatedPerSession,
    SharedHostedOwnerCompatibility,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub(super) enum RemoteHostedIdentityProfile {
    #[default]
    StrongDedicatedSession,
    WeakSharedHostedOwnerCompatibility,
}

impl RemoteHostedIsolationMode {
    pub(super) fn identity_profile(self) -> RemoteHostedIdentityProfile {
        match self {
            Self::DedicatedPerSession => RemoteHostedIdentityProfile::StrongDedicatedSession,
            Self::SharedHostedOwnerCompatibility => {
                RemoteHostedIdentityProfile::WeakSharedHostedOwnerCompatibility
            }
        }
    }

    pub(super) fn snapshot_auth_context(
        self,
        auth_context: SessionAuthContext,
    ) -> SessionAuthContext {
        match (self, auth_context) {
            (
                Self::SharedHostedOwnerCompatibility,
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
pub(super) struct RemoteSessionOwnershipSnapshot {
    pub(super) request_ownership: RequestOwnershipSnapshot,
    #[serde(default)]
    pub(super) hosted_isolation: RemoteHostedIsolationMode,
    #[serde(default)]
    pub(super) hosted_identity_profile: RemoteHostedIdentityProfile,
    pub(super) request_stream_owner: RemoteRequestStreamOwner,
    pub(super) notification_stream_owner: RemoteNotificationStreamOwner,
    pub(super) notification_delivery: RemoteNotificationDelivery,
    pub(super) request_stream_active: bool,
    pub(super) notification_stream_attached: bool,
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
pub(super) struct RemoteSession {
    pub(super) clock: RemoteClock,
    pub(super) session_id: String,
    pub(super) agent_id: String,
    pub(super) capabilities: Vec<RemoteSessionCapability>,
    pub(super) issued_capabilities: Vec<CapabilityToken>,
    pub(super) auth_context: SessionAuthContext,
    pub(super) auth_mode_fingerprint: String,
    pub(super) policy_fingerprint: String,
    pub(super) runtime_contract_fingerprint: String,
    pub(super) hosted_isolation: RemoteHostedIsolationMode,
    pub(super) lifecycle_policy: SessionLifecyclePolicy,
    pub(super) protocol_version: StdMutex<Option<String>>,
    pub(super) peer_capabilities: StdMutex<Option<PeerCapabilities>>,
    pub(super) initialize_params: StdMutex<Option<Value>>,
    pub(super) lifecycle: StdMutex<RemoteSessionLifecycleSnapshot>,
    pub(super) input_tx: McpInboxSender,
    pub(super) event_tx: SessionEventBus,
    pub(super) retained_notification_events: Arc<StdMutex<VecDeque<RetainedRemoteSessionEvent>>>,
    pub(super) active_request_stream: Arc<Mutex<()>>,
    pub(super) worker_serving_closed: tokio::sync::watch::Sender<bool>,
    pub(super) notification_stream_attached: Arc<AtomicBool>,
    pub(super) next_event_id: Arc<AtomicU64>,
    pub(super) session_db_path: Option<PathBuf>,
    pub(super) approval_redemption: Option<remote_mcp_approvals::ApprovalRedemption>,
    pub(super) session_store_lease: Option<Arc<RemoteSessionStoreLifecycleLease>>,
    pub(super) resume_hmac_keyring: Option<Arc<RemoteSessionHmacKeyring>>,
    pub(super) resume_generation: AtomicU64,
    pub(super) terminalization: Mutex<()>,
    pub(super) upstream_transport: RemoteSessionUpstreamTransport,
}

pub(super) struct RemoteSessionUpstreamTransport {
    pub(super) inner: Arc<dyn McpTransport>,
}

impl std::fmt::Debug for RemoteSessionUpstreamTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteSessionUpstreamTransport")
            .finish_non_exhaustive()
    }
}

pub(super) struct RemoteSessionInit {
    pub(super) clock: RemoteClock,
    pub(super) session_id: String,
    pub(super) agent_id: String,
    pub(super) capabilities: Vec<RemoteSessionCapability>,
    pub(super) issued_capabilities: Vec<CapabilityToken>,
    pub(super) auth_context: SessionAuthContext,
    pub(super) auth_mode_fingerprint: String,
    pub(super) policy_fingerprint: String,
    pub(super) runtime_contract_fingerprint: String,
    pub(super) hosted_isolation: RemoteHostedIsolationMode,
    pub(super) lifecycle_policy: SessionLifecyclePolicy,
    pub(super) protocol_version: Option<String>,
    pub(super) peer_capabilities: Option<PeerCapabilities>,
    pub(super) initialize_params: Option<Value>,
    pub(super) lifecycle_snapshot: Option<RemoteSessionLifecycleSnapshot>,
    pub(super) input_tx: McpInboxSender,
    pub(super) event_tx: SessionEventBus,
    pub(super) retained_notification_events: Arc<StdMutex<VecDeque<RetainedRemoteSessionEvent>>>,
    pub(super) next_event_id: Arc<AtomicU64>,
    pub(super) session_db_path: Option<PathBuf>,
    pub(super) approval_redemption: Option<remote_mcp_approvals::ApprovalRedemption>,
    pub(super) session_store_lease: Option<Arc<RemoteSessionStoreLifecycleLease>>,
    pub(super) resume_hmac_keyring: Option<Arc<RemoteSessionHmacKeyring>>,
    pub(super) resume_generation: u64,
    pub(super) upstream_transport: Arc<dyn McpTransport>,
}

pub(super) struct NotificationStreamAttachment {
    pub(super) session: Arc<RemoteSession>,
}

impl Drop for NotificationStreamAttachment {
    fn drop(&mut self) {
        self.session.detach_notification_stream();
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone)]
pub(super) enum RemoteAuthMode {
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
pub(super) enum JwtSignatureAlgorithm {
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
pub(super) enum JwtVerificationKeySource {
    Static(PublicKey),
    Jwks(JwtJwksKeySet),
}

#[derive(Clone)]
pub(super) struct JwtBearerVerifier {
    pub(super) clock: RemoteClock,
    pub(super) key_source: JwtVerificationKeySource,
    pub(super) issuer: Option<String>,
    pub(super) audience: Option<String>,
    pub(super) required_scopes: Vec<String>,
    pub(super) provider_profile: JwtProviderProfile,
    pub(super) enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
    pub(super) sender_dpop_nonce_store: Arc<DpopNonceStore>,
    pub(super) sender_dpop_config: DpopConfig,
}

#[derive(Clone)]
pub(super) struct IntrospectionBearerVerifier {
    pub(super) clock: RemoteClock,
    pub(super) client: HttpClient,
    pub(super) introspection_url: Url,
    pub(super) client_id: Option<String>,
    pub(super) client_secret: Option<String>,
    pub(super) issuer: Option<String>,
    pub(super) audience: Option<String>,
    pub(super) required_scopes: Vec<String>,
    pub(super) provider_profile: JwtProviderProfile,
    pub(super) enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
    pub(super) sender_dpop_nonce_store: Arc<DpopNonceStore>,
    pub(super) sender_dpop_config: DpopConfig,
    /// Typed HTTP egress contract that gates every introspection-endpoint
    /// dispatch. Production deployments must populate this; without a
    /// contract the verifier substrate will fail closed if introspection is
    /// invoked.
    #[allow(dead_code)]
    pub(super) egress_contract: Option<HttpEgressContract>,
}

#[derive(Clone)]
pub(super) struct ProtectedResourceMetadata {
    pub(super) resource: String,
    pub(super) resource_metadata_url: String,
    pub(super) authorization_servers: Vec<String>,
    pub(super) scopes_supported: Vec<String>,
    pub(super) chio_authorization_profile: Value,
}

#[derive(Clone)]
pub(super) struct AuthorizationServerMetadata {
    pub(super) metadata_path: String,
    pub(super) document: Value,
}

#[derive(Clone)]
pub(super) struct LocalAuthorizationServer {
    pub(super) clock: RemoteClock,
    pub(super) signing_key: Keypair,
    pub(super) issuer: String,
    pub(super) default_audience: String,
    pub(super) supported_scopes: Vec<String>,
    pub(super) subject: String,
    pub(super) code_ttl_secs: u64,
    pub(super) access_token_ttl_secs: u64,
    pub(super) codes: Arc<StdMutex<HashMap<String, AuthorizationCodeGrant>>>,
    pub(super) sender_dpop_nonce_store: Arc<DpopNonceStore>,
    pub(super) sender_dpop_config: DpopConfig,
}

impl RemoteAppState {
    // Retained for enterprise-provider validation paths shared with the local
    // trust-control surface even though the current remote flow does not call it.
    #[allow(dead_code)]
    pub(super) fn enterprise_provider_registry(&self) -> Option<&EnterpriseProviderRegistry> {
        self.enterprise_provider_registry.as_deref()
    }

    // Retained for enterprise-provider validation paths shared with the local
    // trust-control surface even though the current remote flow does not call it.
    #[allow(dead_code)]
    pub(super) fn validated_enterprise_provider(
        &self,
        provider_id: &str,
    ) -> Option<&EnterpriseProviderRecord> {
        self.enterprise_provider_registry()
            .and_then(|registry| registry.validated_provider(provider_id))
    }
}

#[derive(Clone, Debug)]
pub(super) struct AuthorizationCodeGrant {
    pub(super) deadline: AuthorityDeadline,
    pub(super) client_id: String,
    pub(super) redirect_uri: String,
    pub(super) resource: String,
    pub(super) scopes: Vec<String>,
    pub(super) subject: String,
    pub(super) code_challenge: String,
    pub(super) code_challenge_method: String,
    pub(super) expires_at: u64,
    pub(super) authorization_details: Option<Vec<GovernedAuthorizationDetail>>,
    pub(super) transaction_context: Option<GovernedAuthorizationTransactionContext>,
    pub(super) sender_constraint: Option<ChioSenderConstraintClaims>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    rename_all = "camelCase",
    try_from = "sender_constraint::ConfirmationWire"
)]
pub(super) struct ChioSenderConstraintClaims {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "chioSenderKey"
    )]
    pub(super) chio_sender_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "x5t#S256")]
    pub(super) mtls_thumbprint_sha256: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "chioAttestationSha256"
    )]
    pub(super) chio_attestation_sha256: Option<String>,
}

impl ChioSenderConstraintClaims {
    pub(super) fn is_empty(&self) -> bool {
        self.chio_sender_key.is_none()
            && self.mtls_thumbprint_sha256.is_none()
            && self.chio_attestation_sha256.is_none()
    }
}

#[derive(Clone, Debug)]
pub(super) struct JwtJwksKeySet {
    pub(super) keys_by_kid: HashMap<String, JwtResolvedJwkPublicKey>,
    pub(super) anonymous_keys: Vec<JwtResolvedJwkPublicKey>,
}

#[derive(Clone, Debug)]
pub(super) struct DiscoveredIdentityProvider {
    pub(super) issuer: String,
    pub(super) authorization_endpoint: Option<String>,
    pub(super) token_endpoint: Option<String>,
    pub(super) registration_endpoint: Option<String>,
    pub(super) jwks_uri: Option<String>,
    pub(super) jwks_keys: Option<JwtJwksKeySet>,
}

#[derive(Debug, Deserialize)]
pub(super) struct JwtHeader {
    pub(super) alg: String,
    #[serde(default)]
    pub(super) kid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct JwtClaims {
    #[serde(default)]
    pub(super) iss: Option<String>,
    #[serde(default)]
    pub(super) sub: Option<String>,
    #[serde(default)]
    pub(super) aud: Option<JwtAudience>,
    #[serde(default)]
    pub(super) scope: Option<String>,
    #[serde(default)]
    pub(super) scp: Vec<String>,
    #[serde(default)]
    pub(super) client_id: Option<String>,
    #[serde(default)]
    pub(super) jti: Option<String>,
    #[serde(default)]
    pub(super) oid: Option<String>,
    #[serde(default)]
    pub(super) azp: Option<String>,
    #[serde(default)]
    pub(super) appid: Option<String>,
    #[serde(default)]
    pub(super) tid: Option<String>,
    #[serde(default)]
    pub(super) tenant_id: Option<String>,
    #[serde(default)]
    pub(super) org_id: Option<String>,
    #[serde(default)]
    pub(super) organization_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_vec")]
    pub(super) groups: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_vec")]
    pub(super) roles: Vec<String>,
    #[serde(default)]
    pub(super) resource: Option<String>,
    #[serde(default)]
    pub(super) authorization_details: Option<Value>,
    #[serde(default)]
    pub(super) chio_transaction_context: Option<Value>,
    #[serde(
        default,
        deserialize_with = "sender_constraint::deserialize_confirmation"
    )]
    pub(super) cnf: Option<ChioSenderConstraintClaims>,
    #[serde(default)]
    pub(super) exp: Option<u64>,
    #[serde(default)]
    pub(super) nbf: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum JwtAudience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Deserialize)]
pub(super) struct OidcDiscoveryDocument {
    pub(super) issuer: String,
    #[serde(default)]
    pub(super) authorization_endpoint: Option<String>,
    #[serde(default)]
    pub(super) token_endpoint: Option<String>,
    #[serde(default)]
    pub(super) registration_endpoint: Option<String>,
    #[serde(default)]
    pub(super) jwks_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct OAuthIntrospectionResponse {
    pub(super) active: bool,
    #[serde(default)]
    pub(super) token_type: Option<String>,
    #[serde(flatten)]
    pub(super) claims: JwtClaims,
}

#[derive(Debug, Deserialize)]
pub(super) struct JwksDocument {
    #[serde(default)]
    pub(super) keys: Vec<JwkDocumentKey>,
}

#[derive(Debug, Deserialize)]
pub(super) struct JwkDocumentKey {
    pub(super) kty: String,
    #[serde(default)]
    pub(super) crv: Option<String>,
    #[serde(default)]
    pub(super) alg: Option<String>,
    #[serde(default, rename = "use")]
    pub(super) key_use: Option<String>,
    #[serde(default)]
    pub(super) kid: Option<String>,
    #[serde(default)]
    pub(super) x: Option<String>,
    #[serde(default)]
    pub(super) y: Option<String>,
    #[serde(default)]
    pub(super) n: Option<String>,
    #[serde(default)]
    pub(super) e: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) struct JwtResolvedJwkPublicKey {
    pub(super) key: JwtResolvedPublicKey,
    pub(super) alg_hint: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) enum JwtResolvedPublicKey {
    Ed25519(PublicKey),
    Rsa(JwtRsaPublicKey),
    P256(P256VerifyingKey),
    P384(P384VerifyingKey),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct RemoteSessionCapability {
    pub(super) id: String,
    pub(super) issuer_public_key: String,
    pub(super) subject_public_key: String,
}

#[path = "session_core/authority_mode.rs"]
pub(super) mod session_core_authority_mode;
#[path = "session_core/events.rs"]
pub(super) mod session_core_events;
pub(super) use session_core_events::{RequestEvents, RequestEventsError, SessionEventBus};
#[path = "session_core/factory.rs"]
pub(super) mod session_core_factory;
#[path = "session_core/ledger.rs"]
pub(super) mod session_core_ledger;
#[path = "session_core/session.rs"]
pub(super) mod session_core_session;

#[path = "session_core/writer.rs"]
pub(super) mod session_core_writer;
pub(super) use session_core_writer::BroadcastJsonRpcWriter;

impl RemoteServeHttpConfig {
    pub(super) fn lifecycle_policy(&self) -> SessionLifecyclePolicy {
        #[cfg(test)]
        if let Some(policy) = &self.test_lifecycle_policy {
            return policy.clone();
        }
        SessionLifecyclePolicy::from_env()
    }
}
