#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::convert::Infallible;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex as StdMutex, Weak};
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
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use pact_core::capability::CapabilityToken;
use pact_core::crypto::{sha256_hex, Keypair, PublicKey, Signature as Ed25519Signature};
use pact_core::session::{
    EnterpriseFederationMethod, EnterpriseIdentityContext, OAuthBearerFederatedClaims,
    RequestOwnershipSnapshot, SessionAuthContext, SessionAuthMethod,
};
use pact_kernel::{KernelError, RevocationStore, ToolServerConnection};
use pact_mcp_adapter::{
    AdaptedMcpServer, AdapterError, McpAdapter, McpAdapterConfig, McpEdgeConfig, McpTransport,
    PactMcpEdge, SerializedMcpTransport, StdioMcpTransport,
};
use reqwest::Client as HttpClient;
use rsa::pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey as RsaPkcs1v15VerifyingKey};
use rsa::pss::{Signature as RsaPssSignature, VerifyingKey as RsaPssVerifyingKey};
use rsa::signature::Verifier as _;
use rsa::{BigUint, RsaPublicKey as JwtRsaPublicKey};
use rusqlite::{params, Connection};
use serde::de::{DeserializeOwned, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};
use url::Url;

use crate::policy::load_policy;
use crate::trust_control::{self, ChildReceiptQuery, RevocationQuery, ToolReceiptQuery};
use crate::JwtProviderProfile;
use crate::{
    authority_public_key_from_seed_file, build_kernel, configure_budget_store,
    configure_capability_authority, configure_receipt_store, configure_revocation_store,
    enterprise_federation::{
        EnterpriseProviderKind, EnterpriseProviderRecord, EnterpriseProviderRegistry,
    },
    issue_default_capabilities, load_or_create_authority_keypair, rotate_authority_keypair,
    CliError,
};

const MCP_ENDPOINT_PATH: &str = "/mcp";
const ADMIN_HEALTH_PATH: &str = "/admin/health";
const ADMIN_AUTHORITY_PATH: &str = "/admin/authority";
const ADMIN_TOOL_RECEIPTS_PATH: &str = "/admin/receipts/tools";
const ADMIN_CHILD_RECEIPTS_PATH: &str = "/admin/receipts/children";
const ADMIN_REVOCATIONS_PATH: &str = "/admin/revocations";
const ADMIN_BUDGETS_PATH: &str = "/admin/budgets";
const ADMIN_SESSIONS_PATH: &str = "/admin/sessions";
const AUTHORIZATION_SERVER_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
const LOCAL_AUTHORIZATION_PATH: &str = "/oauth/authorize";
const LOCAL_TOKEN_PATH: &str = "/oauth/token";
const LOCAL_JWKS_PATH: &str = "/oauth/jwks.json";
const ADMIN_SESSION_TRUST_PATH: &str = "/admin/sessions/{session_id}/trust";
const ADMIN_SESSION_DRAIN_PATH: &str = "/admin/sessions/{session_id}/drain";
const ADMIN_SESSION_SHUTDOWN_PATH: &str = "/admin/sessions/{session_id}/shutdown";
const PROTECTED_RESOURCE_METADATA_ROOT_PATH: &str = "/.well-known/oauth-protected-resource";
const PROTECTED_RESOURCE_METADATA_MCP_PATH: &str = "/.well-known/oauth-protected-resource/mcp";
const MCP_SESSION_ID_HEADER: &str = "mcp-session-id";
const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
const DEFAULT_STREAM_RETRY_MILLIS: u64 = 1_000;
const DEFAULT_NOTIFICATION_STREAM_IDLE_MILLIS: u64 = 100;
const DEFAULT_NOTIFICATION_REPLAY_WINDOW: usize = 64;
const DEFAULT_SHARED_NOTIFICATION_POLL_MILLIS: u64 = 25;
const DEFAULT_ADMIN_LIST_LIMIT: usize = 50;
const MAX_ADMIN_LIST_LIMIT: usize = 200;
const DEFAULT_SESSION_IDLE_EXPIRY_MILLIS: u64 = 15 * 60 * 1000;
const DEFAULT_SESSION_DRAIN_GRACE_MILLIS: u64 = 5 * 1000;
const DEFAULT_SESSION_REAPER_INTERVAL_MILLIS: u64 = 250;
const DEFAULT_SESSION_TOMBSTONE_RETENTION_MILLIS: u64 = 30 * 60 * 1000;
const IDENTITY_PROVIDER_FETCH_TIMEOUT_SECS: u64 = 5;
const TOKEN_INTROSPECTION_TIMEOUT_SECS: u64 = 5;
const IDENTITY_FEDERATION_DERIVATION_LABEL: &[u8] = b"pact.identity_federation.v1";
const SESSION_IDLE_EXPIRY_ENV: &str = "PACT_MCP_SESSION_IDLE_EXPIRY_MILLIS";
const SESSION_DRAIN_GRACE_ENV: &str = "PACT_MCP_SESSION_DRAIN_GRACE_MILLIS";
const SESSION_REAPER_INTERVAL_ENV: &str = "PACT_MCP_SESSION_REAPER_INTERVAL_MILLIS";
const SESSION_TOMBSTONE_RETENTION_ENV: &str = "PACT_MCP_SESSION_TOMBSTONE_RETENTION_MILLIS";

type NotificationTapQueue = Arc<StdMutex<VecDeque<Value>>>;
type NotificationTapWeak = Weak<StdMutex<VecDeque<Value>>>;
type NotificationSubscriberList = Arc<StdMutex<Vec<NotificationTapWeak>>>;

#[derive(Clone)]
pub struct RemoteServeHttpConfig {
    pub listen: SocketAddr,
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
    pub control_url: Option<String>,
    pub control_token: Option<String>,
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
    pub policy_path: PathBuf,
    pub server_id: String,
    pub server_name: String,
    pub server_version: String,
    pub manifest_public_key: Option<String>,
    pub page_size: usize,
    pub tools_list_changed: bool,
    pub shared_hosted_owner: bool,
    pub wrapped_command: String,
    pub wrapped_args: Vec<String>,
}

#[derive(Clone)]
struct RemoteAppState {
    sessions: Arc<RemoteSessionLedger>,
    factory: Arc<RemoteSessionFactory>,
    auth_mode: Arc<RemoteAuthMode>,
    enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
    admin_token: Option<Arc<str>>,
    protected_resource_metadata: Option<Arc<ProtectedResourceMetadata>>,
    authorization_server_metadata: Option<Arc<AuthorizationServerMetadata>>,
    local_auth_server: Option<Arc<LocalAuthorizationServer>>,
}

struct RemoteSessionFactory {
    config: RemoteServeHttpConfig,
    shared_upstream_owner: Arc<StdMutex<Option<Arc<SharedUpstreamOwner>>>>,
    lifecycle_policy: SessionLifecyclePolicy,
}

#[derive(Clone, Debug)]
struct SessionLifecyclePolicy {
    idle_expiry_millis: u64,
    drain_grace_millis: u64,
    reaper_interval_millis: u64,
    tombstone_retention_millis: u64,
}

impl SessionLifecyclePolicy {
    fn from_env() -> Self {
        read_session_lifecycle_policy()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RemoteSessionDiagnosticRecord {
    session_id: String,
    auth_context: SessionAuthContext,
    capabilities: Vec<RemoteSessionCapability>,
    lifecycle: RemoteSessionLifecycleSnapshot,
    protocol_version: Option<String>,
    #[serde(default)]
    ownership: RemoteSessionOwnershipSnapshot,
    terminal_at: u64,
}

#[derive(Clone, Debug)]
enum RemoteSessionEntry {
    Active(Arc<RemoteSession>),
    Terminal(Arc<RemoteSessionDiagnosticRecord>),
}

#[derive(Clone)]
struct RemoteSessionLedger {
    active: Arc<Mutex<HashMap<String, Arc<RemoteSession>>>>,
    terminal: Arc<Mutex<HashMap<String, Arc<RemoteSessionDiagnosticRecord>>>>,
    lifecycle_policy: SessionLifecyclePolicy,
    tombstone_db_path: Option<PathBuf>,
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
}

struct SharedUpstreamNotificationTap {
    queue: NotificationTapQueue,
}

#[derive(Clone, Debug)]
struct RemoteSessionEvent {
    seq: u64,
    event_id: String,
    kind: RemoteSessionEventKind,
    message: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemoteSessionEventKind {
    Notification,
    RequestCorrelated,
}

#[derive(Clone, Debug)]
struct RetainedRemoteSessionEvent {
    seq: u64,
    event_id: String,
    message: Value,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RemoteSessionLifecycleSnapshot {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteSessionOwnershipSnapshot {
    request_ownership: RequestOwnershipSnapshot,
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
    session_id: String,
    capabilities: Vec<RemoteSessionCapability>,
    auth_context: SessionAuthContext,
    lifecycle_policy: SessionLifecyclePolicy,
    protocol_version: StdMutex<Option<String>>,
    lifecycle: StdMutex<RemoteSessionLifecycleSnapshot>,
    input_tx: mpsc::Sender<Value>,
    event_tx: broadcast::Sender<RemoteSessionEvent>,
    retained_notification_events: Arc<StdMutex<VecDeque<RetainedRemoteSessionEvent>>>,
    active_request_stream: Arc<Mutex<()>>,
    notification_stream_attached: Arc<AtomicBool>,
    next_event_id: Arc<AtomicU64>,
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
#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
struct JwtBearerVerifier {
    key_source: JwtVerificationKeySource,
    issuer: Option<String>,
    audience: Option<String>,
    required_scopes: Vec<String>,
    provider_profile: JwtProviderProfile,
    enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
}

#[derive(Clone, Debug)]
struct IntrospectionBearerVerifier {
    client: HttpClient,
    introspection_url: Url,
    client_id: Option<String>,
    client_secret: Option<String>,
    issuer: Option<String>,
    audience: Option<String>,
    required_scopes: Vec<String>,
    provider_profile: JwtProviderProfile,
    enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
}

#[derive(Clone)]
struct ProtectedResourceMetadata {
    resource: String,
    resource_metadata_url: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
}

#[derive(Clone)]
struct AuthorizationServerMetadata {
    metadata_path: String,
    document: Value,
}

#[derive(Clone)]
struct LocalAuthorizationServer {
    signing_key: Keypair,
    issuer: String,
    default_audience: String,
    supported_scopes: Vec<String>,
    subject: String,
    code_ttl_secs: u64,
    access_token_ttl_secs: u64,
    codes: Arc<StdMutex<HashMap<String, AuthorizationCodeGrant>>>,
}

impl RemoteAppState {
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
}

#[derive(Clone, Debug)]
struct AuthorizationCodeGrant {
    client_id: String,
    redirect_uri: String,
    resource: String,
    scopes: Vec<String>,
    subject: String,
    code_challenge: String,
    code_challenge_method: String,
    expires_at: u64,
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

fn canonicalize_federated_issuer(issuer: &str) -> String {
    let trimmed = issuer.trim();
    match Url::parse(trimmed) {
        Ok(url) => url.to_string().trim_end_matches('/').to_string(),
        Err(_) => trimmed.trim_end_matches('/').to_string(),
    }
}

impl JwtSignatureAlgorithm {
    fn from_header(
        header: &JwtHeader,
        protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    ) -> Result<Self, Response> {
        match header.alg.as_str() {
            "EdDSA" => Ok(Self::EdDsa),
            "RS256" => Ok(Self::Rs256),
            "RS384" => Ok(Self::Rs384),
            "RS512" => Ok(Self::Rs512),
            "PS256" => Ok(Self::Ps256),
            "PS384" => Ok(Self::Ps384),
            "PS512" => Ok(Self::Ps512),
            "ES256" => Ok(Self::Es256),
            "ES384" => Ok(Self::Es384),
            _ => Err(unauthorized_bearer_response(
                "JWT bearer token uses unsupported alg",
                protected_resource_metadata,
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
        }
    }
}

fn verify_ed25519_jwt_signature(
    public_key: &PublicKey,
    signed_input: &[u8],
    signature_bytes: &[u8],
) -> bool {
    if signature_bytes.len() != 64 {
        return false;
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(signature_bytes);
    public_key.verify(signed_input, &Ed25519Signature::from_bytes(&signature))
}

fn validate_identity_provider_url(url: &Url, field_name: &str) -> Result<(), CliError> {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or_default();
    let localhost = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if scheme == "https" || (scheme == "http" && localhost) {
        Ok(())
    } else {
        Err(CliError::Other(format!(
            "{field_name} must use https, or localhost http during local testing: {url}"
        )))
    }
}

fn parse_identity_provider_url(value: &str, field_name: &str) -> Result<Url, CliError> {
    let url = Url::parse(value)
        .map_err(|error| CliError::Other(format!("{field_name} is not a valid URL: {error}")))?;
    validate_identity_provider_url(&url, field_name)?;
    Ok(url)
}

fn derive_oidc_discovery_url_from_issuer(issuer: &str) -> Result<Url, CliError> {
    let issuer = parse_identity_provider_url(issuer, "--auth-jwt-issuer")?;
    let mut path = issuer.path().trim_end_matches('/').to_string();
    path.push_str("/.well-known/openid-configuration");
    let mut discovery = issuer;
    discovery.set_path(&path);
    discovery.set_query(None);
    discovery.set_fragment(None);
    Ok(discovery)
}

fn fetch_identity_provider_json<T: DeserializeOwned>(
    url: &Url,
    field_name: &str,
) -> Result<T, CliError> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(IDENTITY_PROVIDER_FETCH_TIMEOUT_SECS))
        .build();
    let response = agent.get(url.as_str()).call().map_err(|error| {
        CliError::Other(format!("failed to fetch {field_name} `{}`: {error}", url))
    })?;
    response.into_json::<T>().map_err(|error| {
        CliError::Other(format!(
            "failed to parse JSON from {field_name} `{}`: {error}",
            url
        ))
    })
}

fn resolve_identity_provider_discovery_url(
    config: &RemoteServeHttpConfig,
) -> Result<Option<Url>, CliError> {
    if let Some(discovery_url) = config.auth_jwt_discovery_url.as_deref() {
        return parse_identity_provider_url(discovery_url, "--auth-jwt-discovery-url").map(Some);
    }
    if config.auth_jwt_provider_profile.is_some() {
        let issuer = config.auth_jwt_issuer.as_deref().ok_or_else(|| {
            CliError::Other(
                "--auth-jwt-provider-profile requires --auth-jwt-issuer or --auth-jwt-discovery-url"
                    .to_string(),
            )
        })?;
        return derive_oidc_discovery_url_from_issuer(issuer).map(Some);
    }
    Ok(None)
}

fn resolve_jwks_key_set(jwks_uri: &Url, field_name: &str) -> Result<JwtJwksKeySet, CliError> {
    let document: JwksDocument = fetch_identity_provider_json(jwks_uri, field_name)?;
    let mut keys_by_kid = HashMap::new();
    let mut anonymous_keys = Vec::new();
    for key in document.keys {
        let kid = key.kid.clone();
        let alg_hint = key.alg.clone();
        if let Some(key_use) = key.key_use.as_deref() {
            if key_use != "sig" {
                continue;
            }
        }
        let Some(resolved_key) =
            resolve_jwk_public_key(key, jwks_uri, field_name, alg_hint.clone())?
        else {
            continue;
        };
        if let Some(kid) = kid {
            keys_by_kid.insert(kid, resolved_key);
        } else {
            anonymous_keys.push(resolved_key);
        }
    }
    if keys_by_kid.is_empty() && anonymous_keys.is_empty() {
        return Err(CliError::Other(format!(
            "{field_name} `{}` did not expose any supported signing keys",
            jwks_uri
        )));
    }
    Ok(JwtJwksKeySet {
        keys_by_kid,
        anonymous_keys,
    })
}

fn decode_jwk_component(
    value: &str,
    component_name: &str,
    jwks_uri: &Url,
    field_name: &str,
) -> Result<Vec<u8>, CliError> {
    URL_SAFE_NO_PAD.decode(value).map_err(|error| {
        CliError::Other(format!(
            "failed to decode {component_name} from {field_name} `{}`: {error}",
            jwks_uri
        ))
    })
}

fn decode_fixed_jwk_component<const N: usize>(
    value: &str,
    component_name: &str,
    jwks_uri: &Url,
    field_name: &str,
) -> Result<[u8; N], CliError> {
    let bytes = decode_jwk_component(value, component_name, jwks_uri, field_name)?;
    if bytes.len() != N {
        return Err(CliError::Other(format!(
            "{component_name} from {field_name} `{}` had invalid length {}, expected {}",
            jwks_uri,
            bytes.len(),
            N
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn resolve_jwk_public_key(
    key: JwkDocumentKey,
    jwks_uri: &Url,
    field_name: &str,
    alg_hint: Option<String>,
) -> Result<Option<JwtResolvedJwkPublicKey>, CliError> {
    let resolved = match key.kty.as_str() {
        "OKP" if key.crv.as_deref() == Some("Ed25519") => {
            let Some(x) = key.x.as_deref() else {
                return Ok(None);
            };
            let x = decode_fixed_jwk_component::<32>(x, "x", jwks_uri, field_name)?;
            JwtResolvedPublicKey::Ed25519(PublicKey::from_bytes(&x)?)
        }
        "EC" if key.crv.as_deref() == Some("P-256") => {
            let (Some(x), Some(y)) = (key.x.as_deref(), key.y.as_deref()) else {
                return Ok(None);
            };
            let x = decode_fixed_jwk_component::<32>(x, "x", jwks_uri, field_name)?;
            let y = decode_fixed_jwk_component::<32>(y, "y", jwks_uri, field_name)?;
            let mut encoded = [0u8; 65];
            encoded[0] = 0x04;
            encoded[1..33].copy_from_slice(&x);
            encoded[33..65].copy_from_slice(&y);
            JwtResolvedPublicKey::P256(P256VerifyingKey::from_sec1_bytes(&encoded).map_err(
                |error| {
                    CliError::Other(format!(
                        "failed to parse P-256 JWK from {field_name} `{}`: {error}",
                        jwks_uri
                    ))
                },
            )?)
        }
        "EC" if key.crv.as_deref() == Some("P-384") => {
            let (Some(x), Some(y)) = (key.x.as_deref(), key.y.as_deref()) else {
                return Ok(None);
            };
            let x = decode_fixed_jwk_component::<48>(x, "x", jwks_uri, field_name)?;
            let y = decode_fixed_jwk_component::<48>(y, "y", jwks_uri, field_name)?;
            let mut encoded = [0u8; 97];
            encoded[0] = 0x04;
            encoded[1..49].copy_from_slice(&x);
            encoded[49..97].copy_from_slice(&y);
            JwtResolvedPublicKey::P384(P384VerifyingKey::from_sec1_bytes(&encoded).map_err(
                |error| {
                    CliError::Other(format!(
                        "failed to parse P-384 JWK from {field_name} `{}`: {error}",
                        jwks_uri
                    ))
                },
            )?)
        }
        "RSA" => {
            let (Some(n), Some(e)) = (key.n.as_deref(), key.e.as_deref()) else {
                return Ok(None);
            };
            let modulus =
                BigUint::from_bytes_be(&decode_jwk_component(n, "n", jwks_uri, field_name)?);
            let exponent =
                BigUint::from_bytes_be(&decode_jwk_component(e, "e", jwks_uri, field_name)?);
            JwtResolvedPublicKey::Rsa(JwtRsaPublicKey::new(modulus, exponent).map_err(|error| {
                CliError::Other(format!(
                    "failed to parse RSA JWK from {field_name} `{}`: {error}",
                    jwks_uri
                ))
            })?)
        }
        _ => return Ok(None),
    };
    Ok(Some(JwtResolvedJwkPublicKey {
        key: resolved,
        alg_hint,
    }))
}

fn resolve_discovered_identity_provider(
    config: &RemoteServeHttpConfig,
) -> Result<Option<DiscoveredIdentityProvider>, CliError> {
    let Some(discovery_url) = resolve_identity_provider_discovery_url(config)? else {
        return Ok(None);
    };
    let document: OidcDiscoveryDocument =
        fetch_identity_provider_json(&discovery_url, "--auth-jwt-discovery-url")?;
    let issuer_url = parse_identity_provider_url(&document.issuer, "discovered OIDC issuer")?;
    let issuer = canonicalize_federated_issuer(issuer_url.as_str());
    if let Some(expected_issuer) = config.auth_jwt_issuer.as_deref() {
        if canonicalize_federated_issuer(expected_issuer) != issuer {
            return Err(CliError::Other(format!(
                "OIDC discovery issuer `{issuer}` did not match configured --auth-jwt-issuer `{expected_issuer}`"
            )));
        }
    }

    let authorization_endpoint = document.authorization_endpoint;
    let token_endpoint = document.token_endpoint;
    let registration_endpoint = document.registration_endpoint;
    let jwks_uri = match document.jwks_uri {
        Some(uri) => Some(parse_identity_provider_url(
            &uri,
            "discovered OIDC jwks_uri",
        )?),
        None => None,
    };
    let jwks_keys = if config.auth_jwt_public_key.is_none()
        && config.auth_server_seed_path.is_none()
        && config.auth_introspection_url.is_none()
    {
        let jwks_uri = jwks_uri.as_ref().ok_or_else(|| {
            CliError::Other(
                "OIDC discovery metadata did not include `jwks_uri` for JWT verification"
                    .to_string(),
            )
        })?;
        Some(resolve_jwks_key_set(jwks_uri, "discovered OIDC jwks_uri")?)
    } else {
        None
    };

    Ok(Some(DiscoveredIdentityProvider {
        issuer,
        authorization_endpoint,
        token_endpoint,
        registration_endpoint,
        jwks_uri: jwks_uri.map(|url| url.to_string()),
        jwks_keys,
    }))
}

fn build_federated_principal(
    claims: &JwtClaims,
    expected_issuer: Option<&str>,
    protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    provider_profile: JwtProviderProfile,
) -> Result<String, Response> {
    let issuer = claims
        .iss
        .as_deref()
        .or(expected_issuer)
        .map(canonicalize_federated_issuer)
        .ok_or_else(|| {
            unauthorized_bearer_response(
                "JWT bearer token missing issuer for identity federation",
                protected_resource_metadata,
            )
        })?;

    match provider_profile {
        JwtProviderProfile::AzureAd => {
            if let Some(object_id) = claims.oid.as_deref() {
                return Ok(format!("oidc:{issuer}#oid:{object_id}"));
            }
            if let Some(subject) = claims.sub.as_deref() {
                return Ok(format!("oidc:{issuer}#sub:{subject}"));
            }
            if let Some(client_id) = claims
                .azp
                .as_deref()
                .or(claims.appid.as_deref())
                .or(claims.client_id.as_deref())
            {
                return Ok(format!("oidc:{issuer}#client:{client_id}"));
            }
            Err(unauthorized_bearer_response(
                "JWT bearer token missing oid, subject, and client claims for Azure AD identity federation",
                protected_resource_metadata,
            ))
        }
        JwtProviderProfile::Generic | JwtProviderProfile::Auth0 | JwtProviderProfile::Okta => {
            if let Some(subject) = claims.sub.as_deref() {
                return Ok(format!("oidc:{issuer}#sub:{subject}"));
            }
            if let Some(client_id) = claims.client_id.as_deref() {
                return Ok(format!("oidc:{issuer}#client:{client_id}"));
            }
            Err(unauthorized_bearer_response(
                "JWT bearer token missing subject and client_id for identity federation",
                protected_resource_metadata,
            ))
        }
    }
}

fn build_federated_claims(
    claims: &JwtClaims,
    _provider_profile: JwtProviderProfile,
) -> OAuthBearerFederatedClaims {
    OAuthBearerFederatedClaims {
        client_id: claims
            .client_id
            .clone()
            .or_else(|| claims.azp.clone())
            .or_else(|| claims.appid.clone()),
        object_id: claims.oid.clone(),
        tenant_id: claims.tid.clone().or_else(|| claims.tenant_id.clone()),
        organization_id: claims
            .org_id
            .clone()
            .or_else(|| claims.organization_id.clone()),
        groups: normalize_claim_list(&claims.groups),
        roles: normalize_claim_list(&claims.roles),
    }
}

fn matched_bearer_enterprise_provider<'a>(
    registry: Option<&'a EnterpriseProviderRegistry>,
    issuer: Option<&str>,
    kind: EnterpriseProviderKind,
) -> Option<&'a EnterpriseProviderRecord> {
    let issuer = issuer.map(canonicalize_federated_issuer)?;
    registry?.providers.values().find(|record| {
        record.kind == kind
            && record.is_validated_enabled()
            && record
                .issuer
                .as_deref()
                .map(canonicalize_federated_issuer)
                .as_deref()
                == Some(issuer.as_str())
    })
}

fn derive_enterprise_subject_key(provider_scope: &str, canonical_principal: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_FEDERATION_DERIVATION_LABEL);
    hasher.update([1u8]);
    hasher.update(provider_scope.as_bytes());
    hasher.update([0u8]);
    hasher.update(canonical_principal.as_bytes());
    let digest = hasher.finalize();
    sha256_hex(digest.as_slice())
}

fn build_enterprise_identity_context(
    claims: &JwtClaims,
    federated_claims: &OAuthBearerFederatedClaims,
    principal: &str,
    provider_profile: JwtProviderProfile,
    provider_kind: EnterpriseProviderKind,
    matched_provider: Option<&EnterpriseProviderRecord>,
) -> EnterpriseIdentityContext {
    let issuer = claims
        .iss
        .as_deref()
        .map(canonicalize_federated_issuer)
        .unwrap_or_default();
    let provider_id = matched_provider
        .map(|provider| provider.provider_id.clone())
        .unwrap_or_else(|| issuer.clone());
    let mut attribute_sources = BTreeMap::new();

    if let Some(source) = matched_provider
        .map(|provider| provider.subject_mapping.principal_source.trim())
        .filter(|source| !source.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| bearer_principal_source_field(claims, provider_profile).map(ToOwned::to_owned))
    {
        attribute_sources.insert("principal".to_string(), source);
    }
    if let Some(source) = matched_provider
        .and_then(|provider| provider.subject_mapping.client_id_field.clone())
        .or_else(|| bearer_client_id_source_field(claims).map(ToOwned::to_owned))
    {
        attribute_sources.insert("clientId".to_string(), source);
    }
    if let Some(source) = matched_provider
        .and_then(|provider| provider.subject_mapping.object_id_field.clone())
        .or_else(|| claims.oid.as_ref().map(|_| "oid".to_string()))
    {
        attribute_sources.insert("objectId".to_string(), source);
    }
    if let Some(source) = matched_provider
        .and_then(|provider| provider.subject_mapping.tenant_id_field.clone())
        .or_else(|| bearer_tenant_source_field(claims).map(ToOwned::to_owned))
    {
        attribute_sources.insert("tenantId".to_string(), source);
    }
    if let Some(source) = matched_provider
        .and_then(|provider| provider.subject_mapping.organization_id_field.clone())
        .or_else(|| bearer_organization_source_field(claims).map(ToOwned::to_owned))
    {
        attribute_sources.insert("organizationId".to_string(), source);
    }
    if !federated_claims.groups.is_empty() {
        let source = matched_provider
            .and_then(|provider| provider.subject_mapping.groups_field.clone())
            .unwrap_or_else(|| "groups".to_string());
        attribute_sources.insert("groups".to_string(), source);
    }
    if !federated_claims.roles.is_empty() {
        let source = matched_provider
            .and_then(|provider| provider.subject_mapping.roles_field.clone())
            .unwrap_or_else(|| "roles".to_string());
        attribute_sources.insert("roles".to_string(), source);
    }

    EnterpriseIdentityContext {
        provider_id: provider_id.clone(),
        provider_record_id: matched_provider.map(|provider| provider.provider_id.clone()),
        provider_kind: enterprise_provider_kind_name(&provider_kind).to_string(),
        federation_method: enterprise_federation_method(&provider_kind),
        principal: principal.to_string(),
        subject_key: derive_enterprise_subject_key(&provider_id, principal),
        client_id: federated_claims.client_id.clone(),
        object_id: federated_claims.object_id.clone(),
        tenant_id: federated_claims.tenant_id.clone(),
        organization_id: federated_claims.organization_id.clone(),
        groups: federated_claims.groups.clone(),
        roles: federated_claims.roles.clone(),
        source_subject: claims.sub.clone(),
        attribute_sources,
        trust_material_ref: matched_provider
            .and_then(|provider| provider.provenance.trust_material_ref.clone()),
    }
}

fn enterprise_provider_kind_name(kind: &EnterpriseProviderKind) -> &'static str {
    match kind {
        EnterpriseProviderKind::OidcJwks => "oidc_jwks",
        EnterpriseProviderKind::OauthIntrospection => "oauth_introspection",
        EnterpriseProviderKind::Scim => "scim",
        EnterpriseProviderKind::Saml => "saml",
    }
}

fn enterprise_federation_method(kind: &EnterpriseProviderKind) -> EnterpriseFederationMethod {
    match kind {
        EnterpriseProviderKind::OidcJwks => EnterpriseFederationMethod::Jwt,
        EnterpriseProviderKind::OauthIntrospection => EnterpriseFederationMethod::Introspection,
        EnterpriseProviderKind::Scim => EnterpriseFederationMethod::Scim,
        EnterpriseProviderKind::Saml => EnterpriseFederationMethod::Saml,
    }
}

fn bearer_principal_source_field(
    claims: &JwtClaims,
    provider_profile: JwtProviderProfile,
) -> Option<&'static str> {
    match provider_profile {
        JwtProviderProfile::AzureAd => {
            if claims.oid.is_some() {
                Some("oid")
            } else if claims.sub.is_some() {
                Some("sub")
            } else if claims.azp.is_some() {
                Some("azp")
            } else if claims.appid.is_some() {
                Some("appid")
            } else if claims.client_id.is_some() {
                Some("client_id")
            } else {
                None
            }
        }
        JwtProviderProfile::Generic | JwtProviderProfile::Auth0 | JwtProviderProfile::Okta => {
            if claims.sub.is_some() {
                Some("sub")
            } else if claims.client_id.is_some() {
                Some("client_id")
            } else {
                None
            }
        }
    }
}

fn bearer_client_id_source_field(claims: &JwtClaims) -> Option<&'static str> {
    if claims.client_id.is_some() {
        Some("client_id")
    } else if claims.azp.is_some() {
        Some("azp")
    } else if claims.appid.is_some() {
        Some("appid")
    } else {
        None
    }
}

fn bearer_tenant_source_field(claims: &JwtClaims) -> Option<&'static str> {
    if claims.tid.is_some() {
        Some("tid")
    } else if claims.tenant_id.is_some() {
        Some("tenant_id")
    } else {
        None
    }
}

fn bearer_organization_source_field(claims: &JwtClaims) -> Option<&'static str> {
    if claims.org_id.is_some() {
        Some("org_id")
    } else if claims.organization_id.is_some() {
        Some("organization_id")
    } else {
        None
    }
}

fn normalize_claim_list(values: &[String]) -> Vec<String> {
    let mut normalized = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn deserialize_string_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringVecOrString {
        String(String),
        Strings(Vec<String>),
    }

    let raw = Option::<StringVecOrString>::deserialize(deserializer)?;
    Ok(match raw {
        None => Vec::new(),
        Some(StringVecOrString::String(value)) => vec![value],
        Some(StringVecOrString::Strings(values)) => values,
    })
}

fn derive_federated_agent_keypair(
    seed_path: &FsPath,
    federated_principal: &str,
) -> Result<Keypair, CliError> {
    let master_key = load_or_create_authority_keypair(seed_path)?;
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_FEDERATION_DERIVATION_LABEL);
    hasher.update([0u8]);
    hasher.update(master_key.seed_bytes());
    hasher.update([0u8]);
    hasher.update(federated_principal.as_bytes());
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    Ok(Keypair::from_seed(&seed))
}

fn derive_session_agent_keypair(
    config: &RemoteServeHttpConfig,
    auth_context: &SessionAuthContext,
) -> Result<Keypair, CliError> {
    let Some(seed_path) = config.identity_federation_seed_path.as_deref() else {
        return Ok(Keypair::generate());
    };
    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            principal: Some(principal),
            ..
        } => derive_federated_agent_keypair(seed_path, principal),
        _ => Ok(Keypair::generate()),
    }
}

impl SharedUpstreamToolServer {
    fn new(upstream: Arc<AdaptedMcpServer>) -> Self {
        let manifest = upstream.manifest_clone();
        Self {
            server_id: manifest.server_id,
            tool_names: manifest
                .tools
                .into_iter()
                .map(|tool| tool.name)
                .collect::<Vec<_>>(),
            upstream,
        }
    }
}

impl ToolServerConnection for SharedUpstreamToolServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tool_names.clone()
    }

    fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        nested_flow_bridge: Option<&mut dyn pact_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        ToolServerConnection::invoke(
            self.upstream.as_ref(),
            tool_name,
            arguments,
            nested_flow_bridge,
        )
    }
}

impl SharedUpstreamOwner {
    fn new(config: &RemoteServeHttpConfig) -> Result<Self, CliError> {
        let wrapped_arg_refs = config
            .wrapped_args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let manifest_public_key = config
            .manifest_public_key
            .clone()
            .unwrap_or_else(|| Keypair::generate().public_key().to_hex());
        let notification_source: Arc<dyn McpTransport> = Arc::new(StdioMcpTransport::spawn(
            &config.wrapped_command,
            &wrapped_arg_refs,
        )?);
        let adapter = McpAdapter::new(
            McpAdapterConfig {
                server_id: config.server_id.clone(),
                server_name: config.server_name.clone(),
                server_version: config.server_version.clone(),
                public_key: manifest_public_key,
            },
            Box::new(SerializedMcpTransport::from_arc(
                notification_source.clone(),
            )),
        );
        let upstream_server = Arc::new(AdaptedMcpServer::new(adapter)?);
        let notification_subscribers =
            Arc::new(StdMutex::new(Vec::<Weak<StdMutex<VecDeque<Value>>>>::new()));
        let notification_source_for_thread = notification_source.clone();
        let notification_subscribers_for_thread = notification_subscribers.clone();
        thread::spawn(move || loop {
            let notifications = notification_source_for_thread.drain_notifications();
            fan_out_shared_upstream_notifications(
                &notification_subscribers_for_thread,
                notifications,
            );
            thread::sleep(Duration::from_millis(
                DEFAULT_SHARED_NOTIFICATION_POLL_MILLIS,
            ));
        });

        Ok(Self {
            upstream_server,
            notification_subscribers,
        })
    }

    fn upstream_server(&self) -> Arc<AdaptedMcpServer> {
        self.upstream_server.clone()
    }

    fn notification_tap(&self) -> Arc<dyn McpTransport> {
        let queue = Arc::new(StdMutex::new(VecDeque::new()));
        if let Ok(mut subscribers) = self.notification_subscribers.lock() {
            subscribers.push(Arc::downgrade(&queue));
        }
        Arc::new(SharedUpstreamNotificationTap { queue })
    }
}

impl McpTransport for SharedUpstreamNotificationTap {
    fn list_tools(&self) -> Result<Vec<pact_mcp_adapter::McpToolInfo>, AdapterError> {
        Err(AdapterError::ConnectionFailed(
            "shared upstream notification tap does not support direct tool calls".to_string(),
        ))
    }

    fn call_tool(
        &self,
        _tool_name: &str,
        _arguments: Value,
    ) -> Result<pact_mcp_adapter::McpToolResult, AdapterError> {
        Err(AdapterError::ConnectionFailed(
            "shared upstream notification tap does not support direct tool calls".to_string(),
        ))
    }

    fn drain_notifications(&self) -> Vec<Value> {
        let Ok(mut queue) = self.queue.lock() else {
            return vec![];
        };
        queue.drain(..).collect()
    }
}

fn fan_out_shared_upstream_notifications(
    subscribers: &NotificationSubscriberList,
    notifications: Vec<Value>,
) {
    if notifications.is_empty() {
        return;
    }
    let Ok(mut subscribers) = subscribers.lock() else {
        return;
    };
    subscribers.retain(|subscriber| subscriber.strong_count() > 0);
    for notification in notifications {
        for subscriber in subscribers.iter() {
            if let Some(queue) = subscriber.upgrade() {
                if let Ok(mut queue) = queue.lock() {
                    queue.push_back(notification.clone());
                }
            }
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct AdminToolReceiptQuery {
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    tool_server: Option<String>,
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminChildReceiptQuery {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    parent_request_id: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    operation_kind: Option<String>,
    #[serde(default)]
    terminal_state: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminRevocationQuery {
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminBudgetQuery {
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AdminRevokeCapabilityRequest {
    capability_id: String,
}

#[derive(Debug, Deserialize)]
struct AuthorizationRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizationApprovalForm {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    decision: String,
}

#[derive(Debug, Deserialize)]
struct TokenRequestForm {
    grant_type: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    subject_token: Option<String>,
    #[serde(default)]
    subject_token_type: Option<String>,
}

impl RemoteSession {
    #[allow(clippy::too_many_arguments)]
    fn new(
        session_id: String,
        capabilities: Vec<RemoteSessionCapability>,
        auth_context: SessionAuthContext,
        lifecycle_policy: SessionLifecyclePolicy,
        input_tx: mpsc::Sender<Value>,
        event_tx: broadcast::Sender<RemoteSessionEvent>,
        retained_notification_events: Arc<StdMutex<VecDeque<RetainedRemoteSessionEvent>>>,
        next_event_id: Arc<AtomicU64>,
    ) -> Self {
        let now = session_now_millis();
        Self {
            session_id,
            capabilities,
            auth_context,
            lifecycle_policy,
            protocol_version: StdMutex::new(None),
            lifecycle: StdMutex::new(RemoteSessionLifecycleSnapshot {
                state: RemoteSessionState::Initializing,
                created_at: now,
                last_seen_at: now,
                idle_expires_at: now,
                drain_deadline_at: None,
            }),
            input_tx,
            event_tx,
            retained_notification_events,
            active_request_stream: Arc::new(Mutex::new(())),
            notification_stream_attached: Arc::new(AtomicBool::new(false)),
            next_event_id,
        }
    }

    fn send(&self, message: Value) -> Result<(), CliError> {
        self.input_tx
            .send(message)
            .map_err(|_| CliError::Other("remote MCP session worker is unavailable".to_string()))
    }

    fn subscribe(&self) -> broadcast::Receiver<RemoteSessionEvent> {
        self.event_tx.subscribe()
    }

    fn next_stream_event_id(&self) -> String {
        let next = self.next_event_id.fetch_add(1, Ordering::SeqCst) + 1;
        format!("{}-{next}", self.session_id)
    }

    fn has_active_notification_stream(&self) -> bool {
        self.notification_stream_attached.load(Ordering::SeqCst)
    }

    fn has_active_request_stream(&self) -> bool {
        self.active_request_stream.try_lock().is_err()
    }

    fn try_attach_notification_stream(&self) -> bool {
        self.notification_stream_attached
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    fn detach_notification_stream(&self) {
        self.notification_stream_attached
            .store(false, Ordering::SeqCst);
    }

    fn replay_notifications_after(
        &self,
        last_event_id: Option<&str>,
    ) -> Result<(u64, Vec<RemoteSessionEvent>), Response> {
        let Some(last_event_id) = last_event_id else {
            return Ok((0, Vec::new()));
        };

        let replay_after = parse_session_event_id(last_event_id, &self.session_id)
            .map_err(|message| plain_http_error(StatusCode::CONFLICT, &message))?;
        let retained = self.retained_notification_events.lock().map_err(|_| {
            plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to inspect retained session notifications",
            )
        })?;

        if retained.is_empty() {
            return Err(plain_http_error(
                StatusCode::CONFLICT,
                "notification replay cursor is no longer provable for this session",
            ));
        }

        let oldest = retained.front().map(|event| event.seq).unwrap_or_default();
        let newest = retained.back().map(|event| event.seq).unwrap_or_default();
        if replay_after < oldest.saturating_sub(1) || replay_after > newest {
            return Err(plain_http_error(
                StatusCode::CONFLICT,
                "notification replay cursor is outside the retained session window",
            ));
        }

        let replay = retained
            .iter()
            .filter(|event| event.seq > replay_after)
            .map(|event| RemoteSessionEvent {
                seq: event.seq,
                event_id: event.event_id.clone(),
                kind: RemoteSessionEventKind::Notification,
                message: event.message.clone(),
            })
            .collect();
        Ok((replay_after, replay))
    }

    fn protocol_version(&self) -> Option<String> {
        self.protocol_version
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    fn set_protocol_version(&self, protocol_version: Option<String>) {
        if let Ok(mut guard) = self.protocol_version.lock() {
            *guard = protocol_version;
        }
    }

    fn lifecycle_snapshot(&self) -> RemoteSessionLifecycleSnapshot {
        self.lifecycle
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or(RemoteSessionLifecycleSnapshot {
                state: RemoteSessionState::Closed,
                created_at: 0,
                last_seen_at: 0,
                idle_expires_at: 0,
                drain_deadline_at: None,
            })
    }

    fn mark_ready(&self, protocol_version: Option<String>) {
        self.set_protocol_version(protocol_version);
        if let Ok(mut guard) = self.lifecycle.lock() {
            guard.state = RemoteSessionState::Ready;
            guard.last_seen_at = session_now_millis();
            guard.idle_expires_at = guard
                .last_seen_at
                .saturating_add(self.lifecycle_policy.idle_expiry_millis);
            guard.drain_deadline_at = None;
        }
    }

    fn touch(&self) {
        if let Ok(mut guard) = self.lifecycle.lock() {
            if guard.state == RemoteSessionState::Ready {
                guard.last_seen_at = session_now_millis();
                guard.idle_expires_at = guard
                    .last_seen_at
                    .saturating_add(self.lifecycle_policy.idle_expiry_millis);
            }
        }
    }

    fn begin_draining(&self) {
        if let Ok(mut guard) = self.lifecycle.lock() {
            guard.state = RemoteSessionState::Draining;
            guard.last_seen_at = session_now_millis();
            guard.drain_deadline_at = Some(
                guard
                    .last_seen_at
                    .saturating_add(self.lifecycle_policy.drain_grace_millis),
            );
        }
    }

    fn mark_deleted(&self) {
        if let Ok(mut guard) = self.lifecycle.lock() {
            guard.state = RemoteSessionState::Deleted;
            guard.last_seen_at = session_now_millis();
            guard.drain_deadline_at = None;
        }
    }

    fn mark_expired(&self) {
        if let Ok(mut guard) = self.lifecycle.lock() {
            guard.state = RemoteSessionState::Expired;
            guard.last_seen_at = session_now_millis();
            guard.drain_deadline_at = None;
        }
    }

    fn mark_closed(&self) {
        if let Ok(mut guard) = self.lifecycle.lock() {
            guard.state = RemoteSessionState::Closed;
            guard.last_seen_at = session_now_millis();
            guard.drain_deadline_at = None;
        }
    }

    fn auth_context(&self) -> &SessionAuthContext {
        &self.auth_context
    }

    fn diagnostic_record(&self) -> RemoteSessionDiagnosticRecord {
        RemoteSessionDiagnosticRecord {
            session_id: self.session_id.clone(),
            auth_context: self.auth_context.clone(),
            capabilities: self.capabilities.clone(),
            lifecycle: self.lifecycle_snapshot(),
            protocol_version: self.protocol_version(),
            ownership: self.ownership_snapshot(),
            terminal_at: session_now_millis(),
        }
    }

    fn ownership_snapshot(&self) -> RemoteSessionOwnershipSnapshot {
        let notification_stream_attached = self.has_active_notification_stream();
        RemoteSessionOwnershipSnapshot {
            notification_delivery: if notification_stream_attached {
                RemoteNotificationDelivery::GetSse
            } else {
                RemoteNotificationDelivery::PostResponseFallback
            },
            request_stream_active: self.has_active_request_stream(),
            notification_stream_attached,
            ..RemoteSessionOwnershipSnapshot::default()
        }
    }
}

struct BroadcastJsonRpcWriter {
    event_tx: broadcast::Sender<RemoteSessionEvent>,
    retained_notification_events: Arc<StdMutex<VecDeque<RetainedRemoteSessionEvent>>>,
    next_event_id: Arc<AtomicU64>,
    session_id: String,
    buffer: Vec<u8>,
}

impl BroadcastJsonRpcWriter {
    fn new(
        event_tx: broadcast::Sender<RemoteSessionEvent>,
        retained_notification_events: Arc<StdMutex<VecDeque<RetainedRemoteSessionEvent>>>,
        next_event_id: Arc<AtomicU64>,
        session_id: String,
    ) -> Self {
        Self {
            event_tx,
            retained_notification_events,
            next_event_id,
            session_id,
            buffer: Vec::new(),
        }
    }

    fn next_event(&self, message: Value) -> RemoteSessionEvent {
        let next = self.next_event_id.fetch_add(1, Ordering::SeqCst) + 1;
        let event_id = format!("{}-{next}", self.session_id);
        let kind = classify_remote_session_event(&message);
        if kind == RemoteSessionEventKind::Notification {
            if let Ok(mut retained) = self.retained_notification_events.lock() {
                retained.push_back(RetainedRemoteSessionEvent {
                    seq: next,
                    event_id: event_id.clone(),
                    message: message.clone(),
                });
                while retained.len() > DEFAULT_NOTIFICATION_REPLAY_WINDOW {
                    retained.pop_front();
                }
            }
        }

        RemoteSessionEvent {
            seq: next,
            event_id,
            kind,
            message,
        }
    }

    fn flush_complete_lines(&mut self) -> io::Result<()> {
        while let Some(position) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let mut line = self.buffer.drain(..=position).collect::<Vec<_>>();
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.is_empty() {
                continue;
            }

            let message: Value = serde_json::from_slice(&line).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse JSON-RPC output from edge worker: {error}"),
                )
            })?;
            let _ = self.event_tx.send(self.next_event(message));
        }

        Ok(())
    }
}

impl Write for BroadcastJsonRpcWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        self.flush_complete_lines()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_complete_lines()
    }
}

impl RemoteSessionFactory {
    fn new(config: RemoteServeHttpConfig) -> Self {
        Self {
            config,
            shared_upstream_owner: Arc::new(StdMutex::new(None)),
            lifecycle_policy: read_session_lifecycle_policy(),
        }
    }

    fn build_session_upstream_server(&self) -> Result<Arc<AdaptedMcpServer>, CliError> {
        let wrapped_arg_refs = self
            .config
            .wrapped_args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let manifest_public_key = self
            .config
            .manifest_public_key
            .clone()
            .unwrap_or_else(|| Keypair::generate().public_key().to_hex());
        let adapted_server = AdaptedMcpServer::from_command(
            &self.config.wrapped_command,
            &wrapped_arg_refs,
            McpAdapterConfig {
                server_id: self.config.server_id.clone(),
                server_name: self.config.server_name.clone(),
                server_version: self.config.server_version.clone(),
                public_key: manifest_public_key,
            },
        )?;

        Ok(Arc::new(adapted_server))
    }

    fn shared_upstream_owner(&self) -> Result<Arc<SharedUpstreamOwner>, CliError> {
        let mut guard = self.shared_upstream_owner.lock().map_err(|error| {
            CliError::Other(format!(
                "failed to lock shared remote MCP upstream owner cache: {error}"
            ))
        })?;
        if let Some(owner) = guard.as_ref() {
            return Ok(owner.clone());
        }

        let owner = Arc::new(SharedUpstreamOwner::new(&self.config)?);
        info!(
            server_id = %self.config.server_id,
            "created shared remote MCP hosted owner"
        );
        *guard = Some(owner.clone());
        Ok(owner)
    }

    fn spawn_session(
        &self,
        auth_context: SessionAuthContext,
    ) -> Result<Arc<RemoteSession>, CliError> {
        let loaded_policy = load_policy(&self.config.policy_path)?;
        let default_capabilities = loaded_policy.default_capabilities.clone();
        let issuance_policy = loaded_policy.issuance_policy.clone();
        let (upstream_server, upstream_notification_source) = if self.config.shared_hosted_owner {
            let owner = self.shared_upstream_owner()?;
            (owner.upstream_server(), owner.notification_tap())
        } else {
            let upstream_server = self.build_session_upstream_server()?;
            let notification_source = upstream_server.notification_source();
            (upstream_server, notification_source)
        };
        let upstream_capabilities = upstream_server.upstream_capabilities();
        let manifest = upstream_server.manifest_clone();

        let kernel_kp = Keypair::generate();
        let mut kernel = build_kernel(loaded_policy, &kernel_kp);
        configure_receipt_store(
            &mut kernel,
            self.config.receipt_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
        )?;
        configure_revocation_store(
            &mut kernel,
            self.config.revocation_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
        )?;
        configure_capability_authority(
            &mut kernel,
            &kernel_kp,
            self.config.authority_seed_path.as_deref(),
            self.config.authority_db_path.as_deref(),
            self.config.receipt_db_path.as_deref(),
            self.config.budget_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
            issuance_policy,
        )?;
        configure_budget_store(
            &mut kernel,
            self.config.budget_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
        )?;
        if let Some(resource_provider) = upstream_server.resource_provider() {
            kernel.register_resource_provider(Box::new(resource_provider));
        }
        if let Some(prompt_provider) = upstream_server.prompt_provider() {
            kernel.register_prompt_provider(Box::new(prompt_provider));
        }
        kernel.register_tool_server(Box::new(SharedUpstreamToolServer::new(
            upstream_server.clone(),
        )));

        let agent_kp = derive_session_agent_keypair(&self.config, &auth_context)?;
        let agent_pk = agent_kp.public_key();
        let agent_id = agent_pk.to_hex();
        let capabilities: Vec<CapabilityToken> =
            issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;
        let session_capabilities = capabilities
            .iter()
            .map(|capability| RemoteSessionCapability {
                id: capability.id.clone(),
                issuer_public_key: capability.issuer.to_hex(),
                subject_public_key: capability.subject.to_hex(),
            })
            .collect();

        let mut edge = PactMcpEdge::new(
            McpEdgeConfig {
                server_name: "PACT MCP Edge".to_string(),
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                page_size: self.config.page_size,
                tools_list_changed: self.config.tools_list_changed
                    || upstream_capabilities.tools_list_changed,
                completion_enabled: Some(upstream_capabilities.completions_supported),
                resources_subscribe: upstream_capabilities.resources_subscribe,
                resources_list_changed: upstream_capabilities.resources_list_changed,
                prompts_list_changed: upstream_capabilities.prompts_list_changed,
                logging_enabled: true,
            },
            kernel,
            agent_id,
            capabilities,
            vec![manifest],
        )?;
        edge.set_session_auth_context(auth_context.clone());
        edge.attach_upstream_transport(upstream_notification_source);

        let (input_tx, input_rx) = mpsc::channel::<Value>();
        let (event_tx, _) = broadcast::channel::<RemoteSessionEvent>(256);
        let session_id = Keypair::generate().public_key().to_hex();
        let retained_notification_events =
            Arc::new(StdMutex::new(VecDeque::<RetainedRemoteSessionEvent>::new()));
        let next_event_id = Arc::new(AtomicU64::new(0));
        let writer = BroadcastJsonRpcWriter::new(
            event_tx.clone(),
            retained_notification_events.clone(),
            next_event_id.clone(),
            session_id.clone(),
        );

        std::thread::spawn(move || {
            if let Err(error) = edge.serve_message_channels(input_rx, writer) {
                error!(error = %error, "remote MCP edge session worker exited with error");
            }
        });

        Ok(Arc::new(RemoteSession::new(
            session_id,
            session_capabilities,
            auth_context,
            self.lifecycle_policy.clone(),
            input_tx,
            event_tx,
            retained_notification_events,
            next_event_id,
        )))
    }
}

impl RemoteSessionLedger {
    fn new(
        lifecycle_policy: SessionLifecyclePolicy,
        tombstone_db_path: Option<PathBuf>,
    ) -> Result<Self, CliError> {
        let terminal = if let Some(path) = tombstone_db_path.as_deref() {
            load_terminal_session_records(path)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            active: Arc::new(Mutex::new(HashMap::new())),
            terminal: Arc::new(Mutex::new(terminal)),
            lifecycle_policy,
            tombstone_db_path,
        })
    }

    async fn insert_active(&self, session: Arc<RemoteSession>) {
        self.active
            .lock()
            .await
            .insert(session.session_id.clone(), session);
    }

    async fn remove_active(&self, session_id: &str) -> Option<Arc<RemoteSession>> {
        self.active.lock().await.remove(session_id)
    }

    async fn lookup(&self, session_id: &str) -> Option<RemoteSessionEntry> {
        if let Some(session) = self.active.lock().await.get(session_id).cloned() {
            return Some(RemoteSessionEntry::Active(session));
        }

        self.terminal
            .lock()
            .await
            .get(session_id)
            .cloned()
            .map(RemoteSessionEntry::Terminal)
    }

    async fn snapshot(
        &self,
    ) -> (
        Vec<RemoteSessionDiagnosticRecord>,
        Vec<RemoteSessionDiagnosticRecord>,
    ) {
        let active = self
            .active
            .lock()
            .await
            .values()
            .map(|session| session.diagnostic_record())
            .collect::<Vec<_>>();
        let terminal = self
            .terminal
            .lock()
            .await
            .values()
            .map(|record| (*record.as_ref()).clone())
            .collect::<Vec<_>>();
        (active, terminal)
    }

    async fn mark_deleted(&self, session: &Arc<RemoteSession>) {
        session.mark_deleted();
        self.transition_to_terminal(session, RemoteSessionState::Deleted)
            .await;
    }

    async fn mark_draining(&self, session: &Arc<RemoteSession>) {
        session.begin_draining();
    }

    async fn mark_closed(&self, session: &Arc<RemoteSession>) {
        session.mark_closed();
        self.transition_to_terminal(session, RemoteSessionState::Closed)
            .await;
    }

    async fn mark_expired(&self, session: &Arc<RemoteSession>) {
        session.mark_expired();
        self.transition_to_terminal(session, RemoteSessionState::Expired)
            .await;
    }

    async fn cleanup_due_sessions(&self) {
        let now = session_now_millis();
        let sessions = {
            let guard = self.active.lock().await;
            guard.values().cloned().collect::<Vec<_>>()
        };

        for session in sessions {
            let snapshot = session.lifecycle_snapshot();
            match snapshot.state {
                RemoteSessionState::Ready if snapshot.idle_expires_at <= now => {
                    self.mark_expired(&session).await;
                    self.active.lock().await.remove(&session.session_id);
                }
                RemoteSessionState::Ready => {}
                RemoteSessionState::Draining => {
                    if snapshot
                        .drain_deadline_at
                        .is_some_and(|deadline| deadline <= now)
                    {
                        self.mark_deleted(&session).await;
                        self.active.lock().await.remove(&session.session_id);
                    }
                }
                RemoteSessionState::Initializing
                | RemoteSessionState::Deleted
                | RemoteSessionState::Expired => {}
                RemoteSessionState::Closed => {
                    self.mark_closed(&session).await;
                    self.active.lock().await.remove(&session.session_id);
                }
            }
        }

        self.purge_old_terminal_records(now).await;
    }

    async fn transition_to_terminal(
        &self,
        session: &Arc<RemoteSession>,
        state: RemoteSessionState,
    ) {
        let mut record = session.diagnostic_record();
        record.lifecycle.state = state;
        record.terminal_at = session_now_millis();
        self.terminal
            .lock()
            .await
            .insert(session.session_id.clone(), Arc::new(record.clone()));
        if let Some(path) = self.tombstone_db_path.as_deref() {
            if let Err(error) = persist_terminal_session_record(path, &record) {
                warn!(
                    session_id = %session.session_id,
                    error = %error,
                    "failed to persist terminal MCP session tombstone"
                );
            }
        }
    }

    async fn purge_old_terminal_records(&self, now: u64) {
        let retention = self.lifecycle_policy.tombstone_retention_millis;
        let cutoff = now.saturating_sub(retention);
        let mut terminal = self.terminal.lock().await;
        terminal.retain(|_, record| now.saturating_sub(record.terminal_at) <= retention);
        if let Some(path) = self.tombstone_db_path.as_deref() {
            if let Err(error) = purge_terminal_session_records_before(path, cutoff) {
                warn!(
                    cutoff,
                    error = %error,
                    "failed to purge expired MCP session tombstones"
                );
            }
        }
    }
}

const SESSION_TOMBSTONE_TABLE: &str = "remote_session_tombstones";

fn open_terminal_session_db(path: &FsPath) -> Result<Connection, CliError> {
    let conn = Connection::open(path)?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {table} (
            session_id TEXT PRIMARY KEY NOT NULL,
            terminal_at INTEGER NOT NULL,
            record_json TEXT NOT NULL
        );",
        table = SESSION_TOMBSTONE_TABLE,
    ))?;
    Ok(conn)
}

fn load_terminal_session_records(
    path: &FsPath,
) -> Result<HashMap<String, Arc<RemoteSessionDiagnosticRecord>>, CliError> {
    let conn = open_terminal_session_db(path)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT session_id, record_json FROM {table}",
        table = SESSION_TOMBSTONE_TABLE,
    ))?;
    let mut rows = stmt.query([])?;
    let mut records = HashMap::new();

    while let Some(row) = rows.next()? {
        let session_id: String = row.get(0)?;
        let record_json: String = row.get(1)?;
        let record: RemoteSessionDiagnosticRecord = serde_json::from_str(&record_json)?;
        records.insert(session_id, Arc::new(record));
    }

    Ok(records)
}

fn persist_terminal_session_record(
    path: &FsPath,
    record: &RemoteSessionDiagnosticRecord,
) -> Result<(), CliError> {
    let conn = open_terminal_session_db(path)?;
    let record_json = serde_json::to_string(record)?;
    conn.execute(
        &format!(
            "INSERT INTO {table} (session_id, terminal_at, record_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(session_id) DO UPDATE SET
                 terminal_at = excluded.terminal_at,
                 record_json = excluded.record_json",
            table = SESSION_TOMBSTONE_TABLE,
        ),
        params![
            record.session_id.as_str(),
            record.terminal_at as i64,
            record_json
        ],
    )?;
    Ok(())
}

fn purge_terminal_session_records_before(path: &FsPath, cutoff: u64) -> Result<(), CliError> {
    let conn = open_terminal_session_db(path)?;
    conn.execute(
        &format!(
            "DELETE FROM {table} WHERE terminal_at < ?1",
            table = SESSION_TOMBSTONE_TABLE,
        ),
        params![cutoff as i64],
    )?;
    Ok(())
}

pub fn serve_http(config: RemoteServeHttpConfig) -> Result<(), CliError> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| CliError::Other(format!("failed to start async runtime: {error}")))?;
    runtime.block_on(async move { serve_http_async(config).await })
}

fn load_enterprise_provider_registry(
    path: Option<&FsPath>,
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

async fn serve_http_async(config: RemoteServeHttpConfig) -> Result<(), CliError> {
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let enterprise_provider_registry = load_enterprise_provider_registry(
        config.enterprise_providers_file.as_deref(),
        "remote_mcp",
    )?;
    let discovered_identity_provider = resolve_discovered_identity_provider(&config)?;
    let (auth_mode, admin_token) = build_remote_auth_state(
        &config,
        local_addr,
        discovered_identity_provider.as_ref(),
        enterprise_provider_registry.clone(),
    )?;
    let protected_resource_metadata = build_protected_resource_metadata(
        &config,
        local_addr,
        discovered_identity_provider.as_ref(),
    )?;
    let authorization_server_metadata = build_authorization_server_metadata(
        &config,
        local_addr,
        discovered_identity_provider.as_ref(),
    )?;
    let local_auth_server = build_local_auth_server(&config, local_addr)?;

    let sessions = Arc::new(RemoteSessionLedger::new(
        SessionLifecyclePolicy::from_env(),
        config.session_db_path.clone(),
    )?);
    sessions.cleanup_due_sessions().await;

    let state = RemoteAppState {
        sessions,
        factory: Arc::new(RemoteSessionFactory::new(config.clone())),
        auth_mode: Arc::new(auth_mode),
        enterprise_provider_registry,
        admin_token,
        protected_resource_metadata: protected_resource_metadata.map(Arc::new),
        authorization_server_metadata: authorization_server_metadata.map(Arc::new),
        local_auth_server: local_auth_server.map(Arc::new),
    };

    let reaper_state = state.clone();
    tokio::spawn(async move {
        session_reaper_loop(reaper_state).await;
    });

    let router = Router::new()
        .route(
            MCP_ENDPOINT_PATH,
            post(handle_post).get(handle_get).delete(handle_delete),
        )
        .route(
            PROTECTED_RESOURCE_METADATA_ROOT_PATH,
            get(handle_protected_resource_metadata),
        )
        .route(
            PROTECTED_RESOURCE_METADATA_MCP_PATH,
            get(handle_protected_resource_metadata),
        )
        .route(
            AUTHORIZATION_SERVER_METADATA_PATH,
            get(handle_authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/{*rest}",
            get(handle_authorization_server_metadata),
        )
        .route(
            LOCAL_AUTHORIZATION_PATH,
            get(handle_authorization_endpoint).post(handle_authorization_approval),
        )
        .route(LOCAL_TOKEN_PATH, post(handle_token_endpoint))
        .route(LOCAL_JWKS_PATH, get(handle_local_jwks))
        .route(ADMIN_HEALTH_PATH, get(handle_admin_health))
        .route(
            ADMIN_AUTHORITY_PATH,
            get(handle_admin_authority).post(handle_admin_rotate_authority),
        )
        .route(ADMIN_TOOL_RECEIPTS_PATH, get(handle_admin_tool_receipts))
        .route(ADMIN_CHILD_RECEIPTS_PATH, get(handle_admin_child_receipts))
        .route(ADMIN_BUDGETS_PATH, get(handle_admin_budgets))
        .route(
            ADMIN_REVOCATIONS_PATH,
            get(handle_admin_revocations).post(handle_admin_revoke_capability),
        )
        .route(
            ADMIN_SESSION_TRUST_PATH,
            get(handle_admin_session_trust).post(handle_admin_revoke_session_trust),
        )
        .route(ADMIN_SESSIONS_PATH, get(handle_admin_sessions))
        .route(ADMIN_SESSION_DRAIN_PATH, post(handle_admin_session_drain))
        .route(
            ADMIN_SESSION_SHUTDOWN_PATH,
            post(handle_admin_session_shutdown),
        )
        .with_state(state);

    info!(
        listen_addr = %local_addr,
        endpoint = %MCP_ENDPOINT_PATH,
        "serving remote MCP edge"
    );
    eprintln!("remote MCP edge listening on http://{local_addr}{MCP_ENDPOINT_PATH}");

    axum::serve(listener, router)
        .await
        .map_err(|error| CliError::Other(format!("remote MCP edge server failed: {error}")))
}

async fn handle_post(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    let request_auth_context = match authenticate_session_request(
        request.headers(),
        &state.auth_mode,
        state.protected_resource_metadata.as_deref(),
    )
    .await
    {
        Ok(auth_context) => auth_context,
        Err(response) => return response,
    };
    if let Err(response) = validate_post_accept_header(request.headers()) {
        return response;
    }
    if let Err(response) = validate_content_type(request.headers()) {
        return response;
    }

    let headers = request.headers().clone();
    let body = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
        Ok(body) => body,
        Err(error) => {
            return jsonrpc_http_error(
                StatusCode::BAD_REQUEST,
                -32700,
                &format!("failed to read request body: {error}"),
            );
        }
    };
    let message: Value = match serde_json::from_slice(&body) {
        Ok(message) => message,
        Err(error) => {
            return jsonrpc_http_error(
                StatusCode::BAD_REQUEST,
                -32700,
                &format!("invalid JSON: {error}"),
            );
        }
    };

    let is_initialize = is_initialize_request(&message);
    let is_request = message.get("id").is_some() && message.get("method").is_some();
    if is_initialize {
        if !is_request {
            return jsonrpc_http_error(
                StatusCode::BAD_REQUEST,
                -32600,
                "initialize must be a JSON-RPC request with an id",
            );
        }
        return handle_initialize_post(state, request_auth_context, &headers, message).await;
    }

    let session = {
        let Some(session_id) = session_id_from_headers(&headers) else {
            return jsonrpc_http_error(
                StatusCode::BAD_REQUEST,
                -32600,
                "request requires MCP-Session-Id",
            );
        };
        let Some(entry) = resolve_session_entry(&state, &session_id).await else {
            return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
        };
        match entry {
            RemoteSessionEntry::Active(session) => {
                if let Err(response) = validate_protocol_version(&headers, &session) {
                    return response;
                }
                if let Err(response) =
                    validate_session_auth_context(&request_auth_context, session.auth_context())
                {
                    return response;
                }
                if let Err(response) = validate_session_lifecycle(&session) {
                    return response;
                }
                session.touch();
                session
            }
            RemoteSessionEntry::Terminal(record) => {
                if let Err(response) =
                    validate_session_auth_context(&request_auth_context, &record.auth_context)
                {
                    return response;
                }
                return terminal_session_response(record.lifecycle.state);
            }
        }
    };
    if !is_request {
        let mut event_rx = session.subscribe();
        let stream_lock = session.active_request_stream.clone().try_lock_owned().ok();
        if let Err(error) = session.send(message) {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
        let Some(stream_lock) = stream_lock else {
            return StatusCode::ACCEPTED.into_response();
        };

        let buffered_events = match collect_session_events_until_idle(&session, &mut event_rx).await
        {
            Ok(buffered_events) => buffered_events,
            Err(response) => return response,
        };
        let buffered_events = buffered_events
            .into_iter()
            .filter(|event| {
                should_emit_post_stream_event(event, None, session.has_active_notification_stream())
            })
            .collect::<Vec<_>>();
        if buffered_events.is_empty() {
            drop(stream_lock);
            return StatusCode::ACCEPTED.into_response();
        }

        return sse_response_from_buffered_events(session.clone(), buffered_events, stream_lock);
    }

    let request_id = message.get("id").cloned().unwrap_or(Value::Null);
    let mut event_rx = session.subscribe();
    let stream_lock = session.active_request_stream.clone().lock_owned().await;
    if let Err(error) = session.send(message) {
        drop(stream_lock);
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }

    let session_for_stream = session.clone();
    let stream = stream! {
        let _stream_lock = stream_lock;
        yield Ok::<Event, Infallible>(
            Event::default()
                .id(session_for_stream.next_stream_event_id())
                .retry(std::time::Duration::from_millis(DEFAULT_STREAM_RETRY_MILLIS))
                .data("")
        );

        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    if is_successful_initialize_response(&event.message, &request_id) {
                        session_for_stream.set_protocol_version(
                            event.message
                                .get("result")
                                .and_then(|result| result.get("protocolVersion"))
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned),
                        );
                    }

                    let should_emit = should_emit_post_stream_event(
                        &event,
                        Some(&request_id),
                        session_for_stream.has_active_notification_stream(),
                    );
                    if should_emit {
                        let data = serde_json::to_string(&event.message).unwrap_or_else(|_| "null".to_string());
                        yield Ok(Event::default().id(event.event_id).data(data));
                    }
                    if is_terminal_response_for_request(&event.message, &request_id) {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, session_id = %session_for_stream.session_id, "remote SSE consumer lagged behind session output");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    Sse::new(stream).into_response()
}

async fn handle_initialize_post(
    state: RemoteAppState,
    auth_context: SessionAuthContext,
    headers: &HeaderMap,
    message: Value,
) -> Response {
    if session_id_from_headers(headers).is_some() {
        return jsonrpc_http_error(
            StatusCode::BAD_REQUEST,
            -32600,
            "initialize request must not include MCP-Session-Id",
        );
    }

    let session = match state.factory.spawn_session(auth_context) {
        Ok(session) => session,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    };

    let request_id = message.get("id").cloned().unwrap_or(Value::Null);
    let mut event_rx = session.subscribe();
    if let Err(error) = session.send(message) {
        return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }

    let mut buffered_events = Vec::new();
    loop {
        match event_rx.recv().await {
            Ok(event) => {
                let is_terminal = is_terminal_response_for_request(&event.message, &request_id);
                let is_success = is_successful_initialize_response(&event.message, &request_id);
                if is_success {
                    session.mark_ready(
                        event
                            .message
                            .get("result")
                            .and_then(|result| result.get("protocolVersion"))
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                    );
                }
                buffered_events.push(event);

                if is_terminal {
                    if is_success {
                        state.sessions.insert_active(session.clone()).await;
                    }
                    return sse_response_from_events(
                        &session,
                        buffered_events,
                        is_success.then_some(session.session_id.as_str()),
                    );
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(
                    skipped,
                    session_id = %session.session_id,
                    "remote initialize SSE consumer lagged behind session output"
                );
            }
            Err(broadcast::error::RecvError::Closed) => {
                return plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "remote MCP session worker closed during initialize",
                );
            }
        }
    }
}

fn sse_response_from_events(
    session: &RemoteSession,
    buffered_events: Vec<RemoteSessionEvent>,
    session_header: Option<&str>,
) -> Response {
    let priming_event_id = session.next_stream_event_id();
    let stream = stream! {
        yield Ok::<Event, Infallible>(
            Event::default()
                .id(priming_event_id)
                .retry(std::time::Duration::from_millis(DEFAULT_STREAM_RETRY_MILLIS))
                .data("")
        );

        for event in buffered_events {
            let data = serde_json::to_string(&event.message).unwrap_or_else(|_| "null".to_string());
            yield Ok(Event::default().id(event.event_id).data(data));
        }
    };

    let mut response = Sse::new(stream).into_response();
    if let Some(session_id) = session_header {
        if let Ok(value) = HeaderValue::from_str(session_id) {
            response
                .headers_mut()
                .insert(HeaderName::from_static(MCP_SESSION_ID_HEADER), value);
        }
    }
    response
}

fn sse_response_from_buffered_events(
    session: Arc<RemoteSession>,
    buffered_events: Vec<RemoteSessionEvent>,
    stream_lock: tokio::sync::OwnedMutexGuard<()>,
) -> Response {
    let priming_event_id = session.next_stream_event_id();
    let stream = stream! {
        let _stream_lock = stream_lock;
        yield Ok::<Event, Infallible>(
            Event::default()
                .id(priming_event_id)
                .retry(std::time::Duration::from_millis(DEFAULT_STREAM_RETRY_MILLIS))
                .data("")
        );

        for event in buffered_events {
            let data = serde_json::to_string(&event.message).unwrap_or_else(|_| "null".to_string());
            yield Ok(Event::default().id(event.event_id).data(data));
        }
    };

    Sse::new(stream).into_response()
}

async fn collect_session_events_until_idle(
    session: &RemoteSession,
    event_rx: &mut broadcast::Receiver<RemoteSessionEvent>,
) -> Result<Vec<RemoteSessionEvent>, Response> {
    let mut buffered_events = Vec::new();

    loop {
        match tokio::time::timeout(
            std::time::Duration::from_millis(DEFAULT_NOTIFICATION_STREAM_IDLE_MILLIS),
            event_rx.recv(),
        )
        .await
        {
            Ok(Ok(event)) => buffered_events.push(event),
            Ok(Err(broadcast::error::RecvError::Lagged(skipped))) => {
                warn!(
                    skipped,
                    session_id = %session.session_id,
                    "remote notification SSE consumer lagged behind session output"
                );
            }
            Ok(Err(broadcast::error::RecvError::Closed)) => {
                if buffered_events.is_empty() {
                    return Err(plain_http_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "remote MCP session worker closed while processing notification",
                    ));
                }
                break;
            }
            Err(_) => break,
        }
    }

    Ok(buffered_events)
}

async fn handle_get(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    let request_auth_context = match authenticate_session_request(
        request.headers(),
        &state.auth_mode,
        state.protected_resource_metadata.as_deref(),
    )
    .await
    {
        Ok(auth_context) => auth_context,
        Err(response) => return response,
    };
    if let Err(response) = validate_get_accept_header(request.headers()) {
        return response;
    }

    let Some(session_id) = session_id_from_headers(request.headers()) else {
        return jsonrpc_http_error(
            StatusCode::BAD_REQUEST,
            -32600,
            "GET stream requires MCP-Session-Id",
        );
    };
    let session = {
        let Some(entry) = resolve_session_entry(&state, &session_id).await else {
            return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
        };
        match entry {
            RemoteSessionEntry::Active(session) => {
                if let Err(response) = validate_protocol_version(request.headers(), &session) {
                    return response;
                }
                if let Err(response) =
                    validate_session_auth_context(&request_auth_context, session.auth_context())
                {
                    return response;
                }
                if let Err(response) = validate_session_lifecycle(&session) {
                    return response;
                }
                session.touch();
                session
            }
            RemoteSessionEntry::Terminal(record) => {
                if let Err(response) =
                    validate_session_auth_context(&request_auth_context, &record.auth_context)
                {
                    return response;
                }
                return terminal_session_response(record.lifecycle.state);
            }
        }
    };

    let Some(last_event_id) = request
        .headers()
        .get(HeaderName::from_static("last-event-id"))
        .and_then(|value| value.to_str().ok())
    else {
        if !session.try_attach_notification_stream() {
            return plain_http_error(
                StatusCode::CONFLICT,
                "an MCP GET notification stream is already active for this session",
            );
        }
        let mut event_rx = session.subscribe();
        let session_for_stream = session.clone();
        let stream = stream! {
            let _attachment = NotificationStreamAttachment {
                session: session_for_stream.clone(),
            };
            loop {
                match event_rx.recv().await {
                    Ok(event) => {
                        if event.kind != RemoteSessionEventKind::Notification {
                            continue;
                        }
                        let data = serde_json::to_string(&event.message).unwrap_or_else(|_| "null".to_string());
                        yield Ok::<Event, Infallible>(Event::default().id(event.event_id).data(data));
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(skipped, session_id = %session_for_stream.session_id, "remote GET notification consumer lagged behind session output");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        };

        return Sse::new(stream).into_response();
    };

    let (mut delivered_through, replay_events) =
        match session.replay_notifications_after(Some(last_event_id)) {
            Ok(result) => result,
            Err(response) => return response,
        };
    if !session.try_attach_notification_stream() {
        return plain_http_error(
            StatusCode::CONFLICT,
            "an MCP GET notification stream is already active for this session",
        );
    }
    let mut event_rx = session.subscribe();
    let session_for_stream = session.clone();
    let stream = stream! {
        let _attachment = NotificationStreamAttachment {
            session: session_for_stream.clone(),
        };
        for event in replay_events {
            delivered_through = delivered_through.max(event.seq);
            let data = serde_json::to_string(&event.message).unwrap_or_else(|_| "null".to_string());
            yield Ok::<Event, Infallible>(Event::default().id(event.event_id).data(data));
        }
        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    if event.kind != RemoteSessionEventKind::Notification || event.seq <= delivered_through {
                        continue;
                    }
                    delivered_through = event.seq;
                    let data = serde_json::to_string(&event.message).unwrap_or_else(|_| "null".to_string());
                    yield Ok::<Event, Infallible>(Event::default().id(event.event_id).data(data));
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, session_id = %session_for_stream.session_id, "remote GET notification consumer lagged behind session output");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream).into_response()
}

async fn handle_protected_resource_metadata(State(state): State<RemoteAppState>) -> Response {
    let Some(metadata) = state.protected_resource_metadata.as_deref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "protected resource metadata is not configured for this edge",
        );
    };

    Json(json!({
        "resource": metadata.resource,
        "authorization_servers": metadata.authorization_servers,
        "scopes_supported": metadata.scopes_supported,
        "bearer_methods_supported": ["header"],
    }))
    .into_response()
}

async fn handle_authorization_server_metadata(
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    let Some(metadata) = state.authorization_server_metadata.as_deref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "authorization server metadata is not configured for this edge",
        );
    };
    if request.uri().path() != metadata.metadata_path {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "authorization server metadata path does not match the configured issuer",
        );
    }

    Json(metadata.document.clone()).into_response()
}

async fn handle_authorization_endpoint(
    State(state): State<RemoteAppState>,
    Query(request): Query<AuthorizationRequest>,
) -> Response {
    let Some(auth_server) = state.local_auth_server.as_deref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "local authorization server is not configured for this edge",
        );
    };
    match auth_server.authorization_page(&request) {
        Ok(page) => Html(page).into_response(),
        Err(response) => response,
    }
}

async fn handle_authorization_approval(
    State(state): State<RemoteAppState>,
    Form(form): Form<AuthorizationApprovalForm>,
) -> Response {
    let Some(auth_server) = state.local_auth_server.as_deref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "local authorization server is not configured for this edge",
        );
    };
    match auth_server.approve_authorization(form) {
        Ok(redirect) => redirect.into_response(),
        Err(response) => response,
    }
}

async fn handle_token_endpoint(
    State(state): State<RemoteAppState>,
    Form(form): Form<TokenRequestForm>,
) -> Response {
    let Some(auth_server) = state.local_auth_server.as_deref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "local authorization server is not configured for this edge",
        );
    };
    match auth_server.exchange_token(form) {
        Ok(token_response) => Json(token_response).into_response(),
        Err(response) => response,
    }
}

async fn handle_local_jwks(State(state): State<RemoteAppState>) -> Response {
    let Some(auth_server) = state.local_auth_server.as_deref() else {
        return plain_http_error(
            StatusCode::NOT_FOUND,
            "local authorization server is not configured for this edge",
        );
    };
    Json(auth_server.jwks()).into_response()
}

async fn handle_delete(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    let request_auth_context = match authenticate_session_request(
        request.headers(),
        &state.auth_mode,
        state.protected_resource_metadata.as_deref(),
    )
    .await
    {
        Ok(auth_context) => auth_context,
        Err(response) => return response,
    };

    let Some(session_id) = session_id_from_headers(request.headers()) else {
        return plain_http_error(StatusCode::BAD_REQUEST, "missing MCP-Session-Id");
    };
    let Some(entry) = resolve_session_entry(&state, &session_id).await else {
        return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    let session = match entry {
        RemoteSessionEntry::Active(session) => session,
        RemoteSessionEntry::Terminal(record) => {
            if let Err(response) =
                validate_session_auth_context(&request_auth_context, &record.auth_context)
            {
                return response;
            }
            return terminal_session_response(record.lifecycle.state);
        }
    };
    if let Err(response) =
        validate_session_auth_context(&request_auth_context, session.auth_context())
    {
        return response;
    }
    state.sessions.mark_deleted(&session).await;
    state.sessions.remove_active(&session_id).await;

    StatusCode::NO_CONTENT.into_response()
}

async fn handle_admin_authority(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    match load_authority_status(&state) {
        Ok(status) => Json(status).into_response(),
        Err(response) => response,
    }
}

async fn handle_admin_health(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    state.sessions.cleanup_due_sessions().await;
    let (active, terminal) = state.sessions.snapshot().await;
    let authority = match load_authority_status(&state) {
        Ok(status) => status,
        Err(response) => return response,
    };

    let enterprise_provider_summary = state
        .enterprise_provider_registry
        .as_deref()
        .map(|registry| {
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
                "count": registry.providers.len(),
                "validatedCount": validated_count,
                "invalidCount": invalid_count,
            })
        })
        .unwrap_or_else(|| {
            json!({
                "configured": false,
                "count": 0,
                "validatedCount": 0,
                "invalidCount": 0,
            })
        });

    Json(json!({
        "ok": true,
        "server": {
            "serverId": &state.factory.config.server_id,
            "serverName": &state.factory.config.server_name,
            "serverVersion": &state.factory.config.server_version,
            "sharedHostedOwner": state.factory.config.shared_hosted_owner,
        },
        "auth": {
            "mode": remote_auth_mode_label(&state.auth_mode),
            "scopes": &state.factory.config.auth_scopes,
            "issuerConfigured": state.factory.config.auth_jwt_issuer.is_some(),
            "audienceConfigured": state.factory.config.auth_jwt_audience.is_some(),
            "adminTokenConfigured": state.admin_token.is_some(),
        },
        "controlPlane": {
            "proxied": state.factory.config.control_url.is_some(),
            "controlUrl": &state.factory.config.control_url,
            "controlTokenConfigured": state.factory.config.control_token.is_some(),
        },
        "stores": {
            "receiptsConfigured": state.factory.config.receipt_db_path.is_some(),
            "revocationsConfigured": state.factory.config.revocation_db_path.is_some(),
            "authorityDbConfigured": state.factory.config.authority_db_path.is_some(),
            "authoritySeedConfigured": state.factory.config.authority_seed_path.is_some(),
            "budgetsConfigured": state.factory.config.budget_db_path.is_some(),
            "sessionTombstonesConfigured": state.factory.config.session_db_path.is_some(),
        },
        "sessions": {
            "activeCount": active.len(),
            "terminalCount": terminal.len(),
            "idleExpiryMillis": state.factory.lifecycle_policy.idle_expiry_millis,
            "drainGraceMillis": state.factory.lifecycle_policy.drain_grace_millis,
            "reaperIntervalMillis": state.factory.lifecycle_policy.reaper_interval_millis,
            "tombstoneRetentionMillis": state.factory.lifecycle_policy.tombstone_retention_millis,
        },
        "authority": authority,
        "federation": {
            "identityFederationConfigured": state.factory.config.identity_federation_seed_path.is_some(),
            "enterpriseProviders": enterprise_provider_summary,
        },
        "oauth": {
            "protectedResourceMetadata": state.protected_resource_metadata.is_some(),
            "authorizationServerMetadata": state.authorization_server_metadata.is_some(),
            "localAuthorizationServer": state.local_auth_server.is_some(),
        },
    }))
    .into_response()
}

async fn handle_admin_rotate_authority(
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.rotate_authority() {
            Ok(status) => Json(json!({
                "configured": status.configured,
                "backend": status.backend,
                "rotated": true,
                "publicKey": status.public_key,
                "generation": status.generation,
                "rotatedAt": status.rotated_at,
                "appliesToFutureSessionsOnly": status.applies_to_future_sessions_only,
                "trustedPublicKeys": status.trusted_public_keys,
            }))
            .into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    }

    if let Some(path) = state.factory.config.authority_db_path.as_deref() {
        return match pact_store_sqlite::SqliteCapabilityAuthority::open(path)
            .and_then(|authority| authority.rotate())
        {
            Ok(status) => Json(json!({
                "configured": true,
                "backend": "sqlite",
                "rotated": true,
                "publicKey": status.public_key.to_hex(),
                "generation": status.generation,
                "rotatedAt": status.rotated_at,
                "appliesToFutureSessionsOnly": true,
                "trustedPublicKeys": status.trusted_public_keys.into_iter().map(|key| key.to_hex()).collect::<Vec<_>>(),
            }))
            .into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    }

    let Some(path) = state.factory.config.authority_seed_path.as_deref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "remote authority admin requires --authority-seed-file or --authority-db",
        );
    };

    match rotate_authority_keypair(path) {
        Ok(public_key) => Json(json!({
            "configured": true,
            "backend": "seed_file",
            "rotated": true,
            "publicKey": public_key.to_hex(),
            "appliesToFutureSessionsOnly": true,
            "trustedPublicKeys": vec![public_key.to_hex()],
        }))
        .into_response(),
        Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn handle_admin_tool_receipts(
    State(state): State<RemoteAppState>,
    Query(query): Query<AdminToolReceiptQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_origin(&headers) {
        return response;
    }
    if let Err(response) = validate_admin_auth(&headers, state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.list_tool_receipts(&ToolReceiptQuery {
            capability_id: query.capability_id.clone(),
            tool_server: query.tool_server.clone(),
            tool_name: query.tool_name.clone(),
            decision: query.decision.clone(),
            limit: Some(admin_list_limit(query.limit)),
        }) {
            Ok(response) => Json(response).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    }
    let store = match open_receipt_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let receipts = match store.list_tool_receipts(
        admin_list_limit(query.limit),
        query.capability_id.as_deref(),
        query.tool_server.as_deref(),
        query.tool_name.as_deref(),
        query.decision.as_deref(),
    ) {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let receipts = match receipts
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    Json(json!({
        "configured": true,
        "backend": "sqlite",
        "kind": "tool",
        "count": receipts.len(),
        "filters": {
            "capabilityId": query.capability_id,
            "toolServer": query.tool_server,
            "toolName": query.tool_name,
            "decision": query.decision,
        },
        "receipts": receipts,
    }))
    .into_response()
}

async fn handle_admin_child_receipts(
    State(state): State<RemoteAppState>,
    Query(query): Query<AdminChildReceiptQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_origin(&headers) {
        return response;
    }
    if let Err(response) = validate_admin_auth(&headers, state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.list_child_receipts(&ChildReceiptQuery {
            session_id: query.session_id.clone(),
            parent_request_id: query.parent_request_id.clone(),
            request_id: query.request_id.clone(),
            operation_kind: query.operation_kind.clone(),
            terminal_state: query.terminal_state.clone(),
            limit: Some(admin_list_limit(query.limit)),
        }) {
            Ok(response) => Json(response).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    }
    let store = match open_receipt_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let receipts = match store.list_child_receipts(
        admin_list_limit(query.limit),
        query.session_id.as_deref(),
        query.parent_request_id.as_deref(),
        query.request_id.as_deref(),
        query.operation_kind.as_deref(),
        query.terminal_state.as_deref(),
    ) {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let receipts = match receipts
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(receipts) => receipts,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    Json(json!({
        "configured": true,
        "backend": "sqlite",
        "kind": "child",
        "count": receipts.len(),
        "filters": {
            "sessionId": query.session_id,
            "parentRequestId": query.parent_request_id,
            "requestId": query.request_id,
            "operationKind": query.operation_kind,
            "terminalState": query.terminal_state,
        },
        "receipts": receipts,
    }))
    .into_response()
}

async fn handle_admin_budgets(
    State(state): State<RemoteAppState>,
    Query(query): Query<AdminBudgetQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_origin(&headers) {
        return response;
    }
    if let Err(response) = validate_admin_auth(&headers, state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.list_budgets(&trust_control::BudgetQuery {
            capability_id: query.capability_id.clone(),
            limit: Some(admin_list_limit(query.limit)),
        }) {
            Ok(response) => Json(response).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    }

    let store = match open_budget_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let usages = match pact_kernel::BudgetStore::list_usages(
        &store,
        admin_list_limit(query.limit),
        query.capability_id.as_deref(),
    ) {
        Ok(usages) => usages,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    Json(json!({
        "configured": true,
        "backend": "sqlite",
        "capabilityId": query.capability_id,
        "count": usages.len(),
        "usages": usages.into_iter().map(|usage| json!({
            "capabilityId": usage.capability_id,
            "grantIndex": usage.grant_index,
            "invocationCount": usage.invocation_count,
            "updatedAt": usage.updated_at,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn handle_admin_revocations(
    State(state): State<RemoteAppState>,
    Query(query): Query<AdminRevocationQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = validate_origin(&headers) {
        return response;
    }
    if let Err(response) = validate_admin_auth(&headers, state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.list_revocations(&RevocationQuery {
            capability_id: query.capability_id.clone(),
            limit: Some(admin_list_limit(query.limit)),
        }) {
            Ok(response) => Json(response).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    }
    let store = match open_revocation_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let revocations = match store.list_revocations(
        admin_list_limit(query.limit),
        query.capability_id.as_deref(),
    ) {
        Ok(revocations) => revocations,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };
    let revoked = query
        .capability_id
        .as_deref()
        .map(|capability_id| store.is_revoked(capability_id))
        .transpose()
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()));
    let revoked = match revoked {
        Ok(revoked) => revoked,
        Err(response) => return response,
    };

    Json(json!({
        "configured": true,
        "backend": "sqlite",
        "capabilityId": query.capability_id,
        "revoked": revoked,
        "count": revocations.len(),
        "revocations": revocations.iter().map(|entry| {
            json!({
                "capabilityId": entry.capability_id,
                "revokedAt": entry.revoked_at,
            })
        }).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn handle_admin_revoke_capability(
    State(state): State<RemoteAppState>,
    headers: HeaderMap,
    Json(payload): Json<AdminRevokeCapabilityRequest>,
) -> Response {
    if let Err(response) = validate_origin(&headers) {
        return response;
    }
    if let Err(response) = validate_admin_auth(&headers, state.admin_token.as_deref()) {
        return response;
    }

    if let Some(client) = match control_client(&state) {
        Ok(client) => client,
        Err(response) => return response,
    } {
        return match client.revoke_capability(&payload.capability_id) {
            Ok(response) => Json(response).into_response(),
            Err(error) => plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };
    }
    let mut store = match open_revocation_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    let newly_revoked = match store.revoke(&payload.capability_id) {
        Ok(revoked) => revoked,
        Err(error) => {
            return plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    };

    Json(json!({
        "capabilityId": payload.capability_id,
        "revoked": true,
        "newlyRevoked": newly_revoked,
    }))
    .into_response()
}

async fn handle_admin_session_trust(
    AxumPath(session_id): AxumPath<String>,
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    let Some(entry) = resolve_session_entry(&state, &session_id).await else {
        return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    let (record, statuses) = match entry {
        RemoteSessionEntry::Active(session) => {
            let record = session.diagnostic_record();
            let statuses = match load_session_revocation_status(&state, &record.capabilities) {
                Ok(statuses) => statuses,
                Err(response) => return response,
            };
            (record, statuses)
        }
        RemoteSessionEntry::Terminal(record) => {
            let statuses = match load_session_revocation_status(&state, &record.capabilities) {
                Ok(statuses) => statuses,
                Err(response) => return response,
            };
            ((*record).clone(), statuses)
        }
    };

    Json(json!({
        "sessionId": session_id,
        "authContext": record.auth_context,
        "lifecycle": serialize_session_lifecycle(&record.lifecycle, record.protocol_version.clone()),
        "ownership": record.ownership,
        "capabilities": statuses,
    }))
    .into_response()
}

async fn handle_admin_revoke_session_trust(
    AxumPath(session_id): AxumPath<String>,
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    let Some(entry) = resolve_session_entry(&state, &session_id).await else {
        return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    let record = match entry {
        RemoteSessionEntry::Active(session) => session.diagnostic_record(),
        RemoteSessionEntry::Terminal(record) => (*record).clone(),
    };

    let mut newly_revoked_count = 0usize;
    for capability in &record.capabilities {
        let newly_revoked = if let Some(client) = match control_client(&state) {
            Ok(client) => client,
            Err(response) => return response,
        } {
            client
                .revoke_capability(&capability.id)
                .map(|response| response.newly_revoked)
                .unwrap_or(false)
        } else {
            let mut store = match open_revocation_store(&state) {
                Ok(store) => store,
                Err(response) => return response,
            };
            store.revoke(&capability.id).unwrap_or(false)
        };
        if newly_revoked {
            newly_revoked_count += 1;
        }
    }

    let statuses = match load_session_revocation_status(&state, &record.capabilities) {
        Ok(statuses) => statuses,
        Err(response) => return response,
    };

    Json(json!({
        "sessionId": session_id,
        "revoked": true,
        "newlyRevokedCount": newly_revoked_count,
        "authContext": record.auth_context,
        "lifecycle": serialize_session_lifecycle(&record.lifecycle, record.protocol_version.clone()),
        "ownership": record.ownership,
        "capabilities": statuses,
    }))
    .into_response()
}

async fn handle_admin_sessions(State(state): State<RemoteAppState>, request: Request) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    state.sessions.cleanup_due_sessions().await;
    let (active, terminal) = state.sessions.snapshot().await;
    Json(json!({
        "configured": true,
        "idleExpiryMillis": state.factory.lifecycle_policy.idle_expiry_millis,
        "drainGraceMillis": state.factory.lifecycle_policy.drain_grace_millis,
        "reaperIntervalMillis": state.factory.lifecycle_policy.reaper_interval_millis,
        "activeCount": active.len(),
        "terminalCount": terminal.len(),
        "activeSessions": active.iter().map(serialize_session_diagnostic_record).collect::<Vec<_>>(),
        "terminalSessions": terminal.iter().map(serialize_session_diagnostic_record).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn handle_admin_session_drain(
    AxumPath(session_id): AxumPath<String>,
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    let Some(entry) = resolve_session_entry(&state, &session_id).await else {
        return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    let record = match entry {
        RemoteSessionEntry::Active(session) => {
            state.sessions.mark_draining(&session).await;
            session.diagnostic_record()
        }
        RemoteSessionEntry::Terminal(record) => (*record).clone(),
    };

    Json(json!({
        "sessionId": session_id,
        "draining": true,
        "lifecycle": serialize_session_lifecycle(&record.lifecycle, record.protocol_version.clone()),
        "ownership": record.ownership,
    }))
    .into_response()
}

async fn handle_admin_session_shutdown(
    AxumPath(session_id): AxumPath<String>,
    State(state): State<RemoteAppState>,
    request: Request,
) -> Response {
    if let Err(response) = validate_origin(request.headers()) {
        return response;
    }
    if let Err(response) = validate_admin_auth(request.headers(), state.admin_token.as_deref()) {
        return response;
    }

    let Some(entry) = resolve_session_entry(&state, &session_id).await else {
        return plain_http_error(StatusCode::NOT_FOUND, "unknown MCP session");
    };
    let record = match entry {
        RemoteSessionEntry::Active(session) => {
            state.sessions.mark_closed(&session).await;
            state.sessions.remove_active(&session_id).await;
            session.diagnostic_record()
        }
        RemoteSessionEntry::Terminal(record) => (*record).clone(),
    };

    Json(json!({
        "sessionId": session_id,
        "shutdown": true,
        "lifecycle": serialize_session_lifecycle(&record.lifecycle, record.protocol_version.clone()),
        "ownership": record.ownership,
    }))
    .into_response()
}

fn is_initialize_request(message: &Value) -> bool {
    message.get("method").and_then(Value::as_str) == Some("initialize")
}

fn is_terminal_response_for_request(message: &Value, request_id: &Value) -> bool {
    message.get("id") == Some(request_id) && message.get("method").is_none()
}

fn is_successful_initialize_response(message: &Value, request_id: &Value) -> bool {
    is_terminal_response_for_request(message, request_id) && message.get("result").is_some()
}

fn classify_remote_session_event(message: &Value) -> RemoteSessionEventKind {
    if message.get("method").is_some() && message.get("id").is_none() {
        RemoteSessionEventKind::Notification
    } else {
        RemoteSessionEventKind::RequestCorrelated
    }
}

fn parse_session_event_id(event_id: &str, expected_session_id: &str) -> Result<u64, String> {
    let Some((session_id, seq)) = event_id.rsplit_once('-') else {
        return Err("invalid Last-Event-ID format for MCP session".to_string());
    };
    if session_id != expected_session_id {
        return Err("Last-Event-ID does not belong to this MCP session".to_string());
    }
    seq.parse::<u64>()
        .map_err(|_| "invalid Last-Event-ID sequence for MCP session".to_string())
}

fn should_emit_post_stream_event(
    event: &RemoteSessionEvent,
    request_id: Option<&Value>,
    notification_stream_attached: bool,
) -> bool {
    match event.kind {
        RemoteSessionEventKind::Notification => !notification_stream_attached,
        RemoteSessionEventKind::RequestCorrelated => {
            request_id.is_none_or(|request_id| {
                is_terminal_response_for_request(&event.message, request_id)
            }) || event.message.get("method").is_some()
        }
    }
}

fn session_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(HeaderName::from_static(MCP_SESSION_ID_HEADER))
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

async fn resolve_session_entry(
    state: &RemoteAppState,
    session_id: &str,
) -> Option<RemoteSessionEntry> {
    state.sessions.cleanup_due_sessions().await;
    state.sessions.lookup(session_id).await
}

async fn session_reaper_loop(state: RemoteAppState) {
    let interval =
        std::time::Duration::from_millis(state.factory.lifecycle_policy.reaper_interval_millis);
    loop {
        tokio::time::sleep(interval).await;
        state.sessions.cleanup_due_sessions().await;
    }
}

fn build_remote_auth_state(
    config: &RemoteServeHttpConfig,
    local_addr: SocketAddr,
    discovered_identity_provider: Option<&DiscoveredIdentityProvider>,
    enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
) -> Result<(RemoteAuthMode, Option<Arc<str>>), CliError> {
    let auth_mode = build_remote_auth_mode(
        config,
        Some(local_addr),
        discovered_identity_provider,
        enterprise_provider_registry.clone(),
    )?;

    let admin_token = if let Some(token) = config.admin_token.as_deref() {
        Some(Arc::<str>::from(token.to_string()))
    } else if let Some(token) = config.auth_token.as_deref() {
        Some(Arc::<str>::from(token.to_string()))
    } else {
        return Err(CliError::Other(
            "bearer-authenticated remote MCP edge requires --admin-token for admin APIs"
                .to_string(),
        ));
    };

    Ok((auth_mode, admin_token))
}

fn build_protected_resource_metadata(
    config: &RemoteServeHttpConfig,
    local_addr: SocketAddr,
    discovered_identity_provider: Option<&DiscoveredIdentityProvider>,
) -> Result<Option<ProtectedResourceMetadata>, CliError> {
    if matches!(
        build_remote_auth_mode(config, Some(local_addr), discovered_identity_provider, None,)?,
        RemoteAuthMode::StaticBearer { .. }
    ) {
        return Ok(None);
    }

    let authorization_servers = if !config.auth_servers.is_empty() {
        config.auth_servers.clone()
    } else if let Some(issuer) = resolve_local_auth_issuer(config, local_addr)? {
        vec![issuer]
    } else if let Some(discovered) = discovered_identity_provider {
        vec![discovered.issuer.clone()]
    } else if let Some(issuer) = config.auth_jwt_issuer.clone() {
        vec![issuer]
    } else {
        return Err(CliError::Other(
            "bearer-authenticated remote MCP edge requires --auth-server or --auth-jwt-issuer so protected-resource metadata can advertise an authorization server".to_string(),
        ));
    };

    let base_url = normalize_public_base_url(config.public_base_url.as_deref(), local_addr)?;
    Ok(Some(ProtectedResourceMetadata {
        resource: format!("{base_url}{MCP_ENDPOINT_PATH}"),
        resource_metadata_url: format!("{base_url}{PROTECTED_RESOURCE_METADATA_MCP_PATH}"),
        authorization_servers,
        scopes_supported: config.auth_scopes.clone(),
    }))
}

fn build_authorization_server_metadata(
    config: &RemoteServeHttpConfig,
    local_addr: SocketAddr,
    discovered_identity_provider: Option<&DiscoveredIdentityProvider>,
) -> Result<Option<AuthorizationServerMetadata>, CliError> {
    if matches!(
        build_remote_auth_mode(config, Some(local_addr), discovered_identity_provider, None,)?,
        RemoteAuthMode::StaticBearer { .. }
    ) {
        return Ok(None);
    }

    if let Some(issuer) = resolve_local_auth_issuer(config, local_addr)? {
        let issuer = Url::parse(&issuer)
            .map_err(|error| CliError::Other(format!("invalid local auth issuer: {error}")))?;
        let metadata_path = metadata_path_for_issuer(&issuer);
        let base_url = normalize_public_base_url(config.public_base_url.as_deref(), local_addr)?;
        let mut document = json!({
            "issuer": issuer.as_str(),
            "authorization_endpoint": format!("{base_url}{LOCAL_AUTHORIZATION_PATH}"),
            "token_endpoint": format!("{base_url}{LOCAL_TOKEN_PATH}"),
            "jwks_uri": format!("{base_url}{LOCAL_JWKS_PATH}"),
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:token-exchange"
            ],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
        });
        if !config.auth_scopes.is_empty() {
            document["scopes_supported"] = json!(config.auth_scopes);
        }
        return Ok(Some(AuthorizationServerMetadata {
            metadata_path,
            document,
        }));
    }

    let issuer = config
        .auth_jwt_issuer
        .as_deref()
        .map(ToOwned::to_owned)
        .or_else(|| discovered_identity_provider.map(|provider| provider.issuer.clone()));
    let authorization_endpoint = config
        .auth_authorization_endpoint
        .as_deref()
        .map(ToOwned::to_owned)
        .or_else(|| {
            discovered_identity_provider
                .and_then(|provider| provider.authorization_endpoint.clone())
        });
    let token_endpoint = config
        .auth_token_endpoint
        .as_deref()
        .map(ToOwned::to_owned)
        .or_else(|| {
            discovered_identity_provider.and_then(|provider| provider.token_endpoint.clone())
        });

    let (Some(issuer), Some(authorization_endpoint), Some(token_endpoint)) = (
        issuer.as_deref(),
        authorization_endpoint.as_deref(),
        token_endpoint.as_deref(),
    ) else {
        return Ok(None);
    };

    let issuer = Url::parse(issuer).map_err(|error| {
        CliError::Other(format!(
            "invalid --auth-jwt-issuer for authorization-server metadata: {error}"
        ))
    })?;
    let public_base_url = Url::parse(&normalize_public_base_url(
        config.public_base_url.as_deref(),
        local_addr,
    )?)
    .map_err(|error| {
        CliError::Other(format!(
            "invalid public base URL for authorization-server metadata: {error}"
        ))
    })?;

    if !same_origin(&issuer, &public_base_url) {
        return Ok(None);
    }

    let metadata_path = metadata_path_for_issuer(&issuer);
    let mut document = json!({
        "issuer": issuer.as_str(),
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
    });
    if !config.auth_scopes.is_empty() {
        document["scopes_supported"] = json!(config.auth_scopes);
    }
    if let Some(registration_endpoint) = config
        .auth_registration_endpoint
        .as_deref()
        .map(ToOwned::to_owned)
        .or_else(|| {
            discovered_identity_provider.and_then(|provider| provider.registration_endpoint.clone())
        })
    {
        document["registration_endpoint"] = json!(registration_endpoint);
    }
    if let Some(jwks_uri) = config
        .auth_jwks_uri
        .as_deref()
        .map(ToOwned::to_owned)
        .or_else(|| discovered_identity_provider.and_then(|provider| provider.jwks_uri.clone()))
    {
        document["jwks_uri"] = json!(jwks_uri);
    }

    Ok(Some(AuthorizationServerMetadata {
        metadata_path,
        document,
    }))
}

fn build_remote_auth_mode(
    config: &RemoteServeHttpConfig,
    local_addr: Option<SocketAddr>,
    discovered_identity_provider: Option<&DiscoveredIdentityProvider>,
    enterprise_provider_registry: Option<Arc<EnterpriseProviderRegistry>>,
) -> Result<RemoteAuthMode, CliError> {
    let has_external_discovery = discovered_identity_provider.is_some()
        || config.auth_jwt_discovery_url.is_some()
        || config.auth_jwt_provider_profile.is_some();
    let has_introspection = config.auth_introspection_url.is_some();
    let provider_profile = config
        .auth_jwt_provider_profile
        .unwrap_or(JwtProviderProfile::Generic);

    if config.auth_token.is_some()
        && (config.auth_jwt_public_key.is_some()
            || config.auth_server_seed_path.is_some()
            || has_external_discovery
            || has_introspection)
    {
        return Err(CliError::Other(
            "use either --auth-token or OAuth bearer auth flags, not both".to_string(),
        ));
    }
    if config.auth_server_seed_path.is_some()
        && (config.auth_jwt_public_key.is_some() || has_external_discovery || has_introspection)
    {
        return Err(CliError::Other(
            "use either --auth-jwt-public-key / discovery flags or --auth-server-seed-file, not both"
                .to_string(),
        ));
    }
    if config.auth_introspection_client_id.is_some()
        != config.auth_introspection_client_secret.is_some()
    {
        return Err(CliError::Other(
            "--auth-introspection-client-id and --auth-introspection-client-secret must be provided together"
                .to_string(),
        ));
    }
    if has_introspection && config.auth_jwt_public_key.is_some() {
        return Err(CliError::Other(
            "use either JWT verification flags or --auth-introspection-url, not both".to_string(),
        ));
    }

    if let Some(token) = config.auth_token.as_deref() {
        return Ok(RemoteAuthMode::StaticBearer {
            token: Arc::<str>::from(token.to_string()),
        });
    }

    if let Some(seed_path) = config.auth_server_seed_path.as_deref() {
        return Ok(RemoteAuthMode::JwtBearer {
            verifier: Arc::new(JwtBearerVerifier {
                key_source: JwtVerificationKeySource::Static(
                    load_or_create_authority_keypair(seed_path)?.public_key(),
                ),
                issuer: config.auth_jwt_issuer.clone().or_else(|| {
                    local_addr
                        .map(|addr| {
                            normalize_public_base_url(config.public_base_url.as_deref(), addr)
                        })
                        .transpose()
                        .ok()
                        .flatten()
                        .map(|base_url| format!("{base_url}/oauth"))
                }),
                audience: config.auth_jwt_audience.clone(),
                required_scopes: config.auth_scopes.clone(),
                provider_profile,
                enterprise_provider_registry: enterprise_provider_registry.clone(),
            }),
        });
    }

    if let Some(introspection_url) = config.auth_introspection_url.as_deref() {
        return Ok(RemoteAuthMode::IntrospectionBearer {
            verifier: Arc::new(IntrospectionBearerVerifier {
                client: HttpClient::builder()
                    .timeout(Duration::from_secs(TOKEN_INTROSPECTION_TIMEOUT_SECS))
                    .build()
                    .map_err(|error| {
                        CliError::Other(format!(
                            "failed to build token introspection client: {error}"
                        ))
                    })?,
                introspection_url: parse_identity_provider_url(
                    introspection_url,
                    "--auth-introspection-url",
                )?,
                client_id: config.auth_introspection_client_id.clone(),
                client_secret: config.auth_introspection_client_secret.clone(),
                issuer: config
                    .auth_jwt_issuer
                    .clone()
                    .or_else(|| {
                        discovered_identity_provider.map(|provider| provider.issuer.clone())
                    })
                    .or_else(|| {
                        local_addr
                            .map(|addr| {
                                normalize_public_base_url(config.public_base_url.as_deref(), addr)
                            })
                            .transpose()
                            .ok()
                            .flatten()
                            .map(|base_url| format!("{base_url}/oauth"))
                    }),
                audience: config.auth_jwt_audience.clone(),
                required_scopes: config.auth_scopes.clone(),
                provider_profile,
                enterprise_provider_registry: enterprise_provider_registry.clone(),
            }),
        });
    }

    let key_source = if let Some(public_key_hex) = config.auth_jwt_public_key.as_deref() {
        JwtVerificationKeySource::Static(PublicKey::from_hex(public_key_hex)?)
    } else if let Some(discovered) = discovered_identity_provider {
        JwtVerificationKeySource::Jwks(discovered.jwks_keys.clone().ok_or_else(|| {
            CliError::Other(
                "OIDC discovery did not resolve any compatible signing keys for JWT verification"
                    .to_string(),
            )
        })?)
    } else {
        return Err(CliError::Other(
            "remote MCP edge requires either --auth-token, --auth-jwt-public-key, --auth-jwt-discovery-url, --auth-introspection-url, or --auth-server-seed-file"
                .to_string(),
        ));
    };

    Ok(RemoteAuthMode::JwtBearer {
        verifier: Arc::new(JwtBearerVerifier {
            key_source,
            issuer: config
                .auth_jwt_issuer
                .clone()
                .or_else(|| discovered_identity_provider.map(|provider| provider.issuer.clone()))
                .or_else(|| {
                    local_addr
                        .map(|addr| {
                            normalize_public_base_url(config.public_base_url.as_deref(), addr)
                        })
                        .transpose()
                        .ok()
                        .flatten()
                        .map(|base_url| format!("{base_url}/oauth"))
                }),
            audience: config.auth_jwt_audience.clone(),
            required_scopes: config.auth_scopes.clone(),
            provider_profile,
            enterprise_provider_registry,
        }),
    })
}

fn resolve_local_auth_issuer(
    config: &RemoteServeHttpConfig,
    local_addr: SocketAddr,
) -> Result<Option<String>, CliError> {
    if config.auth_server_seed_path.is_none() {
        return Ok(None);
    }
    if let Some(issuer) = config.auth_jwt_issuer.as_deref() {
        return Ok(Some(issuer.to_string()));
    }
    let base_url = normalize_public_base_url(config.public_base_url.as_deref(), local_addr)?;
    Ok(Some(format!("{base_url}/oauth")))
}

fn build_local_auth_server(
    config: &RemoteServeHttpConfig,
    local_addr: SocketAddr,
) -> Result<Option<LocalAuthorizationServer>, CliError> {
    let Some(seed_path) = config.auth_server_seed_path.as_deref() else {
        return Ok(None);
    };
    let signing_key = load_or_create_authority_keypair(seed_path)?;
    let issuer = resolve_local_auth_issuer(config, local_addr)?
        .ok_or_else(|| CliError::Other("failed to resolve local auth issuer".to_string()))?;
    let base_url = normalize_public_base_url(config.public_base_url.as_deref(), local_addr)?;
    let default_audience = config
        .auth_jwt_audience
        .clone()
        .unwrap_or_else(|| format!("{base_url}{MCP_ENDPOINT_PATH}"));
    Ok(Some(LocalAuthorizationServer {
        signing_key,
        issuer,
        default_audience,
        supported_scopes: config.auth_scopes.clone(),
        subject: config.auth_subject.clone(),
        code_ttl_secs: config.auth_code_ttl_secs,
        access_token_ttl_secs: config.auth_access_token_ttl_secs,
        codes: Arc::new(StdMutex::new(HashMap::new())),
    }))
}

fn normalize_public_base_url(
    public_base_url: Option<&str>,
    local_addr: SocketAddr,
) -> Result<String, CliError> {
    let base_url = public_base_url
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("http://{local_addr}"));
    let parsed = Url::parse(&base_url).map_err(|error| {
        CliError::Other(format!(
            "invalid --public-base-url for remote MCP edge: {error}"
        ))
    })?;
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn metadata_path_for_issuer(issuer: &Url) -> String {
    let issuer_path = issuer.path().trim_matches('/');
    if issuer_path.is_empty() {
        AUTHORIZATION_SERVER_METADATA_PATH.to_string()
    } else {
        format!("{AUTHORIZATION_SERVER_METADATA_PATH}/{issuer_path}")
    }
}

impl LocalAuthorizationServer {
    fn authorization_page(&self, request: &AuthorizationRequest) -> Result<String, Response> {
        let resource = validate_authorization_request(request, &self.supported_scopes)?;
        let scopes = resolve_requested_scopes(request.scope.as_deref(), &self.supported_scopes)?;
        let state = request.state.clone().unwrap_or_default();
        let scopes_display = scopes.join(" ");
        Ok(format!(
            "<!doctype html><html><body><h1>Authorize MCP Access</h1><p>Client: {client}</p><p>Resource: {resource}</p><p>Subject: {subject}</p><p>Scopes: {scopes}</p><form method=\"post\" action=\"{path}\"><input type=\"hidden\" name=\"response_type\" value=\"code\"><input type=\"hidden\" name=\"client_id\" value=\"{client}\"><input type=\"hidden\" name=\"redirect_uri\" value=\"{redirect}\"><input type=\"hidden\" name=\"state\" value=\"{state}\"><input type=\"hidden\" name=\"scope\" value=\"{scope}\"><input type=\"hidden\" name=\"resource\" value=\"{resource}\"><input type=\"hidden\" name=\"code_challenge\" value=\"{challenge}\"><input type=\"hidden\" name=\"code_challenge_method\" value=\"{method}\"><button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button><button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></form></body></html>",
            client = html_escape(&request.client_id),
            redirect = html_escape(&request.redirect_uri),
            state = html_escape(&state),
            scope = html_escape(&scopes.join(" ")),
            resource = html_escape(&resource),
            subject = html_escape(&self.subject),
            scopes = html_escape(&scopes_display),
            challenge = html_escape(request.code_challenge.as_deref().unwrap_or_default()),
            method = html_escape(request.code_challenge_method.as_deref().unwrap_or_default()),
            path = LOCAL_AUTHORIZATION_PATH,
        ))
    }

    fn approve_authorization(&self, form: AuthorizationApprovalForm) -> Result<Redirect, Response> {
        let request = AuthorizationRequest {
            response_type: form.response_type.clone(),
            client_id: form.client_id.clone(),
            redirect_uri: form.redirect_uri.clone(),
            state: form.state.clone(),
            scope: form.scope.clone(),
            resource: form.resource.clone(),
            code_challenge: Some(form.code_challenge.clone()),
            code_challenge_method: Some(form.code_challenge_method.clone()),
        };
        let resource = validate_authorization_request(&request, &self.supported_scopes)?;
        if form.decision != "approve" {
            return Err(redirect_oauth_error(
                &form.redirect_uri,
                "access_denied",
                "authorization request denied",
                form.state.as_deref(),
            ));
        }

        let scopes = resolve_requested_scopes(form.scope.as_deref(), &self.supported_scopes)?;
        let code = format!(
            "code-{}",
            sha256_hex(
                format!("{}:{}:{}", form.client_id, form.redirect_uri, unix_now()).as_bytes()
            )
        );
        let grant = AuthorizationCodeGrant {
            client_id: form.client_id.clone(),
            redirect_uri: form.redirect_uri.clone(),
            resource: resource.clone(),
            scopes,
            subject: self.subject.clone(),
            code_challenge: form.code_challenge,
            code_challenge_method: form.code_challenge_method,
            expires_at: unix_now().saturating_add(self.code_ttl_secs),
        };
        match self.codes.lock() {
            Ok(mut guard) => {
                guard.insert(code.clone(), grant);
            }
            Err(poisoned) => {
                poisoned.into_inner().insert(code.clone(), grant);
            }
        }

        let mut redirect_uri = Url::parse(&form.redirect_uri)
            .map_err(|_| plain_http_error(StatusCode::BAD_REQUEST, "invalid redirect_uri"))?;
        {
            let mut pairs = redirect_uri.query_pairs_mut();
            pairs.append_pair("code", &code);
            if let Some(state) = form.state.as_deref() {
                pairs.append_pair("state", state);
            }
        }
        Ok(Redirect::to(redirect_uri.as_str()))
    }

    fn exchange_token(&self, form: TokenRequestForm) -> Result<Value, Response> {
        match form.grant_type.as_str() {
            "authorization_code" => self.exchange_authorization_code(form),
            "urn:ietf:params:oauth:grant-type:token-exchange" => self.exchange_subject_token(form),
            _ => Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "unsupported grant_type",
            )),
        }
    }

    fn exchange_authorization_code(&self, form: TokenRequestForm) -> Result<Value, Response> {
        let code = form.code.as_deref().ok_or_else(|| {
            oauth_token_error(StatusCode::BAD_REQUEST, "invalid_request", "missing code")
        })?;
        let redirect_uri = form.redirect_uri.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing redirect_uri",
            )
        })?;
        let client_id = form.client_id.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing client_id",
            )
        })?;
        let code_verifier = form.code_verifier.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing code_verifier",
            )
        })?;

        let grant = match self.codes.lock() {
            Ok(mut guard) => guard.remove(code),
            Err(poisoned) => poisoned.into_inner().remove(code),
        }
        .ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "unknown authorization code",
            )
        })?;

        if unix_now() >= grant.expires_at {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "authorization code expired",
            ));
        }
        if grant.client_id != client_id || grant.redirect_uri != redirect_uri {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "client_id or redirect_uri mismatch",
            ));
        }
        if grant.code_challenge_method != "S256" {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "unsupported code_challenge_method",
            ));
        }
        if pkce_s256(code_verifier) != grant.code_challenge {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "PKCE verification failed",
            ));
        }
        let resource = form.resource.unwrap_or(grant.resource.clone());
        if resource != grant.resource {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "resource parameter mismatch",
            ));
        }

        Ok(self.issue_token_response(
            grant.subject,
            grant.client_id,
            resource,
            grant.scopes,
            Some("authorization_code"),
        ))
    }

    fn exchange_subject_token(&self, form: TokenRequestForm) -> Result<Value, Response> {
        let subject_token = form.subject_token.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing subject_token",
            )
        })?;
        let subject_token_type = form.subject_token_type.as_deref().ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing subject_token_type",
            )
        })?;
        if subject_token_type != "urn:ietf:params:oauth:token-type:access_token" {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "unsupported subject_token_type",
            ));
        }
        let resource = form
            .resource
            .unwrap_or_else(|| self.default_audience.clone());
        let (claims, _) = self.validate_subject_token(subject_token)?;
        let subject = claims.sub.clone().unwrap_or_else(|| self.subject.clone());
        let client_id = claims
            .client_id
            .clone()
            .unwrap_or_else(|| "token-exchange".to_string());
        let scopes = resolve_exchange_scopes(
            form.scope.as_deref(),
            &claims.scopes(),
            &self.supported_scopes,
        )?;

        Ok(self.issue_token_response(
            subject,
            client_id,
            resource,
            scopes,
            Some("urn:ietf:params:oauth:grant-type:token-exchange"),
        ))
    }

    fn validate_subject_token(&self, token: &str) -> Result<(JwtClaims, String), Response> {
        let (header, claims, signed_input, signature) = decode_jwt_parts(token, None)?;
        let alg = JwtSignatureAlgorithm::from_header(&header, None)?;
        if alg != JwtSignatureAlgorithm::EdDsa
            || !verify_ed25519_jwt_signature(
                &self.signing_key.public_key(),
                signed_input.as_bytes(),
                &signature,
            )
        {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "subject token signature is invalid",
            ));
        }
        if claims.iss.as_deref() != Some(self.issuer.as_str()) {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "subject token issuer mismatch",
            ));
        }
        if let Some(exp) = claims.exp {
            if unix_now() >= exp {
                return Err(oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "subject token expired",
                ));
            }
        }
        Ok((claims, signed_input))
    }

    fn issue_token_response(
        &self,
        subject: String,
        client_id: String,
        resource: String,
        scopes: Vec<String>,
        grant_type: Option<&str>,
    ) -> Value {
        let access_token = self.sign_access_token(&subject, &client_id, &resource, &scopes);
        json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.access_token_ttl_secs,
            "scope": scopes.join(" "),
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "grant_type": grant_type,
        })
    }

    fn sign_access_token(
        &self,
        subject: &str,
        client_id: &str,
        resource: &str,
        scopes: &[String],
    ) -> String {
        let now = unix_now();
        let issued_at_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let claims = json!({
            "iss": self.issuer,
            "sub": subject,
            "aud": resource,
            "scope": scopes.join(" "),
            "client_id": client_id,
            "resource": resource,
            "iat": now,
            "exp": now.saturating_add(self.access_token_ttl_secs),
            "jti": format!(
                "atk-{}",
                sha256_hex(
                    format!("{issued_at_nanos}:{subject}:{client_id}:{resource}")
                        .as_bytes()
                )
            ),
        });
        sign_jwt(&self.signing_key, &claims)
    }

    fn jwks(&self) -> Value {
        json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "kid": jwk_key_id(&self.signing_key.public_key()),
                "x": URL_SAFE_NO_PAD.encode(self.signing_key.public_key().as_bytes()),
            }]
        })
    }
}

fn validate_authorization_request(
    request: &AuthorizationRequest,
    supported_scopes: &[String],
) -> Result<String, Response> {
    if request.response_type != "code" {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "response_type must be code",
        ));
    }
    if request.client_id.trim().is_empty() {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id must not be empty",
        ));
    }
    validate_redirect_uri(&request.redirect_uri)?;
    let resource = request.resource.clone().ok_or_else(|| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "missing resource parameter",
        )
    })?;
    let code_challenge = request.code_challenge.as_deref().ok_or_else(|| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "missing code_challenge",
        )
    })?;
    if code_challenge.is_empty() {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "empty code_challenge",
        ));
    }
    if request.code_challenge_method.as_deref() != Some("S256") {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge_method must be S256",
        ));
    }
    let _ = resolve_requested_scopes(request.scope.as_deref(), supported_scopes)?;
    Ok(resource)
}

fn validate_redirect_uri(redirect_uri: &str) -> Result<(), Response> {
    let redirect = Url::parse(redirect_uri).map_err(|_| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid redirect_uri",
        )
    })?;
    let Some(host) = redirect.host_str() else {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid redirect_uri",
        ));
    };
    let is_localhost = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if redirect.scheme() == "https" || (redirect.scheme() == "http" && is_localhost) {
        Ok(())
    } else {
        Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri must use https or localhost",
        ))
    }
}

fn resolve_requested_scopes(
    requested_scope: Option<&str>,
    supported_scopes: &[String],
) -> Result<Vec<String>, Response> {
    let requested = requested_scope
        .unwrap_or_default()
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if supported_scopes.is_empty() {
        return Ok(requested);
    }
    let scopes = if requested.is_empty() {
        supported_scopes.to_vec()
    } else {
        requested
    };
    if scopes
        .iter()
        .all(|scope| supported_scopes.iter().any(|supported| supported == scope))
    {
        Ok(scopes)
    } else {
        Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "requested scope is not supported",
        ))
    }
}

fn resolve_exchange_scopes(
    requested_scope: Option<&str>,
    subject_scopes: &[String],
    supported_scopes: &[String],
) -> Result<Vec<String>, Response> {
    let requested = resolve_requested_scopes(requested_scope, supported_scopes)?;
    let scopes = if requested.is_empty() {
        subject_scopes.to_vec()
    } else {
        requested
    };
    if scopes
        .iter()
        .all(|scope| subject_scopes.iter().any(|granted| granted == scope))
    {
        Ok(scopes)
    } else {
        Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "requested exchange scope exceeds subject token scope",
        ))
    }
}

fn pkce_s256(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn sign_jwt(keypair: &Keypair, claims: &serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": jwk_key_id(&keypair.public_key()),
        }))
        .unwrap_or_default(),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap_or_default());
    let signing_input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(keypair.sign(signing_input.as_bytes()).to_bytes());
    format!("{signing_input}.{signature}")
}

fn jwk_key_id(public_key: &PublicKey) -> String {
    let hex = public_key.to_hex();
    format!("pact-{}", &hex[..hex.len().min(16)])
}

fn redirect_oauth_error(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
) -> Response {
    let mut redirect = match Url::parse(redirect_uri) {
        Ok(url) => url,
        Err(_) => return oauth_token_error(StatusCode::BAD_REQUEST, error, description),
    };
    {
        let mut pairs = redirect.query_pairs_mut();
        pairs.append_pair("error", error);
        pairs.append_pair("error_description", description);
        if let Some(state) = state {
            pairs.append_pair("state", state);
        }
    }
    Redirect::to(redirect.as_str()).into_response()
}

fn oauth_token_error(status: StatusCode, error: &str, description: &str) -> Response {
    let mut response = (
        status,
        Json(json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

impl ProtectedResourceMetadata {
    fn bearer_challenge(&self) -> String {
        let mut challenge = format!(
            "Bearer resource_metadata=\"{}\"",
            self.resource_metadata_url
        );
        if !self.scopes_supported.is_empty() {
            challenge.push_str(&format!(", scope=\"{}\"", self.scopes_supported.join(" ")));
        }
        challenge
    }
}

async fn authenticate_session_request(
    headers: &HeaderMap,
    auth_mode: &RemoteAuthMode,
    protected_resource_metadata: Option<&ProtectedResourceMetadata>,
) -> Result<SessionAuthContext, Response> {
    let token = extract_bearer_token(headers, protected_resource_metadata)?;
    let origin = headers
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);

    match auth_mode {
        RemoteAuthMode::StaticBearer {
            token: expected_token,
        } => {
            if token != expected_token.as_ref() {
                return Err(unauthorized_bearer_response(
                    "missing or invalid bearer token",
                    protected_resource_metadata,
                ));
            }
            Ok(build_static_bearer_session_auth_context(
                headers,
                expected_token.as_ref(),
            ))
        }
        RemoteAuthMode::JwtBearer { verifier } => {
            verifier.authenticate_token(&token, origin, protected_resource_metadata)
        }
        RemoteAuthMode::IntrospectionBearer { verifier } => {
            verifier
                .authenticate_token(&token, origin, protected_resource_metadata)
                .await
        }
    }
}

fn validate_admin_auth(headers: &HeaderMap, admin_token: Option<&str>) -> Result<(), Response> {
    let Some(expected_token) = admin_token else {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "remote admin API is disabled",
        ));
    };
    let token = extract_bearer_token(headers, None)?;
    if token == expected_token {
        Ok(())
    } else {
        Err(unauthorized_bearer_response(
            "missing or invalid admin bearer token",
            None,
        ))
    }
}

fn remote_auth_mode_label(auth_mode: &RemoteAuthMode) -> &'static str {
    match auth_mode {
        RemoteAuthMode::StaticBearer { .. } => "static_bearer",
        RemoteAuthMode::JwtBearer { .. } => "jwt_bearer",
        RemoteAuthMode::IntrospectionBearer { .. } => "introspection_bearer",
    }
}

fn validate_session_auth_context(
    request_auth_context: &SessionAuthContext,
    session_auth_context: &SessionAuthContext,
) -> Result<(), Response> {
    if request_auth_context.transport != session_auth_context.transport {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "authenticated transport does not match session",
        ));
    }

    let matches = match (&request_auth_context.method, &session_auth_context.method) {
        (
            SessionAuthMethod::StaticBearer {
                principal: request_principal,
                token_fingerprint: request_fingerprint,
            },
            SessionAuthMethod::StaticBearer {
                principal: session_principal,
                token_fingerprint: session_fingerprint,
            },
        ) => request_principal == session_principal && request_fingerprint == session_fingerprint,
        (
            SessionAuthMethod::OAuthBearer {
                principal: request_principal,
                issuer: request_issuer,
                subject: request_subject,
                audience: request_audience,
                ..
            },
            SessionAuthMethod::OAuthBearer {
                principal: session_principal,
                issuer: session_issuer,
                subject: session_subject,
                audience: session_audience,
                ..
            },
        ) => {
            request_principal == session_principal
                && request_issuer == session_issuer
                && request_subject == session_subject
                && request_audience == session_audience
        }
        (SessionAuthMethod::Anonymous, SessionAuthMethod::Anonymous) => true,
        _ => false,
    };

    if matches {
        Ok(())
    } else {
        Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "authenticated principal does not match session",
        ))
    }
}

fn validate_session_lifecycle(session: &RemoteSession) -> Result<(), Response> {
    match session.lifecycle_snapshot().state {
        RemoteSessionState::Ready => Ok(()),
        RemoteSessionState::Initializing => Err(plain_http_error(
            StatusCode::CONFLICT,
            "MCP session is still initializing",
        )),
        RemoteSessionState::Draining => Err(plain_http_error(
            StatusCode::CONFLICT,
            "MCP session is draining and must not be resumed",
        )),
        RemoteSessionState::Deleted => Err(plain_http_error(
            StatusCode::GONE,
            "MCP session was deleted and must be re-initialized",
        )),
        RemoteSessionState::Expired => Err(plain_http_error(
            StatusCode::GONE,
            "MCP session expired and must be re-initialized",
        )),
        RemoteSessionState::Closed => Err(plain_http_error(
            StatusCode::GONE,
            "MCP session was shut down and must be re-initialized",
        )),
    }
}

fn serialize_session_lifecycle(
    lifecycle: &RemoteSessionLifecycleSnapshot,
    protocol_version: Option<String>,
) -> Value {
    json!({
        "state": lifecycle.state.as_str(),
        "createdAt": lifecycle.created_at,
        "lastSeenAt": lifecycle.last_seen_at,
        "idleExpiresAt": lifecycle.idle_expires_at,
        "drainDeadlineAt": lifecycle.drain_deadline_at,
        "protocolVersion": protocol_version,
        "reconnect": {
            "mode": "post-session-reuse-only",
            "resumable": lifecycle.state == RemoteSessionState::Ready,
            "requiresAuthContinuity": true,
            "terminalStates": ["draining", "deleted", "expired", "closed"],
        }
    })
}

fn serialize_session_diagnostic_record(record: &RemoteSessionDiagnosticRecord) -> Value {
    json!({
        "sessionId": record.session_id,
        "authContext": record.auth_context,
        "lifecycle": serialize_session_lifecycle(&record.lifecycle, record.protocol_version.clone()),
        "ownership": record.ownership,
        "capabilities": record.capabilities.iter().map(|capability| json!({
            "id": capability.id,
            "issuerPublicKey": capability.issuer_public_key,
            "subjectPublicKey": capability.subject_public_key,
        })).collect::<Vec<_>>(),
    })
}

fn extract_bearer_token(
    headers: &HeaderMap,
    protected_resource_metadata: Option<&ProtectedResourceMetadata>,
) -> Result<String, Response> {
    let header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    header
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            unauthorized_bearer_response(
                "missing or invalid bearer token",
                protected_resource_metadata,
            )
        })
}

fn unauthorized_bearer_response(
    message: &str,
    protected_resource_metadata: Option<&ProtectedResourceMetadata>,
) -> Response {
    let mut response = plain_http_error(StatusCode::UNAUTHORIZED, message);
    let challenge = protected_resource_metadata
        .map(ProtectedResourceMetadata::bearer_challenge)
        .unwrap_or_else(|| "Bearer".to_string());
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(&challenge).unwrap_or_else(|_| HeaderValue::from_static("Bearer")),
    );
    response
}

fn admin_list_limit(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(DEFAULT_ADMIN_LIST_LIMIT)
        .clamp(1, MAX_ADMIN_LIST_LIMIT)
}

fn control_client(
    state: &RemoteAppState,
) -> Result<Option<trust_control::TrustControlClient>, Response> {
    let Some(url) = state.factory.config.control_url.as_deref() else {
        return Ok(None);
    };
    let Some(token) = state.factory.config.control_token.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "remote trust admin requires --control-token when --control-url is configured",
        ));
    };
    trust_control::build_client(url, token)
        .map(Some)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))
}

fn open_receipt_store(
    state: &RemoteAppState,
) -> Result<pact_store_sqlite::SqliteReceiptStore, Response> {
    let Some(path) = state.factory.config.receipt_db_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "remote receipt admin requires --receipt-db",
        ));
    };
    pact_store_sqlite::SqliteReceiptStore::open(path)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))
}

fn open_revocation_store(
    state: &RemoteAppState,
) -> Result<pact_store_sqlite::SqliteRevocationStore, Response> {
    let Some(path) = state.factory.config.revocation_db_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "remote trust admin requires --revocation-db",
        ));
    };
    pact_store_sqlite::SqliteRevocationStore::open(path)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))
}

fn open_budget_store(
    state: &RemoteAppState,
) -> Result<pact_store_sqlite::SqliteBudgetStore, Response> {
    let Some(path) = state.factory.config.budget_db_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "remote budget admin requires --budget-db",
        ));
    };
    pact_store_sqlite::SqliteBudgetStore::open(path)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))
}

fn load_authority_status(state: &RemoteAppState) -> Result<Value, Response> {
    if let Some(client) = control_client(state)? {
        let status = client.authority_status().map_err(|error| {
            plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        })?;
        return Ok(json!({
            "configured": status.configured,
            "backend": status.backend,
            "publicKey": status.public_key,
            "generation": status.generation,
            "rotatedAt": status.rotated_at,
            "appliesToFutureSessionsOnly": status.applies_to_future_sessions_only,
            "trustedPublicKeys": status.trusted_public_keys,
        }));
    }

    if let Some(path) = state.factory.config.authority_db_path.as_deref() {
        let status = pact_store_sqlite::SqliteCapabilityAuthority::open(path)
            .and_then(|authority| authority.status())
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?;
        return Ok(json!({
            "configured": true,
            "backend": "sqlite",
            "publicKey": status.public_key.to_hex(),
            "generation": status.generation,
            "rotatedAt": status.rotated_at,
            "appliesToFutureSessionsOnly": true,
            "trustedPublicKeys": status.trusted_public_keys.into_iter().map(|key| key.to_hex()).collect::<Vec<_>>(),
        }));
    }

    let Some(path) = state.factory.config.authority_seed_path.as_deref() else {
        return Ok(json!({
            "configured": false,
            "backend": Value::Null,
            "publicKey": Value::Null,
            "appliesToFutureSessionsOnly": true,
        }));
    };

    match authority_public_key_from_seed_file(path) {
        Ok(Some(public_key)) => Ok(json!({
            "configured": true,
            "backend": "seed_file",
            "publicKey": public_key.to_hex(),
            "appliesToFutureSessionsOnly": true,
            "trustedPublicKeys": vec![public_key.to_hex()],
        })),
        Ok(None) => Ok(json!({
            "configured": true,
            "backend": "seed_file",
            "publicKey": Value::Null,
            "materialized": false,
            "appliesToFutureSessionsOnly": true,
            "trustedPublicKeys": Vec::<String>::new(),
        })),
        Err(error) => Err(plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &error.to_string(),
        )),
    }
}

fn load_session_revocation_status(
    state: &RemoteAppState,
    capabilities: &[RemoteSessionCapability],
) -> Result<Vec<Value>, Response> {
    if let Some(client) = control_client(state)? {
        return capabilities
            .iter()
            .map(|capability| {
                client
                    .list_revocations(&RevocationQuery {
                        capability_id: Some(capability.id.clone()),
                        limit: Some(1),
                    })
                    .map(|response| {
                        json!({
                            "capabilityId": capability.id,
                            "issuerPublicKey": capability.issuer_public_key,
                            "subjectPublicKey": capability.subject_public_key,
                            "revoked": response.revoked.unwrap_or(false),
                        })
                    })
                    .map_err(|error| {
                        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                    })
            })
            .collect();
    }

    let store = open_revocation_store(state)?;
    capabilities
        .iter()
        .map(|capability| {
            store
                .is_revoked(&capability.id)
                .map(|revoked| {
                    json!({
                        "capabilityId": capability.id,
                        "issuerPublicKey": capability.issuer_public_key,
                        "subjectPublicKey": capability.subject_public_key,
                        "revoked": revoked,
                    })
                })
                .map_err(|error| {
                    plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                })
        })
        .collect()
}

fn validate_origin(headers: &HeaderMap) -> Result<(), Response> {
    let Some(origin) = headers.get(ORIGIN).and_then(|value| value.to_str().ok()) else {
        return Ok(());
    };
    let parsed = Url::parse(origin)
        .map_err(|_| plain_http_error(StatusCode::FORBIDDEN, "invalid Origin header"))?;
    let Some(host) = parsed.host_str() else {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "invalid Origin header",
        ));
    };
    let host = host.trim_matches('[').trim_matches(']');
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return Ok(());
    }

    Err(plain_http_error(
        StatusCode::FORBIDDEN,
        "origin not allowed",
    ))
}

fn validate_post_accept_header(headers: &HeaderMap) -> Result<(), Response> {
    let accept = headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if accept.contains("application/json") && accept.contains("text/event-stream") {
        return Ok(());
    }

    Err(plain_http_error(
        StatusCode::NOT_ACCEPTABLE,
        "POST requests must advertise both application/json and text/event-stream in Accept",
    ))
}

fn validate_get_accept_header(headers: &HeaderMap) -> Result<(), Response> {
    let accept = headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if accept.contains("text/event-stream") {
        return Ok(());
    }

    Err(plain_http_error(
        StatusCode::NOT_ACCEPTABLE,
        "GET requests must advertise text/event-stream in Accept",
    ))
}

fn validate_content_type(headers: &HeaderMap) -> Result<(), Response> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if content_type.starts_with("application/json") {
        return Ok(());
    }

    Err(plain_http_error(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "POST requests must use Content-Type: application/json",
    ))
}

fn validate_protocol_version(headers: &HeaderMap, session: &RemoteSession) -> Result<(), Response> {
    let Some(expected) = session.protocol_version() else {
        return Ok(());
    };
    let Some(actual) = headers
        .get(HeaderName::from_static(MCP_PROTOCOL_VERSION_HEADER))
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(());
    };

    if actual == expected {
        Ok(())
    } else {
        Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "invalid MCP-Protocol-Version for session",
        ))
    }
}

fn build_static_bearer_session_auth_context(
    headers: &HeaderMap,
    expected_token: &str,
) -> SessionAuthContext {
    let token_fingerprint = sha256_hex(expected_token.as_bytes());
    let principal = format!(
        "static-bearer:{}",
        &token_fingerprint[..token_fingerprint.len().min(16)]
    );
    let origin = headers
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);

    SessionAuthContext::streamable_http_static_bearer(principal, token_fingerprint, origin)
}

impl JwtBearerVerifier {
    fn authenticate_token(
        &self,
        token: &str,
        origin: Option<String>,
        protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    ) -> Result<SessionAuthContext, Response> {
        let (header, claims, signed_input, signature) =
            decode_jwt_parts(token, protected_resource_metadata)?;
        let alg = JwtSignatureAlgorithm::from_header(&header, protected_resource_metadata)?;
        if !self.key_source.verify(
            alg,
            &header,
            signed_input.as_bytes(),
            &signature,
            protected_resource_metadata,
        )? {
            return Err(unauthorized_bearer_response(
                "invalid JWT bearer signature",
                protected_resource_metadata,
            ));
        }

        let now = unix_now();
        if let Some(nbf) = claims.nbf {
            if now < nbf {
                return Err(unauthorized_bearer_response(
                    "JWT bearer token not yet valid",
                    protected_resource_metadata,
                ));
            }
        }
        if let Some(exp) = claims.exp {
            if now >= exp {
                return Err(unauthorized_bearer_response(
                    "JWT bearer token expired",
                    protected_resource_metadata,
                ));
            }
        }
        if let Some(expected_issuer) = self.issuer.as_deref() {
            if claims.iss.as_deref() != Some(expected_issuer) {
                return Err(unauthorized_bearer_response(
                    "JWT bearer issuer mismatch",
                    protected_resource_metadata,
                ));
            }
        }
        if let Some(expected_audience) = self.audience.as_deref() {
            if !claims.includes_audience_or_resource(expected_audience) {
                return Err(unauthorized_bearer_response(
                    "JWT bearer audience mismatch",
                    protected_resource_metadata,
                ));
            }
        }
        let scopes = claims.scopes();
        if !self.required_scopes.is_empty()
            && !self
                .required_scopes
                .iter()
                .all(|scope| scopes.iter().any(|granted| granted == scope))
        {
            return Err(unauthorized_bearer_response(
                "JWT bearer token is missing required scope",
                protected_resource_metadata,
            ));
        }

        let principal = Some(build_federated_principal(
            &claims,
            self.issuer.as_deref(),
            protected_resource_metadata,
            self.provider_profile,
        )?);
        let federated_claims = build_federated_claims(&claims, self.provider_profile);
        let matched_provider = matched_bearer_enterprise_provider(
            self.enterprise_provider_registry.as_deref(),
            claims.iss.as_deref().or(self.issuer.as_deref()),
            EnterpriseProviderKind::OidcJwks,
        );
        let enterprise_identity = principal.as_deref().map(|principal| {
            build_enterprise_identity_context(
                &claims,
                &federated_claims,
                principal,
                self.provider_profile,
                EnterpriseProviderKind::OidcJwks,
                matched_provider,
            )
        });
        let audience = self.audience.clone().or_else(|| {
            claims
                .primary_audience()
                .or_else(|| claims.resource.clone())
        });
        Ok(
            SessionAuthContext::streamable_http_oauth_bearer_with_claims(
                principal,
                claims.iss.clone(),
                claims.sub.clone(),
                audience,
                scopes,
                federated_claims,
                enterprise_identity,
                Some(sha256_hex(token.as_bytes())),
                origin,
            ),
        )
    }
}

impl IntrospectionBearerVerifier {
    async fn authenticate_token(
        &self,
        token: &str,
        origin: Option<String>,
        protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    ) -> Result<SessionAuthContext, Response> {
        let mut request = self
            .client
            .post(self.introspection_url.clone())
            .form(&[("token", token)]);
        if let (Some(client_id), Some(client_secret)) =
            (self.client_id.as_deref(), self.client_secret.as_deref())
        {
            request = request.basic_auth(client_id, Some(client_secret));
        }
        let response = request.send().await.map_err(|error| {
            plain_http_error(
                StatusCode::BAD_GATEWAY,
                &format!("token introspection endpoint unavailable: {error}"),
            )
        })?;
        if !response.status().is_success() {
            return Err(plain_http_error(
                StatusCode::BAD_GATEWAY,
                "token introspection endpoint returned an error",
            ));
        }
        let introspection = response
            .json::<OAuthIntrospectionResponse>()
            .await
            .map_err(|error| {
                plain_http_error(
                    StatusCode::BAD_GATEWAY,
                    &format!("token introspection endpoint returned invalid JSON: {error}"),
                )
            })?;
        self.session_auth_context_from_introspection(
            token,
            introspection,
            origin,
            protected_resource_metadata,
        )
    }

    fn session_auth_context_from_introspection(
        &self,
        token: &str,
        introspection: OAuthIntrospectionResponse,
        origin: Option<String>,
        protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    ) -> Result<SessionAuthContext, Response> {
        if !introspection.active {
            return Err(unauthorized_bearer_response(
                "bearer token is inactive",
                protected_resource_metadata,
            ));
        }
        if let Some(token_type) = introspection.token_type.as_deref() {
            if !matches!(
                token_type,
                "Bearer"
                    | "bearer"
                    | "access_token"
                    | "urn:ietf:params:oauth:token-type:access_token"
            ) {
                return Err(unauthorized_bearer_response(
                    "introspection returned unsupported token_type",
                    protected_resource_metadata,
                ));
            }
        }

        let claims = introspection.claims;
        let now = unix_now();
        if let Some(nbf) = claims.nbf {
            if now < nbf {
                return Err(unauthorized_bearer_response(
                    "bearer token not yet valid",
                    protected_resource_metadata,
                ));
            }
        }
        if let Some(exp) = claims.exp {
            if now >= exp {
                return Err(unauthorized_bearer_response(
                    "bearer token expired",
                    protected_resource_metadata,
                ));
            }
        }
        if let Some(expected_issuer) = self.issuer.as_deref() {
            if let Some(actual_issuer) = claims.iss.as_deref() {
                if actual_issuer != expected_issuer {
                    return Err(unauthorized_bearer_response(
                        "bearer token issuer mismatch",
                        protected_resource_metadata,
                    ));
                }
            }
        }
        if let Some(expected_audience) = self.audience.as_deref() {
            if !claims.includes_audience_or_resource(expected_audience) {
                return Err(unauthorized_bearer_response(
                    "bearer token audience mismatch",
                    protected_resource_metadata,
                ));
            }
        }
        let scopes = claims.scopes();
        if !self.required_scopes.is_empty()
            && !self
                .required_scopes
                .iter()
                .all(|scope| scopes.iter().any(|granted| granted == scope))
        {
            return Err(unauthorized_bearer_response(
                "bearer token is missing required scope",
                protected_resource_metadata,
            ));
        }

        let principal = Some(build_federated_principal(
            &claims,
            self.issuer.as_deref(),
            protected_resource_metadata,
            self.provider_profile,
        )?);
        let federated_claims = build_federated_claims(&claims, self.provider_profile);
        let matched_provider = matched_bearer_enterprise_provider(
            self.enterprise_provider_registry.as_deref(),
            claims.iss.as_deref().or(self.issuer.as_deref()),
            EnterpriseProviderKind::OauthIntrospection,
        );
        let enterprise_identity = principal.as_deref().map(|principal| {
            build_enterprise_identity_context(
                &claims,
                &federated_claims,
                principal,
                self.provider_profile,
                EnterpriseProviderKind::OauthIntrospection,
                matched_provider,
            )
        });
        let audience = self.audience.clone().or_else(|| {
            claims
                .primary_audience()
                .or_else(|| claims.resource.clone())
        });
        Ok(
            SessionAuthContext::streamable_http_oauth_bearer_with_claims(
                principal,
                claims.iss.clone().or_else(|| self.issuer.clone()),
                claims.sub.clone(),
                audience,
                scopes,
                federated_claims,
                enterprise_identity,
                Some(sha256_hex(token.as_bytes())),
                origin,
            ),
        )
    }
}

impl JwtVerificationKeySource {
    fn verify(
        &self,
        alg: JwtSignatureAlgorithm,
        header: &JwtHeader,
        signed_input: &[u8],
        signature: &[u8],
        protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    ) -> Result<bool, Response> {
        match self {
            Self::Static(public_key) => {
                if alg != JwtSignatureAlgorithm::EdDsa {
                    return Err(unauthorized_bearer_response(
                        "JWT bearer token uses unsupported alg for configured static key",
                        protected_resource_metadata,
                    ));
                }
                Ok(verify_ed25519_jwt_signature(
                    public_key,
                    signed_input,
                    signature,
                ))
            }
            Self::Jwks(keys) => {
                let public_key =
                    keys.resolve(header.kid.as_deref(), alg, protected_resource_metadata)?;
                Ok(public_key.verify(alg, signed_input, signature))
            }
        }
    }
}

impl JwtJwksKeySet {
    fn resolve<'a>(
        &'a self,
        kid: Option<&str>,
        alg: JwtSignatureAlgorithm,
        protected_resource_metadata: Option<&ProtectedResourceMetadata>,
    ) -> Result<&'a JwtResolvedJwkPublicKey, Response> {
        if let Some(kid) = kid {
            let key = self.keys_by_kid.get(kid).ok_or_else(|| {
                unauthorized_bearer_response(
                    "JWT bearer kid is not trusted",
                    protected_resource_metadata,
                )
            })?;
            if key.supports_alg(alg) {
                return Ok(key);
            }
            return Err(unauthorized_bearer_response(
                "trusted JWT key does not support the requested alg",
                protected_resource_metadata,
            ));
        }
        let mut compatible = self
            .keys_by_kid
            .values()
            .chain(self.anonymous_keys.iter())
            .filter(|key| key.supports_alg(alg));
        let Some(first) = compatible.next() else {
            return Err(unauthorized_bearer_response(
                "identity provider exposes no trusted key for the requested alg",
                protected_resource_metadata,
            ));
        };
        if compatible.next().is_none() {
            return Ok(first);
        }
        Err(unauthorized_bearer_response(
            "JWT bearer token missing kid for multi-key identity provider",
            protected_resource_metadata,
        ))
    }
}

impl JwtResolvedJwkPublicKey {
    fn supports_alg(&self, alg: JwtSignatureAlgorithm) -> bool {
        if let Some(alg_hint) = self.alg_hint.as_deref() {
            if alg_hint != alg.as_str() {
                return false;
            }
        }
        matches!(
            (&self.key, alg),
            (
                JwtResolvedPublicKey::Ed25519(_),
                JwtSignatureAlgorithm::EdDsa
            ) | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Rs256)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Rs384)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Rs512)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Ps256)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Ps384)
                | (JwtResolvedPublicKey::Rsa(_), JwtSignatureAlgorithm::Ps512)
                | (JwtResolvedPublicKey::P256(_), JwtSignatureAlgorithm::Es256)
                | (JwtResolvedPublicKey::P384(_), JwtSignatureAlgorithm::Es384)
        )
    }

    fn verify(&self, alg: JwtSignatureAlgorithm, signed_input: &[u8], signature: &[u8]) -> bool {
        if !self.supports_alg(alg) {
            return false;
        }
        match (&self.key, alg) {
            (JwtResolvedPublicKey::Ed25519(public_key), JwtSignatureAlgorithm::EdDsa) => {
                verify_ed25519_jwt_signature(public_key, signed_input, signature)
            }
            (JwtResolvedPublicKey::P256(public_key), JwtSignatureAlgorithm::Es256) => {
                P256Signature::from_slice(signature)
                    .ok()
                    .and_then(|signature| public_key.verify(signed_input, &signature).ok())
                    .is_some()
            }
            (JwtResolvedPublicKey::P384(public_key), JwtSignatureAlgorithm::Es384) => {
                P384Signature::from_slice(signature)
                    .ok()
                    .and_then(|signature| public_key.verify(signed_input, &signature).ok())
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Rs256) => {
                RsaPkcs1v15Signature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPkcs1v15VerifyingKey::<Sha256>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Rs384) => {
                RsaPkcs1v15Signature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPkcs1v15VerifyingKey::<sha2::Sha384>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Rs512) => {
                RsaPkcs1v15Signature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPkcs1v15VerifyingKey::<sha2::Sha512>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Ps256) => {
                RsaPssSignature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPssVerifyingKey::<Sha256>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Ps384) => {
                RsaPssSignature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPssVerifyingKey::<sha2::Sha384>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            (JwtResolvedPublicKey::Rsa(public_key), JwtSignatureAlgorithm::Ps512) => {
                RsaPssSignature::try_from(signature)
                    .ok()
                    .and_then(|signature| {
                        RsaPssVerifyingKey::<sha2::Sha512>::new(public_key.clone())
                            .verify(signed_input, &signature)
                            .ok()
                    })
                    .is_some()
            }
            _ => false,
        }
    }
}

impl JwtClaims {
    fn scopes(&self) -> Vec<String> {
        let mut scopes = self
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .filter(|scope| !scope.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        scopes.extend(self.scp.iter().cloned());
        scopes.sort();
        scopes.dedup();
        scopes
    }

    fn includes_audience(&self, expected: &str) -> bool {
        match &self.aud {
            Some(JwtAudience::Single(audience)) => audience == expected,
            Some(JwtAudience::Multiple(audiences)) => audiences.iter().any(|aud| aud == expected),
            None => false,
        }
    }

    fn includes_audience_or_resource(&self, expected: &str) -> bool {
        self.includes_audience(expected) || self.resource.as_deref() == Some(expected)
    }

    fn primary_audience(&self) -> Option<String> {
        match &self.aud {
            Some(JwtAudience::Single(audience)) => Some(audience.clone()),
            Some(JwtAudience::Multiple(audiences)) => audiences.first().cloned(),
            None => None,
        }
    }
}

fn decode_jwt_parts(
    token: &str,
    protected_resource_metadata: Option<&ProtectedResourceMetadata>,
) -> Result<(JwtHeader, JwtClaims, String, Vec<u8>), Response> {
    let mut parts = token.split('.');
    let Some(header_b64) = parts.next() else {
        return Err(unauthorized_bearer_response(
            "invalid JWT bearer token",
            protected_resource_metadata,
        ));
    };
    let Some(payload_b64) = parts.next() else {
        return Err(unauthorized_bearer_response(
            "invalid JWT bearer token",
            protected_resource_metadata,
        ));
    };
    let Some(signature_b64) = parts.next() else {
        return Err(unauthorized_bearer_response(
            "invalid JWT bearer token",
            protected_resource_metadata,
        ));
    };
    if parts.next().is_some() {
        return Err(unauthorized_bearer_response(
            "invalid JWT bearer token",
            protected_resource_metadata,
        ));
    }

    let header: JwtHeader =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).map_err(|_| {
            unauthorized_bearer_response("invalid JWT header", protected_resource_metadata)
        })?)
        .map_err(|_| {
            unauthorized_bearer_response("invalid JWT header", protected_resource_metadata)
        })?;
    let claims: JwtClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).map_err(|_| {
            unauthorized_bearer_response("invalid JWT payload", protected_resource_metadata)
        })?)
        .map_err(|_| {
            unauthorized_bearer_response("invalid JWT payload", protected_resource_metadata)
        })?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64).map_err(|_| {
        unauthorized_bearer_response("invalid JWT signature", protected_resource_metadata)
    })?;
    Ok((
        header,
        claims,
        format!("{header_b64}.{payload_b64}"),
        signature_bytes,
    ))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn session_now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn read_session_lifecycle_policy() -> SessionLifecyclePolicy {
    SessionLifecyclePolicy {
        idle_expiry_millis: read_env_u64(
            SESSION_IDLE_EXPIRY_ENV,
            DEFAULT_SESSION_IDLE_EXPIRY_MILLIS,
        ),
        drain_grace_millis: read_env_u64(
            SESSION_DRAIN_GRACE_ENV,
            DEFAULT_SESSION_DRAIN_GRACE_MILLIS,
        ),
        reaper_interval_millis: read_env_u64(
            SESSION_REAPER_INTERVAL_ENV,
            DEFAULT_SESSION_REAPER_INTERVAL_MILLIS,
        ),
        tombstone_retention_millis: read_env_u64(
            SESSION_TOMBSTONE_RETENTION_ENV,
            DEFAULT_SESSION_TOMBSTONE_RETENTION_MILLIS,
        ),
    }
}

fn read_env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn terminal_session_response(state: RemoteSessionState) -> Response {
    match state {
        RemoteSessionState::Initializing => {
            plain_http_error(StatusCode::CONFLICT, "MCP session is still initializing")
        }
        RemoteSessionState::Ready => plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "active session was resolved as terminal",
        ),
        RemoteSessionState::Draining => plain_http_error(
            StatusCode::CONFLICT,
            "MCP session is draining and must not be resumed",
        ),
        RemoteSessionState::Deleted => plain_http_error(
            StatusCode::GONE,
            "MCP session was deleted and must be re-initialized",
        ),
        RemoteSessionState::Expired => plain_http_error(
            StatusCode::GONE,
            "MCP session expired and must be re-initialized",
        ),
        RemoteSessionState::Closed => plain_http_error(
            StatusCode::GONE,
            "MCP session was shut down and must be re-initialized",
        ),
    }
}

fn plain_http_error(status: StatusCode, message: &str) -> Response {
    (status, message.to_string()).into_response()
}

fn jsonrpc_http_error(status: StatusCode, code: i64, message: &str) -> Response {
    let mut response = (
        status,
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message,
            }
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer as _;
    use pact_core::session::{SessionAuthMethod, SessionTransport};
    use rsa::pkcs1v15::SigningKey as RsaPkcs1v15SigningKey;
    use rsa::pss::BlindedSigningKey as RsaPssSigningKey;
    use rsa::rand_core::OsRng;
    use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _};
    use serde_json::json;

    fn sign_jwt_with_header(
        header: Value,
        claims: &serde_json::Value,
        sign: impl Fn(&[u8]) -> Vec<u8>,
    ) -> String {
        let header =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("serialize JWT header"));
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("serialize JWT claims"));
        let signing_input = format!("{header}.{payload}");
        let signature = URL_SAFE_NO_PAD.encode(sign(signing_input.as_bytes()));
        format!("{signing_input}.{signature}")
    }

    fn sign_jwt_rs256(
        private_key: &rsa::RsaPrivateKey,
        claims: &serde_json::Value,
        kid: &str,
    ) -> String {
        let signing_key = RsaPkcs1v15SigningKey::<Sha256>::new(private_key.clone());
        sign_jwt_with_header(
            json!({
                "alg": "RS256",
                "typ": "JWT",
                "kid": kid,
            }),
            claims,
            |message| signing_key.sign(message).to_vec(),
        )
    }

    fn sign_jwt_es256(
        signing_key: &p256::ecdsa::SigningKey,
        claims: &serde_json::Value,
        kid: &str,
    ) -> String {
        sign_jwt_with_header(
            json!({
                "alg": "ES256",
                "typ": "JWT",
                "kid": kid,
            }),
            claims,
            |message| {
                let signature: p256::ecdsa::Signature = signing_key.sign(message);
                signature.to_bytes().to_vec()
            },
        )
    }

    fn sign_jwt_ps256(
        private_key: &rsa::RsaPrivateKey,
        claims: &serde_json::Value,
        kid: &str,
    ) -> String {
        let signing_key = RsaPssSigningKey::<Sha256>::new(private_key.clone());
        sign_jwt_with_header(
            json!({
                "alg": "PS256",
                "typ": "JWT",
                "kid": kid,
            }),
            claims,
            |message| signing_key.sign_with_rng(&mut OsRng, message).to_vec(),
        )
    }

    fn sign_jwt_es384(
        signing_key: &p384::ecdsa::SigningKey,
        claims: &serde_json::Value,
        kid: &str,
    ) -> String {
        sign_jwt_with_header(
            json!({
                "alg": "ES384",
                "typ": "JWT",
                "kid": kid,
            }),
            claims,
            |message| {
                let signature: p384::ecdsa::Signature = signing_key.sign(message);
                signature.to_bytes().to_vec()
            },
        )
    }

    fn test_introspection_verifier(
        issuer: Option<&str>,
        audience: Option<&str>,
        required_scopes: &[&str],
    ) -> IntrospectionBearerVerifier {
        IntrospectionBearerVerifier {
            client: HttpClient::builder().build().expect("build http client"),
            introspection_url: Url::parse("http://127.0.0.1:9/introspect")
                .expect("parse introspection url"),
            client_id: None,
            client_secret: None,
            issuer: issuer.map(ToOwned::to_owned),
            audience: audience.map(ToOwned::to_owned),
            required_scopes: required_scopes
                .iter()
                .map(|scope| (*scope).to_string())
                .collect(),
            provider_profile: JwtProviderProfile::Generic,
            enterprise_provider_registry: None,
        }
    }

    #[test]
    fn remote_session_auth_context_uses_static_bearer_fingerprint_and_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("http://localhost:3000"));

        let auth_context = build_static_bearer_session_auth_context(&headers, "test-token");
        assert_eq!(auth_context.transport, SessionTransport::StreamableHttp);
        assert_eq!(
            auth_context.origin.as_deref(),
            Some("http://localhost:3000")
        );
        assert!(auth_context.is_authenticated());

        match &auth_context.method {
            SessionAuthMethod::StaticBearer {
                principal,
                token_fingerprint,
            } => {
                assert_eq!(token_fingerprint, &sha256_hex(b"test-token"));
                assert!(principal.starts_with("static-bearer:"));
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn jwt_bearer_verifier_builds_oauth_session_auth_context() {
        let keypair = Keypair::generate();
        let token = sign_jwt(
            &keypair,
            &json!({
                "iss": "https://issuer.example",
                "sub": "user-123",
                "aud": "pact-mcp",
                "scope": "tools.read tools.write",
                "client_id": "client-abc",
                "tid": "tenant-123",
                "org_id": "org-789",
                "groups": ["ops", "eng"],
                "roles": ["reviewer", "operator"],
                "exp": unix_now() + 300,
            }),
        );
        let verifier = JwtBearerVerifier {
            key_source: JwtVerificationKeySource::Static(keypair.public_key()),
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("pact-mcp".to_string()),
            required_scopes: vec![],
            provider_profile: JwtProviderProfile::Generic,
            enterprise_provider_registry: None,
        };

        let auth_context = verifier
            .authenticate_token(&token, Some("http://localhost:3000".to_string()), None)
            .unwrap();
        assert_eq!(auth_context.transport, SessionTransport::StreamableHttp);
        assert_eq!(
            auth_context.origin.as_deref(),
            Some("http://localhost:3000")
        );

        match &auth_context.method {
            SessionAuthMethod::OAuthBearer {
                principal,
                issuer,
                subject,
                audience,
                scopes,
                federated_claims,
                enterprise_identity,
                token_fingerprint,
            } => {
                assert_eq!(
                    principal.as_deref(),
                    Some("oidc:https://issuer.example#sub:user-123")
                );
                assert_eq!(issuer.as_deref(), Some("https://issuer.example"));
                assert_eq!(subject.as_deref(), Some("user-123"));
                assert_eq!(audience.as_deref(), Some("pact-mcp"));
                assert_eq!(
                    scopes,
                    &vec!["tools.read".to_string(), "tools.write".to_string()]
                );
                assert_eq!(federated_claims.client_id.as_deref(), Some("client-abc"));
                assert_eq!(federated_claims.tenant_id.as_deref(), Some("tenant-123"));
                assert_eq!(federated_claims.organization_id.as_deref(), Some("org-789"));
                assert_eq!(
                    federated_claims.groups,
                    vec!["eng".to_string(), "ops".to_string()]
                );
                assert_eq!(
                    federated_claims.roles,
                    vec!["operator".to_string(), "reviewer".to_string()]
                );
                assert_eq!(
                    token_fingerprint.as_deref(),
                    Some(sha256_hex(token.as_bytes()).as_str())
                );
                let enterprise_identity = enterprise_identity
                    .as_ref()
                    .expect("enterprise identity should be populated");
                assert_eq!(enterprise_identity.provider_id, "https://issuer.example");
                assert_eq!(enterprise_identity.provider_record_id, None);
                assert_eq!(enterprise_identity.provider_kind, "oidc_jwks");
                assert_eq!(
                    enterprise_identity.federation_method,
                    EnterpriseFederationMethod::Jwt
                );
                assert_eq!(
                    enterprise_identity.principal,
                    "oidc:https://issuer.example#sub:user-123"
                );
                assert_eq!(
                    enterprise_identity.subject_key,
                    derive_enterprise_subject_key(
                        "https://issuer.example",
                        "oidc:https://issuer.example#sub:user-123",
                    )
                );
                assert_eq!(enterprise_identity.tenant_id.as_deref(), Some("tenant-123"));
                assert_eq!(
                    enterprise_identity.organization_id.as_deref(),
                    Some("org-789")
                );
                assert_eq!(
                    enterprise_identity.attribute_sources.get("principal"),
                    Some(&"sub".to_string())
                );
                assert_eq!(
                    enterprise_identity.attribute_sources.get("groups"),
                    Some(&"groups".to_string())
                );
                assert_eq!(
                    enterprise_identity.attribute_sources.get("roles"),
                    Some(&"roles".to_string())
                );
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn jwt_bearer_verifier_authenticates_rs256_jwks_token() {
        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_key = private_key.to_public_key();
        let token = sign_jwt_rs256(
            &private_key,
            &json!({
                "iss": "https://issuer.example",
                "sub": "user-rsa",
                "aud": "pact-mcp",
                "scope": "tools.read",
                "exp": unix_now() + 300,
            }),
            "rsa-key-1",
        );
        let verifier = JwtBearerVerifier {
            key_source: JwtVerificationKeySource::Jwks(JwtJwksKeySet {
                keys_by_kid: HashMap::from([(
                    "rsa-key-1".to_string(),
                    JwtResolvedJwkPublicKey {
                        key: JwtResolvedPublicKey::Rsa(public_key),
                        alg_hint: Some("RS256".to_string()),
                    },
                )]),
                anonymous_keys: vec![],
            }),
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("pact-mcp".to_string()),
            required_scopes: vec![],
            provider_profile: JwtProviderProfile::Generic,
            enterprise_provider_registry: None,
        };

        let auth_context = verifier
            .authenticate_token(&token, Some("http://localhost:3000".to_string()), None)
            .unwrap();
        match &auth_context.method {
            SessionAuthMethod::OAuthBearer {
                principal, subject, ..
            } => {
                assert_eq!(
                    principal.as_deref(),
                    Some("oidc:https://issuer.example#sub:user-rsa")
                );
                assert_eq!(subject.as_deref(), Some("user-rsa"));
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn jwt_bearer_verifier_authenticates_es256_jwks_token() {
        let signing_key =
            p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let token = sign_jwt_es256(
            &signing_key,
            &json!({
                "iss": "https://issuer.example",
                "sub": "user-ec",
                "aud": "pact-mcp",
                "scope": "tools.read",
                "exp": unix_now() + 300,
            }),
            "ec-key-1",
        );
        let verifier = JwtBearerVerifier {
            key_source: JwtVerificationKeySource::Jwks(JwtJwksKeySet {
                keys_by_kid: HashMap::from([(
                    "ec-key-1".to_string(),
                    JwtResolvedJwkPublicKey {
                        key: JwtResolvedPublicKey::P256(*signing_key.verifying_key()),
                        alg_hint: Some("ES256".to_string()),
                    },
                )]),
                anonymous_keys: vec![],
            }),
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("pact-mcp".to_string()),
            required_scopes: vec![],
            provider_profile: JwtProviderProfile::Generic,
            enterprise_provider_registry: None,
        };

        let auth_context = verifier.authenticate_token(&token, None, None).unwrap();
        match &auth_context.method {
            SessionAuthMethod::OAuthBearer {
                principal, subject, ..
            } => {
                assert_eq!(
                    principal.as_deref(),
                    Some("oidc:https://issuer.example#sub:user-ec")
                );
                assert_eq!(subject.as_deref(), Some("user-ec"));
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn jwt_bearer_verifier_authenticates_ps256_jwks_token() {
        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_key = private_key.to_public_key();
        let token = sign_jwt_ps256(
            &private_key,
            &json!({
                "iss": "https://issuer.example",
                "sub": "user-pss",
                "aud": "pact-mcp",
                "scope": "tools.read",
                "exp": unix_now() + 300,
            }),
            "pss-key-1",
        );
        let verifier = JwtBearerVerifier {
            key_source: JwtVerificationKeySource::Jwks(JwtJwksKeySet {
                keys_by_kid: HashMap::from([(
                    "pss-key-1".to_string(),
                    JwtResolvedJwkPublicKey {
                        key: JwtResolvedPublicKey::Rsa(public_key),
                        alg_hint: Some("PS256".to_string()),
                    },
                )]),
                anonymous_keys: vec![],
            }),
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("pact-mcp".to_string()),
            required_scopes: vec![],
            provider_profile: JwtProviderProfile::Generic,
            enterprise_provider_registry: None,
        };

        let auth_context = verifier.authenticate_token(&token, None, None).unwrap();
        match &auth_context.method {
            SessionAuthMethod::OAuthBearer {
                principal, subject, ..
            } => {
                assert_eq!(
                    principal.as_deref(),
                    Some("oidc:https://issuer.example#sub:user-pss")
                );
                assert_eq!(subject.as_deref(), Some("user-pss"));
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn jwt_bearer_verifier_authenticates_es384_jwks_token() {
        let signing_key =
            p384::ecdsa::SigningKey::random(&mut p384::elliptic_curve::rand_core::OsRng);
        let token = sign_jwt_es384(
            &signing_key,
            &json!({
                "iss": "https://issuer.example",
                "sub": "user-es384",
                "aud": "pact-mcp",
                "scope": "tools.read",
                "exp": unix_now() + 300,
            }),
            "ec384-key-1",
        );
        let verifier = JwtBearerVerifier {
            key_source: JwtVerificationKeySource::Jwks(JwtJwksKeySet {
                keys_by_kid: HashMap::from([(
                    "ec384-key-1".to_string(),
                    JwtResolvedJwkPublicKey {
                        key: JwtResolvedPublicKey::P384(*signing_key.verifying_key()),
                        alg_hint: Some("ES384".to_string()),
                    },
                )]),
                anonymous_keys: vec![],
            }),
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("pact-mcp".to_string()),
            required_scopes: vec![],
            provider_profile: JwtProviderProfile::Generic,
            enterprise_provider_registry: None,
        };

        let auth_context = verifier.authenticate_token(&token, None, None).unwrap();
        match &auth_context.method {
            SessionAuthMethod::OAuthBearer {
                principal, subject, ..
            } => {
                assert_eq!(
                    principal.as_deref(),
                    Some("oidc:https://issuer.example#sub:user-es384")
                );
                assert_eq!(subject.as_deref(), Some("user-es384"));
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn introspection_bearer_verifier_accepts_active_token_with_resource_claim() {
        let verifier = test_introspection_verifier(
            Some("https://issuer.example"),
            Some("pact-mcp"),
            &["mcp:invoke"],
        );
        let auth_context = verifier
            .session_auth_context_from_introspection(
                "opaque-token",
                OAuthIntrospectionResponse {
                    active: true,
                    token_type: Some("Bearer".to_string()),
                    claims: JwtClaims {
                        iss: Some("https://issuer.example".to_string()),
                        sub: Some("opaque-user".to_string()),
                        aud: None,
                        scope: Some("mcp:invoke tools.read".to_string()),
                        scp: vec![],
                        client_id: Some("client-123".to_string()),
                        oid: None,
                        azp: None,
                        appid: None,
                        tid: Some("tenant-123".to_string()),
                        tenant_id: None,
                        org_id: Some("org-789".to_string()),
                        organization_id: None,
                        groups: vec!["ops".to_string(), "eng".to_string()],
                        roles: vec!["operator".to_string()],
                        resource: Some("pact-mcp".to_string()),
                        exp: Some(unix_now() + 300),
                        nbf: None,
                    },
                },
                Some("http://localhost:3000".to_string()),
                None,
            )
            .unwrap();
        match &auth_context.method {
            SessionAuthMethod::OAuthBearer {
                principal,
                issuer,
                subject,
                audience,
                scopes,
                federated_claims,
                enterprise_identity,
                token_fingerprint,
            } => {
                assert_eq!(
                    principal.as_deref(),
                    Some("oidc:https://issuer.example#sub:opaque-user")
                );
                assert_eq!(issuer.as_deref(), Some("https://issuer.example"));
                assert_eq!(subject.as_deref(), Some("opaque-user"));
                assert_eq!(audience.as_deref(), Some("pact-mcp"));
                assert_eq!(
                    scopes,
                    &vec!["mcp:invoke".to_string(), "tools.read".to_string()]
                );
                assert_eq!(federated_claims.client_id.as_deref(), Some("client-123"));
                assert_eq!(federated_claims.tenant_id.as_deref(), Some("tenant-123"));
                assert_eq!(federated_claims.organization_id.as_deref(), Some("org-789"));
                assert_eq!(
                    federated_claims.groups,
                    vec!["eng".to_string(), "ops".to_string()]
                );
                assert_eq!(federated_claims.roles, vec!["operator".to_string()]);
                assert_eq!(
                    token_fingerprint.as_deref(),
                    Some(sha256_hex(b"opaque-token").as_str())
                );
                let enterprise_identity = enterprise_identity
                    .as_ref()
                    .expect("enterprise identity should be populated");
                assert_eq!(enterprise_identity.provider_kind, "oauth_introspection");
                assert_eq!(
                    enterprise_identity.federation_method,
                    EnterpriseFederationMethod::Introspection
                );
                assert_eq!(
                    enterprise_identity.subject_key,
                    derive_enterprise_subject_key(
                        "https://issuer.example",
                        "oidc:https://issuer.example#sub:opaque-user",
                    )
                );
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn introspection_bearer_verifier_rejects_inactive_token() {
        let verifier = test_introspection_verifier(None, None, &[]);
        let error = verifier
            .session_auth_context_from_introspection(
                "opaque-token",
                OAuthIntrospectionResponse {
                    active: false,
                    token_type: Some("Bearer".to_string()),
                    claims: JwtClaims {
                        iss: None,
                        sub: Some("opaque-user".to_string()),
                        aud: None,
                        scope: None,
                        scp: vec![],
                        client_id: None,
                        oid: None,
                        azp: None,
                        appid: None,
                        tid: None,
                        tenant_id: None,
                        org_id: None,
                        organization_id: None,
                        groups: Vec::new(),
                        roles: Vec::new(),
                        resource: None,
                        exp: None,
                        nbf: None,
                    },
                },
                None,
                None,
            )
            .unwrap_err();
        assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn build_federated_principal_prefers_subject_over_client_id() {
        let principal = build_federated_principal(
            &JwtClaims {
                iss: Some("https://issuer.example/".to_string()),
                sub: Some("user-123".to_string()),
                aud: None,
                scope: None,
                scp: vec![],
                client_id: Some("client-abc".to_string()),
                oid: None,
                azp: None,
                appid: None,
                tid: None,
                tenant_id: None,
                org_id: None,
                organization_id: None,
                groups: Vec::new(),
                roles: Vec::new(),
                resource: None,
                exp: None,
                nbf: None,
            },
            None,
            None,
            JwtProviderProfile::Generic,
        )
        .unwrap();
        assert_eq!(principal, "oidc:https://issuer.example#sub:user-123");
    }

    #[test]
    fn build_federated_principal_azure_ad_prefers_oid_and_appid() {
        let principal = build_federated_principal(
            &JwtClaims {
                iss: Some("https://login.microsoftonline.com/example/v2.0".to_string()),
                sub: Some("subject-123".to_string()),
                aud: None,
                scope: None,
                scp: vec![],
                client_id: None,
                oid: Some("object-456".to_string()),
                azp: None,
                appid: Some("app-789".to_string()),
                tid: None,
                tenant_id: None,
                org_id: None,
                organization_id: None,
                groups: Vec::new(),
                roles: Vec::new(),
                resource: None,
                exp: None,
                nbf: None,
            },
            None,
            None,
            JwtProviderProfile::AzureAd,
        )
        .unwrap();
        assert_eq!(
            principal,
            "oidc:https://login.microsoftonline.com/example/v2.0#oid:object-456"
        );
    }

    #[test]
    fn build_federated_claims_normalizes_enterprise_identity_metadata() {
        let federated_claims = build_federated_claims(
            &JwtClaims {
                iss: Some("https://issuer.example".to_string()),
                sub: Some("user-123".to_string()),
                aud: None,
                scope: None,
                scp: vec![],
                client_id: None,
                oid: Some("object-456".to_string()),
                azp: Some("client-azp".to_string()),
                appid: Some("client-app".to_string()),
                tid: Some("tenant-123".to_string()),
                tenant_id: Some("tenant-fallback".to_string()),
                org_id: Some("org-789".to_string()),
                organization_id: Some("org-fallback".to_string()),
                groups: vec![
                    " ops ".to_string(),
                    "eng".to_string(),
                    "eng".to_string(),
                    "".to_string(),
                ],
                roles: vec![" reviewer ".to_string(), "operator".to_string()],
                resource: None,
                exp: None,
                nbf: None,
            },
            JwtProviderProfile::AzureAd,
        );
        assert_eq!(federated_claims.client_id.as_deref(), Some("client-azp"));
        assert_eq!(federated_claims.object_id.as_deref(), Some("object-456"));
        assert_eq!(federated_claims.tenant_id.as_deref(), Some("tenant-123"));
        assert_eq!(federated_claims.organization_id.as_deref(), Some("org-789"));
        assert_eq!(
            federated_claims.groups,
            vec!["eng".to_string(), "ops".to_string()]
        );
        assert_eq!(
            federated_claims.roles,
            vec!["operator".to_string(), "reviewer".to_string()]
        );
    }

    #[test]
    fn provider_profile_can_derive_standard_oidc_discovery_url_from_issuer() {
        let config = RemoteServeHttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            auth_token: None,
            auth_jwt_public_key: Some(Keypair::generate().public_key().to_hex()),
            auth_jwt_discovery_url: None,
            auth_introspection_url: None,
            auth_introspection_client_id: None,
            auth_introspection_client_secret: None,
            auth_jwt_provider_profile: Some(JwtProviderProfile::Okta),
            auth_server_seed_path: None,
            identity_federation_seed_path: None,
            enterprise_providers_file: None,
            auth_jwt_issuer: Some("https://id.example.com/oauth2/default".to_string()),
            auth_jwt_audience: None,
            admin_token: Some("admin-token".to_string()),
            control_url: None,
            control_token: None,
            public_base_url: None,
            auth_servers: vec![],
            auth_authorization_endpoint: None,
            auth_token_endpoint: None,
            auth_registration_endpoint: None,
            auth_jwks_uri: None,
            auth_scopes: vec![],
            auth_subject: "operator".to_string(),
            auth_code_ttl_secs: 300,
            auth_access_token_ttl_secs: 600,
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            session_db_path: None,
            policy_path: PathBuf::from("policy.yaml"),
            server_id: "srv".to_string(),
            server_name: "srv".to_string(),
            server_version: "0.1.0".to_string(),
            manifest_public_key: None,
            page_size: 50,
            tools_list_changed: false,
            shared_hosted_owner: false,
            wrapped_command: "python3".to_string(),
            wrapped_args: vec!["mock.py".to_string()],
        };

        let discovery_url = resolve_identity_provider_discovery_url(&config)
            .unwrap()
            .expect("discovery url");
        assert_eq!(
            discovery_url.as_str(),
            "https://id.example.com/oauth2/default/.well-known/openid-configuration"
        );
    }

    #[test]
    fn identity_federation_derives_stable_keypair_per_principal() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seed_path = std::env::temp_dir().join(format!(
            "pact-identity-federation-seed-{}-{nonce}.seed",
            std::process::id()
        ));

        let first =
            derive_federated_agent_keypair(&seed_path, "oidc:https://issuer.example#sub:user-123")
                .unwrap();
        let second =
            derive_federated_agent_keypair(&seed_path, "oidc:https://issuer.example#sub:user-123")
                .unwrap();
        let other =
            derive_federated_agent_keypair(&seed_path, "oidc:https://issuer.example#sub:user-456")
                .unwrap();

        assert_eq!(first.public_key().to_hex(), second.public_key().to_hex());
        assert_ne!(first.public_key().to_hex(), other.public_key().to_hex());
    }

    #[test]
    fn jwt_remote_auth_requires_separate_admin_token() {
        let config = RemoteServeHttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            auth_token: None,
            auth_jwt_public_key: Some(Keypair::generate().public_key().to_hex()),
            auth_jwt_discovery_url: None,
            auth_introspection_url: None,
            auth_introspection_client_id: None,
            auth_introspection_client_secret: None,
            auth_jwt_provider_profile: None,
            auth_server_seed_path: None,
            identity_federation_seed_path: None,
            enterprise_providers_file: None,
            auth_jwt_issuer: None,
            auth_jwt_audience: None,
            admin_token: None,
            control_url: None,
            control_token: None,
            public_base_url: None,
            auth_servers: vec![],
            auth_authorization_endpoint: None,
            auth_token_endpoint: None,
            auth_registration_endpoint: None,
            auth_jwks_uri: None,
            auth_scopes: vec![],
            auth_subject: "operator".to_string(),
            auth_code_ttl_secs: 300,
            auth_access_token_ttl_secs: 600,
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            session_db_path: None,
            policy_path: PathBuf::from("policy.yaml"),
            server_id: "srv".to_string(),
            server_name: "srv".to_string(),
            server_version: "0.1.0".to_string(),
            manifest_public_key: None,
            page_size: 50,
            tools_list_changed: false,
            shared_hosted_owner: false,
            wrapped_command: "python3".to_string(),
            wrapped_args: vec!["mock.py".to_string()],
        };

        let error = build_remote_auth_state(&config, "127.0.0.1:0".parse().unwrap(), None, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("--admin-token"));
    }

    #[test]
    fn shared_upstream_notification_fanout_copies_notifications_to_live_subscribers() {
        let subscribers = Arc::new(StdMutex::new(Vec::new()));
        let queue_a = Arc::new(StdMutex::new(VecDeque::new()));
        let queue_b = Arc::new(StdMutex::new(VecDeque::new()));
        let dropped_queue = Arc::new(StdMutex::new(VecDeque::new()));
        if let Ok(mut guard) = subscribers.lock() {
            guard.push(Arc::downgrade(&queue_a));
            guard.push(Arc::downgrade(&queue_b));
            guard.push(Arc::downgrade(&dropped_queue));
        }
        drop(dropped_queue);

        fan_out_shared_upstream_notifications(
            &subscribers,
            vec![
                json!({"jsonrpc": "2.0", "method": "notifications/resources/list_changed"}),
                json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
            ],
        );

        let queue_a = queue_a.lock().unwrap();
        let queue_b = queue_b.lock().unwrap();
        assert_eq!(queue_a.len(), 2);
        assert_eq!(queue_b.len(), 2);
        assert_eq!(
            queue_a[0]["method"].as_str(),
            Some("notifications/resources/list_changed")
        );
        assert_eq!(
            queue_b[1]["method"].as_str(),
            Some("notifications/tools/list_changed")
        );
        drop(queue_a);
        drop(queue_b);

        let subscriber_count = subscribers.lock().unwrap().len();
        assert_eq!(subscriber_count, 2);
    }

    fn sign_jwt(keypair: &Keypair, claims: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg": "EdDSA",
                "typ": "JWT"
            }))
            .unwrap(),
        );
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{header}.{payload}");
        let signature = keypair.sign(signing_input.as_bytes()).to_bytes();
        let signature = URL_SAFE_NO_PAD.encode(signature);
        format!("{signing_input}.{signature}")
    }
}
