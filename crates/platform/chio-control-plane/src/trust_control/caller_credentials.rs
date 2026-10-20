//! Scoped trust-control caller credentials and pinned cluster peer keys.
//!
//! A caller credential names one deployment, a closed set of scopes and a
//! tenant authority. Its secret is held only as a SHA-256 digest and compared
//! in constant time. A cluster peer authenticates with an Ed25519 signature
//! from the key pinned for its node id; no shared secret authenticates a peer.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use chio_core::crypto::{Keypair, PublicKey, SigningAlgorithm};
use chio_core::{canonical_json_bytes, Signature};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::report_validation::{normalize_cluster_config_url, normalize_cluster_url};
use super::{
    plain_http_error, CLUSTER_AUTH_ISSUED_AT_HEADER, CLUSTER_AUTH_SIGNATURE_HEADER,
    CLUSTER_AUTH_TERM_HEADER, CLUSTER_NODE_ID_HEADER,
};

/// Signature scheme of a cluster peer request. The signed payload binds the
/// scheme, node id, method, path, raw query, issue time and cluster term.
pub const CLUSTER_PEER_SIGNATURE_SCHEME: &str = "chio.cluster.peer-signature.v1";

/// A peer request is fresh only within this many seconds of the receiver's clock.
pub const CLUSTER_PEER_SIGNATURE_MAX_SKEW_SECS: i64 = 60;

const MAX_CREDENTIAL_ID_BYTES: usize = 128;
const MAX_DEPLOYMENT_ID_BYTES: usize = 128;
const MAX_TENANT_ID_BYTES: usize = 256;

macro_rules! scopes {
    ($($variant:ident => $name:literal,)+) => {
        /// The closed trust-control scope set. A name outside it never parses.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum Scope {
            $($variant,)+
        }

        impl Scope {
            pub const ALL: &'static [Scope] = &[$(Scope::$variant,)+];

            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Scope::$variant => $name,)+
                }
            }

            #[must_use]
            pub fn parse(value: &str) -> Option<Self> {
                match value {
                    $($name => Some(Scope::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

scopes! {
    AdminEmergency => "admin:emergency",
    AdmissionAuthorityWrite => "admission-authority:write",
    AttestationWrite => "attestation:write",
    AuthorityAdmin => "authority:admin",
    AuthorityRead => "authority:read",
    BudgetsRead => "budgets:read",
    BudgetsWrite => "budgets:write",
    CapabilitiesIssue => "capabilities:issue",
    CertificationsRead => "certifications:read",
    CertificationsWrite => "certifications:write",
    ClusterReplicate => "cluster:replicate",
    ClusterOpeningsReplicate => "cluster-openings:replicate",
    CreditRead => "credit:read",
    CreditWrite => "credit:write",
    EvidenceRead => "evidence:read",
    EvidenceWrite => "evidence:write",
    FederationRead => "federation:read",
    FederationWrite => "federation:write",
    FindingsRead => "findings:read",
    FindingsWrite => "findings:write",
    FiscalRead => "fiscal:read",
    FiscalWrite => "fiscal:write",
    LineageRead => "lineage:read",
    LineageWrite => "lineage:write",
    MetricsRead => "metrics:read",
    PassportRead => "passport:read",
    PassportWrite => "passport:write",
    ReceiptOpeningsErase => "receipt-openings:erase",
    ReceiptOpeningsRead => "receipt-openings:read",
    ReceiptsAdmin => "receipts:admin",
    ReceiptsAppend => "receipts:append",
    ReceiptsRead => "receipts:read",
    RegistryWrite => "registry:write",
    ReportsRead => "reports:read",
    ReputationRead => "reputation:read",
    ReputationWrite => "reputation:write",
    RevocationsRead => "revocations:read",
    RevocationsWrite => "revocations:write",
    ScimWrite => "scim:write",
    SettlementWrite => "settlement:write",
}

impl Scope {
    /// Cluster scopes belong only to pinned peers, never to caller credentials.
    #[must_use]
    pub const fn is_cluster(self) -> bool {
        matches!(
            self,
            Scope::ClusterReplicate | Scope::ClusterOpeningsReplicate
        )
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Who holds a caller credential. Deployment-kind routes (receipt append,
/// budgets, capability issue, settlement, authority reads, admission
/// authority) refuse a caller-kind credential whatever its scopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialKind {
    Caller,
    Deployment,
}

/// The tenants a credential may act for inside its deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantAuthority {
    Deployment,
    Tenant(String),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrustAccessError {
    #[error("trust-control configuration key \"{0}\" is removed; declare [[credentials]] entries with scopes and tenant authority instead")]
    RemovedKey(&'static str),
    #[error("trust-control access configuration is invalid: {0}")]
    Malformed(String),
    #[error("trust-control access configuration declares no credentials")]
    NoCredentials,
    #[error(
        "deployment id {0:?} must be 1 to 128 printable characters without surrounding whitespace"
    )]
    InvalidDeployment(String),
    #[error("credential id {0:?} must be 1 to 128 characters of [A-Za-z0-9._:-]")]
    InvalidCredentialId(String),
    #[error("credential id \"{0}\" is declared more than once")]
    DuplicateCredentialId(String),
    #[error("credential \"{0}\" secret_sha256 must be 64 lowercase hex characters")]
    InvalidSecretDigest(String),
    #[error("credentials \"{0}\" and \"{1}\" share one secret")]
    DuplicateSecret(String, String),
    #[error("credential \"{0}\" declares no scopes")]
    NoScopes(String),
    #[error("credential \"{credential}\" names unknown scope \"{scope}\"")]
    UnknownScope { credential: String, scope: String },
    #[error("credential \"{credential}\" names scope \"{scope}\" more than once")]
    DuplicateScope { credential: String, scope: Scope },
    #[error("credential \"{credential}\" names cluster scope \"{scope}\", which only a pinned peer may hold")]
    ClusterScopeOnCredential { credential: String, scope: Scope },
    #[error("credential \"{credential}\" belongs to deployment \"{credential_deployment}\", but this trust-control serves deployment \"{deployment}\"")]
    ForeignDeployment {
        credential: String,
        credential_deployment: String,
        deployment: String,
    },
    #[error("credential \"{0}\" tenant_authority must be \"deployment\" or {{ tenant = \"..\" }}")]
    InvalidTenantAuthority(String),
    #[error("credential \"{credential}\" names an invalid tenant id {tenant:?}")]
    InvalidTenant { credential: String, tenant: String },
    #[error("cluster peer node id {0:?} is invalid")]
    InvalidPeerNodeId(String),
    #[error("cluster peer \"{0}\" is declared more than once")]
    DuplicatePeer(String),
    #[error("cluster peer \"{node_id}\" internal_url is invalid: {reason}")]
    InvalidPeerUrl { node_id: String, reason: String },
    #[error("cluster peer \"{0}\" public_key must be a hex Ed25519 public key")]
    InvalidPeerKey(String),
    #[error("cluster peers \"{0}\" and \"{1}\" pin one public key")]
    DuplicatePeerKey(String, String),
    #[error("cluster peer \"{0}\" declares no scopes")]
    PeerNoScopes(String),
    #[error("cluster peer \"{node_id}\" names scope \"{scope}\", but a peer may hold only cluster scopes")]
    PeerNonClusterScope { node_id: String, scope: String },
    #[error("internal_listen {0} must differ from the public listen address")]
    InternalListenerShared(SocketAddr),
    #[error("cluster peer signature payload could not be encoded: {0}")]
    SignaturePayload(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessConfigFile {
    deployment: String,
    internal_listen: SocketAddr,
    #[serde(default)]
    credentials: Vec<CredentialEntryFile>,
    #[serde(default)]
    cluster: ClusterFile,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClusterFile {
    #[serde(default)]
    peers: Vec<PeerEntryFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialEntryFile {
    id: String,
    kind: CredentialKind,
    secret_sha256: String,
    scopes: Vec<String>,
    deployment: String,
    tenant_authority: toml::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantAuthorityTable {
    tenant: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerEntryFile {
    node_id: String,
    internal_url: String,
    public_key: String,
    scopes: Vec<String>,
}

/// Validated trust-control access configuration: the deployment this
/// trust-control serves, the internal listener address, the caller
/// credentials and the pinned cluster peers.
#[derive(Debug)]
pub struct TrustAccessConfig {
    pub deployment: String,
    pub internal_listen: SocketAddr,
    pub credentials: CallerCredentials,
    pub peers: ClusterPeerPins,
}

impl TrustAccessConfig {
    /// Parse and validate an access configuration document. Every failure
    /// refuses the whole document; nothing is defaulted or migrated.
    pub fn from_toml_str(text: &str) -> Result<Self, TrustAccessError> {
        let table: toml::Table = toml::from_str(text)
            .map_err(|error| TrustAccessError::Malformed(error.message().to_string()))?;
        for removed in ["service_token", "tenant_read_tokens"] {
            if table.contains_key(removed) {
                return Err(TrustAccessError::RemovedKey(removed));
            }
        }
        let file: AccessConfigFile =
            toml::Value::Table(table)
                .try_into()
                .map_err(|error: toml::de::Error| {
                    TrustAccessError::Malformed(error.message().to_string())
                })?;
        let deployment = validate_deployment(&file.deployment)?;
        let credentials = CallerCredentials::from_entries(&deployment, file.credentials)?;
        let peers = ClusterPeerPins::from_entries(file.cluster.peers)?;
        Ok(Self {
            deployment,
            internal_listen: file.internal_listen,
            credentials,
            peers,
        })
    }

    /// The internal listener never shares the public listener's address.
    pub fn validate_listeners(&self, public_listen: SocketAddr) -> Result<(), TrustAccessError> {
        if self.internal_listen == public_listen {
            return Err(TrustAccessError::InternalListenerShared(
                self.internal_listen,
            ));
        }
        Ok(())
    }
}

fn validate_deployment(value: &str) -> Result<String, TrustAccessError> {
    if value.is_empty()
        || value.len() > MAX_DEPLOYMENT_ID_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(TrustAccessError::InvalidDeployment(value.to_string()));
    }
    Ok(value.to_string())
}

fn valid_credential_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CREDENTIAL_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn parse_secret_digest(id: &str, value: &str) -> Result<[u8; 32], TrustAccessError> {
    let lowercase_hex = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !lowercase_hex {
        return Err(TrustAccessError::InvalidSecretDigest(id.to_string()));
    }
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(value, &mut digest)
        .map_err(|_| TrustAccessError::InvalidSecretDigest(id.to_string()))?;
    Ok(digest)
}

fn parse_tenant_authority(
    id: &str,
    value: toml::Value,
) -> Result<TenantAuthority, TrustAccessError> {
    match value {
        toml::Value::String(keyword) if keyword == "deployment" => Ok(TenantAuthority::Deployment),
        toml::Value::Table(table) => {
            let parsed: TenantAuthorityTable =
                toml::Value::Table(table)
                    .try_into()
                    .map_err(|_: toml::de::Error| {
                        TrustAccessError::InvalidTenantAuthority(id.to_string())
                    })?;
            let tenant = parsed.tenant;
            if tenant.is_empty()
                || tenant.len() > MAX_TENANT_ID_BYTES
                || tenant.trim() != tenant
                || tenant.chars().any(char::is_control)
            {
                return Err(TrustAccessError::InvalidTenant {
                    credential: id.to_string(),
                    tenant,
                });
            }
            Ok(TenantAuthority::Tenant(tenant))
        }
        _ => Err(TrustAccessError::InvalidTenantAuthority(id.to_string())),
    }
}

#[derive(Debug)]
struct CredentialRecord {
    id: String,
    kind: CredentialKind,
    secret_sha256: [u8; 32],
    scopes: BTreeSet<Scope>,
    tenant_authority: TenantAuthority,
}

/// Every caller credential of one deployment. Secrets are held only as
/// SHA-256 digests.
#[derive(Debug)]
pub struct CallerCredentials {
    deployment: String,
    records: Vec<CredentialRecord>,
}

impl CallerCredentials {
    fn from_entries(
        deployment: &str,
        entries: Vec<CredentialEntryFile>,
    ) -> Result<Self, TrustAccessError> {
        if entries.is_empty() {
            return Err(TrustAccessError::NoCredentials);
        }
        let mut records: Vec<CredentialRecord> = Vec::with_capacity(entries.len());
        for entry in entries {
            if !valid_credential_id(&entry.id) {
                return Err(TrustAccessError::InvalidCredentialId(entry.id));
            }
            if records.iter().any(|record| record.id == entry.id) {
                return Err(TrustAccessError::DuplicateCredentialId(entry.id));
            }
            if entry.deployment != deployment {
                return Err(TrustAccessError::ForeignDeployment {
                    credential: entry.id,
                    credential_deployment: entry.deployment,
                    deployment: deployment.to_string(),
                });
            }
            let secret_sha256 = parse_secret_digest(&entry.id, &entry.secret_sha256)?;
            if let Some(other) = records
                .iter()
                .find(|record| bool::from(record.secret_sha256.ct_eq(&secret_sha256)))
            {
                return Err(TrustAccessError::DuplicateSecret(
                    other.id.clone(),
                    entry.id,
                ));
            }
            if entry.scopes.is_empty() {
                return Err(TrustAccessError::NoScopes(entry.id));
            }
            let mut scopes = BTreeSet::new();
            for name in &entry.scopes {
                let Some(scope) = Scope::parse(name) else {
                    return Err(TrustAccessError::UnknownScope {
                        credential: entry.id,
                        scope: name.clone(),
                    });
                };
                if scope.is_cluster() {
                    return Err(TrustAccessError::ClusterScopeOnCredential {
                        credential: entry.id,
                        scope,
                    });
                }
                if !scopes.insert(scope) {
                    return Err(TrustAccessError::DuplicateScope {
                        credential: entry.id,
                        scope,
                    });
                }
            }
            let tenant_authority = parse_tenant_authority(&entry.id, entry.tenant_authority)?;
            records.push(CredentialRecord {
                id: entry.id,
                kind: entry.kind,
                secret_sha256,
                scopes,
                tenant_authority,
            });
        }
        Ok(Self {
            deployment: deployment.to_string(),
            records,
        })
    }

    #[must_use]
    pub fn deployment(&self) -> &str {
        &self.deployment
    }

    /// Resolve the bearer credential. Every record is compared in constant
    /// time; the loop never exits early on a match.
    pub fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedCaller, CallerAuthError> {
        let token = bearer_token(headers).ok_or(CallerAuthError::Unauthenticated)?;
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut matched = None;
        for record in &self.records {
            if bool::from(record.secret_sha256.ct_eq(&digest)) {
                matched = Some(record);
            }
        }
        let record = matched.ok_or(CallerAuthError::Unauthenticated)?;
        Ok(AuthenticatedCaller {
            credential_id: record.id.clone(),
            kind: record.kind,
            deployment: self.deployment.clone(),
            tenant_authority: record.tenant_authority.clone(),
            scopes: record.scopes.clone(),
        })
    }

    /// Authenticate the bearer credential and require `required_scope`.
    pub fn validate_caller(
        &self,
        headers: &HeaderMap,
        required_scope: Scope,
    ) -> Result<AuthenticatedCaller, CallerAuthError> {
        let caller = self.authenticate(headers)?;
        if !caller.scopes.contains(&required_scope) {
            return Err(CallerAuthError::MissingScope(required_scope));
        }
        Ok(caller)
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let header = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let token = header.strip_prefix("Bearer ")?;
    (!token.is_empty()).then_some(token)
}

/// The authenticated caller a route handler receives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedCaller {
    pub credential_id: String,
    pub kind: CredentialKind,
    pub deployment: String,
    pub tenant_authority: TenantAuthority,
    pub scopes: BTreeSet<Scope>,
}

impl AuthenticatedCaller {
    #[must_use]
    pub fn has_scope(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    /// The receipt read boundary this caller is entitled to.
    #[must_use]
    pub fn receipt_read_context(&self) -> chio_kernel::ReceiptReadContext {
        match &self.tenant_authority {
            TenantAuthority::Deployment => chio_kernel::ReceiptReadContext::admin_service(),
            TenantAuthority::Tenant(tenant) => {
                chio_kernel::ReceiptReadContext::authenticated_tenant(tenant.clone())
            }
        }
    }

    /// The tenant a request acts for. A tenant credential acts only for its
    /// own tenant; naming another tenant refuses.
    pub fn tenant_for_request(
        &self,
        requested: Option<&str>,
    ) -> Result<Option<String>, CallerAuthError> {
        match (&self.tenant_authority, requested) {
            (TenantAuthority::Deployment, requested) => Ok(requested.map(str::to_string)),
            (TenantAuthority::Tenant(tenant), None) => Ok(Some(tenant.clone())),
            (TenantAuthority::Tenant(tenant), Some(requested)) if requested == tenant => {
                Ok(Some(tenant.clone()))
            }
            (TenantAuthority::Tenant(_), Some(_)) => Err(CallerAuthError::CrossTenant),
        }
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CallerAuthError {
    #[error("missing or invalid trust-control credential")]
    Unauthenticated,
    #[error("trust-control credential lacks scope {0}")]
    MissingScope(Scope),
    #[error("route requires a deployment credential")]
    DeploymentCredentialRequired,
    #[error("tenant credential cannot use a deployment-only route")]
    TenantCredentialOnDeploymentRoute,
    #[error("tenant credential cannot act for another tenant")]
    CrossTenant,
    #[error("cluster peer authentication is refused on a caller route")]
    PeerAuthenticationOnCallerRoute,
}

impl CallerAuthError {
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            CallerAuthError::Unauthenticated | CallerAuthError::PeerAuthenticationOnCallerRoute => {
                StatusCode::UNAUTHORIZED
            }
            CallerAuthError::MissingScope(_)
            | CallerAuthError::DeploymentCredentialRequired
            | CallerAuthError::TenantCredentialOnDeploymentRoute
            | CallerAuthError::CrossTenant => StatusCode::FORBIDDEN,
        }
    }

    #[must_use]
    pub fn into_response(self) -> Response {
        let status = self.status();
        let mut response = plain_http_error(status, &self.to_string());
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

/// A cluster node pinned by node id with its Ed25519 public key.
#[derive(Clone, Debug)]
pub struct ClusterPeer {
    pub node_id: String,
    pub internal_url: String,
    pub public_key: PublicKey,
    pub scopes: BTreeSet<Scope>,
}

/// Every pinned cluster peer, keyed by normalized node id.
#[derive(Clone, Debug, Default)]
pub struct ClusterPeerPins {
    peers: BTreeMap<String, ClusterPeer>,
}

impl ClusterPeerPins {
    fn from_entries(entries: Vec<PeerEntryFile>) -> Result<Self, TrustAccessError> {
        let mut peers: BTreeMap<String, ClusterPeer> = BTreeMap::new();
        for entry in entries {
            let node_id = normalize_cluster_url(&entry.node_id)
                .map_err(|_| TrustAccessError::InvalidPeerNodeId(entry.node_id.clone()))?;
            if peers.contains_key(&node_id) {
                return Err(TrustAccessError::DuplicatePeer(node_id));
            }
            let internal_url =
                normalize_cluster_config_url(&entry.internal_url, true).map_err(|error| {
                    TrustAccessError::InvalidPeerUrl {
                        node_id: node_id.clone(),
                        reason: error.to_string(),
                    }
                })?;
            let public_key = PublicKey::from_hex(&entry.public_key)
                .ok()
                .filter(|key| key.algorithm() == SigningAlgorithm::Ed25519)
                .ok_or_else(|| TrustAccessError::InvalidPeerKey(node_id.clone()))?;
            if let Some(other) = peers.values().find(|peer| peer.public_key == public_key) {
                return Err(TrustAccessError::DuplicatePeerKey(
                    other.node_id.clone(),
                    node_id,
                ));
            }
            if entry.scopes.is_empty() {
                return Err(TrustAccessError::PeerNoScopes(node_id));
            }
            let mut scopes = BTreeSet::new();
            for name in &entry.scopes {
                match Scope::parse(name) {
                    Some(scope) if scope.is_cluster() && scopes.insert(scope) => {}
                    _ => {
                        return Err(TrustAccessError::PeerNonClusterScope {
                            node_id,
                            scope: name.clone(),
                        });
                    }
                }
            }
            peers.insert(
                node_id.clone(),
                ClusterPeer {
                    node_id,
                    internal_url,
                    public_key,
                    scopes,
                },
            );
        }
        Ok(Self { peers })
    }

    #[must_use]
    pub fn get(&self, node_id: &str) -> Option<&ClusterPeer> {
        self.peers.get(node_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ClusterPeer> {
        self.peers.values()
    }

    /// Verify a peer request against the pinned key of its claimed node id
    /// and require `required_scope`. `now_secs` is the receiver's clock.
    pub fn verify(
        &self,
        headers: &HeaderMap,
        request: &PeerRequestTarget<'_>,
        now_secs: i64,
        required_scope: Scope,
    ) -> Result<AuthenticatedPeer, PeerAuthError> {
        let node_id = single_header(headers, CLUSTER_NODE_ID_HEADER)
            .and_then(|value| normalize_cluster_url(value).ok())
            .ok_or(PeerAuthError::Unauthenticated)?;
        let issued_at = single_header(headers, CLUSTER_AUTH_ISSUED_AT_HEADER)
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or(PeerAuthError::Unauthenticated)?;
        let signature = single_header(headers, CLUSTER_AUTH_SIGNATURE_HEADER)
            .and_then(|value| Signature::from_hex(value).ok())
            .ok_or(PeerAuthError::Unauthenticated)?;
        let term = match headers.get(CLUSTER_AUTH_TERM_HEADER) {
            None => None,
            Some(_) => Some(
                single_header(headers, CLUSTER_AUTH_TERM_HEADER)
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or(PeerAuthError::Unauthenticated)?,
            ),
        };
        let peer = self
            .peers
            .get(&node_id)
            .ok_or(PeerAuthError::UnpinnedNode)?;
        let payload = peer_signature_payload(&node_id, request, issued_at, term)
            .map_err(|_| PeerAuthError::Unauthenticated)?;
        if !peer.public_key.verify_strict(&payload, &signature) {
            return Err(PeerAuthError::BadSignature);
        }
        if issued_at > now_secs.saturating_add(CLUSTER_PEER_SIGNATURE_MAX_SKEW_SECS)
            || issued_at < now_secs.saturating_sub(CLUSTER_PEER_SIGNATURE_MAX_SKEW_SECS)
        {
            return Err(PeerAuthError::Stale);
        }
        if !peer.scopes.contains(&required_scope) {
            return Err(PeerAuthError::MissingScope(required_scope));
        }
        Ok(AuthenticatedPeer {
            node_id,
            issued_at,
            term,
            scopes: peer.scopes.clone(),
        })
    }
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() || value.trim().is_empty() {
        return None;
    }
    Some(value)
}

/// The request a peer signature covers.
#[derive(Clone, Copy, Debug)]
pub struct PeerRequestTarget<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
}

fn peer_signature_payload(
    node_id: &str,
    request: &PeerRequestTarget<'_>,
    issued_at: i64,
    term: Option<u64>,
) -> Result<Vec<u8>, TrustAccessError> {
    canonical_json_bytes(&json!({
        "scheme": CLUSTER_PEER_SIGNATURE_SCHEME,
        "nodeId": node_id,
        "method": request.method,
        "path": request.path,
        "query": request.query,
        "issuedAt": issued_at,
        "term": term,
    }))
    .map_err(|error| TrustAccessError::SignaturePayload(error.to_string()))
}

/// Sign a peer request with this node's key. Returns the hex signature for
/// the signature header.
pub fn sign_cluster_peer_request(
    keypair: &Keypair,
    node_id: &str,
    request: &PeerRequestTarget<'_>,
    issued_at: i64,
    term: Option<u64>,
) -> Result<String, TrustAccessError> {
    let node_id = normalize_cluster_url(node_id)
        .map_err(|_| TrustAccessError::InvalidPeerNodeId(node_id.to_string()))?;
    let payload = peer_signature_payload(&node_id, request, issued_at, term)?;
    Ok(keypair.sign(&payload).to_hex())
}

/// A verified cluster peer request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    pub node_id: String,
    pub issued_at: i64,
    pub term: Option<u64>,
    pub scopes: BTreeSet<Scope>,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerAuthError {
    #[error("missing or invalid cluster peer authentication")]
    Unauthenticated,
    #[error("cluster peer node id is not pinned")]
    UnpinnedNode,
    #[error("cluster peer signature does not verify under the pinned key")]
    BadSignature,
    #[error("cluster peer signature is outside the freshness window")]
    Stale,
    #[error("cluster peer lacks scope {0}")]
    MissingScope(Scope),
    #[error("caller credentials are refused on a cluster peer route")]
    CallerCredentialOnPeerRoute,
}

impl PeerAuthError {
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            PeerAuthError::MissingScope(_) | PeerAuthError::UnpinnedNode => StatusCode::FORBIDDEN,
            PeerAuthError::Unauthenticated
            | PeerAuthError::BadSignature
            | PeerAuthError::Stale
            | PeerAuthError::CallerCredentialOnPeerRoute => StatusCode::UNAUTHORIZED,
        }
    }

    #[must_use]
    pub fn into_response(self) -> Response {
        let status = self.status();
        let mut response = plain_http_error(status, &self.to_string());
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                WWW_AUTHENTICATE,
                HeaderValue::from_static(CLUSTER_PEER_SIGNATURE_SCHEME),
            );
        }
        response
    }
}

#[cfg(test)]
#[path = "caller_credentials_tests.rs"]
pub(crate) mod tests;
