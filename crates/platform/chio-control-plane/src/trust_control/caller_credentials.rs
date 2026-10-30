//! Scoped trust-control caller credentials and pinned cluster peer keys.
//!
//! A caller credential names one deployment, a closed set of scopes and a
//! tenant authority. Its secret is held only as a SHA-256 digest and compared
//! in constant time. A cluster peer authenticates with an Ed25519 signature
//! from the key pinned for its node id; no shared secret authenticates a peer.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use chio_core::crypto::{Keypair, PublicKey, SigningAlgorithm};
use chio_core::{verify_wrapped_bytes, CanonicalBytes, CanonicalJsonWitness, Signature};
use chio_store_sqlite::{ClusterPeerReplayStoreError, SqliteClusterPeerReplayStore};
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
/// scheme, node id, method, path, raw query, SHA-256 of the request body,
/// single-use nonce, issue time, cluster term, the deployment and the
/// recipient node id.
pub const CLUSTER_PEER_SIGNATURE_SCHEME: &str =
    chio_core::signed_artifact::CHIO_CLUSTER_PEER_REQUEST_V1_SCHEMA;

/// A peer request is fresh only while its `issued_at` is at most this many
/// seconds before the highest receiver time its nonce cache has observed.
pub const CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS: i64 = 60;

/// A peer request is fresh only while its `issued_at` is at most this many
/// seconds after the highest receiver time its nonce cache has observed.
///
/// Clock-skew contract: a peer clock may lead the receiver clock by at most
/// this many seconds. A request from a peer leading by more is refused as
/// stale. A receiver refuses a request from a peer it has no stored
/// high-water mark for when the request is issued at or before its start plus
/// this lead.
pub const CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS: i64 = 5;

/// Header carrying the lowercase hex SHA-256 of the request body (of the
/// empty body when there is none).
pub const CLUSTER_AUTH_BODY_SHA256_HEADER: &str = "x-chio-cluster-auth-body-sha256";

/// Header carrying the request's single-use nonce: 32 random bytes as 64
/// lowercase hex characters.
pub const CLUSTER_AUTH_NONCE_HEADER: &str = "x-chio-cluster-auth-nonce";

/// Upper bound on remembered peer nonces. A full cache refuses new peer
/// requests rather than forgetting a nonce inside its freshness window. Each
/// pinned peer may hold at most an equal share of it.
pub const CLUSTER_PEER_NONCE_CACHE_CAPACITY: usize = 65_536;

const MAX_CREDENTIAL_ID_BYTES: usize = 128;
const MAX_DEPLOYMENT_ID_BYTES: usize = 128;
const MAX_TENANT_ID_BYTES: usize = 256;

/// The closed trust-control scope set. A name outside it never parses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    AdminEmergency,
    AdmissionAuthorityWrite,
    AttestationWrite,
    AuthorityAdmin,
    AuthorityRead,
    BudgetsRead,
    BudgetsWrite,
    CapabilitiesIssue,
    CertificationsRead,
    CertificationsWrite,
    ClusterReplicate,
    ClusterOpeningsReplicate,
    CreditRead,
    CreditWrite,
    EvidenceRead,
    EvidenceWrite,
    FederationRead,
    FederationWrite,
    FindingsRead,
    FindingsWrite,
    FiscalRead,
    FiscalWrite,
    LineageRead,
    LineageWrite,
    MetricsRead,
    PassportRead,
    PassportWrite,
    ReceiptOpeningsErase,
    ReceiptOpeningsRead,
    ReceiptsAdmin,
    ReceiptsAppend,
    ReceiptsRead,
    RegistryWrite,
    ReportsRead,
    ReputationRead,
    ReputationWrite,
    RevocationsRead,
    RootExchangeSign,
    RevocationsWrite,
    ScimWrite,
    SettlementWrite,
}

macro_rules! scopes {
    ($($variant:ident => $name:literal,)+) => {
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
    RootExchangeSign => "root-exchange:sign",
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
    #[error("credential \"{0}\" secret must be non-empty, without surrounding whitespace or control characters")]
    InvalidSecret(String),
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
    #[error("cluster peer \"{node_id}\" names scope \"{scope}\" more than once")]
    DuplicatePeerScope { node_id: String, scope: Scope },
    #[error("cluster peer \"{0}\" holds cluster:replicate without cluster-openings:replicate, so it cannot take the initial cluster snapshot")]
    PeerSnapshotScopeMissing(String),
    #[error("[cluster] node_id {0:?} is invalid")]
    InvalidClusterNodeId(String),
    #[error("[cluster] declares peers but no node_id and node_key_file for this node")]
    ClusterIdentityRequired,
    #[error("[cluster] node_id and node_key_file are declared without any peer")]
    ClusterIdentityWithoutPeers,
    #[error("cluster peer \"{0}\" is this node; a node never pins itself")]
    SelfPinned(String),
    #[error("cluster peer \"{0}\" pins this node's own public key")]
    PeerSharesNodeKey(String),
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
    node_id: Option<String>,
    node_key_file: Option<std::path::PathBuf>,
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
        for removed in [
            "service_token",
            "tenant_read_tokens",
            "authority_workload_token",
        ] {
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
        let peers = ClusterPeerPins::from_config(&deployment, file.cluster)?;
        Ok(Self {
            deployment,
            internal_listen: file.internal_listen,
            credentials,
            peers,
        })
    }

    /// The internal listener never shares the public listener's address. Port
    /// zero asks for two distinct ephemeral sockets and is not a shared address.
    pub fn validate_listeners(&self, public_listen: SocketAddr) -> Result<(), TrustAccessError> {
        if self.internal_listen == public_listen && public_listen.port() != 0 {
            return Err(TrustAccessError::InternalListenerShared(
                self.internal_listen,
            ));
        }
        Ok(())
    }
}

/// Largest access configuration document trust-control reads.
pub const MAX_ACCESS_CONFIG_BYTES: u64 = 1024 * 1024;

/// A validated access configuration and, for a clustered node, the Ed25519
/// key it signs peer requests with. The key is present exactly when the
/// configuration declares a cluster identity.
pub struct TrustAccess {
    config: TrustAccessConfig,
    node_keypair: Option<Keypair>,
}

impl std::fmt::Debug for TrustAccess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustAccess")
            .field("config", &self.config)
            .field(
                "node_public_key",
                &self.node_keypair.as_ref().map(Keypair::public_key),
            )
            .finish()
    }
}

impl TrustAccess {
    /// Read, parse and validate the access configuration at `path` and load
    /// the node key its cluster identity names.
    pub fn load(path: &std::path::Path) -> Result<Self, crate::CliError> {
        use std::io::Read;
        let mut text = String::new();
        std::fs::File::open(path)
            .and_then(|file| {
                file.take(MAX_ACCESS_CONFIG_BYTES + 1)
                    .read_to_string(&mut text)
            })
            .map_err(|error| {
                crate::CliError::cli_other_error(format!(
                    "failed to read trust-control access configuration {}: {error}",
                    path.display()
                ))
            })?;
        if u64::try_from(text.len()).map_or(true, |length| length > MAX_ACCESS_CONFIG_BYTES) {
            return Err(crate::CliError::cli_other_error(format!(
                "trust-control access configuration {} exceeds {MAX_ACCESS_CONFIG_BYTES} bytes",
                path.display()
            )));
        }
        let config = TrustAccessConfig::from_toml_str(&text)
            .map_err(|error| crate::CliError::cli_other_error(error.to_string()))?;
        let node_keypair = config
            .peers
            .identity()
            .map(|identity| crate::load_existing_authority_keypair(&identity.node_key_file))
            .transpose()?;
        Self::from_parts(config, node_keypair)
            .map_err(|error| crate::CliError::cli_other_error(error.to_string()))
    }

    /// Access for a single, unclustered process whose one client holds
    /// `secret`: one deployment credential with deployment tenant authority
    /// holding every caller scope except `receipt-openings:*` and
    /// `root-exchange:sign`, and a loopback ephemeral internal listener.
    pub fn single_client(
        deployment: &str,
        credential_id: &str,
        secret: &str,
    ) -> Result<Self, TrustAccessError> {
        let deployment = validate_deployment(deployment)?;
        if !valid_credential_id(credential_id) {
            return Err(TrustAccessError::InvalidCredentialId(
                credential_id.to_string(),
            ));
        }
        if secret.is_empty() || secret.trim() != secret || secret.chars().any(char::is_control) {
            return Err(TrustAccessError::InvalidSecret(credential_id.to_string()));
        }
        let record = CredentialRecord {
            id: credential_id.to_string(),
            kind: CredentialKind::Deployment,
            secret_sha256: Sha256::digest(secret.as_bytes()).into(),
            scopes: Scope::ALL
                .iter()
                .copied()
                .filter(|scope| {
                    !scope.is_cluster()
                        && !matches!(
                            scope,
                            Scope::ReceiptOpeningsRead
                                | Scope::ReceiptOpeningsErase
                                | Scope::RootExchangeSign
                        )
                })
                .collect(),
            tenant_authority: TenantAuthority::Deployment,
        };
        let config = TrustAccessConfig {
            internal_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            credentials: CallerCredentials {
                deployment: deployment.clone(),
                records: vec![record],
            },
            peers: ClusterPeerPins {
                deployment: deployment.clone(),
                identity: None,
                peers: BTreeMap::new(),
            },
            deployment,
        };
        Self::from_parts(config, None)
    }

    /// Pair a validated configuration with its node key. No pinned peer may
    /// hold this node's own public key.
    pub fn from_parts(
        config: TrustAccessConfig,
        node_keypair: Option<Keypair>,
    ) -> Result<Self, TrustAccessError> {
        if config.peers.identity().is_some() != node_keypair.is_some() {
            return Err(TrustAccessError::ClusterIdentityRequired);
        }
        if let Some(keypair) = &node_keypair {
            let own_key = keypair.public_key();
            if let Some(peer) = config.peers.iter().find(|peer| peer.public_key == own_key) {
                return Err(TrustAccessError::PeerSharesNodeKey(peer.node_id.clone()));
            }
        }
        Ok(Self {
            config,
            node_keypair,
        })
    }

    #[must_use]
    pub fn config(&self) -> &TrustAccessConfig {
        &self.config
    }

    #[must_use]
    pub fn credentials(&self) -> &CallerCredentials {
        &self.config.credentials
    }

    #[must_use]
    pub fn peers(&self) -> &ClusterPeerPins {
        &self.config.peers
    }

    /// The node key a clustered node signs peer requests with.
    #[must_use]
    pub fn node_keypair(&self) -> Option<&Keypair> {
        self.node_keypair.as_ref()
    }

    /// Sign a request this node sends to `recipient`, returning the header
    /// values. Refuses on a node without a cluster identity.
    pub fn sign_peer_request(
        &self,
        recipient: &str,
        request: &PeerRequestTarget<'_>,
        nonce: &[u8; 32],
        issued_at: i64,
        term: Option<u64>,
    ) -> Result<(String, PeerRequestSignature), TrustAccessError> {
        let (Some(identity), Some(keypair)) = (self.peers().identity(), self.node_keypair()) else {
            return Err(TrustAccessError::ClusterIdentityRequired);
        };
        let addressing = PeerAddressing {
            deployment: &self.config.deployment,
            sender: &identity.node_id,
            recipient,
        };
        let signature =
            sign_cluster_peer_request(keypair, &addressing, request, nonce, issued_at, term)?;
        Ok((identity.node_id.clone(), signature))
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

struct CredentialRecord {
    id: String,
    kind: CredentialKind,
    secret_sha256: [u8; 32],
    scopes: BTreeSet<Scope>,
    tenant_authority: TenantAuthority,
}

impl std::fmt::Debug for CredentialRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialRecord")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("secret_sha256", &"[REDACTED]")
            .field("scopes", &self.scopes)
            .field("tenant_authority", &self.tenant_authority)
            .finish()
    }
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

    /// Whether some credential of `kind` holds `scope`.
    #[must_use]
    pub fn any_holds(&self, kind: CredentialKind, scope: Scope) -> bool {
        self.records
            .iter()
            .any(|record| record.kind == kind && record.scopes.contains(&scope))
    }

    /// Credential ids, kinds, scopes and tenant authorities, never secrets.
    pub fn summaries(
        &self,
    ) -> impl Iterator<Item = (&str, CredentialKind, &BTreeSet<Scope>, &TenantAuthority)> {
        self.records.iter().map(|record| {
            (
                record.id.as_str(),
                record.kind,
                &record.scopes,
                &record.tenant_authority,
            )
        })
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
    deployment: String,
    identity: Option<ClusterNodeIdentity>,
    peers: BTreeMap<String, ClusterPeer>,
}

/// This node's own cluster identity: the node id peers address and the file
/// holding the Ed25519 seed it signs peer requests with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterNodeIdentity {
    pub node_id: String,
    pub node_key_file: std::path::PathBuf,
}

impl ClusterPeerPins {
    fn from_config(deployment: &str, cluster: ClusterFile) -> Result<Self, TrustAccessError> {
        let identity = match (cluster.node_id, cluster.node_key_file) {
            (None, None) => None,
            (Some(node_id), Some(node_key_file)) => Some(ClusterNodeIdentity {
                node_id: normalize_cluster_url(&node_id)
                    .map_err(|_| TrustAccessError::InvalidClusterNodeId(node_id.clone()))?,
                node_key_file,
            }),
            _ => return Err(TrustAccessError::ClusterIdentityRequired),
        };
        match (&identity, cluster.peers.is_empty()) {
            (None, false) => return Err(TrustAccessError::ClusterIdentityRequired),
            (Some(_), true) => return Err(TrustAccessError::ClusterIdentityWithoutPeers),
            _ => {}
        }
        let mut peers: BTreeMap<String, ClusterPeer> = BTreeMap::new();
        for entry in cluster.peers {
            let node_id = normalize_cluster_url(&entry.node_id)
                .map_err(|_| TrustAccessError::InvalidPeerNodeId(entry.node_id.clone()))?;
            if peers.contains_key(&node_id) {
                return Err(TrustAccessError::DuplicatePeer(node_id));
            }
            if identity
                .as_ref()
                .is_some_and(|identity| identity.node_id == node_id)
            {
                return Err(TrustAccessError::SelfPinned(node_id));
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
                let scope = Scope::parse(name)
                    .filter(|scope| scope.is_cluster())
                    .ok_or_else(|| TrustAccessError::PeerNonClusterScope {
                        node_id: node_id.clone(),
                        scope: name.clone(),
                    })?;
                if !scopes.insert(scope) {
                    return Err(TrustAccessError::DuplicatePeerScope { node_id, scope });
                }
            }
            if scopes.contains(&Scope::ClusterReplicate)
                && !scopes.contains(&Scope::ClusterOpeningsReplicate)
            {
                return Err(TrustAccessError::PeerSnapshotScopeMissing(node_id));
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
        Ok(Self {
            deployment: deployment.to_string(),
            identity,
            peers,
        })
    }

    /// This node's cluster identity; `None` for a node without peers.
    #[must_use]
    pub fn identity(&self) -> Option<&ClusterNodeIdentity> {
        self.identity.as_ref()
    }

    #[must_use]
    pub fn deployment(&self) -> &str {
        &self.deployment
    }

    #[must_use]
    pub fn get(&self, node_id: &str) -> Option<&ClusterPeer> {
        self.peers.get(node_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ClusterPeer> {
        self.peers.values()
    }

    /// Refuse a peer request whose authentication headers are malformed or
    /// whose claimed node id is not pinned, before its body is read. An
    /// unpinned node id refuses exactly as a bad signature does.
    pub fn precheck(&self, headers: &HeaderMap) -> Result<(), PeerAuthError> {
        let parsed = PeerHeaders::parse(headers)?;
        if self.identity.is_none() || !self.peers.contains_key(&parsed.node_id) {
            return Err(PeerAuthError::BadSignature);
        }
        Ok(())
    }

    /// Verify a peer request against the pinned key of its claimed node id
    /// and require `required_scope`. `now_secs` is the receiver's clock.
    ///
    /// Checks run in this order, each refusing with its own error:
    /// 1. every authentication header is present, single-valued and well
    ///    formed (`Unauthenticated`);
    /// 2. the claimed node id is pinned and the signature verifies under its
    ///    key over this deployment and this node as the recipient; an unpinned
    ///    node id, another recipient or another deployment refuses exactly as
    ///    a bad signature does (`BadSignature`);
    /// 3. the signed body digest equals the SHA-256 of the received body
    ///    (`BodyMismatch`);
    /// 4. the issue time is inside the nonce cache's acceptance window and
    ///    above the peer's restart floor (`Stale`);
    /// 5. the peer holds `required_scope` (`MissingScope`);
    /// 6. the nonce has not been used by this node inside the window
    ///    (`ReplayedNonce`), the peer's durable high-water mark covers the
    ///    issue time (`PeerReplayStoreUnavailable` when it cannot be
    ///    advanced), and the nonce is then remembered until the window closes.
    pub fn verify(
        &self,
        headers: &HeaderMap,
        request: &PeerRequestTarget<'_>,
        now_secs: i64,
        required_scope: Scope,
        nonces: &PeerNonceCache,
    ) -> Result<AuthenticatedPeer, PeerAuthError> {
        let PeerHeaders {
            node_id,
            issued_at,
            signature,
            nonce,
            body_sha256: claimed_body_sha256,
            term,
        } = PeerHeaders::parse(headers)?;
        let recipient = self
            .identity
            .as_ref()
            .map(|identity| identity.node_id.as_str())
            .ok_or(PeerAuthError::BadSignature)?;
        let peer = self
            .peers
            .get(&node_id)
            .ok_or(PeerAuthError::BadSignature)?;
        let signed = SignedPeerFields {
            deployment: &self.deployment,
            recipient,
            node_id: &node_id,
            body_sha256: claimed_body_sha256,
            nonce,
            issued_at,
            term,
        };
        let payload =
            peer_signature_payload(request, &signed).map_err(|_| PeerAuthError::Unauthenticated)?;
        verify_wrapped_bytes(
            &peer.public_key,
            CLUSTER_PEER_SIGNATURE_SCHEME,
            &payload,
            &signature,
        )
        .map_err(|_| PeerAuthError::BadSignature)?;
        let received_body_sha256 = hex::encode(Sha256::digest(request.body));
        if !bool::from(
            received_body_sha256
                .as_bytes()
                .ct_eq(claimed_body_sha256.as_bytes()),
        ) {
            return Err(PeerAuthError::BodyMismatch);
        }
        nonces.check_fresh(&node_id, issued_at, now_secs)?;
        if !peer.scopes.contains(&required_scope) {
            return Err(PeerAuthError::MissingScope(required_scope));
        }
        nonces.record(&node_id, nonce, issued_at, now_secs)?;
        Ok(AuthenticatedPeer {
            node_id,
            issued_at,
            term,
            scopes: peer.scopes.clone(),
        })
    }
}

/// The authentication headers of one peer request, each present,
/// single-valued and well formed.
struct PeerHeaders<'a> {
    node_id: String,
    issued_at: i64,
    signature: Signature,
    nonce: &'a str,
    body_sha256: &'a str,
    term: Option<u64>,
}

impl<'a> PeerHeaders<'a> {
    fn parse(headers: &'a HeaderMap) -> Result<Self, PeerAuthError> {
        let node_id = single_header(headers, CLUSTER_NODE_ID_HEADER)
            .and_then(|value| normalize_cluster_url(value).ok())
            .ok_or(PeerAuthError::Unauthenticated)?;
        let issued_at = single_header(headers, CLUSTER_AUTH_ISSUED_AT_HEADER)
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or(PeerAuthError::Unauthenticated)?;
        let signature = single_header(headers, CLUSTER_AUTH_SIGNATURE_HEADER)
            .and_then(|value| Signature::from_hex(value).ok())
            .ok_or(PeerAuthError::Unauthenticated)?;
        let nonce = single_header(headers, CLUSTER_AUTH_NONCE_HEADER)
            .filter(|value| is_lowercase_hex_32(value))
            .ok_or(PeerAuthError::Unauthenticated)?;
        let body_sha256 = single_header(headers, CLUSTER_AUTH_BODY_SHA256_HEADER)
            .filter(|value| is_lowercase_hex_32(value))
            .ok_or(PeerAuthError::Unauthenticated)?;
        let term = match headers.get(CLUSTER_AUTH_TERM_HEADER) {
            None => None,
            Some(_) => Some(
                single_header(headers, CLUSTER_AUTH_TERM_HEADER)
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or(PeerAuthError::Unauthenticated)?,
            ),
        };
        Ok(Self {
            node_id,
            issued_at,
            signature,
            nonce,
            body_sha256,
            term,
        })
    }
}

fn is_lowercase_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Remembers each `(node id, nonce)` an accepted peer request used, decides
/// which issue times are fresh, and keeps every peer's durable `issued_at`
/// high-water mark.
///
/// The acceptance window is `[high_water - MAX_AGE, high_water + MAX_LEAD]`,
/// where `high_water` is the highest receiver time the cache has observed.
/// Both bounds only rise. An entry is pruned only once its issue time is below
/// the lower bound, so every request the window admits is checked against
/// every nonce that request could reuse, and a backward clock step never
/// reopens a pruned nonce.
///
/// Each peer also has a restart floor, fixed when the cache opens: the
/// peer's stored high-water mark, or `start + MAX_LEAD` for a peer without
/// one, where `start` is the receiver time the cache opened at. A request
/// issued at or below its peer's floor is refused. Before a request is
/// admitted, its peer's stored mark is raised to its issue time whenever the
/// issue time is above it, and a store that cannot be raised refuses the
/// request. Every request an earlier process on the same store accepted is
/// therefore at or below its peer's floor, whatever the receiver clock reads
/// after a restart. A peer without a stored mark keeps the clock-based bound:
/// a missing or reset store never admits more than that bound does.
///
/// Within one process the floor stays fixed, and distinct nonces issued in
/// the same second are admitted; the stored mark only rises.
///
/// The cache holds at most `CLUSTER_PEER_NONCE_CACHE_CAPACITY` entries and
/// each pinned peer at most an equal share of them. A full cache or a full
/// share refuses the request; a live entry is never evicted.
#[derive(Debug)]
pub struct PeerNonceCache {
    state: Mutex<NonceState>,
    store: Arc<SqliteClusterPeerReplayStore>,
    capacity: usize,
    per_peer_capacity: usize,
}

#[derive(Debug)]
struct NonceState {
    start: Option<i64>,
    high_water: i64,
    floors: HashMap<String, i64>,
    stored: HashMap<String, i64>,
    seen: HashSet<(String, String)>,
    by_expiry: BTreeSet<(i64, String, String)>,
    per_peer: HashMap<String, usize>,
}

impl NonceState {
    /// Fold `now_secs` into the high-water time and return the inclusive
    /// acceptance window for `node_id`, pruning every entry below the window.
    fn observe(&mut self, node_id: &str, now_secs: i64) -> (i64, i64) {
        self.high_water = self.high_water.max(now_secs);
        let start = *self.start.get_or_insert(now_secs);
        let window_start = self
            .high_water
            .saturating_sub(CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS);
        let floor = self
            .floors
            .get(node_id)
            .copied()
            .unwrap_or_else(|| start.saturating_add(CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS));
        let latest = self
            .high_water
            .saturating_add(CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS);
        while let Some((issued_at, _, _)) = self.by_expiry.first() {
            if *issued_at >= window_start {
                break;
            }
            if let Some((_, node, nonce)) = self.by_expiry.pop_first() {
                if let Some(count) = self.per_peer.get_mut(&node) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.per_peer.remove(&node);
                    }
                }
                self.seen.remove(&(node, nonce));
            }
        }
        (window_start.max(floor.saturating_add(1)), latest)
    }
}

impl PeerNonceCache {
    /// A cache for a receiver pinning `pinned_peers` peers, holding every
    /// peer high-water mark in `store`. `start_secs` is the receiver time the
    /// cache starts at; when the receiver clock cannot be read at
    /// construction, the first observed time becomes the start.
    pub fn open(
        store: Arc<SqliteClusterPeerReplayStore>,
        start_secs: Option<i64>,
        pinned_peers: usize,
    ) -> Result<Self, ClusterPeerReplayStoreError> {
        Self::with_capacity(
            store,
            start_secs,
            pinned_peers,
            CLUSTER_PEER_NONCE_CACHE_CAPACITY,
        )
    }

    /// As [`PeerNonceCache::open`], holding at most `capacity` entries.
    pub fn with_capacity(
        store: Arc<SqliteClusterPeerReplayStore>,
        start_secs: Option<i64>,
        pinned_peers: usize,
        capacity: usize,
    ) -> Result<Self, ClusterPeerReplayStoreError> {
        let floors: HashMap<String, i64> = store.high_waters()?.into_iter().collect();
        Ok(Self {
            state: Mutex::new(NonceState {
                start: start_secs,
                high_water: start_secs.unwrap_or(i64::MIN),
                stored: floors.clone(),
                floors,
                seen: HashSet::new(),
                by_expiry: BTreeSet::new(),
                per_peer: HashMap::new(),
            }),
            store,
            capacity,
            per_peer_capacity: capacity / pinned_peers.max(1),
        })
    }

    fn check_fresh(
        &self,
        node_id: &str,
        issued_at: i64,
        now_secs: i64,
    ) -> Result<(), PeerAuthError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PeerAuthError::ReplayCacheUnavailable)?;
        let (earliest, latest) = state.observe(node_id, now_secs);
        if issued_at < earliest || issued_at > latest {
            return Err(PeerAuthError::Stale);
        }
        Ok(())
    }

    fn record(
        &self,
        node_id: &str,
        nonce: &str,
        issued_at: i64,
        now_secs: i64,
    ) -> Result<(), PeerAuthError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PeerAuthError::ReplayCacheUnavailable)?;
        let (earliest, latest) = state.observe(node_id, now_secs);
        if issued_at < earliest || issued_at > latest {
            return Err(PeerAuthError::Stale);
        }
        let key = (node_id.to_string(), nonce.to_string());
        if state.seen.contains(&key) {
            return Err(PeerAuthError::ReplayedNonce);
        }
        if state.seen.len() >= self.capacity {
            return Err(PeerAuthError::ReplayCacheUnavailable);
        }
        if state.per_peer.get(node_id).copied().unwrap_or(0) >= self.per_peer_capacity {
            return Err(PeerAuthError::PeerNonceQuotaExhausted);
        }
        if state
            .stored
            .get(node_id)
            .is_none_or(|stored| issued_at > *stored)
        {
            self.store
                .advance(node_id, issued_at)
                .map_err(|_| PeerAuthError::PeerReplayStoreUnavailable)?;
            state.stored.insert(key.0.clone(), issued_at);
        }
        *state.per_peer.entry(key.0.clone()).or_insert(0) += 1;
        state
            .by_expiry
            .insert((issued_at, key.0.clone(), key.1.clone()));
        state.seen.insert(key);
        Ok(())
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

/// The request a peer signature covers. `body` is the exact request body
/// (empty for a request without one).
#[derive(Clone, Copy, Debug)]
pub struct PeerRequestTarget<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub body: &'a [u8],
}

struct SignedPeerFields<'a> {
    deployment: &'a str,
    recipient: &'a str,
    node_id: &'a str,
    body_sha256: &'a str,
    nonce: &'a str,
    issued_at: i64,
    term: Option<u64>,
}

fn peer_signature_payload(
    request: &PeerRequestTarget<'_>,
    signed: &SignedPeerFields<'_>,
) -> Result<CanonicalBytes<CanonicalJsonWitness>, TrustAccessError> {
    CanonicalBytes::from_serializable(&json!({
        "scheme": CLUSTER_PEER_SIGNATURE_SCHEME,
        "deployment": signed.deployment,
        "recipient": signed.recipient,
        "nodeId": signed.node_id,
        "method": request.method,
        "path": request.path,
        "query": request.query,
        "bodySha256": signed.body_sha256,
        "nonce": signed.nonce,
        "issuedAt": signed.issued_at,
        "term": signed.term,
    }))
    .map_err(|error| TrustAccessError::SignaturePayload(error.to_string()))
}

/// The authentication header values of one signed peer request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRequestSignature {
    pub signature: String,
    pub body_sha256: String,
    pub nonce: String,
}

/// The deployment, sending node and receiving node one peer request is
/// signed for. The receiver checks the deployment and recipient against its
/// own configuration, so a signature never authorizes another receiver.
#[derive(Clone, Copy, Debug)]
pub struct PeerAddressing<'a> {
    pub deployment: &'a str,
    pub sender: &'a str,
    pub recipient: &'a str,
}

/// Sign a peer request with this node's key. `nonce` is 32 fresh random
/// bytes; a nonce is never reused.
pub fn sign_cluster_peer_request(
    keypair: &Keypair,
    addressing: &PeerAddressing<'_>,
    request: &PeerRequestTarget<'_>,
    nonce: &[u8; 32],
    issued_at: i64,
    term: Option<u64>,
) -> Result<PeerRequestSignature, TrustAccessError> {
    let sender = normalize_cluster_url(addressing.sender)
        .map_err(|_| TrustAccessError::InvalidPeerNodeId(addressing.sender.to_string()))?;
    let recipient = normalize_cluster_url(addressing.recipient)
        .map_err(|_| TrustAccessError::InvalidPeerNodeId(addressing.recipient.to_string()))?;
    let body_sha256 = hex::encode(Sha256::digest(request.body));
    let nonce = hex::encode(nonce);
    let signed = SignedPeerFields {
        deployment: addressing.deployment,
        recipient: &recipient,
        node_id: &sender,
        body_sha256: &body_sha256,
        nonce: &nonce,
        issued_at,
        term,
    };
    let payload = peer_signature_payload(request, &signed)?;
    let signature = keypair
        .sign_wrapped(CLUSTER_PEER_SIGNATURE_SCHEME, &payload)
        .map_err(|error| TrustAccessError::SignaturePayload(error.to_string()))?;
    Ok(PeerRequestSignature {
        signature: signature.to_hex(),
        body_sha256,
        nonce,
    })
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
    #[error("cluster peer signature does not verify under a pinned key")]
    BadSignature,
    #[error("cluster peer request body does not match its signed digest")]
    BodyMismatch,
    #[error("cluster peer nonce was already used")]
    ReplayedNonce,
    #[error("cluster peer replay cache cannot admit another request")]
    ReplayCacheUnavailable,
    #[error("cluster peer has no nonce capacity left in the replay cache")]
    PeerNonceQuotaExhausted,
    #[error("cluster peer replay high-water store is unavailable")]
    PeerReplayStoreUnavailable,
    #[error("receiver clock is unavailable for cluster peer authentication")]
    ClockUnavailable,
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
            PeerAuthError::MissingScope(_) => StatusCode::FORBIDDEN,
            PeerAuthError::ReplayCacheUnavailable
            | PeerAuthError::PeerNonceQuotaExhausted
            | PeerAuthError::PeerReplayStoreUnavailable
            | PeerAuthError::ClockUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            PeerAuthError::Unauthenticated
            | PeerAuthError::BadSignature
            | PeerAuthError::BodyMismatch
            | PeerAuthError::ReplayedNonce
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
