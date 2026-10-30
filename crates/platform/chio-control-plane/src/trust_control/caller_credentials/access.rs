use std::net::SocketAddr;

use chio_core::crypto::Keypair;
use serde::Deserialize;

use super::caller::{CallerCredentials, CredentialEntry};
use super::is_clean_text;
use super::peer::{
    sign_cluster_peer_request, ClusterPeerPins, ClusterSection, PeerAddressing,
    PeerRequestSignature, PeerRequestTarget,
};
use super::scope::Scope;

const MAX_DEPLOYMENT_ID_BYTES: usize = 128;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrustAccessError {
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

/// An access configuration document as decoded from its file format, before
/// validation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessConfigDocument {
    deployment: String,
    internal_listen: SocketAddr,
    #[serde(default)]
    credentials: Vec<CredentialEntry>,
    #[serde(default)]
    cluster: ClusterSection,
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
    /// Validate a decoded access configuration document. Every failure
    /// refuses the whole document; nothing is defaulted or migrated.
    pub fn from_document(document: AccessConfigDocument) -> Result<Self, TrustAccessError> {
        let deployment = validate_deployment(&document.deployment)?;
        let credentials = CallerCredentials::from_entries(&deployment, document.credentials)?;
        let peers = ClusterPeerPins::from_config(&deployment, document.cluster)?;
        Ok(Self {
            deployment,
            internal_listen: document.internal_listen,
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
        let config = TrustAccessConfig {
            internal_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            credentials: CallerCredentials::single_client(&deployment, credential_id, secret)?,
            peers: ClusterPeerPins::unclustered(&deployment),
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
    if !is_clean_text(value, MAX_DEPLOYMENT_ID_BYTES) {
        return Err(TrustAccessError::InvalidDeployment(value.to_string()));
    }
    Ok(value.to_string())
}
