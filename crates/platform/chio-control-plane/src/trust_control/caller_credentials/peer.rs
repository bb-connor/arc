use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use axum::http::header::WWW_AUTHENTICATE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use chio_core::crypto::{Keypair, PublicKey, SigningAlgorithm};
use chio_core::{verify_wrapped_bytes, CanonicalBytes, CanonicalJsonWitness, Signature};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::access::TrustAccessError;
use super::is_lowercase_hex_32;
use super::peer_nonces::PeerNonceCache;
use super::scope::Scope;
use crate::trust_control::report_validation::{
    normalize_cluster_config_url, normalize_cluster_url,
};
use crate::trust_control::{
    plain_http_error, CLUSTER_AUTH_ISSUED_AT_HEADER, CLUSTER_AUTH_SIGNATURE_HEADER,
    CLUSTER_AUTH_TERM_HEADER, CLUSTER_NODE_ID_HEADER,
};

/// Signature scheme of a cluster peer request. The signed payload binds the
/// scheme, node id, method, path, raw query, SHA-256 of the request body,
/// single-use nonce, issue time, cluster term, the deployment and the
/// recipient node id.
pub const CLUSTER_PEER_SIGNATURE_SCHEME: &str =
    chio_core::signed_artifact::CHIO_CLUSTER_PEER_REQUEST_V1_SCHEMA;

/// Header carrying the lowercase hex SHA-256 of the request body (of the
/// empty body when there is none).
pub const CLUSTER_AUTH_BODY_SHA256_HEADER: &str = "x-chio-cluster-auth-body-sha256";

/// Header carrying the request's single-use nonce: 32 random bytes as 64
/// lowercase hex characters.
pub const CLUSTER_AUTH_NONCE_HEADER: &str = "x-chio-cluster-auth-nonce";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClusterSection {
    node_id: Option<String>,
    node_key_file: Option<PathBuf>,
    #[serde(default)]
    peers: Vec<PeerEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerEntry {
    node_id: String,
    internal_url: String,
    public_key: String,
    scopes: Vec<String>,
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
    pub(super) peers: BTreeMap<String, ClusterPeer>,
}

/// This node's own cluster identity: the node id peers address and the file
/// holding the Ed25519 seed it signs peer requests with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterNodeIdentity {
    pub node_id: String,
    pub node_key_file: PathBuf,
}

impl ClusterPeerPins {
    pub(super) fn from_config(
        deployment: &str,
        cluster: ClusterSection,
    ) -> Result<Self, TrustAccessError> {
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

    pub(super) fn unclustered(deployment: &str) -> Self {
        Self {
            deployment: deployment.to_string(),
            ..Self::default()
        }
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

pub(super) struct SignedPeerFields<'a> {
    pub(super) deployment: &'a str,
    pub(super) recipient: &'a str,
    pub(super) node_id: &'a str,
    pub(super) body_sha256: &'a str,
    pub(super) nonce: &'a str,
    pub(super) issued_at: i64,
    pub(super) term: Option<u64>,
}

pub(super) fn peer_signature_payload(
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
