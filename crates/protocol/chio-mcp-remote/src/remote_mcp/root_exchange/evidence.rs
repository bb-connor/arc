//! What a kind verifier establishes about one presented assertion.

use chio_core::capability::anchor::AnchorKind;
use chio_core::capability::scope::ChioScope;
use chio_core::root_authority::{HolderClass, Identifier, JwsAlgorithm, Sha256Digest};
use serde_json::{Map, Value};

use super::replay::ReplayKey;
use crate::ChioSenderConstraintClaims;

/// The JWS members of a verified assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwsEvidence {
    pub(super) key_snapshot_digest: Sha256Digest,
    pub(super) kid: Identifier,
    pub(super) alg: JwsAlgorithm,
}

/// A verified assertion of one anchor kind, ready for
/// [`RootExchange::prepare`](super::RootExchange::prepare).
///
/// Only a kind verifier constructs it; every member is read-only outside
/// this module.
#[derive(Debug, Clone)]
pub struct AnchorEvidence {
    pub(super) kind: AnchorKind,
    pub(super) issuer: String,
    pub(super) principal: String,
    pub(super) tenant: String,
    pub(super) token_iat: u64,
    pub(super) token_exp: u64,
    pub(super) replay_key: ReplayKey,
    pub(super) jws: Option<JwsEvidence>,
    /// SHA-256 of the presented assertion, or of the introspection response.
    pub(super) artifact_digest: Option<Sha256Digest>,
    /// SHA-256 of the request that presented the assertion.
    pub(super) request_digest: Sha256Digest,
    /// The members a rule's `match.claims` and `recorded_claims` read.
    pub(super) claims: Map<String, Value>,
    /// The identity-provider scope values the rule projection reads.
    pub(super) scope_values: Vec<String>,
    /// The provider record the assertion verified against.
    pub(super) provider_id: Option<String>,
    /// The root scope the input itself carries; the root never exceeds it.
    pub(super) scope_bound: Option<ChioScope>,
    /// The holder class the input names; any other holder refuses.
    pub(super) holder: Option<HolderClass>,
    /// The sender constraint (`cnf`) the input is bound to, which the
    /// access token issued for the root carries.
    pub(super) sender_constraint: Option<ChioSenderConstraintClaims>,
}

impl AnchorEvidence {
    #[must_use]
    pub fn kind(&self) -> AnchorKind {
        self.kind
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    #[must_use]
    pub fn replay_key(&self) -> &ReplayKey {
        &self.replay_key
    }

    #[must_use]
    pub fn token_exp(&self) -> u64 {
        self.token_exp
    }

    #[must_use]
    pub fn artifact_digest(&self) -> Option<&Sha256Digest> {
        self.artifact_digest.as_ref()
    }

    #[must_use]
    pub fn sender_constraint(&self) -> Option<&ChioSenderConstraintClaims> {
        self.sender_constraint.as_ref()
    }
}
