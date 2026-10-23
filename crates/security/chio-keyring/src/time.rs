use std::collections::BTreeMap;
use std::sync::Arc;

use chio_core_types::{Hash, PublicKey, Signature, SigningBackend};
use serde::{Deserialize, Serialize};

use crate::signing::{sign_wrapped_value, verify_wrapped_value};
use crate::{derive_key_id, AnchorId, KeyId, KeyringError, Result};

pub const ARTIFACT_TIME_ANCHOR_SCHEMA: &str = "chio.key-log.artifact-time-anchor.v1";

pub use chio_security_types::clock::{Clock, SystemClock};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactTimeAnchorKind {
    ReceiptCheckpoint {
        checkpoint_sequence: u64,
        checkpoint_hash: Hash,
    },
    KeyLogCheckpoint {
        checkpoint_sequence: u64,
        checkpoint_hash: Hash,
    },
    External {
        commitment: Hash,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactTimeAnchorBody {
    pub schema: String,
    pub anchor_id: AnchorId,
    pub artifact_hash: Hash,
    pub anchored_at: u64,
    pub anchor: ArtifactTimeAnchorKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedArtifactTimeAnchor {
    pub body: ArtifactTimeAnchorBody,
    pub anchor_key_id: KeyId,
    pub signature: Signature,
}

impl SignedArtifactTimeAnchor {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        crate::from_bounded_json(bytes)
    }

    pub fn sign(body: ArtifactTimeAnchorBody, signer: &dyn SigningBackend) -> Result<Self> {
        let outcome = sign_wrapped_value(signer, ARTIFACT_TIME_ANCHOR_SCHEMA, &body)?;
        let anchor_key_id = derive_key_id(outcome.public_key.algorithm(), &outcome.public_key)?;
        Ok(Self {
            body,
            anchor_key_id,
            signature: outcome.signature,
        })
    }
}

#[derive(Clone)]
pub struct ArtifactTimeVerifier {
    trust_roots: BTreeMap<AnchorId, PublicKey>,
    policy_binding: Hash,
    clock: Arc<dyn Clock>,
    max_future_skew: u64,
}

impl ArtifactTimeVerifier {
    pub(crate) fn new(
        trust_roots: BTreeMap<AnchorId, PublicKey>,
        policy_binding: Hash,
        clock: Arc<dyn Clock>,
        max_future_skew: u64,
    ) -> Result<Self> {
        if trust_roots.is_empty() {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        let mut key_ids = std::collections::BTreeSet::new();
        for key in trust_roots.values() {
            if !key_ids.insert(derive_key_id(key.algorithm(), key)?) {
                return Err(KeyringError::DuplicateIdentifier);
            }
        }
        Ok(Self {
            trust_roots,
            policy_binding,
            clock,
            max_future_skew,
        })
    }

    pub fn verify(&self, signed: &SignedArtifactTimeAnchor) -> Result<ArtifactTimeEvidence> {
        if signed.body.schema != ARTIFACT_TIME_ANCHOR_SCHEMA {
            return Err(KeyringError::UnsupportedSchema(signed.body.schema.clone()));
        }
        let key = self
            .trust_roots
            .get(&signed.body.anchor_id)
            .ok_or(KeyringError::InvalidArtifactTimeEvidence)?;
        if derive_key_id(key.algorithm(), key)? != signed.anchor_key_id
            || verify_wrapped_value(
                key,
                ARTIFACT_TIME_ANCHOR_SCHEMA,
                &signed.body,
                &signed.signature,
            )
            .is_err()
        {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        chio_security_types::clock::validate_future_skew(
            chio_security_types::clock::UnixMillis::new(signed.body.anchored_at),
            self.clock.unix_millis()?,
            self.max_future_skew,
        )?;
        Ok(ArtifactTimeEvidence {
            artifact_hash: signed.body.artifact_hash,
            anchored_at: signed.body.anchored_at,
            anchor: signed.body.anchor.clone(),
            policy_binding: self.policy_binding,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ArtifactTimeEvidence {
    artifact_hash: Hash,
    anchored_at: u64,
    anchor: ArtifactTimeAnchorKind,
    policy_binding: Hash,
}

impl ArtifactTimeEvidence {
    #[must_use]
    pub fn artifact_hash(&self) -> Hash {
        self.artifact_hash
    }

    #[must_use]
    pub fn anchored_at(&self) -> u64 {
        self.anchored_at
    }

    #[must_use]
    pub fn anchor(&self) -> &ArtifactTimeAnchorKind {
        &self.anchor
    }

    pub(crate) fn policy_binding(&self) -> Hash {
        self.policy_binding
    }
}
