use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::{
    canonical_json_bytes, Hash, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use serde::{Deserialize, Serialize};

use crate::{derive_key_id, AnchorId, KeyId, KeyringError, Result};

pub const ARTIFACT_TIME_ANCHOR_SCHEMA: &str = "chio.key-log.artifact-time-anchor.v1";
const ARTIFACT_TIME_SIGNATURE_DOMAIN: &[u8] = b"chio.key-log.artifact-time-anchor.v1\0";

pub trait TrustedClock: Send + Sync {
    fn now(&self) -> Result<u64>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemTrustedClock;

impl TrustedClock for SystemTrustedClock {
    fn now(&self) -> Result<u64> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| KeyringError::InvalidTimeOrdering)?;
        u64::try_from(duration.as_millis()).map_err(|_| KeyringError::NumericRange)
    }
}

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
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

impl SignedArtifactTimeAnchor {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        crate::from_bounded_json(bytes)
    }

    pub fn sign(body: ArtifactTimeAnchorBody, signer: &dyn SigningBackend) -> Result<Self> {
        let outcome = signer.sign_bytes_with_identity(&artifact_time_signing_bytes(&body)?)?;
        let anchor_key_id = derive_key_id(outcome.algorithm, &outcome.public_key)?;
        if outcome.public_key.algorithm() != outcome.algorithm
            || outcome.signature.algorithm() != outcome.algorithm
        {
            return Err(KeyringError::AlgorithmMismatch);
        }
        Ok(Self {
            body,
            anchor_key_id,
            algorithm: outcome.algorithm,
            signature: outcome.signature,
        })
    }
}

#[derive(Clone)]
pub struct ArtifactTimeVerifier {
    trust_roots: BTreeMap<AnchorId, PublicKey>,
    policy_binding: Hash,
    clock: Arc<dyn TrustedClock>,
    max_future_skew: u64,
}

impl ArtifactTimeVerifier {
    pub(crate) fn new(
        trust_roots: BTreeMap<AnchorId, PublicKey>,
        policy_binding: Hash,
        clock: Arc<dyn TrustedClock>,
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
        if key.algorithm() != signed.algorithm
            || signed.signature.algorithm() != signed.algorithm
            || derive_key_id(key.algorithm(), key)? != signed.anchor_key_id
            || !key.verify(
                &artifact_time_signing_bytes(&signed.body)?,
                &signed.signature,
            )
        {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        let latest = self
            .clock
            .now()?
            .checked_add(self.max_future_skew)
            .ok_or(KeyringError::NumericRange)?;
        if signed.body.anchored_at > latest {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
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

fn artifact_time_signing_bytes(body: &ArtifactTimeAnchorBody) -> Result<Vec<u8>> {
    let canonical = canonical_json_bytes(body)?;
    let capacity = ARTIFACT_TIME_SIGNATURE_DOMAIN
        .len()
        .checked_add(canonical.len())
        .ok_or(KeyringError::NumericRange)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(ARTIFACT_TIME_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}
