//! Signed verification-state replication rooted in an operator-pinned checkpoint.
//!
//! Service tokens and keys advertised by a peer cannot authorize this chain.
use super::lifecycle::{
    apply_lifecycle_change, AuthorityLifecycleChange, DEFAULT_ISSUER_VERIFICATION_GRACE_SECONDS,
};
use super::{AuthoritySnapshot, AuthorityStoreError, AuthorityTrustedKeySnapshot};
use chio_core::canonical::CanonicalBytes;
use chio_core::crypto::{sha256_hex, Keypair, PublicKey, Signature, SigningAlgorithm};
use serde::{Deserialize, Serialize};

pub const MAX_AUTHORITY_CHAIN: usize = 1024;
pub const MAX_AUTHORITY_KEYS: usize = 4096;
pub const MAX_AUTHORITY_WIRE_BYTES: usize = 4 * 1024 * 1024;
pub const AUTHORITY_ENVELOPE_LIFETIME_SECONDS: u64 = 300;
const LEGACY_ANCHOR_SCHEMA: &str = "chio.authority-replication-anchor.v1";
const ANCHOR_SCHEMA: &str = "chio.authority-replication-anchor.v2";
const LEGACY_TRANSITION_SCHEMA: &str = "chio.authority-rotation.v1";
const TRANSITION_SCHEMA: &str = "chio.authority-lifecycle.v2";
const LEGACY_ENVELOPE_SCHEMA: &str = "chio.authority-snapshot.v1";
const ENVELOPE_SCHEMA: &str = "chio.authority-snapshot.v2";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityReplicationAnchor {
    pub schema: String,
    pub stream_id: String,
    pub snapshot: AuthoritySnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_public_key_hex: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityTransitionBody {
    pub schema: String,
    pub stream_id: String,
    pub anchor_digest: String,
    pub previous_commitment: String,
    pub generation: u64,
    pub public_key_hex: String,
    pub rotated_at: u64,
    pub issuer_set_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<AuthorityLifecycleChange>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedAuthorityTransition {
    pub body: AuthorityTransitionBody,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySnapshotProof {
    pub schema: String,
    pub stream_id: String,
    pub anchor_digest: String,
    pub chain_commitment: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub transitions: Vec<SignedAuthorityTransition>,
    pub signature: Signature,
}

/// Legacy unsigned wire input can decode, but can never pass `verify`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedAuthoritySnapshot {
    #[serde(flatten)]
    pub snapshot: AuthoritySnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<AuthoritySnapshotProof>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnvelopeBody<'a> {
    schema: &'a str,
    stream_id: &'a str,
    anchor_digest: &'a str,
    chain_commitment: &'a str,
    issued_at: u64,
    expires_at: u64,
    snapshot: &'a AuthoritySnapshot,
}

impl AuthorityReplicationAnchor {
    pub fn new(
        stream_id: String,
        snapshot: AuthoritySnapshot,
    ) -> Result<Self, AuthorityStoreError> {
        let anchor = Self {
            schema: ANCHOR_SCHEMA.into(),
            stream_id,
            snapshot,
            recovery_public_key_hex: None,
        };
        anchor.validate()?;
        Ok(anchor)
    }

    pub fn validate(&self) -> Result<(), AuthorityStoreError> {
        if !matches!(self.schema.as_str(), ANCHOR_SCHEMA | LEGACY_ANCHOR_SCHEMA)
            || self.stream_id.is_empty()
            || self.stream_id.len() > 128
            || !self
                .stream_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
        {
            return Err(refused("invalid replication anchor domain"));
        }
        if let Some(recovery) = &self.recovery_public_key_hex {
            canonical_key(recovery)?;
            if self.schema != ANCHOR_SCHEMA
                || self
                    .snapshot
                    .trusted_keys
                    .iter()
                    .any(|key| &key.public_key_hex == recovery)
            {
                return Err(refused("recovery root must be independently pinned"));
            }
        }
        validate_state(&self.snapshot)
    }

    pub fn commitment(&self) -> Result<String, AuthorityStoreError> {
        self.validate()?;
        digest(self)
    }
}

impl SignedAuthorityTransition {
    pub fn sign(
        anchor: &AuthorityReplicationAnchor,
        previous: &AuthoritySnapshot,
        previous_commitment: &str,
        next_key: &PublicKey,
        rotated_at: u64,
        signer: &Keypair,
    ) -> Result<Self, AuthorityStoreError> {
        let verify_until = rotated_at
            .checked_add(DEFAULT_ISSUER_VERIFICATION_GRACE_SECONDS)
            .ok_or_else(|| refused("issuer deadline overflow"))?;
        Self::sign_change(
            anchor,
            previous,
            previous_commitment,
            AuthorityLifecycleChange::Rotate { verify_until },
            next_key,
            rotated_at,
            signer,
        )
    }

    pub fn sign_change(
        anchor: &AuthorityReplicationAnchor,
        previous: &AuthoritySnapshot,
        previous_commitment: &str,
        change: AuthorityLifecycleChange,
        next_key: &PublicKey,
        at: u64,
        signer: &Keypair,
    ) -> Result<Self, AuthorityStoreError> {
        let expected = if matches!(change, AuthorityLifecycleChange::Recover) {
            anchor
                .recovery_public_key_hex
                .as_deref()
                .ok_or_else(|| refused("no independent recovery root is pinned"))?
        } else {
            previous.public_key_hex.as_str()
        };
        if signer.public_key().to_hex() != expected {
            return Err(refused(
                "lifecycle signer does not own the required authority",
            ));
        }
        require_distinct_recovery_root(anchor, &next_key.to_hex())?;
        let next = apply_lifecycle_change(previous, &change, &next_key.to_hex(), at)?;
        let body = AuthorityTransitionBody {
            schema: TRANSITION_SCHEMA.into(),
            stream_id: anchor.stream_id.clone(),
            anchor_digest: anchor.commitment()?,
            previous_commitment: previous_commitment.into(),
            generation: next.generation,
            public_key_hex: next.public_key_hex.clone(),
            rotated_at: at,
            issuer_set_digest: digest(&next.trusted_keys)?,
            change: Some(change),
        };
        let signature = signer.sign_canonical(&body)?.0;
        Ok(Self { body, signature })
    }

    pub fn commitment(&self) -> Result<String, AuthorityStoreError> {
        digest(self)
    }
}

/// Verify every retained rotation from the pinned checkpoint, returning the
/// authenticated final state and commitment. No network-supplied trust anchors.
pub fn verify_authority_chain(
    anchor: &AuthorityReplicationAnchor,
    chain: &[SignedAuthorityTransition],
) -> Result<(AuthoritySnapshot, String), AuthorityStoreError> {
    let anchor_digest = anchor.commitment()?;
    if chain.len() > MAX_AUTHORITY_CHAIN {
        return Err(refused("authority chain limit exceeded"));
    }
    let mut state = anchor.snapshot.clone();
    let mut commitment = anchor_digest.clone();
    for transition in chain {
        let body = &transition.body;
        if !matches!(
            body.schema.as_str(),
            TRANSITION_SCHEMA | LEGACY_TRANSITION_SCHEMA
        ) || body.stream_id != anchor.stream_id
            || body.anchor_digest != anchor_digest
            || body.previous_commitment != commitment
            || state.generation.checked_add(1) != Some(body.generation)
        {
            return Err(refused(
                "authority transition predecessor or domain mismatch",
            ));
        }
        let signer = if matches!(body.change, Some(AuthorityLifecycleChange::Recover)) {
            anchor
                .recovery_public_key_hex
                .as_deref()
                .ok_or_else(|| refused("no independent recovery root is pinned"))?
        } else {
            state.public_key_hex.as_str()
        };
        let key = canonical_key(signer)?;
        if !key.verify_canonical_strict(body, &transition.signature)? {
            return Err(refused("authority transition signature invalid"));
        }
        require_distinct_recovery_root(anchor, &body.public_key_hex)?;
        state = match (body.schema.as_str(), body.change.as_ref()) {
            (TRANSITION_SCHEMA, Some(change)) => {
                apply_lifecycle_change(&state, change, &body.public_key_hex, body.rotated_at)?
            }
            (LEGACY_TRANSITION_SCHEMA, None)
                if anchor.schema == LEGACY_ANCHOR_SCHEMA
                    && state.trusted_keys.iter().all(|key| key.lifecycle.is_none()) =>
            {
                advance(&state, &body.public_key_hex, body.rotated_at)?
            }
            _ => {
                return Err(refused(
                    "authority lifecycle downgrade or missing operation",
                ))
            }
        };
        if digest(&state.trusted_keys)? != body.issuer_set_digest {
            return Err(refused("authority issuer-set digest mismatch"));
        }
        commitment = transition.commitment()?;
    }
    Ok((state, commitment))
}

fn require_distinct_recovery_root(
    anchor: &AuthorityReplicationAnchor,
    issuer: &str,
) -> Result<(), AuthorityStoreError> {
    if anchor.recovery_public_key_hex.as_deref() == Some(issuer) {
        return Err(refused("recovery root cannot be a capability issuer"));
    }
    Ok(())
}

impl SignedAuthoritySnapshot {
    pub fn sign(
        anchor: &AuthorityReplicationAnchor,
        chain: Vec<SignedAuthorityTransition>,
        now: u64,
        signer: &Keypair,
    ) -> Result<Self, AuthorityStoreError> {
        let (snapshot, commitment) = verify_authority_chain(anchor, &chain)?;
        if signer.public_key().to_hex() != snapshot.public_key_hex || now < snapshot.rotated_at {
            return Err(refused(
                "snapshot signing requires current head custody and time",
            ));
        }
        let expires_at = now
            .checked_add(AUTHORITY_ENVELOPE_LIFETIME_SECONDS)
            .ok_or_else(|| refused("authority envelope time overflow"))?;
        let anchor_digest = anchor.commitment()?;
        let body = EnvelopeBody {
            schema: ENVELOPE_SCHEMA,
            stream_id: &anchor.stream_id,
            anchor_digest: &anchor_digest,
            chain_commitment: &commitment,
            issued_at: now,
            expires_at,
            snapshot: &snapshot,
        };
        let signature = signer.sign_canonical(&body)?.0;
        Ok(Self {
            snapshot,
            proof: Some(AuthoritySnapshotProof {
                schema: ENVELOPE_SCHEMA.into(),
                stream_id: anchor.stream_id.clone(),
                anchor_digest,
                chain_commitment: commitment,
                issued_at: now,
                expires_at,
                transitions: chain,
                signature,
            }),
        })
    }

    /// The expected state and commitment come from the receiver's transaction.
    /// Returning success authorizes only this exact snapshot, never extra keys.
    pub fn verify(
        &self,
        anchor: &AuthorityReplicationAnchor,
        current: &AuthoritySnapshot,
        current_commitment: &str,
        now: u64,
    ) -> Result<&AuthoritySnapshotProof, AuthorityStoreError> {
        let proof = self
            .proof
            .as_ref()
            .ok_or_else(|| refused("unsigned authority snapshot"))?;
        if !matches!(
            proof.schema.as_str(),
            ENVELOPE_SCHEMA | LEGACY_ENVELOPE_SCHEMA
        ) || (proof.schema == LEGACY_ENVELOPE_SCHEMA
            && self
                .snapshot
                .trusted_keys
                .iter()
                .any(|key| key.lifecycle.is_some()))
            || proof.stream_id != anchor.stream_id
            || proof.anchor_digest != anchor.commitment()?
        {
            return Err(refused("authority envelope domain mismatch"));
        }
        if proof.issued_at > now
            || proof.expires_at <= now
            || proof.expires_at <= proof.issued_at
            || proof.expires_at - proof.issued_at > AUTHORITY_ENVELOPE_LIFETIME_SECONDS
            || proof.issued_at < self.snapshot.rotated_at
        {
            return Err(refused("authority envelope outside freshness window"));
        }
        let (derived, commitment) = verify_authority_chain(anchor, &proof.transitions)?;
        if derived != self.snapshot || commitment != proof.chain_commitment {
            return Err(refused(
                "authority snapshot differs from authenticated chain",
            ));
        }
        let prefix_len = current
            .generation
            .checked_sub(anchor.snapshot.generation)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| refused("authority replay regression"))?;
        let prefix = proof
            .transitions
            .get(..prefix_len)
            .ok_or_else(|| refused("authority replay regression"))?;
        let (prefix_state, prefix_commitment) = verify_authority_chain(anchor, prefix)?;
        if &prefix_state != current || prefix_commitment != current_commitment {
            return Err(refused("authority history conflict"));
        }
        let body = EnvelopeBody {
            schema: &proof.schema,
            stream_id: &proof.stream_id,
            anchor_digest: &proof.anchor_digest,
            chain_commitment: &proof.chain_commitment,
            issued_at: proof.issued_at,
            expires_at: proof.expires_at,
            snapshot: &self.snapshot,
        };
        if !canonical_key(&self.snapshot.public_key_hex)?
            .verify_canonical_strict(&body, &proof.signature)?
        {
            return Err(refused("authority envelope signature invalid"));
        }
        Ok(proof)
    }
}

pub fn validate_state(state: &AuthoritySnapshot) -> Result<(), AuthorityStoreError> {
    canonical_key(&state.public_key_hex)?;
    if state.generation == 0
        || state.generation > i64::MAX.unsigned_abs()
        || state.rotated_at > i64::MAX.unsigned_abs()
        || state.trusted_keys.is_empty()
        || state.trusted_keys.len() > MAX_AUTHORITY_KEYS
    {
        return Err(refused("invalid authority state bounds"));
    }
    let mut last_generation = 0;
    let mut last_time = 0;
    let mut keys = std::collections::BTreeSet::new();
    for key in &state.trusted_keys {
        canonical_key(&key.public_key_hex)?;
        if key.generation <= last_generation
            || key.generation > state.generation
            || key.activated_at < last_time
            || key.activated_at > state.rotated_at
            || !keys.insert(&key.public_key_hex)
        {
            return Err(refused("invalid authority history"));
        }
        last_generation = key.generation;
        last_time = key.activated_at;
    }
    if !state.trusted_keys.last().is_some_and(|key| {
        key.public_key_hex == state.public_key_hex
            && key.generation <= state.generation
            && key.activated_at <= state.rotated_at
    }) {
        return Err(refused("authority head missing from history"));
    }
    if state.trusted_keys.iter().all(|key| key.lifecycle.is_none())
        && !state.trusted_keys.last().is_some_and(|key| {
            key.generation == state.generation && key.activated_at == state.rotated_at
        })
    {
        return Err(refused("legacy authority head does not match generation"));
    }
    super::lifecycle::validate_lifecycle(state)
}

fn advance(
    previous: &AuthoritySnapshot,
    public_key: &str,
    at: u64,
) -> Result<AuthoritySnapshot, AuthorityStoreError> {
    validate_state(previous)?;
    canonical_key(public_key)?;
    if at < previous.rotated_at
        || previous
            .trusted_keys
            .iter()
            .any(|key| key.public_key_hex == public_key)
    {
        return Err(refused("authority rotation regresses time or reuses a key"));
    }
    let generation = previous
        .generation
        .checked_add(1)
        .ok_or_else(|| refused("authority generation exhausted"))?;
    let mut next = previous.clone();
    next.public_key_hex = public_key.into();
    next.generation = generation;
    next.rotated_at = at;
    next.trusted_keys.push(AuthorityTrustedKeySnapshot {
        public_key_hex: public_key.into(),
        generation,
        activated_at: at,
        lifecycle: None,
    });
    validate_state(&next)?;
    Ok(next)
}

fn canonical_key(encoded: &str) -> Result<PublicKey, AuthorityStoreError> {
    let key = PublicKey::from_hex(encoded)?;
    if key.algorithm() != SigningAlgorithm::Ed25519
        || key.is_weak_ed25519()
        || key.to_hex() != encoded
    {
        return Err(refused("authority key must be canonical strong Ed25519"));
    }
    Ok(key)
}

fn digest(value: &impl Serialize) -> Result<String, AuthorityStoreError> {
    Ok(sha256_hex(
        CanonicalBytes::from_serializable(value)?.as_bytes(),
    ))
}
fn refused(message: &str) -> AuthorityStoreError {
    AuthorityStoreError::Fence(message.into())
}
