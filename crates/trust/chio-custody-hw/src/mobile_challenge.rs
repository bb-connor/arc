//! Server-owned one-time challenge custody for mobile attestation.
//!
//! Platform attestation only proves freshness when the verifier, rather than
//! the mobile caller, owns the expected challenge. [`MobileChallengeAuthority`]
//! issues cryptographically random challenges, binds them to one exact app and
//! audience, and returns verified evidence only after the backing store
//! atomically consumes the challenge. App Attest counter advancement is
//! committed in the same critical section as challenge consumption.
//!
//! The in-memory store is suitable for tests and one-process development. A
//! production issuer should use [`SqliteMobileChallengeStore`] (enabled by the
//! default `sqlite-store` feature) or another store with equivalent atomic and
//! durable semantics shared by every issuer replica. The SQLite store requires
//! an absolute normalized path in a private, caller-owned Unix directory and
//! continuously validates the retained database descriptor's owner, mode,
//! link count, device, and inode before and after every operation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64ct::{Base64UrlUnpadded, Encoding};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::attestation::{
    verify_app_attest, verify_play_integrity, AppAttestVerificationInput, AttestationError,
    PlayIntegrityVerificationInput, VerifiedAppAttest, VerifiedPlayIntegrity,
};

pub const MOBILE_CHALLENGE_SCHEMA: &str = "chio.mobile-attestation.challenge.v1";
pub const DEFAULT_MOBILE_CHALLENGE_LIFETIME_SECONDS: u64 = 300;
pub const DEFAULT_MAX_MOBILE_CHALLENGES: usize = 65_536;
pub const DEFAULT_MAX_APP_ATTEST_COUNTERS: usize = 65_536;
pub const URN_MOBILE_CHALLENGE_INVALID: &str = "urn:chio:error:custody:mobile-challenge-invalid";
pub const URN_MOBILE_CHALLENGE_REPLAYED: &str = "urn:chio:error:custody:mobile-challenge-replayed";
pub const URN_MOBILE_CHALLENGE_STORE_UNAVAILABLE: &str =
    "urn:chio:error:custody:mobile-challenge-store-unavailable";

const MAX_MOBILE_CHALLENGE_LIFETIME_SECONDS: u64 = 600;
const MOBILE_CHALLENGE_BYTES: usize = 32;
const MAX_BINDING_VALUE_BYTES: usize = 512;
const MAX_RANDOM_COLLISION_RETRIES: usize = 4;
const MOBILE_CHALLENGE_ID_DOMAIN: &[u8] = b"chio.mobile-attestation.challenge-id.v1\0";

#[derive(Debug, Error)]
pub enum MobileChallengeError {
    #[error("mobile attestation challenge is invalid: {0}")]
    Invalid(String),
    #[error("mobile attestation challenge `{challenge_id}` was already consumed")]
    Replayed { challenge_id: String },
    #[error("mobile attestation challenge store is unavailable: {0}")]
    StoreUnavailable(String),
    #[error(transparent)]
    Attestation(#[from] AttestationError),
}

impl MobileChallengeError {
    #[must_use]
    pub fn urn(&self) -> &'static str {
        match self {
            Self::Invalid(_) => URN_MOBILE_CHALLENGE_INVALID,
            Self::Replayed { .. } => URN_MOBILE_CHALLENGE_REPLAYED,
            Self::StoreUnavailable(_) => URN_MOBILE_CHALLENGE_STORE_UNAVAILABLE,
            Self::Attestation(error) => error.urn(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum MobileAttestationBinding {
    AppAttest {
        key_id: String,
        app_id: String,
        audience: String,
    },
    PlayIntegrity {
        package_name: String,
        audience: String,
    },
}

impl MobileAttestationBinding {
    fn validate(&self) -> Result<(), MobileChallengeError> {
        match self {
            Self::AppAttest {
                key_id,
                app_id,
                audience,
            } => {
                validate_binding_value(key_id, "App Attest key id")?;
                validate_binding_value(app_id, "App Attest app id")?;
                validate_binding_value(audience, "App Attest audience")
            }
            Self::PlayIntegrity {
                package_name,
                audience,
            } => {
                validate_binding_value(package_name, "Play Integrity package name")?;
                validate_binding_value(audience, "Play Integrity audience")
            }
        }
    }

    fn app_attest_counter_key(&self) -> Option<(&str, &str)> {
        match self {
            Self::AppAttest { key_id, app_id, .. } => Some((key_id, app_id)),
            Self::PlayIntegrity { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuedMobileChallenge {
    pub schema: String,
    pub challenge_id: String,
    pub nonce: String,
    pub binding: MobileAttestationBinding,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

impl IssuedMobileChallenge {
    pub fn validate(&self) -> Result<(), MobileChallengeError> {
        self.binding.validate()?;
        validate_now(self.issued_at_unix_seconds)?;
        validate_now(self.expires_at_unix_seconds)?;
        if self.schema != MOBILE_CHALLENGE_SCHEMA
            || self.challenge_id.len() != 64
            || !self
                .challenge_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            || self.expires_at_unix_seconds <= self.issued_at_unix_seconds
            || self
                .expires_at_unix_seconds
                .saturating_sub(self.issued_at_unix_seconds)
                > MAX_MOBILE_CHALLENGE_LIFETIME_SECONDS
        {
            return Err(MobileChallengeError::Invalid(
                "schema, identifier, or validity window is invalid".to_string(),
            ));
        }
        let nonce = self.nonce_bytes()?;
        if derive_challenge_id(&nonce, &self.binding)? != self.challenge_id {
            return Err(MobileChallengeError::Invalid(
                "challenge identifier does not bind its nonce and application".to_string(),
            ));
        }
        Ok(())
    }

    fn nonce_bytes(&self) -> Result<[u8; MOBILE_CHALLENGE_BYTES], MobileChallengeError> {
        let decoded = Base64UrlUnpadded::decode_vec(&self.nonce).map_err(|error| {
            MobileChallengeError::Invalid(format!("challenge nonce is not base64url: {error}"))
        })?;
        decoded.try_into().map_err(|_| {
            MobileChallengeError::Invalid(format!(
                "challenge nonce must contain exactly {MOBILE_CHALLENGE_BYTES} bytes"
            ))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileChallengeSnapshot {
    challenge: IssuedMobileChallenge,
    previous_app_attest_counter: Option<u32>,
}

impl MobileChallengeSnapshot {
    #[must_use]
    pub fn challenge(&self) -> &IssuedMobileChallenge {
        &self.challenge
    }

    #[must_use]
    pub const fn previous_app_attest_counter(&self) -> Option<u32> {
        self.previous_app_attest_counter
    }
}

/// Durable state boundary for issued mobile challenges.
///
/// Implementations must make `consume_verified` atomic across challenge state
/// and App Attest counter state. If commit durability is uncertain, they must
/// return [`MobileChallengeError::StoreUnavailable`] and callers must deny.
pub trait MobileChallengeStore: Send + Sync {
    /// Register a challenge if its cryptographic identifier is absent.
    /// Returns `false` only for an identifier collision.
    fn register_if_absent(
        &self,
        challenge: &IssuedMobileChallenge,
    ) -> Result<bool, MobileChallengeError>;

    /// Load one issued, unexpired challenge and its exact counter snapshot.
    fn load_active(
        &self,
        challenge_id: &str,
        now_unix_seconds: u64,
    ) -> Result<MobileChallengeSnapshot, MobileChallengeError>;

    /// Atomically consume verified evidence and, for App Attest, advance its
    /// per-key counter from the value captured by `load_active`.
    fn consume_verified(
        &self,
        snapshot: &MobileChallengeSnapshot,
        verified_app_attest_counter: Option<u32>,
        now_unix_seconds: u64,
    ) -> Result<(), MobileChallengeError>;

    /// Remove expired challenge rows. Counter rows are intentionally retained.
    fn gc_expired(&self, now_unix_seconds: u64) -> Result<usize, MobileChallengeError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedMobileAttestationEvidence {
    AppAttest(VerifiedAppAttest),
    PlayIntegrity(VerifiedPlayIntegrity),
}

/// Verified evidence plus the exact authority-owned context it satisfied.
///
/// Fields stay private so capability issuance can consume this result without
/// accidentally replacing its challenge, application, or audience binding
/// with caller-supplied values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMobileAttestation {
    challenge_id: String,
    binding: MobileAttestationBinding,
    evidence: VerifiedMobileAttestationEvidence,
}

impl VerifiedMobileAttestation {
    #[must_use]
    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    #[must_use]
    pub const fn binding(&self) -> &MobileAttestationBinding {
        &self.binding
    }

    #[must_use]
    pub const fn evidence(&self) -> &VerifiedMobileAttestationEvidence {
        &self.evidence
    }
}

pub struct MobileChallengeAuthority {
    store: Arc<dyn MobileChallengeStore>,
    lifetime_seconds: u64,
}

impl MobileChallengeAuthority {
    #[must_use]
    pub fn new(store: Arc<dyn MobileChallengeStore>) -> Self {
        Self {
            store,
            lifetime_seconds: DEFAULT_MOBILE_CHALLENGE_LIFETIME_SECONDS,
        }
    }

    pub fn with_lifetime(
        store: Arc<dyn MobileChallengeStore>,
        lifetime_seconds: u64,
    ) -> Result<Self, MobileChallengeError> {
        if lifetime_seconds == 0 || lifetime_seconds > MAX_MOBILE_CHALLENGE_LIFETIME_SECONDS {
            return Err(MobileChallengeError::Invalid(
                "mobile challenge lifetime is outside the supported bound".to_string(),
            ));
        }
        Ok(Self {
            store,
            lifetime_seconds,
        })
    }

    pub fn issue(
        &self,
        binding: MobileAttestationBinding,
        now_unix_seconds: u64,
    ) -> Result<IssuedMobileChallenge, MobileChallengeError> {
        self.issue_with_rng(binding, now_unix_seconds, &mut OsRng)
    }

    fn issue_with_rng<R: CryptoRng + RngCore>(
        &self,
        binding: MobileAttestationBinding,
        now_unix_seconds: u64,
        rng: &mut R,
    ) -> Result<IssuedMobileChallenge, MobileChallengeError> {
        binding.validate()?;
        validate_now(now_unix_seconds)?;
        let expires_at_unix_seconds = now_unix_seconds
            .checked_add(self.lifetime_seconds)
            .ok_or_else(|| {
                MobileChallengeError::Invalid("challenge expiry overflowed".to_string())
            })?;
        for _ in 0..MAX_RANDOM_COLLISION_RETRIES {
            let mut nonce = [0_u8; MOBILE_CHALLENGE_BYTES];
            rng.try_fill_bytes(&mut nonce).map_err(|error| {
                MobileChallengeError::StoreUnavailable(format!(
                    "operating-system entropy failed: {error}"
                ))
            })?;
            let challenge = build_challenge(
                binding.clone(),
                nonce,
                now_unix_seconds,
                expires_at_unix_seconds,
            )?;
            if self.store.register_if_absent(&challenge)? {
                return Ok(challenge);
            }
        }
        Err(MobileChallengeError::StoreUnavailable(
            "challenge identifier collision retry bound was exhausted".to_string(),
        ))
    }

    pub fn verify_app_attest_and_consume(
        &self,
        challenge_id: &str,
        attestation_cbor: &[u8],
        now_unix_seconds: u64,
    ) -> Result<VerifiedMobileAttestation, MobileChallengeError> {
        let snapshot = self.store.load_active(challenge_id, now_unix_seconds)?;
        let MobileAttestationBinding::AppAttest { key_id, app_id, .. } =
            &snapshot.challenge.binding
        else {
            return Err(MobileChallengeError::Invalid(
                "challenge platform does not match App Attest".to_string(),
            ));
        };
        let nonce = snapshot.challenge.nonce_bytes()?;
        let verified = verify_app_attest(AppAttestVerificationInput {
            attestation_cbor,
            key_id,
            challenge: &nonce,
            app_id,
            previous_counter: snapshot.previous_app_attest_counter,
            production: true,
            allow_development_fixture: false,
        })?;
        self.store
            .consume_verified(&snapshot, Some(verified.counter), now_unix_seconds)?;
        Ok(VerifiedMobileAttestation {
            challenge_id: snapshot.challenge.challenge_id.clone(),
            binding: snapshot.challenge.binding.clone(),
            evidence: VerifiedMobileAttestationEvidence::AppAttest(verified),
        })
    }

    pub fn verify_play_integrity_and_consume(
        &self,
        challenge_id: &str,
        token: &str,
        now_unix_seconds: u64,
    ) -> Result<VerifiedMobileAttestation, MobileChallengeError> {
        let snapshot = self.store.load_active(challenge_id, now_unix_seconds)?;
        let MobileAttestationBinding::PlayIntegrity {
            package_name,
            audience,
        } = &snapshot.challenge.binding
        else {
            return Err(MobileChallengeError::Invalid(
                "challenge platform does not match Play Integrity".to_string(),
            ));
        };
        let verified = verify_play_integrity(PlayIntegrityVerificationInput {
            token,
            expected_nonce: &snapshot.challenge.nonce,
            expected_package_name: package_name,
            expected_audience: audience,
            jwks_json: "",
            allow_caller_supplied_jwks: false,
        })?;
        self.store
            .consume_verified(&snapshot, None, now_unix_seconds)?;
        Ok(VerifiedMobileAttestation {
            challenge_id: snapshot.challenge.challenge_id.clone(),
            binding: snapshot.challenge.binding.clone(),
            evidence: VerifiedMobileAttestationEvidence::PlayIntegrity(verified),
        })
    }
}

#[derive(Debug, Clone)]
struct MemoryChallengeRecord {
    challenge: IssuedMobileChallenge,
    consumed_at_unix_seconds: Option<u64>,
}

#[derive(Default)]
struct MemoryState {
    challenges: HashMap<String, MemoryChallengeRecord>,
    app_attest_counters: HashMap<(String, String), u32>,
}

pub struct InMemoryMobileChallengeStore {
    state: Mutex<MemoryState>,
    max_challenges: usize,
    max_app_attest_counters: usize,
}

impl Default for InMemoryMobileChallengeStore {
    fn default() -> Self {
        Self {
            state: Mutex::new(MemoryState::default()),
            max_challenges: DEFAULT_MAX_MOBILE_CHALLENGES,
            max_app_attest_counters: DEFAULT_MAX_APP_ATTEST_COUNTERS,
        }
    }
}

impl InMemoryMobileChallengeStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(
        max_challenges: usize,
        max_app_attest_counters: usize,
    ) -> Result<Self, MobileChallengeError> {
        validate_store_limits(max_challenges, max_app_attest_counters)?;
        Ok(Self {
            state: Mutex::new(MemoryState::default()),
            max_challenges,
            max_app_attest_counters,
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MemoryState>, MobileChallengeError> {
        self.state.lock().map_err(|error| {
            MobileChallengeError::StoreUnavailable(format!(
                "mobile challenge mutex was poisoned: {error}"
            ))
        })
    }
}

impl MobileChallengeStore for InMemoryMobileChallengeStore {
    fn register_if_absent(
        &self,
        challenge: &IssuedMobileChallenge,
    ) -> Result<bool, MobileChallengeError> {
        challenge.validate()?;
        let mut state = self.lock()?;
        if state.challenges.contains_key(&challenge.challenge_id) {
            return Ok(false);
        }
        if state.challenges.len() >= self.max_challenges {
            return Err(MobileChallengeError::StoreUnavailable(
                "mobile challenge capacity was exhausted".to_string(),
            ));
        }
        state.challenges.insert(
            challenge.challenge_id.clone(),
            MemoryChallengeRecord {
                challenge: challenge.clone(),
                consumed_at_unix_seconds: None,
            },
        );
        Ok(true)
    }

    fn load_active(
        &self,
        challenge_id: &str,
        now_unix_seconds: u64,
    ) -> Result<MobileChallengeSnapshot, MobileChallengeError> {
        validate_challenge_id(challenge_id)?;
        validate_now(now_unix_seconds)?;
        let state = self.lock()?;
        let record = state
            .challenges
            .get(challenge_id)
            .ok_or_else(|| MobileChallengeError::Invalid("challenge is unknown".to_string()))?;
        ensure_record_active(record, now_unix_seconds)?;
        let previous_app_attest_counter = record
            .challenge
            .binding
            .app_attest_counter_key()
            .and_then(|(key_id, app_id)| {
                state
                    .app_attest_counters
                    .get(&(key_id.to_string(), app_id.to_string()))
                    .copied()
            });
        Ok(MobileChallengeSnapshot {
            challenge: record.challenge.clone(),
            previous_app_attest_counter,
        })
    }

    fn consume_verified(
        &self,
        snapshot: &MobileChallengeSnapshot,
        verified_app_attest_counter: Option<u32>,
        now_unix_seconds: u64,
    ) -> Result<(), MobileChallengeError> {
        snapshot.challenge.validate()?;
        validate_now(now_unix_seconds)?;
        let mut state = self.lock()?;
        let record = state
            .challenges
            .get(&snapshot.challenge.challenge_id)
            .cloned()
            .ok_or_else(|| MobileChallengeError::Invalid("challenge is unknown".to_string()))?;
        if record.challenge != snapshot.challenge {
            return Err(MobileChallengeError::Invalid(
                "challenge snapshot does not match stored state".to_string(),
            ));
        }
        ensure_record_active(&record, now_unix_seconds)?;
        apply_counter_transition(
            &mut state.app_attest_counters,
            snapshot,
            verified_app_attest_counter,
            self.max_app_attest_counters,
        )?;
        let stored = state
            .challenges
            .get_mut(&snapshot.challenge.challenge_id)
            .ok_or_else(|| MobileChallengeError::Invalid("challenge is unknown".to_string()))?;
        stored.consumed_at_unix_seconds = Some(now_unix_seconds);
        Ok(())
    }

    fn gc_expired(&self, now_unix_seconds: u64) -> Result<usize, MobileChallengeError> {
        validate_now(now_unix_seconds)?;
        let mut state = self.lock()?;
        let before = state.challenges.len();
        state
            .challenges
            .retain(|_, record| record.challenge.expires_at_unix_seconds > now_unix_seconds);
        Ok(before - state.challenges.len())
    }
}

fn build_challenge(
    binding: MobileAttestationBinding,
    nonce: [u8; MOBILE_CHALLENGE_BYTES],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
) -> Result<IssuedMobileChallenge, MobileChallengeError> {
    let challenge = IssuedMobileChallenge {
        schema: MOBILE_CHALLENGE_SCHEMA.to_string(),
        challenge_id: derive_challenge_id(&nonce, &binding)?,
        nonce: Base64UrlUnpadded::encode_string(&nonce),
        binding,
        issued_at_unix_seconds,
        expires_at_unix_seconds,
    };
    challenge.validate()?;
    Ok(challenge)
}

fn derive_challenge_id(
    nonce: &[u8; MOBILE_CHALLENGE_BYTES],
    binding: &MobileAttestationBinding,
) -> Result<String, MobileChallengeError> {
    let canonical_binding = chio_core_types::canonical_json_bytes(binding).map_err(|error| {
        MobileChallengeError::Invalid(format!("challenge binding encoding failed: {error}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(MOBILE_CHALLENGE_ID_DOMAIN);
    hasher.update(nonce);
    hasher.update(canonical_binding);
    Ok(hex::encode(hasher.finalize()))
}

fn validate_binding_value(value: &str, label: &str) -> Result<(), MobileChallengeError> {
    if value.is_empty()
        || value.len() > MAX_BINDING_VALUE_BYTES
        || value.trim() != value
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(MobileChallengeError::Invalid(format!(
            "{label} is empty, oversized, padded, or contains a control byte"
        )));
    }
    Ok(())
}

fn validate_challenge_id(challenge_id: &str) -> Result<(), MobileChallengeError> {
    if challenge_id.len() != 64
        || !challenge_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(MobileChallengeError::Invalid(
            "challenge identifier must be lowercase SHA-256 hex".to_string(),
        ));
    }
    Ok(())
}

fn validate_now(now_unix_seconds: u64) -> Result<(), MobileChallengeError> {
    if now_unix_seconds == 0 || i64::try_from(now_unix_seconds).is_err() {
        return Err(MobileChallengeError::Invalid(
            "challenge authority clock is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_store_limits(
    max_challenges: usize,
    max_app_attest_counters: usize,
) -> Result<(), MobileChallengeError> {
    if max_challenges == 0
        || max_challenges > DEFAULT_MAX_MOBILE_CHALLENGES
        || max_app_attest_counters == 0
        || max_app_attest_counters > DEFAULT_MAX_APP_ATTEST_COUNTERS
    {
        return Err(MobileChallengeError::Invalid(
            "mobile challenge store limits are invalid".to_string(),
        ));
    }
    Ok(())
}

fn ensure_record_active(
    record: &MemoryChallengeRecord,
    now_unix_seconds: u64,
) -> Result<(), MobileChallengeError> {
    if record.consumed_at_unix_seconds.is_some() {
        return Err(MobileChallengeError::Replayed {
            challenge_id: record.challenge.challenge_id.clone(),
        });
    }
    if now_unix_seconds < record.challenge.issued_at_unix_seconds
        || now_unix_seconds >= record.challenge.expires_at_unix_seconds
    {
        return Err(MobileChallengeError::Invalid(
            "challenge is outside its validity window".to_string(),
        ));
    }
    Ok(())
}

fn apply_counter_transition(
    counters: &mut HashMap<(String, String), u32>,
    snapshot: &MobileChallengeSnapshot,
    verified_app_attest_counter: Option<u32>,
    max_counters: usize,
) -> Result<(), MobileChallengeError> {
    match snapshot.challenge.binding.app_attest_counter_key() {
        Some((key_id, app_id)) => {
            let counter = verified_app_attest_counter.ok_or_else(|| {
                MobileChallengeError::Invalid(
                    "verified App Attest evidence did not carry a counter".to_string(),
                )
            })?;
            let key = (key_id.to_string(), app_id.to_string());
            let current = counters.get(&key).copied();
            if current != snapshot.previous_app_attest_counter {
                return Err(MobileChallengeError::Invalid(
                    "App Attest counter state changed during verification".to_string(),
                ));
            }
            if current.is_some_and(|previous| counter <= previous) {
                return Err(MobileChallengeError::Attestation(
                    AttestationError::CounterRollback,
                ));
            }
            if current.is_none() && counters.len() >= max_counters {
                return Err(MobileChallengeError::StoreUnavailable(
                    "App Attest counter capacity was exhausted".to_string(),
                ));
            }
            counters.insert(key, counter);
            Ok(())
        }
        None if verified_app_attest_counter.is_none() => Ok(()),
        None => Err(MobileChallengeError::Invalid(
            "Play Integrity evidence cannot advance an App Attest counter".to_string(),
        )),
    }
}

#[cfg(feature = "sqlite-store")]
mod sqlite;
#[cfg(feature = "sqlite-store")]
pub use sqlite::SqliteMobileChallengeStore;

#[cfg(test)]
mod tests;
