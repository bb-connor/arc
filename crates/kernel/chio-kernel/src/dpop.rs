//! DPoP (Demonstration of Proof-of-Possession) for Chio tool invocations.
//!
//! A DPoP proof is a signed canonical JSON object that binds a single tool
//! invocation to the agent's keypair. It prevents stolen-token replay by
//! requiring the agent to prove possession of the private key corresponding
//! to `capability.subject` on every invocation.
//!
//! Proof fields:
//! - `schema`:        constant `"chio.dpop_proof.v1"`
//! - `capability_id`: token ID of the capability being invoked
//! - `tool_server`:   server_id of the target tool server
//! - `tool_name`:     name of the tool being called
//! - `action_hash`:   SHA-256 hash of the serialized tool arguments
//! - `nonce`:         caller-chosen random string (replay prevention)
//! - `issued_at`:     Unix seconds when the proof was created
//! - `agent_key`:     hex-encoded public key of the signer (Ed25519 by default;
//!   `p256:` / `p384:` prefix under the FIPS crypto path)
//!
//! Verification steps (in order):
//! 0. Resource bounds -- replay identity parts fit the shipped byte limit
//! 1. Schema check -- must equal `DPOP_SCHEMA`
//! 2. Sender constraint -- `agent_key` must equal `capability.subject`
//! 3. Binding fields -- capability_id, tool_server, tool_name, action_hash all match
//! 4. Freshness -- `issued_at + proof_ttl_secs >= now` and `issued_at <= now + max_clock_skew_secs`
//! 5. Signature -- verified through the signing backend negotiated between
//!    agent and kernel; dispatches off the algorithm carried by `agent_key`
//!    and the proof's `signature` field
//! 6. Nonce replay -- nonce must not have been seen during the proof's signed validity window

use chio_security_types::clock::{Clock, ClockReading, SystemClock};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::{
    sign_canonical_with_backend, Keypair, PublicKey, Signature, SigningBackend,
};
use chio_kernel_core::{dpop_freshness_valid, nonce_admits};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use crate::replay_retention::{ReplayClock, ReplayHorizon, ReplayRetention};
use crate::KernelError;

mod accounting;
mod error;
pub use error::DpopError;
pub mod authority;
mod identity;
pub mod replay_source;
pub use identity::{
    validate_dpop_replay_identity, DEFAULT_DPOP_IDENTITY_BYTE_CAPACITY,
    MAX_DPOP_REPLAY_IDENTITY_PART_BYTES,
};

/// Schema identifier for Chio DPoP proofs.
pub const DPOP_SCHEMA: &str = "chio.dpop_proof.v1";

/// Default number of live DPoP nonce markers retained by the in-memory store.
///
/// This covers roughly 200 proofs per second across the default 300-second
/// proof lifetime, with headroom for short bursts.
pub const DEFAULT_DPOP_NONCE_STORE_CAPACITY: usize = 65_536;

/// Schema accepted by the legacy nonce-store profile. The durable v2 profile
/// requires its separately configured authority verifier, never this predicate.
#[must_use]
pub fn is_supported_dpop_schema(schema: &str) -> bool {
    schema == DPOP_SCHEMA
}

// ---------------------------------------------------------------------------
// DpopProofBody
// ---------------------------------------------------------------------------

/// The signable body of a DPoP proof.
///
/// This is the canonical-JSON-serialized message that the agent signs.
/// All fields are included in the signature; none are mutable after signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpopProofBody {
    /// Schema identifier. Must equal `DPOP_SCHEMA`.
    pub schema: String,
    /// Exact durable replay domain for v2. Absent in the legacy v1 preimage.
    /// Data supplied by a proof is never the verifier's authority selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_authority: Option<authority::DpopReplayAuthorityV1>,
    /// ID of the capability token being used for this invocation.
    pub capability_id: String,
    /// `server_id` of the tool server being called.
    pub tool_server: String,
    /// Name of the tool being invoked.
    pub tool_name: String,
    /// SHA-256 hex of the serialized tool arguments (action binding).
    pub action_hash: String,
    /// Caller-chosen random string; must be unique within the TTL window.
    pub nonce: String,
    /// Unix seconds when this proof was created.
    pub issued_at: u64,
    /// Hex-encoded Ed25519 public key of the signer (must equal capability.subject).
    pub agent_key: PublicKey,
}

// ---------------------------------------------------------------------------
// DpopProof
// ---------------------------------------------------------------------------

/// A signed DPoP proof ready for transmission.
///
/// The `signature` covers the canonical JSON of `body`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpopProof {
    /// The proof body that was signed.
    pub body: DpopProofBody,
    /// Ed25519 signature over `canonical_json_bytes(&body)`.
    pub signature: Signature,
}

impl DpopProof {
    /// Sign a proof body with the agent's Ed25519 keypair.
    ///
    /// The `keypair` must be the one corresponding to `body.agent_key`.
    /// The signature covers the canonical JSON of the body.
    pub fn sign(body: DpopProofBody, keypair: &Keypair) -> Result<DpopProof, KernelError> {
        let body_bytes =
            canonical_json_bytes(&body).map_err(|e| DpopError::Encoding(Box::new(e)))?;
        let signature = keypair.sign(&body_bytes);
        Ok(DpopProof { body, signature })
    }

    /// Sign a proof body with an arbitrary [`SigningBackend`].
    ///
    /// The backend's public key must equal `body.agent_key`. Use this entry
    /// point when the agent's signing identity is served by a FIPS backend
    /// (P-256 / P-384) rather than a direct Ed25519 keypair.
    pub fn sign_with_backend(
        body: DpopProofBody,
        backend: &dyn SigningBackend,
    ) -> Result<DpopProof, KernelError> {
        let (signature, _bytes) = sign_canonical_with_backend(backend, &body)
            .map_err(|e| DpopError::Signing(Box::new(e)))?;
        Ok(DpopProof { body, signature })
    }
}

// ---------------------------------------------------------------------------
// DpopConfig
// ---------------------------------------------------------------------------

/// Configuration for DPoP proof verification.
#[derive(Debug, Clone)]
pub struct DpopConfig {
    /// How many seconds a proof is valid after `issued_at`. Default: 300.
    pub proof_ttl_secs: u64,
    /// How many seconds of future-dated clock skew to tolerate. Default: 30.
    pub max_clock_skew_secs: u64,
    /// Maximum number of entries in the nonce replay cache. Default: 65,536.
    pub nonce_store_capacity: usize,
}

impl Default for DpopConfig {
    fn default() -> Self {
        Self {
            proof_ttl_secs: 300,
            max_clock_skew_secs: 30,
            nonce_store_capacity: DEFAULT_DPOP_NONCE_STORE_CAPACITY,
        }
    }
}

// ---------------------------------------------------------------------------
// DpopNonceStore
// ---------------------------------------------------------------------------

/// In-memory LRU nonce replay store.
///
/// Keys are `(nonce, capability_id)` pairs. Entries retain their replay
/// horizon and, for pre-dispatch transactions, the reservation owner. Signed
/// artifacts use their absolute validity horizon; the configured TTL is only
/// a fallback for callers that do not provide one.
///
/// This is intentionally synchronous (no async) and uses `std::sync::Mutex`
/// so it integrates cleanly into the `Guard` pipeline.
pub struct DpopNonceStore {
    inner: Mutex<DpopNonceState>,
    ttl: Duration,
    clock: Arc<dyn Clock>,
}

struct DpopNonceState {
    source: replay_source::SourceState,
    cache: LruCache<(String, String), DpopNonceEntry>,
    capability_counts: HashMap<String, usize>,
    per_capability_capacity: usize,
    identity_byte_capacity: usize,
    identity_bytes: usize,
    accounting_failed: bool,
    replay_clock: ReplayClock,
}

struct DpopNonceEntry {
    retention: ReplayRetention,
    dispatch_reservation_id: Option<String>,
}

/// Require a representable proof deadline before applying the verified DPoP
/// freshness predicate to production clock and configuration inputs.
#[must_use]
pub fn dpop_freshness_admits(now_secs: u64, issued_at: u64, config: &DpopConfig) -> bool {
    checked_dpop_valid_through(issued_at, config.proof_ttl_secs).is_ok()
        && dpop_freshness_valid(
            now_secs,
            issued_at,
            config.proof_ttl_secs,
            config.max_clock_skew_secs,
        )
}

impl DpopNonceStore {
    /// Create a new nonce store.
    ///
    /// `capacity` is the maximum number of (nonce, capability_id) pairs to
    /// remember. `ttl` is fallback retention for calls to
    /// [`Self::check_and_insert`] that do not supply a signed horizon.
    ///
    /// # Panics
    ///
    /// Panics when `capacity` is zero.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self::new_with_per_capability_capacity(capacity, capacity, ttl)
    }

    /// Create a nonce store with an explicit per-capability live-entry limit.
    ///
    /// This optional fairness boundary must be configured independently from
    /// the store-wide capacity. [`Self::new`] lets one capability use the full
    /// configured store capacity.
    ///
    /// # Panics
    ///
    /// Panics when either capacity is zero or when the per-capability capacity
    /// exceeds the store-wide capacity.
    pub fn new_with_per_capability_capacity(
        capacity: usize,
        per_capability_capacity: usize,
        ttl: Duration,
    ) -> Self {
        Self::new_with_identity_byte_capacity(
            capacity,
            per_capability_capacity,
            DEFAULT_DPOP_IDENTITY_BYTE_CAPACITY,
            ttl,
        )
    }

    /// Configure both marker limits and an aggregate retained identity budget.
    /// The budget conservatively includes nonce, reservation owner and both
    /// capability-key copies. Container overhead is bounded separately by the
    /// marker limit. Exhaustion denies new entries without evicting live ones.
    ///
    /// # Panics
    ///
    /// Panics on zero capacities or a per-capability limit above total capacity.
    pub fn new_with_identity_byte_capacity(
        capacity: usize,
        per_capability_capacity: usize,
        identity_byte_capacity: usize,
        ttl: Duration,
    ) -> Self {
        Self::with_clock(
            capacity,
            per_capability_capacity,
            identity_byte_capacity,
            ttl,
            Arc::new(SystemClock),
        )
    }

    /// All sampling, projection and pruning use this clock under the cache lock.
    pub fn with_clock(
        capacity: usize,
        per_capability_capacity: usize,
        identity_byte_capacity: usize,
        ttl: Duration,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let nz = match NonZeroUsize::new(capacity) {
            Some(capacity) => capacity,
            None => panic!("DPoP nonce store capacity must be greater than zero"),
        };
        if per_capability_capacity == 0 || per_capability_capacity > capacity {
            panic!(
                "DPoP nonce store per-capability capacity must be between one and the store capacity"
            );
        }
        if identity_byte_capacity == 0 {
            panic!("DPoP nonce store identity byte capacity must be greater than zero");
        }
        Self {
            inner: Mutex::new(DpopNonceState {
                source: replay_source::SourceState::new(),
                cache: LruCache::new(nz),
                capability_counts: HashMap::new(),
                per_capability_capacity,
                identity_byte_capacity,
                identity_bytes: 0,
                accounting_failed: false,
                replay_clock: ReplayClock::default(),
            }),
            ttl,
            clock,
        }
    }

    pub(crate) fn bind_clock(&mut self, clock: Arc<dyn Clock>) -> Result<(), KernelError> {
        let state = self.inner.get_mut().map_err(|_| DpopError::Unavailable)?;
        state.source.require_pristine()?;
        self.clock = clock;
        Ok(())
    }

    pub(crate) fn trusted_now(&self) -> Result<ClockReading, KernelError> {
        let mut state = self.inner.lock().map_err(|_| DpopError::Unavailable)?;
        state.source.ensure_unsealed()?;
        let now = state
            .replay_clock
            .observe("dpop_nonce", self.clock.read()?)?;
        state.source.observe_creation(now);
        Ok(now)
    }

    /// Return `(occupied_entries, capacity)` for local utilization monitoring.
    pub fn utilization(&self) -> Result<(usize, usize), KernelError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| KernelError::Dpop(DpopError::Unavailable))?;
        Ok((state.cache.len(), state.cache.cap().get()))
    }

    /// Return `(charged_identity_bytes, identity_byte_capacity)` without pruning.
    pub fn identity_byte_utilization(&self) -> Result<(usize, usize), KernelError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| KernelError::Dpop(DpopError::Unavailable))?;
        Ok((state.identity_bytes, state.identity_byte_capacity))
    }

    /// Check a nonce using the store's local fallback TTL.
    ///
    /// Signed artifacts should use [`Self::check_and_insert_through`] or an
    /// artifact-specific verifier so retention follows their actual validity.
    ///
    /// Returns `Ok(true)` if the nonce is fresh (accepted).
    /// Returns `Ok(false)` if the nonce was already used within the TTL window
    /// (rejected -- replay detected).
    /// Returns `Err` if the internal mutex is poisoned (fail-closed: deny).
    pub fn check_and_insert(&self, nonce: &str, capability_id: &str) -> Result<bool, KernelError> {
        self.check_and_insert_entry(nonce, capability_id, ReplayHorizon::Local(self.ttl), None)
    }

    /// Check and retain a nonce until an exclusive signed Unix-second expiry.
    pub fn check_and_insert_until(
        &self,
        nonce: &str,
        capability_id: &str,
        expires_at: u64,
    ) -> Result<bool, KernelError> {
        self.check_and_insert_entry(nonce, capability_id, ReplayHorizon::Until(expires_at), None)
    }

    /// Check and retain a DPoP nonce through its inclusive freshness horizon.
    pub fn check_and_insert_through(
        &self,
        nonce: &str,
        capability_id: &str,
        valid_through: u64,
    ) -> Result<bool, KernelError> {
        self.check_and_insert_entry(
            nonce,
            capability_id,
            ReplayHorizon::Through(valid_through),
            None,
        )
    }

    fn check_and_insert_entry(
        &self,
        nonce: &str,
        capability_id: &str,
        horizon: ReplayHorizon,
        dispatch_reservation_id: Option<&str>,
    ) -> Result<bool, KernelError> {
        validate_dpop_replay_identity(nonce, capability_id)?;
        if let Some(owner) = dispatch_reservation_id {
            identity::validate_part(owner)?;
        }
        let identity_bytes =
            identity::retained_bytes(nonce, capability_id, dispatch_reservation_id)?;
        let key = (nonce.to_string(), capability_id.to_string());
        let mut state = self.inner.lock().map_err(|_| {
            error!("DPoP nonce store mutex is poisoned; denying proof as fail-closed");
            KernelError::Dpop(DpopError::Unavailable)
        })?;
        state.ensure_accounting()?;
        let now = self.clock.read()?;
        state.source.begin_mutation()?;
        let now = state.replay_clock.observe("dpop_nonce", now)?;
        state.source.observe_creation(now);
        let retention = horizon.project(now);

        let already_live = state
            .cache
            .peek(&key)
            .is_some_and(|entry| !entry.retention.is_expired_at(now));
        if !nonce_admits(already_live) {
            return Ok(false);
        }

        let expired_keys = state
            .cache
            .iter()
            .filter(|(_, entry)| entry.retention.is_expired_at(now))
            .map(|(expired_key, entry)| {
                identity::retained_bytes(
                    &expired_key.0,
                    &expired_key.1,
                    entry.dispatch_reservation_id.as_deref(),
                )
                .map(|bytes| (expired_key.clone(), bytes))
            })
            .collect::<Result<Vec<_>, _>>()?;
        state.release_accounted_entries(&expired_keys)?;
        if !expired_keys.is_empty() {
            state.source.note_pruned(now.unix_millis());
        }
        if retention.signed_horizon_elapsed_at(now.unix_millis()) {
            error!("elapsed signed horizon; denying replay reservation");
            return Err(DpopError::Expired.into());
        }
        if state.cache.len() >= state.cache.cap().get() {
            error!(
                capacity = state.cache.cap().get(),
                "DPoP nonce store capacity exhausted; denying proof as fail-closed"
            );
            return Err(KernelError::Dpop(DpopError::Capacity));
        }

        let capability_entries = state
            .capability_counts
            .get(capability_id)
            .copied()
            .unwrap_or(0);
        if capability_entries >= state.per_capability_capacity {
            warn!(
                capability_id,
                capability_entries,
                per_capability_capacity = state.per_capability_capacity,
                "DPoP nonce store capability quota exhausted; preserving capacity for other capabilities"
            );
            return Err(KernelError::Dpop(DpopError::CapabilityCapacity));
        }

        let retained_bytes = state
            .identity_bytes
            .checked_add(identity_bytes)
            .filter(|bytes| *bytes <= state.identity_byte_capacity)
            .ok_or_else(identity::byte_budget_error)?;

        let next_capability_entries = capability_entries
            .checked_add(1)
            .ok_or_else(accounting::accounting_error)?;
        state.cache.put(
            key,
            DpopNonceEntry {
                retention,
                dispatch_reservation_id: dispatch_reservation_id.map(str::to_string),
            },
        );
        state.identity_bytes = retained_bytes;
        state
            .capability_counts
            .insert(capability_id.to_string(), next_capability_entries);
        warn_on_high_utilization("DPoP nonce", state.cache.len(), state.cache.cap().get());
        Ok(true)
    }

    /// Reserve a DPoP nonce through its inclusive signed freshness horizon.
    pub(crate) fn reserve_for_dispatch_through(
        &self,
        nonce: &str,
        capability_id: &str,
        valid_through: u64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.check_and_insert_entry(
            nonce,
            capability_id,
            ReplayHorizon::Through(valid_through),
            Some(reservation_id),
        )
    }

    /// Reserve a nonce until an exclusive signed Unix-second expiry.
    #[cfg(test)]
    pub(crate) fn reserve_for_dispatch_until(
        &self,
        nonce: &str,
        capability_id: &str,
        expires_at: u64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.check_and_insert_entry(
            nonce,
            capability_id,
            ReplayHorizon::Until(expires_at),
            Some(reservation_id),
        )
    }

    /// Disable owner rollback once dispatch or external authorization commits.
    /// This operation retains custody even when the clock is unavailable.
    pub(crate) fn commit_dispatch_reservation(
        &self,
        nonce: &str,
        capability_id: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        let key = (nonce.to_owned(), capability_id.to_owned());
        let mut state = self.inner.lock().map_err(|_| DpopError::Unavailable)?;
        state.ensure_accounting()?;
        let Some(entry) = state.cache.peek(&key) else {
            return Ok(false);
        };
        if entry.dispatch_reservation_id.as_deref() != Some(reservation_id) {
            return Ok(false);
        }
        let Some(bytes) = state.identity_bytes.checked_sub(reservation_id.len()) else {
            state.accounting_failed = true;
            return Err(DpopError::Accounting.into());
        };
        state.source.begin_mutation()?;
        let entry = state.cache.peek_mut(&key).ok_or(DpopError::Accounting)?;
        entry.dispatch_reservation_id = None;
        state.identity_bytes = bytes;
        Ok(true)
    }

    pub(crate) fn rollback_dispatch_reservation(
        &self,
        nonce: &str,
        capability_id: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        validate_dpop_replay_identity(nonce, capability_id)?;
        identity::validate_part(reservation_id)?;
        let bytes = identity::retained_bytes(nonce, capability_id, Some(reservation_id))?;
        let key = (nonce.to_string(), capability_id.to_string());
        let mut state = self.inner.lock().map_err(|_| {
            error!("DPoP nonce store mutex is poisoned; dispatch reservation rollback failed");
            KernelError::Dpop(DpopError::Unavailable)
        })?;
        state.ensure_accounting()?;
        state.source.begin_mutation()?;
        let owned = state
            .cache
            .peek(&key)
            .is_some_and(|entry| entry.dispatch_reservation_id.as_deref() == Some(reservation_id));
        if owned {
            state.release_accounted_entries(&[(key, bytes)])?;
        }
        Ok(owned)
    }
}

fn warn_on_high_utilization(store: &'static str, live_entries: usize, capacity: usize) {
    // The reserved fifth never exceeds capacity; this is a utilization bound.
    let alert_threshold = capacity - capacity / 5;
    if live_entries >= alert_threshold {
        warn!(
            store,
            live_entries, capacity, "replay store utilization reached 80 percent"
        );
    }
}

// ---------------------------------------------------------------------------
// verify_dpop_proof
// ---------------------------------------------------------------------------

/// Verify the stateless parts of a DPoP proof against an invocation context.
///
/// This validates schema, sender binding, invocation binding, freshness, and
/// signature, but deliberately does not consult or mutate the replay nonce
/// store. Use this only for preview paths that must not burn a nonce before the
/// authoritative invocation. Runtime execution must call [`verify_dpop_proof`].
///
/// # Arguments
///
/// * `proof` - the signed DPoP proof from the agent
/// * `capability` - the capability token being used for this invocation
/// * `expected_tool_server` - `server_id` the kernel expects
/// * `expected_tool_name` - tool name the kernel expects
/// * `expected_action_hash` - SHA-256 hex of the serialized tool arguments
/// * `config` - TTL and clock-skew bounds
pub fn verify_dpop_proof_stateless(
    proof: &DpopProof,
    capability: &CapabilityToken,
    expected_tool_server: &str,
    expected_tool_name: &str,
    expected_action_hash: &str,
    config: &DpopConfig,
    now: ClockReading,
) -> Result<(), KernelError> {
    validate_dpop_replay_identity(&proof.body.nonce, &proof.body.capability_id)?;
    // Step 1: Schema check.
    if !is_supported_dpop_schema(&proof.body.schema) || proof.body.replay_authority.is_some() {
        return Err(DpopError::Schema.into());
    }

    verify_dpop_bindings_at(
        proof,
        capability,
        expected_tool_server,
        expected_tool_name,
        expected_action_hash,
        config,
        now.unix_millis().as_secs(),
    )
}

fn checked_dpop_valid_through(issued_at: u64, ttl_secs: u64) -> Result<u64, KernelError> {
    issued_at
        .checked_add(ttl_secs)
        .ok_or_else(|| DpopError::WindowOverflow.into())
}

/// Shared cryptographic checks only. The caller must first enforce its exact
/// schema and independently selected authority domain. This never burns a nonce.
fn verify_dpop_bindings_at(
    proof: &DpopProof,
    capability: &CapabilityToken,
    expected_tool_server: &str,
    expected_tool_name: &str,
    expected_action_hash: &str,
    config: &DpopConfig,
    now_secs: u64,
) -> Result<(), KernelError> {
    // Step 2: Sender constraint -- agent_key must equal capability.subject.
    if proof.body.agent_key != capability.subject {
        return Err(DpopError::Sender.into());
    }
    for (matches, reason) in [
        (
            proof.body.capability_id == capability.id,
            DpopError::Capability,
        ),
        (
            proof.body.tool_server == expected_tool_server,
            DpopError::Server,
        ),
        (proof.body.tool_name == expected_tool_name, DpopError::Tool),
        (
            proof.body.action_hash == expected_action_hash,
            DpopError::Action,
        ),
    ] {
        if !matches {
            return Err(reason.into());
        }
    }

    // Step 4: Refuse an unrepresentable validity window before either the
    // formal comparison predicate or replay reservation can accept it.
    checked_dpop_valid_through(proof.body.issued_at, config.proof_ttl_secs)?;
    // Saturation of now + skew is an intentional upper comparison bound.
    if !dpop_freshness_admits(now_secs, proof.body.issued_at, config) {
        if proof.body.issued_at > now_secs.saturating_add(config.max_clock_skew_secs) {
            return Err(DpopError::NotYetValid.into());
        }
        return Err(DpopError::Expired.into());
    }

    // Step 5: Signature verification.
    let body_bytes =
        canonical_json_bytes(&proof.body).map_err(|e| DpopError::Encoding(Box::new(e)))?;
    if !proof.body.agent_key.verify(&body_bytes, &proof.signature) {
        return Err(KernelError::Dpop(DpopError::Signature));
    }

    Ok(())
}

/// Verify a DPoP proof against the given capability and invocation context.
///
/// All six verification steps must pass; the first failure returns an error.
///
/// # Arguments
///
/// * `proof` - the signed DPoP proof from the agent
/// * `capability` - the capability token being used for this invocation
/// * `expected_tool_server` - `server_id` the kernel expects
/// * `expected_tool_name` - tool name the kernel expects
/// * `expected_action_hash` - SHA-256 hex of the serialized tool arguments
/// * `nonce_store` - shared replay-rejection store
/// * `config` - TTL and clock-skew bounds
pub fn verify_dpop_proof(
    proof: &DpopProof,
    capability: &CapabilityToken,
    expected_tool_server: &str,
    expected_tool_name: &str,
    expected_action_hash: &str,
    nonce_store: &DpopNonceStore,
    config: &DpopConfig,
) -> Result<(), KernelError> {
    verify_dpop_proof_stateless(
        proof,
        capability,
        expected_tool_server,
        expected_tool_name,
        expected_action_hash,
        config,
        nonce_store.trusted_now()?,
    )?;

    // Step 6: Nonce replay check.
    let valid_through = checked_dpop_valid_through(proof.body.issued_at, config.proof_ttl_secs)?;
    if !nonce_store.check_and_insert_through(
        &proof.body.nonce,
        &proof.body.capability_id,
        valid_through,
    )? {
        return Err(KernelError::Dpop(DpopError::Replayed));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod backend_tests {
    use super::*;
    use chio_core::crypto::Ed25519Backend;

    #[test]
    #[should_panic(expected = "DPoP nonce store capacity must be greater than zero")]
    fn zero_capacity_is_rejected() {
        let _store = DpopNonceStore::new(0, Duration::from_secs(1));
    }

    #[test]
    fn ed25519_backend_produces_equivalent_dpop_proof() {
        // Signing via `DpopProof::sign_with_backend(..., &Ed25519Backend)` must
        // be verifier-equivalent to the `DpopProof::sign(..., &Keypair)`
        // path. The stored `agent_key.verify(...)` pathway already dispatches
        // on algorithm tag, so either signing entry point must produce a proof
        // whose verification succeeds.
        let kp = Keypair::generate();
        let backend = Ed25519Backend::new(kp.clone());
        let body = DpopProofBody {
            replay_authority: None,
            schema: DPOP_SCHEMA.to_string(),
            capability_id: "cap-1".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "tool".to_string(),
            action_hash: "hash".to_string(),
            nonce: "nonce-1".to_string(),
            issued_at: 1_000,
            agent_key: kp.public_key(),
        };
        let proof = DpopProof::sign_with_backend(body.clone(), &backend).unwrap();
        let bytes = canonical_json_bytes(&proof.body).unwrap();
        assert!(proof.body.agent_key.verify(&bytes, &proof.signature));
    }

    #[test]
    fn dispatch_reservation_rolls_back_only_for_its_owner() {
        let store = DpopNonceStore::new(4, Duration::from_secs(60));
        assert!(store
            .reserve_for_dispatch_until("nonce", "capability", u64::MAX, "owner-a")
            .unwrap());
        assert!(!store
            .rollback_dispatch_reservation("nonce", "capability", "owner-b")
            .unwrap());
        assert!(!store.check_and_insert("nonce", "capability").unwrap());
        assert!(store
            .rollback_dispatch_reservation("nonce", "capability", "owner-a")
            .unwrap());
        assert!(store.check_and_insert("nonce", "capability").unwrap());
    }

    #[test]
    fn shared_dpop_and_approval_store_capacity_pressure_does_not_evict_live_reservation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store = DpopNonceStore::new(2, Duration::from_secs(60));
        assert!(store.reserve_for_dispatch_until(
            "nonce-a",
            "capability-a",
            u64::MAX,
            "owner-a"
        )?);
        assert!(store.reserve_for_dispatch_until(
            "nonce-b",
            "capability-b",
            u64::MAX,
            "owner-b"
        )?);
        assert!(store
            .reserve_for_dispatch_until("nonce-c", "capability-c", u64::MAX, "owner-c")
            .is_err());
        assert!(!store.check_and_insert("nonce-a", "capability-a")?);
        assert!(!store.check_and_insert("nonce-b", "capability-b")?);
        assert!(store.rollback_dispatch_reservation("nonce-a", "capability-a", "owner-a")?);
        assert!(store.reserve_for_dispatch_until(
            "nonce-c",
            "capability-c",
            u64::MAX,
            "owner-c"
        )?);
        Ok(())
    }

    #[test]
    fn shared_dpop_and_approval_store_capacity_pressure_retains_consumed_key_until_expiry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store = DpopNonceStore::new(1, Duration::from_secs(60));
        assert!(store.check_and_insert("nonce-a", "capability")?);
        assert!(store.check_and_insert("nonce-b", "capability").is_err());
        assert!(!store.check_and_insert("nonce-a", "capability")?);

        let expired_store = DpopNonceStore::new(1, Duration::ZERO);
        assert!(expired_store.check_and_insert("nonce-a", "capability")?);
        assert!(expired_store.check_and_insert("nonce-b", "capability")?);
        Ok(())
    }

    #[test]
    fn per_capability_quota_preserves_capacity_for_other_capabilities(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store =
            DpopNonceStore::new_with_per_capability_capacity(512, 64, Duration::from_secs(60));
        let per_capability_capacity = store.inner.lock().unwrap().per_capability_capacity;
        assert_eq!(per_capability_capacity, 64);

        for index in 0..per_capability_capacity {
            assert!(store.check_and_insert(&format!("attacker-{index}"), "capability-a")?);
        }
        assert!(store
            .check_and_insert("attacker-over-quota", "capability-a")
            .is_err());
        assert!(store.check_and_insert("other", "capability-b")?);
        assert_eq!(store.utilization()?, (per_capability_capacity + 1, 512));
        Ok(())
    }

    #[test]
    fn small_store_capability_quota_reserves_a_fair_share() -> Result<(), KernelError> {
        let store = DpopNonceStore::new_with_per_capability_capacity(8, 1, Duration::from_secs(60));
        assert_eq!(store.inner.lock().unwrap().per_capability_capacity, 1);
        assert!(store.check_and_insert("capability-a-first", "capability-a")?);
        assert!(store
            .check_and_insert("capability-a-second", "capability-a")
            .is_err());
        assert!(store.check_and_insert("capability-b-first", "capability-b")?);
        Ok(())
    }

    #[test]
    fn default_store_allows_one_capability_to_use_configured_capacity() -> Result<(), KernelError> {
        let store = DpopNonceStore::new(8, Duration::from_secs(60));
        assert_eq!(store.inner.lock().unwrap().per_capability_capacity, 8);
        for index in 0..8 {
            assert!(store.check_and_insert(&format!("nonce-{index}"), "capability")?);
        }
        assert!(store
            .check_and_insert("nonce-over-capacity", "capability")
            .is_err());
        Ok(())
    }

    #[test]
    fn signed_expiry_overrides_local_ttl_under_pressure_and_rejects_expired_input(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let store = DpopNonceStore::new(1, Duration::ZERO);
        assert!(store.check_and_insert_until("approval-a", "intent", now + 60)?);
        assert!(!store.check_and_insert_until("approval-a", "intent", now + 60)?);
        assert!(store
            .check_and_insert_until("approval-b", "intent", now + 60)
            .is_err());

        let expired_store = DpopNonceStore::new(1, Duration::from_secs(60));
        assert!(matches!(
            expired_store.check_and_insert_until("approval-a", "intent", 0),
            Err(KernelError::Dpop(DpopError::Expired))
        ));
        assert!(expired_store.check_and_insert_until("approval-b", "intent", now + 60)?);
        Ok(())
    }

    // The P-256 / P-384 DPoP signing round-trip is exercised in
    // `chio-core-types` where the `fips` feature is directly in scope
    // (see `capability.rs` tests). The DPoP verifier path ultimately calls
    // `PublicKey::verify`, so algorithm dispatch is fully covered there.
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "dpop/clock_tests.rs"]
mod clock_tests;
