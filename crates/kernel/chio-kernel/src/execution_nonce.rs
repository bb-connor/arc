//! Execution nonces prevent TOCTOU races between capability evaluation and tool-server dispatch.
//!
//! An `ExecutionNonce` is a short-lived, single-use token that the kernel
//! attaches to every `Verdict::Allow` response. Tool servers MUST present
//! the nonce before executing; the kernel rejects stale (>`nonce_ttl_secs`,
//! default 30s) or replayed nonces. This closes the time-of-check /
//! time-of-use window between `evaluate()` and tool-server execution that
//! DPoP alone cannot close.
//!
//! # Design
//!
//! * The nonce body is an opaque `nonce_id` plus a `NonceBinding` that
//!   binds the nonce to the exact `(subject, capability, server, tool,
//!   parameter_hash)` tuple. Substituting a nonce between unrelated tool
//!   calls therefore fails the binding check.
//! * The kernel signs the full body (nonce id + binding + expires_at)
//!   with its receipt-signing key, so downstream tool servers can
//!   cryptographically verify authenticity without a round trip.
//! * Replay is prevented by an `ExecutionNonceStore`: the first
//!   `reserve(nonce_id)` returns true and consumes the nonce; any
//!   subsequent reservation returns false and the verify path rejects.
//!
//! # Backward compatibility
//!
//! The whole feature is opt-in by installing an `ExecutionNonceConfig`.
//! With no config installed, no nonce is minted and non-nonce callers keep
//! working. With a config installed and `require_nonce == false`, allow
//! responses carry nonces and dispatch verifies any nonce that is presented,
//! but callers that omit the nonce remain backward-compatible. New strict
//! deployments flip `require_nonce` to make every execution-bound dispatch
//! present a fresh nonce.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{Keypair, PublicKey, Signature};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tracing::{error, warn};
use uuid::Uuid;

use crate::admission_operation::ReplayReservationState;
use crate::KernelError;

const MAX_NONCE_RESERVATION_IDENTIFIER_BYTES: usize = 512;

/// Schema identifier for Chio execution nonces.
pub const EXECUTION_NONCE_SCHEMA: &str = "chio.execution_nonce.v1";

/// Default TTL for a freshly minted execution nonce.
pub const DEFAULT_EXECUTION_NONCE_TTL_SECS: u64 = 30;

/// Default capacity for the in-memory replay-prevention LRU cache.
pub const DEFAULT_EXECUTION_NONCE_STORE_CAPACITY: usize = 16_384;

#[must_use]
pub fn is_supported_execution_nonce_schema(schema: &str) -> bool {
    schema == EXECUTION_NONCE_SCHEMA
}

// ---------------------------------------------------------------------------
// NonceBinding
// ---------------------------------------------------------------------------

/// Fields that tie a nonce to one specific tool invocation.
///
/// All five fields are in the signed body, so any mismatch during verify
/// means either the nonce was minted for a different call or the nonce was
/// tampered with after issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceBinding {
    /// Hex-encoded subject (agent) public key, taken from `capability.subject`.
    pub subject_id: String,
    /// ID of the capability that authorized this invocation.
    pub capability_id: String,
    /// Tool server that is expected to execute the call.
    pub tool_server: String,
    /// Tool name that is expected to execute.
    pub tool_name: String,
    /// SHA-256 hex of the canonical JSON of the evaluated arguments. Taken
    /// directly from the `ToolCallAction::parameter_hash` that the kernel
    /// embedded in the allow receipt.
    pub parameter_hash: String,
}

// ---------------------------------------------------------------------------
// ExecutionNonce (signable body)
// ---------------------------------------------------------------------------

/// The signable body of an execution nonce.
///
/// This is the canonical-JSON-serialized message the kernel signs. Every
/// field is covered by the signature; none are mutable after issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionNonce {
    /// Schema identifier. Must equal `EXECUTION_NONCE_SCHEMA`.
    pub schema: String,
    /// Unique nonce identifier (UUIDv7 hex).
    pub nonce_id: String,
    /// Unix timestamp (seconds) when the kernel issued this nonce.
    pub issued_at: i64,
    /// Unix timestamp (seconds) when this nonce expires.
    /// Default: `issued_at + 30`. Configurable via `ExecutionNonceConfig`.
    pub expires_at: i64,
    /// Invocation binding: subject, capability, server, tool, parameter hash.
    pub bound_to: NonceBinding,
}

// ---------------------------------------------------------------------------
// SignedExecutionNonce
// ---------------------------------------------------------------------------

/// A kernel-signed execution nonce ready for transmission on an allow verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedExecutionNonce {
    /// The nonce body that was signed.
    pub nonce: ExecutionNonce,
    /// Ed25519 signature over `canonical_json_bytes(&nonce)` produced by the
    /// kernel's receipt-signing key.
    pub signature: Signature,
}

impl SignedExecutionNonce {
    /// Convenience accessor for the nonce identifier.
    #[must_use]
    pub fn nonce_id(&self) -> &str {
        &self.nonce.nonce_id
    }

    /// Convenience accessor for the expiry.
    #[must_use]
    pub fn expires_at(&self) -> i64 {
        self.nonce.expires_at
    }
}

// ---------------------------------------------------------------------------
// ExecutionNonceConfig
// ---------------------------------------------------------------------------

/// Configuration for execution nonce issuance and verification.
#[derive(Debug, Clone)]
pub struct ExecutionNonceConfig {
    /// How many seconds a nonce is valid after issuance. Default: 30.
    pub nonce_ttl_secs: u64,
    /// Maximum entries in the replay-prevention LRU cache. Default: 16_384.
    pub nonce_store_capacity: usize,
    /// When `true`, the kernel's strict-mode verify paths reject any call
    /// that does not present a signed nonce. Default: `false` (opt-in).
    pub require_nonce: bool,
}

impl Default for ExecutionNonceConfig {
    fn default() -> Self {
        Self {
            nonce_ttl_secs: DEFAULT_EXECUTION_NONCE_TTL_SECS,
            nonce_store_capacity: DEFAULT_EXECUTION_NONCE_STORE_CAPACITY,
            require_nonce: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ExecutionNonceStore trait
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionNonceReservationError {
    #[error("invalid execution nonce reservation: {0}")]
    Invalid(String),
    #[error("execution nonce reservation conflict: {0}")]
    Conflict(String),
    #[error("execution nonce reservation not found: {0}")]
    NotFound(String),
    #[error("execution nonce reservation store unavailable: {0}")]
    Store(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionNonceReservation {
    operation_id: String,
    nonce_id: String,
    signed_expires_at: i64,
    state: ReplayReservationState,
}

impl ExecutionNonceReservation {
    pub fn new(
        operation_id: String,
        nonce_id: String,
        signed_expires_at: i64,
    ) -> Result<Self, ExecutionNonceReservationError> {
        validate_nonce_operation_id(&operation_id)?;
        validate_nonce_reservation_identifier(&nonce_id, "nonce_id")?;
        if signed_expires_at <= 0 {
            return Err(ExecutionNonceReservationError::Invalid(
                "signed_expires_at must be positive".to_string(),
            ));
        }
        Ok(Self {
            operation_id,
            nonce_id,
            signed_expires_at,
            state: ReplayReservationState::Reserved,
        })
    }

    pub fn from_persisted_parts(
        operation_id: String,
        nonce_id: String,
        signed_expires_at: i64,
        state: ReplayReservationState,
    ) -> Result<Self, ExecutionNonceReservationError> {
        let mut reservation = Self::new(operation_id, nonce_id, signed_expires_at)?;
        reservation.state = state;
        Ok(reservation)
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn nonce_id(&self) -> &str {
        &self.nonce_id
    }

    pub fn signed_expires_at(&self) -> i64 {
        self.signed_expires_at
    }

    pub fn state(&self) -> ReplayReservationState {
        self.state
    }
}

fn validate_nonce_reservation_identifier(
    value: &str,
    label: &'static str,
) -> Result<(), ExecutionNonceReservationError> {
    if value.is_empty()
        || value.len() > MAX_NONCE_RESERVATION_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte == 0)
        || value.trim() != value
    {
        return Err(ExecutionNonceReservationError::Invalid(format!(
            "{label} is empty, oversized, padded, or contains NUL"
        )));
    }
    Ok(())
}

fn validate_nonce_operation_id(value: &str) -> Result<(), ExecutionNonceReservationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ExecutionNonceReservationError::Invalid(
            "operation_id must be lowercase SHA-256 hex".to_string(),
        ));
    }
    Ok(())
}

/// Persistence boundary for replay-prevention of execution nonces.
///
/// Implementations MUST ensure that `reserve(nonce_id)` returns `true`
/// exactly once per nonce identifier. All subsequent calls for the same
/// identifier return `false`. Fail-closed: any internal error is returned
/// via `KernelError` so the caller can deny the request.
pub trait ExecutionNonceStore: Send + Sync {
    /// Attempt to reserve (consume) the given nonce identifier.
    ///
    /// * `Ok(true)`  -- nonce was fresh; it is now marked consumed.
    /// * `Ok(false)` -- nonce has already been consumed (replay detected).
    /// * `Err(_)`    -- the store is unreachable or corrupted; fail-closed.
    ///
    /// Prefer [`Self::reserve_until`] when the caller knows the signed
    /// expiry of the nonce: durable stores need to retain the consumed
    /// marker at least as long as the signed nonce is valid, otherwise
    /// the row may be pruned and the nonce can be replayed within its
    /// remaining validity window.
    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError>;

    /// Reserve a nonce while telling the store when the nonce stops
    /// being cryptographically valid. Durable implementations (SQLite,
    /// remote KV stores) MUST retain the consumed marker until at least
    /// `nonce_expires_at` so replay protection covers the nonce's full
    /// validity window.
    ///
    /// The default implementation falls back to [`Self::reserve`] for
    /// in-memory / best-effort stores that already track retention
    /// internally. `nonce_expires_at` is wall-clock unix seconds.
    fn reserve_until(&self, nonce_id: &str, _nonce_expires_at: i64) -> Result<bool, KernelError> {
        self.reserve(nonce_id)
    }

    /// Atomically bind a nonce and its signed expiry to one operation.
    /// The default fails closed and never delegates to immediate consumption.
    fn reserve_nonce_for_operation(
        &self,
        _operation_id: &str,
        _nonce_id: &str,
        _signed_expires_at: i64,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        Err(ExecutionNonceReservationError::Store(
            "operation-owned execution nonce reservations are unavailable".to_string(),
        ))
    }

    fn commit_nonce_reservation(
        &self,
        _operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        Err(ExecutionNonceReservationError::Store(
            "operation-owned execution nonce reservations are unavailable".to_string(),
        ))
    }

    fn cancel_nonce_reservation(
        &self,
        _operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        Err(ExecutionNonceReservationError::Store(
            "operation-owned execution nonce reservations are unavailable".to_string(),
        ))
    }

    fn get_nonce_reservation(
        &self,
        _operation_id: &str,
    ) -> Result<Option<ExecutionNonceReservation>, ExecutionNonceReservationError> {
        Err(ExecutionNonceReservationError::Store(
            "operation-owned execution nonce reservations are unavailable".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// InMemoryExecutionNonceStore
// ---------------------------------------------------------------------------

/// In-memory LRU-backed execution nonce store.
///
/// Mirrors the shape of `dpop::DpopNonceStore` but keys on the nonce_id
/// alone because the full binding lives inside the signed body and is
/// checked separately by `verify_execution_nonce`.
struct InMemoryExecutionNonceState {
    consumed: LruCache<String, Instant>,
    reservations_by_operation: std::collections::HashMap<String, ExecutionNonceReservation>,
    nonce_owners: std::collections::HashMap<String, String>,
}

pub struct InMemoryExecutionNonceStore {
    inner: Mutex<InMemoryExecutionNonceState>,
    ttl: Duration,
}

impl InMemoryExecutionNonceStore {
    /// Create a new in-memory store.
    ///
    /// `capacity` is the maximum number of recently consumed nonces to
    /// remember. `ttl` is how long a nonce entry is retained when callers use
    /// the legacy `reserve` path. `reserve_until` extends retention to cover
    /// the signed nonce validity window.
    #[must_use]
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let nz = NonZeroUsize::new(capacity).unwrap_or_else(|| {
            NonZeroUsize::new(DEFAULT_EXECUTION_NONCE_STORE_CAPACITY).unwrap_or(NonZeroUsize::MIN)
        });
        Self {
            inner: Mutex::new(InMemoryExecutionNonceState {
                consumed: LruCache::new(nz),
                reservations_by_operation: std::collections::HashMap::new(),
                nonce_owners: std::collections::HashMap::new(),
            }),
            ttl,
        }
    }

    /// Build a store with the TTL and capacity from `config`.
    #[must_use]
    pub fn from_config(config: &ExecutionNonceConfig) -> Self {
        Self::new(
            config.nonce_store_capacity,
            Duration::from_secs(config.nonce_ttl_secs),
        )
    }
}

impl Default for InMemoryExecutionNonceStore {
    fn default() -> Self {
        Self::new(
            DEFAULT_EXECUTION_NONCE_STORE_CAPACITY,
            Duration::from_secs(DEFAULT_EXECUTION_NONCE_TTL_SECS),
        )
    }
}

impl ExecutionNonceStore for InMemoryExecutionNonceStore {
    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError> {
        self.reserve_with_retention(nonce_id, self.ttl)
    }

    fn reserve_until(&self, nonce_id: &str, nonce_expires_at: i64) -> Result<bool, KernelError> {
        let retention = duration_until_unix_secs(nonce_expires_at)
            .map_or(self.ttl, |remaining| remaining.max(self.ttl));
        self.reserve_with_retention(nonce_id, retention)
    }

    fn reserve_nonce_for_operation(
        &self,
        operation_id: &str,
        nonce_id: &str,
        signed_expires_at: i64,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        let requested = ExecutionNonceReservation::new(
            operation_id.to_string(),
            nonce_id.to_string(),
            signed_expires_at,
        )?;
        let mut state = self.inner.lock().map_err(|_| {
            ExecutionNonceReservationError::Store(
                "execution nonce reservation map poisoned".to_string(),
            )
        })?;
        if let Some(existing) = state.reservations_by_operation.get(operation_id) {
            if existing.nonce_id == requested.nonce_id
                && existing.signed_expires_at == requested.signed_expires_at
            {
                return Ok(existing.clone());
            }
            return Err(ExecutionNonceReservationError::Conflict(format!(
                "operation `{operation_id}` is already bound to a different nonce"
            )));
        }
        if let Some(owner) = state.nonce_owners.get(nonce_id) {
            return Err(ExecutionNonceReservationError::Conflict(format!(
                "nonce `{nonce_id}` is already owned by operation `{owner}`"
            )));
        }
        let now = Instant::now();
        if let Some(retain_until) = state.consumed.peek(nonce_id) {
            if *retain_until > now {
                return Err(ExecutionNonceReservationError::Conflict(format!(
                    "nonce `{nonce_id}` was already consumed"
                )));
            }
            state.consumed.pop(nonce_id);
        }
        state
            .nonce_owners
            .insert(nonce_id.to_string(), operation_id.to_string());
        state
            .reservations_by_operation
            .insert(operation_id.to_string(), requested.clone());
        Ok(requested)
    }

    fn commit_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        self.transition_nonce_reservation(operation_id, ReplayReservationState::Committed)
    }

    fn cancel_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        self.transition_nonce_reservation(operation_id, ReplayReservationState::Cancelled)
    }

    fn get_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<Option<ExecutionNonceReservation>, ExecutionNonceReservationError> {
        validate_nonce_operation_id(operation_id)?;
        let state = self.inner.lock().map_err(|_| {
            ExecutionNonceReservationError::Store(
                "execution nonce reservation map poisoned".to_string(),
            )
        })?;
        Ok(state.reservations_by_operation.get(operation_id).cloned())
    }
}

impl InMemoryExecutionNonceStore {
    fn transition_nonce_reservation(
        &self,
        operation_id: &str,
        target: ReplayReservationState,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        validate_nonce_operation_id(operation_id)?;
        let mut state = self.inner.lock().map_err(|_| {
            ExecutionNonceReservationError::Store(
                "execution nonce reservation map poisoned".to_string(),
            )
        })?;
        let reservation = state
            .reservations_by_operation
            .get_mut(operation_id)
            .ok_or_else(|| ExecutionNonceReservationError::NotFound(operation_id.to_string()))?;
        match (reservation.state, target) {
            (current, requested) if current == requested => Ok(reservation.clone()),
            (
                ReplayReservationState::Reserved,
                ReplayReservationState::Committed | ReplayReservationState::Cancelled,
            ) => {
                reservation.state = target;
                Ok(reservation.clone())
            }
            (current, requested) => Err(ExecutionNonceReservationError::Conflict(format!(
                "operation `{operation_id}` nonce reservation cannot transition from {} to {}",
                current.as_str(),
                requested.as_str()
            ))),
        }
    }

    fn reserve_with_retention(
        &self,
        nonce_id: &str,
        retention: Duration,
    ) -> Result<bool, KernelError> {
        let mut cache = self.inner.lock().map_err(|_| {
            error!("execution nonce store mutex poisoned; denying fail-closed");
            KernelError::Internal("execution nonce store mutex poisoned; fail-closed".to_string())
        })?;

        if cache.nonce_owners.contains_key(nonce_id) {
            return Ok(false);
        }
        let key = nonce_id.to_string();
        let now = Instant::now();
        if let Some(retain_until) = cache.consumed.peek(&key) {
            if *retain_until > now {
                return Ok(false);
            }
            cache.consumed.pop(&key);
        }
        let Some(retain_until) = now.checked_add(retention) else {
            error!("execution nonce retention overflow; denying fail-closed");
            return Err(KernelError::Internal(
                "execution nonce retention overflow; fail-closed".to_string(),
            ));
        };
        cache.consumed.put(key, retain_until);
        Ok(true)
    }
}

fn duration_until_unix_secs(expires_at: i64) -> Option<Duration> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let expires_at = u64::try_from(expires_at).ok()?;
    expires_at.checked_sub(now).map(Duration::from_secs)
}

// ---------------------------------------------------------------------------
// Minting
// ---------------------------------------------------------------------------

/// Mint a fresh signed execution nonce.
///
/// The kernel calls this on every `Verdict::Allow` so tool servers can
/// verify that a call was authorized by the kernel at a known, recent
/// time. The returned nonce is signed by `kernel_keypair`; downstream
/// verifiers check the signature with the kernel's public key.
pub fn mint_execution_nonce(
    kernel_keypair: &Keypair,
    binding: NonceBinding,
    config: &ExecutionNonceConfig,
    now: i64,
) -> Result<SignedExecutionNonce, KernelError> {
    let ttl = i64::try_from(config.nonce_ttl_secs).unwrap_or(i64::MAX);
    let expires_at = now.saturating_add(ttl);
    let nonce = ExecutionNonce {
        schema: EXECUTION_NONCE_SCHEMA.to_string(),
        nonce_id: Uuid::now_v7().as_hyphenated().to_string(),
        issued_at: now,
        expires_at,
        bound_to: binding,
    };
    let (signature, _bytes) = kernel_keypair.sign_canonical(&nonce).map_err(|e| {
        KernelError::ReceiptSigningFailed(format!("failed to sign execution nonce: {e}"))
    })?;
    Ok(SignedExecutionNonce { nonce, signature })
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// All the reasons an execution nonce can fail verification.
///
/// Every variant is a hard deny on the kernel side. The nonce flow is
/// fail-closed: schema, expiry, binding, signature, and replay checks all
/// execute on every presented nonce and any failure short-circuits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionNonceError {
    /// Schema did not equal `EXECUTION_NONCE_SCHEMA`.
    BadSchema { got: String },
    /// Nonce has expired (now >= expires_at).
    Expired { now: i64, expires_at: i64 },
    /// Binding fields did not match the presented invocation.
    BindingMismatch { field: &'static str },
    /// Ed25519 signature did not verify under the kernel's public key.
    InvalidSignature,
    /// Nonce was already consumed (single-use).
    Replayed,
    /// Canonical JSON serialization failed during verification.
    Encoding(String),
    /// Replay store was unreachable; fail-closed.
    Store(String),
}

impl std::fmt::Display for ExecutionNonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSchema { got } => write!(
                f,
                "execution nonce has unsupported schema: expected {EXECUTION_NONCE_SCHEMA}, got {got}"
            ),
            Self::Expired { now, expires_at } => write!(
                f,
                "execution nonce expired (now={now}, expires_at={expires_at})"
            ),
            Self::BindingMismatch { field } => {
                write!(f, "execution nonce binding mismatch on field {field}")
            }
            Self::InvalidSignature => write!(f, "execution nonce signature is invalid"),
            Self::Replayed => write!(f, "execution nonce has already been consumed"),
            Self::Encoding(e) => write!(f, "execution nonce canonical encoding failed: {e}"),
            Self::Store(e) => write!(f, "execution nonce store error: {e}"),
        }
    }
}

impl std::error::Error for ExecutionNonceError {}

impl From<ExecutionNonceError> for KernelError {
    fn from(err: ExecutionNonceError) -> Self {
        KernelError::Internal(format!("execution nonce verification failed: {err}"))
    }
}

/// Verify a signed execution nonce against the expected binding.
///
/// Steps, in order:
/// 1. Schema check.
/// 2. Expiry check -- `now < nonce.expires_at`.
/// 3. Binding check -- subject, capability, server, tool, parameter_hash.
/// 4. Signature check -- canonical JSON under the kernel's pubkey.
/// 5. Replay check -- `nonce_store.reserve(nonce_id)` must return `true`.
pub fn verify_execution_nonce(
    presented: &SignedExecutionNonce,
    kernel_pubkey: &PublicKey,
    expected: &NonceBinding,
    now: i64,
    nonce_store: &dyn ExecutionNonceStore,
) -> Result<(), ExecutionNonceError> {
    if !is_supported_execution_nonce_schema(&presented.nonce.schema) {
        warn!(
            schema = %presented.nonce.schema,
            "rejecting execution nonce with unsupported schema"
        );
        return Err(ExecutionNonceError::BadSchema {
            got: presented.nonce.schema.clone(),
        });
    }

    if now >= presented.nonce.expires_at {
        warn!(
            nonce_id = %presented.nonce.nonce_id,
            now,
            expires_at = presented.nonce.expires_at,
            "rejecting stale execution nonce"
        );
        return Err(ExecutionNonceError::Expired {
            now,
            expires_at: presented.nonce.expires_at,
        });
    }

    let bound = &presented.nonce.bound_to;
    if bound.subject_id != expected.subject_id {
        return Err(ExecutionNonceError::BindingMismatch {
            field: "subject_id",
        });
    }
    if bound.capability_id != expected.capability_id {
        return Err(ExecutionNonceError::BindingMismatch {
            field: "capability_id",
        });
    }
    if bound.tool_server != expected.tool_server {
        return Err(ExecutionNonceError::BindingMismatch {
            field: "tool_server",
        });
    }
    if bound.tool_name != expected.tool_name {
        return Err(ExecutionNonceError::BindingMismatch { field: "tool_name" });
    }
    if bound.parameter_hash != expected.parameter_hash {
        return Err(ExecutionNonceError::BindingMismatch {
            field: "parameter_hash",
        });
    }

    let signed_bytes = canonical_json_bytes(&presented.nonce)
        .map_err(|e| ExecutionNonceError::Encoding(e.to_string()))?;
    if !kernel_pubkey.verify(&signed_bytes, &presented.signature) {
        warn!(
            nonce_id = %presented.nonce.nonce_id,
            "execution nonce signature verification failed"
        );
        return Err(ExecutionNonceError::InvalidSignature);
    }

    // Pass the nonce's signed expiry so durable stores retain the
    // consumed marker for the full validity window - otherwise the row
    // can be pruned while the nonce is still cryptographically valid,
    // allowing replay within the remaining window.
    match nonce_store.reserve_until(&presented.nonce.nonce_id, presented.nonce.expires_at) {
        Ok(true) => Ok(()),
        Ok(false) => {
            warn!(
                nonce_id = %presented.nonce.nonce_id,
                "rejecting replayed execution nonce"
            );
            Err(ExecutionNonceError::Replayed)
        }
        Err(e) => Err(ExecutionNonceError::Store(e.to_string())),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::thread;

    fn operation_id(hex_pair: &str) -> String {
        hex_pair.repeat(32)
    }

    fn sample_binding() -> NonceBinding {
        NonceBinding {
            subject_id: "subject-abc".to_string(),
            capability_id: "cap-123".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read_file".to_string(),
            parameter_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        }
    }

    #[test]
    fn mint_then_verify_roundtrip() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let cfg = ExecutionNonceConfig::default();
        let binding = sample_binding();
        let now = 1_000_000;

        let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
        assert_eq!(signed.nonce.schema, EXECUTION_NONCE_SCHEMA);
        assert_eq!(signed.nonce.expires_at, now + cfg.nonce_ttl_secs as i64);

        verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 1, &store).unwrap();
    }

    #[test]
    fn stale_nonce_is_rejected() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let cfg = ExecutionNonceConfig::default();
        let binding = sample_binding();

        let now = 1_000_000;
        let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
        let err = verify_execution_nonce(
            &signed,
            &kp.public_key(),
            &binding,
            now + cfg.nonce_ttl_secs as i64 + 1,
            &store,
        )
        .unwrap_err();
        assert!(matches!(err, ExecutionNonceError::Expired { .. }));
    }

    #[test]
    fn replayed_nonce_is_rejected() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let cfg = ExecutionNonceConfig::default();
        let binding = sample_binding();
        let now = 1_000_000;

        let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
        verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 1, &store).unwrap();
        let err = verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 2, &store)
            .unwrap_err();
        assert!(matches!(err, ExecutionNonceError::Replayed));
    }

    #[test]
    fn mismatched_binding_is_rejected() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let cfg = ExecutionNonceConfig::default();
        let minted_binding = sample_binding();
        let now = 1_000_000;

        let signed = mint_execution_nonce(&kp, minted_binding.clone(), &cfg, now).unwrap();
        let mut wrong = minted_binding;
        wrong.tool_name = "write_file".to_string();

        let err =
            verify_execution_nonce(&signed, &kp.public_key(), &wrong, now + 1, &store).unwrap_err();
        assert!(matches!(
            err,
            ExecutionNonceError::BindingMismatch { field: "tool_name" }
        ));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let cfg = ExecutionNonceConfig::default();
        let binding = sample_binding();
        let now = 1_000_000;

        let mut signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
        // Mutate a signed field without re-signing: signature must no longer verify.
        signed.nonce.bound_to.tool_name = "write_file".to_string();
        // Revert the binding mismatch check by also mutating the presented binding.
        let mut expected = binding;
        expected.tool_name = "write_file".to_string();

        let err = verify_execution_nonce(&signed, &kp.public_key(), &expected, now + 1, &store)
            .unwrap_err();
        assert!(matches!(err, ExecutionNonceError::InvalidSignature));
    }

    #[test]
    fn store_reserves_each_nonce_exactly_once() {
        let store = InMemoryExecutionNonceStore::default();
        assert!(store.reserve("a").unwrap());
        assert!(!store.reserve("a").unwrap());
        assert!(store.reserve("b").unwrap());
    }

    #[test]
    fn reserve_until_retains_nonce_after_local_ttl() {
        let store = InMemoryExecutionNonceStore::new(16, Duration::from_millis(1));
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_add(30);
        let expires_at = i64::try_from(expires_at).unwrap();

        assert!(store.reserve_until("long-lived", expires_at).unwrap());
        thread::sleep(Duration::from_millis(5));
        assert!(!store.reserve_until("long-lived", expires_at).unwrap());
    }

    #[test]
    fn reserve_with_retention_fails_closed_on_overflow() {
        let store = InMemoryExecutionNonceStore::default();
        let err = store
            .reserve_with_retention("overflow", Duration::MAX)
            .unwrap_err();

        assert!(matches!(
            err,
            KernelError::Internal(reason)
                if reason.contains("execution nonce retention overflow")
        ));
    }

    #[test]
    fn store_does_not_stall_between_threads() {
        let store = std::sync::Arc::new(InMemoryExecutionNonceStore::default());
        let mut handles = Vec::new();
        for i in 0..4 {
            let store = std::sync::Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let id = format!("t-{i}");
                store.reserve(&id).unwrap()
            }));
        }
        for h in handles {
            assert!(h.join().unwrap());
        }
    }

    #[test]
    fn in_memory_nonce_reservations_are_operation_owned_and_terminal() {
        let store = InMemoryExecutionNonceStore::default();
        assert!(matches!(
            store.reserve_nonce_for_operation("not-a-digest", "nonce-invalid", 10_000),
            Err(ExecutionNonceReservationError::Invalid(_))
        ));
        let reserved = store
            .reserve_nonce_for_operation(operation_id("01").as_str(), "nonce-1", 10_000)
            .unwrap();
        assert_eq!(reserved.operation_id(), operation_id("01").as_str());
        assert_eq!(reserved.nonce_id(), "nonce-1");
        assert_eq!(reserved.signed_expires_at(), 10_000);
        assert_eq!(reserved.state(), ReplayReservationState::Reserved);
        assert_eq!(
            store
                .reserve_nonce_for_operation(operation_id("01").as_str(), "nonce-1", 10_000)
                .unwrap(),
            reserved
        );
        assert!(matches!(
            store.reserve_nonce_for_operation(operation_id("01").as_str(), "nonce-1", 10_001),
            Err(ExecutionNonceReservationError::Conflict(_))
        ));
        assert!(matches!(
            store.reserve_nonce_for_operation(operation_id("02").as_str(), "nonce-1", 10_000),
            Err(ExecutionNonceReservationError::Conflict(_))
        ));

        let committed = store
            .commit_nonce_reservation(operation_id("01").as_str())
            .unwrap();
        assert_eq!(committed.state(), ReplayReservationState::Committed);
        assert_eq!(
            store
                .commit_nonce_reservation(operation_id("01").as_str())
                .unwrap(),
            committed
        );
        assert!(matches!(
            store.cancel_nonce_reservation(operation_id("01").as_str()),
            Err(ExecutionNonceReservationError::Conflict(_))
        ));

        let cancelled = store
            .reserve_nonce_for_operation(operation_id("03").as_str(), "nonce-3", 20_000)
            .and_then(|_| store.cancel_nonce_reservation(operation_id("03").as_str()))
            .unwrap();
        assert_eq!(cancelled.state(), ReplayReservationState::Cancelled);
        assert_eq!(
            store
                .cancel_nonce_reservation(operation_id("03").as_str())
                .unwrap(),
            cancelled
        );
        assert_eq!(
            store
                .get_nonce_reservation(operation_id("03").as_str())
                .unwrap(),
            Some(cancelled)
        );
        assert!(!store.reserve("nonce-3").unwrap());

        let legacy_expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_add(30);
        assert!(store
            .reserve_until("legacy-consumed", i64::try_from(legacy_expiry).unwrap())
            .unwrap());
        assert!(matches!(
            store.reserve_nonce_for_operation(
                operation_id("04").as_str(),
                "legacy-consumed",
                30_000
            ),
            Err(ExecutionNonceReservationError::Conflict(_))
        ));
    }
}
