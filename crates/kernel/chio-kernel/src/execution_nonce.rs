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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{Ed25519Backend, Keypair, PublicKey, Signature, SigningBackend};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tracing::{error, warn};
use uuid::Uuid;

use crate::security_admission_operation::ReplayReservationState;
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
/// All six fields are in the signed body, so any mismatch during verify
/// means either the nonce was minted for a different call or the nonce was
/// tampered with after issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceBinding {
    /// Hex-encoded subject (agent) public key, taken from `capability.subject`.
    pub subject_id: String,
    /// Request identifier for the single invocation this nonce authorizes.
    pub request_id: String,
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
#[serde(deny_unknown_fields)]
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
    /// Reserved budget hold this nonce authorizes. Set only by the
    /// pre-execution authorization-reserving path so the reconcile-by-nonce
    /// entry point can name the exact hold to settle. Part of the signed body,
    /// so it is tamper-evident like the rest of the binding. `None` on every
    /// other mint path, where it is omitted from the serialized form to keep
    /// non-reserving nonces byte-for-byte backward compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_hold_id: Option<String>,
    /// Request id of the reserving authorization that minted this nonce. Set
    /// only alongside `reserved_hold_id`. Signed and tamper-evident.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserving_request_id: Option<String>,
}

// ---------------------------------------------------------------------------
// SignedExecutionNonce
// ---------------------------------------------------------------------------

/// A kernel-signed execution nonce ready for transmission on an allow verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// The reserved budget hold this nonce authorizes, present only when the
    /// nonce was minted by the pre-execution authorization-reserving path.
    #[must_use]
    pub fn reserved_hold_id(&self) -> Option<&str> {
        self.nonce.reserved_hold_id.as_deref()
    }

    /// The request id of the reserving authorization that minted this nonce,
    /// present only alongside [`Self::reserved_hold_id`].
    #[must_use]
    pub fn reserving_request_id(&self) -> Option<&str> {
        self.nonce.reserving_request_id.as_deref()
    }
}

impl chio_core_types::receipt::authoritative_spend::PresentedNonceView for SignedExecutionNonce {
    fn nonce_id(&self) -> &str {
        &self.nonce.nonce_id
    }
    fn bound_capability_id(&self) -> &str {
        &self.nonce.bound_to.capability_id
    }
    fn bound_tool_server(&self) -> &str {
        &self.nonce.bound_to.tool_server
    }
    fn bound_tool_name(&self) -> &str {
        &self.nonce.bound_to.tool_name
    }
    fn bound_parameter_hash(&self) -> &str {
        &self.nonce.bound_to.parameter_hash
    }
    fn bound_reserved_hold_id(&self) -> Option<&str> {
        self.nonce.reserved_hold_id.as_deref()
    }
    fn verify_signed_by(&self, key: &PublicKey) -> bool {
        match canonical_json_bytes(&self.nonce) {
            Ok(bytes) => key.verify(&bytes, &self.signature),
            Err(_) => false,
        }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionNonceStoreProfile {
    EphemeralLocal,
    SingleNodeDurable,
    SharedLinearizable,
}

impl ExecutionNonceStoreProfile {
    #[must_use]
    pub fn supports_dispatch_workers(self, dispatch_worker_count: usize) -> bool {
        match self {
            Self::EphemeralLocal => false,
            Self::SingleNodeDurable => dispatch_worker_count == 1,
            Self::SharedLinearizable => dispatch_worker_count > 0,
        }
    }
}

pub trait ExecutionNonceStore: Send + Sync {
    fn authority_profile(&self) -> ExecutionNonceStoreProfile {
        ExecutionNonceStoreProfile::EphemeralLocal
    }

    /// Attempt to reserve (consume) the given nonce identifier.
    ///
    /// * `Ok(true)`  -- nonce was fresh; it is now marked consumed.
    /// * `Ok(false)` -- nonce has already been consumed (replay detected).
    /// * `Err(_)`    -- the store is unreachable or corrupted; fail-closed.
    ///
    /// Prefer [`Self::reserve_until`] when the caller knows the signed
    /// expiry of the nonce. Durable store profiles must retain a permanent
    /// tombstone for every consumed identifier. Wall-clock expiry is metadata,
    /// never authority to forget a nonce.
    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError>;

    /// Reserve a nonce while telling the store when the signed artifact stops
    /// being cryptographically valid. Durable implementations (SQLite and
    /// remote KV stores) MUST keep the consumed marker permanently so a
    /// forward wall-clock jump followed by rollback cannot resurrect it.
    ///
    /// The default implementation falls back to [`Self::reserve`] for
    /// in-memory / best-effort stores that already track retention
    /// internally. `nonce_expires_at` is wall-clock unix seconds.
    fn reserve_until(&self, nonce_id: &str, _nonce_expires_at: i64) -> Result<bool, KernelError> {
        self.reserve(nonce_id)
    }

    /// Atomically bind a nonce and its signed expiry to one operation. An exact
    /// retry returns the existing reservation; a different operation or nonce
    /// binding conflicts. Both committed and cancelled reservations are
    /// permanent replay tombstones. Cancellation compensates the owning
    /// operation but never makes the nonce reusable.
    ///
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

    /// Idempotently make an operation-owned reservation committed.
    fn commit_nonce_reservation(
        &self,
        _operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        Err(ExecutionNonceReservationError::Store(
            "operation-owned execution nonce reservations are unavailable".to_string(),
        ))
    }

    /// Idempotently cancel the operation while retaining its nonce tombstone.
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

    /// Whether this store can create and conditionally roll back an owned
    /// reservation before tool dispatch begins.
    fn supports_dispatch_reservations(&self) -> bool {
        false
    }

    /// Reserve a nonce for one dispatch attempt. Stores advertising dispatch
    /// reservation support must retain the owner and permit only that owner to
    /// roll the reservation back.
    fn reserve_for_dispatch(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        _reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.reserve_until(nonce_id, nonce_expires_at)
    }

    /// Remove an owned reservation after a failure known to precede any tool
    /// side effect.
    fn rollback_dispatch_reservation(
        &self,
        _nonce_id: &str,
        _reservation_id: &str,
    ) -> Result<bool, KernelError> {
        Err(KernelError::Internal(
            "execution nonce store does not support dispatch reservation rollback".to_string(),
        ))
    }

    /// Report whether `nonce_id` has already been consumed, WITHOUT consuming
    /// it. The two-phase reconcile path uses this to reject an already-settled
    /// nonce during verification while deferring the single-use mark until after
    /// the bound hold settles. Fail-closed: a store error propagates as `Err`.
    ///
    /// The default returns `Ok(false)` for best-effort stores that cannot peek
    /// without consuming. Those stores still enforce single-use through the
    /// atomic `reserve`/`reserve_until` mark taken after settlement, and the
    /// bound hold's atomic open-to-closed settle independently rejects a replay
    /// (a second presentation finds the hold already closed).
    fn is_consumed(&self, _nonce_id: &str) -> Result<bool, KernelError> {
        Ok(false)
    }
}

impl<T> ExecutionNonceStore for Arc<T>
where
    T: ExecutionNonceStore + ?Sized,
{
    fn authority_profile(&self) -> ExecutionNonceStoreProfile {
        (**self).authority_profile()
    }

    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError> {
        (**self).reserve(nonce_id)
    }

    fn reserve_until(&self, nonce_id: &str, nonce_expires_at: i64) -> Result<bool, KernelError> {
        (**self).reserve_until(nonce_id, nonce_expires_at)
    }

    fn reserve_nonce_for_operation(
        &self,
        operation_id: &str,
        nonce_id: &str,
        signed_expires_at: i64,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        (**self).reserve_nonce_for_operation(operation_id, nonce_id, signed_expires_at)
    }

    fn commit_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        (**self).commit_nonce_reservation(operation_id)
    }

    fn cancel_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        (**self).cancel_nonce_reservation(operation_id)
    }

    fn get_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<Option<ExecutionNonceReservation>, ExecutionNonceReservationError> {
        (**self).get_nonce_reservation(operation_id)
    }

    fn supports_dispatch_reservations(&self) -> bool {
        (**self).supports_dispatch_reservations()
    }

    fn reserve_for_dispatch(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        (**self).reserve_for_dispatch(nonce_id, nonce_expires_at, reservation_id)
    }

    fn rollback_dispatch_reservation(
        &self,
        nonce_id: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        (**self).rollback_dispatch_reservation(nonce_id, reservation_id)
    }

    fn is_consumed(&self, nonce_id: &str) -> Result<bool, KernelError> {
        (**self).is_consumed(nonce_id)
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
    consumed: LruCache<String, InMemoryExecutionNonceEntry>,
    reservations_by_operation: std::collections::HashMap<String, ExecutionNonceReservation>,
    nonce_owners: std::collections::HashMap<String, String>,
}

pub struct InMemoryExecutionNonceStore {
    inner: Mutex<InMemoryExecutionNonceState>,
    ttl: Duration,
}

struct InMemoryExecutionNonceEntry {
    retain_until: Instant,
    reservation_id: Option<String>,
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
        self.reserve_with_retention(nonce_id, self.ttl, None)
    }

    fn reserve_until(&self, nonce_id: &str, nonce_expires_at: i64) -> Result<bool, KernelError> {
        let retention = duration_until_unix_secs(nonce_expires_at)
            .map_or(self.ttl, |remaining| remaining.max(self.ttl));
        self.reserve_with_retention(nonce_id, retention, None)
    }

    fn supports_dispatch_reservations(&self) -> bool {
        true
    }

    fn reserve_for_dispatch(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        let retention = duration_until_unix_secs(nonce_expires_at)
            .map_or(self.ttl, |remaining| remaining.max(self.ttl));
        self.reserve_with_retention(nonce_id, retention, Some(reservation_id))
    }

    fn rollback_dispatch_reservation(
        &self,
        nonce_id: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        let mut cache = self.inner.lock().map_err(|_| {
            error!("execution nonce store mutex poisoned; denying fail-closed");
            KernelError::Internal("execution nonce store mutex poisoned; fail-closed".to_string())
        })?;
        let owned = cache
            .consumed
            .peek(nonce_id)
            .is_some_and(|entry| entry.reservation_id.as_deref() == Some(reservation_id));
        if owned {
            cache.consumed.pop(nonce_id);
        }
        Ok(owned)
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
        if let Some(entry) = state.consumed.peek(nonce_id) {
            if entry.retain_until > now {
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

    fn is_consumed(&self, nonce_id: &str) -> Result<bool, KernelError> {
        let state = self.inner.lock().map_err(|_| {
            error!("execution nonce store mutex poisoned; denying fail-closed");
            KernelError::Internal("execution nonce store mutex poisoned; fail-closed".to_string())
        })?;
        let now = Instant::now();
        // A retained, unexpired marker means the nonce was already consumed. A
        // marker past its retention is treated as absent, mirroring
        // reserve_with_retention, which drops a stale entry before re-reserving.
        Ok(state
            .consumed
            .peek(nonce_id)
            .is_some_and(|entry| entry.retain_until > now))
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
        reservation_id: Option<&str>,
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
        if let Some(entry) = cache.consumed.peek(&key) {
            if entry.retain_until > now {
                return Ok(false);
            }
            cache.consumed.pop(&key);
        }
        let expired: Vec<String> = cache
            .consumed
            .iter()
            .filter(|(_, entry)| entry.retain_until <= now)
            .map(|(nonce_id, _)| nonce_id.clone())
            .collect();
        for nonce_id in expired {
            cache.consumed.pop(&nonce_id);
        }
        if cache.consumed.len() >= cache.consumed.cap().get() {
            error!("execution nonce store capacity exhausted; denying fail-closed");
            return Err(KernelError::Internal(
                "execution nonce store capacity exhausted; fail-closed".to_string(),
            ));
        }
        let Some(retain_until) = now.checked_add(retention) else {
            error!("execution nonce retention overflow; denying fail-closed");
            return Err(KernelError::Internal(
                "execution nonce retention overflow; fail-closed".to_string(),
            ));
        };
        cache.consumed.put(
            key,
            InMemoryExecutionNonceEntry {
                retain_until,
                reservation_id: reservation_id.map(str::to_owned),
            },
        );
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
/// time. This keypair entry point is retained for standalone callers. The
/// governed kernel calls [`mint_execution_nonce_with_backend`] with its shared
/// authority backend.
pub fn mint_execution_nonce(
    kernel_keypair: &Keypair,
    binding: NonceBinding,
    config: &ExecutionNonceConfig,
    now: i64,
) -> Result<SignedExecutionNonce, KernelError> {
    let backend = Ed25519Backend::new(kernel_keypair.clone());
    mint_execution_nonce_with_backend(&backend, binding, config, now)
}

pub fn mint_execution_nonce_with_backend(
    backend: &dyn SigningBackend,
    binding: NonceBinding,
    config: &ExecutionNonceConfig,
    now: i64,
) -> Result<SignedExecutionNonce, KernelError> {
    mint_execution_nonce_with_backend_and_reservation(backend, binding, None, None, config, now)
}

/// Mint a nonce that additionally binds a reserved budget hold identity.
///
/// The pre-execution authorization-reserving path uses this so the minted
/// nonce carries the reserved `hold_id` (and the reserving request id) inside
/// the signed body. The reconcile-by-nonce entry point then reads the hold id
/// straight from the verified nonce to name the exact hold to settle. Because
/// both fields are covered by the kernel signature, tampering with them fails
/// verification. Callers on non-reserving paths pass `None` for both, which
/// mints a nonce byte-for-byte identical to the pre-reservation format.
pub fn mint_execution_nonce_with_reservation(
    kernel_keypair: &Keypair,
    binding: NonceBinding,
    reserved_hold_id: Option<String>,
    reserving_request_id: Option<String>,
    config: &ExecutionNonceConfig,
    now: i64,
) -> Result<SignedExecutionNonce, KernelError> {
    let backend = Ed25519Backend::new(kernel_keypair.clone());
    mint_execution_nonce_with_backend_and_reservation(
        &backend,
        binding,
        reserved_hold_id,
        reserving_request_id,
        config,
        now,
    )
}

pub fn mint_execution_nonce_with_backend_and_reservation(
    backend: &dyn SigningBackend,
    binding: NonceBinding,
    reserved_hold_id: Option<String>,
    reserving_request_id: Option<String>,
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
        reserved_hold_id,
        reserving_request_id,
    };
    let canonical_bytes = canonical_json_bytes(&nonce).map_err(|error| {
        KernelError::ReceiptSigningFailed(format!(
            "failed to canonicalize execution nonce: {error}"
        ))
    })?;
    let outcome = backend
        .sign_bytes_with_identity(&canonical_bytes)
        .map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to sign execution nonce: {e}"))
        })?;
    let expected_algorithm = outcome.algorithm;
    let signature = outcome.signature;
    if signature.algorithm() != expected_algorithm
        || !outcome.public_key.verify(&canonical_bytes, &signature)
    {
        return Err(KernelError::ReceiptSigningFailed(
            "freshly signed execution nonce does not verify under the signing backend snapshot"
                .to_string(),
        ));
    }
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
    /// Signature did not verify under the kernel's public key.
    InvalidSignature,
    /// Runtime authority trust resolution denied the signed nonce artifact.
    AuthorityTrust(String),
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
            Self::AuthorityTrust(error) => {
                write!(f, "execution nonce authority trust verification failed: {error}")
            }
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

/// Verify a nonce's schema, expiry, binding, and signature WITHOUT touching the
/// replay store.
///
/// Steps, in order:
/// 1. Schema check.
/// 2. Expiry check -- `now < nonce.expires_at`.
/// 3. Binding check -- subject, request, capability, server, tool, parameter_hash.
/// 4. Signature check -- canonical JSON under the kernel's pubkey.
///
/// Shared by the single-phase verify-and-consume path and the two-phase
/// verify-then-consume reconcile path so both apply identical cryptographic and
/// binding checks; only the replay handling differs between them.
fn verify_execution_nonce_shape(
    presented: &SignedExecutionNonce,
    kernel_pubkey: &PublicKey,
    expected: &NonceBinding,
    now: i64,
) -> Result<(), ExecutionNonceError> {
    verify_execution_nonce_stateless(presented, kernel_pubkey, expected, now)
}

/// Consume a nonce only after every stateless and authority-trust check passed.
pub(crate) fn consume_verified_execution_nonce(
    presented: &SignedExecutionNonce,
    nonce_store: &dyn ExecutionNonceStore,
) -> Result<(), ExecutionNonceError> {
    // Pass the signed expiry as audit metadata. Durable stores retain the
    // consumed identifier permanently, independent of wall-clock movement.
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

/// Return the exact canonical nonce body covered by its detached signature.
pub(crate) fn execution_nonce_signed_artifact(
    presented: &SignedExecutionNonce,
) -> Result<Vec<u8>, ExecutionNonceError> {
    canonical_json_bytes(&presented.nonce)
        .map_err(|error| ExecutionNonceError::Encoding(error.to_string()))
}

/// Verify schema, expiry, binding, and signature without replay-state mutation.
pub fn verify_execution_nonce_stateless(
    presented: &SignedExecutionNonce,
    kernel_pubkey: &PublicKey,
    expected: &NonceBinding,
    now: i64,
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
    if bound.request_id.is_empty() || bound.request_id != expected.request_id {
        return Err(ExecutionNonceError::BindingMismatch {
            field: "request_id",
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

    let signed_bytes = execution_nonce_signed_artifact(presented)?;
    if !kernel_pubkey.verify(&signed_bytes, &presented.signature) {
        warn!(
            nonce_id = %presented.nonce.nonce_id,
            "execution nonce signature verification failed"
        );
        return Err(ExecutionNonceError::InvalidSignature);
    }

    Ok(())
}

/// Verify a signed execution nonce against the expected binding and CONSUME it
/// in one step (single-phase dispatch gate).
///
/// Steps, in order:
/// 1. Schema check.
/// 2. Expiry check -- `now < nonce.expires_at`.
/// 3. Binding check -- subject, capability, server, tool, parameter_hash.
/// 4. Signature check -- canonical JSON under the kernel's pubkey.
/// 5. Replay check -- `nonce_store.reserve_until(nonce_id, ...)` must return
///    `true`, which also marks the nonce consumed.
///
/// A caller that must defer the single-use mark until an authorized action has
/// committed uses [`verify_execution_nonce_without_consume`] plus
/// [`consume_execution_nonce`] instead.
pub fn verify_execution_nonce(
    presented: &SignedExecutionNonce,
    kernel_pubkey: &PublicKey,
    expected: &NonceBinding,
    now: i64,
    nonce_store: &dyn ExecutionNonceStore,
) -> Result<(), ExecutionNonceError> {
    verify_execution_nonce_shape(presented, kernel_pubkey, expected, now)?;

    // Pass the nonce's signed expiry so durable stores retain the
    // consumed marker for the full validity window - otherwise the row
    // can be pruned while the nonce is still cryptographically valid,
    // allowing replay within the remaining window.
    consume_verified_execution_nonce(presented, nonce_store)
}

/// Verify a signed execution nonce (schema, expiry, binding, signature, AND that
/// it has not already been consumed) WITHOUT marking it consumed.
///
/// The single-use mark is deferred to [`consume_execution_nonce`], which the
/// caller invokes only after the action the nonce authorizes has irreversibly
/// committed. This lets a caller that hit a transient error after verification
/// but before commit retry the same signed nonce instead of forfeiting it. A
/// forged, tampered, expired, or already-consumed nonce is still rejected here,
/// and no store mark is taken on any path.
pub fn verify_execution_nonce_without_consume(
    presented: &SignedExecutionNonce,
    kernel_pubkey: &PublicKey,
    expected: &NonceBinding,
    now: i64,
    nonce_store: &dyn ExecutionNonceStore,
) -> Result<(), ExecutionNonceError> {
    verify_execution_nonce_shape(presented, kernel_pubkey, expected, now)?;

    // Replay peek only: reject an already-consumed nonce, but do NOT mark it.
    if nonce_store
        .is_consumed(&presented.nonce.nonce_id)
        .map_err(|e| ExecutionNonceError::Store(e.to_string()))?
    {
        warn!(
            nonce_id = %presented.nonce.nonce_id,
            "rejecting already-consumed execution nonce"
        );
        return Err(ExecutionNonceError::Replayed);
    }

    Ok(())
}

/// Mark a verified nonce consumed (single-use).
///
/// Call ONLY after the settlement the nonce authorizes has succeeded, so a
/// failure before settlement leaves the nonce replayable for a legitimate
/// retry. Pairs with [`verify_execution_nonce_without_consume`]. Returns
/// [`ExecutionNonceError::Replayed`] if a concurrent consumer already claimed
/// it, and fails closed on any store error.
pub fn consume_execution_nonce(
    nonce_store: &dyn ExecutionNonceStore,
    nonce_id: &str,
    nonce_expires_at: i64,
) -> Result<(), ExecutionNonceError> {
    // Pass the nonce's signed expiry so durable stores retain the consumed
    // marker for the full validity window.
    match nonce_store.reserve_until(nonce_id, nonce_expires_at) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ExecutionNonceError::Replayed),
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
            request_id: "request-abc".to_string(),
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
    fn stateless_verification_does_not_consume_the_nonce() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let cfg = ExecutionNonceConfig::default();
        let binding = sample_binding();
        let now = 1_000_000;
        let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();

        verify_execution_nonce_stateless(&signed, &kp.public_key(), &binding, now + 1).unwrap();
        assert!(store
            .reserve_until(signed.nonce_id(), signed.expires_at())
            .unwrap());
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
        assert_eq!(
            store.authority_profile(),
            ExecutionNonceStoreProfile::EphemeralLocal
        );
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
            .reserve_with_retention("overflow", Duration::MAX, None)
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

    #[test]
    fn execution_nonce_schema_is_frozen() {
        // A rename of any nonce field breaks this frozen-schema test, so downstream
        // consumers that pinned this schema stay in sync.
        let kp = Keypair::generate();
        let signed = mint_execution_nonce(
            &kp,
            sample_binding(),
            &ExecutionNonceConfig::default(),
            1_000_000,
        )
        .unwrap();
        let value = serde_json::to_value(&signed).unwrap();
        assert_eq!(value["nonce"]["schema"], "chio.execution_nonce.v1");
        let nonce_keys: std::collections::BTreeSet<String> = value["nonce"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            nonce_keys,
            ["bound_to", "expires_at", "issued_at", "nonce_id", "schema"]
                .into_iter()
                .map(String::from)
                .collect()
        );
        let binding_keys: std::collections::BTreeSet<String> = value["nonce"]["bound_to"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            binding_keys,
            [
                "capability_id",
                "parameter_hash",
                "subject_id",
                "tool_name",
                "tool_server"
            ]
            .into_iter()
            .map(String::from)
            .collect()
        );
        let top_keys: std::collections::BTreeSet<String> =
            value.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            top_keys,
            ["nonce", "signature"]
                .into_iter()
                .map(String::from)
                .collect()
        );
    }

    #[test]
    fn execution_nonce_rejects_unknown_fields_at_every_signed_layer() {
        let kp = Keypair::generate();
        let signed = mint_execution_nonce(
            &kp,
            sample_binding(),
            &ExecutionNonceConfig::default(),
            1_000_000,
        )
        .unwrap();
        let baseline = serde_json::to_value(&signed).unwrap();

        let mut unknown_outer = baseline.clone();
        unknown_outer
            .as_object_mut()
            .unwrap()
            .insert("unsigned_extension".to_string(), serde_json::json!(true));
        let error = serde_json::from_value::<SignedExecutionNonce>(unknown_outer).unwrap_err();
        assert!(error.to_string().contains("unknown field"));

        let mut unknown_nonce = baseline.clone();
        unknown_nonce["nonce"]
            .as_object_mut()
            .unwrap()
            .insert("unsigned_extension".to_string(), serde_json::json!(true));
        let error = serde_json::from_value::<SignedExecutionNonce>(unknown_nonce).unwrap_err();
        assert!(error.to_string().contains("unknown field"));

        let mut unknown_binding = baseline;
        unknown_binding["nonce"]["bound_to"]
            .as_object_mut()
            .unwrap()
            .insert("unsigned_extension".to_string(), serde_json::json!(true));
        let error = serde_json::from_value::<SignedExecutionNonce>(unknown_binding).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn default_nonce_omits_reservation_fields() {
        // A nonce minted on any non-reserving path carries no reserved hold and
        // serializes without the reservation keys, so it stays byte-for-byte
        // backward compatible with the pre-reservation nonce format.
        let kp = Keypair::generate();
        let signed = mint_execution_nonce(
            &kp,
            sample_binding(),
            &ExecutionNonceConfig::default(),
            1_000_000,
        )
        .unwrap();
        assert_eq!(signed.reserved_hold_id(), None);
        assert_eq!(signed.reserving_request_id(), None);
        let value = serde_json::to_value(&signed).unwrap();
        assert!(value["nonce"].get("reserved_hold_id").is_none());
        assert!(value["nonce"].get("reserving_request_id").is_none());
    }

    #[test]
    fn reserved_nonce_binds_hold_id_in_signed_body() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let cfg = ExecutionNonceConfig::default();
        let binding = sample_binding();
        let now = 1_000_000;
        let signed = mint_execution_nonce_with_reservation(
            &kp,
            binding.clone(),
            Some("budget-hold:req-1:cap-123:0".to_string()),
            Some("req-1".to_string()),
            &cfg,
            now,
        )
        .unwrap();
        assert_eq!(
            signed.reserved_hold_id(),
            Some("budget-hold:req-1:cap-123:0")
        );
        assert_eq!(signed.reserving_request_id(), Some("req-1"));
        // The presented-nonce view surfaces the same signed reserved hold id so
        // the authoritative-spend predicate can cross-bind it to the receipt.
        use chio_core_types::receipt::authoritative_spend::PresentedNonceView;
        assert_eq!(
            PresentedNonceView::bound_reserved_hold_id(&signed),
            Some("budget-hold:req-1:cap-123:0")
        );
        // The reservation fields ride inside the signed body and verify cleanly.
        verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 1, &store).unwrap();
    }

    #[test]
    fn tampered_reserved_hold_id_breaks_signature() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let cfg = ExecutionNonceConfig::default();
        let binding = sample_binding();
        let now = 1_000_000;
        let mut signed = mint_execution_nonce_with_reservation(
            &kp,
            binding.clone(),
            Some("budget-hold:req-1:cap-123:0".to_string()),
            Some("req-1".to_string()),
            &cfg,
            now,
        )
        .unwrap();
        // Repoint the signed hold id at an attacker-chosen hold without
        // re-signing: the signature no longer covers the mutated body.
        signed.nonce.reserved_hold_id = Some("budget-hold:attacker:cap-123:0".to_string());
        let err = verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 1, &store)
            .unwrap_err();
        assert!(matches!(err, ExecutionNonceError::InvalidSignature));
    }

    #[test]
    fn signed_execution_nonce_implements_presented_nonce_view() {
        use chio_core_types::receipt::authoritative_spend::PresentedNonceView;
        let kp = Keypair::generate();
        let signed = mint_execution_nonce(
            &kp,
            sample_binding(),
            &ExecutionNonceConfig::default(),
            1_000_000,
        )
        .unwrap();
        assert_eq!(signed.bound_capability_id(), "cap-123");
        assert_eq!(signed.bound_tool_server(), "fs");
        assert_eq!(signed.bound_tool_name(), "read_file");
        // A non-reserving mint names no reserved hold through the view.
        assert_eq!(signed.bound_reserved_hold_id(), None);
        assert!(signed.verify_signed_by(&kp.public_key()));
        assert!(!signed.verify_signed_by(&Keypair::generate().public_key()));
    }
}
