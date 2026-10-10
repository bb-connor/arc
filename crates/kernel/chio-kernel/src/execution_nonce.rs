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
//!   request_id, parameter_hash)` tuple. Substituting a nonce between unrelated tool
//!   calls therefore fails the binding check.
//! * The kernel signs the full body (nonce id + binding + expires_at)
//!   with its receipt-signing key, so downstream tool servers can
//!   cryptographically verify authenticity without a round trip.
//! * Replay is prevented by an `ExecutionNonceStore`: the first
//!   `reserve_until(nonce_id, signed_expiry)` returns true and consumes the nonce; any
//!   subsequent reservation returns false and the verify path rejects.
//!
//! # Deployment policy
//!
//! Install `ExecutionNonceConfig` to mint and validate execution nonces.
//! Set `require_nonce` when every execution-bound call must present one.
//! Every installed replay store enforces signed expiry and owned rollback.

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{Keypair, PublicKey};
use tracing::warn;
use uuid::Uuid;

use crate::KernelError;

pub use chio_core_types::message::{ExecutionNonce, NonceBinding, SignedExecutionNonce};

/// Schema identifier for Chio execution nonces.
pub const EXECUTION_NONCE_SCHEMA: &str = "chio.execution_nonce.v1";

/// Default TTL for a freshly minted execution nonce.
pub const DEFAULT_EXECUTION_NONCE_TTL_SECS: u64 = 30;

/// Default capacity for the in-memory replay store.
pub const DEFAULT_EXECUTION_NONCE_STORE_CAPACITY: usize = 16_384;

/// Supported by the legacy replay-store verifier, not every admission profile.
#[must_use]
pub fn is_supported_execution_nonce_schema(schema: &str) -> bool {
    schema == EXECUTION_NONCE_SCHEMA
}

// ---------------------------------------------------------------------------
// ExecutionNonceConfig
// ---------------------------------------------------------------------------

/// Configuration for execution nonce issuance and verification.
#[derive(Debug, Clone)]
pub struct ExecutionNonceConfig {
    /// How many seconds a nonce is valid after issuance. Default: 30.
    pub nonce_ttl_secs: u64,
    /// Maximum retained replay markers. Default: 16_384; zero refuses reservations.
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

/// Single-use replay custody. Every implementation retains the signed validity
/// window and supports exact-owner rollback before dispatch effects begin.
/// No method may infer expiry or report an unimplemented lookup as unconsumed.
pub trait ExecutionNonceStore: Send + Sync {
    fn reserve_until(&self, nonce_id: &str, nonce_expires_at: i64) -> Result<bool, KernelError>;
    fn reserve_for_dispatch(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        reservation_id: &str,
    ) -> Result<bool, KernelError>;
    fn rollback_dispatch_reservation(
        &self,
        nonce_id: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError>;
    fn is_consumed(&self, nonce_id: &str) -> Result<bool, KernelError>;
}

mod store;
pub use store::InMemoryExecutionNonceStore;

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
    mint_execution_nonce_with_reservation(kernel_keypair, binding, None, None, config, now)
}

pub fn mint_execution_nonce_with_reservation(
    kernel_keypair: &Keypair,
    binding: NonceBinding,
    reserved_hold_id: Option<String>,
    reserving_request_id: Option<String>,
    config: &ExecutionNonceConfig,
    now: i64,
) -> Result<SignedExecutionNonce, KernelError> {
    let ttl = i64::try_from(config.nonce_ttl_secs)
        .ok()
        .filter(|ttl| *ttl > 0)
        .ok_or_else(|| {
            KernelError::InvalidConstraint(
                "execution nonce TTL is outside the positive clock domain".into(),
            )
        })?;
    let expires_at = now.checked_add(ttl).filter(|_| now >= 0).ok_or_else(|| {
        KernelError::InvalidConstraint("execution nonce expiry exceeds the clock domain".into())
    })?;
    let nonce = ExecutionNonce {
        schema: EXECUTION_NONCE_SCHEMA.to_string(),
        nonce_id: Uuid::now_v7().as_hyphenated().to_string(),
        issued_at: now,
        expires_at,
        bound_to: binding,
        reserved_hold_id,
        reserving_request_id,
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
#[derive(Debug)]
pub enum ExecutionNonceError {
    /// Schema did not equal `EXECUTION_NONCE_SCHEMA`.
    BadSchema { got: String },
    /// Signed epoch window is empty, reversed or negative.
    InvalidWindow,
    /// Signed nonce has not reached its issuance epoch.
    NotYetValid,
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
    Store(Box<KernelError>),
    /// Exact trusted-time failure from replay custody.
    Clock(chio_security_types::clock::ClockError),
}

impl std::fmt::Display for ExecutionNonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSchema { got } => write!(
                f,
                "execution nonce has unsupported schema: expected {EXECUTION_NONCE_SCHEMA}, got {got}"
            ),
            Self::InvalidWindow => write!(f, "execution nonce validity window is invalid"),
            Self::NotYetValid => write!(f, "execution nonce is not yet valid"),
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
            Self::Clock(e) => write!(f, "execution nonce time rejected: {e}"),
        }
    }
}

impl std::error::Error for ExecutionNonceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Clock(error) => Some(error),
            Self::Store(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}
impl ExecutionNonceError {
    /// Stable, input-independent rejection reason for receipts and operator logs.
    pub fn code(&self) -> std::borrow::Cow<'static, str> {
        let code = match self {
            Self::BadSchema { .. } => "urn:chio:error:kernel:execution-nonce-schema",
            Self::InvalidWindow => "urn:chio:error:kernel:execution-nonce-window",
            Self::NotYetValid => "urn:chio:error:kernel:execution-nonce-not-yet-valid",
            Self::Expired { .. } => "urn:chio:error:kernel:execution-nonce-expired",
            Self::BindingMismatch { .. } => "urn:chio:error:kernel:execution-nonce-binding",
            Self::InvalidSignature => "urn:chio:error:kernel:execution-nonce-signature",
            Self::Replayed => "urn:chio:error:kernel:execution-nonce-replayed",
            Self::Encoding(_) => "urn:chio:error:kernel:execution-nonce-encoding",
            Self::Store(error) => return error.report().code.into(),
            Self::Clock(error) => error.code(),
        };
        code.into()
    }
    pub(crate) fn from_store(error: KernelError) -> Self {
        match error {
            KernelError::Clock(error) => Self::Clock(error),
            other => Self::Store(Box::new(other)),
        }
    }
}

impl From<ExecutionNonceError> for KernelError {
    fn from(err: ExecutionNonceError) -> Self {
        match err {
            ExecutionNonceError::Clock(error) => Self::Clock(error),
            ExecutionNonceError::Store(error) => *error,
            other => Self::ExecutionNonce(other),
        }
    }
}

/// Verify a signed execution nonce against the expected binding.
///
/// Steps, in order:
/// 1. Schema check.
/// 2. Expiry check -- `now < nonce.expires_at`.
/// 3. Binding check -- subject, capability, server, tool, parameter_hash.
/// 4. Signature check -- canonical JSON under the kernel's pubkey.
/// 5. Replay check -- `nonce_store.reserve_until(nonce_id, signed_expiry)` must return `true`.
pub fn verify_execution_nonce(
    presented: &SignedExecutionNonce,
    kernel_pubkey: &PublicKey,
    expected: &NonceBinding,
    now: i64,
    nonce_store: &dyn ExecutionNonceStore,
) -> Result<(), ExecutionNonceError> {
    let validated = validate_execution_nonce(presented, kernel_pubkey, expected, now)?;
    reserve_execution_nonce(&validated, nonce_store, now)
}

pub fn verify_execution_nonce_without_consume(
    presented: &SignedExecutionNonce,
    kernel_pubkey: &PublicKey,
    expected: &NonceBinding,
    now: i64,
    nonce_store: &dyn ExecutionNonceStore,
) -> Result<(), ExecutionNonceError> {
    validate_execution_nonce(presented, kernel_pubkey, expected, now)?;
    if nonce_store
        .is_consumed(&presented.nonce.nonce_id)
        .map_err(ExecutionNonceError::from_store)?
    {
        return Err(ExecutionNonceError::Replayed);
    }
    Ok(())
}

pub fn consume_execution_nonce(
    nonce_store: &dyn ExecutionNonceStore,
    nonce_id: &str,
    nonce_expires_at: i64,
) -> Result<(), ExecutionNonceError> {
    match nonce_store.reserve_until(nonce_id, nonce_expires_at) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ExecutionNonceError::Replayed),
        Err(error) => Err(ExecutionNonceError::from_store(error)),
    }
}

/// A nonce checked against a trusted signing key and an exact request binding.
/// This borrows the immutable signed artifact; it is neither a reservation nor
/// an admission-operation authorization. Only the validator can construct it.
pub(crate) struct ValidatedExecutionNonce<'a> {
    presented: &'a SignedExecutionNonce,
}

impl ValidatedExecutionNonce<'_> {
    pub(crate) fn signed(&self) -> &SignedExecutionNonce {
        self.presented
    }
}

impl std::fmt::Debug for ValidatedExecutionNonce<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedExecutionNonce")
            .finish_non_exhaustive()
    }
}

/// Validate a signed execution nonce without consuming it in the replay store.
pub(crate) fn validate_execution_nonce<'a>(
    presented: &'a SignedExecutionNonce,
    kernel_pubkey: &PublicKey,
    expected: &NonceBinding,
    now: i64,
) -> Result<ValidatedExecutionNonce<'a>, ExecutionNonceError> {
    if !is_supported_execution_nonce_schema(&presented.nonce.schema) {
        warn!(
            schema = %presented.nonce.schema,
            "rejecting execution nonce with unsupported schema"
        );
        return Err(ExecutionNonceError::BadSchema {
            got: presented.nonce.schema.clone(),
        });
    }

    validate_execution_nonce_binding_and_expiry(presented, expected, now)?;
    let signed_bytes = canonical_json_bytes(&presented.nonce)
        .map_err(|e| ExecutionNonceError::Encoding(e.to_string()))?;
    if !kernel_pubkey.verify(&signed_bytes, &presented.signature) {
        warn!(
            nonce_id = %presented.nonce.nonce_id,
            "execution nonce signature verification failed"
        );
        return Err(ExecutionNonceError::InvalidSignature);
    }

    Ok(ValidatedExecutionNonce { presented })
}

/// Shared claim checks only. Each profile must separately verify its schema and
/// signature before constructing checked material or touching a replay store.
pub(crate) fn validate_execution_nonce_binding_and_expiry(
    presented: &SignedExecutionNonce,
    expected: &NonceBinding,
    now: i64,
) -> Result<(), ExecutionNonceError> {
    if now < 0 {
        return Err(ExecutionNonceError::Clock(
            chio_security_types::clock::ClockError::BeforeEpoch,
        ));
    }
    if presented.nonce.issued_at < 0 || presented.nonce.expires_at <= presented.nonce.issued_at {
        return Err(ExecutionNonceError::InvalidWindow);
    }
    if now < presented.nonce.issued_at {
        return Err(ExecutionNonceError::NotYetValid);
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

    Ok(())
}

/// Consume a previously validated execution nonce in the replay store.
pub(crate) fn reserve_execution_nonce(
    validated: &ValidatedExecutionNonce<'_>,
    nonce_store: &dyn ExecutionNonceStore,
    now: i64,
) -> Result<(), ExecutionNonceError> {
    let presented = validated.signed();
    if now >= presented.nonce.expires_at {
        return Err(ExecutionNonceError::Expired {
            now,
            expires_at: presented.nonce.expires_at,
        });
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
        Err(e) => Err(ExecutionNonceError::from_store(e)),
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
mod tests {
    use super::*;

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
    fn signed_window_boundaries_are_exact_and_do_not_consume_on_refusal() {
        use chio_security_types::clock::{ClockError, FixedClock};
        let kp = Keypair::from_seed(&[34; 32]);
        let binding = sample_binding();
        let mut signed =
            mint_execution_nonce(&kp, binding.clone(), &ExecutionNonceConfig::default(), 100)
                .unwrap();
        let store =
            InMemoryExecutionNonceStore::with_clock(4, std::sync::Arc::new(FixedClock::new(100)));
        assert!(matches!(
            verify_execution_nonce(&signed, &kp.public_key(), &binding, -1, &store),
            Err(ExecutionNonceError::Clock(ClockError::BeforeEpoch))
        ));
        assert!(matches!(
            verify_execution_nonce(&signed, &kp.public_key(), &binding, 99, &store),
            Err(ExecutionNonceError::NotYetValid)
        ));
        assert!(matches!(
            verify_execution_nonce(&signed, &kp.public_key(), &binding, 130, &store),
            Err(ExecutionNonceError::Expired {
                now: 130,
                expires_at: 130
            })
        ));
        assert!(!store.is_consumed(signed.nonce_id()).unwrap());
        verify_execution_nonce(&signed, &kp.public_key(), &binding, 100, &store).unwrap();

        for (issued_at, expires_at) in [(-1, 130), (100, 100), (101, 100)] {
            signed.nonce.issued_at = issued_at;
            signed.nonce.expires_at = expires_at;
            signed.signature = kp.sign_canonical(&signed.nonce).unwrap().0;
            assert!(matches!(
                validate_execution_nonce(&signed, &kp.public_key(), &binding, 100),
                Err(ExecutionNonceError::InvalidWindow)
            ));
        }
    }

    #[test]
    fn replay_store_failure_keeps_its_source_and_rejection_code() {
        use std::error::Error;
        let error = ExecutionNonceError::from_store(KernelError::ExecutionNonceCapacity);
        assert_eq!(
            error.code(),
            KernelError::ExecutionNonceCapacity.report().code
        );
        assert!(matches!(
            error.source().unwrap().downcast_ref::<KernelError>(),
            Some(KernelError::ExecutionNonceCapacity)
        ));
        assert!(matches!(
            KernelError::from(error),
            KernelError::ExecutionNonceCapacity
        ));
    }

    #[test]
    fn mint_then_verify_roundtrip() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::with_clock(
            16,
            std::sync::Arc::new(chio_security_types::clock::FixedClock::new(1_000_000)),
        );
        let cfg = ExecutionNonceConfig::default();
        let binding = sample_binding();
        let now = 1_000_000;

        let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
        assert_eq!(signed.nonce.schema, EXECUTION_NONCE_SCHEMA);
        assert_eq!(signed.nonce.expires_at, now + cfg.nonce_ttl_secs as i64);

        verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 1, &store).unwrap();
    }

    #[test]
    fn nonce_mint_refuses_empty_negative_and_overflowing_lifetimes() {
        let key = Keypair::from_seed(&[33; 32]);
        for (now, ttl) in [(1, 0), (-1, 1), (1, u64::MAX), (i64::MAX, 1)] {
            let config = ExecutionNonceConfig {
                nonce_ttl_secs: ttl,
                ..ExecutionNonceConfig::default()
            };
            assert!(
                matches!(mint_execution_nonce(&key, sample_binding(), &config, now),
                Err(KernelError::InvalidConstraint(reason)) if reason.starts_with("execution nonce"))
            );
        }
        let config = ExecutionNonceConfig {
            nonce_ttl_secs: 1,
            ..ExecutionNonceConfig::default()
        };
        let signed = mint_execution_nonce(&key, sample_binding(), &config, i64::MAX - 1)
            .expect("exact endpoint");
        assert_eq!(signed.nonce.expires_at, i64::MAX);
    }

    #[test]
    fn stale_nonce_is_rejected() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::with_clock(
            16,
            std::sync::Arc::new(chio_security_types::clock::FixedClock::new(1_000_000)),
        );
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
    fn nonce_expiry_is_rechecked_when_reserved() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::with_clock(
            16,
            std::sync::Arc::new(chio_security_types::clock::FixedClock::new(1_000_000)),
        );
        let cfg = ExecutionNonceConfig::default();
        let binding = sample_binding();
        let now = 1_000_000;
        let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
        let validated =
            validate_execution_nonce(&signed, &kp.public_key(), &binding, now + 1).unwrap();

        let error =
            reserve_execution_nonce(&validated, &store, signed.nonce.expires_at).unwrap_err();

        assert!(matches!(error, ExecutionNonceError::Expired { .. }));
        assert!(!store.is_consumed(signed.nonce_id()).unwrap());
    }

    #[test]
    fn replayed_nonce_is_rejected() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::with_clock(
            16,
            std::sync::Arc::new(chio_security_types::clock::FixedClock::new(1_000_000)),
        );
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
    fn nonce_without_request_binding_is_rejected() {
        let kp = Keypair::generate();
        let cfg = ExecutionNonceConfig::default();
        let binding = sample_binding();
        let now = 1_000_000;
        let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
        let mut encoded = serde_json::to_value(signed).unwrap();
        encoded["nonce"]["bound_to"]
            .as_object_mut()
            .unwrap()
            .remove("request_id");
        let decoded: SignedExecutionNonce = serde_json::from_value(encoded).unwrap();

        assert!(decoded.nonce.bound_to.request_id.is_empty());
        let error =
            validate_execution_nonce(&decoded, &kp.public_key(), &binding, now + 1).unwrap_err();

        assert!(matches!(
            error,
            ExecutionNonceError::BindingMismatch {
                field: "request_id"
            }
        ));
    }

    #[test]
    fn mismatched_binding_is_rejected() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::with_clock(
            16,
            std::sync::Arc::new(chio_security_types::clock::FixedClock::new(1_000_000)),
        );
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
        let store = InMemoryExecutionNonceStore::with_clock(
            16,
            std::sync::Arc::new(chio_security_types::clock::FixedClock::new(1_000_000)),
        );
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
}
