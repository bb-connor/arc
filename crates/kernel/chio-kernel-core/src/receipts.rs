//! Portable receipt signing.
//!
//! Wraps `chio_core_types::receipt::body::ChioReceipt::sign_with_backend` so the kernel core
//! can produce signed receipts without depending on the `chio-kernel` full
//! crate's keypair-based helper. Using the `SigningBackend` trait keeps
//! the FIPS-capable signing path available on every adapter.

use alloc::string::ToString;
#[cfg(kani)]
use alloc::vec::Vec;

use chio_core_types::crypto::SigningBackend;
use chio_core_types::receipt::signing::ReceiptSigningHandle;
use chio_core_types::receipt::{body::ChioReceipt, body::ChioReceiptBody};

/// Errors raised by [`sign_receipt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptSigningError {
    /// The receipt body's `kernel_key` does not match the signing backend's
    /// public key. Signing would succeed but verification against the
    /// embedded `kernel_key` would then fail; we fail early to catch
    /// config drift.
    KernelKeyMismatch,
    /// The body's claimed `content_hash` does not match the hash the signer
    /// recomputed over the bound canonical content. WYSIWYS fail-closed gate:
    /// closes render-A / sign-B forgeries. Carries the recomputed and claimed
    /// hashes for audit.
    ContentHashMismatch {
        /// Hash recomputed by the signer over the handle's canonical content.
        recomputed: alloc::string::String,
        /// `content_hash` the caller embedded in the receipt body.
        claimed: alloc::string::String,
    },
    /// The canonical-JSON signing pipeline raised an error (bubbled up
    /// from `chio-core-types::crypto::sign_canonical_with_backend`).
    SigningFailed(alloc::string::String),
}

/// Sign a receipt body using the given [`SigningBackend`].
///
/// This mirrors the pre-existing `chio_kernel::kernel::responses::build_and_sign_receipt`
/// but accepts an abstract signing backend rather than the `Keypair`
/// concrete type. `chio-kernel` delegates to this function for the pure
/// signing step; adapters on WASM / mobile route to their platform's
/// signing backend (ed25519-dalek in WASM today, AWS LC or system keystores
/// in FIPS deployments) through the same trait.
///
/// The `body.kernel_key` must equal `backend.public_key()`; otherwise we
/// fail fast with [`ReceiptSigningError::KernelKeyMismatch`] so the caller
/// doesn't produce a receipt whose signature cannot be verified.
pub fn sign_receipt(
    body: ChioReceiptBody,
    backend: &dyn SigningBackend,
) -> Result<ChioReceipt, ReceiptSigningError> {
    let backend_key = backend.public_key();
    if body.kernel_key.algorithm() != backend_key.algorithm() || body.kernel_key != backend_key {
        #[cfg(kani)]
        core::mem::forget(body);

        return Err(ReceiptSigningError::KernelKeyMismatch);
    }

    #[cfg(kani)]
    {
        // Kani cannot practically symbolically execute the serde/RFC 8785
        // canonicalization stack. This model still exercises the successful
        // public branch: matching kernel key, backend signing, and field
        // preservation into the returned receipt.
        let signature = backend
            .sign_bytes(b"kani-receipt-signing-model")
            .map_err(|error| ReceiptSigningError::SigningFailed(error.to_string()))?;
        return Ok(ChioReceipt {
            id: body.id,
            timestamp: body.timestamp,
            capability_id: body.capability_id,
            tool_server: body.tool_server,
            tool_name: body.tool_name,
            action: body.action,
            decision: body.decision,
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: body.content_hash,
            policy_hash: body.policy_hash,
            evidence: body.evidence,
            metadata: body.metadata,
            trust_level: body.trust_level,
            tenant_id: body.tenant_id,
            bbs_projection_version: None,
            kernel_key: body.kernel_key,
            bbs_signature: None,
            algorithm: Some(backend.algorithm()),
            signature,
        });
    }

    #[cfg(not(kani))]
    ChioReceipt::sign_with_backend(body, backend)
        .map_err(|error| ReceiptSigningError::SigningFailed(error.to_string()))
}

/// WYSIWYS receipt signing at the kernel-core trust boundary.
///
/// Unlike [`sign_receipt`], which trusts the caller-supplied
/// `body.content_hash`, this entrypoint binds the signature to a specific
/// evaluated artifact via a one-time [`ReceiptSigningHandle`]. The handle
/// recomputed `content_hash` over the artifact's canonical content when it was
/// constructed; here we refuse to sign unless the body's claimed
/// `content_hash` equals that recomputed hash (fail-closed). The handle is
/// consumed by value, so one handle backs at most one signature.
///
/// This closes the render-A / sign-B forgery: a caller can no longer render
/// content `A` to a human while submitting a body claiming the hash of content
/// `B`. The kernel key check from [`sign_receipt`] still applies.
///
/// # Seam note (BAC-539 follow-up)
///
/// Producers currently build the handle from canonical content they supply
/// (see [`ReceiptSigningHandle::from_content`]). The intended end state is for
/// `evaluate()` to return the handle so the only way to obtain one is to have
/// actually run an evaluation. Threading the handle out of [`crate::evaluate`]
/// and through every adapter's receipt path is a larger follow-up; the
/// recompute + refuse gate here already closes the regression regardless.
///
/// # Errors
///
/// - [`ReceiptSigningError::ContentHashMismatch`] when the body's claimed
///   `content_hash` does not match the handle's recomputed hash.
/// - [`ReceiptSigningError::KernelKeyMismatch`] when `body.kernel_key` does not
///   match `backend.public_key()`.
/// - [`ReceiptSigningError::SigningFailed`] when canonical signing fails.
pub fn sign_receipt_with_handle(
    body: ChioReceiptBody,
    backend: &dyn SigningBackend,
    handle: ReceiptSigningHandle,
) -> Result<ChioReceipt, ReceiptSigningError> {
    // Recompute-and-refuse FIRST, before any kernel-key or signing work, so a
    // hash mismatch can never reach the signer. `handle` is consumed here,
    // enforcing one-time use per signature.
    if let Err(mismatch) = handle.ensure_body_matches(&body) {
        #[cfg(kani)]
        core::mem::forget(body);

        return Err(ReceiptSigningError::ContentHashMismatch {
            recomputed: mismatch.recomputed,
            claimed: mismatch.claimed,
        });
    }

    sign_receipt(body, backend)
}
