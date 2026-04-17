//! Portable receipt signing.
//!
//! Wraps `arc_core_types::ArcReceipt::sign_with_backend` so the kernel core
//! can produce signed receipts without depending on the `arc-kernel` full
//! crate's keypair-based helper. Using the `SigningBackend` trait keeps
//! the FIPS-capable signing path available on every adapter.

use alloc::string::ToString;

use arc_core_types::crypto::SigningBackend;
use arc_core_types::receipt::{ArcReceipt, ArcReceiptBody};

/// Errors raised by [`sign_receipt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptSigningError {
    /// The receipt body's `kernel_key` does not match the signing backend's
    /// public key. Signing would succeed but verification against the
    /// embedded `kernel_key` would then fail; we fail early to catch
    /// config drift.
    KernelKeyMismatch,
    /// The canonical-JSON signing pipeline raised an error (bubbled up
    /// from `arc-core-types::crypto::sign_canonical_with_backend`).
    SigningFailed(alloc::string::String),
}

/// Sign a receipt body using the given [`SigningBackend`].
///
/// This mirrors the pre-existing `arc_kernel::kernel::responses::build_and_sign_receipt`
/// but accepts an abstract signing backend rather than the `Keypair`
/// concrete type. `arc-kernel` delegates to this function for the pure
/// signing step; adapters on WASM / mobile route to their platform's
/// signing backend (ed25519-dalek in WASM today, AWS LC or system keystores
/// in FIPS deployments) through the same trait.
///
/// The `body.kernel_key` must equal `backend.public_key()`; otherwise we
/// fail fast with [`ReceiptSigningError::KernelKeyMismatch`] so the caller
/// doesn't produce a receipt whose signature cannot be verified.
pub fn sign_receipt(
    body: ArcReceiptBody,
    backend: &dyn SigningBackend,
) -> Result<ArcReceipt, ReceiptSigningError> {
    if body.kernel_key != backend.public_key() {
        return Err(ReceiptSigningError::KernelKeyMismatch);
    }

    ArcReceipt::sign_with_backend(body, backend)
        .map_err(|error| ReceiptSigningError::SigningFailed(error.to_string()))
}
