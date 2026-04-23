//! Portable receipt signing.
//!
//! Wraps `chio_core_types::ChioReceipt::sign_with_backend` so the kernel core
//! can produce signed receipts without depending on the `chio-kernel` full
//! crate's keypair-based helper. Using the `SigningBackend` trait keeps
//! the FIPS-capable signing path available on every adapter.

use alloc::string::ToString;

use chio_core_types::crypto::SigningBackend;
use chio_core_types::receipt::{ChioReceipt, ChioReceiptBody};

/// Errors raised by [`sign_receipt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptSigningError {
    /// The receipt body's `kernel_key` does not match the signing backend's
    /// public key. Signing would succeed but verification against the
    /// embedded `kernel_key` would then fail; we fail early to catch
    /// config drift.
    KernelKeyMismatch,
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
    #[cfg(kani)]
    {
        if body.kernel_key != backend.public_key() {
            core::mem::forget(body);
            return Err(ReceiptSigningError::KernelKeyMismatch);
        }
        // Kani public harnesses cover mismatch fail-closed behavior here.
        // Successful canonical signing is covered by runtime boundary tests.
        core::mem::forget(body);
        kani::assume(false);
        unreachable!("successful receipt signing is outside this Kani harness");
    }

    #[cfg(not(kani))]
    {
        if body.kernel_key != backend.public_key() {
            return Err(ReceiptSigningError::KernelKeyMismatch);
        }

        ChioReceipt::sign_with_backend(body, backend)
            .map_err(|error| ReceiptSigningError::SigningFailed(error.to_string()))
    }
}
