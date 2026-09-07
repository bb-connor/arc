//! Shared boot-selected authority for proposals and ordinary receipts.

use super::*;
use chio_core::crypto::{SigningAlgorithm, SigningBackend, SigningOutcome};

#[cfg(test)]
#[path = "signing_authority/forwarding_tests.rs"]
mod forwarding_tests;

/// Immutable backend and the boot policy under which it was admitted.
pub(super) struct KernelSigningAuthority {
    pub(super) backend: Arc<dyn SigningBackend>,
    pub(super) floor: KernelCryptoFloor,
}

impl KernelSigningAuthority {
    pub(super) fn classical(keypair: &Keypair) -> Self {
        Self {
            backend: Arc::new(chio_core::crypto::Ed25519Backend::new(keypair.clone())),
            floor: KernelCryptoFloor::AllowClassical,
        }
    }
}

impl ChioKernel {
    /// Install the proposal and ordinary receipt signing backend under
    /// `hybrid`'s configured floor and PQ key material after the kernel
    /// self-quote gate has run.
    ///
    /// Threads the kernel's classical Ed25519 keypair into a
    /// [`chio_core::crypto::Ed25519Backend`] under
    /// [`KernelCryptoFloor::AllowClassical`], or composes it with an
    /// [`chio_core::crypto::MlDsa65Backend`] derived from `hybrid.pq_signing_seed`
    /// into a [`chio_core::crypto::HybridBackend`] under
    /// [`KernelCryptoFloor::AllowHybrid`] or [`KernelCryptoFloor::PqRequired`],
    /// but only after [`crate::boot::load_kernel_signing_backend_after_self_quote`]
    /// accepts `self_quote_bytes`.
    ///
    /// The installed authority and returned handle share one immutable backend.
    /// Configure this before serving requests. A failed configuration changes
    /// neither the existing backend nor the cryptographic floor. Inline receipt
    /// construction, the signing queue and its bounded-memory fallback use the
    /// same backend and content-preimage verification. Reconfiguration preserves
    /// queue limits and shutdown state.
    ///
    /// This configures proposal and ordinary receipt signing, not the separate
    /// capability, child-receipt, session-anchor or checkpoint authorities. It
    /// does not establish witnessed key rotation or qualify an all-artifact PQ
    /// runtime. The boxed handle is retained for source compatibility.
    ///
    /// # Errors
    ///
    /// Returns [`crate::boot::KernelBootError::SelfQuoteRejected`] when the
    /// self-quote verifier rejects a non-classical floor, or
    /// [`crate::boot::KernelBootError::SigningBackend`] when the configured
    /// floor needs a PQ key but `hybrid.pq_signing_seed` is `None`. Mirrors
    /// the policy-level check in `chio_policy::CryptoFloor::validate_with_pq_key`
    /// so the boot path catches the misconfiguration even when the policy crate
    /// is bypassed.
    pub fn with_hybrid_signing_backend(
        &mut self,
        hybrid: &HybridSigningConfig,
        self_quote_bytes: &[u8],
        verifier: &dyn crate::boot::KernelSelfQuoteVerifier,
    ) -> Result<Box<dyn chio_core::crypto::SigningBackend>, crate::boot::KernelBootError> {
        let backend = crate::boot::load_kernel_signing_backend_after_self_quote(
            hybrid.crypto_floor,
            self.config.keypair.clone(),
            hybrid.pq_signing_seed.as_ref(),
            self_quote_bytes,
            verifier,
        )?;
        let backend: Arc<dyn SigningBackend> = Arc::from(backend);
        let signing_task = self
            .signing_task
            .reconfigured_with_backend(Arc::clone(&backend));
        self.signing_authority = KernelSigningAuthority {
            backend: Arc::clone(&backend),
            floor: hybrid.crypto_floor,
        };
        self.signing_task = Arc::new(signing_task);
        self.capability_crypto_floor = hybrid.crypto_floor;
        Ok(Box::new(SharedSigningBackend(backend)))
    }

    /// Current ordinary receipt signer. This is distinct from the classical
    /// capability authority returned by [`Self::public_key`].
    pub fn receipt_signing_public_key(&self) -> chio_core::PublicKey {
        self.signing_authority.backend.public_key()
    }

    pub(super) fn receipt_signing_crypto_floor(
        &self,
    ) -> chio_core::receipt::crypto_floor::ReceiptCryptoFloor {
        receipt_crypto_floor(self.signing_authority.floor)
    }
}

/// A compatible owned return handle without duplicating the gated key material.
/// Forward atomic identity methods too so a future leased backend keeps custody
/// of its selector throughout signing.
struct SharedSigningBackend(Arc<dyn SigningBackend>);

impl SigningBackend for SharedSigningBackend {
    fn algorithm(&self) -> SigningAlgorithm {
        self.0.algorithm()
    }

    fn public_key(&self) -> chio_core::PublicKey {
        self.0.public_key()
    }

    fn sign_bytes(&self, message: &[u8]) -> Result<chio_core::Signature, chio_core::Error> {
        self.0.sign_bytes(message)
    }

    fn sign_bytes_with_identity(&self, message: &[u8]) -> Result<SigningOutcome, chio_core::Error> {
        self.0.sign_bytes_with_identity(message)
    }

    fn sign_bytes_for_identity(
        &self,
        key: &chio_core::PublicKey,
        message: &[u8],
    ) -> Result<SigningOutcome, chio_core::Error> {
        self.0.sign_bytes_for_identity(key, message)
    }

    fn sign_canonical_bytes(
        &self,
        canonical: &chio_core::CanonicalBytes<chio_core::CanonicalJsonWitness>,
    ) -> Result<chio_core::Signature, chio_core::Error> {
        self.0.sign_canonical_bytes(canonical)
    }
}
