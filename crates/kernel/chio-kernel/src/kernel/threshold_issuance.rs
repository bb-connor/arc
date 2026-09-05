//! Boot-gated threshold proposal signing authority.

use super::*;
use chio_core::crypto::{SigningAlgorithm, SigningBackend, SigningOutcome};

#[cfg(test)]
#[path = "threshold_issuance/forwarding_tests.rs"]
mod forwarding_tests;

impl ChioKernel {
    /// Install the threshold proposal signing backend the kernel uses under
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
    /// neither the existing backend nor the cryptographic floor. This does not
    /// install the backend in the inline receipt-signing path.
    ///
    /// Receipt body construction continues to flow through the existing
    /// inline path (`build_and_sign_receipt`); callers that opt in to
    /// hybrid signing pass the returned backend through
    /// [`crate::sign_receipt_body_with_backend`] (along with the canonical
    /// content preimage the body's `content_hash` was derived from) before
    /// persistence, so the hybrid path recomputes `content_hash` inside the
    /// trust boundary and is WYSIWYS fail-closed just like the inline
    /// classical path.
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
        self.threshold_approval_signing_backend = Some(Arc::clone(&backend));
        self.capability_crypto_floor = hybrid.crypto_floor;
        Ok(Box::new(SharedSigningBackend(backend)))
    }

    pub fn set_threshold_approval_requirement_resolver(
        &mut self,
        resolver: Arc<dyn crate::threshold_approval::ThresholdApprovalRequirementResolver>,
    ) {
        self.threshold_approval_requirement_resolver = Some(resolver);
    }

    pub(super) fn threshold_proposal_signing_key(&self) -> chio_core::PublicKey {
        self.threshold_approval_signing_backend
            .as_ref()
            .map_or_else(
                || self.config.keypair.public_key(),
                |backend| backend.public_key(),
            )
    }

    /// Reject incompatible retained authority before resuming acquisition or
    /// cleanup. A quiescent approval-required operation retains its hold and
    /// original proposal; this read does not claim those resources were released.
    pub(super) fn revalidate_pending_threshold_proposal(
        &self,
        request: &ToolCallRequest,
        operation: &crate::admission_operation::AdmissionOperationV1,
        now: u64,
    ) -> Result<(), KernelError> {
        let proposal = operation.threshold_proposal().ok_or_else(|| {
            KernelError::DurableAdmission("approval-required operation omitted its proposal".into())
        })?;
        if proposal.body.proposal_id != operation.binding().operation_id().as_str() {
            return Err(KernelError::DurableAdmission(
                "retained threshold proposal changed its admission operation".into(),
            ));
        }
        let requirement = self.threshold_approval_requirement(request, now)?;
        self.validate_cumulative_threshold_proposal(request, proposal, &requirement, now)
    }

    pub(super) fn ensure_threshold_proposal_signer_ready(
        &self,
    ) -> Result<SigningAlgorithm, KernelError> {
        let algorithm = self
            .threshold_approval_signing_backend
            .as_ref()
            .map_or(SigningAlgorithm::Ed25519, |backend| backend.algorithm());
        if !self
            .capability_crypto_floor
            .allowed_signing_algorithms()
            .contains(&algorithm)
        {
            return Err(KernelError::GovernedTransactionDenied(
                "threshold proposal signing backend does not satisfy the kernel crypto floor"
                    .into(),
            ));
        }
        Ok(algorithm)
    }

    pub(super) fn sign_threshold_proposal(
        &self,
        body: chio_core::capability::governance::ThresholdApprovalProposalBody,
    ) -> Result<chio_core::capability::governance::ThresholdApprovalProposal, KernelError> {
        use chio_core::capability::governance::ThresholdApprovalProposal;

        let algorithm = self.ensure_threshold_proposal_signer_ready()?;
        let mut proposal = match &self.threshold_approval_signing_backend {
            Some(backend) => ThresholdApprovalProposal::sign_with_backend(body, backend.as_ref()),
            None => ThresholdApprovalProposal::sign(body, &self.config.keypair),
        }
        .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        // Ed25519's absent algorithm tag is the existing signed artifact wire
        // form. Keep it byte-identical even when boot installed an Ed25519 backend.
        if algorithm == SigningAlgorithm::Ed25519 {
            proposal.algorithm = None;
        }
        Ok(proposal)
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
