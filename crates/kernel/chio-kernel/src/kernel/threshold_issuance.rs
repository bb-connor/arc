//! Threshold proposal issuance and retained authority validation.

use super::*;
use chio_core::crypto::SigningAlgorithm;

impl ChioKernel {
    pub fn set_threshold_approval_requirement_resolver(
        &mut self,
        resolver: Arc<dyn crate::threshold_approval::ThresholdApprovalRequirementResolver>,
    ) {
        self.threshold_approval_requirement_resolver = Some(resolver);
    }

    pub(super) fn threshold_proposal_signing_key(&self) -> chio_core::PublicKey {
        self.signing_authority.backend.public_key()
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
        let algorithm = self.signing_authority.backend.algorithm();
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
        let mut proposal = ThresholdApprovalProposal::sign_with_backend(
            body,
            self.signing_authority.backend.as_ref(),
        )
        .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        // Ed25519's absent algorithm tag is the existing signed artifact wire
        // form. Keep it byte-identical even when boot installed an Ed25519 backend.
        if algorithm == SigningAlgorithm::Ed25519 {
            proposal.algorithm = None;
        }
        Ok(proposal)
    }
}
