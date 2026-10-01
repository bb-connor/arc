//! Bind a fresh live plan to its attested kernel admission envelope.

use super::*;

impl AttestedFindingAdmissionArtifacts {
    pub(super) fn into_admission_request(
        self,
        response_plan: ResponsePlan,
    ) -> Result<ActiveResponseAdmissionRequest, chio_kernel::KernelError> {
        match self.payload {
            AttestedFindingAdmissionArtifactPayload::Kernel(payload) => {
                let KernelAttestedFindingAdmissionArtifactPayload {
                    artifact_ref,
                    operator_capability,
                    governed_intent,
                    submission_proof,
                    authority_attestation,
                    threshold_proposal,
                    approval_tokens,
                } = *payload;
                let authorization = ActiveResponseAuthorizationRequest::new(
                    operator_capability,
                    response_plan.authorization_body(),
                    governed_intent,
                    submission_proof,
                )?;
                let fresh = chio_security_types::FreshLiveAdmission::new(response_plan).map_err(
                    |error| {
                        chio_kernel::KernelError::GovernedTransactionDenied(format!(
                            "active-response admission denied: {error}"
                        ))
                    },
                )?;
                ActiveResponseAdmissionRequest::new(
                    fresh,
                    authorization,
                    artifact_ref,
                    authority_attestation,
                    threshold_proposal,
                    approval_tokens,
                )
            }
            #[cfg(test)]
            AttestedFindingAdmissionArtifactPayload::Synthetic { .. } => {
                Err(chio_kernel::KernelError::Internal(
                    "synthetic admission artifacts cannot reach the kernel".to_string(),
                ))
            }
        }
    }
    pub(super) fn into_simulation_request(
        self,
        response_plan: ResponsePlan,
    ) -> Result<chio_kernel::ActiveResponseSimulationRequest, chio_kernel::KernelError> {
        match self.payload {
            AttestedFindingAdmissionArtifactPayload::Kernel(payload) => {
                let KernelAttestedFindingAdmissionArtifactPayload {
                    artifact_ref,
                    operator_capability,
                    governed_intent,
                    submission_proof,
                    authority_attestation,
                    threshold_proposal,
                    approval_tokens,
                } = *payload;
                let authorization = ActiveResponseAuthorizationRequest::new(
                    operator_capability,
                    response_plan.authorization_body(),
                    governed_intent,
                    submission_proof,
                )?;
                chio_kernel::ActiveResponseSimulationRequest::new(
                    response_plan,
                    authorization,
                    artifact_ref,
                    authority_attestation,
                    threshold_proposal,
                    approval_tokens,
                )
            }
            #[cfg(test)]
            AttestedFindingAdmissionArtifactPayload::Synthetic { .. } => {
                Err(chio_kernel::KernelError::Internal(
                    "synthetic admission artifacts cannot reach the kernel".to_string(),
                ))
            }
        }
    }
}
