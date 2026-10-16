//! Canonical request review preserves exact semantic and presented custody data.
use crate::{dpop::DpopProof, execution_nonce::SignedExecutionNonce, ToolCallRequest};
use chio_core::capability::{
    governance::{GovernedApprovalToken, GovernedTransactionIntent, ThresholdApprovalProposal},
    scope::ModelMetadata,
    supplemental_authorization::OpaqueSupplementalAuthorization,
    token::{CapabilityToken, CapabilityTokenSigningBody},
};
use chio_core_types::{
    canonical::CanonicalBytes, recovery::RecoveryDigestDomain, SignedDeclassificationGrant,
};
use chio_security_types::recovery::{ActionIntentV1, ContractError, ReviewDigest};
use serde::Serialize;

/// A borrowed view of the request's semantics and exact presented credentials.
/// Serialization carries data and does not authenticate any attachment.
#[derive(Serialize)]
pub struct RecoveryRequestProjection<'a> {
    semantics: ReviewedSemantics<'a>,
    fixed_authorization: FixedAuthorization<'a>,
    native_nonce_claim: &'a Option<SignedExecutionNonce>,
}

#[derive(Serialize)]
struct ReviewedSemantics<'a> {
    capability_signing_body: CapabilityTokenSigningBody,
    request_id: &'a str,
    tool_name: &'a str,
    server_id: &'a str,
    agent_id: &'a str,
    arguments: &'a serde_json::Value,
    governed_intent: &'a Option<GovernedTransactionIntent>,
    model_metadata: &'a Option<ModelMetadata>,
    federated_origin_kernel_id: &'a Option<String>,
}

#[derive(Serialize)]
struct FixedAuthorization<'a> {
    capability: &'a CapabilityToken,
    dpop_proof: &'a Option<DpopProof>,
    approval_token: &'a Option<GovernedApprovalToken>,
    approval_tokens: &'a [GovernedApprovalToken],
    threshold_approval_proposal: &'a Option<ThresholdApprovalProposal>,
    supplemental_authorization: &'a Option<OpaqueSupplementalAuthorization>,
    declassification_grant: &'a Option<SignedDeclassificationGrant>,
}

impl core::fmt::Debug for RecoveryRequestProjection<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RecoveryRequestProjection([redacted])")
    }
}

impl RecoveryRequestProjection<'_> {
    /// Canonical semantic data for exact-action materialization.
    pub fn canonical_semantics(&self) -> Result<CanonicalBytes, ContractError> {
        CanonicalBytes::new(&self.semantics).map_err(|_| ContractError::Malformed)
    }

    /// Full action and semantic request bytes for the protected review document.
    /// Presented credentials remain in the separately serialized custody view.
    pub fn canonical_action_preview(
        &self,
        action: &ActionIntentV1,
    ) -> Result<CanonicalBytes, ContractError> {
        CanonicalBytes::new(&(action, &self.semantics)).map_err(|_| ContractError::Malformed)
    }
}

impl ToolCallRequest {
    /// Every request field is assigned to a review or presented-custody class.
    pub fn recovery_review_projection(&self) -> RecoveryRequestProjection<'_> {
        let Self {
            request_id,
            capability,
            tool_name,
            server_id,
            agent_id,
            arguments,
            dpop_proof,
            execution_nonce,
            governed_intent,
            approval_token,
            approval_tokens,
            threshold_approval_proposal,
            supplemental_authorization,
            model_metadata,
            federated_origin_kernel_id,
            declassification_grant,
        } = self;
        RecoveryRequestProjection {
            semantics: ReviewedSemantics {
                capability_signing_body: capability.signing_body(),
                request_id,
                tool_name,
                server_id,
                agent_id,
                arguments,
                governed_intent,
                model_metadata,
                federated_origin_kernel_id,
            },
            fixed_authorization: FixedAuthorization {
                capability,
                dpop_proof,
                approval_token,
                approval_tokens,
                threshold_approval_proposal,
                supplemental_authorization,
                declassification_grant,
            },
            native_nonce_claim: execution_nonce,
        }
    }
}

/// Domain-separated digest of the complete action preview.
pub fn recovery_review_digest(
    action: &ActionIntentV1,
    request: &ToolCallRequest,
) -> Result<ReviewDigest, crate::KernelError> {
    let bytes = request
        .recovery_review_projection()
        .canonical_action_preview(action)
        .map_err(|_| crate::KernelError::DurableAdmission("recovery preview refused".into()))?;
    Ok(ReviewDigest::from_bytes(
        *RecoveryDigestDomain::Preview.digest(&bytes).as_bytes(),
    ))
}

#[cfg(test)]
#[path = "request_review_tests.rs"]
mod tests;
