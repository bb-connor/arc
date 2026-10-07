//! Exhaustive request review without changing legacy process/native digests.
use super::ToolCallRequest;
use crate::{dpop::DpopProof, execution_nonce::SignedExecutionNonce};
use chio_core::capability::{
    governance::{GovernedApprovalToken, GovernedTransactionIntent, ThresholdApprovalProposal},
    scope::ModelMetadata,
    supplemental_authorization::OpaqueSupplementalAuthorization,
    token::{CapabilityToken, CapabilityTokenSigningBody},
};
use chio_core_types::{canonical::CanonicalBytes, recovery::SignedDisclosureGrant};
use chio_security_types::recovery::ContractError;
use serde::Serialize;

/// A borrowed review projection is data. It cannot be deserialized, retargeted
/// or converted into an existing kernel dispatch/capture owner.
///
/// ```compile_fail
/// use chio_kernel::NativeSecurityDispatchCaptureAuthority;
/// let _: Result<NativeSecurityDispatchCaptureAuthority<'static, 'static>, _> =
///     serde_json::from_str("{}");
/// ```
///
/// ```compile_fail
/// use chio_kernel::NativeSecurityDispatchCaptureAuthority;
/// fn duplicate(owner: &NativeSecurityDispatchCaptureAuthority<'_, '_>) {
///     let _: NativeSecurityDispatchCaptureAuthority<'_, '_> = Clone::clone(owner);
/// }
/// ```
///
/// ```compile_fail
/// use chio_kernel::{NativeSecurityDispatchCaptureAuthority, PreparedNativeSecurityEgress};
/// fn dispatch_shared(owner: &NativeSecurityDispatchCaptureAuthority<'_, '_>,
///     prepared: PreparedNativeSecurityEgress<'_>,
///     ledger: &chio_kernel::admission_operation::NativeSecurityDispatchLedgerRecordV1) {
///     let _ = owner.capture(prepared, ledger, b"{}");
/// }
/// ```
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
    declassification_grant: &'a Option<SignedDisclosureGrant>,
}

impl core::fmt::Debug for RecoveryRequestProjection<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryRequestProjection([redacted])")
    }
}
impl RecoveryRequestProjection<'_> {
    /// Protected canonical data for the native recovery exact-action materializer. This is
    /// not an ActionIntent digest or the frozen process request hash.
    pub fn canonical_semantics(&self) -> Result<CanonicalBytes, ContractError> {
        CanonicalBytes::new(&self.semantics).map_err(|_| ContractError::Malformed)
    }
    /// Exact display bytes include the complete semantic projection, including
    /// the unsigned capability, tool, recipient, model metadata and arguments.
    pub fn canonical_action_preview(
        &self,
        action: &chio_security_types::recovery::ActionIntentV1,
    ) -> Result<CanonicalBytes, ContractError> {
        CanonicalBytes::new(&(action, &self.semantics)).map_err(|_| ContractError::Malformed)
    }
}

impl ToolCallRequest {
    /// Every added request field forces an explicit review/custody decision at
    /// compile time. A presented nonce is only a claim until the native owner
    /// verifies its exact original issuance. No attachment may be refreshed here.
    pub fn recovery_review_projection(&self) -> RecoveryRequestProjection<'_> {
        let ToolCallRequest {
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
