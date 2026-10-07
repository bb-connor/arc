//! Only the installed resolver converts the owning policy's closed vocabulary.
use super::*;
use chio_kernel::NativeFlowPolicyRefusal;

impl NativeFlowResolver {
    pub(super) fn record_policy_refusal(
        &self,
        authority: &mut chio_kernel::NativeSecurityDispatchCaptureAuthority<'_, '_>,
        denial: &FlowDenial,
    ) -> Result<(), KernelError> {
        let owner = self
            .policy_refusal_owner
            .lock()
            .map_err(|_| KernelError::Internal("native policy refusal owner unavailable".into()))?;
        // Legacy ordinary registration remains generic. A returned name or
        // diagnostic cannot acquire the reserved native owner.
        let Some(owner) = owner.as_ref() else {
            return Ok(());
        };
        let refusal = match denial {
            FlowDenial::StateOverflow => NativeFlowPolicyRefusal::StateOverflow,
            FlowDenial::StateChanged => NativeFlowPolicyRefusal::StateChanged,
            FlowDenial::InvalidManifest => NativeFlowPolicyRefusal::InvalidManifest,
            FlowDenial::DeclassificationBindingMismatch => {
                NativeFlowPolicyRefusal::DeclassificationBindingMismatch
            }
            FlowDenial::DeclassificationPurposeDenied => {
                NativeFlowPolicyRefusal::DeclassificationPurposeDenied
            }
            FlowDenial::DeclassificationNotYetValid => {
                NativeFlowPolicyRefusal::DeclassificationNotYetValid
            }
            FlowDenial::DeclassificationExpired => NativeFlowPolicyRefusal::DeclassificationExpired,
            FlowDenial::DeclassificationUntrustedAuthority => {
                NativeFlowPolicyRefusal::DeclassificationUntrustedAuthority
            }
            FlowDenial::UnexpectedDeclassification => {
                NativeFlowPolicyRefusal::UnexpectedDeclassification
            }
            FlowDenial::DeclassificationReplay => NativeFlowPolicyRefusal::DeclassificationReplay,
            FlowDenial::DeclassificationStoreFailure => {
                NativeFlowPolicyRefusal::DeclassificationStoreFailure
            }
            FlowDenial::ClassifierFailure => NativeFlowPolicyRefusal::ClassifierFailure,
            FlowDenial::ClassifierBindingMismatch => {
                NativeFlowPolicyRefusal::ClassifierBindingMismatch
            }
            FlowDenial::MissingPolicyClearance => NativeFlowPolicyRefusal::MissingPolicyClearance,
            FlowDenial::MissingManifestClearance => {
                NativeFlowPolicyRefusal::MissingManifestClearance
            }
            FlowDenial::TopSource => NativeFlowPolicyRefusal::TopSource,
            FlowDenial::TopClearance => NativeFlowPolicyRefusal::TopClearance,
            FlowDenial::PolicyFlowViolation => NativeFlowPolicyRefusal::PolicyFlowViolation,
            FlowDenial::ManifestFlowViolation => NativeFlowPolicyRefusal::ManifestFlowViolation,
        };
        authority.record_policy_refusal(owner, refusal)
    }
}
