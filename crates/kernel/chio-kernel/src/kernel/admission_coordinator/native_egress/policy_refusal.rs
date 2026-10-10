//! Reserved policy evidence belongs to one installed native resolver.
use super::*;
use std::cell::RefCell;
use std::sync::Weak;

pub(in crate::kernel) const RESERVED_NATIVE_POLICY_OWNER: &str = "native-flow-resolver";

/// Fixed owning-policy data. Extension errors and panic text are never accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFlowPolicyRefusal {
    StateOverflow,
    StateChanged,
    InvalidManifest,
    DeclassificationBindingMismatch,
    DeclassificationPurposeDenied,
    DeclassificationNotYetValid,
    DeclassificationExpired,
    DeclassificationUntrustedAuthority,
    UnexpectedDeclassification,
    DeclassificationReplay,
    DeclassificationStoreFailure,
    ClassifierFailure,
    ClassifierBindingMismatch,
    MissingPolicyClearance,
    MissingManifestClearance,
    TopSource,
    TopClearance,
    PolicyFlowViolation,
    ManifestFlowViolation,
}

impl NativeFlowPolicyRefusal {
    const fn category(self) -> &'static str {
        match self {
            Self::StateOverflow => "state_overflow",
            Self::StateChanged => "state_changed",
            Self::InvalidManifest => "invalid_manifest",
            Self::DeclassificationBindingMismatch => "declassification_binding_mismatch",
            Self::DeclassificationPurposeDenied => "declassification_purpose_denied",
            Self::DeclassificationNotYetValid => "declassification_not_yet_valid",
            Self::DeclassificationExpired => "declassification_expired",
            Self::DeclassificationUntrustedAuthority => "declassification_untrusted_authority",
            Self::UnexpectedDeclassification => "unexpected_declassification",
            Self::DeclassificationReplay => "declassification_replay",
            Self::DeclassificationStoreFailure => "declassification_store_failure",
            Self::ClassifierFailure => "classifier_failure",
            Self::ClassifierBindingMismatch => "classifier_binding_mismatch",
            Self::MissingPolicyClearance => "missing_policy_clearance",
            Self::MissingManifestClearance => "missing_manifest_clearance",
            Self::TopSource => "top_source",
            Self::TopClearance => "top_clearance",
            Self::PolicyFlowViolation => "policy_flow_violation",
            Self::ManifestFlowViolation => "manifest_flow_violation",
        }
    }
}

/// Installation custody selected by the trusted host, separate from ordinary
/// guard registration. Request metadata cannot construct or decode this owner.
pub struct NativeFlowPolicyRefusalOwner {
    identity: Arc<()>,
    binding: NativeSecurityAuthorityBindingV1,
}

impl fmt::Debug for NativeFlowPolicyRefusalOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeFlowPolicyRefusalOwner")
            .finish_non_exhaustive()
    }
}

pub(in crate::kernel) struct NativeFlowPolicyWitnessRegistration {
    identity: Arc<()>,
    hook: Weak<dyn SecurityPreDispatchHook>,
    binding: NativeSecurityAuthorityBindingV1,
}

impl NativeFlowPolicyWitnessRegistration {
    pub(super) fn verify(
        &self,
        kernel: &ChioKernel,
        original: &NativeSecurityAuthorityBindingV1,
        owner: &NativeFlowPolicyRefusalOwner,
    ) -> Result<(), KernelError> {
        let installed = kernel
            .security_pre_dispatch_hook
            .as_ref()
            .ok_or_else(|| invalid("native policy witness owner is absent"))?;
        let selected = self
            .hook
            .upgrade()
            .ok_or_else(|| invalid("native policy witness owner was replaced"))?;
        if !Arc::ptr_eq(installed, &selected)
            || !Arc::ptr_eq(&self.identity, &owner.identity)
            || original != &self.binding
            || owner.binding != self.binding
            || kernel.native_security_authority_binding()?.as_ref() != Some(&self.binding)
        {
            return Err(invalid(
                "native policy witness owner differs from original selection",
            ));
        }
        Ok(())
    }
}

impl ChioKernel {
    /// Trusted installation of one reserved native policy witness owner.
    /// Ordinary callback registration receives no token. Original native
    /// admission and the physical store still verify authority independently.
    pub fn set_native_flow_policy_pre_dispatch_hook(
        &mut self,
        hook: Arc<dyn SecurityPreDispatchHook>,
        binding: &NativeSecurityAuthorityBindingV1,
    ) -> Result<NativeFlowPolicyRefusalOwner, KernelError> {
        let (named, supported, selected) = crate::kernel::security_dispatch::callback(
            "native policy witness installation",
            || {
                Ok((
                    hook.name() == RESERVED_NATIVE_POLICY_OWNER,
                    hook.supports_native_dispatch(),
                    hook.native_authority_binding()?,
                ))
            },
        )?;
        if !named || !supported || selected.as_ref() != Some(binding) {
            return Err(invalid(
                "native policy witness installation differs from selected authority",
            ));
        }
        let identity = Arc::new(());
        let registration = NativeFlowPolicyWitnessRegistration {
            identity: identity.clone(),
            hook: Arc::downgrade(&hook),
            binding: binding.clone(),
        };
        self.security_pre_dispatch_hook = Some(hook);
        self.native_flow_policy_witness_registration = Some(registration);
        Ok(NativeFlowPolicyRefusalOwner {
            identity,
            binding: binding.clone(),
        })
    }
}

struct NativePolicyReceiptWitness {
    kernel_identity: usize,
    request_id: String,
    capability_id: String,
    server: String,
    tool: String,
    binding: AdmissionOperationBindingV1,
    refusal: NativeFlowPolicyRefusal,
}

thread_local! {
    static NATIVE_POLICY_RECEIPT_WITNESS: RefCell<Option<NativePolicyReceiptWitness>> =
        const { RefCell::new(None) };
}

pub(in crate::kernel) struct ScopedNativePolicyReceiptWitness {
    previous: Option<NativePolicyReceiptWitness>,
}

impl Drop for ScopedNativePolicyReceiptWitness {
    fn drop(&mut self) {
        let previous = self.previous.take();
        NATIVE_POLICY_RECEIPT_WITNESS.with(|slot| {
            slot.replace(previous);
        });
    }
}

impl ChioKernel {
    pub(in crate::kernel) fn scope_native_policy_refusal_receipt(
        &self,
        request: &ToolCallRequest,
        operation: &AdmissionOperationV1,
        refusal: NativeFlowPolicyRefusal,
    ) -> Result<ScopedNativePolicyReceiptWitness, KernelError> {
        if operation.binding().request_id().as_str() != request.request_id
            || operation.dispatch_commit().is_some()
        {
            return Err(invalid(
                "native policy receipt belongs to another original request",
            ));
        }
        let witness = NativePolicyReceiptWitness {
            kernel_identity: self as *const Self as usize,
            request_id: request.request_id.clone(),
            capability_id: request.capability.id.clone(),
            server: request.server_id.clone(),
            tool: request.tool_name.clone(),
            binding: operation.binding().clone(),
            refusal,
        };
        let previous = NATIVE_POLICY_RECEIPT_WITNESS.with(|slot| slot.replace(Some(witness)));
        Ok(ScopedNativePolicyReceiptWitness { previous })
    }

    /// Signing drops extension-supplied reserved names and adds this exact
    /// private witness only with confirmed native compensation metadata.
    pub(in crate::kernel) fn native_policy_refusal_receipt_evidence(
        &self,
        params: &ReceiptParams<'_>,
        metadata: &Option<serde_json::Value>,
    ) -> Result<Option<chio_core::receipt::metadata::GuardEvidence>, KernelError> {
        NATIVE_POLICY_RECEIPT_WITNESS.with(|slot| {
            let current = slot.borrow();
            let Some(witness) = current.as_ref() else {
                return Ok(None);
            };
            if witness.kernel_identity != self as *const Self as usize
                || params.request_id != Some(witness.request_id.as_str())
                || params.capability_id != witness.capability_id
                || params.server_id != witness.server
                || params.tool_name != witness.tool
            {
                return Ok(None);
            }
            let raw = metadata
                .as_ref()
                .and_then(|value| value.get(ADMISSION_RECEIPT_METADATA_KEY))
                .ok_or_else(|| {
                    invalid("native policy receipt lacks compensated operation custody")
                })?;
            let physical: AdmissionReceiptMetadataV1 = serde_json::from_value(raw.clone())
                .map_err(|_| invalid("native policy receipt compensation metadata is invalid"))?;
            if !matches!(&params.decision, Decision::Deny { .. })
                || physical.operation_id != *witness.binding.operation_id()
                || physical.request_id != *witness.binding.request_id()
                || physical.request_namespace_digest != *witness.binding.request_namespace_digest()
                || physical.request_binding_hash != *witness.binding.request_binding_hash()
                || physical.projected_state != AdmissionOperationState::CompensatedBeforeDispatch
                || physical.projected_dispatch_state != AdmissionDispatchState::Terminal
                || physical.retained_dispatch_commit.is_some()
                || physical.compensation_status
                    != AdmissionCompensationStatus::CompensatedBeforeDispatch
                || physical.tool_outcome_id.is_some()
                || physical.tool_outcome_version.is_some()
            {
                return Err(invalid(
                    "native policy receipt compensation differs from original custody",
                ));
            }
            Ok(Some(chio_core::receipt::metadata::GuardEvidence {
                guard_name: RESERVED_NATIVE_POLICY_OWNER.into(),
                verdict: false,
                details: Some(witness.refusal.category().into()),
            }))
        })
    }
}
