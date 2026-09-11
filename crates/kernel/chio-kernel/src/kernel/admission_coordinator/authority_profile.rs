//! Freeze configured selections without treating them as activated authority.

use super::*;
use crate::admission_operation::{
    AdmissionAuthorityProfileV1, AdmissionAuthoritySelectionV1, RetainedToolAdmissionRequestV1,
};

impl DurableToolAdmission {
    pub(crate) fn original_retained_request(&self) -> Option<&RetainedToolAdmissionRequestV1> {
        self.retained_request.as_ref()
    }

    /// The immutable original selection, not current activation or write authority.
    /// A later hook cannot remove this operation's native lifecycle requirement.
    pub(in crate::kernel) fn original_native_security_authority_binding(
        &self,
    ) -> Option<&crate::admission_operation::NativeSecurityAuthorityBindingV1> {
        self.retained_request
            .as_ref()
            .and_then(RetainedToolAdmissionRequestV1::native_security_authority_binding)
    }
}

impl ChioKernel {
    pub(super) fn load_original_request_for_finalization(
        &self,
        operation: &AdmissionOperationV1,
        observed_at: u64,
    ) -> Result<Option<RetainedToolAdmissionRequestV1>, KernelError> {
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(observed_at);
        let loaded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.store.load_retained_tool_request(
                operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        }))
        .map_err(|_| {
            KernelError::DurableAdmission(
                "original profile recovery read panicked (fail-closed)".into(),
            )
        })?
        .map_err(durable_store_error)?;
        loaded
            .map(|(actual, original)| {
                if actual != *operation {
                    return Err(KernelError::DurableAdmission(
                        "original profile recovery read changed its operation".into(),
                    ));
                }
                original
                    .validate_binding(operation.binding())
                    .map_err(durable_store_error)?;
                Ok(original)
            })
            .transpose()
    }

    pub(crate) fn admission_authority_profile(
        &self,
    ) -> Result<AdmissionAuthorityProfileV1, KernelError> {
        let runtime = self.configured_runtime_participant_binding()?.cloned();
        let (enforces_swarm, revalidates) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.runtime_admission_hook
                    .as_ref()
                    .map_or((false, false), |hook| {
                        (
                            hook.enforces_swarm_authority(),
                            hook.requires_dispatch_revalidation(),
                        )
                    })
            }))
            .map_err(|_| {
                KernelError::DurableAdmission(
                    "runtime authority declaration panicked (fail-closed)".into(),
                )
            })?;
        AdmissionAuthorityProfileV1::new(AdmissionAuthoritySelectionV1 {
            runtime_hook_installed: self.runtime_admission_hook.is_some(),
            swarm_admission_required: self.swarm_admission_required,
            runtime_enforces_swarm_authority: enforces_swarm,
            runtime_requires_dispatch_revalidation: revalidates,
            runtime,
            approval: self.configured_governed_approval_binding().cloned(),
            dpop: self.dpop_authority.clone(),
        })
        .map_err(durable_store_error)
    }

    pub(crate) fn validate_original_authority_profile(
        &self,
        original: &RetainedToolAdmissionRequestV1,
    ) -> Result<(), KernelError> {
        let current = self.admission_authority_profile()?;
        let matches = match original.authority_profile() {
            Some(profile) => profile == &current,
            // Legacy history is readable but cannot select newly configured
            // operation-owned authority. Concrete claim ports require v4.
            None => !current.has_operation_owned_authority(),
        };
        if !matches {
            return Err(KernelError::DurableAdmission(
                "authority profile differs from original admission".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_live_admission_authority_profile(
        &self,
        admission: Option<&DurableToolAdmission>,
    ) -> Result<(), KernelError> {
        if let Some(original) = admission.and_then(|admission| admission.retained_request.as_ref())
        {
            self.validate_original_authority_profile(original)?;
        }
        Ok(())
    }
}
