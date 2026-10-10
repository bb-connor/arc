//! Explicit immutable selection for financed native output retention.
//! Selection is configuration DATA. Original operation binding, native source
//! support and whole physical funding independently precede capture.
use super::*;
use crate::admission_operation::{NativeOutputRetentionProfileV1, RetainedToolAdmissionRequestV1};

impl ChioKernel {
    /// Choose a native durable producer profile for this Kernel instance.
    /// Exact repeated selection is harmless; replacement requires a new
    /// serving instance. Historical captured operations retain their original
    /// profile, including explicit absence. This method activates no store or
    /// financing role and grants no invocation, retry or output authority.
    pub fn select_native_output_retention(
        &mut self,
        profile: NativeOutputRetentionProfileV1,
    ) -> Result<(), KernelError> {
        match self.native_output_retention.as_deref() {
            Some(selected) if *selected == profile => Ok(()),
            Some(_) => Err(KernelError::DurableAdmission(
                "native output retention selection cannot be replaced".into(),
            )),
            None => {
                self.native_output_retention = Some(Box::new(profile));
                Ok(())
            }
        }
    }
}

impl ChioKernel {
    /// A fresh capture must use the exact profile selected by original admission.
    /// This local check is not loan verification: the physical native store
    /// independently authenticates and funds its complete retained phase plan.
    pub(super) fn require_native_output_retention_for_capture<'a>(
        &self,
        original: &'a RetainedToolAdmissionRequestV1,
    ) -> Result<&'a NativeOutputRetentionProfileV1, KernelError> {
        if original.native_security_authority_binding().is_none() {
            return Err(KernelError::DurableAdmission(
                "native output retention requires original native selection".into(),
            ));
        }
        let retained = original.native_output_retention().ok_or_else(|| {
            KernelError::DurableAdmission(
                "native capture requires an original output retention profile".into(),
            )
        })?;
        if self.native_output_retention.as_deref() != Some(retained) {
            return Err(KernelError::DurableAdmission(
                "native output retention differs from original admission".into(),
            ));
        }
        retained
            .validate_original_plan(original.post_return_steps().len())
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        Ok(retained)
    }
}

impl ChioKernel {
    /// Every fresh native external authorization uses the real original and a
    /// physical recovery lease. This call transports identity to the native
    /// source factory, which independently authenticates and funds its complete
    /// promise. Configuration data cannot supply a loan.
    pub(in crate::kernel) fn require_native_finishing_before_payment(
        &self,
        request: &ToolCallRequest,
        admission: Option<&DurableToolAdmission>,
        context: Option<&SecurityInvocationContext>,
        observed_at_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let selected = self.native_security_authority_binding()?;
        let Some(admission) = admission else {
            return if selected.is_some() {
                Err(KernelError::DurableAdmission(
                    "native external authorization requires original admission".into(),
                ))
            } else {
                Ok(())
            };
        };
        let original = admission.original_retained_request();
        let original_native =
            original.and_then(|original| original.native_security_authority_binding());
        let Some(binding) = original_native else {
            return if selected.is_some() {
                Err(KernelError::DurableAdmission(
                    "native external authorization lost its original selection".into(),
                ))
            } else {
                Ok(())
            };
        };
        // Recorded Authorized/Settled journal replay returns before this
        // fresh-authorization gate. A captured native operation cannot create a
        // new rail authorization under its retained cleanup purpose.
        if admission.operation().dispatch_commit().is_some() {
            return Err(KernelError::DurableAdmission(
                "captured native operation cannot create a new payment authorization".into(),
            ));
        }
        let original = original.ok_or_else(|| {
            KernelError::DurableAdmission(
                "native external authorization lost its original request".into(),
            )
        })?;
        let context = context.ok_or_else(|| {
            KernelError::DurableAdmission(
                "native external authorization requires trusted invocation context".into(),
            )
        })?;
        if selected.as_ref() != Some(binding)
            || admission.operation().state() != AdmissionOperationState::CapturePending
            || admission.operation().binding().kind() != AdmissionOperationKind::ToolDispatch
        {
            return Err(KernelError::DurableAdmission(
                "native external authorization changed its original capture".into(),
            ));
        }
        self.validate_security_invocation_context_binding(request, Some(context), None)?;
        self.validate_original_authority_profile(original)?;
        original
            .validate_binding(admission.operation().binding())
            .map_err(durable_store_error)?;
        original
            .validate_request_material(request)
            .map_err(durable_store_error)?;
        original
            .validate_native_security_authority(binding)
            .map_err(durable_store_error)?;
        original
            .validate_native_security_context(context)
            .map_err(durable_store_error)?;
        if original.native_output_retention() != self.native_output_retention.as_deref() {
            return Err(KernelError::DurableAdmission(
                "native external authorization changed its original output selection".into(),
            ));
        }
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(observed_at_unix_ms);
        let loaded = super::native_acquisition::store_call(|| {
            runtime.store.load_retained_tool_request(
                admission.operation().binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| {
            KernelError::DurableAdmission(
                "native external authorization original source is absent".into(),
            )
        })?;
        if loaded.0 != *admission.operation()
            || loaded.1.canonical_bytes() != original.canonical_bytes()
        {
            return Err(KernelError::DurableAdmission(
                "native external authorization original source changed".into(),
            ));
        }
        let lease = self.claim_admission_recovery(&loaded.0, now)?;
        let custody = crate::admission_operation::NativeSecurityEgressContext {
            operation: &loaded.0,
            lease: &lease,
            binding,
            request,
            security_context: context,
            trusted_now_unix_ms: now,
        };
        super::native_acquisition::store_call(|| {
            runtime
                .store
                .require_native_pre_authorization_finishing_funding(&custody)
        })
    }
}

impl ChioKernel {
    /// Freeze the selected native program only at fresh original admission.
    /// This is producer identity DATA, not a funded phase or effect permit.
    /// Legacy/ordinary absence uses the unchanged original plan, and every
    /// captured operation retains its already frozen historical identities.
    pub(super) fn durable_post_return_plan_for_fresh_native_profile(
        &self,
        selected: Option<&NativeOutputRetentionProfileV1>,
    ) -> Result<DurablePostReturnPlan, KernelError> {
        let Some(profile) = selected else {
            return self.durable_post_return_plan();
        };
        if profile.envelopes().post_return_steps() != 1
            || !self.guards.is_empty()
            || !self.post_invocation_pipeline.is_empty()
        {
            return Err(KernelError::DurableAdmission(
                "original bounded native program does not support the configured guard pipeline"
                    .into(),
            ));
        }
        Ok(DurablePostReturnPlan {
            hook_identities: Vec::new(),
            frozen_steps: vec![profile
                .materialization_identity()
                .map_err(durable_store_error)?],
        })
    }
}

impl ChioKernel {
    pub(super) fn durable_post_return_plan_for_original(
        &self,
        original: Option<&RetainedToolAdmissionRequestV1>,
    ) -> Result<DurablePostReturnPlan, KernelError> {
        let Some(original) = original else {
            return self.durable_post_return_plan();
        };
        if original.native_output_retention().is_none() {
            return self.durable_post_return_plan();
        }
        original
            .validate_bounded_native_materializer()
            .map_err(durable_store_error)?;
        Ok(DurablePostReturnPlan {
            hook_identities: Vec::new(),
            frozen_steps: original.post_return_steps().to_vec(),
        })
    }
}
