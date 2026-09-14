//! Release-only recovery from physically captured native caller custody and
//! independently authenticated original delivery. Ordinary live native owners
//! remain non-reconstructible. Nothing here creates dispatch authority.
use super::super::native_acquisition::store_call;
use super::*;
use crate::tool_outcome::DurableSecurityReleaseContext;

struct NativeCallerReleaseOwner {
    captured: AdmissionOperationV1,
    context: SecurityInvocationContext,
}

impl SecurityRequestLifecyclePermit for NativeCallerReleaseOwner {
    fn ensure_final_release(self: Box<Self>) -> Result<(), KernelError> {
        Err(recovery_required(
            "native caller release requires the exact durable output",
        ))
    }

    fn ensure_final_release_with_output(
        self: Box<Self>,
        context: &DurableSecurityReleaseContext<'_>,
    ) -> Result<(), KernelError> {
        if context.operation() != &self.captured
            || context.operation().state() != AdmissionOperationState::Finalizing
            || context.security_context() != &self.context
        {
            return Err(recovery_required(
                "native caller release changed its original finalization",
            ));
        }
        // The shared finalizer independently commits the guarded native output
        // join before consuming this owner, then checkpoints the exact lease.
        Ok(())
    }
}

impl ChioKernel {
    pub(in crate::kernel::admission_coordinator) fn recover_native_caller_release_owner(
        &self,
        admission: &DurableToolAdmission,
        raw: &RawInvocationOutcomeV1,
    ) -> Result<Option<SecurityRequestLifecycleHandle>, KernelError> {
        if !admission
            .operation
            .provider_attempt()
            .is_some_and(ProviderAttemptBindingV1::is_native_caller_report)
        {
            return Ok(None);
        }
        let original = admission
            .original_retained_request()
            .ok_or_else(|| recovery_required("native caller original request is absent"))?;
        self.validate_original_authority_profile(original)?;
        let evidence = raw
            .caller_delivery_evidence()
            .ok_or_else(|| recovery_required("native caller release lacks signed delivery"))?;
        let runtime = self.durable_runtime()?;
        let guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let operation_id = admission.operation.binding().operation_id();
        let (operation, physical_original) = store_call(|| {
            runtime
                .store
                .load_retained_tool_request(operation_id, &runtime.fence, now)
        })?
        .ok_or_else(|| recovery_required("native caller original capture is absent"))?;
        if operation != admission.operation
            || physical_original.canonical_bytes() != original.canonical_bytes()
        {
            return Err(recovery_required("native caller original capture changed"));
        }
        let frame = store_call(|| {
            runtime
                .store
                .load_caller_dispatch_context(operation_id, &runtime.fence, now)
        })?
        .ok_or_else(|| recovery_required("native caller release frame is absent"))?;
        let nonce = store_call(|| {
            runtime
                .store
                .load_execution_nonce_reservation(operation_id, &runtime.fence, now)
        })?
        .ok_or_else(|| recovery_required("native caller nonce history is absent"))?;
        let ledger = store_call(|| {
            runtime
                .store
                .load_native_dispatch_ledger(operation_id, &runtime.fence, now)
        })?
        .ok_or_else(|| recovery_required("native caller ledger is absent"))?;
        let capture = store_call(|| {
            runtime
                .store
                .load_native_dispatch_capture(operation_id, &runtime.fence, now)
        })?
        .ok_or_else(|| recovery_required("native caller physical budget capture is absent"))?;
        if capture.operation != operation
            || nonce.issuer() != &self.config.keypair.public_key()
            || evidence.report.report.completed_at_unix_ms > now
        {
            return Err(recovery_required(
                "native caller capture or delivery time changed",
            ));
        }
        drop(guard);
        let context = self.restore_caller_return_context(admission, &frame, now)?;
        let custody = evidence
            .validate_native_original(&operation, original, &nonce, &frame)
            .map_err(recovery_required)?;
        // The evidence verifier above reconstructs the complete expected body
        // from the fenced nonce, executor pin and frame, then verifies both
        // signatures. Do not re-enter the start issuer here: that would repeat
        // the entire native history walk inside an already deep finalizer and
        // generate an authorization that release-only recovery does not need.
        let canonical =
            canonical_json_bytes(original.request_for_revalidation()).map_err(recovery_required)?;
        let raw_request = raw
            .recovery_request()
            .map_err(recovery_required)?
            .ok_or_else(|| recovery_required("native caller raw request is absent"))?;
        if ledger.record_digest != *custody.ledger_digest()
            || ledger.canonical_record != custody.ledger_bytes()
            || context.security_invocation_context.as_ref() != Some(custody.security_context())
            || canonical_json_bytes(&raw_request).map_err(recovery_required)? != canonical
            || raw.security_invocation_context() != Some(custody.security_context())
        {
            return Err(recovery_required(
                "native caller release differs from authenticated original custody",
            ));
        }
        let dispatch_commitment_id = raw
            .security_dispatch_commitment_id()
            .map_err(recovery_required)?;
        let dispatch = SecurityPreDispatchContext {
            request: original.request_for_revalidation(),
            canonical_request: &canonical,
            security_context: custody.security_context(),
            dispatch_commitment_id: &dispatch_commitment_id,
        };
        Ok(Some(SecurityRequestLifecycleHandle::new(
            Box::new(NativeCallerReleaseOwner {
                captured: operation,
                context: custody.security_context().clone(),
            }),
            &dispatch,
        )))
    }
}
