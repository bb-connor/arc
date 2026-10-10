//! Release-only restoration for the operator-selected native recovery profile. The fenced
//! original capture, exact request custody and durable return are all required.
//! No constructor or decoded record can create a dispatch/capture owner.
use super::super::native_acquisition::store_call;
use super::*;
use crate::tool_outcome::DurableSecurityReleaseContext;

struct RecoveryReleaseOwner {
    original: AdmissionOperationV1,
    context: SecurityInvocationContext,
}
impl SecurityRequestLifecyclePermit for RecoveryReleaseOwner {
    fn ensure_final_release(self: Box<Self>) -> Result<(), KernelError> {
        Err(recovery_required(
            "recovery release requires the original guarded output",
        ))
    }
    fn ensure_final_release_with_output(
        self: Box<Self>,
        context: &DurableSecurityReleaseContext<'_>,
    ) -> Result<(), KernelError> {
        if context.operation() != &self.original
            || context.operation().state() != AdmissionOperationState::Finalizing
            || context.security_context() != &self.context
        {
            return Err(recovery_required(
                "recovery release substituted its original finalization",
            ));
        }
        // The common finalizer commits and reads back the exact classified
        // output under its original lease before acknowledging this owner.
        Ok(())
    }
}
impl ChioKernel {
    pub(super) fn recover_original_release_owner(
        &self,
        admission: &DurableToolAdmission,
        raw: &RawInvocationOutcomeV1,
    ) -> Result<Option<SecurityRequestLifecycleHandle>, KernelError> {
        let runtime = self.durable_runtime()?;
        let Some(port) = runtime.store.recovery_authority() else {
            return Ok(None);
        };
        let operation = &admission.operation;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let Some(record) = port
            .historical_release(operation.binding().operation_id(), &runtime.fence, now)
            .map_err(durable_store_error)?
        else {
            return Ok(None);
        };
        let deployment = match self.captured_recovery_deployment(operation)? {
            Some(crate::recovery::RecoveryCapturedDeploymentV1::Verified(deployment)) => deployment,
            _ => {
                return Err(recovery_required(
                    "recovery release historical deployment unavailable",
                ))
            }
        };
        let original = admission
            .original_retained_request()
            .ok_or_else(|| recovery_required("recovery release original request is absent"))?;
        original
            .validate_native_security_authority(&deployment.native_authority)
            .map_err(recovery_required)?;
        let context = raw
            .security_invocation_context()
            .ok_or_else(|| recovery_required("recovery release context is absent"))?;
        original
            .validate_native_security_context(context)
            .map_err(recovery_required)?;
        let mut request = raw
            .recovery_request()
            .map_err(recovery_required)?
            .ok_or_else(|| recovery_required("recovery release raw request is absent"))?;
        original
            .validate_request_material(&request)
            .map_err(recovery_required)?;
        request.execution_nonce = None;
        let envelope = record
            .envelope
            .as_ref()
            .ok_or_else(|| recovery_required("recovery release exact custody is absent"))?;
        if canonical_json_bytes(&request).map_err(recovery_required)?
            != envelope.request.as_str().as_bytes()
            || record.signed_grant.as_ref().is_none_or(|grant| {
                request
                    .declassification_grant
                    .as_ref()
                    .and_then(|grant| grant.recovery_v2())
                    != Some(grant)
            })
        {
            return Err(recovery_required(
                "recovery release request differs from original reviewed custody",
            ));
        }
        let guard = runtime.lock_mutations()?;
        let physical = store_call(|| {
            runtime.store.load_retained_tool_request(
                operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| recovery_required("recovery release physical original is absent"))?;
        let ledger = store_call(|| {
            runtime.store.load_native_dispatch_ledger(
                operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| recovery_required("recovery release original dispatch ledger is absent"))?;
        let capture = store_call(|| {
            runtime.store.load_native_dispatch_capture(
                operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| recovery_required("recovery release physical capture is absent"))?;
        if &physical.0 != operation
            || physical.1.canonical_bytes() != original.canonical_bytes()
            || &capture.operation != operation
            || operation.native_dispatch_ledger_digest() != Some(&ledger.record_digest)
            || operation.dispatch_commit().is_none()
        {
            return Err(recovery_required(
                "recovery release lost its original physical capture",
            ));
        }
        drop(guard);
        let canonical = canonical_json_bytes(
            &raw.recovery_request()
                .map_err(recovery_required)?
                .ok_or_else(|| recovery_required("recovery release raw request is absent"))?,
        )
        .map_err(recovery_required)?;
        let commitment = raw
            .security_dispatch_commitment_id()
            .map_err(recovery_required)?;
        let dispatch = SecurityPreDispatchContext {
            request: &request,
            canonical_request: &canonical,
            security_context: context,
            dispatch_commitment_id: &commitment,
        };
        Ok(Some(SecurityRequestLifecycleHandle::new(
            Box::new(RecoveryReleaseOwner {
                original: operation.clone(),
                context: context.clone(),
            }),
            &dispatch,
        )))
    }
}
