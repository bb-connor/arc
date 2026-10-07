//! Qualification bridge for the exact scoped original-operation decision.
use super::*;
use crate::admission_operation::AdmissionOperationId;

impl ChioKernel {
    /// Exercise the owning decision using real retained native caller custody.
    /// This is not a workflow, a caller-v2 wire route, or execution permission.
    pub fn reconcile_scoped_caller_wait_for_test(
        &self,
        id: &AdmissionOperationId,
    ) -> Result<AdmissionOperationState, KernelError> {
        let runtime = self.durable_runtime()?;
        let now = runtime.refresh_trusted_time(0);
        let _owner = runtime
            .mutation_sequencer
            .try_own_operation(id)?
            .ok_or_else(unsupported)?;
        let (operation, original) = runtime
            .store
            .load_retained_tool_request(id, &runtime.fence, now)
            .map_err(durable_store_error)?
            .ok_or_else(unsupported)?;
        if operation.binding().operation_id() != id
            || operation.state() != AdmissionOperationState::DispatchCommitted
            || operation
                .provider_attempt()
                .is_none_or(|attempt| !attempt.is_native_caller_report())
            || operation.native_dispatch_ledger_digest().is_none()
            || operation.caller_dispatch_context_digest().is_none()
            || original
                .authority_profile()
                .and_then(|profile| profile.caller_executor())
                .is_none()
            || runtime
                .store
                .load_execution_nonce_reservation(id, &runtime.fence, now)
                .map_err(durable_store_error)?
                .is_none()
            || runtime
                .store
                .load_caller_dispatch_context(id, &runtime.fence, now)
                .map_err(durable_store_error)?
                .is_none()
        {
            return Err(unsupported());
        }
        self.reconcile_scoped_dispatch_committed_original(&operation, now)?;
        let (actual, retained) = runtime
            .store
            .load_retained_tool_request(id, &runtime.fence, runtime.refresh_trusted_time(now))
            .map_err(durable_store_error)?
            .ok_or_else(unsupported)?;
        if actual.binding() != operation.binding()
            || actual.native_dispatch_ledger_digest() != operation.native_dispatch_ledger_digest()
            || actual.caller_dispatch_context_digest() != operation.caller_dispatch_context_digest()
            || actual.dispatch_commit() != operation.dispatch_commit()
            || retained.canonical_bytes() != original.canonical_bytes()
        {
            return Err(unsupported());
        }
        Ok(actual.state())
    }
}
