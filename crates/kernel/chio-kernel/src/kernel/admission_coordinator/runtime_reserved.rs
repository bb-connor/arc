//! A reserved caller revalidates its original runtime claim. It must never
//! reacquire a continuation or release an episode to get past grant selection.

use super::*;

impl ChioKernel {
    pub(super) fn revalidate_reserved_caller_runtime(
        &self,
        hook: &dyn RuntimeAdmissionHook,
        context: &RuntimeAdmissionContext<'_>,
        admission: &DurableToolAdmission,
        binding: &RuntimeParticipantAuthorityBindingV1,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        let operation = admission.operation();
        let original = admission.original_retained_request().ok_or_else(|| {
            acquisition_error("reserved caller lost its original runtime request")
        })?;
        self.validate_original_authority_profile(original)?;
        original
            .validate_request_material(context.request)
            .map_err(durable_store_error)?;
        let grant = context
            .matched_grant_index
            .ok_or_else(|| acquisition_error("reserved caller has no selected runtime grant"))?;
        if operation.state() != AdmissionOperationState::ReadyToDispatch
            || operation.dispatch_commit().is_some()
            || !operation
                .provider_attempt()
                .is_some_and(is_caller_report_attempt)
            || original
                .authority_profile()
                .and_then(|profile| profile.runtime())
                != Some(binding)
            || !admission.permits_grant(grant)
        {
            return Err(acquisition_error(
                "reserved caller changed its original runtime binding",
            ));
        }
        let runtime = self.durable_runtime()?;
        let (source, history) = {
            let _guard = runtime.lock_mutations()?;
            let now = runtime.refresh_trusted_time(context.now_unix_ms);
            let (current, history) = load_history(runtime, operation, now)?;
            if current != *operation {
                return Err(acquisition_error("reserved runtime operation changed"));
            }
            super::super::runtime_participant::validate_recovery_history(operation, &history)?;
            let source = store_call("activation", || {
                runtime
                    .store
                    .load_runtime_participant_activation(binding, &runtime.fence, now)
            })?;
            (source, history)
        };
        let claim = history
            .iter()
            .find(|claim| {
                claim.disposition == RuntimeParticipantDisposition::ReservedBeforeDispatch
            })
            .ok_or_else(|| acquisition_error("reserved caller has no live runtime episode"))?;
        if claim.intent.phase() != RuntimeParticipantPhase::Dispatch
            || usize::try_from(claim.intent.grant_index()).ok() != Some(grant)
            || claim.intent.runtime_authority_id() != binding.runtime_authority_id()
            || claim.intent.expectation_id() != binding.expectation_id()
            || source.destination_authority_id() != runtime.fence.store_uuid
            || source.runtime_authority_id() != binding.runtime_authority_id().as_str()
        {
            return Err(acquisition_error(
                "reserved caller runtime episode or source changed",
            ));
        }
        let decision = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hook.revalidate_reserved_operation(context, &source, claim)
        }))
        .map_err(|_| acquisition_error("reserved runtime revalidation panicked"))??;
        let _guard = runtime.lock_mutations()?;
        let now =
            runtime.refresh_trusted_time(current_unix_timestamp_ms().max(context.now_unix_ms));
        let (current, retained) = load_history(runtime, operation, now)?;
        if current != *operation || retained != history {
            return Err(acquisition_error(
                "reserved runtime changed during revalidation",
            ));
        }
        Ok(decision)
    }
}
