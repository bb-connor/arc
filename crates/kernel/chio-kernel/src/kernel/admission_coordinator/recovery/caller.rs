//! A committed caller waits for evidence without reopening admission or the
//! immutable legacy unknown-outcome terminal. No recovery callback executes it.
use super::*;

impl ChioKernel {
    pub(super) fn retain_authenticated_caller_wait(
        &self,
        operation: &AdmissionOperationV1,
        now: u64,
    ) -> Result<bool, KernelError> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.retain_authenticated_caller_wait_inner(operation, now)
        }))
        .unwrap_or_else(|_| {
            Err(KernelError::DurableAdmission(
                "caller wait recovery callback panicked".into(),
            ))
        })
    }

    fn retain_authenticated_caller_wait_inner(
        &self,
        operation: &AdmissionOperationV1,
        now: u64,
    ) -> Result<bool, KernelError> {
        if !operation
            .provider_attempt()
            .is_some_and(|attempt| attempt.is_caller_report())
        {
            return Ok(false);
        }
        let original = self.load_original_request_for_finalization(operation, now)?;
        if original
            .as_ref()
            .and_then(|original| original.authority_profile())
            .and_then(|profile| profile.caller_executor())
            .is_none()
        {
            return Ok(false);
        }
        let runtime = self.durable_runtime()?;
        let lease = self.claim_admission_recovery(operation, now)?;
        let command = AdmissionOperationCommand::new(
            operation.binding().operation_id().clone(),
            operation.version(),
            lease,
            Vec::new(),
            Some(AdmissionOperationState::AwaitingCallerReport),
            None,
            None,
        )?;
        let expected = operation.apply_command(&command, now)?.into_operation();
        let retained = runtime
            .store
            .await_caller_report(&command, now)
            .map_err(durable_store_error)?
            .into_operation();
        if retained != expected {
            return Err(KernelError::DurableAdmission(
                "caller wait changed the committed operation".into(),
            ));
        }
        let physical = runtime
            .store
            .load_retained_tool_request(expected.binding().operation_id(), &runtime.fence, now)
            .map_err(durable_store_error)?;
        if !physical.is_some_and(|(actual, _)| actual == expected) {
            return Err(KernelError::DurableAdmission(
                "caller wait physical readback is absent or changed".into(),
            ));
        }
        Ok(true)
    }
}
