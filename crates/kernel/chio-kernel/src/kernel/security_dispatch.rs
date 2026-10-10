//! Containment of live security extension callbacks. These owners are not
//! serializable admission custody and cannot certify recovery after a crash.
use super::{
    KernelError, SecurityDispatchOutcome, SecurityDispatchOutcomeHandle,
    SecurityDispatchOutcomeRecorder, SecurityPreDispatchContext, SecurityRequestLifecyclePermit,
};

pub(super) fn callback<T>(
    stage: &'static str,
    action: impl FnOnce() -> Result<T, KernelError>,
) -> Result<T, KernelError> {
    let failure = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        Ok(Ok(value)) => return Ok(value),
        Ok(Err(_)) => "failed",
        Err(_) => "panicked",
    };
    // Do not include extension-controlled errors or panic payloads. In
    // particular a post-effect fault must not advertise a retryable rejection.
    Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(
        format!("security {stage} callback {failure}; authoritative recovery required"),
    ))
}

pub(super) fn record_outcome(
    mut recorder: Box<dyn SecurityDispatchOutcomeRecorder>,
    outcome: SecurityDispatchOutcome,
) -> Result<(), KernelError> {
    let recorded = callback("outcome recording", || recorder.record(outcome));
    // Drop separately, after unwinding the callback. A recorder whose record
    // and destructor both panic must not cause a double-panic process abort.
    let disposed = callback("outcome recorder disposal", || {
        drop(recorder);
        Ok(())
    });
    recorded.and(disposed)
}

impl SecurityDispatchOutcomeHandle {
    #[must_use]
    pub fn new(
        context: &SecurityPreDispatchContext<'_>,
        recorder: Box<dyn SecurityDispatchOutcomeRecorder>,
    ) -> Self {
        Self {
            request_id: context.request.request_id.clone(),
            dispatch_commitment_id: context.dispatch_commitment_id.clone(),
            recorder: Some(recorder),
            drop_outcome: SecurityDispatchOutcome::DispatchFailed,
        }
    }

    pub(crate) fn mark_dispatch_started(&mut self) {
        self.drop_outcome = SecurityDispatchOutcome::OutcomeUnknownAfterDispatch;
    }

    pub fn record_released(self) -> Result<(), KernelError> {
        self.record(SecurityDispatchOutcome::Released)
    }

    pub fn record_dispatch_failed(self) -> Result<(), KernelError> {
        self.record(SecurityDispatchOutcome::DispatchFailed)
    }

    pub fn record_outcome_unknown_after_dispatch(self) -> Result<(), KernelError> {
        self.record(SecurityDispatchOutcome::OutcomeUnknownAfterDispatch)
    }

    fn record(mut self, outcome: SecurityDispatchOutcome) -> Result<(), KernelError> {
        let recorder = self.recorder.take().ok_or_else(|| {
            KernelError::Internal(
                "security dispatch outcome handle was already completed".to_string(),
            )
        })?;
        record_outcome(recorder, outcome)
    }
}

impl Drop for SecurityDispatchOutcomeHandle {
    fn drop(&mut self) {
        let Some(recorder) = self.recorder.take() else {
            return;
        };
        if record_outcome(recorder, self.drop_outcome).is_err() {
            tracing::warn!(
                request_id = %self.request_id,
                dispatch_commitment_id = %self.dispatch_commitment_id.as_str(),
                audit_fault = "security_dispatch_outcome_unrecorded",
                outcome = ?self.drop_outcome,
                "failed to record dropped security dispatch outcome"
            );
        }
    }
}

impl SecurityDispatchOutcomeHandle {
    pub(super) fn validate_context(
        &self,
        context: &SecurityPreDispatchContext<'_>,
    ) -> Result<(), KernelError> {
        if self.request_id != context.request.request_id
            || self.dispatch_commitment_id != *context.dispatch_commitment_id
        {
            return Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(
                "security outcome owner does not match the current dispatch commitment".into(),
            ));
        }
        Ok(())
    }
}

/// Keep extension disposal contained on all early returns and cancellation
/// paths. Dropping a permit does not assert successful final release.
pub(crate) struct SecurityRequestLifecycleHandle {
    permit: Option<Box<dyn SecurityRequestLifecyclePermit>>,
    dispatch_commitment_id: chio_security_types::ports::RecordId,
}

impl SecurityRequestLifecycleHandle {
    /// Final release gates response publication, including a signed denial
    /// after tool execution. A failed response never asserts successful release.
    pub(super) fn finish_response<T>(
        response: Result<T, KernelError>,
        permit: Option<Self>,
    ) -> Result<T, KernelError> {
        let response = response?;
        if let Some(permit) = permit {
            permit.ensure_final_release()?;
        }
        Ok(response)
    }

    pub(super) fn new(
        permit: Box<dyn SecurityRequestLifecyclePermit>,
        context: &SecurityPreDispatchContext<'_>,
    ) -> Self {
        Self {
            permit: Some(permit),
            dispatch_commitment_id: context.dispatch_commitment_id.clone(),
        }
    }

    pub(crate) fn ensure_final_release_for(
        mut self,
        context: &crate::tool_outcome::DurableSecurityReleaseContext<'_>,
    ) -> Result<(), KernelError> {
        self.validate_release_context(context)?;
        let permit = self.permit.take().ok_or_else(|| {
            KernelError::SecurityDispatchOutcomeRecoveryRequired(
                "security request lifecycle owner was already completed".into(),
            )
        })?;
        callback("final request release", || {
            permit.ensure_final_release_with_output(context)
        })
    }

    pub(crate) fn validate_release_context(
        &self,
        context: &crate::tool_outcome::DurableSecurityReleaseContext<'_>,
    ) -> Result<(), KernelError> {
        if &self.dispatch_commitment_id != context.dispatch_commitment_id() || self.permit.is_none()
        {
            return Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(
                "release owner belongs to another dispatch commitment or is completed".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_final_release(mut self) -> Result<(), KernelError> {
        let permit = self.permit.take().ok_or_else(|| {
            KernelError::SecurityDispatchOutcomeRecoveryRequired(
                "security request lifecycle owner was already completed".into(),
            )
        })?;
        callback("final request release", || permit.ensure_final_release())
    }
}

impl Drop for SecurityRequestLifecycleHandle {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        if callback("request lifecycle disposal", || {
            drop(permit);
            Ok(())
        })
        .is_err()
        {
            tracing::warn!(
                audit_fault = "security_request_lifecycle_disposal_failed",
                "security request lifecycle disposal requires authoritative recovery"
            );
        }
    }
}
