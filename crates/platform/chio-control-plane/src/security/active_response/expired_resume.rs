use super::{
    has_durable_execution_proof, ActiveResponseExecutionEvidence, ActiveResponseExecutorError,
    ActiveResponseReceiptProofSource, DurableActiveResponseExecutor, EffectPort,
    ResponseApprovalRequirement, ResponseDispatchApproval, ResponseDispatchRecord,
    ResponseDispatchStore, ResponsePlanKey, ResponseState, SecurityAlertPort, SecurityReceiptSink,
    ValidatedExecutionRequest,
};
use chio_quarantine::{decode_response_record, ResponseStateMachine};
use chio_security_types::ResponseEffectProgress;
use std::sync::Arc;

impl<
        S: ResponseDispatchStore + ?Sized,
        E: EffectPort + ?Sized,
        R: SecurityReceiptSink + ActiveResponseReceiptProofSource + ?Sized,
        A: SecurityAlertPort + ?Sized,
    > DurableActiveResponseExecutor<S, E, R, A>
{
    pub(super) fn drive_loaded_dispatch(
        &self,
        request: &ValidatedExecutionRequest,
        dispatch: &ResponseDispatchRecord,
        recovered: bool,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        self.drive_committed_dispatch(request, dispatch, recovered)
    }

    pub(super) fn drive_committed_dispatch(
        &self,
        request: &ValidatedExecutionRequest,
        dispatch: &ResponseDispatchRecord,
        recovered: bool,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        if request.raw.dispatch_committed_resume
            && !matches!(
                (
                    &request.raw.response_plan.approval_requirement,
                    &request.approval
                ),
                (
                    ResponseApprovalRequirement::Governed { .. },
                    ResponseDispatchApproval::Governed { .. }
                )
            )
        {
            return Err(ActiveResponseExecutorError::RejectedBeforeCommit(
                "dispatch-committed resume is not governed".to_string(),
            ));
        }
        let now_unix_ms = self.execution_time_after_commit()?;
        if now_unix_ms >= request.raw.response_plan.expires_at_unix_ms {
            return self.fail_expired_dispatch_committed_resume(
                request,
                dispatch,
                recovered,
                now_unix_ms,
            );
        }
        self.drive_dispatch(request, dispatch, recovered)
    }

    fn fail_expired_dispatch_committed_resume(
        &self,
        request: &ValidatedExecutionRequest,
        dispatch: &ResponseDispatchRecord,
        recovered: bool,
        now_unix_ms: u64,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        self.validate_existing_dispatch(request, dispatch)?;
        let key = ResponsePlanKey {
            tenant_id: request.raw.response_plan.tenant_id.clone(),
            action_id: request.raw.response_plan.action_id.clone(),
        };
        let current = self
            .store
            .load_plan(&key)
            .map_err(|error| {
                ActiveResponseExecutorError::OutcomeUnknown(format!(
                    "expired dispatch-committed response lookup failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                ActiveResponseExecutorError::OutcomeUnknown(
                    "expired dispatch-committed response is missing".to_string(),
                )
            })?;
        let snapshot = decode_response_record(&current).map_err(|error| {
            ActiveResponseExecutorError::OutcomeUnknown(format!(
                "expired dispatch-committed response is invalid: {error}"
            ))
        })?;
        if snapshot.plan != request.raw.response_plan {
            return Err(ActiveResponseExecutorError::OutcomeUnknown(
                "expired dispatch-committed response plan changed".to_string(),
            ));
        }
        if has_durable_execution_proof(&snapshot) {
            return self.map_active_evidence(request, dispatch, &current, true);
        }
        if snapshot.state != ResponseState::Applying
            || snapshot.plan.effects.as_slice().iter().any(|effect| {
                snapshot.effect_progress(&effect.effect_id) != Some(ResponseEffectProgress::Planned)
            })
        {
            return Err(ActiveResponseExecutorError::OutcomeUnknown(
                "expired dispatch-committed response is not untouched Applying".to_string(),
            ));
        }

        let state_machine = ResponseStateMachine::new(Arc::clone(&self.store));
        let work = self.recover_expired_work(request, dispatch, &current, now_unix_ms)?;
        let failed = match state_machine.fail_expired_dispatch_committed_resume_scheduled(
            &current,
            &work,
            current.generation,
            now_unix_ms,
        ) {
            Ok(failed) => failed,
            Err(transition_error) => {
                let latest = self
                    .store
                    .load_plan(&key)
                    .map_err(|load_error| {
                        ActiveResponseExecutorError::OutcomeUnknown(format!(
                            "expired dispatch-committed failure raced and reload failed: \
                             {transition_error}; {load_error}"
                        ))
                    })?
                    .ok_or_else(|| {
                        ActiveResponseExecutorError::OutcomeUnknown(format!(
                            "expired dispatch-committed failure raced and disappeared: \
                             {transition_error}"
                        ))
                    })?;
                let latest_snapshot = decode_response_record(&latest).map_err(|error| {
                    ActiveResponseExecutorError::OutcomeUnknown(format!(
                        "expired dispatch-committed raced response is invalid: {error}"
                    ))
                })?;
                if latest_snapshot.plan != request.raw.response_plan
                    || !has_durable_execution_proof(&latest_snapshot)
                {
                    return Err(ActiveResponseExecutorError::OutcomeUnknown(format!(
                        "expired dispatch-committed failure did not converge: {transition_error}"
                    )));
                }
                latest
            }
        };
        self.map_active_evidence(request, dispatch, &failed, recovered)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{require_error, require_success, Harness};
    use super::super::{
        decode_response_record, has_durable_execution_proof, ActiveResponseExecutionOutcome,
        ActiveResponseExecutorError, ResponseState,
    };
    use chio_security_types::{ResponseEffectProgress, ResponseMutationRecord};

    #[test]
    fn governed_dispatch_committed_resume_after_expiry_fails_without_late_effects() {
        let harness = Harness::new();
        let mut request = harness.expired_governed_request();
        request.dispatch_committed_resume = true;

        let evidence = require_success(
            harness.executor.execute_source(&request),
            "resume governed dispatch commitment after plan expiry",
        );
        assert_eq!(
            evidence.outcome(),
            ActiveResponseExecutionOutcome::FailedBeforeAnyEffect
        );
        assert!(evidence.effects().is_empty());
        assert_eq!(
            evidence.dispatch_authorization().body.authorized_at_unix_ms,
            request.authorized_at_unix_ms
        );
        assert_eq!(harness.effect_executions(), 0);
        let failed_snapshot = decode_response_record(evidence.response_record())
            .unwrap_or_else(|error| panic!("decode expired resume response: {error}"));
        assert_eq!(failed_snapshot.state, ResponseState::Failed);
        let failure = evidence
            .failure()
            .unwrap_or_else(|| panic!("expired resume failure evidence is missing"));
        assert!(failure.failed_effect().is_none());
        assert!(matches!(
            failed_snapshot.mutations.as_slice().last(),
            Some(ResponseMutationRecord::Failed(terminal))
                if failure.error_code() == &terminal.error_code
        ));

        let replay = require_success(
            harness.executor.execute_source(&request),
            "replay governed expired dispatch commitment",
        );
        assert_eq!(
            replay.outcome(),
            ActiveResponseExecutionOutcome::FailedBeforeAnyEffect
        );
        assert_eq!(replay.proof_evidence_id(), evidence.proof_evidence_id());
        assert_eq!(replay.failure(), evidence.failure());
        assert_eq!(harness.effect_executions(), 0);
    }

    #[test]
    fn automatic_commit_crash_retries_after_expiry_without_effects() {
        let harness = Harness::new();
        let request = harness.automatic_request();
        harness.fail_clock_after_next_success();

        assert!(matches!(
            require_error(harness.executor.execute_source(&request)),
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        let committed = harness.response_snapshot(&request);
        assert_eq!(committed.state, ResponseState::Applying);
        assert!(request
            .response_plan
            .effects
            .as_slice()
            .iter()
            .all(|effect| {
                committed.effect_progress(&effect.effect_id)
                    == Some(ResponseEffectProgress::Planned)
            }));
        assert!(!has_durable_execution_proof(&committed));
        assert_eq!(harness.effect_executions(), 0);

        harness.set_clock(request.response_plan.expires_at_unix_ms.saturating_add(1));
        let recovered = require_success(
            harness.executor.execute_source(&request),
            "recover automatic dispatch commitment after expiry",
        );
        assert_eq!(
            recovered.outcome(),
            ActiveResponseExecutionOutcome::FailedBeforeAnyEffect
        );
        assert!(recovered.recovered());
        assert!(recovered.effects().is_empty());
        let failure = recovered
            .failure()
            .unwrap_or_else(|| panic!("expired recovery failure evidence is missing"));
        assert!(failure.failed_effect().is_none());
        assert_eq!(harness.effect_executions(), 0);
        let failed_snapshot = harness.response_snapshot(&request);
        assert_eq!(failed_snapshot.state, ResponseState::Failed);
        assert!(matches!(
            failed_snapshot.mutations.as_slice().last(),
            Some(ResponseMutationRecord::Failed(terminal))
                if failure.error_code() == &terminal.error_code
        ));
    }

    #[test]
    fn resume_flag_and_stable_authorization_time_fail_closed_when_invalid() {
        let harness = Harness::new();
        let mut automatic = harness.automatic_request();
        automatic.dispatch_committed_resume = true;
        assert!(matches!(
            harness.executor.execute_source(&automatic),
            Err(ActiveResponseExecutorError::RejectedBeforeCommit(_))
        ));

        let mut before_plan = harness.governed_request();
        before_plan.authorized_at_unix_ms = before_plan
            .response_plan
            .created_at_unix_ms
            .saturating_sub(1);
        assert!(matches!(
            harness.executor.execute_source(&before_plan),
            Err(ActiveResponseExecutorError::RejectedBeforeCommit(_))
        ));

        let mut at_expiry = harness.governed_request();
        at_expiry.dispatch_committed_resume = true;
        at_expiry.authorized_at_unix_ms = at_expiry.response_plan.expires_at_unix_ms;
        assert!(matches!(
            harness.executor.execute_source(&at_expiry),
            Err(ActiveResponseExecutorError::RejectedBeforeCommit(_))
        ));
    }

    #[test]
    fn expired_resume_preserves_effect_requested_ambiguity_without_failed_proof() {
        let harness = Harness::new();
        let mut request = harness.governed_request();
        harness.set_effect_outcome_unknown();
        assert!(matches!(
            require_error(harness.executor.execute_source(&request)),
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));
        let before_expiry = harness.response_snapshot(&request);
        let effect_id = request.response_plan.effects.as_slice()[0]
            .effect_id
            .clone();
        assert_eq!(before_expiry.state, ResponseState::Applying);
        assert_eq!(
            before_expiry.effect_progress(&effect_id),
            Some(ResponseEffectProgress::Requested)
        );
        assert!(!has_durable_execution_proof(&before_expiry));
        assert_eq!(harness.effect_executions(), 0);

        request.dispatch_committed_resume = true;
        harness.set_clock(request.response_plan.expires_at_unix_ms.saturating_add(1));
        assert!(matches!(
            require_error(harness.executor.execute_source(&request)),
            ActiveResponseExecutorError::OutcomeUnknown(_)
        ));

        let after_expiry = harness.response_snapshot(&request);
        assert_eq!(after_expiry.state, ResponseState::Applying);
        assert_eq!(
            after_expiry.effect_progress(&effect_id),
            Some(ResponseEffectProgress::Requested)
        );
        assert!(after_expiry
            .mutations
            .as_slice()
            .iter()
            .all(|mutation| !matches!(mutation, ResponseMutationRecord::Failed(_))));
        assert!(!has_durable_execution_proof(&after_expiry));
        assert_eq!(harness.effect_executions(), 0);
    }
}
