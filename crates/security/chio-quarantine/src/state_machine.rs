// Adapted from Clawdstrike concepts; see docs/security/clawdstrike-active-defense-provenance.md.
//! Durable response transitions and scheduler-fenced writes.
//! Pure plan validation and evidence projection live in chio-response-model.

use chio_security_types::ports::{
    CreateOutcome, ErrorCode, RecordId, ResponseCasRequest, ResponsePlanRecord,
    ResponseScheduledMutationCasRequest, ResponseSchedulerStore, ResponseStore, ScheduledWork,
};
use chio_security_types::{ResponseEffectProgress, ResponseSnapshot, ResponseState};
use std::sync::Arc;

pub(crate) use chio_response_model::state::projection::encode_normalized_dispatch_response_record;
pub use chio_response_model::state::*;

const DISPATCH_COMMITTED_RESUME_EXPIRED_ERROR: &str =
    "active_response.dispatch_committed_resume_expired";
const DISPATCH_APPLY_LEASE_EXPIRED_BEFORE_EFFECT_ERROR: &str =
    "active_response.dispatch_apply_lease_expired_before_effect";

pub struct ResponseStateMachine<S: ResponseStore + ?Sized> {
    store: Arc<S>,
}

impl<S: ResponseStore + ?Sized> ResponseStateMachine<S> {
    #[must_use]
    pub const fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    /// Create fresh state only from a plan whose execution provenance is live.
    ///
    /// ```compile_fail
    /// use chio_quarantine::ResponseStateMachine;
    /// use chio_security_types::{ResponsePlan, ports::ResponseStore};
    /// fn bypass<S: ResponseStore>(machine: &ResponseStateMachine<S>, plan: ResponsePlan) {
    ///     let _ = machine.create(plan);
    /// }
    /// ```
    pub fn create(
        &self,
        admission: chio_security_types::FreshLiveAdmission,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        let snapshot = projection::initial_response_snapshot(admission.plan().clone())?;
        let record = encode_response_record(&snapshot)?;
        match self.store.create(&record)? {
            CreateOutcome::Created | CreateOutcome::Existing => Ok(record),
        }
    }

    pub fn transition(
        &self,
        current: &ResponsePlanRecord,
        request: &ResponseTransitionRequest,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        let (record, transition_id) = transition_candidate(current, request, None)?;
        self.commit(current, record, transition_id)
    }

    pub fn record_effect(
        &self,
        current: &ResponsePlanRecord,
        request: &EffectMutationRequest,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        self.record_effect_with_receipt(current, request, &EffectReceiptContext::state_only())
    }

    pub fn record_effect_with_receipt(
        &self,
        current: &ResponsePlanRecord,
        request: &EffectMutationRequest,
        receipt: &EffectReceiptContext,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        let (record, transition_id) = effect_candidate(current, request, receipt, None)?;
        self.commit(current, record, transition_id)
    }

    pub fn handle_due(
        &self,
        current: &ResponsePlanRecord,
        expected_generation: u64,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        self.handle_due_with(
            current,
            expected_generation,
            now_unix_ms,
            |record, request| self.transition(record, request),
        )
    }

    fn handle_due_with<F>(
        &self,
        current: &ResponsePlanRecord,
        expected_generation: u64,
        now_unix_ms: u64,
        mut transition: F,
    ) -> Result<ResponsePlanRecord, StateMachineError>
    where
        F: FnMut(
            &ResponsePlanRecord,
            &ResponseTransitionRequest,
        ) -> Result<ResponsePlanRecord, StateMachineError>,
    {
        let snapshot = decode_response_record(current)?;
        require_generation(&snapshot, expected_generation)?;
        let due = snapshot.due_at_unix_ms.ok_or(StateMachineError::NotDue)?;
        if now_unix_ms < due {
            return Err(StateMachineError::NotDue);
        }
        let occurred_at_unix_ms = due;
        match snapshot.state {
            ResponseState::Planned | ResponseState::AwaitingApproval => transition(
                current,
                &ResponseTransitionRequest {
                    expected_generation,
                    target_state: ResponseState::Expired,
                    occurred_at_unix_ms,
                    applying_lease_expires_at_unix_ms: None,
                    error_code: None,
                },
            ),
            ResponseState::Applying => {
                if snapshot.execution_dispatch.is_some() && !snapshot.any_effect_applied() {
                    if !all_response_effects_planned(&snapshot) {
                        return Err(StateMachineError::IncompleteApplication);
                    }
                    return transition(
                        current,
                        &ResponseTransitionRequest {
                            expected_generation,
                            target_state: ResponseState::Failed,
                            occurred_at_unix_ms,
                            applying_lease_expires_at_unix_ms: None,
                            error_code: Some(error_code(
                                DISPATCH_APPLY_LEASE_EXPIRED_BEFORE_EFFECT_ERROR,
                            )?),
                        },
                    );
                }
                let partial = transition(
                    current,
                    &ResponseTransitionRequest {
                        expected_generation,
                        target_state: ResponseState::ApplyPartial,
                        occurred_at_unix_ms,
                        applying_lease_expires_at_unix_ms: None,
                        error_code: Some(error_code("response.applying_lease_expired")?),
                    },
                )?;
                let partial_snapshot = decode_response_record(&partial)?;
                if partial_snapshot.state == ResponseState::RollingBack {
                    return Ok(partial);
                }
                transition(
                    &partial,
                    &ResponseTransitionRequest {
                        expected_generation: partial.generation,
                        target_state: ResponseState::RollingBack,
                        occurred_at_unix_ms,
                        applying_lease_expires_at_unix_ms: None,
                        error_code: None,
                    },
                )
            }
            ResponseState::Active => {
                let expiring = transition(
                    current,
                    &ResponseTransitionRequest {
                        expected_generation,
                        target_state: ResponseState::Expiring,
                        occurred_at_unix_ms,
                        applying_lease_expires_at_unix_ms: None,
                        error_code: None,
                    },
                )?;
                let expiring_snapshot = decode_response_record(&expiring)?;
                if expiring_snapshot.state == ResponseState::RollingBack {
                    return Ok(expiring);
                }
                transition(
                    &expiring,
                    &ResponseTransitionRequest {
                        expected_generation: expiring.generation,
                        target_state: ResponseState::RollingBack,
                        occurred_at_unix_ms,
                        applying_lease_expires_at_unix_ms: None,
                        error_code: None,
                    },
                )
            }
            ResponseState::ApplyPartial
            | ResponseState::Expiring
            | ResponseState::RollbackPartial => transition(
                current,
                &ResponseTransitionRequest {
                    expected_generation,
                    target_state: ResponseState::RollingBack,
                    occurred_at_unix_ms,
                    applying_lease_expires_at_unix_ms: None,
                    error_code: None,
                },
            ),
            ResponseState::RollingBack
            | ResponseState::Cancelled
            | ResponseState::Expired
            | ResponseState::Failed
            | ResponseState::Lifted => Err(StateMachineError::NotDue),
        }
    }

    /// Fail one exact dispatch that was durably admitted before plan expiry
    /// but resumed only after the plan became due. This path never acquires
    /// effect work and is valid only while no effect has started.
    pub fn fail_expired_dispatch_committed_resume(
        &self,
        current: &ResponsePlanRecord,
        expected_generation: u64,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        let snapshot = decode_response_record(current)?;
        require_generation(&snapshot, expected_generation)?;
        if snapshot.state != ResponseState::Applying
            || now_unix_ms < snapshot.plan.expires_at_unix_ms
            || !all_response_effects_planned(&snapshot)
        {
            return Err(StateMachineError::InvalidTransition);
        }
        self.transition(
            current,
            &ResponseTransitionRequest {
                expected_generation,
                target_state: ResponseState::Failed,
                occurred_at_unix_ms: snapshot.plan.expires_at_unix_ms,
                applying_lease_expires_at_unix_ms: None,
                error_code: Some(error_code(DISPATCH_COMMITTED_RESUME_EXPIRED_ERROR)?),
            },
        )
    }

    fn commit(
        &self,
        current: &ResponsePlanRecord,
        record: ResponsePlanRecord,
        transition_id: RecordId,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        let stored = self.store.compare_and_swap(&ResponseCasRequest {
            record,
            expected_generation: current.generation,
            transition_id,
        })?;
        decode_response_record(&stored)?;
        Ok(stored)
    }
}

impl<S: ResponseSchedulerStore + ?Sized> ResponseStateMachine<S> {
    pub fn handle_due_scheduled(
        &self,
        current: &ResponsePlanRecord,
        work: &ScheduledWork,
        expected_generation: u64,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        self.handle_due_with(
            current,
            expected_generation,
            now_unix_ms,
            |record, request| self.transition_scheduled(record, work, request),
        )
    }

    pub fn fail_expired_dispatch_committed_resume_scheduled(
        &self,
        current: &ResponsePlanRecord,
        work: &ScheduledWork,
        expected_generation: u64,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        let snapshot = decode_response_record(current)?;
        require_generation(&snapshot, expected_generation)?;
        if snapshot.state != ResponseState::Applying
            || now_unix_ms < snapshot.plan.expires_at_unix_ms
            || !all_response_effects_planned(&snapshot)
        {
            return Err(StateMachineError::InvalidTransition);
        }
        self.transition_scheduled(
            current,
            work,
            &ResponseTransitionRequest {
                expected_generation,
                target_state: ResponseState::Failed,
                occurred_at_unix_ms: snapshot.plan.expires_at_unix_ms,
                applying_lease_expires_at_unix_ms: None,
                error_code: Some(error_code(DISPATCH_COMMITTED_RESUME_EXPIRED_ERROR)?),
            },
        )
    }

    /// Commit one state transition under the exact scheduler work item that
    /// owns it. The owner and token are persisted in the mutation itself.
    pub fn transition_scheduled(
        &self,
        current: &ResponsePlanRecord,
        work: &ScheduledWork,
        request: &ResponseTransitionRequest,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        let (record, transition_id) = transition_candidate(
            current,
            request,
            Some((&work.lease_owner_id, work.fencing_token)),
        )?;
        self.commit_scheduled(current, work, record, transition_id)
    }

    /// Commit one effect mutation and its exact durable effect receipt binding
    /// under the same scheduler fence.
    pub fn record_effect_with_receipt_scheduled(
        &self,
        current: &ResponsePlanRecord,
        work: &ScheduledWork,
        request: &EffectMutationRequest,
        receipt: &EffectReceiptContext,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        if receipt.scheduler_lease_owner_id.as_ref() != Some(&work.lease_owner_id)
            || receipt.scheduler_fencing_token != work.fencing_token
        {
            return Err(StateMachineError::InvalidEffectLifecycle);
        }
        let (record, transition_id) = effect_candidate(current, request, receipt, Some(work))?;
        self.commit_scheduled(current, work, record, transition_id)
    }

    /// Extend an in-progress applying deadline under an exact live scheduler
    /// lease. Generic state transitions cannot renew this deadline because
    /// they do not carry the authoritative worker fence.
    pub fn renew_applying_lease(
        &self,
        current: &ResponsePlanRecord,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        let snapshot = decode_response_record(current)?;
        if snapshot.state != ResponseState::Applying
            || work.tenant_id != snapshot.plan.tenant_id
            || work.action_id != snapshot.plan.action_id
        {
            return Err(StateMachineError::InvalidTransition);
        }
        let current_expiry = snapshot
            .applying_lease_expires_at_unix_ms
            .ok_or(RecordDefect::MissingApplyingLease)?;
        let renewed_expiry = work
            .lease_expires_at_unix_ms
            .min(snapshot.plan.expires_at_unix_ms);
        if now_unix_ms >= current_expiry
            || renewed_expiry <= current_expiry
            || renewed_expiry <= now_unix_ms
        {
            return Err(StateMachineError::InvalidTiming);
        }
        let request = ResponseTransitionRequest {
            expected_generation: snapshot.generation,
            target_state: ResponseState::Applying,
            occurred_at_unix_ms: now_unix_ms,
            applying_lease_expires_at_unix_ms: Some(renewed_expiry),
            error_code: None,
        };
        self.transition_scheduled(current, work, &request)
    }

    fn commit_scheduled(
        &self,
        current: &ResponsePlanRecord,
        work: &ScheduledWork,
        candidate: ResponsePlanRecord,
        transition_id: RecordId,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        let stored = self.store.compare_and_swap_scheduled_mutation(
            &ResponseScheduledMutationCasRequest {
                work: work.clone(),
                current: current.clone(),
                candidate,
                transition_id,
            },
        )?;
        decode_response_record(&stored)?;
        Ok(stored)
    }
}

fn all_response_effects_planned(snapshot: &ResponseSnapshot) -> bool {
    snapshot.plan.effects.as_slice().iter().all(|effect| {
        snapshot.effect_progress(&effect.effect_id) == Some(ResponseEffectProgress::Planned)
    })
}

fn require_generation(
    snapshot: &ResponseSnapshot,
    expected_generation: u64,
) -> Result<(), StateMachineError> {
    if snapshot.generation == expected_generation {
        Ok(())
    } else {
        Err(StateMachineError::StaleGeneration)
    }
}

fn error_code(value: &str) -> Result<ErrorCode, StateMachineError> {
    Ok(ErrorCode::new(value).map_err(CanonicalFailure::Identifier)?)
}
