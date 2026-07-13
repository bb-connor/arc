use crate::state_machine::{
    decode_response_record, EffectMutation, EffectMutationRequest, ResponseStateMachine,
    ResponseTransitionRequest, StateMachineError,
};
use chio_core_types::{canonical_json_bytes, sha256};
use chio_security_types::ports::{
    ActionId, CanonicalBody, Digest32, EffectExecutionStatus, EffectId, EffectOperation,
    EffectPort, EffectRequest, EffectResult, EffectResultQuery, ErrorCode, PortError,
    ReceiptAppendRequest, RecordId, ResponseEffectCasRequest, ResponseEffectKey,
    ResponseEffectRecord, ResponsePlanRecord, ResponseSchedulerStore, ScheduledWork, SecurityAlert,
    SecurityAlertPort, SecurityReceiptSink, TenantId,
};
use chio_security_types::{
    PlannedResponseEffect, ResponseApprovalRequirement, ResponseEffectProgress, ResponsePlan,
    ResponseSnapshot, ResponseState,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

const EFFECT_JOURNAL_SCHEMA_VERSION: u8 = 1;
const EFFECT_COMMAND_ID_DOMAIN: &[u8] = b"chio.response-effect-command.v1\0";
const EFFECT_TRANSITION_ID_DOMAIN: &[u8] = b"chio.response-effect-transition.v1\0";
const RECEIPT_ID_DOMAIN: &[u8] = b"chio.response-execution-receipt.v1\0";
const ALERT_HASH_DOMAIN: &[u8] = b"chio.response-alert.v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseExecutionReceipt {
    pub schema_version: u8,
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub state: ResponseState,
    pub generation: u64,
    pub operator_page_required: bool,
    pub transition_id: RecordId,
    pub effect_id: Option<EffectId>,
    pub effect_generation: Option<u64>,
    pub effect_state: Option<RecordId>,
    pub effect_body_hash: Option<Digest32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectJournal {
    schema_version: u8,
    tenant_id: TenantId,
    action_id: ActionId,
    effect_id: EffectId,
    plan_hash: Digest32,
    canonical_contribution: CanonicalBody,
    contribution_hash: Digest32,
    observed_base_version_hash: Digest32,
    apply_idempotency_key: RecordId,
    phase: EffectJournalPhase,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "phase", deny_unknown_fields)]
enum EffectJournalPhase {
    ApplyRequested,
    Applied {
        resulting_version_hash: Digest32,
    },
    ApplyFailed {
        error_code: ErrorCode,
    },
    RollbackRequested {
        attempt: u32,
        idempotency_key: RecordId,
        installed_version_hash: Digest32,
    },
    Restored {
        attempt: u32,
        resulting_version_hash: Digest32,
    },
    RollbackFailed {
        attempt: u32,
        installed_version_hash: Digest32,
        error_code: ErrorCode,
    },
}

impl EffectJournalPhase {
    const fn state_name(&self) -> &'static str {
        match self {
            Self::ApplyRequested => "apply_requested",
            Self::Applied { .. } => "applied",
            Self::ApplyFailed { .. } => "apply_failed",
            Self::RollbackRequested { .. } => "rollback_requested",
            Self::Restored { .. } => "restored",
            Self::RollbackFailed { .. } => "rollback_failed",
        }
    }
}

pub struct ResponseExecutor<
    S: ResponseSchedulerStore + ?Sized,
    E: EffectPort + ?Sized,
    R: SecurityReceiptSink + ?Sized,
    A: SecurityAlertPort + ?Sized,
> {
    store: Arc<S>,
    effects: Arc<E>,
    receipts: Arc<R>,
    alerts: Arc<A>,
}

impl<
        S: ResponseSchedulerStore + ?Sized,
        E: EffectPort + ?Sized,
        R: SecurityReceiptSink + ?Sized,
        A: SecurityAlertPort + ?Sized,
    > ResponseExecutor<S, E, R, A>
{
    #[must_use]
    pub const fn new(store: Arc<S>, effects: Arc<E>, receipts: Arc<R>, alerts: Arc<A>) -> Self {
        Self {
            store,
            effects,
            receipts,
            alerts,
        }
    }

    pub fn execute(
        &self,
        current: &ResponsePlanRecord,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        let mut current = current.clone();
        loop {
            let snapshot = decode_response_record(&current)?;
            self.validate_work(&snapshot, work, now_unix_ms)?;
            if let Some(reconciled) =
                self.reconcile_durable_effect_result(&current, &snapshot, work, now_unix_ms)?
            {
                current = reconciled;
                continue;
            }
            if snapshot
                .due_at_unix_ms
                .is_some_and(|due| now_unix_ms >= due)
                && !matches!(
                    snapshot.state,
                    ResponseState::RollingBack
                        | ResponseState::Cancelled
                        | ResponseState::Expired
                        | ResponseState::Failed
                        | ResponseState::Lifted
                )
            {
                current =
                    self.state_machine()
                        .handle_due(&current, current.generation, now_unix_ms)?;
                self.append_receipt(&current, None)?;
                continue;
            }
            match snapshot.state {
                ResponseState::Planned => {
                    if snapshot.plan.approval_requirement != ResponseApprovalRequirement::Automatic
                    {
                        return Err(ExecutorError::ApprovalRequired);
                    }
                    let applying_lease = work
                        .lease_expires_at_unix_ms
                        .min(snapshot.plan.expires_at_unix_ms);
                    if applying_lease <= now_unix_ms {
                        return Err(ExecutorError::StaleLease);
                    }
                    current = self.state_machine().transition(
                        &current,
                        &ResponseTransitionRequest {
                            expected_generation: current.generation,
                            target_state: ResponseState::Applying,
                            occurred_at_unix_ms: now_unix_ms,
                            applying_lease_expires_at_unix_ms: Some(applying_lease),
                            error_code: None,
                        },
                    )?;
                    self.append_receipt(&current, None)?;
                }
                ResponseState::Applying => {
                    return self.drive_apply(current, work, now_unix_ms);
                }
                ResponseState::Active => return Ok(current),
                ResponseState::ApplyPartial
                | ResponseState::Expiring
                | ResponseState::RollbackPartial => {
                    if snapshot.state == ResponseState::RollbackPartial {
                        self.page_rollback_failure(&snapshot, &current)?;
                    }
                    current = self.state_machine().transition(
                        &current,
                        &ResponseTransitionRequest {
                            expected_generation: current.generation,
                            target_state: ResponseState::RollingBack,
                            occurred_at_unix_ms: now_unix_ms,
                            applying_lease_expires_at_unix_ms: None,
                            error_code: None,
                        },
                    )?;
                    self.append_receipt(&current, None)?;
                }
                ResponseState::RollingBack => {
                    return self.drive_rollback(current, work, now_unix_ms);
                }
                ResponseState::AwaitingApproval => {
                    return Err(ExecutorError::ApprovalRequired);
                }
                ResponseState::Cancelled
                | ResponseState::Expired
                | ResponseState::Failed
                | ResponseState::Lifted => return Ok(current),
            }
        }
    }

    fn reconcile_durable_effect_result(
        &self,
        current: &ResponsePlanRecord,
        snapshot: &ResponseSnapshot,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<Option<ResponsePlanRecord>, ExecutorError> {
        if snapshot.state == ResponseState::RollingBack {
            for effect in snapshot.plan.effects.as_slice() {
                if snapshot.effect_progress(&effect.effect_id)
                    != Some(ResponseEffectProgress::RollbackRequested)
                {
                    continue;
                }
                let effect_record = self.load_effect_record(&snapshot.plan, effect)?;
                let journal = self.decode_journal(&snapshot.plan, effect, &effect_record)?;
                if let EffectJournalPhase::Restored {
                    resulting_version_hash,
                    ..
                } = journal.phase
                {
                    let reconciled = self.state_machine().record_effect(
                        current,
                        &EffectMutationRequest {
                            expected_generation: current.generation,
                            effect_id: effect.effect_id.clone(),
                            occurred_at_unix_ms: now_unix_ms,
                            mutation: EffectMutation::RollbackRestored {
                                resulting_version_hash,
                            },
                        },
                    )?;
                    self.append_receipt(&reconciled, Some(&effect_record))?;
                    return Ok(Some(reconciled));
                }
            }
            return Ok(None);
        }
        if snapshot.state != ResponseState::Applying
            || snapshot.due_at_unix_ms.is_none_or(|due| now_unix_ms < due)
        {
            return Ok(None);
        }

        for effect in snapshot.plan.effects.as_slice() {
            let progress = snapshot
                .effect_progress(&effect.effect_id)
                .ok_or(ExecutorError::InvalidEffectJournal)?;
            if progress == ResponseEffectProgress::Planned {
                let Some(effect_record) = self
                    .store
                    .load_effect(&ResponseEffectKey {
                        tenant_id: snapshot.plan.tenant_id.clone(),
                        effect_id: effect.effect_id.clone(),
                    })
                    .map_err(ExecutorError::Store)?
                else {
                    continue;
                };
                let journal = self.decode_journal(&snapshot.plan, effect, &effect_record)?;
                if !matches!(
                    journal.phase,
                    EffectJournalPhase::ApplyRequested
                        | EffectJournalPhase::Applied { .. }
                        | EffectJournalPhase::ApplyFailed { .. }
                ) {
                    return Err(ExecutorError::InvalidEffectJournal);
                }
                let requested = self.state_machine().record_effect(
                    current,
                    &EffectMutationRequest {
                        expected_generation: current.generation,
                        effect_id: effect.effect_id.clone(),
                        occurred_at_unix_ms: now_unix_ms,
                        mutation: EffectMutation::Requested,
                    },
                )?;
                self.append_receipt(&requested, Some(&effect_record))?;
                return Ok(Some(requested));
            }
            if progress != ResponseEffectProgress::Requested {
                continue;
            }
            let effect_record = self.load_effect_record(&snapshot.plan, effect)?;
            let journal = self.decode_journal(&snapshot.plan, effect, &effect_record)?;
            match journal.phase.clone() {
                EffectJournalPhase::Applied {
                    resulting_version_hash,
                } => {
                    let reconciled = self.state_machine().record_effect(
                        current,
                        &EffectMutationRequest {
                            expected_generation: current.generation,
                            effect_id: effect.effect_id.clone(),
                            occurred_at_unix_ms: now_unix_ms,
                            mutation: EffectMutation::Applied {
                                resulting_version_hash,
                            },
                        },
                    )?;
                    self.append_receipt(&reconciled, Some(&effect_record))?;
                    return Ok(Some(reconciled));
                }
                EffectJournalPhase::ApplyFailed { error_code } => {
                    let reconciled = self.state_machine().record_effect(
                        current,
                        &EffectMutationRequest {
                            expected_generation: current.generation,
                            effect_id: effect.effect_id.clone(),
                            occurred_at_unix_ms: now_unix_ms,
                            mutation: EffectMutation::Failed { error_code },
                        },
                    )?;
                    self.append_receipt(&reconciled, Some(&effect_record))?;
                    return Ok(Some(reconciled));
                }
                EffectJournalPhase::ApplyRequested => {
                    let status = self.load_effect_execution_status(
                        &snapshot.plan.tenant_id,
                        &effect.effect_id,
                        EffectOperation::Apply,
                        &journal.apply_idempotency_key,
                        journal.observed_base_version_hash,
                        work,
                    )?;
                    let outcome = match status {
                        EffectExecutionStatus::Completed { result }
                            if valid_effect_result(&result, &effect.effect_id, true) =>
                        {
                            Ok(result.resulting_version_hash)
                        }
                        EffectExecutionStatus::Completed { .. } => {
                            return Err(ExecutorError::InvalidEffectResult);
                        }
                        EffectExecutionStatus::Failed { error_code } => Err(error_code),
                        EffectExecutionStatus::NotExecuted => {
                            Err(error_code("response.effect_not_executed")?)
                        }
                        EffectExecutionStatus::Unknown => {
                            return Err(ExecutorError::EffectOutcomeUnknown);
                        }
                    };
                    let (updated_journal, mutation) = match outcome {
                        Ok(resulting_version_hash) => (
                            EffectJournal {
                                phase: EffectJournalPhase::Applied {
                                    resulting_version_hash,
                                },
                                ..journal
                            },
                            EffectMutation::Applied {
                                resulting_version_hash,
                            },
                        ),
                        Err(error_code) => (
                            EffectJournal {
                                phase: EffectJournalPhase::ApplyFailed {
                                    error_code: error_code.clone(),
                                },
                                ..journal
                            },
                            EffectMutation::Failed { error_code },
                        ),
                    };
                    let updated =
                        self.update_effect_record(&effect_record, updated_journal, work)?;
                    self.append_receipt(current, Some(&updated))?;
                    let reconciled = self.state_machine().record_effect(
                        current,
                        &EffectMutationRequest {
                            expected_generation: current.generation,
                            effect_id: effect.effect_id.clone(),
                            occurred_at_unix_ms: now_unix_ms,
                            mutation,
                        },
                    )?;
                    self.append_receipt(&reconciled, Some(&updated))?;
                    return Ok(Some(reconciled));
                }
                _ => return Err(ExecutorError::InvalidEffectJournal),
            }
        }
        Ok(None)
    }

    fn drive_apply(
        &self,
        mut current: ResponsePlanRecord,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        loop {
            let snapshot = decode_response_record(&current)?;
            let next = snapshot
                .plan
                .effects
                .as_slice()
                .iter()
                .find(|effect| {
                    snapshot.effect_progress(&effect.effect_id)
                        != Some(ResponseEffectProgress::Applied)
                })
                .cloned();
            let Some(effect) = next else {
                let active = self.state_machine().transition(
                    &current,
                    &ResponseTransitionRequest {
                        expected_generation: current.generation,
                        target_state: ResponseState::Active,
                        occurred_at_unix_ms: now_unix_ms,
                        applying_lease_expires_at_unix_ms: None,
                        error_code: None,
                    },
                )?;
                self.append_receipt(&active, None)?;
                return Ok(active);
            };
            let progress = snapshot
                .effect_progress(&effect.effect_id)
                .ok_or(ExecutorError::InvalidEffectJournal)?;
            match progress {
                ResponseEffectProgress::Planned => {
                    let effect_record = self.ensure_apply_intent(&snapshot.plan, &effect, work)?;
                    self.append_receipt(&current, Some(&effect_record))?;
                    current = self.state_machine().record_effect(
                        &current,
                        &EffectMutationRequest {
                            expected_generation: current.generation,
                            effect_id: effect.effect_id.clone(),
                            occurred_at_unix_ms: now_unix_ms,
                            mutation: EffectMutation::Requested,
                        },
                    )?;
                    self.append_receipt(&current, Some(&effect_record))?;
                }
                ResponseEffectProgress::Requested => {
                    let effect_record = self.load_effect_record(&snapshot.plan, &effect)?;
                    let journal = self.decode_journal(&snapshot.plan, &effect, &effect_record)?;
                    match journal.phase.clone() {
                        EffectJournalPhase::ApplyRequested => {
                            self.append_receipt(&current, Some(&effect_record))?;
                            let request = EffectRequest {
                                tenant_id: snapshot.plan.tenant_id.clone(),
                                effect_id: effect.effect_id.clone(),
                                operation: EffectOperation::Apply,
                                idempotency_key: journal.apply_idempotency_key.clone(),
                                expected_version_hash: journal.observed_base_version_hash,
                                scheduler_fencing_token: work.fencing_token,
                                canonical_contribution: journal.canonical_contribution.clone(),
                                contribution_hash: journal.contribution_hash,
                            };
                            let status = self.load_effect_execution_status(
                                &snapshot.plan.tenant_id,
                                &effect.effect_id,
                                EffectOperation::Apply,
                                &journal.apply_idempotency_key,
                                journal.observed_base_version_hash,
                                work,
                            )?;
                            let result = match status {
                                EffectExecutionStatus::Completed { result } => result,
                                EffectExecutionStatus::Failed { error_code } => {
                                    return self.record_apply_failure(
                                        current,
                                        &effect,
                                        effect_record,
                                        journal,
                                        error_code,
                                        work,
                                        now_unix_ms,
                                    );
                                }
                                EffectExecutionStatus::NotExecuted => {
                                    self.store
                                        .validate_lease(work)
                                        .map_err(ExecutorError::Store)?;
                                    self.effects
                                        .execute(&request)
                                        .map_err(ExecutorError::EffectMutation)?
                                }
                                EffectExecutionStatus::Unknown => {
                                    return Err(ExecutorError::EffectOutcomeUnknown);
                                }
                            };
                            if valid_effect_result(&result, &effect.effect_id, true) {
                                let resulting_version_hash = result.resulting_version_hash;
                                let applied = self.update_effect_record(
                                    &effect_record,
                                    EffectJournal {
                                        phase: EffectJournalPhase::Applied {
                                            resulting_version_hash,
                                        },
                                        ..journal
                                    },
                                    work,
                                )?;
                                self.append_receipt(&current, Some(&applied))?;
                                current = self.state_machine().record_effect(
                                    &current,
                                    &EffectMutationRequest {
                                        expected_generation: current.generation,
                                        effect_id: effect.effect_id.clone(),
                                        occurred_at_unix_ms: now_unix_ms,
                                        mutation: EffectMutation::Applied {
                                            resulting_version_hash,
                                        },
                                    },
                                )?;
                                self.append_receipt(&current, Some(&applied))?;
                            } else {
                                return Err(ExecutorError::InvalidEffectResult);
                            }
                        }
                        EffectJournalPhase::Applied {
                            resulting_version_hash,
                        } => {
                            current = self.state_machine().record_effect(
                                &current,
                                &EffectMutationRequest {
                                    expected_generation: current.generation,
                                    effect_id: effect.effect_id.clone(),
                                    occurred_at_unix_ms: now_unix_ms,
                                    mutation: EffectMutation::Applied {
                                        resulting_version_hash,
                                    },
                                },
                            )?;
                            self.append_receipt(&current, Some(&effect_record))?;
                        }
                        EffectJournalPhase::ApplyFailed { error_code } => {
                            return self.finish_apply_failure(
                                current,
                                &effect,
                                &effect_record,
                                error_code,
                                work,
                                now_unix_ms,
                            );
                        }
                        _ => return Err(ExecutorError::InvalidEffectJournal),
                    }
                }
                ResponseEffectProgress::ApplyFailed => {
                    return Err(ExecutorError::InvalidEffectJournal);
                }
                ResponseEffectProgress::Applied => {}
                ResponseEffectProgress::RollbackRequested
                | ResponseEffectProgress::Restored
                | ResponseEffectProgress::RollbackFailed => {
                    return Err(ExecutorError::InvalidEffectJournal);
                }
            }
        }
    }

    fn record_apply_failure(
        &self,
        current: ResponsePlanRecord,
        effect: &PlannedResponseEffect,
        effect_record: ResponseEffectRecord,
        journal: EffectJournal,
        error_code: ErrorCode,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        let failed = self.update_effect_record(
            &effect_record,
            EffectJournal {
                phase: EffectJournalPhase::ApplyFailed {
                    error_code: error_code.clone(),
                },
                ..journal
            },
            work,
        )?;
        self.append_receipt(&current, Some(&failed))?;
        self.finish_apply_failure(current, effect, &failed, error_code, work, now_unix_ms)
    }

    fn finish_apply_failure(
        &self,
        current: ResponsePlanRecord,
        effect: &PlannedResponseEffect,
        effect_record: &ResponseEffectRecord,
        error_code: ErrorCode,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        let failed_effect = self.state_machine().record_effect(
            &current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: effect.effect_id.clone(),
                occurred_at_unix_ms: now_unix_ms,
                mutation: EffectMutation::Failed {
                    error_code: error_code.clone(),
                },
            },
        )?;
        self.append_receipt(&failed_effect, Some(effect_record))?;
        let failed_state = self.state_machine().transition(
            &failed_effect,
            &ResponseTransitionRequest {
                expected_generation: failed_effect.generation,
                target_state: ResponseState::Failed,
                occurred_at_unix_ms: now_unix_ms,
                applying_lease_expires_at_unix_ms: None,
                error_code: Some(error_code),
            },
        )?;
        self.append_receipt(&failed_state, None)?;
        if decode_response_record(&failed_state)?.state == ResponseState::ApplyPartial {
            let rolling_back = self.state_machine().transition(
                &failed_state,
                &ResponseTransitionRequest {
                    expected_generation: failed_state.generation,
                    target_state: ResponseState::RollingBack,
                    occurred_at_unix_ms: now_unix_ms,
                    applying_lease_expires_at_unix_ms: None,
                    error_code: None,
                },
            )?;
            self.append_receipt(&rolling_back, None)?;
            self.drive_rollback(rolling_back, work, now_unix_ms)
        } else {
            Ok(failed_state)
        }
    }

    fn drive_rollback(
        &self,
        mut current: ResponsePlanRecord,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        loop {
            let snapshot = decode_response_record(&current)?;
            let next = snapshot
                .plan
                .effects
                .as_slice()
                .iter()
                .rev()
                .find(|effect| {
                    effect.kind.is_reversible()
                        && effect_was_applied(&snapshot, &effect.effect_id)
                        && snapshot.effect_progress(&effect.effect_id)
                            != Some(ResponseEffectProgress::Restored)
                })
                .cloned();
            let Some(effect) = next else {
                let lifted = self.state_machine().transition(
                    &current,
                    &ResponseTransitionRequest {
                        expected_generation: current.generation,
                        target_state: ResponseState::Lifted,
                        occurred_at_unix_ms: now_unix_ms,
                        applying_lease_expires_at_unix_ms: None,
                        error_code: None,
                    },
                )?;
                self.append_receipt(&lifted, None)?;
                return Ok(lifted);
            };
            let progress = snapshot
                .effect_progress(&effect.effect_id)
                .ok_or(ExecutorError::InvalidEffectJournal)?;
            match progress {
                ResponseEffectProgress::Applied | ResponseEffectProgress::RollbackFailed => {
                    let effect_record = self.load_effect_record(&snapshot.plan, &effect)?;
                    let journal = self.decode_journal(&snapshot.plan, &effect, &effect_record)?;
                    let rollback_intent = match journal.phase.clone() {
                        EffectJournalPhase::RollbackRequested { .. } => effect_record,
                        EffectJournalPhase::Applied {
                            resulting_version_hash,
                        } => self.update_effect_record(
                            &effect_record,
                            EffectJournal {
                                phase: EffectJournalPhase::RollbackRequested {
                                    attempt: 0,
                                    idempotency_key: effect_command_id(
                                        &snapshot.plan,
                                        &effect.effect_id,
                                        EffectOperation::Remove,
                                        0,
                                    )?,
                                    installed_version_hash: resulting_version_hash,
                                },
                                ..journal
                            },
                            work,
                        )?,
                        EffectJournalPhase::RollbackFailed {
                            attempt,
                            installed_version_hash,
                            ..
                        } => {
                            let next_attempt = attempt
                                .checked_add(1)
                                .ok_or(ExecutorError::AttemptOverflow)?;
                            self.update_effect_record(
                                &effect_record,
                                EffectJournal {
                                    phase: EffectJournalPhase::RollbackRequested {
                                        attempt: next_attempt,
                                        idempotency_key: effect_command_id(
                                            &snapshot.plan,
                                            &effect.effect_id,
                                            EffectOperation::Remove,
                                            next_attempt,
                                        )?,
                                        installed_version_hash,
                                    },
                                    ..journal
                                },
                                work,
                            )?
                        }
                        _ => return Err(ExecutorError::InvalidEffectJournal),
                    };
                    self.append_receipt(&current, Some(&rollback_intent))?;
                    current = self.state_machine().record_effect(
                        &current,
                        &EffectMutationRequest {
                            expected_generation: current.generation,
                            effect_id: effect.effect_id.clone(),
                            occurred_at_unix_ms: now_unix_ms,
                            mutation: EffectMutation::RollbackRequested,
                        },
                    )?;
                    self.append_receipt(&current, Some(&rollback_intent))?;
                }
                ResponseEffectProgress::RollbackRequested => {
                    let effect_record = self.load_effect_record(&snapshot.plan, &effect)?;
                    let journal = self.decode_journal(&snapshot.plan, &effect, &effect_record)?;
                    match journal.phase.clone() {
                        EffectJournalPhase::RollbackRequested {
                            attempt,
                            idempotency_key,
                            installed_version_hash,
                        } => {
                            self.append_receipt(&current, Some(&effect_record))?;
                            let request = EffectRequest {
                                tenant_id: snapshot.plan.tenant_id.clone(),
                                effect_id: effect.effect_id.clone(),
                                operation: EffectOperation::Remove,
                                idempotency_key,
                                expected_version_hash: installed_version_hash,
                                scheduler_fencing_token: work.fencing_token,
                                canonical_contribution: journal.canonical_contribution.clone(),
                                contribution_hash: journal.contribution_hash,
                            };
                            let status = self.load_effect_execution_status(
                                &snapshot.plan.tenant_id,
                                &effect.effect_id,
                                EffectOperation::Remove,
                                &request.idempotency_key,
                                installed_version_hash,
                                work,
                            )?;
                            let result = match status {
                                EffectExecutionStatus::Completed { result } => Ok(result),
                                EffectExecutionStatus::Failed { error_code } => Err(error_code),
                                EffectExecutionStatus::NotExecuted => {
                                    self.store
                                        .validate_lease(work)
                                        .map_err(ExecutorError::Store)?;
                                    self.effects
                                        .execute(&request)
                                        .map_err(|error| error.code().clone())
                                }
                                EffectExecutionStatus::Unknown => {
                                    return Err(ExecutorError::EffectOutcomeUnknown);
                                }
                            };
                            match result {
                                Ok(result)
                                    if valid_effect_result(&result, &effect.effect_id, false) =>
                                {
                                    let resulting_version_hash = result.resulting_version_hash;
                                    let restored = self.update_effect_record(
                                        &effect_record,
                                        EffectJournal {
                                            phase: EffectJournalPhase::Restored {
                                                attempt,
                                                resulting_version_hash,
                                            },
                                            ..journal
                                        },
                                        work,
                                    )?;
                                    self.append_receipt(&current, Some(&restored))?;
                                    current = self.state_machine().record_effect(
                                        &current,
                                        &EffectMutationRequest {
                                            expected_generation: current.generation,
                                            effect_id: effect.effect_id.clone(),
                                            occurred_at_unix_ms: now_unix_ms,
                                            mutation: EffectMutation::RollbackRestored {
                                                resulting_version_hash,
                                            },
                                        },
                                    )?;
                                    self.append_receipt(&current, Some(&restored))?;
                                }
                                Ok(_) => {
                                    let error_code = error_code("response.effect_result_invalid")?;
                                    return self.record_rollback_failure(
                                        current,
                                        &effect,
                                        effect_record,
                                        journal,
                                        attempt,
                                        installed_version_hash,
                                        error_code,
                                        work,
                                        now_unix_ms,
                                    );
                                }
                                Err(error_code) => {
                                    return self.record_rollback_failure(
                                        current,
                                        &effect,
                                        effect_record,
                                        journal,
                                        attempt,
                                        installed_version_hash,
                                        error_code,
                                        work,
                                        now_unix_ms,
                                    );
                                }
                            }
                        }
                        EffectJournalPhase::Restored {
                            resulting_version_hash,
                            ..
                        } => {
                            current = self.state_machine().record_effect(
                                &current,
                                &EffectMutationRequest {
                                    expected_generation: current.generation,
                                    effect_id: effect.effect_id.clone(),
                                    occurred_at_unix_ms: now_unix_ms,
                                    mutation: EffectMutation::RollbackRestored {
                                        resulting_version_hash,
                                    },
                                },
                            )?;
                            self.append_receipt(&current, Some(&effect_record))?;
                        }
                        EffectJournalPhase::RollbackFailed { error_code, .. } => {
                            return self.finish_rollback_failure(
                                current,
                                &effect,
                                &effect_record,
                                error_code,
                                now_unix_ms,
                            );
                        }
                        _ => return Err(ExecutorError::InvalidEffectJournal),
                    }
                }
                ResponseEffectProgress::Restored => {}
                ResponseEffectProgress::Planned
                | ResponseEffectProgress::Requested
                | ResponseEffectProgress::ApplyFailed => {
                    return Err(ExecutorError::InvalidEffectJournal);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_rollback_failure(
        &self,
        current: ResponsePlanRecord,
        effect: &PlannedResponseEffect,
        effect_record: ResponseEffectRecord,
        journal: EffectJournal,
        attempt: u32,
        installed_version_hash: Digest32,
        error_code: ErrorCode,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        let failed = self.update_effect_record(
            &effect_record,
            EffectJournal {
                phase: EffectJournalPhase::RollbackFailed {
                    attempt,
                    installed_version_hash,
                    error_code: error_code.clone(),
                },
                ..journal
            },
            work,
        )?;
        self.append_receipt(&current, Some(&failed))?;
        self.finish_rollback_failure(current, effect, &failed, error_code, now_unix_ms)
    }

    fn finish_rollback_failure(
        &self,
        current: ResponsePlanRecord,
        effect: &PlannedResponseEffect,
        effect_record: &ResponseEffectRecord,
        error_code: ErrorCode,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        let failed_effect = self.state_machine().record_effect(
            &current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: effect.effect_id.clone(),
                occurred_at_unix_ms: now_unix_ms,
                mutation: EffectMutation::RollbackFailed {
                    error_code: error_code.clone(),
                },
            },
        )?;
        self.append_receipt(&failed_effect, Some(effect_record))?;
        let partial = self.state_machine().transition(
            &failed_effect,
            &ResponseTransitionRequest {
                expected_generation: failed_effect.generation,
                target_state: ResponseState::RollbackPartial,
                occurred_at_unix_ms: now_unix_ms,
                applying_lease_expires_at_unix_ms: None,
                error_code: Some(error_code),
            },
        )?;
        self.append_receipt(&partial, None)?;
        let snapshot = decode_response_record(&partial)?;
        self.page_rollback_failure(&snapshot, &partial)?;
        Ok(partial)
    }

    fn ensure_apply_intent(
        &self,
        plan: &ResponsePlan,
        effect: &PlannedResponseEffect,
        work: &ScheduledWork,
    ) -> Result<ResponseEffectRecord, ExecutorError> {
        let key = ResponseEffectKey {
            tenant_id: plan.tenant_id.clone(),
            effect_id: effect.effect_id.clone(),
        };
        if let Some(existing) = self.store.load_effect(&key).map_err(ExecutorError::Store)? {
            let journal = self.decode_journal(plan, effect, &existing)?;
            if !matches!(journal.phase, EffectJournalPhase::ApplyRequested) {
                return Err(ExecutorError::InvalidEffectJournal);
            }
            return Ok(existing);
        }
        let journal = EffectJournal {
            schema_version: EFFECT_JOURNAL_SCHEMA_VERSION,
            tenant_id: plan.tenant_id.clone(),
            action_id: plan.action_id.clone(),
            effect_id: effect.effect_id.clone(),
            plan_hash: plan.plan_hash,
            canonical_contribution: effect.canonical_contribution.clone(),
            contribution_hash: effect.contribution_hash,
            observed_base_version_hash: effect.observed_base_version_hash,
            apply_idempotency_key: effect_command_id(
                plan,
                &effect.effect_id,
                EffectOperation::Apply,
                0,
            )?,
            phase: EffectJournalPhase::ApplyRequested,
        };
        let record = encode_effect_record(&journal, 0, work.fencing_token, None)?;
        match self
            .store
            .persist_effect(&record)
            .map_err(ExecutorError::Store)?
        {
            chio_security_types::ports::CreateOutcome::Created
            | chio_security_types::ports::CreateOutcome::Existing => Ok(record),
        }
    }

    fn load_effect_record(
        &self,
        plan: &ResponsePlan,
        effect: &PlannedResponseEffect,
    ) -> Result<ResponseEffectRecord, ExecutorError> {
        self.store
            .load_effect(&ResponseEffectKey {
                tenant_id: plan.tenant_id.clone(),
                effect_id: effect.effect_id.clone(),
            })
            .map_err(ExecutorError::Store)?
            .ok_or(ExecutorError::InvalidEffectJournal)
    }

    fn decode_journal(
        &self,
        plan: &ResponsePlan,
        effect: &PlannedResponseEffect,
        record: &ResponseEffectRecord,
    ) -> Result<EffectJournal, ExecutorError> {
        let journal: EffectJournal = serde_json::from_slice(record.canonical_body.as_bytes())
            .map_err(|_| ExecutorError::InvalidEffectJournal)?;
        let canonical =
            canonical_json_bytes(&journal).map_err(|_| ExecutorError::InvalidEffectJournal)?;
        if canonical.as_slice() != record.canonical_body.as_bytes()
            || Digest32::new(*sha256(&canonical).as_bytes()) != record.body_hash
            || record.tenant_id != plan.tenant_id
            || record.action_id != plan.action_id
            || record.effect_id != effect.effect_id
            || record.state.as_str() != journal.phase.state_name()
            || journal.schema_version != EFFECT_JOURNAL_SCHEMA_VERSION
            || journal.tenant_id != plan.tenant_id
            || journal.action_id != plan.action_id
            || journal.effect_id != effect.effect_id
            || journal.plan_hash != plan.plan_hash
            || journal.canonical_contribution != effect.canonical_contribution
            || journal.contribution_hash != effect.contribution_hash
            || journal.observed_base_version_hash != effect.observed_base_version_hash
        {
            return Err(ExecutorError::InvalidEffectJournal);
        }
        Ok(journal)
    }

    fn update_effect_record(
        &self,
        current: &ResponseEffectRecord,
        journal: EffectJournal,
        work: &ScheduledWork,
    ) -> Result<ResponseEffectRecord, ExecutorError> {
        let generation = current
            .generation
            .checked_add(1)
            .ok_or(ExecutorError::GenerationOverflow)?;
        let record = encode_effect_record(
            &journal,
            generation,
            work.fencing_token,
            current.encrypted_rollback_ref.clone(),
        )?;
        let transition_id = effect_transition_id(current.generation, &record)?;
        self.store
            .compare_and_swap_effect(&ResponseEffectCasRequest {
                record,
                expected_generation: current.generation,
                transition_id,
            })
            .map_err(ExecutorError::Store)
    }

    fn append_receipt(
        &self,
        plan_record: &ResponsePlanRecord,
        effect_record: Option<&ResponseEffectRecord>,
    ) -> Result<(), ExecutorError> {
        let snapshot = decode_response_record(plan_record)?;
        let transition_id = snapshot
            .mutations
            .as_slice()
            .last()
            .ok_or(ExecutorError::InvalidEffectJournal)?
            .transition_id()
            .clone();
        let receipt = ResponseExecutionReceipt {
            schema_version: 1,
            tenant_id: snapshot.plan.tenant_id.clone(),
            action_id: snapshot.plan.action_id.clone(),
            plan_hash: snapshot.plan.plan_hash,
            state: snapshot.state,
            generation: snapshot.generation,
            operator_page_required: snapshot.operator_page_required,
            transition_id,
            effect_id: effect_record.map(|record| record.effect_id.clone()),
            effect_generation: effect_record.map(|record| record.generation),
            effect_state: effect_record.map(|record| record.state.clone()),
            effect_body_hash: effect_record.map(|record| record.body_hash),
        };
        let canonical = canonical_json_bytes(&receipt).map_err(|_| ExecutorError::Canonical)?;
        let body_hash = Digest32::new(*sha256(&canonical).as_bytes());
        let canonical_body = CanonicalBody::new(canonical).map_err(|_| ExecutorError::Canonical)?;
        let receipt_transition_id = receipt_id(&receipt)?;
        self.receipts
            .sign_and_append(&ReceiptAppendRequest {
                tenant_id: receipt.tenant_id.clone(),
                evidence_type: record_id("response_execution")?,
                canonical_body,
                body_hash,
                transition_id: receipt_transition_id,
            })
            .map_err(ExecutorError::Receipt)?;
        Ok(())
    }

    fn page_rollback_failure(
        &self,
        snapshot: &ResponseSnapshot,
        record: &ResponsePlanRecord,
    ) -> Result<(), ExecutorError> {
        self.alerts
            .page(&SecurityAlert {
                tenant_id: snapshot.plan.tenant_id.clone(),
                alert_type: record_id("response_rollback_partial")?,
                finding_id_hash: domain_hash(ALERT_HASH_DOMAIN, &snapshot.plan.trigger_finding_id)?,
                action_id_hash: Some(domain_hash(ALERT_HASH_DOMAIN, &snapshot.plan.action_id)?),
                evidence_hash: record.body_hash,
            })
            .map_err(ExecutorError::Alert)
    }

    fn load_effect_execution_status(
        &self,
        tenant_id: &TenantId,
        effect_id: &EffectId,
        operation: EffectOperation,
        idempotency_key: &RecordId,
        expected_version_hash: Digest32,
        work: &ScheduledWork,
    ) -> Result<EffectExecutionStatus, ExecutorError> {
        let query = EffectResultQuery {
            tenant_id: tenant_id.clone(),
            effect_id: effect_id.clone(),
            operation,
            idempotency_key: idempotency_key.clone(),
            expected_version_hash,
            scheduler_fencing_token: work.fencing_token,
        };
        self.store
            .validate_lease(work)
            .map_err(ExecutorError::Store)?;
        self.effects
            .load_result(&query)
            .map_err(ExecutorError::EffectQuery)
    }

    fn validate_work(
        &self,
        snapshot: &ResponseSnapshot,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<(), ExecutorError> {
        if work.tenant_id != snapshot.plan.tenant_id || work.action_id != snapshot.plan.action_id {
            return Err(ExecutorError::WorkMismatch);
        }
        if work.lease_expires_at_unix_ms <= now_unix_ms {
            return Err(ExecutorError::StaleLease);
        }
        Ok(())
    }

    fn state_machine(&self) -> ResponseStateMachine<S> {
        ResponseStateMachine::new(Arc::clone(&self.store))
    }
}

fn encode_effect_record(
    journal: &EffectJournal,
    generation: u64,
    scheduler_fencing_token: u64,
    encrypted_rollback_ref: Option<RecordId>,
) -> Result<ResponseEffectRecord, ExecutorError> {
    let canonical = canonical_json_bytes(journal).map_err(|_| ExecutorError::Canonical)?;
    let body_hash = Digest32::new(*sha256(&canonical).as_bytes());
    let canonical_body = CanonicalBody::new(canonical).map_err(|_| ExecutorError::Canonical)?;
    Ok(ResponseEffectRecord {
        tenant_id: journal.tenant_id.clone(),
        action_id: journal.action_id.clone(),
        effect_id: journal.effect_id.clone(),
        generation,
        scheduler_fencing_token,
        state: record_id(journal.phase.state_name())?,
        canonical_body,
        body_hash,
        encrypted_rollback_ref,
    })
}

#[derive(Serialize)]
struct EffectCommandCommitment<'a> {
    tenant_id: &'a str,
    action_id: &'a str,
    plan_hash: Digest32,
    effect_id: &'a str,
    operation: EffectOperation,
    attempt: u32,
}

fn effect_command_id(
    plan: &ResponsePlan,
    effect_id: &EffectId,
    operation: EffectOperation,
    attempt: u32,
) -> Result<RecordId, ExecutorError> {
    domain_record_id(
        "response_effect_command",
        EFFECT_COMMAND_ID_DOMAIN,
        &EffectCommandCommitment {
            tenant_id: plan.tenant_id.as_str(),
            action_id: plan.action_id.as_str(),
            plan_hash: plan.plan_hash,
            effect_id: effect_id.as_str(),
            operation,
            attempt,
        },
    )
}

#[derive(Serialize)]
struct EffectTransitionCommitment<'a> {
    tenant_id: &'a str,
    action_id: &'a str,
    effect_id: &'a str,
    expected_generation: u64,
    generation: u64,
    scheduler_fencing_token: u64,
    state: &'a str,
    body_hash: Digest32,
}

fn effect_transition_id(
    expected_generation: u64,
    record: &ResponseEffectRecord,
) -> Result<RecordId, ExecutorError> {
    domain_record_id(
        "response_effect_transition",
        EFFECT_TRANSITION_ID_DOMAIN,
        &EffectTransitionCommitment {
            tenant_id: record.tenant_id.as_str(),
            action_id: record.action_id.as_str(),
            effect_id: record.effect_id.as_str(),
            expected_generation,
            generation: record.generation,
            scheduler_fencing_token: record.scheduler_fencing_token,
            state: record.state.as_str(),
            body_hash: record.body_hash,
        },
    )
}

fn receipt_id(receipt: &ResponseExecutionReceipt) -> Result<RecordId, ExecutorError> {
    domain_record_id("response_execution_receipt", RECEIPT_ID_DOMAIN, receipt)
}

fn domain_record_id<T: Serialize>(
    prefix: &str,
    domain: &[u8],
    value: &T,
) -> Result<RecordId, ExecutorError> {
    let digest = domain_hash(domain, value)?;
    RecordId::new(format!("{prefix}_{}", hex_bytes(digest.as_bytes())))
        .map_err(|_| ExecutorError::Canonical)
}

fn domain_hash<T: Serialize>(domain: &[u8], value: &T) -> Result<Digest32, ExecutorError> {
    let canonical = canonical_json_bytes(value).map_err(|_| ExecutorError::Canonical)?;
    let mut input = Vec::with_capacity(domain.len() + canonical.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&canonical);
    Ok(Digest32::new(*sha256(&input).as_bytes()))
}

fn record_id(value: &str) -> Result<RecordId, ExecutorError> {
    RecordId::new(value).map_err(|_| ExecutorError::Canonical)
}

fn error_code(value: &str) -> Result<ErrorCode, ExecutorError> {
    ErrorCode::new(value).map_err(|_| ExecutorError::Canonical)
}

fn valid_effect_result(result: &EffectResult, effect_id: &EffectId, applied: bool) -> bool {
    result.effect_id == *effect_id && result.applied == applied
}

fn effect_was_applied(snapshot: &ResponseSnapshot, effect_id: &EffectId) -> bool {
    snapshot.mutations.as_slice().iter().any(|mutation| {
        matches!(
            mutation,
            chio_security_types::ResponseMutationRecord::EffectApplied(record)
                if &record.effect_id == effect_id
        )
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("response execution requires a completed approval")]
    ApprovalRequired,
    #[error("response execution retry attempt overflowed")]
    AttemptOverflow,
    #[error("response execution alert failed: {0}")]
    Alert(PortError),
    #[error("response execution canonicalization failed")]
    Canonical,
    #[error("response effect outcome is unknown")]
    EffectOutcomeUnknown,
    #[error("response effect mutation returned without an authoritative result: {0}")]
    EffectMutation(PortError),
    #[error("response effect result query failed: {0}")]
    EffectQuery(PortError),
    #[error("response effect result is invalid")]
    InvalidEffectResult,
    #[error("response effect generation overflowed")]
    GenerationOverflow,
    #[error("response effect journal is invalid")]
    InvalidEffectJournal,
    #[error("response execution receipt failed: {0}")]
    Receipt(PortError),
    #[error("response execution lease is stale")]
    StaleLease,
    #[error("response execution store failed: {0}")]
    Store(PortError),
    #[error("response state machine failed: {0}")]
    StateMachine(#[from] StateMachineError),
    #[error("scheduled work does not match the response plan")]
    WorkMismatch,
}
