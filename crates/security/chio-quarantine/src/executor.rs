// Adapted from Clawdstrike concepts; see docs/security/clawdstrike-active-defense-provenance.md.
use crate::executor_proof::{
    durable_execution_proof_snapshot,
    validate_dispatch_authorization as validate_dispatch_authorization_proof,
};
use crate::native_receipts::{
    latest_response_receipt, receipt_append_request, response_receipt_for_mutation,
};
use crate::state_machine::{
    decode_response_record, EffectMutation, EffectMutationRequest, EffectReceiptContext,
    ResponseStateMachine, ResponseTransitionRequest, StateMachineError,
};
use chio_core_types::{canonical_json_bytes, sha256};
use chio_security_types::ports::{
    ActionId, AlertDeliveryQuery, CanonicalBody, Digest32, EffectExecutionStatus, EffectId,
    EffectOperation, EffectPort, EffectRequest, EffectResult, EffectResultQuery, ErrorCode,
    LineageFenceMaintenanceOutcome, LineageFenceMaintenanceRequest, OpaqueReceiptRef, PortError,
    ReceiptAppendRequest, RecordId, ResponseDispatchAuthorization, ResponseEffectCasRequest,
    ResponseEffectKey, ResponseEffectRecord, ResponsePlanKey, ResponsePlanRecord,
    ResponseReceiptCursor, ResponseReceiptCursorCasRequest, ResponseSchedulerStore, ScheduledWork,
    SecurityAlert, SecurityAlertPort, SecurityReceiptSink, TenantId,
};
use chio_security_types::{
    PlannedResponseEffect, ResponseApprovalRequirement, ResponseEffectKind, ResponseEffectProgress,
    ResponseMutationRecord, ResponsePlan, ResponseSnapshot, ResponseState,
    ResponseTerminalFailureEvidence,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

const EFFECT_JOURNAL_SCHEMA_VERSION: u8 = 2;
const EFFECT_COMMAND_ID_DOMAIN: &[u8] = b"chio.response-effect-command.v1\0";
const EFFECT_TRANSITION_ID_DOMAIN: &[u8] = b"chio.response-effect-transition.v1\0";
const RECEIPT_CURSOR_ID_DOMAIN: &[u8] = b"chio.response-receipt-cursor.v1\0";
const ALERT_HASH_DOMAIN: &[u8] = b"chio.response-alert.v1\0";
const ALERT_EVENT_ID_DOMAIN: &[u8] = b"chio.response-alert-event.v1\0";
const ALERT_IDEMPOTENCY_KEY_DOMAIN: &[u8] = b"chio.response-alert-command.v1\0";

/// Exact durable transition evidence for one successfully applied effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedResponseEffectEvidence {
    pub effect_id: EffectId,
    pub transition_id: RecordId,
    pub generation: u64,
    pub resulting_version_hash: Digest32,
}

/// Proven durable terminal result for one committed active-response dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableActiveResponseOutcome {
    Activated,
    FailedBeforeAnyEffect,
    RolledBackAfterPartial,
}

/// Exact durable evidence for an activated, failed, or fully rolled-back response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveResponseRecordEvidence {
    pub outcome: DurableActiveResponseOutcome,
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub response_generation: u64,
    pub response_transition_id: RecordId,
    pub response_body_hash: Digest32,
    pub response_record: ResponsePlanRecord,
    pub completion_evidence_id: OpaqueReceiptRef,
    pub completion_body_hash: Digest32,
    pub completion_receipt_request: ReceiptAppendRequest,
    pub effects: Vec<AppliedResponseEffectEvidence>,
    pub failure: Option<ResponseTerminalFailureEvidence>,
}

/// Validate the exact durable response record and dispatch authorization pair.
pub fn validate_response_dispatch_authorization(
    current: &ResponsePlanRecord,
    dispatch_authorization: &ResponseDispatchAuthorization,
) -> Result<(), ExecutorError> {
    let snapshot = decode_response_record(current)?;
    validate_dispatch_authorization_proof(&snapshot, dispatch_authorization)
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
    occurred_at_unix_ms: u64,
    receipt_prior_id: Option<OpaqueReceiptRef>,
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

    pub(crate) fn maintain_effect_lineage_fences(
        &self,
        request: &LineageFenceMaintenanceRequest,
    ) -> Result<LineageFenceMaintenanceOutcome, PortError> {
        self.effects.maintain_lineage_fences(request)
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
            self.reconcile_receipts(&current)?;
            if let Some(reconciled) =
                self.reconcile_durable_effect_result(&current, &snapshot, work, now_unix_ms)?
            {
                let reconciled_snapshot = decode_response_record(&reconciled)?;
                let installed_freeze =
                    freeze_issuance_became_applied(&snapshot, &reconciled_snapshot);
                current = reconciled;
                if installed_freeze {
                    return Ok(current);
                }
                continue;
            }
            if snapshot.state == ResponseState::Applying
                && !snapshot.plan.effects.as_slice().iter().any(|effect| {
                    snapshot.effect_progress(&effect.effect_id)
                        == Some(ResponseEffectProgress::ApplyFailed)
                })
                && snapshot
                    .applying_lease_expires_at_unix_ms
                    .is_some_and(|current_expiry| {
                        now_unix_ms < current_expiry
                            && work
                                .lease_expires_at_unix_ms
                                .min(snapshot.plan.expires_at_unix_ms)
                                > current_expiry
                    })
            {
                current = self
                    .state_machine()
                    .renew_applying_lease(&current, work, now_unix_ms)?;
                self.append_receipt(&current, None)?;
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
                current = self.state_machine().handle_due_scheduled(
                    &current,
                    work,
                    current.generation,
                    now_unix_ms,
                )?;
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
                    current = self.state_machine().transition_scheduled(
                        &current,
                        work,
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
                        if rollback_retry_budget_exhausted(&snapshot) {
                            return Ok(current);
                        }
                    }
                    current = self.state_machine().transition_scheduled(
                        &current,
                        work,
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

    /// Reconstruct exact evidence from the durable active response record.
    ///
    /// This is intentionally a read-after-write validation. It does not trust
    /// an effect-port return value or an in-process transition. Every effect is
    /// loaded again, validated against the approved plan, and bound to the CAS
    /// transition that persisted its successful result.
    pub fn active_execution_evidence(
        &self,
        current: &ResponsePlanRecord,
    ) -> Result<ActiveResponseRecordEvidence, ExecutorError> {
        self.execution_evidence(current, None)
    }

    /// Reconstruct a terminal proof bound to the exact durable dispatch
    /// authorization.
    pub fn dispatch_bound_execution_evidence(
        &self,
        current: &ResponsePlanRecord,
        dispatch_authorization: &ResponseDispatchAuthorization,
    ) -> Result<ActiveResponseRecordEvidence, ExecutorError> {
        self.execution_evidence(current, Some(dispatch_authorization))
    }

    /// Validate the exact durable dispatch commitment without requiring a
    /// terminal response outcome.
    pub fn validate_dispatch_authorization(
        &self,
        current: &ResponsePlanRecord,
        dispatch_authorization: &ResponseDispatchAuthorization,
    ) -> Result<(), ExecutorError> {
        validate_response_dispatch_authorization(current, dispatch_authorization)
    }

    fn execution_evidence(
        &self,
        current: &ResponsePlanRecord,
        dispatch_authorization: Option<&ResponseDispatchAuthorization>,
    ) -> Result<ActiveResponseRecordEvidence, ExecutorError> {
        let current_snapshot = decode_response_record(current)?;
        self.reconcile_receipts(current)?;
        let (snapshot, response_record, outcome) =
            durable_execution_proof_snapshot(&current_snapshot)?;
        dispatch_authorization
            .map(|authorization| {
                validate_dispatch_authorization_proof(&current_snapshot, authorization)
            })
            .transpose()?;
        let completion =
            latest_response_receipt(&snapshot).map_err(|_| ExecutorError::Canonical)?;
        match &completion {
            chio_core_types::receipt::security::ActiveDefenseReceiptBody::ResponseCompletion(
                _,
            ) => {}
            chio_core_types::receipt::security::ActiveDefenseReceiptBody::LiftRollbackCompletion(
                _,
            ) => {}
            _ => return Err(ExecutorError::InvalidActiveEvidence),
        }
        let completion_receipt_request =
            receipt_append_request(&completion).map_err(|_| ExecutorError::Canonical)?;
        let completion_evidence_id = completion_receipt_request.evidence_id.clone();
        let completion_body_hash = completion_receipt_request.body_hash;
        let failure = match outcome {
            DurableActiveResponseOutcome::FailedBeforeAnyEffect => Some(
                snapshot
                    .terminal_failure_evidence()
                    .ok_or(ExecutorError::InvalidActiveEvidence)?,
            ),
            DurableActiveResponseOutcome::Activated
            | DurableActiveResponseOutcome::RolledBackAfterPartial => None,
        };
        let response_transition_id = snapshot
            .mutations
            .as_slice()
            .last()
            .map(|mutation| mutation.transition_id().clone())
            .ok_or(ExecutorError::InvalidActiveEvidence)?;

        let mut effects = Vec::with_capacity(snapshot.plan.effects.len());
        for effect in snapshot.plan.effects.as_slice() {
            let mut applied =
                snapshot
                    .mutations
                    .as_slice()
                    .iter()
                    .filter_map(|mutation| match mutation {
                        ResponseMutationRecord::EffectApplied(record)
                            if record.effect_id == effect.effect_id =>
                        {
                            Some(record)
                        }
                        _ => None,
                    });
            let Some(applied_record) = applied.next() else {
                continue;
            };
            if applied.next().is_some() {
                return Err(ExecutorError::InvalidActiveEvidence);
            }
            let generation = applied_record
                .effect_generation
                .checked_sub(1)
                .ok_or(ExecutorError::InvalidActiveEvidence)?;
            if generation == 0 {
                return Err(ExecutorError::InvalidActiveEvidence);
            }
            let transition_id = applied_record
                .effect_transition_id
                .clone()
                .ok_or(ExecutorError::InvalidActiveEvidence)?;
            effects.push(AppliedResponseEffectEvidence {
                effect_id: effect.effect_id.clone(),
                transition_id,
                generation,
                resulting_version_hash: applied_record.resulting_version_hash,
            });
        }

        Ok(ActiveResponseRecordEvidence {
            outcome,
            tenant_id: snapshot.plan.tenant_id,
            action_id: snapshot.plan.action_id,
            plan_hash: snapshot.plan.plan_hash,
            response_generation: response_record.generation,
            response_transition_id,
            response_body_hash: response_record.body_hash,
            response_record,
            completion_evidence_id,
            completion_body_hash,
            completion_receipt_request,
            effects,
            failure,
        })
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
                    let reconciled = self.record_effect_mutation(
                        current,
                        work,
                        &effect_record,
                        EffectMutation::RollbackRestored {
                            resulting_version_hash,
                        },
                    )?;
                    self.append_receipt(&reconciled, Some(&effect_record))?;
                    return Ok(Some(reconciled));
                }
            }
            return Ok(None);
        }
        if snapshot.state != ResponseState::Applying {
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
                if !matches!(journal.phase, EffectJournalPhase::ApplyRequested) {
                    return Err(ExecutorError::InvalidEffectJournal);
                }
                let requested = self.record_effect_mutation(
                    current,
                    work,
                    &effect_record,
                    EffectMutation::Requested,
                )?;
                self.append_receipt(&requested, Some(&effect_record))?;
                return Ok(Some(requested));
            }
            if progress == ResponseEffectProgress::ApplyFailed {
                let effect_record = self.load_effect_record(&snapshot.plan, effect)?;
                let journal = self.decode_journal(&snapshot.plan, effect, &effect_record)?;
                let EffectJournalPhase::ApplyFailed { error_code } = journal.phase else {
                    return Err(ExecutorError::InvalidEffectJournal);
                };
                return self
                    .finish_apply_failure(
                        current.clone(),
                        &effect_record,
                        error_code,
                        work,
                        now_unix_ms,
                    )
                    .map(Some);
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
                    let reconciled = self.record_effect_mutation(
                        current,
                        work,
                        &effect_record,
                        EffectMutation::Applied {
                            resulting_version_hash,
                        },
                    )?;
                    self.append_receipt(&reconciled, Some(&effect_record))?;
                    return Ok(Some(reconciled));
                }
                EffectJournalPhase::ApplyFailed { error_code } => {
                    return self
                        .finish_apply_failure(
                            current.clone(),
                            &effect_record,
                            error_code,
                            work,
                            now_unix_ms,
                        )
                        .map(Some);
                }
                EffectJournalPhase::ApplyRequested => {
                    let status = self.load_effect_execution_status(
                        &snapshot.plan,
                        effect,
                        EffectResultLookup {
                            operation: EffectOperation::Apply,
                            idempotency_key: &journal.apply_idempotency_key,
                            expected_version_hash: journal.observed_base_version_hash,
                            command_lease_owner_id: &effect_record.scheduler_lease_owner_id,
                            command_fencing_token: effect_record.scheduler_fencing_token,
                        },
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
                            let applying_deadline = snapshot
                                .applying_lease_expires_at_unix_ms
                                .ok_or(ExecutorError::InvalidEffectJournal)?;
                            if now_unix_ms < applying_deadline {
                                return Ok(None);
                            }
                            Err(error_code("response.effect_not_executed")?)
                        }
                        EffectExecutionStatus::Unknown => {
                            return Err(ExecutorError::EffectOutcomeUnknown);
                        }
                    };
                    let (updated_journal, mutation) = match outcome {
                        Ok(resulting_version_hash) => (
                            EffectJournal {
                                occurred_at_unix_ms: now_unix_ms,
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
                                occurred_at_unix_ms: now_unix_ms,
                                phase: EffectJournalPhase::ApplyFailed {
                                    error_code: error_code.clone(),
                                },
                                ..journal
                            },
                            EffectMutation::Failed { error_code },
                        ),
                    };
                    let updated =
                        self.update_effect_record(current, &effect_record, updated_journal, work)?;
                    self.append_receipt(current, Some(&updated))?;
                    let reconciled =
                        self.record_effect_mutation(current, work, &updated, mutation)?;
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
                let active = self.state_machine().transition_scheduled(
                    &current,
                    work,
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
                    let effect_record =
                        self.ensure_apply_intent(&snapshot.plan, &effect, work, now_unix_ms)?;
                    current = self.record_effect_mutation(
                        &current,
                        work,
                        &effect_record,
                        EffectMutation::Requested,
                    )?;
                    self.append_receipt(&current, Some(&effect_record))?;
                }
                ResponseEffectProgress::Requested => {
                    let mut effect_record = self.load_effect_record(&snapshot.plan, &effect)?;
                    let journal = self.decode_journal(&snapshot.plan, &effect, &effect_record)?;
                    match journal.phase.clone() {
                        EffectJournalPhase::ApplyRequested => {
                            self.append_receipt(&current, Some(&effect_record))?;
                            let status = self.load_effect_execution_status(
                                &snapshot.plan,
                                &effect,
                                EffectResultLookup {
                                    operation: EffectOperation::Apply,
                                    idempotency_key: &journal.apply_idempotency_key,
                                    expected_version_hash: journal.observed_base_version_hash,
                                    command_lease_owner_id: &effect_record.scheduler_lease_owner_id,
                                    command_fencing_token: effect_record.scheduler_fencing_token,
                                },
                                work,
                            )?;
                            let result = match status {
                                EffectExecutionStatus::Completed { result } => result,
                                EffectExecutionStatus::Failed { error_code } => {
                                    return self.record_apply_failure(
                                        current,
                                        effect_record,
                                        journal,
                                        error_code,
                                        work,
                                        now_unix_ms,
                                    );
                                }
                                EffectExecutionStatus::NotExecuted => {
                                    effect_record = self.rebind_pending_effect_command(
                                        &current,
                                        &effect_record,
                                        journal.clone(),
                                        work,
                                    )?;
                                    self.store
                                        .validate_lease(work)
                                        .map_err(ExecutorError::Store)?;
                                    let request = EffectRequest {
                                        tenant_id: snapshot.plan.tenant_id.clone(),
                                        action_id: snapshot.plan.action_id.clone(),
                                        plan_hash: snapshot.plan.plan_hash,
                                        effect_id: effect.effect_id.clone(),
                                        effect_kind: effect.kind,
                                        target: effect.target.clone(),
                                        plan_expires_at_unix_ms: snapshot.plan.expires_at_unix_ms,
                                        operation: EffectOperation::Apply,
                                        idempotency_key: journal.apply_idempotency_key.clone(),
                                        expected_version_hash: journal.observed_base_version_hash,
                                        scheduler_lease_owner_id: effect_record
                                            .scheduler_lease_owner_id
                                            .clone(),
                                        scheduler_fencing_token: effect_record
                                            .scheduler_fencing_token,
                                        canonical_contribution: journal
                                            .canonical_contribution
                                            .clone(),
                                        contribution_hash: journal.contribution_hash,
                                    };
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
                                    &current,
                                    &effect_record,
                                    EffectJournal {
                                        occurred_at_unix_ms: now_unix_ms,
                                        phase: EffectJournalPhase::Applied {
                                            resulting_version_hash,
                                        },
                                        ..journal
                                    },
                                    work,
                                )?;
                                self.append_receipt(&current, Some(&applied))?;
                                current = self.record_effect_mutation(
                                    &current,
                                    work,
                                    &applied,
                                    EffectMutation::Applied {
                                        resulting_version_hash,
                                    },
                                )?;
                                self.append_receipt(&current, Some(&applied))?;
                                if effect.kind == ResponseEffectKind::FreezeIssuance {
                                    return Ok(current);
                                }
                            } else {
                                return Err(ExecutorError::InvalidEffectResult);
                            }
                        }
                        EffectJournalPhase::Applied {
                            resulting_version_hash,
                        } => {
                            current = self.record_effect_mutation(
                                &current,
                                work,
                                &effect_record,
                                EffectMutation::Applied {
                                    resulting_version_hash,
                                },
                            )?;
                            self.append_receipt(&current, Some(&effect_record))?;
                            if effect.kind == ResponseEffectKind::FreezeIssuance {
                                return Ok(current);
                            }
                        }
                        EffectJournalPhase::ApplyFailed { error_code } => {
                            return self.finish_apply_failure(
                                current,
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
                    let effect_record = self.load_effect_record(&snapshot.plan, &effect)?;
                    let journal = self.decode_journal(&snapshot.plan, &effect, &effect_record)?;
                    let EffectJournalPhase::ApplyFailed { error_code } = journal.phase else {
                        return Err(ExecutorError::InvalidEffectJournal);
                    };
                    return self.finish_apply_failure(
                        current,
                        &effect_record,
                        error_code,
                        work,
                        now_unix_ms,
                    );
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
        effect_record: ResponseEffectRecord,
        journal: EffectJournal,
        error_code: ErrorCode,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        let failed = self.update_effect_record(
            &current,
            &effect_record,
            EffectJournal {
                occurred_at_unix_ms: now_unix_ms,
                phase: EffectJournalPhase::ApplyFailed {
                    error_code: error_code.clone(),
                },
                ..journal
            },
            work,
        )?;
        self.append_receipt(&current, Some(&failed))?;
        self.finish_apply_failure(current, &failed, error_code, work, now_unix_ms)
    }

    fn finish_apply_failure(
        &self,
        current: ResponsePlanRecord,
        effect_record: &ResponseEffectRecord,
        error_code: ErrorCode,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        let snapshot = decode_response_record(&current)?;
        let effect = snapshot
            .plan
            .effect(&effect_record.effect_id)
            .ok_or(ExecutorError::InvalidEffectJournal)?;
        let journal = self.decode_journal(&snapshot.plan, effect, effect_record)?;
        let EffectJournalPhase::ApplyFailed {
            error_code: journal_error,
        } = journal.phase
        else {
            return Err(ExecutorError::InvalidEffectJournal);
        };
        if journal_error != error_code {
            return Err(ExecutorError::InvalidEffectJournal);
        }
        let failed_effect = match snapshot.effect_progress(&effect_record.effect_id) {
            Some(ResponseEffectProgress::Requested) => {
                let failed_effect = self.record_effect_mutation(
                    &current,
                    work,
                    effect_record,
                    EffectMutation::Failed {
                        error_code: error_code.clone(),
                    },
                )?;
                self.append_receipt(&failed_effect, Some(effect_record))?;
                failed_effect
            }
            Some(ResponseEffectProgress::ApplyFailed)
                if matches!(
                    snapshot.mutations.as_slice().last(),
                    Some(ResponseMutationRecord::EffectFailed(failed))
                        if failed.effect_id == effect_record.effect_id
                            && failed.error_code == error_code
                ) =>
            {
                current
            }
            _ => return Err(ExecutorError::InvalidEffectJournal),
        };
        let failed_state = self.state_machine().transition_scheduled(
            &failed_effect,
            work,
            &ResponseTransitionRequest {
                expected_generation: failed_effect.generation,
                target_state: ResponseState::Failed,
                occurred_at_unix_ms: journal.occurred_at_unix_ms,
                applying_lease_expires_at_unix_ms: None,
                error_code: Some(error_code),
            },
        )?;
        self.append_receipt(&failed_state, None)?;
        if decode_response_record(&failed_state)?.state == ResponseState::ApplyPartial {
            let rolling_back = self.state_machine().transition_scheduled(
                &failed_state,
                work,
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
            let retry_active = rollback_retry_is_active(&snapshot);
            let next = snapshot
                .plan
                .effects
                .as_slice()
                .iter()
                .rev()
                .find(|effect| {
                    effect.kind.is_reversible()
                        && effect_was_applied(&snapshot, &effect.effect_id)
                        && (matches!(
                            snapshot.effect_progress(&effect.effect_id),
                            Some(
                                ResponseEffectProgress::Applied
                                    | ResponseEffectProgress::RollbackRequested
                            )
                        ) || (retry_active
                            && snapshot.effect_progress(&effect.effect_id)
                                == Some(ResponseEffectProgress::RollbackFailed)
                            && rollback_failure_count(&snapshot, &effect.effect_id) == 1))
                })
                .cloned();
            let Some(effect) = next else {
                if let Some(error_code) = latest_rollback_failure_error(&snapshot) {
                    let partial = self.state_machine().transition_scheduled(
                        &current,
                        work,
                        &ResponseTransitionRequest {
                            expected_generation: current.generation,
                            target_state: ResponseState::RollbackPartial,
                            occurred_at_unix_ms: now_unix_ms,
                            applying_lease_expires_at_unix_ms: None,
                            error_code: Some(error_code),
                        },
                    )?;
                    self.append_receipt(&partial, None)?;
                    let partial_snapshot = decode_response_record(&partial)?;
                    self.page_rollback_failure(&partial_snapshot, &partial)?;
                    return Ok(partial);
                }
                let lifted = self.state_machine().transition_scheduled(
                    &current,
                    work,
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
                            &current,
                            &effect_record,
                            EffectJournal {
                                occurred_at_unix_ms: now_unix_ms,
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
                            let prior_idempotency_key = effect_command_id(
                                &snapshot.plan,
                                &effect.effect_id,
                                EffectOperation::Remove,
                                attempt,
                            )?;
                            match self.load_effect_execution_status(
                                &snapshot.plan,
                                &effect,
                                EffectResultLookup {
                                    operation: EffectOperation::Remove,
                                    idempotency_key: &prior_idempotency_key,
                                    expected_version_hash: installed_version_hash,
                                    command_lease_owner_id: &effect_record.scheduler_lease_owner_id,
                                    command_fencing_token: effect_record.scheduler_fencing_token,
                                },
                                work,
                            )? {
                                EffectExecutionStatus::Completed { result }
                                    if valid_effect_result(&result, &effect.effect_id, false) =>
                                {
                                    let resulting_version_hash = result.resulting_version_hash;
                                    let rollback_intent = self.update_effect_record(
                                        &current,
                                        &effect_record,
                                        EffectJournal {
                                            occurred_at_unix_ms: now_unix_ms,
                                            phase: EffectJournalPhase::RollbackRequested {
                                                attempt,
                                                idempotency_key: prior_idempotency_key,
                                                installed_version_hash,
                                            },
                                            ..journal.clone()
                                        },
                                        work,
                                    )?;
                                    self.append_receipt(&current, Some(&rollback_intent))?;
                                    let rollback_requested = self.record_effect_mutation(
                                        &current,
                                        work,
                                        &rollback_intent,
                                        EffectMutation::RollbackRequested,
                                    )?;
                                    self.append_receipt(
                                        &rollback_requested,
                                        Some(&rollback_intent),
                                    )?;
                                    let restored = self.update_effect_record(
                                        &rollback_requested,
                                        &rollback_intent,
                                        EffectJournal {
                                            occurred_at_unix_ms: now_unix_ms,
                                            phase: EffectJournalPhase::Restored {
                                                attempt,
                                                resulting_version_hash,
                                            },
                                            ..journal
                                        },
                                        work,
                                    )?;
                                    self.append_receipt(&rollback_requested, Some(&restored))?;
                                    current = self.record_effect_mutation(
                                        &rollback_requested,
                                        work,
                                        &restored,
                                        EffectMutation::RollbackRestored {
                                            resulting_version_hash,
                                        },
                                    )?;
                                    self.append_receipt(&current, Some(&restored))?;
                                    continue;
                                }
                                EffectExecutionStatus::Completed { .. } => {
                                    return Err(ExecutorError::InvalidEffectResult);
                                }
                                EffectExecutionStatus::Unknown => {
                                    return Err(ExecutorError::EffectOutcomeUnknown);
                                }
                                EffectExecutionStatus::NotExecuted
                                | EffectExecutionStatus::Failed { .. } => {}
                            }
                            let next_attempt = attempt
                                .checked_add(1)
                                .ok_or(ExecutorError::AttemptOverflow)?;
                            self.update_effect_record(
                                &current,
                                &effect_record,
                                EffectJournal {
                                    occurred_at_unix_ms: now_unix_ms,
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
                    current = self.record_effect_mutation(
                        &current,
                        work,
                        &rollback_intent,
                        EffectMutation::RollbackRequested,
                    )?;
                    self.append_receipt(&current, Some(&rollback_intent))?;
                }
                ResponseEffectProgress::RollbackRequested => {
                    let mut effect_record = self.load_effect_record(&snapshot.plan, &effect)?;
                    let journal = self.decode_journal(&snapshot.plan, &effect, &effect_record)?;
                    match journal.phase.clone() {
                        EffectJournalPhase::RollbackRequested {
                            attempt,
                            idempotency_key,
                            installed_version_hash,
                        } => {
                            self.append_receipt(&current, Some(&effect_record))?;
                            let status = self.load_effect_execution_status(
                                &snapshot.plan,
                                &effect,
                                EffectResultLookup {
                                    operation: EffectOperation::Remove,
                                    idempotency_key: &idempotency_key,
                                    expected_version_hash: installed_version_hash,
                                    command_lease_owner_id: &effect_record.scheduler_lease_owner_id,
                                    command_fencing_token: effect_record.scheduler_fencing_token,
                                },
                                work,
                            )?;
                            let result = match status {
                                EffectExecutionStatus::Completed { result } => Ok(result),
                                EffectExecutionStatus::Failed { error_code } => Err(error_code),
                                EffectExecutionStatus::NotExecuted => {
                                    effect_record = self.rebind_pending_effect_command(
                                        &current,
                                        &effect_record,
                                        journal.clone(),
                                        work,
                                    )?;
                                    self.store
                                        .validate_lease(work)
                                        .map_err(ExecutorError::Store)?;
                                    let request = EffectRequest {
                                        tenant_id: snapshot.plan.tenant_id.clone(),
                                        action_id: snapshot.plan.action_id.clone(),
                                        plan_hash: snapshot.plan.plan_hash,
                                        effect_id: effect.effect_id.clone(),
                                        effect_kind: effect.kind,
                                        target: effect.target.clone(),
                                        plan_expires_at_unix_ms: snapshot.plan.expires_at_unix_ms,
                                        operation: EffectOperation::Remove,
                                        idempotency_key: idempotency_key.clone(),
                                        expected_version_hash: installed_version_hash,
                                        scheduler_lease_owner_id: effect_record
                                            .scheduler_lease_owner_id
                                            .clone(),
                                        scheduler_fencing_token: effect_record
                                            .scheduler_fencing_token,
                                        canonical_contribution: journal
                                            .canonical_contribution
                                            .clone(),
                                        contribution_hash: journal.contribution_hash,
                                    };
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
                                        &current,
                                        &effect_record,
                                        EffectJournal {
                                            occurred_at_unix_ms: now_unix_ms,
                                            phase: EffectJournalPhase::Restored {
                                                attempt,
                                                resulting_version_hash,
                                            },
                                            ..journal
                                        },
                                        work,
                                    )?;
                                    self.append_receipt(&current, Some(&restored))?;
                                    current = self.record_effect_mutation(
                                        &current,
                                        work,
                                        &restored,
                                        EffectMutation::RollbackRestored {
                                            resulting_version_hash,
                                        },
                                    )?;
                                    self.append_receipt(&current, Some(&restored))?;
                                }
                                Ok(_) => {
                                    let error_code = error_code("response.effect_result_invalid")?;
                                    return self.record_rollback_failure(
                                        current,
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
                            current = self.record_effect_mutation(
                                &current,
                                work,
                                &effect_record,
                                EffectMutation::RollbackRestored {
                                    resulting_version_hash,
                                },
                            )?;
                            self.append_receipt(&current, Some(&effect_record))?;
                        }
                        EffectJournalPhase::RollbackFailed { error_code, .. } => {
                            return self.finish_rollback_failure(
                                current,
                                work,
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
        effect_record: ResponseEffectRecord,
        journal: EffectJournal,
        attempt: u32,
        installed_version_hash: Digest32,
        error_code: ErrorCode,
        work: &ScheduledWork,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        let failed = self.update_effect_record(
            &current,
            &effect_record,
            EffectJournal {
                occurred_at_unix_ms: now_unix_ms,
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
        self.finish_rollback_failure(current, work, &failed, error_code, now_unix_ms)
    }

    fn finish_rollback_failure(
        &self,
        current: ResponsePlanRecord,
        work: &ScheduledWork,
        effect_record: &ResponseEffectRecord,
        error_code: ErrorCode,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        let failed_effect = self.record_effect_mutation(
            &current,
            work,
            effect_record,
            EffectMutation::RollbackFailed {
                error_code: error_code.clone(),
            },
        )?;
        self.append_receipt(&failed_effect, Some(effect_record))?;
        let partial = self.state_machine().transition_scheduled(
            &failed_effect,
            work,
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
}

include!("executor_parts/effect_journal_methods.inc");

struct EffectResultLookup<'a> {
    operation: EffectOperation,
    idempotency_key: &'a RecordId,
    expected_version_hash: Digest32,
    command_lease_owner_id: &'a chio_security_types::ports::LeaseOwnerId,
    command_fencing_token: u64,
}

fn encode_effect_record(
    journal: &EffectJournal,
    generation: u64,
    scheduler_lease_owner_id: chio_security_types::ports::LeaseOwnerId,
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
        scheduler_lease_owner_id,
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
    let digest = domain_hash(
        EFFECT_COMMAND_ID_DOMAIN,
        &EffectCommandCommitment {
            tenant_id: plan.tenant_id.as_str(),
            action_id: plan.action_id.as_str(),
            plan_hash: plan.plan_hash,
            effect_id: effect_id.as_str(),
            operation,
            attempt,
        },
    )?;
    RecordId::new(format!(
        "response_effect_command:{}",
        hex_bytes(digest.as_bytes())
    ))
    .map_err(|_| ExecutorError::Canonical)
}

#[derive(Serialize)]
struct EffectTransitionCommitment<'a> {
    tenant_id: &'a str,
    action_id: &'a str,
    effect_id: &'a str,
    expected_generation: u64,
    generation: u64,
    scheduler_lease_owner_id: &'a str,
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
            scheduler_lease_owner_id: record.scheduler_lease_owner_id.as_str(),
            scheduler_fencing_token: record.scheduler_fencing_token,
            state: record.state.as_str(),
            body_hash: record.body_hash,
        },
    )
}

#[derive(Serialize)]
struct ReceiptCursorTransitionCommitment<'a> {
    tenant_id: &'a str,
    action_id: &'a str,
    plan_hash: Digest32,
    expected_generation: u64,
    expected_evidence_id: &'a str,
    generation: u64,
    current_evidence_id: &'a str,
}

fn receipt_cursor_transition_id(
    current: &ResponseReceiptCursor,
    next: &ResponseReceiptCursor,
) -> Result<RecordId, ExecutorError> {
    domain_record_id(
        "response_receipt_cursor",
        RECEIPT_CURSOR_ID_DOMAIN,
        &ReceiptCursorTransitionCommitment {
            tenant_id: current.tenant_id.as_str(),
            action_id: current.action_id.as_str(),
            plan_hash: current.plan_hash,
            expected_generation: current.generation,
            expected_evidence_id: current.current_evidence_id.as_str(),
            generation: next.generation,
            current_evidence_id: next.current_evidence_id.as_str(),
        },
    )
}

fn validate_receipt_cursor(
    cursor: &ResponseReceiptCursor,
    initial: &ResponseReceiptCursor,
    snapshot: &ResponseSnapshot,
) -> Result<(), ExecutorError> {
    let generation =
        usize::try_from(cursor.generation).map_err(|_| ExecutorError::ReceiptLineageMismatch)?;
    if cursor.tenant_id != initial.tenant_id
        || cursor.action_id != initial.action_id
        || cursor.plan_hash != initial.plan_hash
        || generation > snapshot.mutations.len()
    {
        return Err(ExecutorError::ReceiptLineageMismatch);
    }
    let expected = if generation == 0 {
        initial.current_evidence_id.clone()
    } else if generation == snapshot.mutations.len() {
        latest_response_receipt(snapshot)
            .and_then(|body| body.evidence_id())
            .map_err(|_| ExecutorError::Canonical)?
    } else {
        response_receipt_for_mutation(snapshot, generation - 1)
            .and_then(|body| body.evidence_id())
            .map_err(|_| ExecutorError::Canonical)?
    };
    if cursor.current_evidence_id != expected {
        return Err(ExecutorError::ReceiptLineageMismatch);
    }
    Ok(())
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

fn mutation_for_journal_phase(phase: &EffectJournalPhase) -> EffectMutation {
    match phase {
        EffectJournalPhase::ApplyRequested => EffectMutation::Requested,
        EffectJournalPhase::Applied {
            resulting_version_hash,
        } => EffectMutation::Applied {
            resulting_version_hash: *resulting_version_hash,
        },
        EffectJournalPhase::ApplyFailed { error_code } => EffectMutation::Failed {
            error_code: error_code.clone(),
        },
        EffectJournalPhase::RollbackRequested { .. } => EffectMutation::RollbackRequested,
        EffectJournalPhase::Restored {
            resulting_version_hash,
            ..
        } => EffectMutation::RollbackRestored {
            resulting_version_hash: *resulting_version_hash,
        },
        EffectJournalPhase::RollbackFailed { error_code, .. } => EffectMutation::RollbackFailed {
            error_code: error_code.clone(),
        },
    }
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

fn rollback_failure_count(snapshot: &ResponseSnapshot, effect_id: &EffectId) -> usize {
    snapshot
        .mutations
        .as_slice()
        .iter()
        .filter(|mutation| {
            matches!(
                mutation,
                ResponseMutationRecord::Rollback(record)
                    if &record.effect_id == effect_id
                        && matches!(
                            record.outcome,
                            chio_security_types::ResponseRollbackOutcome::Failed { .. }
                        )
            )
        })
        .count()
}

fn rollback_retry_is_active(snapshot: &ResponseSnapshot) -> bool {
    let latest_retry = snapshot.mutations.as_slice().iter().rposition(|mutation| {
        matches!(
            mutation,
            ResponseMutationRecord::Transition(record)
                if record.from_state == ResponseState::RollbackPartial
                    && record.to_state == ResponseState::RollingBack
        )
    });
    let latest_failure = snapshot.mutations.as_slice().iter().rposition(|mutation| {
        matches!(
            mutation,
            ResponseMutationRecord::Rollback(record)
                if matches!(
                    record.outcome,
                    chio_security_types::ResponseRollbackOutcome::Failed { .. }
                )
        )
    });
    latest_retry.is_some_and(|retry| latest_failure.is_some_and(|failure| retry > failure))
}

fn latest_rollback_failure_error(snapshot: &ResponseSnapshot) -> Option<ErrorCode> {
    snapshot
        .mutations
        .as_slice()
        .iter()
        .rev()
        .find_map(|mutation| match mutation {
            ResponseMutationRecord::Rollback(record)
                if snapshot.effect_progress(&record.effect_id)
                    == Some(ResponseEffectProgress::RollbackFailed) =>
            {
                match &record.outcome {
                    chio_security_types::ResponseRollbackOutcome::Failed { error_code } => {
                        Some(error_code.clone())
                    }
                    _ => None,
                }
            }
            _ => None,
        })
}

fn rollback_retry_budget_exhausted(snapshot: &ResponseSnapshot) -> bool {
    snapshot.plan.effects.as_slice().iter().any(|effect| {
        snapshot.effect_progress(&effect.effect_id) == Some(ResponseEffectProgress::RollbackFailed)
            && rollback_failure_count(snapshot, &effect.effect_id) >= 2
    })
}

fn freeze_issuance_became_applied(before: &ResponseSnapshot, after: &ResponseSnapshot) -> bool {
    before.plan.effects.as_slice().iter().any(|effect| {
        effect.kind == ResponseEffectKind::FreezeIssuance
            && before.effect_progress(&effect.effect_id) != Some(ResponseEffectProgress::Applied)
            && after.effect_progress(&effect.effect_id) == Some(ResponseEffectProgress::Applied)
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
    #[error("active response execution evidence is invalid or incomplete")]
    InvalidActiveEvidence,
    #[error("response execution receipt failed: {0}")]
    Receipt(PortError),
    #[error("response execution receipt lineage does not match durable state")]
    ReceiptLineageMismatch,
    #[error("response execution lease is stale")]
    StaleLease,
    #[error("response execution store failed: {0}")]
    Store(PortError),
    #[error("response state machine failed: {0}")]
    StateMachine(#[from] StateMachineError),
    #[error("scheduled work does not match the response plan")]
    WorkMismatch,
}
