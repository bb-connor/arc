// Adapted from Clawdstrike concepts; see docs/security/clawdstrike-active-defense-provenance.md.
use chio_core_types::{
    canonical_json_bytes, capability::governance::GovernedResponsePlanIntentBody,
    receipt::security::validate_response_snapshot_lifecycle, sha256,
};
use chio_security_types::ports::{
    response_affected_set_hash, BlastRadiusResult, BoundedVec, CanonicalBody, CreateOutcome,
    Digest32, EffectId, ErrorCode, IssuanceFreezeSpec, LeaseOwnerId, OpaqueReceiptRef, PortError,
    RecordId, RecordIdSet, ResponseCasRequest, ResponseDispatchApproval,
    ResponseDispatchAuthorization, ResponseDispatchAuthorizationBody, ResponseDispatchCommitMode,
    ResponseDispatchCommitRequest, ResponseDispatchKey, ResponseDispatchLease, ResponsePlanRecord,
    ResponseScheduledMutationCasRequest, ResponseSchedulerStore, ResponseStore, ScheduledWork,
    RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
};
use chio_security_types::{
    is_legal_response_transition, PlannedResponseEffect, PlannedResponseEffects,
    ResponseApprovalRequirement, ResponseEffectAppliedRecord, ResponseEffectFailedRecord,
    ResponseEffectProgress, ResponseEffectRequestedRecord, ResponseEffectSpec,
    ResponseExecutionDispatchBinding, ResponseFailureRecord, ResponseFinalRecord,
    ResponseMutationLog, ResponseMutationRecord, ResponsePlan, ResponsePlanInput,
    ResponseRequestedRecord, ResponseRollbackOutcome, ResponseRollbackRecord, ResponseShapeError,
    ResponseSnapshot, ResponseState, ResponseTransitionCause, ResponseTransitionRecord,
    MAX_RESPONSE_EFFECTS, MAX_RESPONSE_MUTATIONS, RESPONSE_STATE_SCHEMA_VERSION,
};
use serde::Serialize;
use std::sync::Arc;
use thiserror::Error;

use crate::native_receipts::response_receipt_for_mutation;

const EFFECT_ID_DOMAIN: &[u8] = b"chio.response-effect.v1\0";
const REQUEST_ID_DOMAIN: &[u8] = b"chio.response-request.v1\0";
const TRANSITION_ID_DOMAIN: &[u8] = b"chio.response-transition.v1\0";
const DISPATCH_COMMITTED_RESUME_EXPIRED_ERROR: &str =
    "active_response.dispatch_committed_resume_expired";
const DISPATCH_APPLY_LEASE_EXPIRED_BEFORE_EFFECT_ERROR: &str =
    "active_response.dispatch_apply_lease_expired_before_effect";
const APPLYING_LEASE_EXPIRED_ERROR: &str = "response.applying_lease_expired";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "mutation")]
pub enum EffectMutation {
    Requested,
    Applied { resulting_version_hash: Digest32 },
    Failed { error_code: ErrorCode },
    RollbackRequested,
    RollbackRestored { resulting_version_hash: Digest32 },
    RollbackFailed { error_code: ErrorCode },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectMutationRequest {
    pub expected_generation: u64,
    pub effect_id: EffectId,
    pub occurred_at_unix_ms: u64,
    pub mutation: EffectMutation,
}

/// Durable inputs that bind an effect-state mutation to its native receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectReceiptContext {
    pub effect_generation: u64,
    pub scheduler_lease_owner_id: Option<LeaseOwnerId>,
    pub scheduler_fencing_token: u64,
    pub effect_transition_id: Option<RecordId>,
    pub prior_receipt_id: Option<OpaqueReceiptRef>,
}

impl EffectReceiptContext {
    #[must_use]
    pub const fn state_only() -> Self {
        Self {
            effect_generation: 1,
            scheduler_lease_owner_id: None,
            scheduler_fencing_token: 1,
            effect_transition_id: None,
            prior_receipt_id: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResponseTransitionRequest {
    pub expected_generation: u64,
    pub target_state: ResponseState,
    pub occurred_at_unix_ms: u64,
    pub applying_lease_expires_at_unix_ms: Option<u64>,
    pub error_code: Option<ErrorCode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseDispatchPreparationRequest {
    pub plan: ResponsePlan,
    pub dispatch_id: RecordId,
    pub authorization_capability_hash: Digest32,
    pub governed_intent_hash: Digest32,
    pub policy_decision_hash: Digest32,
    pub executor_authority_id: RecordId,
    pub executor_authority_generation: u64,
    pub approval: ResponseDispatchApproval,
    pub authorized_at_unix_ms: u64,
    pub initial_lease: ResponseDispatchLease,
    pub commit_mode: ResponseDispatchCommitMode,
}

pub struct ResponseStateMachine<S: ResponseStore + ?Sized> {
    store: Arc<S>,
}

impl<S: ResponseStore + ?Sized> ResponseStateMachine<S> {
    #[must_use]
    pub const fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    pub fn create(&self, plan: ResponsePlan) -> Result<ResponsePlanRecord, StateMachineError> {
        validate_plan(&plan)?;
        let request_id = request_id(&plan)?;
        let mutations = ResponseMutationLog::new(vec![ResponseMutationRecord::Requested(
            ResponseRequestedRecord {
                transition_id: request_id,
                generation: 0,
                prior_receipt_id: plan.trigger_finding_receipt_id.clone(),
                occurred_at_unix_ms: plan.created_at_unix_ms,
            },
        )])
        .map_err(|_| StateMachineError::MutationLimit)?;
        let snapshot = ResponseSnapshot {
            schema_version: RESPONSE_STATE_SCHEMA_VERSION,
            execution_dispatch: None,
            dispatch_authorization_hash: None,
            state: ResponseState::Planned,
            generation: 0,
            applying_lease_expires_at_unix_ms: None,
            due_at_unix_ms: Some(plan.expires_at_unix_ms),
            operator_page_required: false,
            plan,
            mutations,
        };
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

fn transition_candidate(
    current: &ResponsePlanRecord,
    request: &ResponseTransitionRequest,
    scheduler_fence: Option<(&LeaseOwnerId, u64)>,
) -> Result<(ResponsePlanRecord, RecordId), StateMachineError> {
    let mut snapshot = decode_response_record(current)?;
    require_generation(&snapshot, request.expected_generation)?;
    if snapshot.state == ResponseState::Applying
        && request.target_state == ResponseState::Applying
        && scheduler_fence.is_none()
    {
        return Err(StateMachineError::InvalidTransition);
    }
    let from_state = snapshot.state;
    let actual_target = if from_state == ResponseState::Applying
        && request.target_state == ResponseState::Failed
        && (snapshot.any_effect_applied()
            || request
                .error_code
                .as_ref()
                .is_some_and(|error| error.as_str() == "response.effect_not_executed"))
    {
        ResponseState::ApplyPartial
    } else {
        request.target_state
    };
    if !is_legal_response_transition(from_state, actual_target) {
        return Err(StateMachineError::InvalidTransition);
    }
    validate_transition_request(&snapshot, request, actual_target)?;

    let next_generation = snapshot
        .generation
        .checked_add(1)
        .ok_or(StateMachineError::GenerationOverflow)?;
    let due_at_unix_ms = transition_due_at(&snapshot, request, actual_target)?;
    let prior_receipt_id = latest_evidence_id(&snapshot)?;
    let (scheduler_lease_owner_id, scheduler_fencing_token) = scheduler_fence
        .map(|(owner, token)| (Some(owner.clone()), Some(token)))
        .unwrap_or((None, None));
    let mutation = transition_mutation(
        &snapshot,
        request,
        TransitionMutationContext {
            from_state,
            actual_target,
            prior_receipt_id,
            generation: next_generation,
            scheduler_lease_owner_id,
            scheduler_fencing_token,
        },
    )?;
    let transition_id = mutation.transition_id().clone();
    push_mutation(&mut snapshot, mutation)?;
    snapshot.state = actual_target;
    snapshot.generation = next_generation;
    snapshot.applying_lease_expires_at_unix_ms = if actual_target == ResponseState::Applying {
        request.applying_lease_expires_at_unix_ms
    } else {
        None
    };
    snapshot.due_at_unix_ms = due_at_unix_ms;
    if actual_target == ResponseState::RollbackPartial {
        snapshot.operator_page_required = true;
    }
    let record = encode_response_record(&snapshot)?;
    Ok((record, transition_id))
}

fn effect_candidate(
    current: &ResponsePlanRecord,
    request: &EffectMutationRequest,
    receipt: &EffectReceiptContext,
    scheduler_work: Option<&ScheduledWork>,
) -> Result<(ResponsePlanRecord, RecordId), StateMachineError> {
    let mut snapshot = decode_response_record(current)?;
    require_generation(&snapshot, request.expected_generation)?;
    if snapshot.plan.effect(&request.effect_id).is_none() {
        return Err(StateMachineError::UnknownEffect);
    }
    if receipt.effect_generation == 0 || receipt.scheduler_fencing_token == 0 {
        return Err(StateMachineError::InvalidEffectLifecycle);
    }
    validate_effect_mutation(&snapshot, request, receipt, scheduler_work)?;
    validate_effect_receipt_order(&snapshot, request, receipt)?;
    let next_generation = snapshot
        .generation
        .checked_add(1)
        .ok_or(StateMachineError::GenerationOverflow)?;
    let prior_receipt_id = latest_evidence_id(&snapshot)?;
    if receipt
        .prior_receipt_id
        .as_ref()
        .is_some_and(|expected| expected != &prior_receipt_id)
    {
        return Err(StateMachineError::InvalidEffectLifecycle);
    }
    let mutation = effect_mutation_record(
        &snapshot.plan,
        request,
        receipt,
        prior_receipt_id,
        next_generation,
    )?;
    let transition_id = mutation.transition_id().clone();
    push_mutation(&mut snapshot, mutation)?;
    snapshot.generation = next_generation;
    let record = encode_response_record(&snapshot)?;
    Ok((record, transition_id))
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
            .ok_or(StateMachineError::InvalidRecord)?;
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

pub fn build_response_plan(input: ResponsePlanInput) -> Result<ResponsePlan, StateMachineError> {
    if input.effects.is_empty() || input.effects.len() > MAX_RESPONSE_EFFECTS {
        return Err(StateMachineError::InvalidPlan);
    }
    if input.ttl_ms == 0 {
        return Err(StateMachineError::InvalidPlan);
    }
    let expires_at_unix_ms = input
        .created_at_unix_ms
        .checked_add(input.ttl_ms)
        .ok_or(StateMachineError::InvalidPlan)?;
    let affected_ids =
        RecordIdSet::new(input.affected_ids).map_err(|_| StateMachineError::InvalidPlan)?;
    let affected_set_hash = response_affected_set_hash(&input.tenant_id, &affected_ids)
        .map_err(|_| StateMachineError::InvalidPlan)?;
    let mut effects = Vec::with_capacity(input.effects.len());
    for (index, spec) in input.effects.into_iter().enumerate() {
        validate_effect_contribution(&spec.canonical_contribution, &spec.contribution_hash)?;
        let ordinal = u16::try_from(index).map_err(|_| StateMachineError::InvalidPlan)?;
        let effect_id = derive_effect_id(&input.action_id, ordinal, &spec)?;
        effects.push(PlannedResponseEffect {
            effect_id,
            ordinal,
            kind: spec.kind,
            target: spec.target,
            canonical_contribution: spec.canonical_contribution,
            contribution_hash: spec.contribution_hash,
            observed_base_version_hash: spec.observed_base_version_hash,
        });
    }
    let effects =
        PlannedResponseEffects::new(effects).map_err(|_| StateMachineError::InvalidPlan)?;
    let mut plan = ResponsePlan {
        action_id: input.action_id,
        trigger_finding_id: input.trigger_finding_id,
        trigger_finding_hash: input.trigger_finding_hash,
        trigger_finding_receipt_id: input.trigger_finding_receipt_id,
        tenant_id: input.tenant_id,
        policy_version: input.policy_version,
        policy_hash: input.policy_hash,
        affected_ids,
        affected_set_hash,
        effects,
        ttl_ms: input.ttl_ms,
        created_at_unix_ms: input.created_at_unix_ms,
        expires_at_unix_ms,
        operator_capability: input.operator_capability,
        approval_requirement: input.approval_requirement,
        submitter: input.submitter,
        reason_hash: input.reason_hash,
        plan_hash: Digest32::new([0_u8; 32]),
    };
    plan.plan_hash = Digest32::new(compute_plan_hash(&plan)?);
    validate_plan(&plan)?;
    Ok(plan)
}

/// Build the exact durable record and first lease admitted by an executor.
///
/// This function performs no I/O. The returned request is committed atomically
/// by `ResponseDispatchStore`, which allocates the first scheduler fencing
/// token. Both approval modes start execution in `Applying`. A committed record
/// with no effect progress is recovered only through exact dispatch readback;
/// scheduler recovery begins after effect progress diverges from that record.
pub fn prepare_response_dispatch(
    request: ResponseDispatchPreparationRequest,
) -> Result<ResponseDispatchCommitRequest, StateMachineError> {
    let ResponseDispatchPreparationRequest {
        plan,
        dispatch_id,
        authorization_capability_hash,
        governed_intent_hash,
        policy_decision_hash,
        executor_authority_id,
        executor_authority_generation,
        approval,
        authorized_at_unix_ms,
        initial_lease,
        commit_mode,
    } = request;
    validate_plan(&plan)?;
    if authorization_capability_hash != plan.operator_capability.capability_digest
        || executor_authority_generation == 0
        || authorized_at_unix_ms < plan.created_at_unix_ms
        || authorized_at_unix_ms >= plan.expires_at_unix_ms
        || initial_lease.lease_expires_at_unix_ms <= authorized_at_unix_ms
        || initial_lease.lease_expires_at_unix_ms > plan.expires_at_unix_ms
    {
        return Err(StateMachineError::InvalidDispatch);
    }
    let governed = match (&plan.approval_requirement, &approval) {
        (ResponseApprovalRequirement::Automatic, ResponseDispatchApproval::Automatic) => false,
        (
            ResponseApprovalRequirement::Governed { .. },
            ResponseDispatchApproval::Governed {
                admission_operation_version,
                ..
            },
        ) if *admission_operation_version > 0 => true,
        _ => return Err(StateMachineError::InvalidDispatch),
    };
    if matches!(
        commit_mode,
        ResponseDispatchCommitMode::GovernedCommittedResume
            | ResponseDispatchCommitMode::GovernedCommittedExpiredResume
    ) && !governed
    {
        return Err(StateMachineError::InvalidDispatch);
    }

    let requested = ResponseMutationRecord::Requested(ResponseRequestedRecord {
        transition_id: request_id(&plan)?,
        generation: 0,
        prior_receipt_id: plan.trigger_finding_receipt_id.clone(),
        occurred_at_unix_ms: plan.created_at_unix_ms,
    });
    let mutations =
        ResponseMutationLog::new(vec![requested]).map_err(|_| StateMachineError::MutationLimit)?;
    let execution_dispatch = ResponseExecutionDispatchBinding {
        schema_version: RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
        tenant_id: plan.tenant_id.clone(),
        dispatch_id: dispatch_id.clone(),
        action_id: plan.action_id.clone(),
        plan_hash: plan.plan_hash,
        executor_authority_id: executor_authority_id.clone(),
        executor_authority_generation,
        authorization_capability_hash,
        governed_intent_hash,
        policy_decision_hash,
        approval: approval.clone(),
        authorized_at_unix_ms,
    };
    let mut snapshot = ResponseSnapshot {
        schema_version: RESPONSE_STATE_SCHEMA_VERSION,
        plan,
        execution_dispatch: Some(execution_dispatch),
        dispatch_authorization_hash: None,
        state: ResponseState::Planned,
        generation: 0,
        applying_lease_expires_at_unix_ms: None,
        due_at_unix_ms: None,
        operator_page_required: false,
        mutations,
    };
    snapshot.due_at_unix_ms = Some(snapshot.plan.expires_at_unix_ms);
    if governed {
        let created_at_unix_ms = snapshot.plan.created_at_unix_ms;
        prepare_dispatch_transition(
            &mut snapshot,
            ResponseState::AwaitingApproval,
            created_at_unix_ms,
            None,
        )?;
    }
    prepare_dispatch_transition(
        &mut snapshot,
        ResponseState::Applying,
        authorized_at_unix_ms,
        Some(initial_lease.lease_expires_at_unix_ms),
    )?;
    let normalized_response_plan = encode_normalized_dispatch_response_record(&snapshot)?;
    let authorization_body = ResponseDispatchAuthorizationBody {
        schema_version: RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
        key: ResponseDispatchKey {
            tenant_id: normalized_response_plan.tenant_id.clone(),
            dispatch_id,
        },
        action_id: normalized_response_plan.action_id.clone(),
        plan_hash: snapshot.plan.plan_hash,
        response_body_hash: normalized_response_plan.body_hash,
        authorization_capability_hash,
        governed_intent_hash,
        policy_decision_hash,
        executor_authority_id,
        executor_authority_generation,
        approval,
        authorized_at_unix_ms,
    };
    let authorization_bytes =
        canonical_json_bytes(&authorization_body).map_err(|_| StateMachineError::Canonical)?;
    let authorization_hash = Digest32::new(*sha256(&authorization_bytes).as_bytes());
    let canonical_authorization =
        CanonicalBody::new(authorization_bytes).map_err(|_| StateMachineError::Canonical)?;
    snapshot.dispatch_authorization_hash = Some(authorization_hash);
    let response_plan = encode_response_record(&snapshot)?;
    Ok(ResponseDispatchCommitRequest {
        mode: commit_mode,
        authorization: ResponseDispatchAuthorization {
            body: authorization_body,
            canonical_body: canonical_authorization,
            body_hash: authorization_hash,
        },
        response_plan,
        initial_lease,
    })
}

fn prepare_dispatch_transition(
    snapshot: &mut ResponseSnapshot,
    target_state: ResponseState,
    occurred_at_unix_ms: u64,
    applying_lease_expires_at_unix_ms: Option<u64>,
) -> Result<(), StateMachineError> {
    if !is_legal_response_transition(snapshot.state, target_state) {
        return Err(StateMachineError::InvalidTransition);
    }
    let request = ResponseTransitionRequest {
        expected_generation: snapshot.generation,
        target_state,
        occurred_at_unix_ms,
        applying_lease_expires_at_unix_ms,
        error_code: None,
    };
    validate_transition_request(snapshot, &request, target_state)?;
    let next_generation = snapshot
        .generation
        .checked_add(1)
        .ok_or(StateMachineError::GenerationOverflow)?;
    let due_at_unix_ms = transition_due_at(snapshot, &request, target_state)?;
    let prior_receipt_id = latest_evidence_id(snapshot)?;
    let mutation = transition_mutation(
        snapshot,
        &request,
        TransitionMutationContext {
            from_state: snapshot.state,
            actual_target: target_state,
            prior_receipt_id,
            generation: next_generation,
            scheduler_lease_owner_id: None,
            scheduler_fencing_token: None,
        },
    )?;
    push_mutation(snapshot, mutation)?;
    snapshot.state = target_state;
    snapshot.generation = next_generation;
    snapshot.applying_lease_expires_at_unix_ms = applying_lease_expires_at_unix_ms;
    snapshot.due_at_unix_ms = due_at_unix_ms;
    Ok(())
}

pub fn decode_response_record(
    record: &ResponsePlanRecord,
) -> Result<ResponseSnapshot, StateMachineError> {
    let snapshot: ResponseSnapshot = serde_json::from_slice(record.canonical_body.as_bytes())
        .map_err(|_| StateMachineError::InvalidRecord)?;
    let canonical = canonical_json_bytes(&snapshot).map_err(|_| StateMachineError::Canonical)?;
    if canonical.as_slice() != record.canonical_body.as_bytes()
        || Digest32::new(*sha256(&canonical).as_bytes()) != record.body_hash
        || snapshot.plan.tenant_id != record.tenant_id
        || snapshot.plan.action_id != record.action_id
        || snapshot.generation != record.generation
        || snapshot.state.as_str() != record.state.as_str()
        || snapshot.due_at_unix_ms != record.due_at_unix_ms
    {
        return Err(StateMachineError::InvalidRecord);
    }
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

pub(crate) fn encode_response_record(
    snapshot: &ResponseSnapshot,
) -> Result<ResponsePlanRecord, StateMachineError> {
    encode_response_record_with_mode(snapshot, false)
}

pub(crate) fn encode_normalized_dispatch_response_record(
    snapshot: &ResponseSnapshot,
) -> Result<ResponsePlanRecord, StateMachineError> {
    if snapshot.execution_dispatch.is_none() || snapshot.dispatch_authorization_hash.is_some() {
        return Err(StateMachineError::InvalidDispatch);
    }
    encode_response_record_with_mode(snapshot, true)
}

fn encode_response_record_with_mode(
    snapshot: &ResponseSnapshot,
    allow_normalized_dispatch: bool,
) -> Result<ResponsePlanRecord, StateMachineError> {
    validate_snapshot_with_mode(snapshot, allow_normalized_dispatch)?;
    let bytes = canonical_json_bytes(snapshot).map_err(|_| StateMachineError::Canonical)?;
    let body_hash = Digest32::new(*sha256(&bytes).as_bytes());
    let canonical_body = CanonicalBody::new(bytes).map_err(|_| StateMachineError::Canonical)?;
    Ok(ResponsePlanRecord {
        tenant_id: snapshot.plan.tenant_id.clone(),
        action_id: snapshot.plan.action_id.clone(),
        generation: snapshot.generation,
        state: RecordId::new(snapshot.state.as_str()).map_err(|_| StateMachineError::Canonical)?,
        canonical_body,
        body_hash,
        due_at_unix_ms: snapshot.due_at_unix_ms,
    })
}

fn validate_plan(plan: &ResponsePlan) -> Result<(), StateMachineError> {
    plan.validate_shape()?;
    if plan.affected_set_hash
        != response_affected_set_hash(&plan.tenant_id, &plan.affected_ids)
            .map_err(|_| StateMachineError::InvalidPlan)?
    {
        return Err(StateMachineError::InvalidPlan);
    }
    for effect in plan.effects.as_slice() {
        let spec = ResponseEffectSpec {
            kind: effect.kind,
            target: effect.target.clone(),
            canonical_contribution: effect.canonical_contribution.clone(),
            contribution_hash: effect.contribution_hash,
            observed_base_version_hash: effect.observed_base_version_hash,
        };
        validate_effect_contribution(&spec.canonical_contribution, &spec.contribution_hash)?;
        if effect.effect_id != derive_effect_id(&plan.action_id, effect.ordinal, &spec)? {
            return Err(StateMachineError::InvalidPlan);
        }
        validate_effect_plan_binding(plan, effect)?;
    }
    if plan.plan_hash != Digest32::new(compute_plan_hash(plan)?) {
        return Err(StateMachineError::InvalidPlan);
    }
    Ok(())
}

fn validate_effect_plan_binding(
    plan: &ResponsePlan,
    effect: &PlannedResponseEffect,
) -> Result<(), StateMachineError> {
    if effect.kind != chio_security_types::ResponseEffectKind::FreezeIssuance {
        return Ok(());
    }
    let freeze: IssuanceFreezeSpec =
        serde_json::from_slice(effect.canonical_contribution.as_bytes())
            .map_err(|_| StateMachineError::InvalidPlan)?;
    let chio_security_types::ResponseTarget::Lineage { lineage_id } = &effect.target else {
        return Err(StateMachineError::InvalidPlan);
    };
    let BlastRadiusResult::Exact {
        sorted_affected_ids,
        affected_set_hash,
        ..
    } = &freeze.acquisition.approved_result
    else {
        return Err(StateMachineError::InvalidPlan);
    };
    if &freeze.lineage_id != lineage_id
        || freeze.acquisition.request.tenant_id != plan.tenant_id
        || freeze.acquisition.request.action_id != plan.action_id
        || sorted_affected_ids != &plan.affected_ids
        || *affected_set_hash != plan.affected_set_hash
    {
        return Err(StateMachineError::InvalidPlan);
    }
    Ok(())
}

fn validate_effect_contribution(
    body: &CanonicalBody,
    expected_hash: &Digest32,
) -> Result<(), StateMachineError> {
    let value: serde_json::Value =
        serde_json::from_slice(body.as_bytes()).map_err(|_| StateMachineError::InvalidPlan)?;
    let canonical = canonical_json_bytes(&value).map_err(|_| StateMachineError::Canonical)?;
    if canonical.as_slice() != body.as_bytes()
        || Digest32::new(*sha256(&canonical).as_bytes()) != *expected_hash
    {
        return Err(StateMachineError::InvalidPlan);
    }
    Ok(())
}

fn validate_snapshot(snapshot: &ResponseSnapshot) -> Result<(), StateMachineError> {
    validate_snapshot_with_mode(snapshot, false)
}

fn validate_snapshot_with_mode(
    snapshot: &ResponseSnapshot,
    allow_normalized_dispatch: bool,
) -> Result<(), StateMachineError> {
    validate_plan(&snapshot.plan)?;
    validate_response_snapshot_lifecycle(snapshot, allow_normalized_dispatch)
        .map_err(|_| StateMachineError::InvalidRecord)
}

fn validate_transition_request(
    snapshot: &ResponseSnapshot,
    request: &ResponseTransitionRequest,
    actual_target: ResponseState,
) -> Result<(), StateMachineError> {
    if !response_approval_path_is_valid(snapshot, actual_target) {
        return Err(StateMachineError::InvalidTransition);
    }
    if actual_target == ResponseState::Applying {
        let lease = request
            .applying_lease_expires_at_unix_ms
            .ok_or(StateMachineError::InvalidTiming)?;
        if lease <= request.occurred_at_unix_ms
            || lease > snapshot.plan.expires_at_unix_ms
            || (snapshot.state != ResponseState::Applying
                && snapshot
                    .execution_dispatch
                    .as_ref()
                    .is_some_and(|dispatch| {
                        request.occurred_at_unix_ms != dispatch.authorized_at_unix_ms
                    }))
        {
            return Err(StateMachineError::InvalidTiming);
        }
    } else if request.applying_lease_expires_at_unix_ms.is_some() {
        return Err(StateMachineError::InvalidTiming);
    }
    let needs_error = matches!(
        actual_target,
        ResponseState::Failed | ResponseState::ApplyPartial | ResponseState::RollbackPartial
    );
    if needs_error != request.error_code.is_some() {
        return Err(StateMachineError::InvalidFailureRecord);
    }
    if matches!(
        (snapshot.state, actual_target),
        (
            ResponseState::Planned | ResponseState::AwaitingApproval,
            ResponseState::Expired
        ) | (ResponseState::Active, ResponseState::Expiring)
    ) && request.occurred_at_unix_ms < snapshot.plan.expires_at_unix_ms
    {
        return Err(StateMachineError::NotDue);
    }
    if snapshot.state == ResponseState::Applying && actual_target == ResponseState::Active {
        let lease = snapshot
            .applying_lease_expires_at_unix_ms
            .ok_or(StateMachineError::InvalidRecord)?;
        if request.occurred_at_unix_ms >= lease {
            return Err(StateMachineError::NotDue);
        }
        if snapshot.plan.effects.as_slice().iter().any(|effect| {
            snapshot.effect_progress(&effect.effect_id) != Some(ResponseEffectProgress::Applied)
        }) {
            return Err(StateMachineError::IncompleteApplication);
        }
    }
    let dispatch_failure_before_effect = request.error_code.as_ref().is_some_and(|error| {
        is_dispatch_failure_before_effect(
            snapshot,
            snapshot.state,
            actual_target,
            request.occurred_at_unix_ms,
            error,
            snapshot.applying_lease_expires_at_unix_ms,
        )
    });
    let exact_effect_failure = request
        .error_code
        .as_ref()
        .is_some_and(|error| exact_effect_failure_snapshot_is_valid(snapshot, error));
    if request.error_code.as_ref().is_some_and(|error| {
        !reserved_failure_timing_is_valid(
            snapshot,
            actual_target,
            request.occurred_at_unix_ms,
            error,
            dispatch_failure_before_effect,
        )
    }) {
        return Err(StateMachineError::InvalidTiming);
    }
    if snapshot.state == ResponseState::Applying && actual_target == ResponseState::Failed {
        let lease = snapshot
            .applying_lease_expires_at_unix_ms
            .ok_or(StateMachineError::InvalidRecord)?;
        if request.occurred_at_unix_ms >= lease
            && !dispatch_failure_before_effect
            && !exact_effect_failure
        {
            return Err(StateMachineError::InvalidTiming);
        }
    }
    if actual_target == ResponseState::Failed
        && !snapshot.terminal_failure_effects_are_exact(
            request
                .error_code
                .as_ref()
                .ok_or(StateMachineError::InvalidFailureRecord)?,
        )
    {
        return Err(StateMachineError::InvalidFailureRecord);
    }
    if actual_target == ResponseState::ApplyPartial
        && !snapshot.terminal_apply_partial_effects_are_exact(
            request
                .error_code
                .as_ref()
                .ok_or(StateMachineError::InvalidFailureRecord)?,
        )
    {
        return Err(StateMachineError::InvalidFailureRecord);
    }
    if actual_target == ResponseState::RollbackPartial && !snapshot.has_rollback_failure() {
        return Err(StateMachineError::InvalidFailureRecord);
    }
    if actual_target == ResponseState::Lifted && !snapshot.all_applied_reversible_effects_restored()
    {
        return Err(StateMachineError::UnrestoredEffects);
    }
    Ok(())
}

fn is_dispatch_failure_before_effect(
    snapshot: &ResponseSnapshot,
    from_state: ResponseState,
    to_state: ResponseState,
    occurred_at_unix_ms: u64,
    error: &ErrorCode,
    applying_lease_expires_at_unix_ms: Option<u64>,
) -> bool {
    snapshot.execution_dispatch.is_some()
        && from_state == ResponseState::Applying
        && to_state == ResponseState::Failed
        && all_response_effects_planned(snapshot)
        && ((error.as_str() == DISPATCH_COMMITTED_RESUME_EXPIRED_ERROR
            && occurred_at_unix_ms == snapshot.plan.expires_at_unix_ms)
            || (error.as_str() == DISPATCH_APPLY_LEASE_EXPIRED_BEFORE_EFFECT_ERROR
                && applying_lease_expires_at_unix_ms == Some(occurred_at_unix_ms)))
}

fn all_response_effects_planned(snapshot: &ResponseSnapshot) -> bool {
    snapshot.plan.effects.as_slice().iter().all(|effect| {
        snapshot.effect_progress(&effect.effect_id) == Some(ResponseEffectProgress::Planned)
    })
}

fn response_approval_path_is_valid(
    snapshot: &ResponseSnapshot,
    actual_target: ResponseState,
) -> bool {
    match &snapshot.plan.approval_requirement {
        ResponseApprovalRequirement::Automatic => {
            (snapshot.state, actual_target)
                != (ResponseState::Planned, ResponseState::AwaitingApproval)
        }
        ResponseApprovalRequirement::Governed { .. } => {
            (snapshot.state, actual_target) != (ResponseState::Planned, ResponseState::Applying)
        }
    }
}

fn reserved_failure_timing_is_valid(
    snapshot: &ResponseSnapshot,
    actual_target: ResponseState,
    occurred_at_unix_ms: u64,
    error: &ErrorCode,
    dispatch_failure_before_effect: bool,
) -> bool {
    match error.as_str() {
        DISPATCH_COMMITTED_RESUME_EXPIRED_ERROR
        | DISPATCH_APPLY_LEASE_EXPIRED_BEFORE_EFFECT_ERROR => dispatch_failure_before_effect,
        APPLYING_LEASE_EXPIRED_ERROR => {
            snapshot.state == ResponseState::Applying
                && actual_target == ResponseState::ApplyPartial
                && snapshot.applying_lease_expires_at_unix_ms == Some(occurred_at_unix_ms)
        }
        _ => true,
    }
}

fn exact_effect_failure_snapshot_is_valid(snapshot: &ResponseSnapshot, error: &ErrorCode) -> bool {
    let progress = snapshot
        .plan
        .effects
        .as_slice()
        .iter()
        .filter_map(|effect| snapshot.effect_progress(&effect.effect_id))
        .collect::<Vec<_>>();
    exact_effect_failure_progress_is_valid(
        &snapshot.plan,
        &progress,
        snapshot.mutations.as_slice().last(),
        error,
    )
}

fn exact_effect_failure_progress_is_valid(
    plan: &ResponsePlan,
    progress: &[ResponseEffectProgress],
    prior_mutation: Option<&ResponseMutationRecord>,
    error: &ErrorCode,
) -> bool {
    if progress
        .iter()
        .filter(|effect| **effect == ResponseEffectProgress::ApplyFailed)
        .count()
        != 1
        || progress.iter().any(|effect| {
            !matches!(
                effect,
                ResponseEffectProgress::Planned | ResponseEffectProgress::ApplyFailed
            )
        })
    {
        return false;
    }
    let Some(ResponseMutationRecord::EffectFailed(failed)) = prior_mutation else {
        return false;
    };
    failed.error_code == *error
        && plan
            .effects
            .as_slice()
            .iter()
            .position(|effect| effect.effect_id == failed.effect_id)
            .and_then(|index| progress.get(index))
            == Some(&ResponseEffectProgress::ApplyFailed)
}

fn transition_due_at(
    snapshot: &ResponseSnapshot,
    request: &ResponseTransitionRequest,
    actual_target: ResponseState,
) -> Result<Option<u64>, StateMachineError> {
    Ok(match actual_target {
        ResponseState::Planned => return Err(StateMachineError::InvalidTransition),
        ResponseState::AwaitingApproval | ResponseState::Active => {
            Some(snapshot.plan.expires_at_unix_ms)
        }
        ResponseState::Applying => request.applying_lease_expires_at_unix_ms,
        ResponseState::ApplyPartial
        | ResponseState::Expiring
        | ResponseState::RollingBack
        | ResponseState::RollbackPartial => Some(request.occurred_at_unix_ms),
        ResponseState::Cancelled
        | ResponseState::Expired
        | ResponseState::Failed
        | ResponseState::Lifted => None,
    })
}

fn transition_mutation(
    snapshot: &ResponseSnapshot,
    request: &ResponseTransitionRequest,
    context: TransitionMutationContext,
) -> Result<ResponseMutationRecord, StateMachineError> {
    let TransitionMutationContext {
        from_state,
        actual_target,
        prior_receipt_id,
        generation,
        scheduler_lease_owner_id,
        scheduler_fencing_token,
    } = context;
    let body = if matches!(
        actual_target,
        ResponseState::Failed | ResponseState::ApplyPartial | ResponseState::RollbackPartial
    ) {
        CanonicalMutationBody::Failed {
            generation,
            from_state,
            to_state: actual_target,
            error_code: request
                .error_code
                .clone()
                .ok_or(StateMachineError::InvalidFailureRecord)?,
            scheduler_lease_owner_id,
            scheduler_fencing_token,
            prior_receipt_id,
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        }
    } else if actual_target.is_terminal() {
        CanonicalMutationBody::Final {
            generation,
            from_state,
            final_state: actual_target,
            scheduler_lease_owner_id,
            scheduler_fencing_token,
            prior_receipt_id,
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        }
    } else {
        CanonicalMutationBody::Transition {
            generation,
            from_state,
            to_state: actual_target,
            cause: transition_cause(snapshot, request, actual_target),
            applying_lease_expires_at_unix_ms: request.applying_lease_expires_at_unix_ms,
            scheduler_lease_owner_id,
            scheduler_fencing_token,
            prior_receipt_id,
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        }
    };
    finalize_mutation(&snapshot.plan, body)
}

fn transition_cause(
    snapshot: &ResponseSnapshot,
    request: &ResponseTransitionRequest,
    actual_target: ResponseState,
) -> ResponseTransitionCause {
    if snapshot.state == ResponseState::Applying && actual_target == ResponseState::Applying {
        return ResponseTransitionCause::ApplyingLeaseRenewed;
    }
    match actual_target {
        ResponseState::AwaitingApproval => ResponseTransitionCause::ApprovalRequested,
        ResponseState::Applying if snapshot.state == ResponseState::AwaitingApproval => {
            ResponseTransitionCause::ApprovalSatisfied
        }
        ResponseState::Applying => ResponseTransitionCause::ApplyStarted,
        ResponseState::Active => ResponseTransitionCause::ApplyCompleted,
        ResponseState::Expiring | ResponseState::Expired => ResponseTransitionCause::PlanExpired,
        ResponseState::RollingBack if snapshot.state == ResponseState::RollbackPartial => {
            ResponseTransitionCause::RollbackRetry
        }
        ResponseState::RollingBack => ResponseTransitionCause::RollbackRequested,
        ResponseState::Cancelled => ResponseTransitionCause::OperatorCancelled,
        ResponseState::Lifted => ResponseTransitionCause::RollbackCompleted,
        ResponseState::RollbackPartial => ResponseTransitionCause::RollbackFailed,
        ResponseState::ApplyPartial
            if request
                .error_code
                .as_ref()
                .is_some_and(|code| code.as_str() == APPLYING_LEASE_EXPIRED_ERROR) =>
        {
            ResponseTransitionCause::ApplyingLeaseExpired
        }
        ResponseState::ApplyPartial | ResponseState::Failed => {
            ResponseTransitionCause::ValidationFailed
        }
        ResponseState::Planned => ResponseTransitionCause::ValidationFailed,
    }
}

fn validate_effect_mutation(
    snapshot: &ResponseSnapshot,
    request: &EffectMutationRequest,
    receipt: &EffectReceiptContext,
    scheduler_work: Option<&ScheduledWork>,
) -> Result<(), StateMachineError> {
    let effect = snapshot
        .plan
        .effect(&request.effect_id)
        .ok_or(StateMachineError::UnknownEffect)?;
    let progress = snapshot
        .effect_progress(&request.effect_id)
        .ok_or(StateMachineError::UnknownEffect)?;
    let apply_is_blocked = snapshot.plan.effects.as_slice().iter().any(|candidate| {
        matches!(
            snapshot.effect_progress(&candidate.effect_id),
            Some(ResponseEffectProgress::Requested | ResponseEffectProgress::ApplyFailed)
        )
    });
    let applying_mutation = matches!(
        &request.mutation,
        EffectMutation::Requested | EffectMutation::Applied { .. } | EffectMutation::Failed { .. }
    );
    let late_authoritative_takeover =
        late_authoritative_effect_takeover_is_valid(snapshot, request, receipt, scheduler_work);
    let reserved_not_executed_failure = matches!(
        &request.mutation,
        EffectMutation::Failed { error_code }
            if error_code.as_str() == "response.effect_not_executed"
    );
    if reserved_not_executed_failure && !late_authoritative_takeover {
        return Err(StateMachineError::InvalidEffectLifecycle);
    }
    if applying_mutation
        && snapshot
            .applying_lease_expires_at_unix_ms
            .is_none_or(|lease| request.occurred_at_unix_ms >= lease)
        && !late_authoritative_takeover
    {
        return Err(StateMachineError::InvalidEffectLifecycle);
    }
    let valid = match &request.mutation {
        EffectMutation::Requested => {
            snapshot.state == ResponseState::Applying
                && progress == ResponseEffectProgress::Planned
                && !apply_is_blocked
        }
        EffectMutation::Applied { .. } | EffectMutation::Failed { .. } => {
            snapshot.state == ResponseState::Applying
                && progress == ResponseEffectProgress::Requested
        }
        EffectMutation::RollbackRequested => {
            effect.kind.is_reversible()
                && snapshot.state == ResponseState::RollingBack
                && matches!(
                    progress,
                    ResponseEffectProgress::Applied | ResponseEffectProgress::RollbackFailed
                )
        }
        EffectMutation::RollbackRestored { .. } | EffectMutation::RollbackFailed { .. } => {
            effect.kind.is_reversible()
                && snapshot.state == ResponseState::RollingBack
                && progress == ResponseEffectProgress::RollbackRequested
        }
    };
    if valid {
        Ok(())
    } else {
        Err(StateMachineError::InvalidEffectLifecycle)
    }
}

fn late_authoritative_effect_takeover_is_valid(
    snapshot: &ResponseSnapshot,
    request: &EffectMutationRequest,
    receipt: &EffectReceiptContext,
    scheduler_work: Option<&ScheduledWork>,
) -> bool {
    if !matches!(
        &request.mutation,
        EffectMutation::Applied { .. } | EffectMutation::Failed { .. }
    ) || snapshot.state != ResponseState::Applying
        || snapshot.effect_progress(&request.effect_id) != Some(ResponseEffectProgress::Requested)
        || receipt.effect_transition_id.is_none()
        || receipt.prior_receipt_id.is_none()
    {
        return false;
    }
    let Some(work) = scheduler_work else {
        return false;
    };
    if work.tenant_id != snapshot.plan.tenant_id
        || work.action_id != snapshot.plan.action_id
        || work.lease_owner_id.as_str().is_empty()
        || work.lease_expires_at_unix_ms <= request.occurred_at_unix_ms
        || receipt.scheduler_lease_owner_id.as_ref() != Some(&work.lease_owner_id)
        || receipt.scheduler_fencing_token != work.fencing_token
    {
        return false;
    }

    let mut highest_scheduler_fencing_token = 0;
    let mut prior_effect_generation = 0;
    let mut prior_effect_is_receipt_backed = false;
    for mutation in snapshot.mutations.as_slice() {
        if let Some((_, token)) = mutation_scheduler_fence(mutation) {
            highest_scheduler_fencing_token = highest_scheduler_fencing_token.max(token);
        }
        let Some((effect_id, effect_generation, scheduler_lease_owner_id, _, transition_id)) =
            effect_receipt_metadata(mutation)
        else {
            continue;
        };
        if effect_id == &request.effect_id {
            prior_effect_generation = prior_effect_generation.max(effect_generation);
            prior_effect_is_receipt_backed |= scheduler_lease_owner_id.is_some()
                && (transition_id.is_some()
                    || matches!(mutation, ResponseMutationRecord::EffectRequested(_)));
        }
    }
    prior_effect_is_receipt_backed
        && receipt.effect_generation > prior_effect_generation
        && receipt.scheduler_fencing_token > highest_scheduler_fencing_token
}

fn mutation_scheduler_fence(
    mutation: &ResponseMutationRecord,
) -> Option<(Option<&LeaseOwnerId>, u64)> {
    match mutation {
        ResponseMutationRecord::Transition(record) => record
            .scheduler_fencing_token
            .map(|token| (record.scheduler_lease_owner_id.as_ref(), token)),
        ResponseMutationRecord::EffectRequested(record) => Some((
            record.scheduler_lease_owner_id.as_ref(),
            record.scheduler_fencing_token,
        )),
        ResponseMutationRecord::EffectApplied(record) => Some((
            record.scheduler_lease_owner_id.as_ref(),
            record.scheduler_fencing_token,
        )),
        ResponseMutationRecord::EffectFailed(record) => Some((
            record.scheduler_lease_owner_id.as_ref(),
            record.scheduler_fencing_token,
        )),
        ResponseMutationRecord::Rollback(record) => Some((
            record.scheduler_lease_owner_id.as_ref(),
            record.scheduler_fencing_token,
        )),
        ResponseMutationRecord::Failed(record) => record
            .scheduler_fencing_token
            .map(|token| (record.scheduler_lease_owner_id.as_ref(), token)),
        ResponseMutationRecord::Final(record) => record
            .scheduler_fencing_token
            .map(|token| (record.scheduler_lease_owner_id.as_ref(), token)),
        ResponseMutationRecord::Requested(_) => None,
    }
}

fn validate_effect_receipt_order(
    snapshot: &ResponseSnapshot,
    request: &EffectMutationRequest,
    receipt: &EffectReceiptContext,
) -> Result<(), StateMachineError> {
    let state_only = effect_receipt_is_state_only(
        receipt.effect_generation,
        receipt.scheduler_lease_owner_id.as_ref(),
        receipt.scheduler_fencing_token,
        receipt.effect_transition_id.as_ref(),
    );
    let non_request = !matches!(&request.mutation, EffectMutation::Requested);
    if !non_request && receipt.effect_transition_id.is_some() {
        return Err(StateMachineError::InvalidEffectLifecycle);
    }

    let mut highest_scheduler_fencing_token = 0;
    let mut prior_effect_generation = 0;
    let mut receipt_backed_effect_seen = false;
    for mutation in snapshot.mutations.as_slice() {
        let Some((
            effect_id,
            effect_generation,
            scheduler_lease_owner_id,
            scheduler_fencing_token,
            transition_id,
        )) = effect_receipt_metadata(mutation)
        else {
            continue;
        };
        let prior_state_only = effect_receipt_is_state_only(
            effect_generation,
            scheduler_lease_owner_id,
            scheduler_fencing_token,
            transition_id,
        );
        if !prior_state_only {
            highest_scheduler_fencing_token =
                highest_scheduler_fencing_token.max(scheduler_fencing_token);
        }
        if effect_id == &request.effect_id {
            prior_effect_generation = prior_effect_generation.max(effect_generation);
            receipt_backed_effect_seen |= !prior_state_only;
        }
    }

    if non_request
        && receipt.effect_transition_id.is_none()
        && (snapshot.execution_dispatch.is_some() || receipt_backed_effect_seen)
    {
        return Err(StateMachineError::InvalidEffectLifecycle);
    }
    if (state_only && receipt_backed_effect_seen)
        || (!state_only
            && (receipt.effect_generation <= prior_effect_generation
                || receipt.scheduler_fencing_token < highest_scheduler_fencing_token))
    {
        return Err(StateMachineError::InvalidEffectLifecycle);
    }
    Ok(())
}

struct TransitionMutationContext {
    from_state: ResponseState,
    actual_target: ResponseState,
    prior_receipt_id: OpaqueReceiptRef,
    generation: u64,
    scheduler_lease_owner_id: Option<LeaseOwnerId>,
    scheduler_fencing_token: Option<u64>,
}

type EffectReceiptMetadata<'a> = (
    &'a EffectId,
    u64,
    Option<&'a LeaseOwnerId>,
    u64,
    Option<&'a RecordId>,
);

fn effect_receipt_metadata(mutation: &ResponseMutationRecord) -> Option<EffectReceiptMetadata<'_>> {
    match mutation {
        ResponseMutationRecord::EffectRequested(record) => Some((
            &record.effect_id,
            record.effect_generation,
            record.scheduler_lease_owner_id.as_ref(),
            record.scheduler_fencing_token,
            None,
        )),
        ResponseMutationRecord::EffectApplied(record) => Some((
            &record.effect_id,
            record.effect_generation,
            record.scheduler_lease_owner_id.as_ref(),
            record.scheduler_fencing_token,
            record.effect_transition_id.as_ref(),
        )),
        ResponseMutationRecord::EffectFailed(record) => Some((
            &record.effect_id,
            record.effect_generation,
            record.scheduler_lease_owner_id.as_ref(),
            record.scheduler_fencing_token,
            record.effect_transition_id.as_ref(),
        )),
        ResponseMutationRecord::Rollback(record) => Some((
            &record.effect_id,
            record.effect_generation,
            record.scheduler_lease_owner_id.as_ref(),
            record.scheduler_fencing_token,
            record.effect_transition_id.as_ref(),
        )),
        ResponseMutationRecord::Requested(_)
        | ResponseMutationRecord::Transition(_)
        | ResponseMutationRecord::Failed(_)
        | ResponseMutationRecord::Final(_) => None,
    }
}

fn effect_receipt_is_state_only(
    effect_generation: u64,
    scheduler_lease_owner_id: Option<&LeaseOwnerId>,
    scheduler_fencing_token: u64,
    effect_transition_id: Option<&RecordId>,
) -> bool {
    effect_generation == 1
        && scheduler_lease_owner_id.is_none()
        && scheduler_fencing_token == 1
        && effect_transition_id.is_none()
}

fn effect_mutation_record(
    plan: &ResponsePlan,
    request: &EffectMutationRequest,
    receipt: &EffectReceiptContext,
    prior_receipt_id: OpaqueReceiptRef,
    generation: u64,
) -> Result<ResponseMutationRecord, StateMachineError> {
    let body = match &request.mutation {
        EffectMutation::Requested => CanonicalMutationBody::EffectRequested {
            generation,
            effect_id: request.effect_id.clone(),
            effect_generation: receipt.effect_generation,
            scheduler_lease_owner_id: receipt.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: receipt.scheduler_fencing_token,
            prior_receipt_id,
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        },
        EffectMutation::Applied {
            resulting_version_hash,
        } => CanonicalMutationBody::EffectApplied {
            generation,
            effect_id: request.effect_id.clone(),
            effect_generation: receipt.effect_generation,
            resulting_version_hash: *resulting_version_hash,
            scheduler_lease_owner_id: receipt.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: receipt.scheduler_fencing_token,
            effect_transition_id: receipt.effect_transition_id.clone(),
            prior_receipt_id,
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        },
        EffectMutation::Failed { error_code } => CanonicalMutationBody::EffectFailed {
            generation,
            effect_id: request.effect_id.clone(),
            effect_generation: receipt.effect_generation,
            error_code: error_code.clone(),
            scheduler_lease_owner_id: receipt.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: receipt.scheduler_fencing_token,
            effect_transition_id: receipt.effect_transition_id.clone(),
            prior_receipt_id,
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        },
        EffectMutation::RollbackRequested => CanonicalMutationBody::Rollback {
            generation,
            effect_id: request.effect_id.clone(),
            effect_generation: receipt.effect_generation,
            outcome: ResponseRollbackOutcome::Requested,
            scheduler_lease_owner_id: receipt.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: receipt.scheduler_fencing_token,
            effect_transition_id: receipt.effect_transition_id.clone(),
            prior_receipt_id,
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        },
        EffectMutation::RollbackRestored {
            resulting_version_hash,
        } => CanonicalMutationBody::Rollback {
            generation,
            effect_id: request.effect_id.clone(),
            effect_generation: receipt.effect_generation,
            outcome: ResponseRollbackOutcome::Restored {
                resulting_version_hash: *resulting_version_hash,
            },
            scheduler_lease_owner_id: receipt.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: receipt.scheduler_fencing_token,
            effect_transition_id: receipt.effect_transition_id.clone(),
            prior_receipt_id,
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        },
        EffectMutation::RollbackFailed { error_code } => CanonicalMutationBody::Rollback {
            generation,
            effect_id: request.effect_id.clone(),
            effect_generation: receipt.effect_generation,
            outcome: ResponseRollbackOutcome::Failed {
                error_code: error_code.clone(),
            },
            scheduler_lease_owner_id: receipt.scheduler_lease_owner_id.clone(),
            scheduler_fencing_token: receipt.scheduler_fencing_token,
            effect_transition_id: receipt.effect_transition_id.clone(),
            prior_receipt_id,
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        },
    };
    finalize_mutation(plan, body)
}

fn push_mutation(
    snapshot: &mut ResponseSnapshot,
    mutation: ResponseMutationRecord,
) -> Result<(), StateMachineError> {
    if snapshot.mutations.len() >= MAX_RESPONSE_MUTATIONS {
        return Err(StateMachineError::MutationLimit);
    }
    let mut mutations = snapshot.mutations.clone().into_vec();
    mutations.push(mutation);
    snapshot.mutations =
        BoundedVec::new(mutations).map_err(|_| StateMachineError::MutationLimit)?;
    Ok(())
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

#[derive(Serialize)]
struct EffectCommitment<'a> {
    action_id: &'a str,
    ordinal: u16,
    spec: &'a ResponseEffectSpec,
}

fn derive_effect_id(
    action_id: &chio_security_types::ports::ActionId,
    ordinal: u16,
    spec: &ResponseEffectSpec,
) -> Result<EffectId, StateMachineError> {
    let digest = domain_hash(
        EFFECT_ID_DOMAIN,
        &EffectCommitment {
            action_id: action_id.as_str(),
            ordinal,
            spec,
        },
    )?;
    EffectId::new(format!("response_effect_{}", hex_bytes(digest.as_bytes())))
        .map_err(|_| StateMachineError::Canonical)
}

fn compute_plan_hash(plan: &ResponsePlan) -> Result<[u8; 32], StateMachineError> {
    let body = serde_json::to_value(plan.authorization_body())
        .map_err(|_| StateMachineError::Canonical)?;
    let digest = GovernedResponsePlanIntentBody::compute_plan_body_digest(&body)
        .map_err(|_| StateMachineError::InvalidPlan)?;
    Ok(*digest.as_bytes())
}

include!("state_machine_parts/canonicalization_and_errors.inc");
