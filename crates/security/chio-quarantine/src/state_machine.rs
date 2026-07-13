use chio_core_types::{
    canonical_json_bytes, capability::governance::CHIO_RESPONSE_PLAN_HASH_DOMAIN, sha256,
};
use chio_security_types::ports::{
    BoundedVec, CanonicalBody, CreateOutcome, Digest32, EffectId, ErrorCode, PortError, RecordId,
    RecordIdSet, ResponseCasRequest, ResponsePlanRecord, ResponseStore,
};
use chio_security_types::{
    is_legal_response_transition, PlannedResponseEffect, PlannedResponseEffects,
    ResponseEffectAppliedRecord, ResponseEffectFailedRecord, ResponseEffectProgress,
    ResponseEffectRequestedRecord, ResponseEffectSpec, ResponseFailureRecord, ResponseFinalRecord,
    ResponseMutationLog, ResponseMutationRecord, ResponsePlan, ResponsePlanInput,
    ResponseRequestedRecord, ResponseRollbackOutcome, ResponseRollbackRecord, ResponseShapeError,
    ResponseSnapshot, ResponseState, ResponseTransitionCause, ResponseTransitionRecord,
    MAX_RESPONSE_EFFECTS, RESPONSE_STATE_SCHEMA_VERSION,
};
use serde::Serialize;
use std::sync::Arc;
use thiserror::Error;

const AFFECTED_SET_HASH_DOMAIN: &[u8] = b"chio.response-affected-set.v1\0";
const EFFECT_ID_DOMAIN: &[u8] = b"chio.response-effect.v1\0";
const REQUEST_ID_DOMAIN: &[u8] = b"chio.response-request.v1\0";
const TRANSITION_ID_DOMAIN: &[u8] = b"chio.response-transition.v1\0";

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResponseTransitionRequest {
    pub expected_generation: u64,
    pub target_state: ResponseState,
    pub occurred_at_unix_ms: u64,
    pub applying_lease_expires_at_unix_ms: Option<u64>,
    pub error_code: Option<ErrorCode>,
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
                occurred_at_unix_ms: plan.created_at_unix_ms,
            },
        )])
        .map_err(|_| StateMachineError::MutationLimit)?;
        let snapshot = ResponseSnapshot {
            schema_version: RESPONSE_STATE_SCHEMA_VERSION,
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
        let mut snapshot = decode_response_record(current)?;
        require_generation(&snapshot, request.expected_generation)?;
        let from_state = snapshot.state;
        let actual_target = if from_state == ResponseState::Applying
            && request.target_state == ResponseState::Failed
            && snapshot.any_effect_applied()
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
        let mutation = transition_mutation(
            &snapshot,
            request,
            from_state,
            actual_target,
            next_generation,
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
        self.commit(current, record, transition_id)
    }

    pub fn record_effect(
        &self,
        current: &ResponsePlanRecord,
        request: &EffectMutationRequest,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        let mut snapshot = decode_response_record(current)?;
        require_generation(&snapshot, request.expected_generation)?;
        if snapshot.plan.effect(&request.effect_id).is_none() {
            return Err(StateMachineError::UnknownEffect);
        }
        validate_effect_mutation(&snapshot, request)?;
        let next_generation = snapshot
            .generation
            .checked_add(1)
            .ok_or(StateMachineError::GenerationOverflow)?;
        let mutation = effect_mutation_record(&snapshot.plan, request, next_generation)?;
        let transition_id = mutation.transition_id().clone();
        push_mutation(&mut snapshot, mutation)?;
        snapshot.generation = next_generation;
        let record = encode_response_record(&snapshot)?;
        self.commit(current, record, transition_id)
    }

    pub fn handle_due(
        &self,
        current: &ResponsePlanRecord,
        expected_generation: u64,
        now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, StateMachineError> {
        let snapshot = decode_response_record(current)?;
        require_generation(&snapshot, expected_generation)?;
        let due = snapshot.due_at_unix_ms.ok_or(StateMachineError::NotDue)?;
        if now_unix_ms < due {
            return Err(StateMachineError::NotDue);
        }
        let occurred_at_unix_ms = due;
        match snapshot.state {
            ResponseState::Planned | ResponseState::AwaitingApproval => self.transition(
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
                let partial = self.transition(
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
                self.transition(
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
                let expiring = self.transition(
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
                self.transition(
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
            | ResponseState::RollbackPartial => self.transition(
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
    let affected_set_hash = domain_hash(
        AFFECTED_SET_HASH_DOMAIN,
        &AffectedSetCommitment {
            tenant_id: input.tenant_id.as_str(),
            affected_ids: affected_ids.as_slice(),
        },
    )?;
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
        tenant_id: input.tenant_id,
        policy_version: input.policy_version,
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
    plan.plan_hash = compute_plan_hash(&plan)?;
    validate_plan(&plan)?;
    Ok(plan)
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

fn encode_response_record(
    snapshot: &ResponseSnapshot,
) -> Result<ResponsePlanRecord, StateMachineError> {
    validate_snapshot(snapshot)?;
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
        != domain_hash(
            AFFECTED_SET_HASH_DOMAIN,
            &AffectedSetCommitment {
                tenant_id: plan.tenant_id.as_str(),
                affected_ids: plan.affected_ids.as_slice(),
            },
        )?
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
    }
    if plan.plan_hash != compute_plan_hash(plan)? {
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
    validate_plan(&snapshot.plan)?;
    if snapshot.schema_version != RESPONSE_STATE_SCHEMA_VERSION
        || snapshot.mutations.is_empty()
        || snapshot.mutations.len() != usize_from_generation(snapshot.generation)?
    {
        return Err(StateMachineError::InvalidRecord);
    }
    let request = match &snapshot.mutations.as_slice()[0] {
        ResponseMutationRecord::Requested(record)
            if record.generation == 0
                && record.occurred_at_unix_ms == snapshot.plan.created_at_unix_ms
                && record.transition_id == request_id(&snapshot.plan)? =>
        {
            record
        }
        _ => return Err(StateMachineError::InvalidRecord),
    };
    let _ = request;
    let mut replay_state = ResponseState::Planned;
    let mut replay_applying_lease_expires_at_unix_ms = None;
    let mut any_effect_applied = false;
    let mut page_required = false;
    let mut previous_occurred_at_unix_ms = snapshot.plan.created_at_unix_ms;
    let mut progress = vec![ResponseEffectProgress::Planned; snapshot.plan.effects.len()];
    for (index, mutation) in snapshot.mutations.as_slice().iter().enumerate().skip(1) {
        let expected_generation =
            u64::try_from(index).map_err(|_| StateMachineError::InvalidRecord)?;
        if mutation.generation() != expected_generation
            || mutation.transition_id() != &mutation_transition_id(&snapshot.plan, mutation)?
            || mutation.occurred_at_unix_ms() < previous_occurred_at_unix_ms
        {
            return Err(StateMachineError::InvalidRecord);
        }
        previous_occurred_at_unix_ms = mutation.occurred_at_unix_ms();
        match mutation {
            ResponseMutationRecord::Requested(_) => return Err(StateMachineError::InvalidRecord),
            ResponseMutationRecord::Transition(record) => {
                let applying_lease_is_valid = match record.to_state {
                    ResponseState::Applying => record
                        .applying_lease_expires_at_unix_ms
                        .is_some_and(|lease| {
                            lease > record.occurred_at_unix_ms
                                && lease <= snapshot.plan.expires_at_unix_ms
                        }),
                    _ => record.applying_lease_expires_at_unix_ms.is_none(),
                };
                if record.from_state != replay_state
                    || !is_legal_response_transition(record.from_state, record.to_state)
                    || expected_transition_cause(record.from_state, record.to_state)
                        != Some(record.cause)
                    || !applying_lease_is_valid
                    || (record.to_state == ResponseState::Active
                        && (progress
                            .iter()
                            .any(|item| *item != ResponseEffectProgress::Applied)
                            || replay_applying_lease_expires_at_unix_ms
                                .is_none_or(|lease| record.occurred_at_unix_ms >= lease)))
                    || (record.to_state == ResponseState::Expiring
                        && record.occurred_at_unix_ms < snapshot.plan.expires_at_unix_ms)
                {
                    return Err(StateMachineError::InvalidRecord);
                }
                replay_state = record.to_state;
                replay_applying_lease_expires_at_unix_ms = record.applying_lease_expires_at_unix_ms;
            }
            ResponseMutationRecord::EffectRequested(record) => {
                if replay_state != ResponseState::Applying {
                    return Err(StateMachineError::InvalidRecord);
                }
                let effect_index = effect_index(&snapshot.plan, &record.effect_id)?;
                if progress[effect_index] != ResponseEffectProgress::Planned {
                    return Err(StateMachineError::InvalidRecord);
                }
                progress[effect_index] = ResponseEffectProgress::Requested;
            }
            ResponseMutationRecord::EffectApplied(record) => {
                if replay_state != ResponseState::Applying {
                    return Err(StateMachineError::InvalidRecord);
                }
                let effect_index = effect_index(&snapshot.plan, &record.effect_id)?;
                if progress[effect_index] != ResponseEffectProgress::Requested {
                    return Err(StateMachineError::InvalidRecord);
                }
                progress[effect_index] = ResponseEffectProgress::Applied;
                any_effect_applied = true;
            }
            ResponseMutationRecord::EffectFailed(record) => {
                if replay_state != ResponseState::Applying {
                    return Err(StateMachineError::InvalidRecord);
                }
                let effect_index = effect_index(&snapshot.plan, &record.effect_id)?;
                if progress[effect_index] != ResponseEffectProgress::Requested {
                    return Err(StateMachineError::InvalidRecord);
                }
                progress[effect_index] = ResponseEffectProgress::ApplyFailed;
            }
            ResponseMutationRecord::Rollback(record) => {
                if replay_state != ResponseState::RollingBack {
                    return Err(StateMachineError::InvalidRecord);
                }
                let effect_index = effect_index(&snapshot.plan, &record.effect_id)?;
                if !snapshot.plan.effects.as_slice()[effect_index]
                    .kind
                    .is_reversible()
                {
                    return Err(StateMachineError::InvalidRecord);
                }
                progress[effect_index] =
                    replay_rollback_progress(progress[effect_index], &record.outcome)?;
            }
            ResponseMutationRecord::Failed(record) => {
                if record.from_state != replay_state
                    || !is_legal_response_transition(record.from_state, record.to_state)
                    || !matches!(
                        record.to_state,
                        ResponseState::Failed
                            | ResponseState::ApplyPartial
                            | ResponseState::RollbackPartial
                    )
                    || (record.to_state == ResponseState::Failed && any_effect_applied)
                    || (record.to_state == ResponseState::Failed
                        && record.from_state == ResponseState::Applying
                        && replay_applying_lease_expires_at_unix_ms
                            .is_none_or(|lease| record.occurred_at_unix_ms >= lease))
                    || (record.to_state == ResponseState::RollbackPartial
                        && !progress.contains(&ResponseEffectProgress::RollbackFailed))
                {
                    return Err(StateMachineError::InvalidRecord);
                }
                if record.to_state == ResponseState::RollbackPartial {
                    page_required = true;
                }
                replay_state = record.to_state;
                replay_applying_lease_expires_at_unix_ms = None;
            }
            ResponseMutationRecord::Final(record) => {
                if record.from_state != replay_state
                    || !record.final_state.is_terminal()
                    || record.final_state == ResponseState::Failed
                    || !is_legal_response_transition(record.from_state, record.final_state)
                    || (record.final_state == ResponseState::Expired
                        && record.occurred_at_unix_ms < snapshot.plan.expires_at_unix_ms)
                {
                    return Err(StateMachineError::InvalidRecord);
                }
                replay_state = record.final_state;
                replay_applying_lease_expires_at_unix_ms = None;
            }
        }
    }
    if replay_state != snapshot.state
        || replay_applying_lease_expires_at_unix_ms != snapshot.applying_lease_expires_at_unix_ms
        || snapshot.operator_page_required != page_required
    {
        return Err(StateMachineError::InvalidRecord);
    }
    validate_due_shape(snapshot)?;
    if snapshot.state == ResponseState::Lifted
        && !snapshot.all_applied_reversible_effects_restored()
    {
        return Err(StateMachineError::InvalidRecord);
    }
    if snapshot.state == ResponseState::RollbackPartial
        && (!snapshot.operator_page_required || !snapshot.has_rollback_failure())
    {
        return Err(StateMachineError::InvalidRecord);
    }
    Ok(())
}

fn validate_due_shape(snapshot: &ResponseSnapshot) -> Result<(), StateMachineError> {
    match snapshot.state {
        ResponseState::Planned | ResponseState::AwaitingApproval | ResponseState::Active => {
            if snapshot.due_at_unix_ms != Some(snapshot.plan.expires_at_unix_ms)
                || snapshot.applying_lease_expires_at_unix_ms.is_some()
            {
                return Err(StateMachineError::InvalidRecord);
            }
        }
        ResponseState::Applying => {
            if snapshot.due_at_unix_ms != snapshot.applying_lease_expires_at_unix_ms
                || snapshot.due_at_unix_ms.is_none()
            {
                return Err(StateMachineError::InvalidRecord);
            }
        }
        ResponseState::ApplyPartial
        | ResponseState::Expiring
        | ResponseState::RollingBack
        | ResponseState::RollbackPartial => {
            if snapshot.due_at_unix_ms.is_none()
                || snapshot.applying_lease_expires_at_unix_ms.is_some()
            {
                return Err(StateMachineError::InvalidRecord);
            }
        }
        ResponseState::Cancelled
        | ResponseState::Expired
        | ResponseState::Failed
        | ResponseState::Lifted => {
            if snapshot.due_at_unix_ms.is_some()
                || snapshot.applying_lease_expires_at_unix_ms.is_some()
            {
                return Err(StateMachineError::InvalidRecord);
            }
        }
    }
    Ok(())
}

fn validate_transition_request(
    snapshot: &ResponseSnapshot,
    request: &ResponseTransitionRequest,
    actual_target: ResponseState,
) -> Result<(), StateMachineError> {
    if actual_target == ResponseState::Applying {
        let lease = request
            .applying_lease_expires_at_unix_ms
            .ok_or(StateMachineError::InvalidTiming)?;
        if lease <= request.occurred_at_unix_ms || lease > snapshot.plan.expires_at_unix_ms {
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
    if snapshot.state == ResponseState::Applying && actual_target == ResponseState::Failed {
        let lease = snapshot
            .applying_lease_expires_at_unix_ms
            .ok_or(StateMachineError::InvalidRecord)?;
        if request.occurred_at_unix_ms >= lease {
            return Err(StateMachineError::InvalidTiming);
        }
    }
    if actual_target == ResponseState::Failed && snapshot.any_effect_applied() {
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
    from_state: ResponseState,
    actual_target: ResponseState,
    generation: u64,
) -> Result<ResponseMutationRecord, StateMachineError> {
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
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        }
    } else if actual_target.is_terminal() {
        CanonicalMutationBody::Final {
            generation,
            from_state,
            final_state: actual_target,
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        }
    } else {
        CanonicalMutationBody::Transition {
            generation,
            from_state,
            to_state: actual_target,
            cause: transition_cause(snapshot, request, actual_target),
            applying_lease_expires_at_unix_ms: request.applying_lease_expires_at_unix_ms,
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        }
    };
    finalize_mutation(&snapshot.plan, body)
}

const fn expected_transition_cause(
    from_state: ResponseState,
    to_state: ResponseState,
) -> Option<ResponseTransitionCause> {
    match (from_state, to_state) {
        (ResponseState::Planned, ResponseState::AwaitingApproval) => {
            Some(ResponseTransitionCause::ApprovalRequested)
        }
        (ResponseState::Planned, ResponseState::Applying) => {
            Some(ResponseTransitionCause::ApplyStarted)
        }
        (ResponseState::AwaitingApproval, ResponseState::Applying) => {
            Some(ResponseTransitionCause::ApprovalSatisfied)
        }
        (ResponseState::Applying, ResponseState::Active) => {
            Some(ResponseTransitionCause::ApplyCompleted)
        }
        (ResponseState::Active, ResponseState::Expiring) => {
            Some(ResponseTransitionCause::PlanExpired)
        }
        (
            ResponseState::ApplyPartial | ResponseState::Active | ResponseState::Expiring,
            ResponseState::RollingBack,
        ) => Some(ResponseTransitionCause::RollbackRequested),
        (ResponseState::RollbackPartial, ResponseState::RollingBack) => {
            Some(ResponseTransitionCause::RollbackRetry)
        }
        _ => None,
    }
}

fn transition_cause(
    snapshot: &ResponseSnapshot,
    request: &ResponseTransitionRequest,
    actual_target: ResponseState,
) -> ResponseTransitionCause {
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
                .is_some_and(|code| code.as_str() == "response.applying_lease_expired") =>
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
) -> Result<(), StateMachineError> {
    let effect = snapshot
        .plan
        .effect(&request.effect_id)
        .ok_or(StateMachineError::UnknownEffect)?;
    let progress = snapshot
        .effect_progress(&request.effect_id)
        .ok_or(StateMachineError::UnknownEffect)?;
    let valid = match request.mutation {
        EffectMutation::Requested => {
            snapshot.state == ResponseState::Applying && progress == ResponseEffectProgress::Planned
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

fn effect_mutation_record(
    plan: &ResponsePlan,
    request: &EffectMutationRequest,
    generation: u64,
) -> Result<ResponseMutationRecord, StateMachineError> {
    let body = match &request.mutation {
        EffectMutation::Requested => CanonicalMutationBody::EffectRequested {
            generation,
            effect_id: request.effect_id.clone(),
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        },
        EffectMutation::Applied {
            resulting_version_hash,
        } => CanonicalMutationBody::EffectApplied {
            generation,
            effect_id: request.effect_id.clone(),
            resulting_version_hash: *resulting_version_hash,
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        },
        EffectMutation::Failed { error_code } => CanonicalMutationBody::EffectFailed {
            generation,
            effect_id: request.effect_id.clone(),
            error_code: error_code.clone(),
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        },
        EffectMutation::RollbackRequested => CanonicalMutationBody::Rollback {
            generation,
            effect_id: request.effect_id.clone(),
            outcome: ResponseRollbackOutcome::Requested,
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        },
        EffectMutation::RollbackRestored {
            resulting_version_hash,
        } => CanonicalMutationBody::Rollback {
            generation,
            effect_id: request.effect_id.clone(),
            outcome: ResponseRollbackOutcome::Restored {
                resulting_version_hash: *resulting_version_hash,
            },
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        },
        EffectMutation::RollbackFailed { error_code } => CanonicalMutationBody::Rollback {
            generation,
            effect_id: request.effect_id.clone(),
            outcome: ResponseRollbackOutcome::Failed {
                error_code: error_code.clone(),
            },
            occurred_at_unix_ms: request.occurred_at_unix_ms,
        },
    };
    finalize_mutation(plan, body)
}

fn replay_rollback_progress(
    current: ResponseEffectProgress,
    outcome: &ResponseRollbackOutcome,
) -> Result<ResponseEffectProgress, StateMachineError> {
    match (current, outcome) {
        (
            ResponseEffectProgress::Applied | ResponseEffectProgress::RollbackFailed,
            ResponseRollbackOutcome::Requested,
        ) => Ok(ResponseEffectProgress::RollbackRequested),
        (ResponseEffectProgress::RollbackRequested, ResponseRollbackOutcome::Restored { .. }) => {
            Ok(ResponseEffectProgress::Restored)
        }
        (ResponseEffectProgress::RollbackRequested, ResponseRollbackOutcome::Failed { .. }) => {
            Ok(ResponseEffectProgress::RollbackFailed)
        }
        _ => Err(StateMachineError::InvalidRecord),
    }
}

fn effect_index(plan: &ResponsePlan, effect_id: &EffectId) -> Result<usize, StateMachineError> {
    plan.effects
        .as_slice()
        .iter()
        .position(|effect| &effect.effect_id == effect_id)
        .ok_or(StateMachineError::InvalidRecord)
}

fn push_mutation(
    snapshot: &mut ResponseSnapshot,
    mutation: ResponseMutationRecord,
) -> Result<(), StateMachineError> {
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

fn usize_from_generation(generation: u64) -> Result<usize, StateMachineError> {
    let count = generation
        .checked_add(1)
        .ok_or(StateMachineError::InvalidRecord)?;
    usize::try_from(count).map_err(|_| StateMachineError::InvalidRecord)
}

#[derive(Serialize)]
struct AffectedSetCommitment<'a> {
    tenant_id: &'a str,
    affected_ids: &'a [RecordId],
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

fn compute_plan_hash(plan: &ResponsePlan) -> Result<Digest32, StateMachineError> {
    domain_hash(
        CHIO_RESPONSE_PLAN_HASH_DOMAIN.as_bytes(),
        &plan.authorization_body(),
    )
}

#[derive(Serialize)]
struct RequestCommitment<'a> {
    tenant_id: &'a str,
    action_id: &'a str,
    plan_hash: Digest32,
    created_at_unix_ms: u64,
}

fn request_id(plan: &ResponsePlan) -> Result<RecordId, StateMachineError> {
    let digest = domain_hash(
        REQUEST_ID_DOMAIN,
        &RequestCommitment {
            tenant_id: plan.tenant_id.as_str(),
            action_id: plan.action_id.as_str(),
            plan_hash: plan.plan_hash,
            created_at_unix_ms: plan.created_at_unix_ms,
        },
    )?;
    RecordId::new(format!("response_request_{}", hex_bytes(digest.as_bytes())))
        .map_err(|_| StateMachineError::Canonical)
}

#[derive(Serialize)]
struct TransitionCommitment<'a, T> {
    kind: &'a str,
    tenant_id: &'a str,
    action_id: &'a str,
    plan_hash: Digest32,
    expected_generation: u64,
    mutation: &'a T,
}

fn transition_id<T: Serialize>(
    kind: &str,
    plan: &ResponsePlan,
    expected_generation: u64,
    mutation: &T,
) -> Result<RecordId, StateMachineError> {
    let digest = domain_hash(
        TRANSITION_ID_DOMAIN,
        &TransitionCommitment {
            kind,
            tenant_id: plan.tenant_id.as_str(),
            action_id: plan.action_id.as_str(),
            plan_hash: plan.plan_hash,
            expected_generation,
            mutation,
        },
    )?;
    RecordId::new(format!(
        "response_transition_{}",
        hex_bytes(digest.as_bytes())
    ))
    .map_err(|_| StateMachineError::Canonical)
}

#[derive(Serialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
enum CanonicalMutationBody {
    Transition {
        generation: u64,
        from_state: ResponseState,
        to_state: ResponseState,
        cause: ResponseTransitionCause,
        applying_lease_expires_at_unix_ms: Option<u64>,
        occurred_at_unix_ms: u64,
    },
    EffectRequested {
        generation: u64,
        effect_id: EffectId,
        occurred_at_unix_ms: u64,
    },
    EffectApplied {
        generation: u64,
        effect_id: EffectId,
        resulting_version_hash: Digest32,
        occurred_at_unix_ms: u64,
    },
    EffectFailed {
        generation: u64,
        effect_id: EffectId,
        error_code: ErrorCode,
        occurred_at_unix_ms: u64,
    },
    Rollback {
        generation: u64,
        effect_id: EffectId,
        outcome: ResponseRollbackOutcome,
        occurred_at_unix_ms: u64,
    },
    Failed {
        generation: u64,
        from_state: ResponseState,
        to_state: ResponseState,
        error_code: ErrorCode,
        occurred_at_unix_ms: u64,
    },
    Final {
        generation: u64,
        from_state: ResponseState,
        final_state: ResponseState,
        occurred_at_unix_ms: u64,
    },
}

impl CanonicalMutationBody {
    const fn generation(&self) -> u64 {
        match self {
            Self::Transition { generation, .. }
            | Self::EffectRequested { generation, .. }
            | Self::EffectApplied { generation, .. }
            | Self::EffectFailed { generation, .. }
            | Self::Rollback { generation, .. }
            | Self::Failed { generation, .. }
            | Self::Final { generation, .. } => *generation,
        }
    }

    fn from_record(mutation: &ResponseMutationRecord) -> Result<Self, StateMachineError> {
        match mutation {
            ResponseMutationRecord::Requested(_) => Err(StateMachineError::InvalidRecord),
            ResponseMutationRecord::Transition(record) => Ok(Self::Transition {
                generation: record.generation,
                from_state: record.from_state,
                to_state: record.to_state,
                cause: record.cause,
                applying_lease_expires_at_unix_ms: record.applying_lease_expires_at_unix_ms,
                occurred_at_unix_ms: record.occurred_at_unix_ms,
            }),
            ResponseMutationRecord::EffectRequested(record) => Ok(Self::EffectRequested {
                generation: record.generation,
                effect_id: record.effect_id.clone(),
                occurred_at_unix_ms: record.occurred_at_unix_ms,
            }),
            ResponseMutationRecord::EffectApplied(record) => Ok(Self::EffectApplied {
                generation: record.generation,
                effect_id: record.effect_id.clone(),
                resulting_version_hash: record.resulting_version_hash,
                occurred_at_unix_ms: record.occurred_at_unix_ms,
            }),
            ResponseMutationRecord::EffectFailed(record) => Ok(Self::EffectFailed {
                generation: record.generation,
                effect_id: record.effect_id.clone(),
                error_code: record.error_code.clone(),
                occurred_at_unix_ms: record.occurred_at_unix_ms,
            }),
            ResponseMutationRecord::Rollback(record) => Ok(Self::Rollback {
                generation: record.generation,
                effect_id: record.effect_id.clone(),
                outcome: record.outcome.clone(),
                occurred_at_unix_ms: record.occurred_at_unix_ms,
            }),
            ResponseMutationRecord::Failed(record) => Ok(Self::Failed {
                generation: record.generation,
                from_state: record.from_state,
                to_state: record.to_state,
                error_code: record.error_code.clone(),
                occurred_at_unix_ms: record.occurred_at_unix_ms,
            }),
            ResponseMutationRecord::Final(record) => Ok(Self::Final {
                generation: record.generation,
                from_state: record.from_state,
                final_state: record.final_state,
                occurred_at_unix_ms: record.occurred_at_unix_ms,
            }),
        }
    }

    fn into_record(self, transition_id: RecordId) -> ResponseMutationRecord {
        match self {
            Self::Transition {
                generation,
                from_state,
                to_state,
                cause,
                applying_lease_expires_at_unix_ms,
                occurred_at_unix_ms,
            } => ResponseMutationRecord::Transition(ResponseTransitionRecord {
                transition_id,
                generation,
                from_state,
                to_state,
                cause,
                applying_lease_expires_at_unix_ms,
                occurred_at_unix_ms,
            }),
            Self::EffectRequested {
                generation,
                effect_id,
                occurred_at_unix_ms,
            } => ResponseMutationRecord::EffectRequested(ResponseEffectRequestedRecord {
                transition_id,
                generation,
                effect_id,
                occurred_at_unix_ms,
            }),
            Self::EffectApplied {
                generation,
                effect_id,
                resulting_version_hash,
                occurred_at_unix_ms,
            } => ResponseMutationRecord::EffectApplied(ResponseEffectAppliedRecord {
                transition_id,
                generation,
                effect_id,
                resulting_version_hash,
                occurred_at_unix_ms,
            }),
            Self::EffectFailed {
                generation,
                effect_id,
                error_code,
                occurred_at_unix_ms,
            } => ResponseMutationRecord::EffectFailed(ResponseEffectFailedRecord {
                transition_id,
                generation,
                effect_id,
                error_code,
                occurred_at_unix_ms,
            }),
            Self::Rollback {
                generation,
                effect_id,
                outcome,
                occurred_at_unix_ms,
            } => ResponseMutationRecord::Rollback(ResponseRollbackRecord {
                transition_id,
                generation,
                effect_id,
                outcome,
                occurred_at_unix_ms,
            }),
            Self::Failed {
                generation,
                from_state,
                to_state,
                error_code,
                occurred_at_unix_ms,
            } => ResponseMutationRecord::Failed(ResponseFailureRecord {
                transition_id,
                generation,
                from_state,
                to_state,
                error_code,
                occurred_at_unix_ms,
            }),
            Self::Final {
                generation,
                from_state,
                final_state,
                occurred_at_unix_ms,
            } => ResponseMutationRecord::Final(ResponseFinalRecord {
                transition_id,
                generation,
                from_state,
                final_state,
                occurred_at_unix_ms,
            }),
        }
    }
}

fn canonical_mutation_id(
    plan: &ResponsePlan,
    body: &CanonicalMutationBody,
) -> Result<RecordId, StateMachineError> {
    let expected_generation = body
        .generation()
        .checked_sub(1)
        .ok_or(StateMachineError::InvalidRecord)?;
    transition_id("mutation", plan, expected_generation, body)
}

fn finalize_mutation(
    plan: &ResponsePlan,
    body: CanonicalMutationBody,
) -> Result<ResponseMutationRecord, StateMachineError> {
    let transition_id = canonical_mutation_id(plan, &body)?;
    Ok(body.into_record(transition_id))
}

fn mutation_transition_id(
    plan: &ResponsePlan,
    mutation: &ResponseMutationRecord,
) -> Result<RecordId, StateMachineError> {
    if matches!(mutation, ResponseMutationRecord::Requested(_)) {
        return request_id(plan);
    }
    canonical_mutation_id(plan, &CanonicalMutationBody::from_record(mutation)?)
}

fn domain_hash<T: Serialize>(domain: &[u8], value: &T) -> Result<Digest32, StateMachineError> {
    let canonical = canonical_json_bytes(value).map_err(|_| StateMachineError::Canonical)?;
    let mut input = Vec::with_capacity(domain.len() + canonical.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&canonical);
    Ok(Digest32::new(*sha256(&input).as_bytes()))
}

fn error_code(value: &str) -> Result<ErrorCode, StateMachineError> {
    ErrorCode::new(value).map_err(|_| StateMachineError::Canonical)
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
pub enum StateMachineError {
    #[error("response canonicalization failed")]
    Canonical,
    #[error("response effect application is incomplete")]
    IncompleteApplication,
    #[error("response effect lifecycle transition is invalid")]
    InvalidEffectLifecycle,
    #[error("response failure record is invalid")]
    InvalidFailureRecord,
    #[error("response plan is invalid")]
    InvalidPlan,
    #[error("response state record is invalid")]
    InvalidRecord,
    #[error("response transition timing is invalid")]
    InvalidTiming,
    #[error("response state transition is not permitted")]
    InvalidTransition,
    #[error("response mutation limit exceeded")]
    MutationLimit,
    #[error("response is not due")]
    NotDue,
    #[error("response generation overflow")]
    GenerationOverflow,
    #[error("response generation is stale")]
    StaleGeneration,
    #[error("response effect is unknown")]
    UnknownEffect,
    #[error("response still has unrestored reversible effects")]
    UnrestoredEffects,
    #[error("response plan shape is invalid: {0}")]
    Shape(#[from] ResponseShapeError),
    #[error("response store failed: {0}")]
    Store(#[from] PortError),
}
