// Adapted from Clawdstrike concepts; see docs/security/clawdstrike-active-defense-provenance.md.
use chio_core_types::{
    canonical_json_bytes, capability::governance::GovernedResponsePlanIntentBody,
    receipt::security::validate_response_snapshot_lifecycle, sha256,
};
use chio_security_types::ports::{
    response_affected_set_hash, BlastRadiusResult, BoundedVec, CanonicalBody, Digest32, EffectId,
    ErrorCode, IssuanceFreezeSpec, LeaseOwnerId, OpaqueReceiptRef, RecordId, RecordIdSet,
    ResponsePlanRecord, ScheduledWork, RESPONSE_EFFECT_ID_DOMAIN, RESPONSE_REQUEST_ID_DOMAIN,
    RESPONSE_TRANSITION_ID_DOMAIN,
};
use chio_security_types::{
    is_legal_response_transition, PlannedResponseEffect, PlannedResponseEffects,
    ResponseApprovalRequirement, ResponseEffectAppliedRecord, ResponseEffectFailedRecord,
    ResponseEffectProgress, ResponseEffectRequestedRecord, ResponseEffectSpec,
    ResponseFailureRecord, ResponseFinalRecord, ResponseMutationRecord, ResponsePlan,
    ResponsePlanInput, ResponseRollbackOutcome, ResponseRollbackRecord, ResponseSnapshot,
    ResponseState, ResponseTransitionCause, ResponseTransitionRecord, MAX_RESPONSE_EFFECTS,
};
use serde::Serialize;

use chio_core_types::receipt::security::active_defense_response_receipt_for_mutation as response_receipt_for_mutation;

mod error;
pub mod projection;

pub use error::{
    CanonicalFailure, FreezeBindingField, PlanDefect, RecordDefect, StateMachineError,
};

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

pub fn transition_candidate(
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
    // A direct store transition cannot create historical execution authority.
    // The kernel projects verified committed admissions separately, then commits
    // their exact dispatch and initial Applying snapshot atomically.
    if actual_target == ResponseState::Applying && from_state != ResponseState::Applying {
        snapshot.plan.require_live_execution()?;
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

pub fn effect_candidate(
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

pub fn build_response_plan(input: ResponsePlanInput) -> Result<ResponsePlan, StateMachineError> {
    if input.effects.is_empty() {
        return Err(PlanDefect::NoEffects.into());
    }
    if input.effects.len() > MAX_RESPONSE_EFFECTS {
        return Err(PlanDefect::TooManyEffects {
            count: input.effects.len(),
            bound: MAX_RESPONSE_EFFECTS,
        }
        .into());
    }
    if input.ttl_ms == 0 {
        return Err(PlanDefect::ZeroTtl.into());
    }
    let expires_at_unix_ms = input
        .created_at_unix_ms
        .checked_add(input.ttl_ms)
        .ok_or(PlanDefect::ExpiryOverflow)?;
    let affected_ids = RecordIdSet::new(input.affected_ids).map_err(PlanDefect::AffectedIds)?;
    let affected_set_hash = response_affected_set_hash(&input.tenant_id, &affected_ids)
        .map_err(PlanDefect::AffectedSetHash)?;
    let mut effects = Vec::with_capacity(input.effects.len());
    for (index, spec) in input.effects.into_iter().enumerate() {
        validate_effect_contribution(&spec.canonical_contribution, &spec.contribution_hash)?;
        let ordinal = u16::try_from(index).map_err(PlanDefect::EffectOrdinalOverflow)?;
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
    let effects = PlannedResponseEffects::new(effects).map_err(PlanDefect::EffectBound)?;
    let mut plan = ResponsePlan {
        execution: input.execution,
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

pub fn decode_response_record(
    record: &ResponsePlanRecord,
) -> Result<ResponseSnapshot, StateMachineError> {
    let snapshot: ResponseSnapshot =
        serde_json::from_slice(record.canonical_body.as_bytes()).map_err(RecordDefect::Decode)?;
    let canonical = canonical_json_bytes(&snapshot).map_err(CanonicalFailure::Encoding)?;
    if canonical.as_slice() != record.canonical_body.as_bytes() {
        return Err(RecordDefect::NotCanonical.into());
    }
    if Digest32::new(*sha256(&canonical).as_bytes()) != record.body_hash {
        return Err(RecordDefect::BodyHashMismatch.into());
    }
    if snapshot.plan.tenant_id != record.tenant_id {
        return Err(RecordDefect::TenantMismatch.into());
    }
    if snapshot.plan.action_id != record.action_id {
        return Err(RecordDefect::ActionMismatch.into());
    }
    if snapshot.generation != record.generation {
        return Err(RecordDefect::GenerationMismatch.into());
    }
    if snapshot.state.as_str() != record.state.as_str() {
        return Err(RecordDefect::StateMismatch.into());
    }
    if snapshot.due_at_unix_ms != record.due_at_unix_ms {
        return Err(RecordDefect::DueAtMismatch.into());
    }
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

pub fn encode_response_record(
    snapshot: &ResponseSnapshot,
) -> Result<ResponsePlanRecord, StateMachineError> {
    encode_response_record_with_mode(snapshot, false)
}

fn encode_response_record_with_mode(
    snapshot: &ResponseSnapshot,
    allow_normalized_dispatch: bool,
) -> Result<ResponsePlanRecord, StateMachineError> {
    validate_snapshot_with_mode(snapshot, allow_normalized_dispatch)?;
    let bytes = canonical_json_bytes(snapshot).map_err(CanonicalFailure::Encoding)?;
    let body_hash = Digest32::new(*sha256(&bytes).as_bytes());
    let canonical_body = CanonicalBody::new(bytes).map_err(CanonicalFailure::Body)?;
    Ok(ResponsePlanRecord {
        tenant_id: snapshot.plan.tenant_id.clone(),
        action_id: snapshot.plan.action_id.clone(),
        generation: snapshot.generation,
        state: RecordId::new(snapshot.state.as_str()).map_err(CanonicalFailure::Identifier)?,
        canonical_body,
        body_hash,
        due_at_unix_ms: snapshot.due_at_unix_ms,
    })
}

pub fn validate_plan(plan: &ResponsePlan) -> Result<(), StateMachineError> {
    plan.validate_shape()?;
    if plan.affected_set_hash
        != response_affected_set_hash(&plan.tenant_id, &plan.affected_ids)
            .map_err(PlanDefect::AffectedSetHash)?
    {
        return Err(PlanDefect::AffectedSetHashMismatch.into());
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
            return Err(PlanDefect::EffectIdMismatch.into());
        }
        validate_effect_plan_binding(plan, effect)?;
    }
    if plan.plan_hash != Digest32::new(compute_plan_hash(plan)?) {
        return Err(PlanDefect::PlanHashMismatch.into());
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
            .map_err(PlanDefect::FreezeContribution)?;
    let chio_security_types::ResponseTarget::Lineage { lineage_id } = &effect.target else {
        return Err(PlanDefect::FreezeTargetNotLineage.into());
    };
    let BlastRadiusResult::Exact {
        sorted_affected_ids,
        affected_set_hash,
        ..
    } = &freeze.acquisition.approved_result
    else {
        return Err(PlanDefect::FreezeAcquisitionNotExact.into());
    };
    let mismatch = |field: FreezeBindingField| PlanDefect::FreezeBindingMismatch(field).into();
    if &freeze.lineage_id != lineage_id {
        return Err(mismatch(FreezeBindingField::Lineage));
    }
    if freeze.acquisition.request.tenant_id != plan.tenant_id {
        return Err(mismatch(FreezeBindingField::Tenant));
    }
    if freeze.acquisition.request.action_id != plan.action_id {
        return Err(mismatch(FreezeBindingField::Action));
    }
    if sorted_affected_ids != &plan.affected_ids {
        return Err(mismatch(FreezeBindingField::AffectedIds));
    }
    if *affected_set_hash != plan.affected_set_hash {
        return Err(mismatch(FreezeBindingField::AffectedSetHash));
    }
    Ok(())
}

fn validate_effect_contribution(
    body: &CanonicalBody,
    expected_hash: &Digest32,
) -> Result<(), StateMachineError> {
    let value: serde_json::Value =
        serde_json::from_slice(body.as_bytes()).map_err(PlanDefect::ContributionNotJson)?;
    let canonical = canonical_json_bytes(&value).map_err(CanonicalFailure::Encoding)?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(PlanDefect::ContributionNotCanonical.into());
    }
    if Digest32::new(*sha256(&canonical).as_bytes()) != *expected_hash {
        return Err(PlanDefect::ContributionHashMismatch.into());
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
        .map_err(RecordDefect::Lifecycle)?;
    Ok(())
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
            .ok_or(RecordDefect::MissingApplyingLease)?;
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
            .ok_or(RecordDefect::MissingApplyingLease)?;
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
    let mut mutations = snapshot.mutations.clone().into_vec();
    mutations.push(mutation);
    snapshot.mutations = BoundedVec::new(mutations).map_err(StateMachineError::MutationLimit)?;
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
        RESPONSE_EFFECT_ID_DOMAIN,
        &EffectCommitment {
            action_id: action_id.as_str(),
            ordinal,
            spec,
        },
    )?;
    Ok(
        EffectId::new(format!("response_effect_{}", hex_bytes(digest.as_bytes())))
            .map_err(CanonicalFailure::Identifier)?,
    )
}

fn compute_plan_hash(plan: &ResponsePlan) -> Result<[u8; 32], StateMachineError> {
    let body = serde_json::to_value(plan.authorization_body()).map_err(CanonicalFailure::Value)?;
    let digest =
        GovernedResponsePlanIntentBody::plan_body_hash(&body).map_err(PlanDefect::PlanBodyHash)?;
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(digest, &mut bytes).map_err(PlanDefect::PlanBodyHashEncoding)?;
    Ok(bytes)
}

mod canonicalization;
use canonicalization::{
    domain_hash, finalize_mutation, hex_bytes, latest_evidence_id, request_id,
    CanonicalMutationBody,
};
