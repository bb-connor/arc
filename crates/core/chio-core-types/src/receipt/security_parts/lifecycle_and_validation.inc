/// Validate the complete durable mutation lifecycle of a response snapshot.
///
/// The check is pure. It replays the state and effect machines, recomputes
/// every mutation transition ID, and reconstructs every native receipt ID to
/// verify the exact prior-receipt chain. `allow_normalized_dispatch` is only
/// for the pre-commit Applying snapshot whose authorization hash is attached
/// by the subsequent dispatch commit.
pub fn validate_response_snapshot_lifecycle(
    snapshot: &ResponseSnapshot,
    allow_normalized_dispatch: bool,
) -> Result<()> {
    snapshot
        .plan
        .validate_shape()
        .map_err(|error| response_snapshot_error(&error.to_string()))?;
    if let Some(dispatch) = &snapshot.execution_dispatch {
        dispatch
            .validate_for_plan(&snapshot.plan)
            .map_err(|error| response_snapshot_error(&error.to_string()))?;
    }
    match (
        &snapshot.execution_dispatch,
        &snapshot.dispatch_authorization_hash,
    ) {
        (None, None) => {}
        (Some(_), Some(hash)) if hash.as_bytes().iter().any(|byte| *byte != 0) => {}
        (Some(_), None)
            if allow_normalized_dispatch && snapshot.state == ResponseState::Applying => {}
        _ => {
            return Err(response_snapshot_error(
                "response dispatch binding is invalid",
            ))
        }
    }
    let expected_mutation_count = snapshot
        .generation
        .checked_add(1)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| response_snapshot_error("response generation is invalid"))?;
    if snapshot.schema_version != RESPONSE_STATE_SCHEMA_VERSION
        || snapshot.mutations.is_empty()
        || snapshot.mutations.len() != expected_mutation_count
    {
        return Err(response_snapshot_error(
            "response mutation count is invalid",
        ));
    }
    let request = match &snapshot.mutations.as_slice()[0] {
        ResponseMutationRecord::Requested(record)
            if record.generation == 0
                && record.occurred_at_unix_ms == snapshot.plan.created_at_unix_ms
                && record.prior_receipt_id == snapshot.plan.trigger_finding_receipt_id
                && record.transition_id
                    == expected_response_mutation_transition_id(
                        &snapshot.plan,
                        &snapshot.mutations.as_slice()[0],
                    )? =>
        {
            record
        }
        _ => {
            return Err(response_snapshot_error(
                "response request mutation is invalid",
            ))
        }
    };
    let _ = request;
    let mut previous_evidence_id =
        active_defense_response_receipt_for_mutation(snapshot, 0)?.evidence_id()?;
    let mut replay_state = ResponseState::Planned;
    let mut replay_lease = None;
    let mut replay_due = Some(snapshot.plan.expires_at_unix_ms);
    let mut page_required = false;
    let mut previous_time = snapshot.plan.created_at_unix_ms;
    let mut progress = vec![ResponseEffectProgress::Planned; snapshot.plan.effects.len()];
    let mut apply_failure_errors = vec![None; snapshot.plan.effects.len()];
    let mut applying_transition_seen = false;
    let mut scheduler_fence: Option<(LeaseOwnerId, u64)> = None;
    let mut highest_legacy_scheduler_fencing_token = 0;
    let mut effect_generations = vec![0; snapshot.plan.effects.len()];
    let mut receipt_backed_effects = vec![false; snapshot.plan.effects.len()];
    for (index, mutation) in snapshot.mutations.as_slice().iter().enumerate().skip(1) {
        let expected_generation = u64::try_from(index)
            .map_err(|_| response_snapshot_error("response generation is invalid"))?;
        if mutation.generation() != expected_generation
            || mutation.transition_id()
                != &expected_response_mutation_transition_id(&snapshot.plan, mutation)?
            || mutation.prior_receipt_id() != &previous_evidence_id
            || mutation.occurred_at_unix_ms() < previous_time
        {
            return Err(response_snapshot_error(
                "response mutation binding is invalid",
            ));
        }
        previous_time = mutation.occurred_at_unix_ms();
        match mutation {
            ResponseMutationRecord::Requested(_) => {
                return Err(response_snapshot_error(
                    "response request mutation is repeated",
                ));
            }
            ResponseMutationRecord::Transition(record) => {
                let applying_renewal = record.from_state == ResponseState::Applying
                    && record.to_state == ResponseState::Applying;
                let lease_is_valid = match record.to_state {
                    ResponseState::Applying => record
                        .applying_lease_expires_at_unix_ms
                        .is_some_and(|lease| {
                            lease > record.occurred_at_unix_ms
                                && lease <= snapshot.plan.expires_at_unix_ms
                        }),
                    _ => record.applying_lease_expires_at_unix_ms.is_none(),
                };
                let applying_renewal_is_valid = !applying_renewal
                    || (applying_transition_seen
                        && replay_lease.is_some_and(|current_lease| {
                            record.occurred_at_unix_ms < current_lease
                                && record
                                    .applying_lease_expires_at_unix_ms
                                    .is_some_and(|renewed_lease| renewed_lease > current_lease)
                        }));
                let applying_renewal_fence_is_valid = if applying_renewal {
                    record.scheduler_lease_owner_id.is_some()
                        && record.scheduler_fencing_token.is_some_and(|token| token > 0)
                } else {
                    record.scheduler_lease_owner_id.is_some()
                        == record.scheduler_fencing_token.is_some()
                };
                validate_response_scheduler_fence(
                    record.scheduler_lease_owner_id.as_ref(),
                    record.scheduler_fencing_token,
                    applying_renewal,
                    &mut scheduler_fence,
                    &mut highest_legacy_scheduler_fencing_token,
                )?;
                if record.from_state != replay_state
                    || !is_legal_response_transition(record.from_state, record.to_state)
                    || !response_approval_path_is_valid(
                        &snapshot.plan,
                        record.from_state,
                        record.to_state,
                    )
                    || expected_response_lifecycle_transition_cause(
                        record.from_state,
                        record.to_state,
                    ) != Some(record.cause)
                    || !lease_is_valid
                    || !applying_renewal_is_valid
                    || !applying_renewal_fence_is_valid
                    || (record.to_state == ResponseState::Active
                        && (progress
                            .iter()
                            .any(|effect| *effect != ResponseEffectProgress::Applied)
                            || replay_lease
                                .is_none_or(|lease| record.occurred_at_unix_ms >= lease)))
                    || (record.to_state == ResponseState::Expiring
                        && record.occurred_at_unix_ms < snapshot.plan.expires_at_unix_ms)
                    || (record.to_state == ResponseState::Applying
                        && !applying_renewal
                        && (applying_transition_seen
                            || snapshot
                                .execution_dispatch
                                .as_ref()
                                .is_some_and(|dispatch| {
                                    record.occurred_at_unix_ms != dispatch.authorized_at_unix_ms
                                })))
                {
                    return Err(response_snapshot_error(
                        "response state transition is invalid",
                    ));
                }
                applying_transition_seen |= record.to_state == ResponseState::Applying;
                replay_state = record.to_state;
                replay_lease = record.applying_lease_expires_at_unix_ms;
                replay_due = response_state_due(
                    &snapshot.plan,
                    record.to_state,
                    record.occurred_at_unix_ms,
                    record.applying_lease_expires_at_unix_ms,
                )?;
            }
            ResponseMutationRecord::EffectRequested(record) => {
                let effect_index = response_effect_index(&snapshot.plan, &record.effect_id)?;
                if replay_state != ResponseState::Applying
                    || replay_lease.is_none_or(|lease| record.occurred_at_unix_ms >= lease)
                    || progress[effect_index] != ResponseEffectProgress::Planned
                    || progress.iter().any(|effect| {
                        matches!(
                            effect,
                            ResponseEffectProgress::Requested | ResponseEffectProgress::ApplyFailed
                        )
                    })
                {
                    return Err(response_snapshot_error(
                        "effect request lifecycle is invalid",
                    ));
                }
                validate_response_effect_receipt_order(
                    ResponseEffectReceiptOrderInput {
                        effect_index,
                        effect_generation: record.effect_generation,
                        scheduler_lease_owner_id: record.scheduler_lease_owner_id.as_ref(),
                        scheduler_fencing_token: record.scheduler_fencing_token,
                        effect_transition_id: None,
                        non_request: false,
                        dispatch_bound: snapshot.execution_dispatch.is_some(),
                    },
                    ResponseEffectReceiptOrderState {
                        scheduler_fence: &mut scheduler_fence,
                        highest_legacy_scheduler_fencing_token: &mut highest_legacy_scheduler_fencing_token,
                        effect_generations: &mut effect_generations,
                        receipt_backed_effects: &mut receipt_backed_effects,
                    },
                )?;
                progress[effect_index] = ResponseEffectProgress::Requested;
            }
            ResponseMutationRecord::EffectApplied(record) => {
                let effect_index = response_effect_index(&snapshot.plan, &record.effect_id)?;
                let late_authoritative_takeover = LateAuthoritativeEffectTakeover {
                    occurred_at_unix_ms: record.occurred_at_unix_ms,
                    applying_lease_expires_at_unix_ms: replay_lease,
                    effect_index,
                    effect_generation: record.effect_generation,
                    scheduler_lease_owner_id: record.scheduler_lease_owner_id.as_ref(),
                    scheduler_fencing_token: record.scheduler_fencing_token,
                    effect_transition_id: record.effect_transition_id.as_ref(),
                    current_scheduler_fence: scheduler_fence.as_ref(),
                    highest_legacy_scheduler_fencing_token,
                    effect_generations: &effect_generations,
                    receipt_backed_effects: &receipt_backed_effects,
                }
                .is_valid();
                if replay_state != ResponseState::Applying
                    || (replay_lease.is_none_or(|lease| record.occurred_at_unix_ms >= lease)
                        && !late_authoritative_takeover)
                    || progress[effect_index] != ResponseEffectProgress::Requested
                {
                    return Err(response_snapshot_error("effect apply lifecycle is invalid"));
                }
                validate_response_effect_receipt_order(
                    ResponseEffectReceiptOrderInput {
                        effect_index,
                        effect_generation: record.effect_generation,
                        scheduler_lease_owner_id: record.scheduler_lease_owner_id.as_ref(),
                        scheduler_fencing_token: record.scheduler_fencing_token,
                        effect_transition_id: record.effect_transition_id.as_ref(),
                        non_request: true,
                        dispatch_bound: snapshot.execution_dispatch.is_some(),
                    },
                    ResponseEffectReceiptOrderState {
                        scheduler_fence: &mut scheduler_fence,
                        highest_legacy_scheduler_fencing_token: &mut highest_legacy_scheduler_fencing_token,
                        effect_generations: &mut effect_generations,
                        receipt_backed_effects: &mut receipt_backed_effects,
                    },
                )?;
                progress[effect_index] = ResponseEffectProgress::Applied;
            }
            ResponseMutationRecord::EffectFailed(record) => {
                let effect_index = response_effect_index(&snapshot.plan, &record.effect_id)?;
                let late_authoritative_takeover = LateAuthoritativeEffectTakeover {
                    occurred_at_unix_ms: record.occurred_at_unix_ms,
                    applying_lease_expires_at_unix_ms: replay_lease,
                    effect_index,
                    effect_generation: record.effect_generation,
                    scheduler_lease_owner_id: record.scheduler_lease_owner_id.as_ref(),
                    scheduler_fencing_token: record.scheduler_fencing_token,
                    effect_transition_id: record.effect_transition_id.as_ref(),
                    current_scheduler_fence: scheduler_fence.as_ref(),
                    highest_legacy_scheduler_fencing_token,
                    effect_generations: &effect_generations,
                    receipt_backed_effects: &receipt_backed_effects,
                }
                .is_valid();
                if replay_state != ResponseState::Applying
                    || (replay_lease.is_none_or(|lease| record.occurred_at_unix_ms >= lease)
                        && !late_authoritative_takeover)
                    || (record.error_code.as_str() == "response.effect_not_executed"
                        && !late_authoritative_takeover)
                    || progress[effect_index] != ResponseEffectProgress::Requested
                {
                    return Err(response_snapshot_error(
                        "effect failure lifecycle is invalid",
                    ));
                }
                validate_response_effect_receipt_order(
                    ResponseEffectReceiptOrderInput {
                        effect_index,
                        effect_generation: record.effect_generation,
                        scheduler_lease_owner_id: record.scheduler_lease_owner_id.as_ref(),
                        scheduler_fencing_token: record.scheduler_fencing_token,
                        effect_transition_id: record.effect_transition_id.as_ref(),
                        non_request: true,
                        dispatch_bound: snapshot.execution_dispatch.is_some(),
                    },
                    ResponseEffectReceiptOrderState {
                        scheduler_fence: &mut scheduler_fence,
                        highest_legacy_scheduler_fencing_token: &mut highest_legacy_scheduler_fencing_token,
                        effect_generations: &mut effect_generations,
                        receipt_backed_effects: &mut receipt_backed_effects,
                    },
                )?;
                progress[effect_index] = ResponseEffectProgress::ApplyFailed;
                apply_failure_errors[effect_index] = Some(record.error_code.clone());
            }
            ResponseMutationRecord::Rollback(record) => {
                let effect_index = response_effect_index(&snapshot.plan, &record.effect_id)?;
                if replay_state != ResponseState::RollingBack
                    || !snapshot.plan.effects.as_slice()[effect_index]
                        .kind
                        .is_reversible()
                {
                    return Err(response_snapshot_error(
                        "effect rollback lifecycle is invalid",
                    ));
                }
                validate_response_effect_receipt_order(
                    ResponseEffectReceiptOrderInput {
                        effect_index,
                        effect_generation: record.effect_generation,
                        scheduler_lease_owner_id: record.scheduler_lease_owner_id.as_ref(),
                        scheduler_fencing_token: record.scheduler_fencing_token,
                        effect_transition_id: record.effect_transition_id.as_ref(),
                        non_request: true,
                        dispatch_bound: snapshot.execution_dispatch.is_some(),
                    },
                    ResponseEffectReceiptOrderState {
                        scheduler_fence: &mut scheduler_fence,
                        highest_legacy_scheduler_fencing_token: &mut highest_legacy_scheduler_fencing_token,
                        effect_generations: &mut effect_generations,
                        receipt_backed_effects: &mut receipt_backed_effects,
                    },
                )?;
                progress[effect_index] =
                    response_rollback_progress(progress[effect_index], &record.outcome)?;
            }
            ResponseMutationRecord::Failed(record) => {
                validate_response_scheduler_fence(
                    record.scheduler_lease_owner_id.as_ref(),
                    record.scheduler_fencing_token,
                    false,
                    &mut scheduler_fence,
                    &mut highest_legacy_scheduler_fencing_token,
                )?;
                let immediately_prior = index
                    .checked_sub(1)
                    .and_then(|prior| snapshot.mutations.as_slice().get(prior));
                let effect_states =
                    response_completion_effect_states(&progress, &apply_failure_errors);
                let exact_effect_failure = response_exact_effect_failure(
                    &snapshot.plan,
                    &progress,
                    immediately_prior,
                    &record.error_code,
                );
                let dispatch_failure_before_effect = response_dispatch_failure_before_effect(
                    snapshot,
                    record.from_state,
                    record.to_state,
                    record.occurred_at_unix_ms,
                    &record.error_code,
                    replay_lease,
                    &progress,
                );
                let reserved_failure_timing_is_valid = response_reserved_failure_timing_is_valid(
                    record.from_state,
                    record.to_state,
                    record.occurred_at_unix_ms,
                    &record.error_code,
                    replay_lease,
                    dispatch_failure_before_effect,
                );
                if record.from_state != replay_state
                    || !is_legal_response_transition(record.from_state, record.to_state)
                    || !matches!(
                        record.to_state,
                        ResponseState::Failed
                            | ResponseState::ApplyPartial
                            | ResponseState::RollbackPartial
                    )
                    || (matches!(
                        record.to_state,
                        ResponseState::Failed | ResponseState::ApplyPartial
                    ) && !response_completion_effect_shape_is_valid(
                        record.to_state,
                        Some(&record.error_code),
                        &effect_states,
                    ))
                    || (record.to_state == ResponseState::Failed
                        && record.from_state == ResponseState::Applying
                        && replay_lease.is_none_or(|lease| record.occurred_at_unix_ms >= lease)
                        && !dispatch_failure_before_effect
                        && !exact_effect_failure)
                    || (record.to_state == ResponseState::Failed
                        && progress.contains(&ResponseEffectProgress::ApplyFailed)
                        && !exact_effect_failure)
                    || (record.to_state == ResponseState::ApplyPartial
                        && progress.contains(&ResponseEffectProgress::ApplyFailed)
                        && !exact_effect_failure)
                    || (record.to_state == ResponseState::RollbackPartial
                        && (!progress.contains(&ResponseEffectProgress::RollbackFailed)
                            || snapshot
                                .plan
                                .effects
                                .as_slice()
                                .iter()
                                .zip(progress.iter())
                                .any(|(effect, progress)| {
                                    effect.kind.is_reversible()
                                        && matches!(
                                            progress,
                                            ResponseEffectProgress::Applied
                                                | ResponseEffectProgress::RollbackRequested
                                        )
                                })))
                    || !reserved_failure_timing_is_valid
                {
                    return Err(response_snapshot_error(
                        "response failure lifecycle is invalid",
                    ));
                }
                if record.to_state == ResponseState::RollbackPartial {
                    page_required = true;
                }
                replay_state = record.to_state;
                replay_lease = None;
                replay_due = response_state_due(
                    &snapshot.plan,
                    record.to_state,
                    record.occurred_at_unix_ms,
                    None,
                )?;
            }
            ResponseMutationRecord::Final(record) => {
                validate_response_scheduler_fence(
                    record.scheduler_lease_owner_id.as_ref(),
                    record.scheduler_fencing_token,
                    false,
                    &mut scheduler_fence,
                    &mut highest_legacy_scheduler_fencing_token,
                )?;
                if record.from_state != replay_state
                    || !record.final_state.is_terminal()
                    || record.final_state == ResponseState::Failed
                    || !is_legal_response_transition(record.from_state, record.final_state)
                    || (record.final_state == ResponseState::Expired
                        && record.occurred_at_unix_ms < snapshot.plan.expires_at_unix_ms)
                {
                    return Err(response_snapshot_error(
                        "response final lifecycle is invalid",
                    ));
                }
                replay_state = record.final_state;
                replay_lease = None;
                replay_due = None;
            }
        }
        let replay_mutations = ResponseMutationLog::new(
            snapshot.mutations.as_slice()[..=index].to_vec(),
        )
        .map_err(|_| response_snapshot_error("response mutation prefix is invalid"))?;
        let replay_snapshot = ResponseSnapshot {
            schema_version: snapshot.schema_version,
            plan: snapshot.plan.clone(),
            execution_dispatch: snapshot.execution_dispatch.clone(),
            dispatch_authorization_hash: snapshot.dispatch_authorization_hash,
            state: replay_state,
            generation: expected_generation,
            applying_lease_expires_at_unix_ms: replay_lease,
            due_at_unix_ms: replay_due,
            operator_page_required: page_required,
            mutations: replay_mutations,
        };
        if !response_snapshot_has_mutation_capacity(&replay_snapshot) {
            return Err(response_snapshot_error(
                "response mutation suffix exceeds the protocol bound",
            ));
        }
        previous_evidence_id =
            active_defense_response_receipt_for_mutation(snapshot, index)?.evidence_id()?;
    }
    if replay_state != snapshot.state
        || replay_lease != snapshot.applying_lease_expires_at_unix_ms
        || replay_due != snapshot.due_at_unix_ms
        || page_required != snapshot.operator_page_required
        || (snapshot.execution_dispatch.is_some() && !applying_transition_seen)
        || (snapshot.state == ResponseState::Lifted
            && !snapshot.all_applied_reversible_effects_restored())
        || (snapshot.state == ResponseState::RollbackPartial
            && (!snapshot.operator_page_required || !snapshot.has_rollback_failure()))
        || !response_snapshot_has_mutation_capacity(snapshot)
    {
        return Err(response_snapshot_error(
            "response snapshot replay is inconsistent",
        ));
    }
    Ok(())
}

struct LateAuthoritativeEffectTakeover<'a> {
    occurred_at_unix_ms: u64,
    applying_lease_expires_at_unix_ms: Option<u64>,
    effect_index: usize,
    effect_generation: u64,
    scheduler_lease_owner_id: Option<&'a LeaseOwnerId>,
    scheduler_fencing_token: u64,
    effect_transition_id: Option<&'a RecordId>,
    current_scheduler_fence: Option<&'a (LeaseOwnerId, u64)>,
    highest_legacy_scheduler_fencing_token: u64,
    effect_generations: &'a [u64],
    receipt_backed_effects: &'a [bool],
}

impl LateAuthoritativeEffectTakeover<'_> {
    fn is_valid(&self) -> bool {
        self.applying_lease_expires_at_unix_ms
            .is_some_and(|lease| self.occurred_at_unix_ms >= lease)
            && self.scheduler_lease_owner_id.is_some()
            && self.effect_transition_id.is_some()
            && self.current_scheduler_fence.is_some_and(|(_, current_token)| {
                self.scheduler_fencing_token > *current_token
            })
            && self.scheduler_fencing_token > self.highest_legacy_scheduler_fencing_token
            && self
                .effect_generations
                .get(self.effect_index)
                .is_some_and(|previous| self.effect_generation > *previous)
            && self.receipt_backed_effects.get(self.effect_index) == Some(&true)
    }
}

/// Recompute the canonical transition identifier for one response mutation.
pub fn expected_response_mutation_transition_id(
    plan: &ResponsePlan,
    mutation: &ResponseMutationRecord,
) -> Result<RecordId> {
    if matches!(mutation, ResponseMutationRecord::Requested(_)) {
        return response_request_transition_id(plan);
    }
    let body = CanonicalResponseMutation::from_record(mutation)?;
    let expected_generation = body
        .generation()
        .checked_sub(1)
        .ok_or_else(|| response_snapshot_error("response mutation generation is zero"))?;
    response_transition_id("mutation", plan, expected_generation, &body)
}

fn response_request_transition_id(plan: &ResponsePlan) -> Result<RecordId> {
    #[derive(Serialize)]
    struct RequestCommitment<'a> {
        tenant_id: &'a str,
        action_id: &'a str,
        plan_hash: Digest32,
        created_at_unix_ms: u64,
    }
    let digest = response_domain_hash(
        RESPONSE_REQUEST_ID_DOMAIN,
        &RequestCommitment {
            tenant_id: plan.tenant_id.as_str(),
            action_id: plan.action_id.as_str(),
            plan_hash: plan.plan_hash,
            created_at_unix_ms: plan.created_at_unix_ms,
        },
    )?;
    RecordId::new(format!(
        "response_request_{}",
        response_hex_bytes(digest.as_bytes())
    ))
    .map_err(|error| response_snapshot_error(&error.to_string()))
}

fn response_transition_id<T: Serialize>(
    kind: &str,
    plan: &ResponsePlan,
    expected_generation: u64,
    mutation: &T,
) -> Result<RecordId> {
    #[derive(Serialize)]
    struct TransitionCommitment<'a, T> {
        kind: &'a str,
        tenant_id: &'a str,
        action_id: &'a str,
        plan_hash: Digest32,
        expected_generation: u64,
        mutation: &'a T,
    }
    let digest = response_domain_hash(
        RESPONSE_MUTATION_ID_DOMAIN,
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
        response_hex_bytes(digest.as_bytes())
    ))
    .map_err(|error| response_snapshot_error(&error.to_string()))
}

#[derive(Serialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
enum CanonicalResponseMutation<'a> {
    Transition {
        generation: u64,
        from_state: ResponseState,
        to_state: ResponseState,
        cause: ResponseTransitionCause,
        applying_lease_expires_at_unix_ms: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_lease_owner_id: &'a Option<LeaseOwnerId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_fencing_token: Option<u64>,
        prior_receipt_id: &'a OpaqueReceiptRef,
        occurred_at_unix_ms: u64,
    },
    EffectRequested {
        generation: u64,
        effect_id: &'a EffectId,
        effect_generation: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_lease_owner_id: &'a Option<LeaseOwnerId>,
        scheduler_fencing_token: u64,
        prior_receipt_id: &'a OpaqueReceiptRef,
        occurred_at_unix_ms: u64,
    },
    EffectApplied {
        generation: u64,
        effect_id: &'a EffectId,
        effect_generation: u64,
        resulting_version_hash: Digest32,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_lease_owner_id: &'a Option<LeaseOwnerId>,
        scheduler_fencing_token: u64,
        effect_transition_id: &'a Option<RecordId>,
        prior_receipt_id: &'a OpaqueReceiptRef,
        occurred_at_unix_ms: u64,
    },
    EffectFailed {
        generation: u64,
        effect_id: &'a EffectId,
        effect_generation: u64,
        error_code: &'a ErrorCode,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_lease_owner_id: &'a Option<LeaseOwnerId>,
        scheduler_fencing_token: u64,
        effect_transition_id: &'a Option<RecordId>,
        prior_receipt_id: &'a OpaqueReceiptRef,
        occurred_at_unix_ms: u64,
    },
    Rollback {
        generation: u64,
        effect_id: &'a EffectId,
        effect_generation: u64,
        outcome: &'a ResponseRollbackOutcome,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_lease_owner_id: &'a Option<LeaseOwnerId>,
        scheduler_fencing_token: u64,
        effect_transition_id: &'a Option<RecordId>,
        prior_receipt_id: &'a OpaqueReceiptRef,
        occurred_at_unix_ms: u64,
    },
    Failed {
        generation: u64,
        from_state: ResponseState,
        to_state: ResponseState,
        error_code: &'a ErrorCode,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_lease_owner_id: &'a Option<LeaseOwnerId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_fencing_token: Option<u64>,
        prior_receipt_id: &'a OpaqueReceiptRef,
        occurred_at_unix_ms: u64,
    },
    Final {
        generation: u64,
        from_state: ResponseState,
        final_state: ResponseState,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_lease_owner_id: &'a Option<LeaseOwnerId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_fencing_token: Option<u64>,
        prior_receipt_id: &'a OpaqueReceiptRef,
        occurred_at_unix_ms: u64,
    },
}

impl<'a> CanonicalResponseMutation<'a> {
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

    fn from_record(mutation: &'a ResponseMutationRecord) -> Result<Self> {
        match mutation {
            ResponseMutationRecord::Requested(_) => Err(response_snapshot_error(
                "request mutation has no canonical body",
            )),
            ResponseMutationRecord::Transition(record) => Ok(Self::Transition {
                generation: record.generation,
                from_state: record.from_state,
                to_state: record.to_state,
                cause: record.cause,
                applying_lease_expires_at_unix_ms: record.applying_lease_expires_at_unix_ms,
                scheduler_lease_owner_id: &record.scheduler_lease_owner_id,
                scheduler_fencing_token: record.scheduler_fencing_token,
                prior_receipt_id: &record.prior_receipt_id,
                occurred_at_unix_ms: record.occurred_at_unix_ms,
            }),
            ResponseMutationRecord::EffectRequested(record) => Ok(Self::EffectRequested {
                generation: record.generation,
                effect_id: &record.effect_id,
                effect_generation: record.effect_generation,
                scheduler_lease_owner_id: &record.scheduler_lease_owner_id,
                scheduler_fencing_token: record.scheduler_fencing_token,
                prior_receipt_id: &record.prior_receipt_id,
                occurred_at_unix_ms: record.occurred_at_unix_ms,
            }),
            ResponseMutationRecord::EffectApplied(record) => Ok(Self::EffectApplied {
                generation: record.generation,
                effect_id: &record.effect_id,
                effect_generation: record.effect_generation,
                resulting_version_hash: record.resulting_version_hash,
                scheduler_lease_owner_id: &record.scheduler_lease_owner_id,
                scheduler_fencing_token: record.scheduler_fencing_token,
                effect_transition_id: &record.effect_transition_id,
                prior_receipt_id: &record.prior_receipt_id,
                occurred_at_unix_ms: record.occurred_at_unix_ms,
            }),
            ResponseMutationRecord::EffectFailed(record) => Ok(Self::EffectFailed {
                generation: record.generation,
                effect_id: &record.effect_id,
                effect_generation: record.effect_generation,
                error_code: &record.error_code,
                scheduler_lease_owner_id: &record.scheduler_lease_owner_id,
                scheduler_fencing_token: record.scheduler_fencing_token,
                effect_transition_id: &record.effect_transition_id,
                prior_receipt_id: &record.prior_receipt_id,
                occurred_at_unix_ms: record.occurred_at_unix_ms,
            }),
            ResponseMutationRecord::Rollback(record) => Ok(Self::Rollback {
                generation: record.generation,
                effect_id: &record.effect_id,
                effect_generation: record.effect_generation,
                outcome: &record.outcome,
                scheduler_lease_owner_id: &record.scheduler_lease_owner_id,
                scheduler_fencing_token: record.scheduler_fencing_token,
                effect_transition_id: &record.effect_transition_id,
                prior_receipt_id: &record.prior_receipt_id,
                occurred_at_unix_ms: record.occurred_at_unix_ms,
            }),
            ResponseMutationRecord::Failed(record) => Ok(Self::Failed {
                generation: record.generation,
                from_state: record.from_state,
                to_state: record.to_state,
                error_code: &record.error_code,
                scheduler_lease_owner_id: &record.scheduler_lease_owner_id,
                scheduler_fencing_token: record.scheduler_fencing_token,
                prior_receipt_id: &record.prior_receipt_id,
                occurred_at_unix_ms: record.occurred_at_unix_ms,
            }),
            ResponseMutationRecord::Final(record) => Ok(Self::Final {
                generation: record.generation,
                from_state: record.from_state,
                final_state: record.final_state,
                scheduler_lease_owner_id: &record.scheduler_lease_owner_id,
                scheduler_fencing_token: record.scheduler_fencing_token,
                prior_receipt_id: &record.prior_receipt_id,
                occurred_at_unix_ms: record.occurred_at_unix_ms,
            }),
        }
    }
}

fn response_domain_hash<T: Serialize>(domain: &[u8], value: &T) -> Result<Digest32> {
    let canonical = canonical_json_bytes(value)?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Ok(Digest32::new(*sha256(&preimage).as_bytes()))
}

fn response_hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

const fn expected_response_lifecycle_transition_cause(
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
        (ResponseState::Applying, ResponseState::Applying) => {
            Some(ResponseTransitionCause::ApplyingLeaseRenewed)
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

fn response_approval_path_is_valid(
    plan: &ResponsePlan,
    from_state: ResponseState,
    to_state: ResponseState,
) -> bool {
    match &plan.approval_requirement {
        ResponseApprovalRequirement::Automatic => {
            (from_state, to_state) != (ResponseState::Planned, ResponseState::AwaitingApproval)
        }
        ResponseApprovalRequirement::Governed { .. } => {
            (from_state, to_state) != (ResponseState::Planned, ResponseState::Applying)
        }
    }
}

fn response_effect_index(plan: &ResponsePlan, effect_id: &EffectId) -> Result<usize> {
    plan.effects
        .as_slice()
        .iter()
        .position(|effect| &effect.effect_id == effect_id)
        .ok_or_else(|| response_snapshot_error("response effect is unknown"))
}

struct ResponseEffectReceiptOrderInput<'a> {
    effect_index: usize,
    effect_generation: u64,
    scheduler_lease_owner_id: Option<&'a LeaseOwnerId>,
    scheduler_fencing_token: u64,
    effect_transition_id: Option<&'a RecordId>,
    non_request: bool,
    dispatch_bound: bool,
}

struct ResponseEffectReceiptOrderState<'a> {
    scheduler_fence: &'a mut Option<(LeaseOwnerId, u64)>,
    highest_legacy_scheduler_fencing_token: &'a mut u64,
    effect_generations: &'a mut [u64],
    receipt_backed_effects: &'a mut [bool],
}

fn validate_response_effect_receipt_order(
    input: ResponseEffectReceiptOrderInput<'_>,
    state: ResponseEffectReceiptOrderState<'_>,
) -> Result<()> {
    let prior_effect_generation = state
        .effect_generations
        .get_mut(input.effect_index)
        .ok_or_else(|| response_snapshot_error("response effect generation is invalid"))?;
    let receipt_backed = state
        .receipt_backed_effects
        .get_mut(input.effect_index)
        .ok_or_else(|| response_snapshot_error("response effect receipt mode is invalid"))?;
    let state_only = input.effect_generation == 1
        && input.scheduler_lease_owner_id.is_none()
        && input.scheduler_fencing_token == 1
        && input.effect_transition_id.is_none();
    if input.non_request
        && input.effect_transition_id.is_none()
        && (input.dispatch_bound || *receipt_backed)
    {
        return Err(response_snapshot_error(
            "receipt-backed effect mutation is missing its transition identifier",
        ));
    }
    if state_only {
        if *receipt_backed {
            return Err(response_snapshot_error(
                "state-only effect mutation follows receipt-backed evidence",
            ));
        }
    } else {
        if input.effect_generation <= *prior_effect_generation {
            return Err(response_snapshot_error(
                "effect receipt generation or fencing token regressed",
            ));
        }
        validate_response_scheduler_fence(
            input.scheduler_lease_owner_id,
            Some(input.scheduler_fencing_token),
            false,
            state.scheduler_fence,
            state.highest_legacy_scheduler_fencing_token,
        )?;
        *receipt_backed = true;
    }
    *prior_effect_generation = (*prior_effect_generation).max(input.effect_generation);
    Ok(())
}

fn validate_response_scheduler_fence(
    owner: Option<&LeaseOwnerId>,
    token: Option<u64>,
    required: bool,
    current: &mut Option<(LeaseOwnerId, u64)>,
    highest_legacy_token: &mut u64,
) -> Result<()> {
    match (owner, token) {
        (None, None) if !required && current.is_none() => Ok(()),
        (None, Some(token)) if !required && current.is_none() && token > 0 => {
            if token < *highest_legacy_token {
                return Err(response_snapshot_error(
                    "legacy scheduler fencing token regressed",
                ));
            }
            *highest_legacy_token = token;
            Ok(())
        }
        (Some(owner), Some(token)) if token > 0 => {
            if let Some((current_owner, current_token)) = current.as_ref() {
                if token < *current_token
                    || (token == *current_token && owner != current_owner)
                    || (owner != current_owner && token <= *current_token)
                {
                    return Err(response_snapshot_error(
                        "scheduler owner or fencing token regressed",
                    ));
                }
            } else if *highest_legacy_token > 0 && token <= *highest_legacy_token {
                return Err(response_snapshot_error(
                    "scheduler owner is not a strictly fenced legacy takeover",
                ));
            }
            *current = Some((owner.clone(), token));
            Ok(())
        }
        _ => Err(response_snapshot_error(
            "scheduler owner and fencing token binding is invalid",
        )),
    }
}

fn response_rollback_progress(
    current: ResponseEffectProgress,
    outcome: &ResponseRollbackOutcome,
) -> Result<ResponseEffectProgress> {
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
        _ => Err(response_snapshot_error(
            "response rollback transition is invalid",
        )),
    }
}

fn response_completion_effect_states(
    progress: &[ResponseEffectProgress],
    failures: &[Option<ErrorCode>],
) -> Vec<ResponseCompletionEffectState> {
    progress
        .iter()
        .zip(failures)
        .map(|(progress, failure)| match progress {
            ResponseEffectProgress::Planned => ResponseCompletionEffectState::Planned,
            ResponseEffectProgress::Requested => ResponseCompletionEffectState::Requested,
            ResponseEffectProgress::Applied => ResponseCompletionEffectState::Applied,
            ResponseEffectProgress::ApplyFailed => failure
                .as_ref()
                .map(|error| ResponseCompletionEffectState::ApplyFailed(error.clone()))
                .unwrap_or(ResponseCompletionEffectState::Unresolved),
            ResponseEffectProgress::RollbackRequested
            | ResponseEffectProgress::Restored
            | ResponseEffectProgress::RollbackFailed => ResponseCompletionEffectState::Unresolved,
        })
        .collect()
}

fn response_exact_effect_failure(
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

fn response_dispatch_failure_before_effect(
    snapshot: &ResponseSnapshot,
    from_state: ResponseState,
    to_state: ResponseState,
    occurred_at_unix_ms: u64,
    error: &ErrorCode,
    applying_lease_expires_at_unix_ms: Option<u64>,
    progress: &[ResponseEffectProgress],
) -> bool {
    snapshot.execution_dispatch.is_some()
        && from_state == ResponseState::Applying
        && to_state == ResponseState::Failed
        && progress
            .iter()
            .all(|effect| *effect == ResponseEffectProgress::Planned)
        && ((error.as_str() == RESPONSE_DISPATCH_COMMITTED_RESUME_EXPIRED_ERROR
            && occurred_at_unix_ms == snapshot.plan.expires_at_unix_ms)
            || (error.as_str() == RESPONSE_DISPATCH_APPLY_LEASE_EXPIRED_BEFORE_EFFECT_ERROR
                && applying_lease_expires_at_unix_ms == Some(occurred_at_unix_ms)))
}

fn response_reserved_failure_timing_is_valid(
    from_state: ResponseState,
    to_state: ResponseState,
    occurred_at_unix_ms: u64,
    error: &ErrorCode,
    applying_lease_expires_at_unix_ms: Option<u64>,
    dispatch_failure_before_effect: bool,
) -> bool {
    match error.as_str() {
        RESPONSE_DISPATCH_COMMITTED_RESUME_EXPIRED_ERROR
        | RESPONSE_DISPATCH_APPLY_LEASE_EXPIRED_BEFORE_EFFECT_ERROR => {
            dispatch_failure_before_effect
        }
        RESPONSE_APPLYING_LEASE_EXPIRED_ERROR => {
            from_state == ResponseState::Applying
                && to_state == ResponseState::ApplyPartial
                && applying_lease_expires_at_unix_ms == Some(occurred_at_unix_ms)
        }
        _ => true,
    }
}

fn response_state_due(
    plan: &ResponsePlan,
    state: ResponseState,
    occurred_at_unix_ms: u64,
    applying_lease_expires_at_unix_ms: Option<u64>,
) -> Result<Option<u64>> {
    Ok(match state {
        ResponseState::Planned | ResponseState::AwaitingApproval | ResponseState::Active => {
            Some(plan.expires_at_unix_ms)
        }
        ResponseState::Applying => Some(
            applying_lease_expires_at_unix_ms
                .ok_or_else(|| response_snapshot_error("applying response lease is missing"))?,
        ),
        ResponseState::ApplyPartial
        | ResponseState::Expiring
        | ResponseState::RollingBack
        | ResponseState::RollbackPartial => Some(occurred_at_unix_ms),
        ResponseState::Cancelled
        | ResponseState::Expired
        | ResponseState::Failed
        | ResponseState::Lifted => None,
    })
}

fn validate_policy(
    policy: &ActiveDefensePolicyBinding,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    require_nonzero_digest(&policy.policy_hash, "policy_hash")
}

fn validate_response_binding(
    response: &ActiveDefenseResponseBinding,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    validate_policy(&response.policy)?;
    require_nonzero_digest(&response.plan_hash, "plan_hash")?;
    require_nonzero_digest(&response.trigger_finding_hash, "trigger_finding_hash")?;
    require_nonzero_digest(&response.affected_set_hash, "affected_set_hash")?;
    require_nonzero_time(response.plan_expires_at_unix_ms, "plan_expires_at_unix_ms")?;
    require_json_safe_time(response.plan_expires_at_unix_ms, "plan_expires_at_unix_ms")
}

fn validate_execution_dispatch_binding_pair(
    execution_dispatch: &Option<ResponseExecutionDispatchBinding>,
    dispatch_authorization_hash: &Option<Digest32>,
    header: &ActiveDefenseReceiptHeader,
    response: &ActiveDefenseResponseBinding,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    match (execution_dispatch, dispatch_authorization_hash) {
        (None, None) => Ok(()),
        (Some(dispatch), Some(authorization_hash)) => {
            require_nonzero_digest(authorization_hash, "dispatch_authorization_hash")?;
            dispatch
                .validate_for_response(
                    &header.tenant_id,
                    &response.action_id,
                    &response.plan_hash,
                    response.plan_expires_at_unix_ms,
                )
                .map_err(|_| ActiveDefenseReceiptValidationError::InvalidResponseDispatchBinding)?;
            if dispatch.authorized_at_unix_ms > header.occurred_at_unix_ms {
                return Err(ActiveDefenseReceiptValidationError::InvalidResponseDispatchBinding);
            }
            Ok(())
        }
        _ => Err(ActiveDefenseReceiptValidationError::InvalidResponseDispatchBinding),
    }
}

fn validate_flow_denial(
    body: &FlowDenialReceiptBody,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    validate_policy(&body.policy)?;
    require_nonzero_digest(&body.request_hash, "request_hash")?;
    require_nonzero_digest(&body.source_label_hash, "source_label_hash")?;
    require_nonzero_digest(&body.destination_label_hash, "destination_label_hash")?;
    require_nonzero_digest(&body.guard_evidence_hash, "guard_evidence_hash")
}

fn validate_declassification_consumption(
    body: &DeclassificationConsumptionReceiptBody,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    validate_policy(&body.policy)?;
    require_nonzero_digest(&body.grant_hash, "grant_hash")?;
    require_nonzero_digest(&body.request_hash, "request_hash")?;
    if body.state != DeclassificationUseState::ConsumedPendingDispatch {
        return Err(ActiveDefenseReceiptValidationError::InvalidDeclassificationConsumptionState);
    }
    Ok(())
}

fn validate_declassification_outcome(
    body: &DeclassificationOutcomeReceiptBody,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    validate_policy(&body.policy)?;
    require_nonzero_digest(&body.grant_hash, "grant_hash")?;
    require_nonzero_digest(&body.request_hash, "request_hash")?;
    if body.from_state != DeclassificationUseState::ConsumedPendingDispatch
        || !matches!(
            body.to_state,
            DeclassificationUseState::Released
                | DeclassificationUseState::DispatchFailed
                | DeclassificationUseState::OutcomeUnknown
        )
    {
        return Err(ActiveDefenseReceiptValidationError::InvalidDeclassificationOutcomeTransition);
    }
    Ok(())
}

fn validate_tripwire_observation(
    body: &TripwireObservationReceiptBody,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    validate_policy(&body.policy)?;
    require_nonzero_digest(&body.request_hash, "request_hash")?;
    require_nonzero_digest(&body.artifact_id_hash, "artifact_id_hash")?;
    require_nonzero_digest(&body.artifact_version_hash, "artifact_version_hash")?;
    require_nonzero_digest(&body.observation_hash, "observation_hash")
}

fn validate_correlated_finding(
    body: &CorrelatedFindingReceiptBody,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    validate_policy(&body.policy)?;
    require_prior_receipt(&body.header)?;
    require_nonzero_digest(&body.finding_hash, "finding_hash")?;
    require_nonzero_digest(&body.rule_version_hash, "rule_version_hash")?;
    require_nonzero_digest(&body.group_key_hash, "group_key_hash")?;
    let event_ids = body.ordered_event_ids.as_slice();
    let evidence_digests = body.ordered_evidence_digests.as_slice();
    let source_receipt_ids = body.ordered_source_receipt_ids.as_slice();
    if event_ids.is_empty() {
        return Err(ActiveDefenseReceiptValidationError::EmptyFindingEvents);
    }
    if event_ids.len() != evidence_digests.len() || event_ids.len() != source_receipt_ids.len() {
        return Err(ActiveDefenseReceiptValidationError::MismatchedFindingEvidence);
    }
    for (index, event_id) in event_ids.iter().enumerate() {
        if event_ids[..index].contains(event_id) {
            return Err(ActiveDefenseReceiptValidationError::DuplicateFindingEvent);
        }
        require_nonzero_digest(&evidence_digests[index], "ordered_evidence_digest")?;
    }
    let mut expected_priors = source_receipt_ids.to_vec();
    expected_priors.sort();
    expected_priors.dedup();
    if body.header.prior_receipt_ids.as_slice() != expected_priors.as_slice() {
        return Err(ActiveDefenseReceiptValidationError::FindingPriorReceiptMismatch);
    }
    require_nonzero_time(body.first_event_time_unix_ms, "first_event_time_unix_ms")?;
    require_nonzero_time(body.last_event_time_unix_ms, "last_event_time_unix_ms")?;
    if body.first_event_time_unix_ms > body.last_event_time_unix_ms
        || body.last_event_time_unix_ms > body.header.occurred_at_unix_ms
    {
        return Err(ActiveDefenseReceiptValidationError::InvalidTimeRange(
            "correlated_finding_event_time",
        ));
    }
    Ok(())
}

fn validate_response_plan(
    body: &ResponsePlanReceiptBody,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    require_prior_receipt(&body.header)?;
    validate_response_binding(&body.response)?;
    if !body
        .header
        .prior_receipt_ids
        .as_slice()
        .contains(&body.response.trigger_finding_receipt_id)
    {
        return Err(ActiveDefenseReceiptValidationError::MissingTriggerFindingReceipt);
    }
    require_nonzero_time(body.plan_created_at_unix_ms, "plan_created_at_unix_ms")?;
    if body.plan_created_at_unix_ms > body.header.occurred_at_unix_ms
        || body.plan_created_at_unix_ms >= body.response.plan_expires_at_unix_ms
    {
        return Err(ActiveDefenseReceiptValidationError::InvalidTimeRange(
            "response_plan",
        ));
    }
    validate_effect_commitments(
        body.effects.as_slice(),
        &body.header.tenant_id,
        EffectOrder::ContiguousFromZero,
    )
}

fn validate_response_state_transition(
    body: &ResponseStateTransitionReceiptBody,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    require_single_prior_receipt(&body.header)?;
    validate_response_binding(&body.response)?;
    if body.generation == 0 {
        return Err(ActiveDefenseReceiptValidationError::ZeroResponseGeneration);
    }
    require_json_safe_integer(body.generation, "generation")?;
    if !is_legal_response_transition(body.from_state, body.to_state)
        || expected_response_transition_cause(body) != Some(body.cause)
    {
        return Err(ActiveDefenseReceiptValidationError::InvalidResponseStateTransition);
    }

    let applying_lease_is_valid = match body.to_state {
        ResponseState::Applying => body.applying_lease_expires_at_unix_ms.is_some_and(|lease| {
            lease > body.header.occurred_at_unix_ms
                && lease <= body.response.plan_expires_at_unix_ms
        }),
        _ => body.applying_lease_expires_at_unix_ms.is_none(),
    };
    let needs_error = matches!(
        body.to_state,
        ResponseState::Failed | ResponseState::ApplyPartial | ResponseState::RollbackPartial
    );
    let expiry_is_valid = body.cause != ResponseTransitionCause::PlanExpired
        || body.header.occurred_at_unix_ms >= body.response.plan_expires_at_unix_ms;
    if let Some(token) = body.scheduler_fencing_token {
        require_json_safe_integer(token, "scheduler_fencing_token")?;
    }
    let applying_renewal = body.from_state == ResponseState::Applying
        && body.to_state == ResponseState::Applying;
    let scheduler_fence_is_valid = match (
        &body.scheduler_lease_owner_id,
        body.scheduler_fencing_token,
    ) {
        (Some(_), Some(token)) => token > 0,
        (None, None) => !applying_renewal,
        _ => false,
    };
    if !applying_lease_is_valid
        || !scheduler_fence_is_valid
        || needs_error != body.error_code.is_some()
        || !expiry_is_valid
    {
        return Err(ActiveDefenseReceiptValidationError::InvalidResponseStateTransition);
    }
    Ok(())
}

fn expected_response_transition_cause(
    body: &ResponseStateTransitionReceiptBody,
) -> Option<ResponseTransitionCause> {
    match (body.from_state, body.to_state) {
        (ResponseState::Planned, ResponseState::AwaitingApproval) => {
            Some(ResponseTransitionCause::ApprovalRequested)
        }
        (ResponseState::Planned, ResponseState::Applying) => {
            Some(ResponseTransitionCause::ApplyStarted)
        }
        (ResponseState::AwaitingApproval, ResponseState::Applying) => {
            Some(ResponseTransitionCause::ApprovalSatisfied)
        }
        (ResponseState::Applying, ResponseState::Applying) => {
            Some(ResponseTransitionCause::ApplyingLeaseRenewed)
        }
        (ResponseState::Applying, ResponseState::Active) => {
            Some(ResponseTransitionCause::ApplyCompleted)
        }
        (ResponseState::Planned | ResponseState::AwaitingApproval, ResponseState::Cancelled) => {
            Some(ResponseTransitionCause::OperatorCancelled)
        }
        (ResponseState::Planned | ResponseState::AwaitingApproval, ResponseState::Expired)
        | (ResponseState::Active, ResponseState::Expiring) => {
            Some(ResponseTransitionCause::PlanExpired)
        }
        (
            ResponseState::ApplyPartial | ResponseState::Active | ResponseState::Expiring,
            ResponseState::RollingBack,
        ) => Some(ResponseTransitionCause::RollbackRequested),
        (ResponseState::RollbackPartial, ResponseState::RollingBack) => {
            Some(ResponseTransitionCause::RollbackRetry)
        }
        (ResponseState::RollingBack, ResponseState::Lifted) => {
            Some(ResponseTransitionCause::RollbackCompleted)
        }
        (ResponseState::RollingBack, ResponseState::RollbackPartial) => {
            Some(ResponseTransitionCause::RollbackFailed)
        }
        (ResponseState::Applying, ResponseState::ApplyPartial)
            if body
                .error_code
                .as_ref()
                .is_some_and(|code| code.as_str() == "response.applying_lease_expired") =>
        {
            Some(ResponseTransitionCause::ApplyingLeaseExpired)
        }
        (
            ResponseState::Planned | ResponseState::AwaitingApproval | ResponseState::Applying,
            ResponseState::Failed,
        )
        | (ResponseState::Applying, ResponseState::ApplyPartial) => {
            Some(ResponseTransitionCause::ValidationFailed)
        }
        _ => None,
    }
}

fn validate_effect_transition(
    body: &EffectTransitionReceiptBody,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    require_single_prior_receipt(&body.header)?;
    validate_response_binding(&body.response)?;
    validate_effect_commitment(&body.effect, &body.header.tenant_id)?;
    if body.generation == 0 {
        return Err(ActiveDefenseReceiptValidationError::ZeroResponseGeneration);
    }
    require_json_safe_integer(body.generation, "generation")?;
    if body.scheduler_fencing_token == 0 {
        return Err(ActiveDefenseReceiptValidationError::ZeroSchedulerFencingToken);
    }
    require_json_safe_integer(body.scheduler_fencing_token, "scheduler_fencing_token")?;
    validate_effect_outcome_hashes(&body.outcome)?;
    let rollback_outcome = matches!(
        body.outcome,
        ActiveDefenseEffectOutcome::RollbackRequested
            | ActiveDefenseEffectOutcome::Restored { .. }
            | ActiveDefenseEffectOutcome::RollbackFailed { .. }
    );
    if matches!(
        body.outcome,
        ActiveDefenseEffectOutcome::Planned | ActiveDefenseEffectOutcome::NoRollbackRequired
    ) || (rollback_outcome && !body.effect.kind.is_reversible())
    {
        return Err(ActiveDefenseReceiptValidationError::InvalidEffectTransition);
    }
    Ok(())
}

fn validate_response_completion(
    body: &ResponseCompletionReceiptBody,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    require_single_prior_receipt(&body.header)?;
    validate_response_binding(&body.response)?;
    validate_execution_dispatch_binding_pair(
        &body.execution_dispatch,
        &body.dispatch_authorization_hash,
        &body.header,
        &body.response,
    )?;
    if body.response_generation == 0 {
        return Err(ActiveDefenseReceiptValidationError::ZeroResponseGeneration);
    }
    require_json_safe_integer(body.response_generation, "response_generation")?;
    require_nonzero_digest(&body.response_body_hash, "response_body_hash")?;
    validate_effect_outcome_commitments(
        body.effects.as_slice(),
        &body.header.tenant_id,
        EffectOrder::ContiguousFromZero,
    )?;

    let effect_states = body
        .effects
        .as_slice()
        .iter()
        .map(|effect| match &effect.outcome {
            ActiveDefenseEffectOutcome::Planned => ResponseCompletionEffectState::Planned,
            ActiveDefenseEffectOutcome::Requested => ResponseCompletionEffectState::Requested,
            ActiveDefenseEffectOutcome::Applied { .. } => ResponseCompletionEffectState::Applied,
            ActiveDefenseEffectOutcome::ApplyFailed { error_code } => {
                ResponseCompletionEffectState::ApplyFailed(error_code.clone())
            }
            _ => ResponseCompletionEffectState::Unresolved,
        })
        .collect::<Vec<_>>();
    if !response_completion_effect_shape_is_valid(
        body.final_state,
        body.error_code.as_ref(),
        &effect_states,
    ) {
        return Err(ActiveDefenseReceiptValidationError::InvalidResponseCompletion);
    }
    Ok(())
}

fn validate_lift_rollback_completion(
    body: &LiftRollbackCompletionReceiptBody,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    require_single_prior_receipt(&body.header)?;
    validate_response_binding(&body.response)?;
    validate_execution_dispatch_binding_pair(
        &body.execution_dispatch,
        &body.dispatch_authorization_hash,
        &body.header,
        &body.response,
    )?;
    if body.response_generation == 0 {
        return Err(ActiveDefenseReceiptValidationError::ZeroResponseGeneration);
    }
    require_json_safe_integer(body.response_generation, "response_generation")?;
    require_nonzero_digest(&body.response_body_hash, "response_body_hash")?;
    validate_effect_outcome_commitments(
        body.effects.as_slice(),
        &body.header.tenant_id,
        EffectOrder::ContiguousFromZero,
    )?;

    let mut rollback_failures = 0_usize;
    for effect in body.effects.as_slice() {
        let valid = match (&effect.outcome, effect.effect.kind.is_reversible()) {
            (ActiveDefenseEffectOutcome::Restored { .. }, true) => true,
            (ActiveDefenseEffectOutcome::RollbackFailed { .. }, true) => {
                rollback_failures += 1;
                true
            }
            (
                ActiveDefenseEffectOutcome::Planned
                | ActiveDefenseEffectOutcome::ApplyFailed { .. },
                _,
            ) => true,
            (ActiveDefenseEffectOutcome::NoRollbackRequired, false) => true,
            _ => false,
        };
        if !valid {
            return Err(ActiveDefenseReceiptValidationError::InvalidLiftRollbackCompletion);
        }
    }
    let valid = match body.final_state {
        ResponseState::Lifted => rollback_failures == 0,
        ResponseState::RollbackPartial => rollback_failures > 0,
        _ => false,
    };
    if !valid {
        return Err(ActiveDefenseReceiptValidationError::InvalidLiftRollbackCompletion);
    }
    Ok(())
}

fn validate_detector_health(
    body: &DetectorHealthReceiptBody,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    validate_policy(&body.policy)?;
    require_nonzero_digest(&body.rule_version_hash, "rule_version_hash")?;
    if let DetectorGroupBindingEvidence::Resolved { group_key_hash } = body.group_binding {
        require_nonzero_digest(&group_key_hash, "group_key_hash")?;
    }
    if matches!(body.group_binding, DetectorGroupBindingEvidence::Unresolved)
        && !matches!(&body.watermark, DetectorWatermarkEvidence::Unknown)
    {
        return Err(ActiveDefenseReceiptValidationError::InvalidDetectorKnowledge);
    }
    require_nonzero_digest(&body.evidence_hash, "evidence_hash")?;
    match &body.watermark {
        DetectorWatermarkEvidence::Unknown => {}
        DetectorWatermarkEvidence::Committed { unix_ms } => {
            require_nonzero_time(*unix_ms, "watermark.unix_ms")?;
            require_json_safe_time(*unix_ms, "watermark.unix_ms")?;
            if *unix_ms > body.header.occurred_at_unix_ms {
                return Err(ActiveDefenseReceiptValidationError::InvalidTimeRange(
                    "detector_watermark",
                ));
            }
        }
        DetectorWatermarkEvidence::Contradictory { claimed_unix_ms } => {
            let Some(claimed) = parse_canonical_u64(claimed_unix_ms) else {
                return Err(ActiveDefenseReceiptValidationError::InvalidDetectorKnowledge);
            };
            if body.health_kind != DetectorHealthKind::CorruptState
                || (claimed != 0
                    && claimed <= body.header.occurred_at_unix_ms
                    && claimed <= MAX_ACTIVE_DEFENSE_JSON_INTEGER)
            {
                return Err(ActiveDefenseReceiptValidationError::InvalidDetectorKnowledge);
            }
        }
    }
    Ok(())
}

fn validate_scheduler_health(
    body: &SchedulerHealthReceiptBody,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    require_prior_receipt(&body.header)?;
    validate_response_binding(&body.response)?;
    require_nonzero_digest(&body.evidence_hash, "evidence_hash")?;
    require_nonzero_time(body.first_failure_at_unix_ms, "first_failure_at_unix_ms")?;
    if body.first_failure_at_unix_ms > body.header.occurred_at_unix_ms {
        return Err(ActiveDefenseReceiptValidationError::InvalidTimeRange(
            "scheduler_first_failure",
        ));
    }
    if body.attempts == 0 {
        return Err(ActiveDefenseReceiptValidationError::ZeroSchedulerAttempts);
    }
    if body.scheduler_fencing_token == 0 {
        return Err(ActiveDefenseReceiptValidationError::ZeroSchedulerFencingToken);
    }
    require_json_safe_integer(body.scheduler_fencing_token, "scheduler_fencing_token")?;
    Ok(())
}

#[derive(Clone, Copy)]
enum EffectOrder {
    ContiguousFromZero,
}

fn validate_effect_commitments(
    effects: &[ActiveDefenseEffectCommitment],
    tenant_id: &TenantId,
    order: EffectOrder,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    if effects.is_empty() {
        return Err(ActiveDefenseReceiptValidationError::EmptyEffects);
    }
    for (index, effect) in effects.iter().enumerate() {
        validate_effect_order(effects, index, effect, order)?;
        validate_effect_commitment(effect, tenant_id)?;
    }
    Ok(())
}

fn validate_effect_outcome_commitments(
    effects: &[ActiveDefenseEffectOutcomeCommitment],
    tenant_id: &TenantId,
    order: EffectOrder,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    if effects.is_empty() {
        return Err(ActiveDefenseReceiptValidationError::EmptyEffects);
    }
    for (index, effect) in effects.iter().enumerate() {
        if matches!(order, EffectOrder::ContiguousFromZero)
            && usize::from(effect.effect.ordinal) != index
        {
            return Err(ActiveDefenseReceiptValidationError::InvalidEffectOrdinal);
        }
        if effects[..index]
            .iter()
            .any(|earlier| earlier.effect.effect_id == effect.effect.effect_id)
        {
            return Err(ActiveDefenseReceiptValidationError::DuplicateEffectId);
        }
        validate_effect_commitment(&effect.effect, tenant_id)?;
        validate_effect_outcome_hashes(&effect.outcome)?;
    }
    Ok(())
}

fn validate_effect_order(
    effects: &[ActiveDefenseEffectCommitment],
    index: usize,
    effect: &ActiveDefenseEffectCommitment,
    order: EffectOrder,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    if matches!(order, EffectOrder::ContiguousFromZero) && usize::from(effect.ordinal) != index {
        return Err(ActiveDefenseReceiptValidationError::InvalidEffectOrdinal);
    }
    if effects[..index]
        .iter()
        .any(|earlier| earlier.effect_id == effect.effect_id)
    {
        return Err(ActiveDefenseReceiptValidationError::DuplicateEffectId);
    }
    Ok(())
}

fn validate_effect_commitment(
    effect: &ActiveDefenseEffectCommitment,
    tenant_id: &TenantId,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    if !effect.kind.accepts_target(&effect.target) {
        return Err(ActiveDefenseReceiptValidationError::InvalidEffectTarget);
    }
    if matches!(
        &effect.target,
        ResponseTarget::Tenant {
            tenant_id: target_tenant
        } if target_tenant != tenant_id
    ) {
        return Err(ActiveDefenseReceiptValidationError::CrossTenantTarget);
    }
    require_nonzero_digest(&effect.contribution_hash, "effect_contribution_hash")?;
    require_nonzero_digest(
        &effect.observed_base_version_hash,
        "effect_observed_base_version_hash",
    )
}

fn validate_effect_outcome_hashes(
    outcome: &ActiveDefenseEffectOutcome,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    match outcome {
        ActiveDefenseEffectOutcome::Applied {
            resulting_version_hash,
        }
        | ActiveDefenseEffectOutcome::Restored {
            resulting_version_hash,
        } => require_nonzero_digest(resulting_version_hash, "resulting_version_hash"),
        _ => Ok(()),
    }
}

fn require_prior_receipt(
    header: &ActiveDefenseReceiptHeader,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    if header.prior_receipt_ids.is_empty() {
        return Err(ActiveDefenseReceiptValidationError::MissingPriorReceipt);
    }
    Ok(())
}

fn require_single_prior_receipt(
    header: &ActiveDefenseReceiptHeader,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    require_prior_receipt(header)?;
    if header.prior_receipt_ids.as_slice().len() != 1 {
        return Err(ActiveDefenseReceiptValidationError::InvalidPriorReceiptCount);
    }
    Ok(())
}

fn require_nonzero_time(
    value: u64,
    field: &'static str,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    if value == 0 {
        return Err(ActiveDefenseReceiptValidationError::ZeroTime(field));
    }
    Ok(())
}

fn require_json_safe_time(
    value: u64,
    field: &'static str,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    if value > MAX_ACTIVE_DEFENSE_JSON_INTEGER {
        return Err(ActiveDefenseReceiptValidationError::InvalidTimeRange(field));
    }
    Ok(())
}

fn require_json_safe_integer(
    value: u64,
    field: &'static str,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    if value > MAX_ACTIVE_DEFENSE_JSON_INTEGER {
        return Err(ActiveDefenseReceiptValidationError::InvalidJsonInteger(
            field,
        ));
    }
    Ok(())
}

fn parse_canonical_u64(value: &str) -> Option<u64> {
    let parsed = value.parse::<u64>().ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

fn require_nonzero_digest(
    digest: &Digest32,
    field: &'static str,
) -> core::result::Result<(), ActiveDefenseReceiptValidationError> {
    if digest.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(ActiveDefenseReceiptValidationError::ZeroDigest(field));
    }
    Ok(())
}
