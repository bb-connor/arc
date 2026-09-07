use chio_security_types::ports::{
    Digest32, EffectId, LeaseOwnerId, OpaqueReceiptRef, PreparedActiveResponseDispatchBinding,
    RecordId, ResponseDispatchApproval, TenantId,
    PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
};
use chio_security_types::{
    is_legal_response_transition, response_required_mutation_suffix,
    response_snapshot_has_mutation_capacity, PlannedResponseEffects, ResponseEffectAppliedRecord,
    ResponseEffectKind, ResponseEffectRequestedRecord, ResponseMutationLog, ResponseMutationRecord,
    ResponsePlan, ResponseRequestedRecord, ResponseRollbackOutcome, ResponseRollbackRecord,
    ResponseShapeError, ResponseSnapshot, ResponseState, ResponseTarget, ResponseTransitionCause,
    ResponseTransitionRecord, MAX_RESPONSE_MUTATIONS, RESPONSE_STATE_SCHEMA_VERSION,
};

const STATES: [ResponseState; 12] = [
    ResponseState::Planned,
    ResponseState::AwaitingApproval,
    ResponseState::Applying,
    ResponseState::Active,
    ResponseState::ApplyPartial,
    ResponseState::Expiring,
    ResponseState::RollingBack,
    ResponseState::RollbackPartial,
    ResponseState::Cancelled,
    ResponseState::Expired,
    ResponseState::Failed,
    ResponseState::Lifted,
];

type ResponsePlanMutation = fn(&mut ResponsePlan);
type ResponsePlanShapeCase = (ResponseShapeError, ResponsePlanMutation);

#[test]
fn response_transition_matrix_contains_only_the_specified_edges() {
    let legal = [
        (ResponseState::Planned, ResponseState::AwaitingApproval),
        (ResponseState::Planned, ResponseState::Applying),
        (ResponseState::Planned, ResponseState::Cancelled),
        (ResponseState::Planned, ResponseState::Expired),
        (ResponseState::Planned, ResponseState::Failed),
        (ResponseState::AwaitingApproval, ResponseState::Applying),
        (ResponseState::AwaitingApproval, ResponseState::Cancelled),
        (ResponseState::AwaitingApproval, ResponseState::Expired),
        (ResponseState::AwaitingApproval, ResponseState::Failed),
        (ResponseState::Applying, ResponseState::Applying),
        (ResponseState::Applying, ResponseState::Active),
        (ResponseState::Applying, ResponseState::ApplyPartial),
        (ResponseState::Applying, ResponseState::Failed),
        (ResponseState::ApplyPartial, ResponseState::RollingBack),
        (ResponseState::Active, ResponseState::Expiring),
        (ResponseState::Active, ResponseState::RollingBack),
        (ResponseState::Expiring, ResponseState::RollingBack),
        (ResponseState::RollingBack, ResponseState::Lifted),
        (ResponseState::RollingBack, ResponseState::RollbackPartial),
        (ResponseState::RollbackPartial, ResponseState::RollingBack),
    ];

    for from in STATES {
        for to in STATES {
            assert_eq!(
                is_legal_response_transition(from, to),
                legal.contains(&(from, to)),
                "unexpected transition result for {from:?} -> {to:?}"
            );
        }
    }
}

#[test]
fn permanent_revocation_is_not_a_reversible_effect_kind() {
    let reversible = [
        ResponseEffectKind::EscalateAlert,
        ResponseEffectKind::ThrottleSession,
        ResponseEffectKind::RestrictEgress,
        ResponseEffectKind::SuspendSession,
        ResponseEffectKind::SuspendCapabilitySet,
        ResponseEffectKind::FreezeIssuance,
    ];
    for kind in reversible {
        let encoded = serde_json::to_string(&kind)
            .unwrap_or_else(|error| panic!("effect kind serialization failed: {error}"));
        assert!(!encoded.contains("revocation"));
    }
    assert!(serde_json::from_str::<ResponseEffectKind>("\"permanent_revocation\"").is_err());
}

#[test]
fn response_targets_and_mutation_records_reject_unknown_fields() {
    let target = ResponseTarget::Tenant {
        tenant_id: TenantId::new("tenant-response")
            .unwrap_or_else(|error| panic!("invalid tenant id: {error}")),
    };
    let mut target_value = serde_json::to_value(target)
        .unwrap_or_else(|error| panic!("target serialization failed: {error}"));
    target_value["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ResponseTarget>(target_value).is_err());

    let mutation = ResponseMutationRecord::Requested(ResponseRequestedRecord {
        transition_id: RecordId::new("response-request")
            .unwrap_or_else(|error| panic!("invalid transition id: {error}")),
        generation: 0,
        prior_receipt_id: OpaqueReceiptRef::new("finding-receipt")
            .unwrap_or_else(|error| panic!("invalid prior receipt id: {error}")),
        occurred_at_unix_ms: 100,
    });
    let mut mutation_value = serde_json::to_value(mutation)
        .unwrap_or_else(|error| panic!("mutation serialization failed: {error}"));
    mutation_value["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ResponseMutationRecord>(mutation_value).is_err());
}

fn valid_response_plan() -> ResponsePlan {
    serde_json::from_str(include_str!(
        "../../../../tests/bindings/vectors/security/active-defense/positive/response-plan-v1.json"
    ))
    .unwrap_or_else(|error| panic!("response plan fixture failed: {error}"))
}

fn applying_snapshot_with_reversible_effects(effect_count: usize) -> ResponseSnapshot {
    let mut plan = valid_response_plan();
    let template = plan.effects.as_slice()[0].clone();
    assert!(template.kind.is_reversible());
    let effects = (0..effect_count)
        .map(|ordinal| {
            let mut effect = template.clone();
            effect.effect_id = EffectId::new(format!("capacity-effect-{ordinal}"))
                .unwrap_or_else(|error| panic!("invalid effect id: {error}"));
            effect.ordinal = u16::try_from(ordinal)
                .unwrap_or_else(|error| panic!("effect ordinal overflow: {error}"));
            effect
        })
        .collect();
    plan.effects = PlannedResponseEffects::new(effects)
        .unwrap_or_else(|error| panic!("bounded effects failed: {error}"));
    ResponseSnapshot {
        schema_version: RESPONSE_STATE_SCHEMA_VERSION,
        plan,
        execution_dispatch: None,
        dispatch_authorization_hash: None,
        state: ResponseState::Applying,
        generation: 1,
        applying_lease_expires_at_unix_ms: Some(1_000),
        due_at_unix_ms: Some(1_000),
        operator_page_required: false,
        mutations: ResponseMutationLog::new(Vec::new())
            .unwrap_or_else(|error| panic!("empty mutation log failed: {error}")),
    }
}

fn capacity_effect_requested(
    snapshot: &ResponseSnapshot,
    ordinal: usize,
    generation: u64,
) -> ResponseMutationRecord {
    ResponseMutationRecord::EffectRequested(ResponseEffectRequestedRecord {
        transition_id: RecordId::new(format!("capacity-request-{ordinal}-{generation}"))
            .unwrap_or_else(|error| panic!("invalid transition id: {error}")),
        generation,
        effect_id: snapshot.plan.effects.as_slice()[ordinal].effect_id.clone(),
        effect_generation: 1,
        scheduler_lease_owner_id: Some(
            LeaseOwnerId::new("capacity-scheduler")
                .unwrap_or_else(|error| panic!("invalid lease owner: {error}")),
        ),
        scheduler_fencing_token: 7,
        prior_receipt_id: OpaqueReceiptRef::new("capacity-prior")
            .unwrap_or_else(|error| panic!("invalid prior receipt: {error}")),
        occurred_at_unix_ms: 500,
    })
}

fn capacity_effect_applied(
    snapshot: &ResponseSnapshot,
    ordinal: usize,
    generation: u64,
) -> ResponseMutationRecord {
    ResponseMutationRecord::EffectApplied(ResponseEffectAppliedRecord {
        transition_id: RecordId::new(format!("capacity-applied-{ordinal}-{generation}"))
            .unwrap_or_else(|error| panic!("invalid transition id: {error}")),
        generation,
        effect_id: snapshot.plan.effects.as_slice()[ordinal].effect_id.clone(),
        effect_generation: 2,
        resulting_version_hash: Digest32::new([91; 32]),
        scheduler_lease_owner_id: Some(
            LeaseOwnerId::new("capacity-scheduler")
                .unwrap_or_else(|error| panic!("invalid lease owner: {error}")),
        ),
        scheduler_fencing_token: 7,
        effect_transition_id: Some(
            RecordId::new(format!("capacity-effect-receipt-{ordinal}"))
                .unwrap_or_else(|error| panic!("invalid effect transition id: {error}")),
        ),
        prior_receipt_id: OpaqueReceiptRef::new("capacity-prior")
            .unwrap_or_else(|error| panic!("invalid prior receipt: {error}")),
        occurred_at_unix_ms: 501,
    })
}

#[test]
fn mutation_capacity_reserves_the_complete_sixty_four_effect_lifecycle() {
    let mut snapshot = applying_snapshot_with_reversible_effects(64);
    assert_eq!(response_required_mutation_suffix(&snapshot), Some(390));

    let mut mutations = vec![capacity_effect_requested(&snapshot, 0, 2)];
    snapshot.mutations = ResponseMutationLog::new(mutations.clone())
        .unwrap_or_else(|error| panic!("requested mutation log failed: {error}"));
    assert_eq!(response_required_mutation_suffix(&snapshot), Some(389));

    mutations.push(capacity_effect_applied(&snapshot, 0, 3));
    snapshot.mutations = ResponseMutationLog::new(mutations.clone())
        .unwrap_or_else(|error| panic!("applied mutation log failed: {error}"));
    assert_eq!(response_required_mutation_suffix(&snapshot), Some(388));

    for ordinal in 1..64 {
        mutations.push(capacity_effect_requested(
            &snapshot,
            ordinal,
            u64::try_from(mutations.len() + 2)
                .unwrap_or_else(|error| panic!("generation overflow: {error}")),
        ));
        mutations.push(capacity_effect_applied(
            &snapshot,
            ordinal,
            u64::try_from(mutations.len() + 2)
                .unwrap_or_else(|error| panic!("generation overflow: {error}")),
        ));
    }
    snapshot.mutations = ResponseMutationLog::new(mutations)
        .unwrap_or_else(|error| panic!("all-applied mutation log failed: {error}"));
    assert_eq!(response_required_mutation_suffix(&snapshot), Some(262));

    snapshot.state = ResponseState::RollingBack;
    assert_eq!(response_required_mutation_suffix(&snapshot), Some(259));
}

#[test]
fn mutation_capacity_tracks_rollback_failure_and_retry_boundaries() {
    let mut snapshot = applying_snapshot_with_reversible_effects(64);
    let mut mutations = Vec::new();
    for ordinal in 0..64 {
        mutations.push(capacity_effect_requested(
            &snapshot,
            ordinal,
            u64::try_from(mutations.len() + 2)
                .unwrap_or_else(|error| panic!("generation overflow: {error}")),
        ));
        mutations.push(capacity_effect_applied(
            &snapshot,
            ordinal,
            u64::try_from(mutations.len() + 2)
                .unwrap_or_else(|error| panic!("generation overflow: {error}")),
        ));
    }
    snapshot.state = ResponseState::RollingBack;
    for ordinal in 0..64 {
        let effect_id = snapshot.plan.effects.as_slice()[ordinal].effect_id.clone();
        mutations.push(ResponseMutationRecord::Rollback(ResponseRollbackRecord {
            transition_id: RecordId::new(format!("rollback-request-{ordinal}"))
                .unwrap_or_else(|error| panic!("invalid transition id: {error}")),
            generation: u64::try_from(mutations.len() + 2)
                .unwrap_or_else(|error| panic!("generation overflow: {error}")),
            effect_id: effect_id.clone(),
            effect_generation: 3,
            outcome: ResponseRollbackOutcome::Requested,
            scheduler_lease_owner_id: Some(
                LeaseOwnerId::new("capacity-scheduler")
                    .unwrap_or_else(|error| panic!("invalid lease owner: {error}")),
            ),
            scheduler_fencing_token: 7,
            effect_transition_id: None,
            prior_receipt_id: OpaqueReceiptRef::new("capacity-prior")
                .unwrap_or_else(|error| panic!("invalid prior receipt: {error}")),
            occurred_at_unix_ms: 600,
        }));
        mutations.push(ResponseMutationRecord::Rollback(ResponseRollbackRecord {
            transition_id: RecordId::new(format!("rollback-failed-{ordinal}"))
                .unwrap_or_else(|error| panic!("invalid transition id: {error}")),
            generation: u64::try_from(mutations.len() + 2)
                .unwrap_or_else(|error| panic!("generation overflow: {error}")),
            effect_id,
            effect_generation: 4,
            outcome: ResponseRollbackOutcome::Failed {
                error_code: chio_security_types::ports::ErrorCode::new("rollback.failed")
                    .unwrap_or_else(|error| panic!("invalid error code: {error}")),
            },
            scheduler_lease_owner_id: Some(
                LeaseOwnerId::new("capacity-scheduler")
                    .unwrap_or_else(|error| panic!("invalid lease owner: {error}")),
            ),
            scheduler_fencing_token: 7,
            effect_transition_id: Some(
                RecordId::new(format!("rollback-failed-receipt-{ordinal}"))
                    .unwrap_or_else(|error| panic!("invalid effect transition id: {error}")),
            ),
            prior_receipt_id: OpaqueReceiptRef::new("capacity-prior")
                .unwrap_or_else(|error| panic!("invalid prior receipt: {error}")),
            occurred_at_unix_ms: 601,
        }));
    }
    snapshot.mutations = ResponseMutationLog::new(mutations)
        .unwrap_or_else(|error| panic!("rollback failure mutation log failed: {error}"));
    assert_eq!(response_required_mutation_suffix(&snapshot), Some(131));

    snapshot.state = ResponseState::RollbackPartial;
    assert_eq!(response_required_mutation_suffix(&snapshot), Some(130));
}

#[test]
fn mutation_capacity_accepts_the_exact_bound_and_rejects_one_more() {
    let mut snapshot = applying_snapshot_with_reversible_effects(64);
    let padding = ResponseMutationRecord::Transition(ResponseTransitionRecord {
        transition_id: RecordId::new("capacity-renewal")
            .unwrap_or_else(|error| panic!("invalid transition id: {error}")),
        generation: 1,
        from_state: ResponseState::Applying,
        to_state: ResponseState::Applying,
        cause: ResponseTransitionCause::ApplyingLeaseRenewed,
        applying_lease_expires_at_unix_ms: Some(1_000),
        scheduler_lease_owner_id: Some(
            LeaseOwnerId::new("capacity-scheduler")
                .unwrap_or_else(|error| panic!("invalid lease owner: {error}")),
        ),
        scheduler_fencing_token: Some(7),
        prior_receipt_id: OpaqueReceiptRef::new("capacity-prior")
            .unwrap_or_else(|error| panic!("invalid prior receipt: {error}")),
        occurred_at_unix_ms: 500,
    });
    snapshot.mutations =
        ResponseMutationLog::new(vec![padding.clone(); MAX_RESPONSE_MUTATIONS - 390])
            .unwrap_or_else(|error| panic!("exact-bound mutation log failed: {error}"));
    assert!(response_snapshot_has_mutation_capacity(&snapshot));

    let mut over = snapshot.mutations.into_vec();
    over.push(padding);
    snapshot.mutations = ResponseMutationLog::new(over)
        .unwrap_or_else(|error| panic!("over-bound mutation log failed: {error}"));
    assert!(!response_snapshot_has_mutation_capacity(&snapshot));
}

fn valid_prepared_dispatch_binding(plan: &ResponsePlan) -> PreparedActiveResponseDispatchBinding {
    PreparedActiveResponseDispatchBinding {
        schema_version: PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
        tenant_id: plan.tenant_id.clone(),
        action_id: plan.action_id.clone(),
        plan_hash: plan.plan_hash,
        dispatch_id: RecordId::new("dispatch-prepared-1")
            .unwrap_or_else(|error| panic!("invalid dispatch id: {error}")),
        executor_authority_id: RecordId::new("executor-authority-1")
            .unwrap_or_else(|error| panic!("invalid executor authority id: {error}")),
        executor_authority_generation: 1,
        authorized_at_unix_ms: plan.created_at_unix_ms,
        authorization_capability_hash: plan.operator_capability.capability_digest,
        governed_intent_hash: Digest32::new([41; 32]),
        policy_decision_hash: Digest32::new([42; 32]),
        approval: ResponseDispatchApproval::Automatic,
    }
}

#[test]
fn prepared_dispatch_binding_is_strict_and_plan_bound() {
    let plan = valid_response_plan();
    let binding = valid_prepared_dispatch_binding(&plan);
    binding
        .validate_for_plan(&plan)
        .unwrap_or_else(|error| panic!("valid prepared binding failed: {error}"));

    let encoded = serde_json::to_vec(&binding)
        .unwrap_or_else(|error| panic!("prepared binding serialization failed: {error}"));
    let decoded = serde_json::from_slice::<PreparedActiveResponseDispatchBinding>(&encoded)
        .unwrap_or_else(|error| panic!("prepared binding decoding failed: {error}"));
    assert_eq!(decoded, binding);

    let mut wrong_plan_hash = binding.clone();
    wrong_plan_hash.plan_hash = Digest32::new([43; 32]);
    assert!(wrong_plan_hash.validate_for_plan(&plan).is_err());

    let mut zero_generation = binding.clone();
    zero_generation.executor_authority_generation = 0;
    assert!(zero_generation.validate_for_plan(&plan).is_err());

    let mut authorization_before_plan = binding.clone();
    authorization_before_plan.authorized_at_unix_ms = plan.created_at_unix_ms.saturating_sub(1);
    assert!(authorization_before_plan.validate_for_plan(&plan).is_err());

    let mut authorization_at_expiry = binding.clone();
    authorization_at_expiry.authorized_at_unix_ms = plan.expires_at_unix_ms;
    assert!(authorization_at_expiry.validate_for_plan(&plan).is_err());

    let mut zero_intent_hash = binding.clone();
    zero_intent_hash.governed_intent_hash = Digest32::new([0; 32]);
    assert!(zero_intent_hash.validate_for_plan(&plan).is_err());

    let mut wrong_approval = binding;
    wrong_approval.approval = ResponseDispatchApproval::Governed {
        admission_operation_id: RecordId::new("operation-1")
            .unwrap_or_else(|error| panic!("invalid operation id: {error}")),
        admission_operation_version: 1,
        approval_set_hash: Digest32::new([44; 32]),
    };
    assert!(wrong_approval.validate_for_plan(&plan).is_err());
}

#[test]
fn prepared_dispatch_binding_rejects_unknown_serialized_fields() {
    let plan = valid_response_plan();
    let binding = valid_prepared_dispatch_binding(&plan);
    let mut value = serde_json::to_value(binding)
        .unwrap_or_else(|error| panic!("prepared binding serialization failed: {error}"));
    value["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PreparedActiveResponseDispatchBinding>(value).is_err());
}

#[test]
fn response_plan_rejects_zero_cryptographic_commitments() {
    let valid = valid_response_plan();
    valid
        .validate_shape()
        .unwrap_or_else(|error| panic!("valid response plan failed: {error}"));

    let cases: [ResponsePlanShapeCase; 4] = [
        (
            ResponseShapeError::InvalidAffectedSetHash,
            |plan: &mut ResponsePlan| plan.affected_set_hash = Digest32::new([0; 32]),
        ),
        (
            ResponseShapeError::InvalidOperatorCapabilityHash,
            |plan: &mut ResponsePlan| {
                plan.operator_capability.capability_digest = Digest32::new([0; 32]);
            },
        ),
        (
            ResponseShapeError::InvalidReasonHash,
            |plan: &mut ResponsePlan| plan.reason_hash = Digest32::new([0; 32]),
        ),
        (
            ResponseShapeError::InvalidPlanHash,
            |plan: &mut ResponsePlan| plan.plan_hash = Digest32::new([0; 32]),
        ),
    ];
    for (expected, mutate) in cases {
        let mut plan = valid.clone();
        mutate(&mut plan);
        assert_eq!(plan.validate_shape(), Err(expected));
    }

    let mut zero_contribution = valid.clone();
    let mut effects = zero_contribution.effects.into_vec();
    effects[0].contribution_hash = Digest32::new([0; 32]);
    zero_contribution.effects = PlannedResponseEffects::new(effects)
        .unwrap_or_else(|error| panic!("bounded effects failed: {error}"));
    assert_eq!(
        zero_contribution.validate_shape(),
        Err(ResponseShapeError::InvalidContributionHash)
    );

    let mut zero_base = valid.clone();
    let mut effects = zero_base.effects.into_vec();
    effects[0].observed_base_version_hash = Digest32::new([0; 32]);
    zero_base.effects = PlannedResponseEffects::new(effects)
        .unwrap_or_else(|error| panic!("bounded effects failed: {error}"));
    assert_eq!(
        zero_base.validate_shape(),
        Err(ResponseShapeError::InvalidObservedBaseVersionHash)
    );

    let mut zero_target = valid;
    let mut effects = zero_target.effects.into_vec();
    effects[0].kind = ResponseEffectKind::SuspendCapabilitySet;
    effects[0].target = ResponseTarget::CapabilitySet {
        affected_set_hash: Digest32::new([0; 32]),
    };
    zero_target.effects = PlannedResponseEffects::new(effects)
        .unwrap_or_else(|error| panic!("bounded effects failed: {error}"));
    assert_eq!(
        zero_target.validate_shape(),
        Err(ResponseShapeError::InvalidTargetAffectedSetHash)
    );
}
