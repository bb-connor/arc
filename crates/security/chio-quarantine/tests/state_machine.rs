mod response_support;

use chio_quarantine::{
    build_response_plan, decode_response_record, EffectMutation, EffectMutationRequest,
    EffectReceiptContext, ResponseStateMachine, ResponseTransitionRequest, StateMachineError,
};
use chio_security_types::ports::{
    response_affected_set_hash, ActionId, BlastRadiusFenceAcquisition, BlastRadiusQueryBounds,
    BlastRadiusRequest, BlastRadiusResult, BlastRadiusSeeds, BlastRadiusSnapshotMetadata,
    BoundedVec, CanonicalBody, Digest32, EffectId, ErrorCode, IssuanceFreezeSpec, LineageId,
    OpaqueReceiptRef, RecordIdSet, ResponsePlanRecord, SessionId, TenantId,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind,
    ResponseEffectProgress, ResponseEffectSpec, ResponsePlanAuthorizationBody, ResponsePlanInput,
    ResponseState, ResponseTarget,
};
use proptest::prelude::*;
use response_support::{record, TestResponseStore};
use std::sync::Arc;

const RESPONSE_STATES: [ResponseState; 12] = [
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

const LEGAL_STATE_EDGES: [(ResponseState, ResponseState); 20] = [
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

fn digest(value: u8) -> Digest32 {
    Digest32::new([value; 32])
}

fn error(value: &str) -> ErrorCode {
    ErrorCode::new(value).unwrap_or_else(|failure| panic!("invalid error code: {failure}"))
}

fn effect(kind: ResponseEffectKind, index: u8) -> ResponseEffectSpec {
    let target = match kind {
        ResponseEffectKind::EscalateAlert => ResponseTarget::Tenant {
            tenant_id: TenantId::new("tenant-response")
                .unwrap_or_else(|failure| panic!("invalid tenant id: {failure}")),
        },
        ResponseEffectKind::ThrottleSession
        | ResponseEffectKind::RestrictEgress
        | ResponseEffectKind::SuspendSession => ResponseTarget::Session {
            session_id: SessionId::new(format!("session-{index}"))
                .unwrap_or_else(|failure| panic!("invalid session id: {failure}")),
        },
        ResponseEffectKind::SuspendCapabilitySet => ResponseTarget::CapabilitySet {
            affected_set_hash: digest(index),
        },
        ResponseEffectKind::FreezeIssuance => ResponseTarget::Lineage {
            lineage_id: chio_security_types::ports::LineageId::new("lineage-response")
                .unwrap_or_else(|failure| panic!("invalid lineage id: {failure}")),
        },
    };
    let canonical_contribution = CanonicalBody::new(
        format!("{{\"posture_rank\":{}}}", index.saturating_add(1)).into_bytes(),
    )
    .unwrap_or_else(|failure| panic!("invalid contribution body: {failure}"));
    let contribution_hash =
        Digest32::new(*chio_core_types::sha256(canonical_contribution.as_bytes()).as_bytes());
    ResponseEffectSpec {
        kind,
        target,
        canonical_contribution,
        contribution_hash,
        observed_base_version_hash: digest(index.saturating_add(20)),
    }
}

fn plan_input(effect_count: u8) -> ResponsePlanInput {
    let effects = (0..effect_count)
        .map(|index| effect(ResponseEffectKind::ThrottleSession, index))
        .collect();
    ResponsePlanInput {
        action_id: ActionId::new("action-response")
            .unwrap_or_else(|failure| panic!("invalid action id: {failure}")),
        trigger_finding_id: record("finding-response"),
        trigger_finding_hash: digest(32),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("finding-receipt-response")
            .unwrap_or_else(|failure| panic!("invalid finding receipt id: {failure}")),
        tenant_id: TenantId::new("tenant-response")
            .unwrap_or_else(|failure| panic!("invalid tenant id: {failure}")),
        policy_version: record("policy-response"),
        policy_hash: digest(33),
        affected_ids: vec![record("affected-response")],
        effects,
        ttl_ms: 900,
        created_at_unix_ms: 100,
        operator_capability: OperatorCapabilityBinding {
            capability_id: record("operator-capability"),
            capability_digest: digest(30),
            expires_at_unix_ms: 2_000,
            executor_subject: record("response-executor"),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: record("response-submitter"),
        reason_hash: digest(31),
    }
}

fn freeze_plan_input(approved_ids: Vec<chio_security_types::ports::RecordId>) -> ResponsePlanInput {
    let mut input = plan_input(1);
    let lineage_id = LineageId::new("affected-response-root")
        .unwrap_or_else(|failure| panic!("invalid lineage id: {failure}"));
    let approved_ids = RecordIdSet::new(approved_ids)
        .unwrap_or_else(|failure| panic!("invalid approved affected set: {failure}"));
    let affected_set_hash = response_affected_set_hash(&input.tenant_id, &approved_ids)
        .unwrap_or_else(|failure| panic!("approved affected-set hash failed: {failure:?}"));
    let query_bounds = BlastRadiusQueryBounds {
        max_depth: 8,
        max_nodes: 32,
        max_edges: 32,
    };
    let freeze = IssuanceFreezeSpec {
        lineage_id: lineage_id.clone(),
        acquisition: BlastRadiusFenceAcquisition {
            request: BlastRadiusRequest {
                tenant_id: input.tenant_id.clone(),
                action_id: input.action_id.clone(),
                seed_ids: BlastRadiusSeeds::new(vec![record(lineage_id.as_str())])
                    .unwrap_or_else(|failure| panic!("invalid blast-radius seed: {failure}")),
                query_bounds: query_bounds.clone(),
            },
            approved_result: BlastRadiusResult::Exact {
                metadata: BlastRadiusSnapshotMetadata {
                    query_bounds,
                    source_lineage_version: 1,
                    commit_index: 1,
                    authoritative_commit_index: 1,
                    completeness_watermark: Some(1),
                },
                sorted_affected_ids: approved_ids,
                affected_set_hash,
                graph_slice_hash: digest(70),
            },
            expires_at_unix_ms: 500,
        },
    };
    let canonical_contribution = chio_core_types::canonical_json_bytes(&freeze)
        .unwrap_or_else(|failure| panic!("canonical freeze contribution failed: {failure}"));
    let canonical_contribution = CanonicalBody::new(canonical_contribution)
        .unwrap_or_else(|failure| panic!("invalid freeze contribution: {failure}"));
    input.affected_ids = vec![
        record("affected-response-child"),
        record("affected-response-root"),
    ];
    input.effects = vec![ResponseEffectSpec {
        kind: ResponseEffectKind::FreezeIssuance,
        target: ResponseTarget::Lineage { lineage_id },
        contribution_hash: Digest32::new(
            *chio_core_types::sha256(canonical_contribution.as_bytes()).as_bytes(),
        ),
        canonical_contribution,
        observed_base_version_hash: digest(71),
    }];
    input
}

fn transition(
    expected_generation: u64,
    target_state: ResponseState,
    occurred_at_unix_ms: u64,
) -> ResponseTransitionRequest {
    ResponseTransitionRequest {
        expected_generation,
        target_state,
        occurred_at_unix_ms,
        applying_lease_expires_at_unix_ms: if target_state == ResponseState::Applying {
            Some(500)
        } else {
            None
        },
        error_code: matches!(
            target_state,
            ResponseState::Failed | ResponseState::ApplyPartial | ResponseState::RollbackPartial
        )
        .then(|| error("response.transition_failed")),
    }
}

fn machine_with_plan(
    effect_count: u8,
) -> (
    ResponseStateMachine<TestResponseStore>,
    chio_security_types::ports::ResponsePlanRecord,
) {
    machine_with_approval(effect_count, ResponseApprovalRequirement::Automatic)
}

fn machine_with_approval(
    effect_count: u8,
    approval_requirement: ResponseApprovalRequirement,
) -> (
    ResponseStateMachine<TestResponseStore>,
    chio_security_types::ports::ResponsePlanRecord,
) {
    let store = Arc::new(TestResponseStore::default());
    let machine = ResponseStateMachine::new(store);
    let mut input = plan_input(effect_count);
    input.approval_requirement = approval_requirement;
    let plan = build_response_plan(input)
        .unwrap_or_else(|failure| panic!("valid response plan rejected: {failure}"));
    let record = machine
        .create(plan)
        .unwrap_or_else(|failure| panic!("response plan create failed: {failure}"));
    (machine, record)
}

fn effect_id(record: &chio_security_types::ports::ResponsePlanRecord, index: usize) -> EffectId {
    decode_response_record(record)
        .unwrap_or_else(|failure| panic!("response record decode failed: {failure}"))
        .plan
        .effects
        .as_slice()[index]
        .effect_id
        .clone()
}

fn request_effect_at(
    machine: &ResponseStateMachine<TestResponseStore>,
    current: &ResponsePlanRecord,
    index: usize,
    occurred_at_unix_ms: u64,
) -> ResponsePlanRecord {
    machine
        .record_effect(
            current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: effect_id(current, index),
                occurred_at_unix_ms,
                mutation: EffectMutation::Requested,
            },
        )
        .unwrap_or_else(|failure| panic!("effect request failed: {failure}"))
}

fn apply_requested_effect_at(
    machine: &ResponseStateMachine<TestResponseStore>,
    current: &ResponsePlanRecord,
    index: usize,
    occurred_at_unix_ms: u64,
) -> ResponsePlanRecord {
    machine
        .record_effect(
            current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: effect_id(current, index),
                occurred_at_unix_ms,
                mutation: EffectMutation::Applied {
                    resulting_version_hash: digest(
                        70_u8.saturating_add(u8::try_from(index).unwrap_or(0)),
                    ),
                },
            },
        )
        .unwrap_or_else(|failure| panic!("effect apply failed: {failure}"))
}

fn fail_requested_effect_at(
    machine: &ResponseStateMachine<TestResponseStore>,
    current: &ResponsePlanRecord,
    index: usize,
    occurred_at_unix_ms: u64,
    failure_code: &str,
) -> ResponsePlanRecord {
    machine
        .record_effect(
            current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: effect_id(current, index),
                occurred_at_unix_ms,
                mutation: EffectMutation::Failed {
                    error_code: error(failure_code),
                },
            },
        )
        .unwrap_or_else(|failure| panic!("effect failure failed: {failure}"))
}

fn enter_applying(
    machine: &ResponseStateMachine<TestResponseStore>,
    current: &ResponsePlanRecord,
    occurred_at_unix_ms: u64,
) -> ResponsePlanRecord {
    machine
        .transition(
            current,
            &transition(
                current.generation,
                ResponseState::Applying,
                occurred_at_unix_ms,
            ),
        )
        .unwrap_or_else(|failure| panic!("begin apply failed: {failure}"))
}

fn apply_only_effect(
    machine: &ResponseStateMachine<TestResponseStore>,
    current: &ResponsePlanRecord,
) -> ResponsePlanRecord {
    let effect_id = effect_id(current, 0);
    let requested = machine
        .record_effect(
            current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: effect_id.clone(),
                occurred_at_unix_ms: 120,
                mutation: EffectMutation::Requested,
            },
        )
        .unwrap_or_else(|failure| panic!("effect request failed: {failure}"));
    machine
        .record_effect(
            &requested,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id,
                occurred_at_unix_ms: 121,
                mutation: EffectMutation::Applied {
                    resulting_version_hash: digest(70),
                },
            },
        )
        .unwrap_or_else(|failure| panic!("effect apply failed: {failure}"))
}

fn enter_active(
    machine: &ResponseStateMachine<TestResponseStore>,
    planned: &ResponsePlanRecord,
) -> ResponsePlanRecord {
    let applying = enter_applying(machine, planned, 110);
    let applied = apply_only_effect(machine, &applying);
    machine
        .transition(
            &applied,
            &transition(applied.generation, ResponseState::Active, 200),
        )
        .unwrap_or_else(|failure| panic!("activate failed: {failure}"))
}

fn enter_apply_partial(
    machine: &ResponseStateMachine<TestResponseStore>,
    planned: &ResponsePlanRecord,
) -> ResponsePlanRecord {
    let applying = enter_applying(machine, planned, 110);
    let applied = apply_only_effect(machine, &applying);
    machine
        .transition(
            &applied,
            &transition(applied.generation, ResponseState::ApplyPartial, 122),
        )
        .unwrap_or_else(|failure| panic!("partial apply failed: {failure}"))
}

fn enter_rolling_back_from_partial(
    machine: &ResponseStateMachine<TestResponseStore>,
    planned: &ResponsePlanRecord,
) -> ResponsePlanRecord {
    let partial = enter_apply_partial(machine, planned);
    machine
        .transition(
            &partial,
            &transition(partial.generation, ResponseState::RollingBack, 123),
        )
        .unwrap_or_else(|failure| panic!("begin rollback failed: {failure}"))
}

fn enter_rolling_back_ready_to_lift(
    machine: &ResponseStateMachine<TestResponseStore>,
    planned: &ResponsePlanRecord,
) -> ResponsePlanRecord {
    let rolling_back = enter_rolling_back_from_partial(machine, planned);
    let effect_id = effect_id(&rolling_back, 0);
    let requested = machine
        .record_effect(
            &rolling_back,
            &EffectMutationRequest {
                expected_generation: rolling_back.generation,
                effect_id: effect_id.clone(),
                occurred_at_unix_ms: 124,
                mutation: EffectMutation::RollbackRequested,
            },
        )
        .unwrap_or_else(|failure| panic!("rollback request failed: {failure}"));
    machine
        .record_effect(
            &requested,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id,
                occurred_at_unix_ms: 125,
                mutation: EffectMutation::RollbackRestored {
                    resulting_version_hash: digest(20),
                },
            },
        )
        .unwrap_or_else(|failure| panic!("rollback restore failed: {failure}"))
}

fn enter_rolling_back_with_failure(
    machine: &ResponseStateMachine<TestResponseStore>,
    planned: &ResponsePlanRecord,
) -> ResponsePlanRecord {
    let active = enter_active(machine, planned);
    let rolling_back = machine
        .transition(
            &active,
            &transition(active.generation, ResponseState::RollingBack, 201),
        )
        .unwrap_or_else(|failure| panic!("begin rollback failed: {failure}"));
    let effect_id = effect_id(&rolling_back, 0);
    let requested = machine
        .record_effect(
            &rolling_back,
            &EffectMutationRequest {
                expected_generation: rolling_back.generation,
                effect_id: effect_id.clone(),
                occurred_at_unix_ms: 202,
                mutation: EffectMutation::RollbackRequested,
            },
        )
        .unwrap_or_else(|failure| panic!("rollback request failed: {failure}"));
    machine
        .record_effect(
            &requested,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id,
                occurred_at_unix_ms: 203,
                mutation: EffectMutation::RollbackFailed {
                    error_code: error("response.rollback_failed"),
                },
            },
        )
        .unwrap_or_else(|failure| panic!("rollback failure failed: {failure}"))
}

fn state_source(
    from_state: ResponseState,
    target_state: ResponseState,
) -> (ResponseStateMachine<TestResponseStore>, ResponsePlanRecord) {
    let approval_requirement = if from_state == ResponseState::AwaitingApproval
        || (from_state == ResponseState::Planned && target_state == ResponseState::AwaitingApproval)
    {
        ResponseApprovalRequirement::Governed {
            policy_id: record("response-governed-policy"),
        }
    } else {
        ResponseApprovalRequirement::Automatic
    };
    let (machine, planned) = machine_with_approval(1, approval_requirement);
    let current = match from_state {
        ResponseState::Planned => planned,
        ResponseState::AwaitingApproval => machine
            .transition(
                &planned,
                &transition(0, ResponseState::AwaitingApproval, 110),
            )
            .unwrap_or_else(|failure| panic!("await approval failed: {failure}")),
        ResponseState::Applying => {
            let applying = enter_applying(&machine, &planned, 110);
            if matches!(
                target_state,
                ResponseState::Active | ResponseState::ApplyPartial
            ) {
                apply_only_effect(&machine, &applying)
            } else {
                applying
            }
        }
        ResponseState::Active => enter_active(&machine, &planned),
        ResponseState::ApplyPartial => enter_apply_partial(&machine, &planned),
        ResponseState::Expiring => {
            let active = enter_active(&machine, &planned);
            machine
                .transition(
                    &active,
                    &transition(active.generation, ResponseState::Expiring, 1_000),
                )
                .unwrap_or_else(|failure| panic!("expire active response failed: {failure}"))
        }
        ResponseState::RollingBack if target_state == ResponseState::RollbackPartial => {
            enter_rolling_back_with_failure(&machine, &planned)
        }
        ResponseState::RollingBack if target_state == ResponseState::Lifted => {
            enter_rolling_back_ready_to_lift(&machine, &planned)
        }
        ResponseState::RollingBack => enter_rolling_back_from_partial(&machine, &planned),
        ResponseState::RollbackPartial => {
            let rolling_back = enter_rolling_back_with_failure(&machine, &planned);
            machine
                .transition(
                    &rolling_back,
                    &transition(rolling_back.generation, ResponseState::RollbackPartial, 204),
                )
                .unwrap_or_else(|failure| panic!("partial rollback failed: {failure}"))
        }
        ResponseState::Cancelled => machine
            .transition(&planned, &transition(0, ResponseState::Cancelled, 110))
            .unwrap_or_else(|failure| panic!("cancel failed: {failure}")),
        ResponseState::Expired => machine
            .transition(&planned, &transition(0, ResponseState::Expired, 1_000))
            .unwrap_or_else(|failure| panic!("expire failed: {failure}")),
        ResponseState::Failed => machine
            .transition(&planned, &transition(0, ResponseState::Failed, 110))
            .unwrap_or_else(|failure| panic!("fail failed: {failure}")),
        ResponseState::Lifted => {
            let rolling_back = enter_rolling_back_ready_to_lift(&machine, &planned);
            machine
                .transition(
                    &rolling_back,
                    &transition(rolling_back.generation, ResponseState::Lifted, 126),
                )
                .unwrap_or_else(|failure| panic!("lift failed: {failure}"))
        }
    };
    (machine, current)
}

fn next_transition_time(current: &ResponsePlanRecord, target_state: ResponseState) -> u64 {
    let snapshot = decode_response_record(current)
        .unwrap_or_else(|failure| panic!("response decode failed: {failure}"));
    let previous = snapshot
        .mutations
        .as_slice()
        .last()
        .map_or(snapshot.plan.created_at_unix_ms, |mutation| {
            mutation.occurred_at_unix_ms()
        });
    let minimum = if matches!(
        target_state,
        ResponseState::Expired | ResponseState::Expiring
    ) {
        snapshot.plan.expires_at_unix_ms
    } else {
        0
    };
    previous.saturating_add(1).max(minimum)
}

#[test]
fn state_machine_accepts_exactly_the_nineteen_specified_edges() {
    for from_state in RESPONSE_STATES {
        for target_state in RESPONSE_STATES {
            let (machine, current) = state_source(from_state, target_state);
            let request = transition(
                current.generation,
                target_state,
                next_transition_time(&current, target_state),
            );
            let result = machine.transition(&current, &request);
            let expected = LEGAL_STATE_EDGES.contains(&(from_state, target_state))
                && (from_state, target_state) != (ResponseState::Applying, ResponseState::Applying);
            assert_eq!(
                result.is_ok(),
                expected,
                "unexpected state-machine result for {from_state:?} -> {target_state:?}: {result:?}"
            );
            if let Ok(record) = result {
                let snapshot = decode_response_record(&record)
                    .unwrap_or_else(|failure| panic!("response decode failed: {failure}"));
                assert_eq!(snapshot.state, target_state);
            }
        }
    }
}

#[test]
fn approval_mode_selects_the_only_valid_path_into_applying() {
    let (automatic_machine, automatic) = machine_with_plan(1);
    assert!(matches!(
        automatic_machine.transition(
            &automatic,
            &transition(automatic.generation, ResponseState::AwaitingApproval, 110),
        ),
        Err(StateMachineError::InvalidTransition)
    ));

    let (governed_machine, governed) = machine_with_approval(
        1,
        ResponseApprovalRequirement::Governed {
            policy_id: record("response-governed-policy"),
        },
    );
    assert!(matches!(
        governed_machine.transition(
            &governed,
            &transition(governed.generation, ResponseState::Applying, 110),
        ),
        Err(StateMachineError::InvalidTransition)
    ));
    let awaiting = governed_machine
        .transition(
            &governed,
            &transition(governed.generation, ResponseState::AwaitingApproval, 110),
        )
        .unwrap_or_else(|failure| panic!("governed approval wait rejected: {failure}"));
    let applying = governed_machine
        .transition(
            &awaiting,
            &transition(awaiting.generation, ResponseState::Applying, 111),
        )
        .unwrap_or_else(|failure| panic!("governed approval satisfaction rejected: {failure}"));
    assert_eq!(
        decode_response_record(&applying)
            .unwrap_or_else(|failure| panic!("governed response decode failed: {failure}"))
            .state,
        ResponseState::Applying
    );
}

#[test]
fn canonical_plan_effect_and_transition_ids_are_stable_and_cas_is_idempotent() {
    let first = build_response_plan(plan_input(2))
        .unwrap_or_else(|failure| panic!("valid response plan rejected: {failure}"));
    let second = build_response_plan(plan_input(2))
        .unwrap_or_else(|failure| panic!("valid response plan rejected: {failure}"));
    assert_eq!(first.plan_hash, second.plan_hash);
    assert_eq!(first.effects, second.effects);

    let (machine, planned) = machine_with_plan(2);
    let request = transition(0, ResponseState::Applying, 110);
    let applying = machine
        .transition(&planned, &request)
        .unwrap_or_else(|failure| panic!("begin apply failed: {failure}"));
    let duplicate = machine
        .transition(&planned, &request)
        .unwrap_or_else(|failure| panic!("duplicate transition failed: {failure}"));
    assert_eq!(applying, duplicate);
    let snapshot = decode_response_record(&applying)
        .unwrap_or_else(|failure| panic!("response record decode failed: {failure}"));
    assert_eq!(snapshot.state, ResponseState::Applying);
    assert_eq!(snapshot.generation, 1);
    assert_eq!(snapshot.mutations.len(), 2);

    let effect_request = EffectMutationRequest {
        expected_generation: applying.generation,
        effect_id: effect_id(&applying, 0),
        occurred_at_unix_ms: 120,
        mutation: EffectMutation::Requested,
    };
    let requested = machine
        .record_effect(&applying, &effect_request)
        .unwrap_or_else(|failure| panic!("effect request failed: {failure}"));
    let duplicate_request = machine
        .record_effect(&applying, &effect_request)
        .unwrap_or_else(|failure| panic!("duplicate effect request failed: {failure}"));
    assert_eq!(duplicate_request, requested);

    assert!(machine
        .transition(
            &planned,
            &transition(0, ResponseState::AwaitingApproval, 111),
        )
        .is_err());
}

#[test]
fn zero_effect_receipt_generation_is_rejected_before_persistence() {
    let (machine, planned) = machine_with_plan(1);
    let applying = machine
        .transition(&planned, &transition(0, ResponseState::Applying, 110))
        .unwrap_or_else(|failure| panic!("begin apply failed: {failure}"));
    let result = machine.record_effect_with_receipt(
        &applying,
        &EffectMutationRequest {
            expected_generation: applying.generation,
            effect_id: effect_id(&applying, 0),
            occurred_at_unix_ms: 120,
            mutation: EffectMutation::Requested,
        },
        &EffectReceiptContext {
            effect_generation: 0,
            scheduler_lease_owner_id: None,
            scheduler_fencing_token: 1,
            effect_transition_id: None,
            prior_receipt_id: None,
        },
    );
    assert!(matches!(
        result,
        Err(StateMachineError::InvalidEffectLifecycle)
    ));
}

#[test]
fn apply_effect_mutations_must_precede_the_applying_lease_deadline() {
    let (machine, planned) = machine_with_plan(1);
    let applying = enter_applying(&machine, &planned, 110);
    let effect_id = effect_id(&applying, 0);
    let late_request = machine.record_effect(
        &applying,
        &EffectMutationRequest {
            expected_generation: applying.generation,
            effect_id: effect_id.clone(),
            occurred_at_unix_ms: 500,
            mutation: EffectMutation::Requested,
        },
    );
    assert!(matches!(
        late_request,
        Err(StateMachineError::InvalidEffectLifecycle)
    ));

    let requested = machine
        .record_effect(
            &applying,
            &EffectMutationRequest {
                expected_generation: applying.generation,
                effect_id: effect_id.clone(),
                occurred_at_unix_ms: 499,
                mutation: EffectMutation::Requested,
            },
        )
        .unwrap_or_else(|failure| panic!("pre-deadline effect request rejected: {failure}"));
    for mutation in [
        EffectMutation::Applied {
            resulting_version_hash: digest(70),
        },
        EffectMutation::Failed {
            error_code: error("response.effect_late"),
        },
    ] {
        assert!(matches!(
            machine.record_effect(
                &requested,
                &EffectMutationRequest {
                    expected_generation: requested.generation,
                    effect_id: effect_id.clone(),
                    occurred_at_unix_ms: 500,
                    mutation,
                },
            ),
            Err(StateMachineError::InvalidEffectLifecycle)
        ));
    }
}

#[test]
fn effect_not_executed_is_reserved_for_a_late_receipt_backed_takeover() {
    let (machine, planned) = machine_with_plan(1);
    let applying = enter_applying(&machine, &planned, 110);
    let requested = request_effect_at(&machine, &applying, 0, 120);
    let not_executed = error("response.effect_not_executed");

    assert!(matches!(
        machine.record_effect(
            &requested,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id: effect_id(&requested, 0),
                occurred_at_unix_ms: 121,
                mutation: EffectMutation::Failed {
                    error_code: not_executed,
                },
            },
        ),
        Err(StateMachineError::InvalidEffectLifecycle)
    ));
}

#[test]
fn pure_replay_rejects_predeadline_not_executed_without_takeover_provenance() {
    let (machine, planned) = machine_with_plan(1);
    let applying = enter_applying(&machine, &planned, 110);
    let requested = request_effect_at(&machine, &applying, 0, 120);
    let rejected = machine
        .record_effect(
            &requested,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id: effect_id(&requested, 0),
                occurred_at_unix_ms: 121,
                mutation: EffectMutation::Failed {
                    error_code: error("response.effect_rejected"),
                },
            },
        )
        .unwrap_or_else(|failure| panic!("ordinary effect rejection failed: {failure}"));
    let mut snapshot = decode_response_record(&rejected)
        .unwrap_or_else(|failure| panic!("response decode failed: {failure}"));
    let mut mutations = snapshot.mutations.into_vec();
    let mutation_index = mutations
        .len()
        .checked_sub(1)
        .unwrap_or_else(|| panic!("effect failure mutation missing"));
    match &mut mutations[mutation_index] {
        chio_security_types::ResponseMutationRecord::EffectFailed(failed) => {
            failed.error_code = error("response.effect_not_executed");
        }
        _ => panic!("effect failure mutation missing"),
    }
    let transition_id =
        chio_core_types::receipt::security::expected_response_mutation_transition_id(
            &snapshot.plan,
            &mutations[mutation_index],
        )
        .unwrap_or_else(|failure| panic!("effect failure transition id failed: {failure}"));
    match &mut mutations[mutation_index] {
        chio_security_types::ResponseMutationRecord::EffectFailed(failed) => {
            failed.transition_id = transition_id;
        }
        _ => panic!("effect failure mutation missing"),
    }
    snapshot.mutations = BoundedVec::new(mutations)
        .unwrap_or_else(|failure| panic!("mutation reconstruction failed: {failure}"));

    assert!(
        chio_core_types::receipt::security::validate_response_snapshot_lifecycle(&snapshot, false,)
            .is_err()
    );
}

#[test]
fn applying_lease_expiry_code_is_reserved_for_the_exact_lease_deadline() {
    let (machine, planned) = machine_with_plan(1);
    let applying = enter_applying(&machine, &planned, 110);
    let requested = request_effect_at(&machine, &applying, 0, 120);
    let applied = apply_requested_effect_at(&machine, &requested, 0, 121);
    let expiry_error = error("response.applying_lease_expired");
    assert!(matches!(
        machine.transition(
            &applied,
            &ResponseTransitionRequest {
                expected_generation: applied.generation,
                target_state: ResponseState::ApplyPartial,
                occurred_at_unix_ms: 499,
                applying_lease_expires_at_unix_ms: None,
                error_code: Some(expiry_error.clone()),
            },
        ),
        Err(StateMachineError::InvalidTiming)
    ));

    let partial = machine
        .transition(
            &applied,
            &ResponseTransitionRequest {
                expected_generation: applied.generation,
                target_state: ResponseState::ApplyPartial,
                occurred_at_unix_ms: 500,
                applying_lease_expires_at_unix_ms: None,
                error_code: Some(expiry_error),
            },
        )
        .unwrap_or_else(|failure| panic!("exact applying-lease expiry rejected: {failure}"));
    assert_eq!(
        decode_response_record(&partial)
            .unwrap_or_else(|failure| panic!("apply-partial decode failed: {failure}"))
            .state,
        ResponseState::ApplyPartial
    );
}

#[test]
fn receipt_backed_effect_generation_and_fencing_token_cannot_regress() {
    let (generation_machine, planned) = machine_with_plan(1);
    let applying = enter_applying(&generation_machine, &planned, 110);
    let generation_effect_id = effect_id(&applying, 0);
    let requested = generation_machine
        .record_effect_with_receipt(
            &applying,
            &EffectMutationRequest {
                expected_generation: applying.generation,
                effect_id: generation_effect_id.clone(),
                occurred_at_unix_ms: 120,
                mutation: EffectMutation::Requested,
            },
            &EffectReceiptContext {
                effect_generation: 3,
                scheduler_lease_owner_id: None,
                scheduler_fencing_token: 1,
                effect_transition_id: None,
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|failure| panic!("receipt-backed effect request rejected: {failure}"));
    assert!(matches!(
        generation_machine.record_effect_with_receipt(
            &requested,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id: generation_effect_id,
                occurred_at_unix_ms: 121,
                mutation: EffectMutation::Applied {
                    resulting_version_hash: digest(70),
                },
            },
            &EffectReceiptContext {
                effect_generation: 2,
                scheduler_lease_owner_id: None,
                scheduler_fencing_token: 1,
                effect_transition_id: Some(record("effect-generation-regression")),
                prior_receipt_id: None,
            },
        ),
        Err(StateMachineError::InvalidEffectLifecycle)
    ));

    let (fencing_machine, planned) = machine_with_plan(1);
    let applying = enter_applying(&fencing_machine, &planned, 110);
    let effect_id = effect_id(&applying, 0);
    let requested = fencing_machine
        .record_effect_with_receipt(
            &applying,
            &EffectMutationRequest {
                expected_generation: applying.generation,
                effect_id: effect_id.clone(),
                occurred_at_unix_ms: 120,
                mutation: EffectMutation::Requested,
            },
            &EffectReceiptContext {
                effect_generation: 1,
                scheduler_lease_owner_id: None,
                scheduler_fencing_token: 9,
                effect_transition_id: None,
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|failure| panic!("fenced effect request rejected: {failure}"));
    assert!(matches!(
        fencing_machine.record_effect_with_receipt(
            &requested,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id: effect_id.clone(),
                occurred_at_unix_ms: 121,
                mutation: EffectMutation::Applied {
                    resulting_version_hash: digest(70),
                },
            },
            &EffectReceiptContext {
                effect_generation: 2,
                scheduler_lease_owner_id: None,
                scheduler_fencing_token: 9,
                effect_transition_id: None,
                prior_receipt_id: None,
            },
        ),
        Err(StateMachineError::InvalidEffectLifecycle)
    ));
    assert!(matches!(
        fencing_machine.record_effect_with_receipt(
            &requested,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id,
                occurred_at_unix_ms: 121,
                mutation: EffectMutation::Applied {
                    resulting_version_hash: digest(70),
                },
            },
            &EffectReceiptContext {
                effect_generation: 2,
                scheduler_lease_owner_id: None,
                scheduler_fencing_token: 8,
                effect_transition_id: Some(record("effect-fencing-regression")),
                prior_receipt_id: None,
            },
        ),
        Err(StateMachineError::InvalidEffectLifecycle)
    ));
}

#[test]
fn response_plan_authorization_body_excludes_its_own_hash() {
    let plan = build_response_plan(plan_input(2))
        .unwrap_or_else(|failure| panic!("valid response plan rejected: {failure}"));
    let body = plan.authorization_body();
    let mut encoded = serde_json::to_value(&body)
        .unwrap_or_else(|failure| panic!("authorization body encoding failed: {failure}"));

    assert_eq!(body.action_id, plan.action_id);
    assert!(encoded.get("plan_hash").is_none());
    let keys = encoded
        .as_object()
        .unwrap_or_else(|| panic!("authorization body is not an object"))
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = [
        "action_id",
        "affected_ids",
        "affected_set_hash",
        "approval_requirement",
        "created_at_unix_ms",
        "effects",
        "expires_at_unix_ms",
        "operator_capability",
        "policy_hash",
        "policy_version",
        "reason_hash",
        "submitter",
        "tenant_id",
        "trigger_finding_hash",
        "trigger_finding_id",
        "trigger_finding_receipt_id",
        "ttl_ms",
    ]
    .into_iter()
    .collect();
    assert_eq!(keys, expected);
    let canonical = serde_json::to_string(&body)
        .unwrap_or_else(|failure| panic!("authorization body encoding failed: {failure}"));
    assert!(!canonical.contains("canonical_contribution"));
    assert!(!canonical.contains("posture_rank"));

    encoded["plan_hash"] = serde_json::json!(plan.plan_hash);
    assert!(serde_json::from_value::<ResponsePlanAuthorizationBody>(encoded).is_err());
}

#[test]
fn response_plan_rejects_authorization_body_above_governance_ceiling() {
    let mut input = plan_input(1);
    input.affected_ids = (0..300)
        .map(|index| record(&format!("affected-{index:04}-{}", "a".repeat(220))))
        .collect();

    assert!(build_response_plan(input).is_err());
}

#[test]
fn response_plan_rejects_authorization_body_above_governance_node_ceiling() {
    assert!(build_response_plan(plan_input(64)).is_err());
}

#[test]
fn response_plan_hash_commits_to_the_validated_canonical_contribution() {
    let first = build_response_plan(plan_input(1))
        .unwrap_or_else(|failure| panic!("valid response plan rejected: {failure}"));

    let mut changed_input = plan_input(1);
    let changed_body = CanonicalBody::new(br#"{"posture_rank":99}"#.to_vec())
        .unwrap_or_else(|failure| panic!("invalid contribution body: {failure}"));
    changed_input.effects[0].contribution_hash =
        Digest32::new(*chio_core_types::sha256(changed_body.as_bytes()).as_bytes());
    changed_input.effects[0].canonical_contribution = changed_body;
    let changed = build_response_plan(changed_input)
        .unwrap_or_else(|failure| panic!("changed response plan rejected: {failure}"));

    assert_ne!(first.plan_hash, changed.plan_hash);
    assert_ne!(first.effects, changed.effects);

    let mut mismatched_input = plan_input(1);
    mismatched_input.effects[0].contribution_hash = digest(99);
    assert!(build_response_plan(mismatched_input).is_err());
}

#[test]
fn freeze_issuance_plan_requires_the_exact_globally_approved_affected_set() {
    let exact = build_response_plan(freeze_plan_input(vec![
        record("affected-response-child"),
        record("affected-response-root"),
    ]))
    .unwrap_or_else(|failure| panic!("exact issuance-freeze plan rejected: {failure}"));
    assert_eq!(
        exact.affected_ids.as_slice(),
        &[
            record("affected-response-child"),
            record("affected-response-root"),
        ]
    );

    let narrower = freeze_plan_input(vec![record("affected-response-root")]);
    assert!(build_response_plan(narrower).is_err());

    let broader = freeze_plan_input(vec![
        record("affected-response-child"),
        record("affected-response-extra"),
        record("affected-response-root"),
    ]);
    assert!(build_response_plan(broader).is_err());
}

#[test]
fn response_plan_hash_commits_to_exact_policy_and_finding_authority_bindings() {
    let baseline = build_response_plan(plan_input(1))
        .unwrap_or_else(|failure| panic!("valid response plan rejected: {failure}"));
    assert_eq!(
        baseline.authorization_body().policy_hash,
        baseline.policy_hash
    );
    assert_eq!(
        baseline.authorization_body().trigger_finding_hash,
        baseline.trigger_finding_hash
    );
    assert_eq!(
        baseline.authorization_body().trigger_finding_receipt_id,
        baseline.trigger_finding_receipt_id
    );

    let mut changed_policy = plan_input(1);
    changed_policy.policy_hash = digest(34);
    let changed_policy = build_response_plan(changed_policy)
        .unwrap_or_else(|failure| panic!("changed policy plan rejected: {failure}"));
    assert_ne!(baseline.plan_hash, changed_policy.plan_hash);

    let mut changed_finding = plan_input(1);
    changed_finding.trigger_finding_hash = digest(35);
    let changed_finding = build_response_plan(changed_finding)
        .unwrap_or_else(|failure| panic!("changed finding plan rejected: {failure}"));
    assert_ne!(baseline.plan_hash, changed_finding.plan_hash);

    let mut changed_receipt = plan_input(1);
    changed_receipt.trigger_finding_receipt_id =
        OpaqueReceiptRef::new("finding-receipt-response-other")
            .unwrap_or_else(|failure| panic!("invalid finding receipt id: {failure}"));
    let changed_receipt = build_response_plan(changed_receipt)
        .unwrap_or_else(|failure| panic!("changed finding receipt plan rejected: {failure}"));
    assert_ne!(baseline.plan_hash, changed_receipt.plan_hash);
}

#[test]
fn response_plan_hash_changes_with_every_authorized_field() {
    let baseline = build_response_plan(plan_input(1))
        .unwrap_or_else(|failure| panic!("valid response plan rejected: {failure}"));
    let mut variants = Vec::new();

    let mut changed = plan_input(1);
    changed.action_id = ActionId::new("action-response-other")
        .unwrap_or_else(|failure| panic!("action: {failure}"));
    variants.push(("action_id", changed));

    let mut changed = plan_input(1);
    changed.trigger_finding_id = record("finding-response-other");
    variants.push(("trigger_finding_id", changed));

    let mut changed = plan_input(1);
    changed.trigger_finding_hash = digest(41);
    variants.push(("trigger_finding_hash", changed));

    let mut changed = plan_input(1);
    changed.trigger_finding_receipt_id = OpaqueReceiptRef::new("finding-receipt-response-other")
        .unwrap_or_else(|failure| panic!("finding receipt: {failure}"));
    variants.push(("trigger_finding_receipt_id", changed));

    let mut changed = plan_input(1);
    changed.tenant_id = TenantId::new("tenant-response-other")
        .unwrap_or_else(|failure| panic!("tenant: {failure}"));
    variants.push(("tenant_id", changed));

    let mut changed = plan_input(1);
    changed.policy_version = record("policy-response-other");
    variants.push(("policy_version", changed));

    let mut changed = plan_input(1);
    changed.policy_hash = digest(42);
    variants.push(("policy_hash", changed));

    let mut changed = plan_input(1);
    changed.affected_ids.push(record("affected-response-other"));
    variants.push(("affected_ids", changed));

    let mut changed = plan_input(1);
    changed.effects[0].target = ResponseTarget::Session {
        session_id: SessionId::new("session-other")
            .unwrap_or_else(|failure| panic!("session: {failure}")),
    };
    variants.push(("effect_target", changed));

    let mut changed = plan_input(1);
    changed.effects[0].observed_base_version_hash = digest(43);
    variants.push(("effect_base_version", changed));

    let mut changed = plan_input(1);
    changed.ttl_ms = 901;
    variants.push(("ttl_ms", changed));

    let mut changed = plan_input(1);
    changed.created_at_unix_ms = 101;
    variants.push(("created_at_unix_ms", changed));

    let mut changed = plan_input(1);
    changed.operator_capability.capability_id = record("operator-capability-other");
    variants.push(("operator_capability_id", changed));

    let mut changed = plan_input(1);
    changed.operator_capability.capability_digest = digest(44);
    variants.push(("operator_capability_digest", changed));

    let mut changed = plan_input(1);
    changed.operator_capability.expires_at_unix_ms = 2_001;
    variants.push(("operator_capability_expiry", changed));

    let mut changed = plan_input(1);
    changed.operator_capability.executor_subject = record("response-executor-other");
    variants.push(("operator_capability_subject", changed));

    let mut changed = plan_input(1);
    changed.approval_requirement = ResponseApprovalRequirement::Governed {
        policy_id: record("response-policy"),
    };
    variants.push(("approval_requirement", changed));

    let mut changed = plan_input(1);
    changed.submitter = record("response-submitter-other");
    variants.push(("submitter", changed));

    let mut changed = plan_input(1);
    changed.reason_hash = digest(45);
    variants.push(("reason_hash", changed));

    for (field, input) in variants {
        let changed = build_response_plan(input)
            .unwrap_or_else(|failure| panic!("changed {field} rejected: {failure}"));
        assert_ne!(
            baseline.plan_hash, changed.plan_hash,
            "unbound field {field}"
        );
    }
}

#[test]
fn response_plan_rejects_zero_policy_or_finding_hashes() {
    let mut zero_policy = plan_input(1);
    zero_policy.policy_hash = Digest32::new([0; 32]);
    assert!(build_response_plan(zero_policy).is_err());

    let mut zero_finding = plan_input(1);
    zero_finding.trigger_finding_hash = Digest32::new([0; 32]);
    assert!(build_response_plan(zero_finding).is_err());
}

#[test]
fn applying_lease_deadline_is_part_of_the_canonical_transition_id() {
    let (first_machine, first_planned) = machine_with_plan(1);
    let first = first_machine
        .transition(
            &first_planned,
            &ResponseTransitionRequest {
                expected_generation: 0,
                target_state: ResponseState::Applying,
                occurred_at_unix_ms: 110,
                applying_lease_expires_at_unix_ms: Some(500),
                error_code: None,
            },
        )
        .unwrap_or_else(|failure| panic!("first apply transition failed: {failure}"));
    let (second_machine, second_planned) = machine_with_plan(1);
    let second = second_machine
        .transition(
            &second_planned,
            &ResponseTransitionRequest {
                expected_generation: 0,
                target_state: ResponseState::Applying,
                occurred_at_unix_ms: 110,
                applying_lease_expires_at_unix_ms: Some(600),
                error_code: None,
            },
        )
        .unwrap_or_else(|failure| panic!("second apply transition failed: {failure}"));
    let first_snapshot = decode_response_record(&first)
        .unwrap_or_else(|failure| panic!("first response decode failed: {failure}"));
    let second_snapshot = decode_response_record(&second)
        .unwrap_or_else(|failure| panic!("second response decode failed: {failure}"));
    assert_ne!(
        first_snapshot.mutations.as_slice()[1].transition_id(),
        second_snapshot.mutations.as_slice()[1].transition_id()
    );
}

#[test]
fn canonical_body_with_recomputed_hash_cannot_forge_a_transition_id() {
    let (machine, planned) = machine_with_plan(1);
    let applying = machine
        .transition(&planned, &transition(0, ResponseState::Applying, 110))
        .unwrap_or_else(|failure| panic!("begin apply failed: {failure}"));
    let mut snapshot = decode_response_record(&applying)
        .unwrap_or_else(|failure| panic!("response decode failed: {failure}"));
    let mut mutations = snapshot.mutations.into_vec();
    match &mut mutations[1] {
        chio_security_types::ResponseMutationRecord::Transition(transition_record) => {
            transition_record.transition_id = record("forged-transition-id");
        }
        _ => panic!("expected state transition mutation"),
    }
    snapshot.mutations = BoundedVec::new(mutations)
        .unwrap_or_else(|error| panic!("bounded mutation reconstruction failed: {error}"));
    let bytes = chio_core_types::canonical_json_bytes(&snapshot)
        .unwrap_or_else(|error| panic!("snapshot canonicalization failed: {error}"));
    let mut forged = applying;
    forged.body_hash = Digest32::new(*chio_core_types::sha256(&bytes).as_bytes());
    forged.canonical_body = CanonicalBody::new(bytes)
        .unwrap_or_else(|error| panic!("canonical body construction failed: {error}"));
    assert!(decode_response_record(&forged).is_err());
}

include!("state_machine_parts/apply_failure_edges.inc");

#[test]
fn partial_apply_timeout_full_rollback_and_rollback_failure_remain_truthful() {
    let (machine, planned) = machine_with_plan(2);
    let mut current = machine
        .transition(&planned, &transition(0, ResponseState::Applying, 110))
        .unwrap_or_else(|failure| panic!("begin apply failed: {failure}"));
    let first_effect = effect_id(&current, 0);
    let second_effect = effect_id(&current, 1);
    current = machine
        .record_effect(
            &current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: first_effect.clone(),
                occurred_at_unix_ms: 120,
                mutation: EffectMutation::Requested,
            },
        )
        .unwrap_or_else(|failure| panic!("effect request persistence failed: {failure}"));
    current = machine
        .record_effect(
            &current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: first_effect.clone(),
                occurred_at_unix_ms: 121,
                mutation: EffectMutation::Applied {
                    resulting_version_hash: digest(40),
                },
            },
        )
        .unwrap_or_else(|failure| panic!("effect result persistence failed: {failure}"));
    current = machine
        .record_effect(
            &current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: second_effect.clone(),
                occurred_at_unix_ms: 122,
                mutation: EffectMutation::Requested,
            },
        )
        .unwrap_or_else(|failure| panic!("effect request persistence failed: {failure}"));
    current = machine
        .record_effect(
            &current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: second_effect,
                occurred_at_unix_ms: 123,
                mutation: EffectMutation::Failed {
                    error_code: error("response.effect_failed"),
                },
            },
        )
        .unwrap_or_else(|failure| panic!("effect failure persistence failed: {failure}"));
    current = machine
        .transition(
            &current,
            &ResponseTransitionRequest {
                expected_generation: current.generation,
                target_state: ResponseState::Failed,
                occurred_at_unix_ms: 124,
                applying_lease_expires_at_unix_ms: None,
                error_code: Some(error("response.effect_failed")),
            },
        )
        .unwrap_or_else(|failure| panic!("partial apply transition failed: {failure}"));
    assert_eq!(
        decode_response_record(&current)
            .unwrap_or_else(|failure| panic!("response decode failed: {failure}"))
            .state,
        ResponseState::ApplyPartial
    );
    current = machine
        .transition(
            &current,
            &transition(current.generation, ResponseState::RollingBack, 125),
        )
        .unwrap_or_else(|failure| panic!("begin rollback failed: {failure}"));
    current = machine
        .record_effect(
            &current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: first_effect.clone(),
                occurred_at_unix_ms: 126,
                mutation: EffectMutation::RollbackRequested,
            },
        )
        .unwrap_or_else(|failure| panic!("rollback intent persistence failed: {failure}"));
    current = machine
        .record_effect(
            &current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: first_effect.clone(),
                occurred_at_unix_ms: 127,
                mutation: EffectMutation::RollbackFailed {
                    error_code: error("response.rollback_failed"),
                },
            },
        )
        .unwrap_or_else(|failure| panic!("rollback failure persistence failed: {failure}"));
    current = machine
        .transition(
            &current,
            &transition(current.generation, ResponseState::RollbackPartial, 128),
        )
        .unwrap_or_else(|failure| panic!("rollback partial transition failed: {failure}"));
    let partial = decode_response_record(&current)
        .unwrap_or_else(|failure| panic!("response decode failed: {failure}"));
    assert_eq!(partial.state, ResponseState::RollbackPartial);
    assert!(partial.operator_page_required);
    assert!(machine
        .transition(
            &current,
            &transition(current.generation, ResponseState::Lifted, 129),
        )
        .is_err());

    current = machine
        .transition(
            &current,
            &transition(current.generation, ResponseState::RollingBack, 130),
        )
        .unwrap_or_else(|failure| panic!("rollback retry failed: {failure}"));
    current = machine
        .record_effect(
            &current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: first_effect.clone(),
                occurred_at_unix_ms: 131,
                mutation: EffectMutation::RollbackRequested,
            },
        )
        .unwrap_or_else(|failure| panic!("rollback retry intent failed: {failure}"));
    current = machine
        .record_effect(
            &current,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: first_effect,
                occurred_at_unix_ms: 132,
                mutation: EffectMutation::RollbackRestored {
                    resulting_version_hash: digest(41),
                },
            },
        )
        .unwrap_or_else(|failure| panic!("rollback restore persistence failed: {failure}"));
    current = machine
        .transition(
            &current,
            &transition(current.generation, ResponseState::Lifted, 133),
        )
        .unwrap_or_else(|failure| panic!("rollback completion failed: {failure}"));
    let lifted = decode_response_record(&current)
        .unwrap_or_else(|failure| panic!("response decode failed: {failure}"));
    assert_eq!(lifted.state, ResponseState::Lifted);
    assert!(lifted.all_applied_reversible_effects_restored());
    assert!(matches!(
        lifted.mutations.as_slice().last(),
        Some(chio_security_types::ResponseMutationRecord::Final(record))
            if record.final_state == ResponseState::Lifted
    ));
}

#[test]
fn applying_timeout_and_active_expiry_enter_rollback_through_required_states() {
    let (machine, planned) = machine_with_plan(1);
    let applying = enter_applying(&machine, &planned, 110);
    let requested = request_effect_at(&machine, &applying, 0, 120);
    let applying = apply_requested_effect_at(&machine, &requested, 0, 121);
    let timed_out = machine
        .handle_due(&applying, applying.generation, 500)
        .unwrap_or_else(|failure| panic!("applying timeout failed: {failure}"));
    let timeout_snapshot = decode_response_record(&timed_out)
        .unwrap_or_else(|failure| panic!("response decode failed: {failure}"));
    assert_eq!(timeout_snapshot.state, ResponseState::RollingBack);
    assert!(timeout_snapshot
        .mutations
        .as_slice()
        .iter()
        .any(|mutation| {
            matches!(
                mutation,
                chio_security_types::ResponseMutationRecord::Failed(record)
                    if record.to_state == ResponseState::ApplyPartial
            )
        }));

    let (active_machine, active_planned) = machine_with_plan(1);
    let mut applying = active_machine
        .transition(
            &active_planned,
            &transition(0, ResponseState::Applying, 110),
        )
        .unwrap_or_else(|failure| panic!("begin apply failed: {failure}"));
    let active_effect = effect_id(&applying, 0);
    applying = active_machine
        .record_effect(
            &applying,
            &EffectMutationRequest {
                expected_generation: applying.generation,
                effect_id: active_effect.clone(),
                occurred_at_unix_ms: 120,
                mutation: EffectMutation::Requested,
            },
        )
        .unwrap_or_else(|failure| panic!("effect request failed: {failure}"));
    applying = active_machine
        .record_effect(
            &applying,
            &EffectMutationRequest {
                expected_generation: applying.generation,
                effect_id: active_effect,
                occurred_at_unix_ms: 121,
                mutation: EffectMutation::Applied {
                    resulting_version_hash: digest(42),
                },
            },
        )
        .unwrap_or_else(|failure| panic!("effect apply failed: {failure}"));
    let active = active_machine
        .transition(
            &applying,
            &transition(applying.generation, ResponseState::Active, 200),
        )
        .unwrap_or_else(|failure| panic!("activate failed: {failure}"));
    let expired = active_machine
        .handle_due(&active, active.generation, 1_000)
        .unwrap_or_else(|failure| panic!("active expiry failed: {failure}"));
    let expiry_snapshot = decode_response_record(&expired)
        .unwrap_or_else(|failure| panic!("response decode failed: {failure}"));
    assert_eq!(expiry_snapshot.state, ResponseState::RollingBack);
    assert!(expiry_snapshot.mutations.as_slice().iter().any(|mutation| {
        matches!(
            mutation,
            chio_security_types::ResponseMutationRecord::Transition(record)
                if record.to_state == ResponseState::Expiring
        )
    }));
}

#[test]
fn overdue_retry_at_a_later_clock_is_idempotent() {
    let (machine, planned) = machine_with_plan(1);
    let applying = enter_applying(&machine, &planned, 110);
    let requested = request_effect_at(&machine, &applying, 0, 120);
    let applying = apply_requested_effect_at(&machine, &requested, 0, 121);
    let first = machine
        .handle_due(&applying, applying.generation, 500)
        .unwrap_or_else(|failure| panic!("first timeout handling failed: {failure}"));
    let retry = machine
        .handle_due(&applying, applying.generation, 700)
        .unwrap_or_else(|failure| panic!("timeout retry failed: {failure}"));
    assert_eq!(retry, first);
}

#[test]
fn terminal_failure_cannot_bypass_partial_rollback_at_the_apply_lease_deadline() {
    let (machine, planned) = machine_with_plan(1);
    let applying = machine
        .transition(&planned, &transition(0, ResponseState::Applying, 110))
        .unwrap_or_else(|failure| panic!("begin apply failed: {failure}"));
    assert!(machine
        .transition(
            &applying,
            &transition(applying.generation, ResponseState::Failed, 500),
        )
        .is_err());
    let requested = request_effect_at(&machine, &applying, 0, 120);
    let applying = apply_requested_effect_at(&machine, &requested, 0, 121);
    let timed_out = machine
        .handle_due(&applying, applying.generation, 500)
        .unwrap_or_else(|failure| panic!("apply timeout handling failed: {failure}"));
    let snapshot = decode_response_record(&timed_out)
        .unwrap_or_else(|failure| panic!("response decode failed: {failure}"));
    assert_eq!(snapshot.state, ResponseState::RollingBack);
    assert!(snapshot.mutations.as_slice().iter().any(|mutation| {
        matches!(
            mutation,
            chio_security_types::ResponseMutationRecord::Failed(record)
                if record.to_state == ResponseState::ApplyPartial
        )
    }));
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn lifted_is_unreachable_until_every_applied_reversible_effect_is_restored(
        restore in proptest::collection::vec(any::<bool>(), 1..8)
    ) {
        let count = u8::try_from(restore.len()).unwrap_or(u8::MAX);
        let (machine, planned) = machine_with_plan(count);
        let mut current = machine
            .transition(&planned, &transition(0, ResponseState::Applying, 110))
            .unwrap_or_else(|failure| panic!("begin apply failed: {failure}"));
        let effect_ids: Vec<EffectId> = decode_response_record(&current)
            .unwrap_or_else(|failure| panic!("response decode failed: {failure}"))
            .plan
            .effects
            .as_slice()
            .iter()
            .map(|effect| effect.effect_id.clone())
            .collect();
        for (index, effect_id) in effect_ids.iter().enumerate() {
            current = machine
                .record_effect(
                    &current,
                    &EffectMutationRequest {
                        expected_generation: current.generation,
                        effect_id: effect_id.clone(),
                        occurred_at_unix_ms: 120 + index as u64 * 2,
                        mutation: EffectMutation::Requested,
                    },
                )
                .unwrap_or_else(|failure| panic!("effect request failed: {failure}"));
            current = machine
                .record_effect(
                    &current,
                    &EffectMutationRequest {
                        expected_generation: current.generation,
                        effect_id: effect_id.clone(),
                        occurred_at_unix_ms: 121 + index as u64 * 2,
                        mutation: EffectMutation::Applied {
                            resulting_version_hash: digest(50),
                        },
                    },
                )
                .unwrap_or_else(|failure| panic!("effect apply failed: {failure}"));
        }
        current = machine
            .transition(
                &current,
                &transition(current.generation, ResponseState::Active, 300),
            )
            .unwrap_or_else(|failure| panic!("activation failed: {failure}"));
        current = machine
            .transition(
                &current,
                &transition(current.generation, ResponseState::RollingBack, 301),
            )
            .unwrap_or_else(|failure| panic!("rollback start failed: {failure}"));
        for (index, (effect_id, should_restore)) in effect_ids.iter().zip(&restore).enumerate() {
            current = machine
                .record_effect(
                    &current,
                    &EffectMutationRequest {
                        expected_generation: current.generation,
                        effect_id: effect_id.clone(),
                        occurred_at_unix_ms: 310 + index as u64 * 2,
                        mutation: EffectMutation::RollbackRequested,
                    },
                )
                .unwrap_or_else(|failure| panic!("rollback request failed: {failure}"));
            if *should_restore {
                current = machine
                    .record_effect(
                        &current,
                        &EffectMutationRequest {
                            expected_generation: current.generation,
                            effect_id: effect_id.clone(),
                            occurred_at_unix_ms: 311 + index as u64 * 2,
                            mutation: EffectMutation::RollbackRestored {
                                resulting_version_hash: digest(51),
                            },
                        },
                    )
                .unwrap_or_else(|failure| panic!("rollback restore failed: {failure}"));
            }
        }
        let rollback_snapshot = decode_response_record(&current)
            .unwrap_or_else(|failure| panic!("rollback response decode failed: {failure}"));
        prop_assert_eq!(
            rollback_snapshot.all_applied_reversible_effects_restored(),
            restore.iter().all(|restored| *restored)
        );
        let result = machine.transition(
            &current,
            &transition(current.generation, ResponseState::Lifted, 400),
        );
        prop_assert_eq!(result.is_ok(), restore.iter().all(|restored| *restored));
    }
}

#[test]
fn reversible_effect_vocabulary_cannot_construct_permanent_revocation() {
    for value in 0_u8..=u8::MAX {
        let kind = match value % 6 {
            0 => ResponseEffectKind::EscalateAlert,
            1 => ResponseEffectKind::ThrottleSession,
            2 => ResponseEffectKind::RestrictEgress,
            3 => ResponseEffectKind::SuspendSession,
            4 => ResponseEffectKind::SuspendCapabilitySet,
            _ => ResponseEffectKind::FreezeIssuance,
        };
        let encoded = serde_json::to_string(&kind)
            .unwrap_or_else(|failure| panic!("effect kind serialization failed: {failure}"));
        assert!(!encoded.contains("revocation"));
    }
    assert!(serde_json::from_str::<ResponseEffectKind>("\"permanent_revocation\"").is_err());
}

#[test]
fn cancellation_before_apply_is_terminal() {
    let (machine, planned) = machine_with_plan(1);
    let cancelled = machine
        .transition(&planned, &transition(0, ResponseState::Cancelled, 110))
        .unwrap_or_else(|failure| panic!("cancel failed: {failure}"));
    let snapshot = decode_response_record(&cancelled)
        .unwrap_or_else(|failure| panic!("response decode failed: {failure}"));
    assert_eq!(snapshot.state, ResponseState::Cancelled);
    assert!(matches!(
        snapshot.mutations.as_slice().last(),
        Some(chio_security_types::ResponseMutationRecord::Final(record))
            if record.final_state == ResponseState::Cancelled
    ));
    assert!(machine
        .transition(
            &cancelled,
            &transition(cancelled.generation, ResponseState::Applying, 111),
        )
        .is_err());
}

#[test]
fn response_plan_rejects_empty_effects_and_invalid_target_shapes() {
    assert!(build_response_plan(plan_input(0)).is_err());
    let mut invalid = plan_input(1);
    invalid.effects[0] = ResponseEffectSpec {
        kind: ResponseEffectKind::FreezeIssuance,
        target: ResponseTarget::Session {
            session_id: SessionId::new("wrong-target")
                .unwrap_or_else(|failure| panic!("invalid session id: {failure}")),
        },
        canonical_contribution: CanonicalBody::new(b"{}".to_vec())
            .unwrap_or_else(|failure| panic!("invalid contribution body: {failure}")),
        contribution_hash: digest(60),
        observed_base_version_hash: digest(61),
    };
    assert!(build_response_plan(invalid).is_err());
}
