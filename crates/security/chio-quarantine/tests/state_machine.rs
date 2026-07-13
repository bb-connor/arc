mod response_support;

use chio_quarantine::{
    build_response_plan, decode_response_record, EffectMutation, EffectMutationRequest,
    ResponseStateMachine, ResponseTransitionRequest,
};
use chio_security_types::ports::{
    ActionId, BoundedVec, CanonicalBody, Digest32, EffectId, ErrorCode, ResponsePlanRecord,
    SessionId, TenantId,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind, ResponseEffectSpec,
    ResponsePlanAuthorizationBody, ResponsePlanInput, ResponseState, ResponseTarget,
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

const LEGAL_STATE_EDGES: [(ResponseState, ResponseState); 19] = [
    (ResponseState::Planned, ResponseState::AwaitingApproval),
    (ResponseState::Planned, ResponseState::Applying),
    (ResponseState::Planned, ResponseState::Cancelled),
    (ResponseState::Planned, ResponseState::Expired),
    (ResponseState::Planned, ResponseState::Failed),
    (ResponseState::AwaitingApproval, ResponseState::Applying),
    (ResponseState::AwaitingApproval, ResponseState::Cancelled),
    (ResponseState::AwaitingApproval, ResponseState::Expired),
    (ResponseState::AwaitingApproval, ResponseState::Failed),
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
        tenant_id: TenantId::new("tenant-response")
            .unwrap_or_else(|failure| panic!("invalid tenant id: {failure}")),
        policy_version: record("policy-response"),
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
    let store = Arc::new(TestResponseStore::default());
    let machine = ResponseStateMachine::new(store);
    let plan = build_response_plan(plan_input(effect_count))
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
    machine
        .transition(
            &applying,
            &transition(applying.generation, ResponseState::ApplyPartial, 120),
        )
        .unwrap_or_else(|failure| panic!("partial apply failed: {failure}"))
}

fn enter_rolling_back_without_applied_effect(
    machine: &ResponseStateMachine<TestResponseStore>,
    planned: &ResponsePlanRecord,
) -> ResponsePlanRecord {
    let partial = enter_apply_partial(machine, planned);
    machine
        .transition(
            &partial,
            &transition(partial.generation, ResponseState::RollingBack, 121),
        )
        .unwrap_or_else(|failure| panic!("begin rollback failed: {failure}"))
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
    let (machine, planned) = machine_with_plan(1);
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
            if target_state == ResponseState::Active {
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
        ResponseState::RollingBack => enter_rolling_back_without_applied_effect(&machine, &planned),
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
            let rolling_back = enter_rolling_back_without_applied_effect(&machine, &planned);
            machine
                .transition(
                    &rolling_back,
                    &transition(rolling_back.generation, ResponseState::Lifted, 122),
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
            let expected = LEGAL_STATE_EDGES.contains(&(from_state, target_state));
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
fn response_plan_authorization_body_excludes_its_own_hash() {
    let plan = build_response_plan(plan_input(2))
        .unwrap_or_else(|failure| panic!("valid response plan rejected: {failure}"));
    let body = plan.authorization_body();
    let mut encoded = serde_json::to_value(&body)
        .unwrap_or_else(|failure| panic!("authorization body encoding failed: {failure}"));

    assert_eq!(body.action_id, plan.action_id);
    assert!(encoded.get("plan_hash").is_none());
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
            &transition(current.generation, ResponseState::Failed, 124),
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
    let applying = machine
        .transition(&planned, &transition(0, ResponseState::Applying, 110))
        .unwrap_or_else(|failure| panic!("begin apply failed: {failure}"));
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
    let applying = machine
        .transition(&planned, &transition(0, ResponseState::Applying, 110))
        .unwrap_or_else(|failure| panic!("begin apply failed: {failure}"));
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
    #![proptest_config(ProptestConfig::with_cases(32))]

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
