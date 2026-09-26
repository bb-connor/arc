mod response_support;

use chio_quarantine::{
    build_response_plan, decode_response_record, prepare_response_dispatch, EffectMutation,
    EffectMutationRequest, EffectReceiptContext, ResponseDispatchPreparationRequest,
    ResponseStateMachine, ResponseTransitionRequest, StateMachineError,
};
use chio_security_types::ports::{
    ActionId, BoundedVec, CanonicalBody, CreateOutcome, Digest32, ErrorCode, LeaseOwnerId,
    RecordId, ResponseDispatchApproval, ResponseDispatchAuthorizationBody, ResponseDispatchLease,
    ResponsePlanRecord, ResponseStore, SessionId, TenantId,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind,
    ResponseEffectProgress, ResponseEffectSpec, ResponseMutationRecord, ResponsePlanInput,
    ResponseSnapshot, ResponseState, ResponseTarget, ResponseTransitionCause,
};
use response_support::TestResponseStore;
use std::sync::Arc;

fn digest(value: u8) -> Digest32 {
    Digest32::new([value; 32])
}

fn record_id(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("invalid record id: {error}"))
}

fn error_code(value: &str) -> ErrorCode {
    ErrorCode::new(value).unwrap_or_else(|error| panic!("invalid error code: {error}"))
}

fn response_record(snapshot: &ResponseSnapshot) -> ResponsePlanRecord {
    let canonical = chio_core_types::canonical_json_bytes(snapshot)
        .unwrap_or_else(|error| panic!("response snapshot canonicalization failed: {error}"));
    ResponsePlanRecord {
        tenant_id: snapshot.plan.tenant_id.clone(),
        action_id: snapshot.plan.action_id.clone(),
        generation: snapshot.generation,
        state: RecordId::new(snapshot.state.as_str())
            .unwrap_or_else(|error| panic!("response state id failed: {error}")),
        canonical_body: CanonicalBody::new(canonical.clone())
            .unwrap_or_else(|error| panic!("response canonical body failed: {error}")),
        body_hash: Digest32::new(*chio_core_types::sha256(&canonical).as_bytes()),
        due_at_unix_ms: snapshot.due_at_unix_ms,
    }
}

fn plan(approval_requirement: ResponseApprovalRequirement) -> chio_security_types::ResponsePlan {
    let canonical_contribution = CanonicalBody::new(b"{\"posture_rank\":2}".to_vec())
        .unwrap_or_else(|error| panic!("invalid contribution body: {error}"));
    let contribution_hash =
        Digest32::new(*chio_core_types::sha256(canonical_contribution.as_bytes()).as_bytes());
    build_response_plan(ResponsePlanInput {
        action_id: ActionId::new("action-dispatch")
            .unwrap_or_else(|error| panic!("invalid action id: {error}")),
        trigger_finding_id: record_id("finding-dispatch"),
        trigger_finding_hash: digest(31),
        trigger_finding_receipt_id: chio_security_types::ports::OpaqueReceiptRef::new(
            "finding-dispatch-receipt",
        )
        .unwrap_or_else(|error| panic!("invalid finding receipt id: {error}")),
        tenant_id: TenantId::new("tenant-dispatch")
            .unwrap_or_else(|error| panic!("invalid tenant id: {error}")),
        policy_version: record_id("policy-dispatch"),
        policy_hash: digest(32),
        affected_ids: vec![record_id("affected-dispatch")],
        effects: vec![ResponseEffectSpec {
            kind: ResponseEffectKind::ThrottleSession,
            target: ResponseTarget::Session {
                session_id: SessionId::new("session-dispatch")
                    .unwrap_or_else(|error| panic!("invalid session id: {error}")),
            },
            canonical_contribution,
            contribution_hash,
            observed_base_version_hash: digest(20),
        }],
        ttl_ms: 10_000,
        created_at_unix_ms: 40_000,
        operator_capability: OperatorCapabilityBinding {
            capability_id: record_id("capability-dispatch"),
            capability_digest: digest(30),
            expires_at_unix_ms: 60_000,
            executor_subject: record_id("executor-subject"),
        },
        approval_requirement,
        submitter: record_id("submitter-dispatch"),
        reason_hash: digest(31),
    })
    .unwrap_or_else(|error| panic!("response plan build failed: {error}"))
}

fn preparation(
    plan: chio_security_types::ResponsePlan,
    approval: ResponseDispatchApproval,
) -> ResponseDispatchPreparationRequest {
    ResponseDispatchPreparationRequest {
        plan,
        dispatch_id: record_id("active-response-dispatch"),
        authorization_capability_hash: digest(30),
        governed_intent_hash: digest(32),
        policy_decision_hash: digest(33),
        executor_authority_id: record_id("executor-authority"),
        executor_authority_generation: 4,
        approval,
        authorized_at_unix_ms: 41_000,
        initial_lease: ResponseDispatchLease {
            lease_owner_id: LeaseOwnerId::new("response-worker")
                .unwrap_or_else(|error| panic!("invalid lease owner: {error}")),
            lease_expires_at_unix_ms: 42_000,
        },
        commit_mode: chio_security_types::ports::ResponseDispatchCommitMode::Fresh,
    }
}

#[test]
fn automatic_dispatch_prepares_one_atomic_applying_transition() {
    let prepared = prepare_response_dispatch(preparation(
        plan(ResponseApprovalRequirement::Automatic),
        ResponseDispatchApproval::Automatic,
    ))
    .unwrap_or_else(|error| panic!("automatic dispatch preparation failed: {error}"));

    let snapshot = decode_response_record(&prepared.response_plan)
        .unwrap_or_else(|error| panic!("prepared response record is invalid: {error}"));
    assert_eq!(snapshot.state, ResponseState::Applying);
    assert_eq!(snapshot.generation, 1);
    assert_eq!(snapshot.applying_lease_expires_at_unix_ms, Some(42_000));
    assert_eq!(snapshot.due_at_unix_ms, Some(42_000));
    assert_eq!(snapshot.mutations.len(), 2);
    assert!(matches!(
        snapshot.mutations.as_slice(),
        [
            ResponseMutationRecord::Requested(_),
            ResponseMutationRecord::Transition(transition)
        ] if transition.from_state == ResponseState::Planned
            && transition.to_state == ResponseState::Applying
            && transition.cause == ResponseTransitionCause::ApplyStarted
            && transition.generation == 1
    ));
    assert_eq!(
        snapshot.dispatch_authorization_hash,
        Some(prepared.authorization.body_hash)
    );
    let mut normalized_snapshot = snapshot.clone();
    normalized_snapshot.dispatch_authorization_hash = None;
    let normalized_canonical = chio_core_types::canonical_json_bytes(&normalized_snapshot)
        .unwrap_or_else(|error| panic!("normalized response canonicalization failed: {error}"));
    assert_eq!(
        prepared.authorization.body.response_body_hash,
        Digest32::new(*chio_core_types::sha256(&normalized_canonical).as_bytes())
    );
    assert_ne!(
        prepared.authorization.body.response_body_hash,
        prepared.response_plan.body_hash
    );
    assert_eq!(
        prepared.authorization.body.authorization_capability_hash,
        snapshot.plan.operator_capability.capability_digest
    );
    let decoded_authorization: ResponseDispatchAuthorizationBody =
        serde_json::from_slice(prepared.authorization.canonical_body.as_bytes())
            .unwrap_or_else(|error| panic!("authorization body decode failed: {error}"));
    assert_eq!(decoded_authorization, prepared.authorization.body);
    assert_eq!(
        prepared.authorization.body_hash,
        Digest32::new(
            *chio_core_types::sha256(prepared.authorization.canonical_body.as_bytes()).as_bytes()
        )
    );
    assert_eq!(prepared.initial_lease.lease_expires_at_unix_ms, 42_000);

    let normalized_record = ResponsePlanRecord {
        tenant_id: snapshot.plan.tenant_id.clone(),
        action_id: snapshot.plan.action_id.clone(),
        generation: snapshot.generation,
        state: RecordId::new(snapshot.state.as_str())
            .unwrap_or_else(|error| panic!("normalized state id failed: {error}")),
        canonical_body: CanonicalBody::new(normalized_canonical.clone())
            .unwrap_or_else(|error| panic!("normalized canonical body failed: {error}")),
        body_hash: Digest32::new(*chio_core_types::sha256(&normalized_canonical).as_bytes()),
        due_at_unix_ms: snapshot.due_at_unix_ms,
    };
    assert!(decode_response_record(&normalized_record).is_err());

    let mut authorization_without_dispatch = snapshot;
    authorization_without_dispatch.execution_dispatch = None;
    let canonical = chio_core_types::canonical_json_bytes(&authorization_without_dispatch)
        .unwrap_or_else(|error| panic!("mismatched response canonicalization failed: {error}"));
    let mismatched_record = ResponsePlanRecord {
        tenant_id: authorization_without_dispatch.plan.tenant_id.clone(),
        action_id: authorization_without_dispatch.plan.action_id.clone(),
        generation: authorization_without_dispatch.generation,
        state: RecordId::new(authorization_without_dispatch.state.as_str())
            .unwrap_or_else(|error| panic!("mismatched state id failed: {error}")),
        canonical_body: CanonicalBody::new(canonical.clone())
            .unwrap_or_else(|error| panic!("mismatched canonical body failed: {error}")),
        body_hash: Digest32::new(*chio_core_types::sha256(&canonical).as_bytes()),
        due_at_unix_ms: authorization_without_dispatch.due_at_unix_ms,
    };
    assert!(decode_response_record(&mismatched_record).is_err());
}

#[test]
fn dispatch_binding_requires_one_applying_transition_at_authorization_time() {
    let prepared = prepare_response_dispatch(preparation(
        plan(ResponseApprovalRequirement::Automatic),
        ResponseDispatchApproval::Automatic,
    ))
    .unwrap_or_else(|error| panic!("automatic dispatch preparation failed: {error}"));
    let snapshot = decode_response_record(&prepared.response_plan)
        .unwrap_or_else(|error| panic!("prepared response record is invalid: {error}"));

    let mut mismatched_time = snapshot.clone();
    mismatched_time
        .execution_dispatch
        .as_mut()
        .unwrap_or_else(|| panic!("execution dispatch binding missing"))
        .authorized_at_unix_ms = 41_001;
    assert!(decode_response_record(&response_record(&mismatched_time)).is_err());

    let mut missing_applying = snapshot;
    missing_applying.mutations =
        BoundedVec::new(vec![missing_applying.mutations.as_slice()[0].clone()])
            .unwrap_or_else(|error| panic!("requested-only mutation log failed: {error}"));
    missing_applying.state = ResponseState::Planned;
    missing_applying.generation = 0;
    missing_applying.applying_lease_expires_at_unix_ms = None;
    missing_applying.due_at_unix_ms = Some(missing_applying.plan.expires_at_unix_ms);
    assert!(decode_response_record(&response_record(&missing_applying)).is_err());
}

#[test]
fn dispatch_bound_effect_outcome_requires_effect_transition_id() {
    let prepared = prepare_response_dispatch(preparation(
        plan(ResponseApprovalRequirement::Automatic),
        ResponseDispatchApproval::Automatic,
    ))
    .unwrap_or_else(|error| panic!("automatic dispatch preparation failed: {error}"));
    let store = Arc::new(TestResponseStore::default());
    store
        .create(&prepared.response_plan)
        .unwrap_or_else(|error| panic!("prepared dispatch persistence failed: {error}"));
    let machine = ResponseStateMachine::new(store);
    let snapshot = decode_response_record(&prepared.response_plan)
        .unwrap_or_else(|error| panic!("prepared response record is invalid: {error}"));
    let effect_id = snapshot.plan.effects.as_slice()[0].effect_id.clone();
    let requested = machine
        .record_effect(
            &prepared.response_plan,
            &EffectMutationRequest {
                expected_generation: prepared.response_plan.generation,
                effect_id: effect_id.clone(),
                occurred_at_unix_ms: 41_500,
                mutation: EffectMutation::Requested,
            },
        )
        .unwrap_or_else(|error| panic!("dispatch effect request failed: {error}"));
    assert!(matches!(
        machine.record_effect_with_receipt(
            &requested,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id,
                occurred_at_unix_ms: 41_600,
                mutation: EffectMutation::Applied {
                    resulting_version_hash: digest(70),
                },
            },
            &EffectReceiptContext {
                effect_generation: 2,
                scheduler_lease_owner_id: None,
                scheduler_fencing_token: 1,
                effect_transition_id: None,
                prior_receipt_id: None,
            },
        ),
        Err(StateMachineError::InvalidEffectLifecycle)
    ));
}

#[test]
fn committed_dispatch_apply_deadline_fails_before_any_effect() {
    let prepared = prepare_response_dispatch(preparation(
        plan(ResponseApprovalRequirement::Automatic),
        ResponseDispatchApproval::Automatic,
    ))
    .unwrap_or_else(|error| panic!("automatic dispatch preparation failed: {error}"));
    let store = Arc::new(TestResponseStore::default());
    assert_eq!(
        store
            .create(&prepared.response_plan)
            .unwrap_or_else(|error| panic!("prepared dispatch persistence failed: {error}")),
        CreateOutcome::Created
    );
    let machine = ResponseStateMachine::new(Arc::clone(&store));

    assert!(matches!(
        machine.transition(
            &prepared.response_plan,
            &ResponseTransitionRequest {
                expected_generation: prepared.response_plan.generation,
                target_state: ResponseState::Failed,
                occurred_at_unix_ms: 41_999,
                applying_lease_expires_at_unix_ms: None,
                error_code: Some(error_code(
                    "active_response.dispatch_apply_lease_expired_before_effect",
                )),
            },
        ),
        Err(StateMachineError::InvalidTiming)
    ));

    let failed = machine
        .handle_due(
            &prepared.response_plan,
            prepared.response_plan.generation,
            42_000,
        )
        .unwrap_or_else(|error| panic!("dispatch deadline terminalization failed: {error}"));
    let snapshot = decode_response_record(&failed)
        .unwrap_or_else(|error| panic!("failed dispatch record is invalid: {error}"));
    assert_eq!(snapshot.state, ResponseState::Failed);
    assert!(snapshot.plan.effects.as_slice().iter().all(|effect| {
        snapshot.effect_progress(&effect.effect_id) == Some(ResponseEffectProgress::Planned)
    }));
    assert!(matches!(
        snapshot.mutations.as_slice().last(),
        Some(ResponseMutationRecord::Failed(record))
            if record.error_code.as_str()
                == "active_response.dispatch_apply_lease_expired_before_effect"
    ));
}

#[test]
fn committed_resume_expiry_code_is_reserved_for_exact_plan_expiry() {
    let prepared = prepare_response_dispatch(preparation(
        plan(ResponseApprovalRequirement::Automatic),
        ResponseDispatchApproval::Automatic,
    ))
    .unwrap_or_else(|error| panic!("automatic dispatch preparation failed: {error}"));
    let store = Arc::new(TestResponseStore::default());
    store
        .create(&prepared.response_plan)
        .unwrap_or_else(|error| panic!("prepared dispatch persistence failed: {error}"));
    let machine = ResponseStateMachine::new(store);
    assert!(matches!(
        machine.transition(
            &prepared.response_plan,
            &ResponseTransitionRequest {
                expected_generation: prepared.response_plan.generation,
                target_state: ResponseState::Failed,
                occurred_at_unix_ms: 41_500,
                applying_lease_expires_at_unix_ms: None,
                error_code: Some(error_code(
                    "active_response.dispatch_committed_resume_expired",
                )),
            },
        ),
        Err(StateMachineError::InvalidTiming)
    ));

    let failed = machine
        .fail_expired_dispatch_committed_resume(
            &prepared.response_plan,
            prepared.response_plan.generation,
            50_000,
        )
        .unwrap_or_else(|error| panic!("exact committed-resume expiry rejected: {error}"));
    assert_eq!(
        decode_response_record(&failed)
            .unwrap_or_else(|error| panic!("expired committed resume is invalid: {error}"))
            .state,
        ResponseState::Failed
    );
}

#[test]
fn committed_dispatch_deadline_preserves_requested_ambiguity_and_applied_rollback() {
    let requested_prepared = prepare_response_dispatch(preparation(
        plan(ResponseApprovalRequirement::Automatic),
        ResponseDispatchApproval::Automatic,
    ))
    .unwrap_or_else(|error| panic!("requested dispatch preparation failed: {error}"));
    let requested_store = Arc::new(TestResponseStore::default());
    requested_store
        .create(&requested_prepared.response_plan)
        .unwrap_or_else(|error| panic!("requested dispatch persistence failed: {error}"));
    let requested_machine = ResponseStateMachine::new(Arc::clone(&requested_store));
    let requested_snapshot = decode_response_record(&requested_prepared.response_plan)
        .unwrap_or_else(|error| panic!("requested dispatch record is invalid: {error}"));
    let effect_id = requested_snapshot.plan.effects.as_slice()[0]
        .effect_id
        .clone();
    let requested = requested_machine
        .record_effect(
            &requested_prepared.response_plan,
            &EffectMutationRequest {
                expected_generation: requested_prepared.response_plan.generation,
                effect_id: effect_id.clone(),
                occurred_at_unix_ms: 41_500,
                mutation: EffectMutation::Requested,
            },
        )
        .unwrap_or_else(|error| panic!("effect request persistence failed: {error}"));
    assert!(matches!(
        requested_machine.handle_due(&requested, requested.generation, 42_000),
        Err(StateMachineError::IncompleteApplication)
    ));
    assert_eq!(
        requested_store
            .load_plan(&chio_security_types::ports::ResponsePlanKey {
                tenant_id: requested.tenant_id.clone(),
                action_id: requested.action_id.clone(),
            })
            .unwrap_or_else(|error| panic!("requested dispatch reload failed: {error}")),
        Some(requested.clone())
    );

    let applied_prepared = prepare_response_dispatch(preparation(
        plan(ResponseApprovalRequirement::Automatic),
        ResponseDispatchApproval::Automatic,
    ))
    .unwrap_or_else(|error| panic!("applied dispatch preparation failed: {error}"));
    let applied_store = Arc::new(TestResponseStore::default());
    applied_store
        .create(&applied_prepared.response_plan)
        .unwrap_or_else(|error| panic!("applied dispatch persistence failed: {error}"));
    let applied_machine = ResponseStateMachine::new(applied_store);
    let effect_requested = applied_machine
        .record_effect(
            &applied_prepared.response_plan,
            &EffectMutationRequest {
                expected_generation: applied_prepared.response_plan.generation,
                effect_id: effect_id.clone(),
                occurred_at_unix_ms: 41_500,
                mutation: EffectMutation::Requested,
            },
        )
        .unwrap_or_else(|error| panic!("applied effect request failed: {error}"));
    let applied = applied_machine
        .record_effect_with_receipt(
            &effect_requested,
            &EffectMutationRequest {
                expected_generation: effect_requested.generation,
                effect_id,
                occurred_at_unix_ms: 41_600,
                mutation: EffectMutation::Applied {
                    resulting_version_hash: digest(70),
                },
            },
            &EffectReceiptContext {
                effect_generation: 2,
                scheduler_lease_owner_id: None,
                scheduler_fencing_token: 1,
                effect_transition_id: Some(record_id("dispatch-effect-applied")),
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|error| panic!("applied effect persistence failed: {error}"));
    let rolling_back = applied_machine
        .handle_due(&applied, applied.generation, 42_000)
        .unwrap_or_else(|error| panic!("applied dispatch rollback failed: {error}"));
    assert_eq!(
        decode_response_record(&rolling_back)
            .unwrap_or_else(|error| panic!("rollback dispatch record is invalid: {error}"))
            .state,
        ResponseState::RollingBack
    );
}

#[test]
fn governed_dispatch_preserves_approval_history_before_applying() {
    let prepared = prepare_response_dispatch(preparation(
        plan(ResponseApprovalRequirement::Governed {
            policy_id: record_id("response-policy"),
        }),
        ResponseDispatchApproval::Governed {
            admission_operation_id: record_id("admission-operation"),
            admission_operation_version: 2,
            approval_set_hash: digest(40),
        },
    ))
    .unwrap_or_else(|error| panic!("governed dispatch preparation failed: {error}"));

    let snapshot = decode_response_record(&prepared.response_plan)
        .unwrap_or_else(|error| panic!("prepared response record is invalid: {error}"));
    assert_eq!(snapshot.state, ResponseState::Applying);
    assert_eq!(snapshot.generation, 2);
    assert!(matches!(
        snapshot.mutations.as_slice(),
        [
            ResponseMutationRecord::Requested(_),
            ResponseMutationRecord::Transition(awaiting),
            ResponseMutationRecord::Transition(applying)
        ] if awaiting.from_state == ResponseState::Planned
            && awaiting.to_state == ResponseState::AwaitingApproval
            && awaiting.cause == ResponseTransitionCause::ApprovalRequested
            && awaiting.generation == 1
            && applying.from_state == ResponseState::AwaitingApproval
            && applying.to_state == ResponseState::Applying
            && applying.cause == ResponseTransitionCause::ApprovalSatisfied
            && applying.generation == 2
    ));
}

#[test]
fn dispatch_preparation_rejects_authorization_or_approval_mismatch() {
    let mut wrong_capability = preparation(
        plan(ResponseApprovalRequirement::Automatic),
        ResponseDispatchApproval::Automatic,
    );
    wrong_capability.authorization_capability_hash = digest(99);
    assert!(prepare_response_dispatch(wrong_capability).is_err());

    let wrong_mode = preparation(
        plan(ResponseApprovalRequirement::Governed {
            policy_id: record_id("response-policy"),
        }),
        ResponseDispatchApproval::Automatic,
    );
    assert!(prepare_response_dispatch(wrong_mode).is_err());
}
