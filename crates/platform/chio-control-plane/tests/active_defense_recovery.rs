use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_control_plane::security::adapters::effect_port::{
    session_containment_target, session_overlay_version_hash, CapabilitySetSuspensionBackend,
    ResponseEffectBackend, SessionSuspensionOverlayBackend,
};
use chio_core::canonical_json_bytes;
use chio_core::capability::scope::ChioScope;
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::Keypair;
use chio_kernel::{
    Guard, GuardContext, SecurityInvocationContext, SecurityInvocationContextV1, ToolCallRequest,
    Verdict,
};
use chio_quarantine::{
    build_response_plan, decode_response_record, prepare_response_dispatch, EffectMutation,
    EffectMutationRequest, EffectReceiptContext, ResponseDispatchPreparationRequest,
    ResponseStateMachine, ResponseTransitionRequest,
};
use chio_security_kernel::{ContainmentGuard, MissingContextPolicy};
use chio_security_types::ports::{
    capability_set_suspension_version_hash, empty_capability_set_suspension_snapshot,
    response_affected_set_hash, ActionId, CanonicalBody, CapabilitySetSuspensionKey,
    CapabilitySetSuspensionSpec, CapabilitySetSuspensionStore, CapabilitySuspensionQuery,
    ContainmentOverlayStore, Digest32, EffectId, EffectOperation, EffectRequest, ErrorCode,
    IsolationEpochId, LeaseOwnerId, LineageId, OpaqueReceiptRef, RecordId, RecordIdSet,
    ResponseDispatchApproval, ResponseDispatchCommitOutcome, ResponseDispatchLease,
    ResponseDispatchStore, ResponsePlanRecord, ResponseStore, ScheduledWork, SchedulerClaimRequest,
    SessionId, TenantId,
};
use chio_security_types::{
    OperatorCapabilityBinding, PrincipalId, ResponseApprovalRequirement, ResponseEffectKind,
    ResponseEffectSpec, ResponsePlanInput, ResponseState, ResponseTarget,
};
use chio_store_sqlite::SqliteSecurityStateStore;
use tempfile::tempdir;

const POSTURE_TTL_MS: u64 = 120_000;

fn now_unix_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("clock before Unix epoch: {error}"));
    u64::try_from(elapsed.as_millis()).unwrap_or_else(|error| panic!("clock range: {error}"))
}

fn tenant() -> TenantId {
    TenantId::new("tenant-active-defense-recovery")
        .unwrap_or_else(|error| panic!("tenant id: {error}"))
}

fn session() -> SessionId {
    SessionId::new("session-active-defense-recovery")
        .unwrap_or_else(|error| panic!("session id: {error}"))
}

fn action(value: impl Into<String>) -> ActionId {
    ActionId::new(value).unwrap_or_else(|error| panic!("action id: {error}"))
}

fn effect(value: impl Into<String>) -> EffectId {
    EffectId::new(value).unwrap_or_else(|error| panic!("effect id: {error}"))
}

fn record(value: impl Into<String>) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
}

fn digest(value: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(value).as_bytes())
}

fn posture_body(rank: u32) -> (CanonicalBody, Digest32) {
    let bytes = format!("{{\"posture_rank\":{rank}}}").into_bytes();
    let hash = digest(&bytes);
    (
        CanonicalBody::new(bytes).unwrap_or_else(|error| panic!("canonical posture body: {error}")),
        hash,
    )
}

fn open_claimed_store(
    path: &Path,
    actions: &[ActionId],
) -> (Arc<SqliteSecurityStateStore>, Vec<ScheduledWork>) {
    let store = Arc::new(
        SqliteSecurityStateStore::open(path)
            .unwrap_or_else(|error| panic!("open SQLite security store: {error}")),
    );
    let now = now_unix_ms();
    for action_id in actions {
        let canonical_body =
            CanonicalBody::new(b"{}".to_vec()).unwrap_or_else(|error| panic!("plan: {error}"));
        store
            .create(&ResponsePlanRecord {
                tenant_id: tenant(),
                action_id: action_id.clone(),
                generation: 0,
                state: record("active"),
                body_hash: digest(canonical_body.as_bytes()),
                canonical_body,
                due_at_unix_ms: Some(now.saturating_sub(1)),
            })
            .unwrap_or_else(|error| panic!("create response plan: {error}"));
    }
    let work = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: tenant(),
            claim_id: record("active-defense-recovery-claim"),
            lease_owner_id: LeaseOwnerId::new("active-defense-recovery-worker")
                .unwrap_or_else(|error| panic!("lease owner: {error}")),
            now_unix_ms: now,
            lease_expires_at_unix_ms: now.saturating_add(POSTURE_TTL_MS),
            max_claims: u32::try_from(actions.len())
                .unwrap_or_else(|error| panic!("claim count: {error}")),
        })
        .unwrap_or_else(|error| panic!("claim response plans: {error}"));
    assert_eq!(work.len(), actions.len());
    (store, work)
}

fn work_for<'a>(work: &'a [ScheduledWork], action_id: &ActionId) -> &'a ScheduledWork {
    work.iter()
        .find(|entry| &entry.action_id == action_id)
        .unwrap_or_else(|| panic!("scheduled work missing for {action_id:?}"))
}

fn session_request(
    action_id: &ActionId,
    effect_id: &EffectId,
    rank: u32,
    expected_version_hash: Digest32,
    work: &ScheduledWork,
    expires_at_unix_ms: u64,
    command_suffix: &str,
) -> EffectRequest {
    let (canonical_contribution, contribution_hash) = posture_body(rank);
    EffectRequest {
        tenant_id: tenant(),
        action_id: action_id.clone(),
        plan_hash: digest(format!("plan:{}", action_id.as_str()).as_bytes()),
        effect_id: effect_id.clone(),
        effect_kind: ResponseEffectKind::SuspendSession,
        target: ResponseTarget::Session {
            session_id: session(),
        },
        plan_expires_at_unix_ms: expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record(format!("response_effect_command:{command_suffix}:apply")),
        expected_version_hash,
        scheduler_lease_owner_id: work.lease_owner_id.clone(),
        scheduler_fencing_token: work.fencing_token,
        canonical_contribution,
        contribution_hash,
    }
}

fn remove_request(
    apply: &EffectRequest,
    installed_version_hash: Digest32,
    suffix: &str,
) -> EffectRequest {
    let mut remove = apply.clone();
    remove.operation = EffectOperation::Remove;
    remove.idempotency_key = record(format!("response_effect_command:{suffix}:remove"));
    remove.expected_version_hash = installed_version_hash;
    remove
}

fn request_for_guard() -> ToolCallRequest {
    let keypair = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "capability-active-defense-recovery".to_string(),
            issuer: keypair.public_key(),
            subject: keypair.public_key(),
            scope: ChioScope::default(),
            issued_at: 1,
            expires_at: u64::MAX,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &keypair,
    )
    .unwrap_or_else(|error| panic!("sign guard capability: {error}"));
    ToolCallRequest {
        request_id: "request-active-defense-recovery".to_string(),
        agent_id: capability.subject.to_hex(),
        capability,
        tool_name: "tool-active-defense-recovery".to_string(),
        server_id: "server-active-defense-recovery".to_string(),
        arguments: serde_json::json!({"value": "input"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

fn security_context() -> SecurityInvocationContext {
    SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        tenant(),
        session(),
        PrincipalId::new("principal-active-defense-recovery")
            .unwrap_or_else(|error| panic!("principal id: {error}")),
        IsolationEpochId::new("epoch-active-defense-recovery")
            .unwrap_or_else(|error| panic!("isolation epoch: {error}")),
        LineageId::new("lineage-active-defense-recovery")
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        1,
    ))
}

fn session_verdict(store: &Arc<SqliteSecurityStateStore>) -> Verdict {
    let overlays: Arc<dyn ContainmentOverlayStore> = store.clone();
    let guard = ContainmentGuard::new(overlays, MissingContextPolicy::Deny);
    let request = request_for_guard();
    let security = security_context();
    let context = GuardContext::new(&request, &request.capability.scope)
        .with_security_context(Some(&security));
    guard
        .evaluate(&context)
        .unwrap_or_else(|error| panic!("evaluate containment guard: {error}"))
        .verdict
}

#[test]
fn normal_to_restricted_to_normal_at_ttl() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temporary directory: {error}"));
    let action_id = action("normal-restricted-normal-action");
    let effect_id = effect("normal-restricted-normal-effect");
    let (store, work) = open_claimed_store(
        directory.path().join("ttl.db").as_path(),
        std::slice::from_ref(&action_id),
    );
    let target = session_containment_target(&tenant(), &session())
        .unwrap_or_else(|error| panic!("session target: {error}"));
    let base = session_overlay_version_hash(store.as_ref(), &target)
        .unwrap_or_else(|error| panic!("base overlay version: {error}"));
    let overlays: Arc<dyn ContainmentOverlayStore> = store.clone();
    let backend = SessionSuspensionOverlayBackend::new(overlays);
    let ttl_boundary = now_unix_ms().saturating_add(POSTURE_TTL_MS);

    assert_eq!(session_verdict(&store), Verdict::Allow);
    let apply = session_request(
        &action_id,
        &effect_id,
        5,
        base,
        work_for(&work, &action_id),
        ttl_boundary,
        "normal-restricted-normal",
    );
    let applied = backend
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply temporary restriction: {error}"));
    let restricted = store
        .load_effective(&target)
        .unwrap_or_else(|error| panic!("load restricted posture: {error}"))
        .unwrap_or_else(|| panic!("restricted posture missing"));
    assert_eq!(restricted.generation, 1);
    assert_eq!(restricted.effective_posture_rank, 5);
    assert_eq!(restricted.active_contributions.len(), 1);
    assert_eq!(
        restricted.active_contributions.as_slice()[0].expires_at_unix_ms,
        Some(ttl_boundary)
    );
    assert_eq!(session_verdict(&store), Verdict::Deny);

    let remove = remove_request(
        &apply,
        applied.resulting_version_hash,
        "normal-restricted-normal",
    );
    let removed = backend
        .execute(&remove)
        .unwrap_or_else(|error| panic!("remove restriction at TTL: {error}"));
    assert!(!removed.applied);
    let normal = store
        .load_effective(&target)
        .unwrap_or_else(|error| panic!("load restored posture: {error}"))
        .unwrap_or_else(|| panic!("restored posture missing"));
    assert_eq!(normal.generation, 2);
    assert_eq!(normal.effective_posture_rank, 0);
    assert!(normal.active_contributions.is_empty());
    assert_eq!(session_verdict(&store), Verdict::Allow);
}

#[test]
fn normal_to_quarantined_to_rollback_partial_remains_denied() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temporary directory: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("rollback-partial.db"))
            .unwrap_or_else(|error| panic!("open SQLite security store: {error}")),
    );
    let now = now_unix_ms();
    let action_id = action("rollback-partial-action");
    let (canonical_contribution, contribution_hash) = posture_body(9);
    let target = session_containment_target(&tenant(), &session())
        .unwrap_or_else(|error| panic!("session target: {error}"));
    let base = session_overlay_version_hash(store.as_ref(), &target)
        .unwrap_or_else(|error| panic!("base overlay version: {error}"));
    let plan = build_response_plan(ResponsePlanInput {
        action_id: action_id.clone(),
        trigger_finding_id: record("rollback-partial-finding"),
        trigger_finding_hash: digest(b"rollback-partial-finding"),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("rollback-partial-finding-receipt")
            .unwrap_or_else(|error| panic!("finding receipt: {error}")),
        tenant_id: tenant(),
        policy_version: record("rollback-partial-policy"),
        policy_hash: digest(b"rollback-partial-policy"),
        affected_ids: vec![record("session-active-defense-recovery")],
        effects: vec![ResponseEffectSpec {
            kind: ResponseEffectKind::SuspendSession,
            target: ResponseTarget::Session {
                session_id: session(),
            },
            canonical_contribution,
            contribution_hash,
            observed_base_version_hash: base,
        }],
        ttl_ms: POSTURE_TTL_MS,
        created_at_unix_ms: now,
        operator_capability: OperatorCapabilityBinding {
            capability_id: record("rollback-partial-operator-capability"),
            capability_digest: digest(b"rollback-partial-operator-capability"),
            expires_at_unix_ms: now.saturating_add(POSTURE_TTL_MS * 2),
            executor_subject: record("rollback-partial-executor"),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: record("rollback-partial-submitter"),
        reason_hash: digest(b"rollback-partial-reason"),
    })
    .unwrap_or_else(|error| panic!("build response plan: {error}"));
    let dispatch = prepare_response_dispatch(ResponseDispatchPreparationRequest {
        authorization_capability_hash: plan.operator_capability.capability_digest,
        plan: plan.clone(),
        dispatch_id: record("rollback-partial-dispatch"),
        governed_intent_hash: digest(b"rollback-partial-intent"),
        policy_decision_hash: digest(b"rollback-partial-decision"),
        executor_authority_id: record("rollback-partial-authority"),
        executor_authority_generation: 1,
        approval: ResponseDispatchApproval::Automatic,
        authorized_at_unix_ms: now,
        initial_lease: ResponseDispatchLease {
            lease_owner_id: LeaseOwnerId::new("rollback-partial-worker")
                .unwrap_or_else(|error| panic!("lease owner: {error}")),
            lease_expires_at_unix_ms: now.saturating_add(60_000),
        },
        commit_mode: chio_security_types::ports::ResponseDispatchCommitMode::Fresh,
    })
    .unwrap_or_else(|error| panic!("prepare response dispatch: {error}"));
    let outcome = store
        .commit_dispatch(&dispatch)
        .unwrap_or_else(|error| panic!("commit response dispatch: {error}"));
    let ResponseDispatchCommitOutcome::Committed(committed) = outcome else {
        panic!("rollback-partial response dispatch unexpectedly existed");
    };
    let machine = ResponseStateMachine::new(Arc::clone(&store));
    let work = committed.initial_work;
    let mut current = committed.response_plan;
    let planned_effect = decode_response_record(&current)
        .unwrap_or_else(|error| panic!("decode applying response: {error}"))
        .plan
        .effects
        .as_slice()[0]
        .clone();
    let apply = EffectRequest {
        tenant_id: tenant(),
        action_id: action_id.clone(),
        plan_hash: plan.plan_hash,
        effect_id: planned_effect.effect_id.clone(),
        effect_kind: planned_effect.kind,
        target: planned_effect.target.clone(),
        plan_expires_at_unix_ms: plan.expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record("response_effect_command:rollback-partial:apply"),
        expected_version_hash: planned_effect.observed_base_version_hash,
        scheduler_lease_owner_id: work.lease_owner_id.clone(),
        scheduler_fencing_token: work.fencing_token,
        canonical_contribution: planned_effect.canonical_contribution.clone(),
        contribution_hash: planned_effect.contribution_hash,
    };
    let overlays: Arc<dyn ContainmentOverlayStore> = store.clone();
    let backend = SessionSuspensionOverlayBackend::new(overlays);
    current = machine
        .record_effect_with_receipt_scheduled(
            &current,
            &work,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: planned_effect.effect_id.clone(),
                occurred_at_unix_ms: now.saturating_add(2),
                mutation: EffectMutation::Requested,
            },
            &EffectReceiptContext {
                effect_generation: 1,
                scheduler_lease_owner_id: Some(work.lease_owner_id.clone()),
                scheduler_fencing_token: work.fencing_token,
                effect_transition_id: None,
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|error| panic!("record apply intent: {error}"));
    let applied = backend
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply quarantine: {error}"));
    current = machine
        .record_effect_with_receipt_scheduled(
            &current,
            &work,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: planned_effect.effect_id.clone(),
                occurred_at_unix_ms: now.saturating_add(3),
                mutation: EffectMutation::Applied {
                    resulting_version_hash: applied.resulting_version_hash,
                },
            },
            &EffectReceiptContext {
                effect_generation: 2,
                scheduler_lease_owner_id: Some(work.lease_owner_id.clone()),
                scheduler_fencing_token: work.fencing_token,
                effect_transition_id: Some(record("rollback-partial-effect-applied")),
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|error| panic!("record applied quarantine: {error}"));
    current = machine
        .transition_scheduled(
            &current,
            &work,
            &ResponseTransitionRequest {
                expected_generation: current.generation,
                target_state: ResponseState::Active,
                occurred_at_unix_ms: now.saturating_add(4),
                applying_lease_expires_at_unix_ms: None,
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("activate quarantine: {error}"));
    assert_eq!(session_verdict(&store), Verdict::Deny);
    current = machine
        .transition_scheduled(
            &current,
            &work,
            &ResponseTransitionRequest {
                expected_generation: current.generation,
                target_state: ResponseState::RollingBack,
                occurred_at_unix_ms: now.saturating_add(5),
                applying_lease_expires_at_unix_ms: None,
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("begin rollback: {error}"));
    current = machine
        .record_effect_with_receipt_scheduled(
            &current,
            &work,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: planned_effect.effect_id.clone(),
                occurred_at_unix_ms: now.saturating_add(6),
                mutation: EffectMutation::RollbackRequested,
            },
            &EffectReceiptContext {
                effect_generation: 3,
                scheduler_lease_owner_id: Some(work.lease_owner_id.clone()),
                scheduler_fencing_token: work.fencing_token,
                effect_transition_id: Some(record("rollback-partial-rollback-requested")),
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|error| panic!("record rollback intent: {error}"));
    let mut failed_remove =
        remove_request(&apply, applied.resulting_version_hash, "rollback-partial");
    failed_remove.expected_version_hash = Digest32::new([99_u8; 32]);
    assert!(backend.execute(&failed_remove).is_err());
    current = machine
        .record_effect_with_receipt_scheduled(
            &current,
            &work,
            &EffectMutationRequest {
                expected_generation: current.generation,
                effect_id: planned_effect.effect_id,
                occurred_at_unix_ms: now.saturating_add(7),
                mutation: EffectMutation::RollbackFailed {
                    error_code: ErrorCode::new("response.rollback_failed")
                        .unwrap_or_else(|error| panic!("rollback error code: {error}")),
                },
            },
            &EffectReceiptContext {
                effect_generation: 4,
                scheduler_lease_owner_id: Some(work.lease_owner_id.clone()),
                scheduler_fencing_token: work.fencing_token,
                effect_transition_id: Some(record("rollback-partial-rollback-failed")),
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|error| panic!("record rollback failure: {error}"));
    current = machine
        .transition_scheduled(
            &current,
            &work,
            &ResponseTransitionRequest {
                expected_generation: current.generation,
                target_state: ResponseState::RollbackPartial,
                occurred_at_unix_ms: now.saturating_add(8),
                applying_lease_expires_at_unix_ms: None,
                error_code: Some(
                    ErrorCode::new("response.rollback_partial")
                        .unwrap_or_else(|error| panic!("rollback partial code: {error}")),
                ),
            },
        )
        .unwrap_or_else(|error| panic!("enter rollback partial: {error}"));
    let partial = decode_response_record(&current)
        .unwrap_or_else(|error| panic!("decode rollback partial: {error}"));
    assert_eq!(partial.state, ResponseState::RollbackPartial);
    assert!(partial.operator_page_required);
    assert_eq!(partial.generation, 8);
    assert_eq!(partial.mutations.len(), 9);
    let overlay = store
        .load_effective(&target)
        .unwrap_or_else(|error| panic!("load rollback partial overlay: {error}"))
        .unwrap_or_else(|| panic!("rollback partial overlay missing"));
    assert_eq!(overlay.generation, 1);
    assert_eq!(overlay.effective_posture_rank, 9);
    assert_eq!(overlay.active_contributions.len(), 1);
    assert_eq!(session_verdict(&store), Verdict::Deny);
}

#[test]
fn overlapping_temporary_actions_expire_in_both_orders_preserving_remaining_contribution() {
    for reverse in [false, true] {
        let directory = tempdir().unwrap_or_else(|error| panic!("temporary directory: {error}"));
        let first_action = action("overlap-first-action");
        let second_action = action("overlap-second-action");
        let actions = [first_action.clone(), second_action.clone()];
        let (store, work) =
            open_claimed_store(directory.path().join("overlap.db").as_path(), &actions);
        let target = session_containment_target(&tenant(), &session())
            .unwrap_or_else(|error| panic!("session target: {error}"));
        let overlays: Arc<dyn ContainmentOverlayStore> = store.clone();
        let backend = SessionSuspensionOverlayBackend::new(overlays);
        let expires_at = now_unix_ms().saturating_add(POSTURE_TTL_MS);

        let first = session_request(
            &first_action,
            &effect("overlap-first-effect"),
            3,
            session_overlay_version_hash(store.as_ref(), &target)
                .unwrap_or_else(|error| panic!("first base version: {error}")),
            work_for(&work, &first_action),
            expires_at,
            "overlap-first",
        );
        let first_result = backend
            .execute(&first)
            .unwrap_or_else(|error| panic!("apply first overlap: {error}"));
        let second = session_request(
            &second_action,
            &effect("overlap-second-effect"),
            8,
            session_overlay_version_hash(store.as_ref(), &target)
                .unwrap_or_else(|error| panic!("second base version: {error}")),
            work_for(&work, &second_action),
            expires_at,
            "overlap-second",
        );
        let second_result = backend
            .execute(&second)
            .unwrap_or_else(|error| panic!("apply second overlap: {error}"));
        let both = store
            .load_effective(&target)
            .unwrap_or_else(|error| panic!("load overlapping posture: {error}"))
            .unwrap_or_else(|| panic!("overlapping posture missing"));
        assert_eq!(both.generation, 2);
        assert_eq!(both.effective_posture_rank, 8);
        assert_eq!(both.active_contributions.len(), 2);

        let first_remove =
            remove_request(&first, first_result.resulting_version_hash, "overlap-first");
        let second_remove = remove_request(
            &second,
            second_result.resulting_version_hash,
            "overlap-second",
        );
        let (remove_one, remaining_effect, remaining_rank, remove_two) = if reverse {
            (&second_remove, &first.effect_id, 3, &first_remove)
        } else {
            (&first_remove, &second.effect_id, 8, &second_remove)
        };
        backend
            .execute(remove_one)
            .unwrap_or_else(|error| panic!("remove first-expiring overlap: {error}"));
        let remaining = store
            .load_effective(&target)
            .unwrap_or_else(|error| panic!("load remaining overlap: {error}"))
            .unwrap_or_else(|| panic!("remaining overlap missing"));
        assert_eq!(remaining.generation, 3);
        assert_eq!(remaining.effective_posture_rank, remaining_rank);
        assert_eq!(remaining.active_contributions.len(), 1);
        assert_eq!(
            &remaining.active_contributions.as_slice()[0].effect_id,
            remaining_effect
        );
        assert_eq!(session_verdict(&store), Verdict::Deny);

        backend
            .execute(remove_two)
            .unwrap_or_else(|error| panic!("remove last overlap: {error}"));
        let restored = store
            .load_effective(&target)
            .unwrap_or_else(|error| panic!("load restored overlap posture: {error}"))
            .unwrap_or_else(|| panic!("restored overlap posture missing"));
        assert_eq!(restored.generation, 4);
        assert_eq!(restored.effective_posture_rank, 0);
        assert!(restored.active_contributions.is_empty());
        assert_eq!(session_verdict(&store), Verdict::Allow);
    }
}

#[test]
fn exact_subtree_root_and_every_recorded_descendant_lift() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temporary directory: {error}"));
    let action_id = action("subtree-lift-action");
    let (store, work) = open_claimed_store(
        directory.path().join("subtree.db").as_path(),
        std::slice::from_ref(&action_id),
    );
    let affected_ids = RecordIdSet::new(vec![
        record("capability-child"),
        record("capability-grandchild"),
        record("capability-root"),
    ])
    .unwrap_or_else(|error| panic!("affected set: {error}"));
    let affected_set_hash = response_affected_set_hash(&tenant(), &affected_ids)
        .unwrap_or_else(|error| panic!("affected set hash: {error}"));
    let key = CapabilitySetSuspensionKey {
        tenant_id: tenant(),
        affected_set_hash,
    };
    let empty = empty_capability_set_suspension_snapshot(key.clone())
        .unwrap_or_else(|error| panic!("empty capability suspension: {error}"));
    let spec = CapabilitySetSuspensionSpec {
        affected_ids: affected_ids.clone(),
    };
    let contribution = canonical_json_bytes(&spec)
        .unwrap_or_else(|error| panic!("canonical capability suspension: {error}"));
    let work = work_for(&work, &action_id);
    let apply = EffectRequest {
        tenant_id: tenant(),
        action_id: action_id.clone(),
        plan_hash: digest(b"subtree-lift-plan"),
        effect_id: effect("subtree-lift-effect"),
        effect_kind: ResponseEffectKind::SuspendCapabilitySet,
        target: ResponseTarget::CapabilitySet { affected_set_hash },
        plan_expires_at_unix_ms: now_unix_ms().saturating_add(POSTURE_TTL_MS),
        operation: EffectOperation::Apply,
        idempotency_key: record("response_effect_command:subtree-lift:apply"),
        expected_version_hash: capability_set_suspension_version_hash(&empty)
            .unwrap_or_else(|error| panic!("empty suspension version: {error}")),
        scheduler_lease_owner_id: work.lease_owner_id.clone(),
        scheduler_fencing_token: work.fencing_token,
        canonical_contribution: CanonicalBody::new(contribution.clone())
            .unwrap_or_else(|error| panic!("capability suspension body: {error}")),
        contribution_hash: digest(&contribution),
    };
    let suspensions: Arc<dyn CapabilitySetSuspensionStore> = store.clone();
    let backend = CapabilitySetSuspensionBackend::new(suspensions);
    let applied = backend
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply exact subtree suspension: {error}"));
    let suspended = store
        .load_capability_set_suspensions(&key)
        .unwrap_or_else(|error| panic!("load exact subtree suspension: {error}"))
        .unwrap_or_else(|| panic!("exact subtree suspension missing"));
    assert_eq!(suspended.generation, 1);
    assert_eq!(suspended.contributions.len(), 1);
    for capability_id in affected_ids.as_slice() {
        let decision = store
            .evaluate_capability_suspension(&CapabilitySuspensionQuery {
                tenant_id: tenant(),
                capability_id: capability_id.clone(),
            })
            .unwrap_or_else(|error| panic!("evaluate suspended capability: {error}"));
        assert!(decision.denied, "recorded subtree member was not denied");
        assert_eq!(decision.active_matches.len(), 1);
    }

    let remove = remove_request(&apply, applied.resulting_version_hash, "subtree-lift");
    backend
        .execute(&remove)
        .unwrap_or_else(|error| panic!("lift exact subtree suspension: {error}"));
    let lifted = store
        .load_capability_set_suspensions(&key)
        .unwrap_or_else(|error| panic!("load lifted subtree suspension: {error}"))
        .unwrap_or_else(|| panic!("lifted subtree snapshot missing"));
    assert_eq!(lifted.generation, 2);
    assert!(lifted.contributions.is_empty());
    for capability_id in affected_ids.as_slice() {
        let decision = store
            .evaluate_capability_suspension(&CapabilitySuspensionQuery {
                tenant_id: tenant(),
                capability_id: capability_id.clone(),
            })
            .unwrap_or_else(|error| panic!("evaluate lifted capability: {error}"));
        assert!(!decision.denied, "recorded subtree member remained denied");
        assert!(decision.active_matches.is_empty());
    }
}
