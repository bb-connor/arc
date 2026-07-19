use chio_quarantine::{
    build_response_plan, decode_response_record, prepare_response_dispatch, EffectMutation,
    EffectMutationRequest, EffectReceiptContext, ResponseDispatchPreparationRequest,
    ResponseStateMachine, ResponseTransitionRequest,
};
use chio_security_types::ports::{
    ActionId, AutomaticResponseDispatchFenceOutcome, AutomaticResponseDispatchFenceRequest,
    CanonicalBody, CreateOutcome, Digest32, LeaseOwnerId, OpaqueReceiptRef, PortErrorKind,
    RecordId, ResponseDispatchApproval, ResponseDispatchCommitMode, ResponseDispatchCommitOutcome,
    ResponseDispatchKey, ResponseDispatchLease, ResponseDispatchLoadOutcome,
    ResponseDispatchRecoveryOutcome, ResponseDispatchRecoveryRequest, ResponseDispatchStore,
    ResponsePlanKey, ResponsePlanRecord, ResponseReceiptCursor, ResponseReceiptCursorCasRequest,
    ResponseScheduledMutationCasRequest, ResponseSchedulerStore, ResponseStore,
    SchedulerClaimRequest, SchedulerLeaseReleaseRequest, SchedulerLeaseRenewRequest, SessionId,
    TenantId, PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind,
    ResponseEffectProgress, ResponseEffectSpec, ResponseMutationLog, ResponseMutationRecord,
    ResponsePlanInput, ResponseState, ResponseTarget,
};
use chio_store_sqlite::SqliteSecurityStateStore;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("system clock is before the epoch: {error}"))
        .as_millis()
        .try_into()
        .unwrap_or_else(|error| panic!("system clock exceeds u64 milliseconds: {error}"))
}

fn digest(value: u8) -> Digest32 {
    Digest32::new([value; 32])
}

fn record_id(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("invalid record id: {error}"))
}

fn rejected<T, E>(result: Result<T, E>, message: &str) -> E {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

fn rewrite_last_scheduler_fence(
    record: &ResponsePlanRecord,
    lease_owner_id: Option<LeaseOwnerId>,
    fencing_token: Option<u64>,
) -> (ResponsePlanRecord, RecordId) {
    let mut snapshot = decode_response_record(record)
        .unwrap_or_else(|error| panic!("candidate response decode failed: {error}"));
    let mut mutations = snapshot.mutations.into_vec();
    let last = mutations
        .last_mut()
        .unwrap_or_else(|| panic!("candidate response has no mutations"));
    let transition_id = last.transition_id().clone();
    match last {
        ResponseMutationRecord::Transition(mutation) => {
            mutation.scheduler_lease_owner_id = lease_owner_id;
            mutation.scheduler_fencing_token = fencing_token;
        }
        ResponseMutationRecord::EffectRequested(mutation) => {
            mutation.scheduler_lease_owner_id = lease_owner_id;
            mutation.scheduler_fencing_token = fencing_token.unwrap_or(0);
        }
        ResponseMutationRecord::EffectApplied(mutation) => {
            mutation.scheduler_lease_owner_id = lease_owner_id;
            mutation.scheduler_fencing_token = fencing_token.unwrap_or(0);
        }
        ResponseMutationRecord::EffectFailed(mutation) => {
            mutation.scheduler_lease_owner_id = lease_owner_id;
            mutation.scheduler_fencing_token = fencing_token.unwrap_or(0);
        }
        ResponseMutationRecord::Rollback(mutation) => {
            mutation.scheduler_lease_owner_id = lease_owner_id;
            mutation.scheduler_fencing_token = fencing_token.unwrap_or(0);
        }
        ResponseMutationRecord::Failed(mutation) => {
            mutation.scheduler_lease_owner_id = lease_owner_id;
            mutation.scheduler_fencing_token = fencing_token;
        }
        ResponseMutationRecord::Final(mutation) => {
            mutation.scheduler_lease_owner_id = lease_owner_id;
            mutation.scheduler_fencing_token = fencing_token;
        }
        ResponseMutationRecord::Requested(_) => {
            panic!("requested response mutation has no scheduler fence")
        }
    }
    snapshot.mutations = ResponseMutationLog::new(mutations)
        .unwrap_or_else(|error| panic!("candidate mutation log failed: {error}"));
    let bytes = chio_core::canonical_json_bytes(&snapshot)
        .unwrap_or_else(|error| panic!("candidate canonicalization failed: {error}"));
    let canonical_body = CanonicalBody::new(bytes)
        .unwrap_or_else(|error| panic!("candidate canonical body failed: {error}"));
    let body_hash = Digest32::new(*chio_core::sha256(canonical_body.as_bytes()).as_bytes());
    (
        ResponsePlanRecord {
            canonical_body,
            body_hash,
            ..record.clone()
        },
        transition_id,
    )
}

fn response_plan_with_approval(
    action: &str,
    created_at_unix_ms: u64,
    ttl_ms: u64,
    approval_requirement: ResponseApprovalRequirement,
) -> chio_security_types::ResponsePlan {
    response_plan_for_tenant_with_approval(
        "tenant-dispatch",
        action,
        created_at_unix_ms,
        ttl_ms,
        approval_requirement,
    )
}

fn response_plan_for_tenant_with_approval(
    tenant: &str,
    action: &str,
    created_at_unix_ms: u64,
    ttl_ms: u64,
    approval_requirement: ResponseApprovalRequirement,
) -> chio_security_types::ResponsePlan {
    let canonical_contribution = CanonicalBody::new(b"{\"posture_rank\":3}".to_vec())
        .unwrap_or_else(|error| panic!("invalid contribution body: {error}"));
    let contribution_hash =
        Digest32::new(*chio_core::sha256(canonical_contribution.as_bytes()).as_bytes());
    build_response_plan(ResponsePlanInput {
        action_id: ActionId::new(action)
            .unwrap_or_else(|error| panic!("invalid action id: {error}")),
        trigger_finding_id: record_id("finding-dispatch"),
        trigger_finding_hash: digest(31),
        trigger_finding_receipt_id: chio_security_types::ports::OpaqueReceiptRef::new(
            "finding-dispatch-receipt",
        )
        .unwrap_or_else(|error| panic!("invalid finding receipt id: {error}")),
        tenant_id: TenantId::new(tenant)
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
        ttl_ms,
        created_at_unix_ms,
        operator_capability: OperatorCapabilityBinding {
            capability_id: record_id("capability-dispatch"),
            capability_digest: digest(30),
            expires_at_unix_ms: created_at_unix_ms + 30_000,
            executor_subject: record_id("executor-subject"),
        },
        approval_requirement,
        submitter: record_id("submitter-dispatch"),
        reason_hash: digest(31),
    })
    .unwrap_or_else(|error| panic!("response plan build failed: {error}"))
}

fn dispatch_request(
    action: &str,
    dispatch_id: &str,
    created_at_unix_ms: u64,
    authorized_at_unix_ms: u64,
    lease_expires_at_unix_ms: u64,
) -> chio_security_types::ports::ResponseDispatchCommitRequest {
    dispatch_request_for_tenant(
        "tenant-dispatch",
        action,
        dispatch_id,
        created_at_unix_ms,
        authorized_at_unix_ms,
        lease_expires_at_unix_ms,
    )
}

fn dispatch_request_for_tenant(
    tenant: &str,
    action: &str,
    dispatch_id: &str,
    created_at_unix_ms: u64,
    authorized_at_unix_ms: u64,
    lease_expires_at_unix_ms: u64,
) -> chio_security_types::ports::ResponseDispatchCommitRequest {
    prepare_response_dispatch(ResponseDispatchPreparationRequest {
        plan: response_plan_for_tenant_with_approval(
            tenant,
            action,
            created_at_unix_ms,
            20_000,
            ResponseApprovalRequirement::Automatic,
        ),
        dispatch_id: record_id(dispatch_id),
        authorization_capability_hash: digest(30),
        governed_intent_hash: digest(32),
        policy_decision_hash: digest(33),
        executor_authority_id: record_id("executor-authority"),
        executor_authority_generation: 4,
        approval: ResponseDispatchApproval::Automatic,
        authorized_at_unix_ms,
        initial_lease: ResponseDispatchLease {
            lease_owner_id: LeaseOwnerId::new("response-worker")
                .unwrap_or_else(|error| panic!("invalid lease owner: {error}")),
            lease_expires_at_unix_ms,
        },
        commit_mode: chio_security_types::ports::ResponseDispatchCommitMode::Fresh,
    })
    .unwrap_or_else(|error| panic!("response dispatch preparation failed: {error}"))
}

fn automatic_fence_request(
    request: &chio_security_types::ports::ResponseDispatchCommitRequest,
) -> AutomaticResponseDispatchFenceRequest {
    let snapshot = decode_response_record(&request.response_plan)
        .unwrap_or_else(|error| panic!("response plan decode failed: {error}"));
    AutomaticResponseDispatchFenceRequest {
        response_plan: snapshot.plan,
        prepared_dispatch_binding:
            chio_security_types::ports::PreparedActiveResponseDispatchBinding {
                schema_version: PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
                tenant_id: request.authorization.body.key.tenant_id.clone(),
                action_id: request.authorization.body.action_id.clone(),
                plan_hash: request.authorization.body.plan_hash,
                dispatch_id: request.authorization.body.key.dispatch_id.clone(),
                executor_authority_id: request.authorization.body.executor_authority_id.clone(),
                executor_authority_generation: request
                    .authorization
                    .body
                    .executor_authority_generation,
                authorized_at_unix_ms: request.authorization.body.authorized_at_unix_ms,
                authorization_capability_hash: request
                    .authorization
                    .body
                    .authorization_capability_hash,
                governed_intent_hash: request.authorization.body.governed_intent_hash,
                policy_decision_hash: request.authorization.body.policy_decision_hash,
                approval: request.authorization.body.approval.clone(),
            },
    }
}

fn race_dispatch_commit_and_fence(
    path: &std::path::Path,
    dispatch: &chio_security_types::ports::ResponseDispatchCommitRequest,
) -> (
    chio_security_types::ports::PortResult<ResponseDispatchCommitOutcome>,
    chio_security_types::ports::PortResult<AutomaticResponseDispatchFenceOutcome>,
) {
    let commit_store = SqliteSecurityStateStore::open(path)
        .unwrap_or_else(|error| panic!("commit-race store open failed: {error}"));
    let fence_store = SqliteSecurityStateStore::open(path)
        .unwrap_or_else(|error| panic!("fence-race store open failed: {error}"));
    let start = Arc::new(Barrier::new(3));
    let commit_start = Arc::clone(&start);
    let commit_request = dispatch.clone();
    let commit_thread = thread::spawn(move || {
        commit_start.wait();
        commit_store.commit_dispatch(&commit_request)
    });
    let fence_start = Arc::clone(&start);
    let fence_request = automatic_fence_request(dispatch);
    let fence_thread = thread::spawn(move || {
        fence_start.wait();
        fence_store.fence_uncommitted_automatic_dispatch(&fence_request)
    });

    start.wait();
    let commit_result = commit_thread
        .join()
        .unwrap_or_else(|_| panic!("dispatch commit race thread panicked"));
    let fence_result = fence_thread
        .join()
        .unwrap_or_else(|_| panic!("dispatch fence race thread panicked"));
    (commit_result, fence_result)
}

fn durable_dispatch_fence_counts(
    path: &std::path::Path,
    dispatch: &chio_security_types::ports::ResponseDispatchCommitRequest,
) -> (i64, i64) {
    let connection = rusqlite::Connection::open(path)
        .unwrap_or_else(|error| panic!("durable race readback open failed: {error}"));
    let authorization = &dispatch.authorization.body;
    let dispatch_count = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM security_response_dispatches
            WHERE tenant_id = ?1 AND action_id = ?2 AND dispatch_id = ?3
            "#,
            rusqlite::params![
                authorization.key.tenant_id.as_str(),
                authorization.action_id.as_str(),
                authorization.key.dispatch_id.as_str(),
            ],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or_else(|error| panic!("durable dispatch count failed: {error}"));
    let fence_count = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM security_response_dispatch_fences
            WHERE tenant_id = ?1 AND action_id = ?2 AND dispatch_id = ?3
            "#,
            rusqlite::params![
                authorization.key.tenant_id.as_str(),
                authorization.action_id.as_str(),
                authorization.key.dispatch_id.as_str(),
            ],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or_else(|error| panic!("durable fence count failed: {error}"));
    (dispatch_count, fence_count)
}

#[test]
fn atomic_dispatch_is_idempotent_bound_and_recoverable_after_crash() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("response-dispatch.db");
    let created_at_unix_ms = now_unix_ms();
    let authorized_at_unix_ms = created_at_unix_ms;
    let initial_lease_expires_at_unix_ms = created_at_unix_ms + 2_000;
    let request = dispatch_request(
        "action-dispatch",
        "active-response-dispatch",
        created_at_unix_ms,
        authorized_at_unix_ms,
        initial_lease_expires_at_unix_ms,
    );
    let key = request.authorization.body.key.clone();

    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    store
        .ensure_dispatch_ready()
        .unwrap_or_else(|error| panic!("dispatch store is not ready: {error}"));
    let committed = store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("dispatch commit failed: {error}"));
    let ResponseDispatchCommitOutcome::Committed(committed_record) = committed else {
        panic!("first dispatch commit did not report committed");
    };
    assert_eq!(committed_record.authorization, request.authorization);
    assert_eq!(committed_record.response_plan, request.response_plan);
    assert_eq!(
        committed_record.initial_work.lease_owner_id,
        request.initial_lease.lease_owner_id
    );
    assert_eq!(
        committed_record.initial_work.lease_expires_at_unix_ms,
        initial_lease_expires_at_unix_ms
    );
    assert!(committed_record.initial_work.fencing_token > 0);
    store
        .validate_lease(&committed_record.initial_work)
        .unwrap_or_else(|error| panic!("initial scheduler lease is not live: {error}"));
    assert_eq!(
        store
            .load_plan(&ResponsePlanKey {
                tenant_id: key.tenant_id.clone(),
                action_id: request.authorization.body.action_id.clone(),
            })
            .unwrap_or_else(|error| panic!("response plan load failed: {error}")),
        Some(request.response_plan.clone())
    );
    assert_eq!(
        store
            .load_dispatch(&key)
            .unwrap_or_else(|error| panic!("dispatch load failed: {error}")),
        ResponseDispatchLoadOutcome::Found(Box::new(committed_record.clone()))
    );

    let duplicate = store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("idempotent dispatch retry failed: {error}"));
    assert_eq!(
        duplicate,
        ResponseDispatchCommitOutcome::Existing(committed_record.clone())
    );

    let colliding = dispatch_request(
        "action-collision",
        "active-response-dispatch",
        created_at_unix_ms,
        authorized_at_unix_ms,
        initial_lease_expires_at_unix_ms,
    );
    let collision_error = match store.commit_dispatch(&colliding) {
        Ok(_) => panic!("dispatch binding collision unexpectedly committed"),
        Err(error) => error,
    };
    assert_eq!(collision_error.kind(), PortErrorKind::Conflict);
    assert!(store
        .load_plan(&ResponsePlanKey {
            tenant_id: key.tenant_id.clone(),
            action_id: colliding.authorization.body.action_id.clone(),
        })
        .unwrap_or_else(|error| panic!("colliding action lookup failed: {error}"))
        .is_none());

    let initial_fencing_token = committed_record.initial_work.fencing_token;
    drop(store);
    let sleep_ms = initial_lease_expires_at_unix_ms
        .saturating_sub(now_unix_ms())
        .saturating_add(50);
    thread::sleep(Duration::from_millis(sleep_ms));

    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store reopen failed: {error}"));
    assert_eq!(
        reopened
            .load_dispatch(&key)
            .unwrap_or_else(|error| panic!("reopened dispatch load failed: {error}")),
        ResponseDispatchLoadOutcome::Found(Box::new(committed_record))
    );
    let takeover_now = now_unix_ms();
    let claimed = reopened
        .claim_due(&SchedulerClaimRequest {
            tenant_id: key.tenant_id.clone(),
            claim_id: record_id("recovery-claim"),
            lease_owner_id: LeaseOwnerId::new("recovery-worker")
                .unwrap_or_else(|error| panic!("invalid recovery owner: {error}")),
            now_unix_ms: takeover_now,
            lease_expires_at_unix_ms: takeover_now + 5_000,
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("expired dispatch lease claim failed: {error}"));
    assert!(claimed.is_empty());

    let recovered = reopened
        .recover_dispatch_work(&ResponseDispatchRecoveryRequest {
            key,
            action_id: request.authorization.body.action_id,
            recovery_id: record_id("recovery-after-scheduler-ack-loss"),
            lease_owner_id: LeaseOwnerId::new("replacement-recovery-worker")
                .unwrap_or_else(|error| panic!("invalid replacement owner: {error}")),
            expected_fencing_token: Some(initial_fencing_token),
            now_unix_ms: takeover_now,
            lease_expires_at_unix_ms: takeover_now + 7_000,
        })
        .unwrap_or_else(|error| panic!("exact dispatch recovery failed: {error}"));
    let ResponseDispatchRecoveryOutcome::Takeover(recovered_work) = recovered else {
        panic!("expired exact dispatch recovery returned the stale live lease");
    };
    assert!(recovered_work.fencing_token > initial_fencing_token);
    reopened
        .validate_lease(&recovered_work)
        .unwrap_or_else(|error| panic!("recovered exact dispatch lease is invalid: {error}"));
}

#[test]
fn scheduled_response_cas_sequences_one_fence_and_rejects_forged_mutation_fences() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("scheduled-response-cas.db"))
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let created_at_unix_ms = now_unix_ms();
    let request = dispatch_request(
        "action-scheduled-response-cas",
        "dispatch-scheduled-response-cas",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms.saturating_add(5_000),
    );
    let committed = store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("dispatch commit failed: {error}"));
    let ResponseDispatchCommitOutcome::Committed(committed) = committed else {
        panic!("first dispatch unexpectedly existed");
    };
    let renewal_now = now_unix_ms();
    let work = store
        .renew_lease(&SchedulerLeaseRenewRequest {
            work: committed.initial_work.clone(),
            transition_id: record_id("scheduled-response-work-renewal"),
            now_unix_ms: renewal_now,
            lease_expires_at_unix_ms: created_at_unix_ms.saturating_add(15_000),
        })
        .unwrap_or_else(|error| panic!("scheduler work renewal failed: {error}"));
    let machine = ResponseStateMachine::new(Arc::clone(&store));
    let applying = committed.response_plan;
    let renewed = machine
        .renew_applying_lease(&applying, &work, renewal_now)
        .unwrap_or_else(|error| panic!("response applying lease renewal failed: {error}"));
    let foreign_owner = LeaseOwnerId::new("forged-scheduler-owner")
        .unwrap_or_else(|error| panic!("invalid forged scheduler owner: {error}"));

    let assert_forged_fence_rejected = |current: &ResponsePlanRecord,
                                        valid_candidate: &ResponsePlanRecord,
                                        owner: Option<LeaseOwnerId>,
                                        token: Option<u64>| {
        let (candidate, transition_id) =
            rewrite_last_scheduler_fence(valid_candidate, owner, token);
        assert!(store
            .compare_and_swap_scheduled_mutation(&ResponseScheduledMutationCasRequest {
                work: work.clone(),
                current: current.clone(),
                candidate,
                transition_id,
            })
            .is_err());
    };

    assert_forged_fence_rejected(
        &applying,
        &renewed,
        Some(foreign_owner.clone()),
        Some(work.fencing_token),
    );
    assert_forged_fence_rejected(&applying, &renewed, None, None);
    assert_forged_fence_rejected(
        &applying,
        &renewed,
        Some(work.lease_owner_id.clone()),
        Some(0),
    );

    let renewed_snapshot = decode_response_record(&renewed)
        .unwrap_or_else(|error| panic!("renewed response decode failed: {error}"));
    let effect_id = renewed_snapshot.plan.effects.as_slice()[0]
        .effect_id
        .clone();
    let requested = machine
        .record_effect_with_receipt_scheduled(
            &renewed,
            &work,
            &EffectMutationRequest {
                expected_generation: renewed.generation,
                effect_id: effect_id.clone(),
                occurred_at_unix_ms: renewal_now.saturating_add(1),
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
        .unwrap_or_else(|error| panic!("effect request failed: {error}"));
    assert_forged_fence_rejected(
        &renewed,
        &requested,
        Some(foreign_owner.clone()),
        Some(work.fencing_token),
    );
    assert_forged_fence_rejected(&renewed, &requested, None, Some(work.fencing_token));

    let applied = machine
        .record_effect_with_receipt_scheduled(
            &requested,
            &work,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id: effect_id.clone(),
                occurred_at_unix_ms: renewal_now.saturating_add(2),
                mutation: EffectMutation::Applied {
                    resulting_version_hash: digest(81),
                },
            },
            &EffectReceiptContext {
                effect_generation: 2,
                scheduler_lease_owner_id: Some(work.lease_owner_id.clone()),
                scheduler_fencing_token: work.fencing_token,
                effect_transition_id: Some(record_id("scheduled-effect-applied")),
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|error| panic!("effect result failed: {error}"));
    assert_forged_fence_rejected(
        &requested,
        &applied,
        Some(foreign_owner.clone()),
        Some(work.fencing_token),
    );
    assert_forged_fence_rejected(&requested, &applied, None, Some(work.fencing_token));

    let active = machine
        .transition_scheduled(
            &applied,
            &work,
            &ResponseTransitionRequest {
                expected_generation: applied.generation,
                target_state: ResponseState::Active,
                occurred_at_unix_ms: renewal_now.saturating_add(3),
                applying_lease_expires_at_unix_ms: None,
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("response activation failed: {error}"));
    let rolling_back = machine
        .transition_scheduled(
            &active,
            &work,
            &ResponseTransitionRequest {
                expected_generation: active.generation,
                target_state: ResponseState::RollingBack,
                occurred_at_unix_ms: renewal_now.saturating_add(4),
                applying_lease_expires_at_unix_ms: None,
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("rollback transition failed: {error}"));
    let rollback_requested = machine
        .record_effect_with_receipt_scheduled(
            &rolling_back,
            &work,
            &EffectMutationRequest {
                expected_generation: rolling_back.generation,
                effect_id: effect_id.clone(),
                occurred_at_unix_ms: renewal_now.saturating_add(5),
                mutation: EffectMutation::RollbackRequested,
            },
            &EffectReceiptContext {
                effect_generation: 3,
                scheduler_lease_owner_id: Some(work.lease_owner_id.clone()),
                scheduler_fencing_token: work.fencing_token,
                effect_transition_id: None,
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|error| panic!("rollback request failed: {error}"));
    let restored = machine
        .record_effect_with_receipt_scheduled(
            &rollback_requested,
            &work,
            &EffectMutationRequest {
                expected_generation: rollback_requested.generation,
                effect_id,
                occurred_at_unix_ms: renewal_now.saturating_add(6),
                mutation: EffectMutation::RollbackRestored {
                    resulting_version_hash: digest(82),
                },
            },
            &EffectReceiptContext {
                effect_generation: 4,
                scheduler_lease_owner_id: Some(work.lease_owner_id.clone()),
                scheduler_fencing_token: work.fencing_token,
                effect_transition_id: Some(record_id("scheduled-effect-restored")),
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|error| panic!("rollback result failed: {error}"));
    let lifted = machine
        .transition_scheduled(
            &restored,
            &work,
            &ResponseTransitionRequest {
                expected_generation: restored.generation,
                target_state: ResponseState::Lifted,
                occurred_at_unix_ms: renewal_now.saturating_add(7),
                applying_lease_expires_at_unix_ms: None,
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("response finalization failed: {error}"));
    assert_forged_fence_rejected(
        &restored,
        &lifted,
        Some(foreign_owner),
        Some(work.fencing_token),
    );
    assert_forged_fence_rejected(&restored, &lifted, None, None);
    assert_eq!(
        decode_response_record(&lifted)
            .unwrap_or_else(|error| panic!("lifted response decode failed: {error}"))
            .state,
        ResponseState::Lifted
    );
}

#[test]
fn automatic_dispatch_fence_wins_before_commit() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("fence-wins.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-fence-wins",
        "dispatch-fence-wins",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let fence = automatic_fence_request(&dispatch);
    let outcome = store
        .fence_uncommitted_automatic_dispatch(&fence)
        .unwrap_or_else(|error| panic!("automatic dispatch fence failed: {error}"));
    assert!(matches!(
        outcome,
        AutomaticResponseDispatchFenceOutcome::Fenced(_)
    ));

    let error = rejected(
        store.commit_dispatch(&dispatch),
        "fenced automatic dispatch commit must fail",
    );
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    assert_eq!(
        store
            .load_dispatch(&dispatch.authorization.body.key)
            .unwrap_or_else(|error| panic!("fenced dispatch load failed: {error}")),
        ResponseDispatchLoadOutcome::Missing
    );
}

#[test]
fn automatic_dispatch_commit_wins_before_fence() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("commit-wins.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-commit-wins",
        "dispatch-commit-wins",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let committed = match store
        .commit_dispatch(&dispatch)
        .unwrap_or_else(|error| panic!("dispatch commit failed: {error}"))
    {
        ResponseDispatchCommitOutcome::Committed(record) => record,
        ResponseDispatchCommitOutcome::Existing(_) => {
            panic!("first dispatch commit unexpectedly existed")
        }
    };
    let outcome = store
        .fence_uncommitted_automatic_dispatch(&automatic_fence_request(&dispatch))
        .unwrap_or_else(|error| panic!("automatic dispatch fence lookup failed: {error}"));
    assert_eq!(
        outcome,
        AutomaticResponseDispatchFenceOutcome::Committed(Box::new(committed))
    );
}

#[test]
fn simultaneous_two_handle_commit_and_fence_preserve_durable_exclusivity() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("simultaneous-commit-fence.db");
    let bootstrap = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store bootstrap failed: {error}"));
    drop(bootstrap);
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-simultaneous-commit-fence",
        "dispatch-simultaneous-commit-fence",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let fence_request = automatic_fence_request(&dispatch);

    let (commit_result, fence_result) = race_dispatch_commit_and_fence(&path, &dispatch);
    let commit_won = match (commit_result, fence_result) {
        (
            Ok(ResponseDispatchCommitOutcome::Committed(committed)),
            Ok(AutomaticResponseDispatchFenceOutcome::Committed(observed)),
        ) => {
            assert_eq!(observed, Box::new(committed));
            true
        }
        (
            Err(commit_error),
            Ok(AutomaticResponseDispatchFenceOutcome::Fenced(fenced)),
        ) => {
            assert_eq!(commit_error.kind(), PortErrorKind::Conflict);
            assert_eq!(
                fenced.prepared_dispatch_binding,
                fence_request.prepared_dispatch_binding
            );
            false
        }
        (unexpected_commit, unexpected_fence) => panic!(
            "simultaneous dispatch race produced an invalid result pair: commit={unexpected_commit:?}, fence={unexpected_fence:?}"
        ),
    };

    assert_eq!(
        durable_dispatch_fence_counts(&path, &dispatch),
        if commit_won { (1, 0) } else { (0, 1) }
    );
    let verifier = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store verifier open failed: {error}"));
    verifier
        .ensure_dispatch_ready()
        .unwrap_or_else(|error| panic!("exclusive race result is not ready: {error}"));
}

#[test]
fn durable_fence_winner_survives_simultaneous_two_handle_retries() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("durable-fence-winner-race.db");
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-durable-fence-winner",
        "dispatch-durable-fence-winner",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let fence_request = automatic_fence_request(&dispatch);
    let seed_store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store seed open failed: {error}"));
    assert!(matches!(
        seed_store
            .fence_uncommitted_automatic_dispatch(&fence_request)
            .unwrap_or_else(|error| panic!("durable fence seed failed: {error}")),
        AutomaticResponseDispatchFenceOutcome::Fenced(_)
    ));
    drop(seed_store);

    let (commit_result, fence_result) = race_dispatch_commit_and_fence(&path, &dispatch);
    let commit_error = rejected(
        commit_result,
        "durable fence winner must reject the competing commit",
    );
    assert_eq!(commit_error.kind(), PortErrorKind::Conflict);
    let AutomaticResponseDispatchFenceOutcome::ExistingFence(existing) =
        fence_result.unwrap_or_else(|error| panic!("durable fence retry failed: {error}"))
    else {
        panic!("durable fence retry did not recover the existing fence");
    };
    assert_eq!(
        existing.prepared_dispatch_binding,
        fence_request.prepared_dispatch_binding
    );
    assert_eq!(durable_dispatch_fence_counts(&path, &dispatch), (0, 1));
}

#[test]
fn durable_commit_winner_survives_simultaneous_two_handle_retries() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("durable-commit-winner-race.db");
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-durable-commit-winner",
        "dispatch-durable-commit-winner",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let seed_store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store seed open failed: {error}"));
    let committed = match seed_store
        .commit_dispatch(&dispatch)
        .unwrap_or_else(|error| panic!("durable commit seed failed: {error}"))
    {
        ResponseDispatchCommitOutcome::Committed(record) => record,
        ResponseDispatchCommitOutcome::Existing(_) => {
            panic!("first durable commit unexpectedly existed")
        }
    };
    drop(seed_store);

    let (commit_result, fence_result) = race_dispatch_commit_and_fence(&path, &dispatch);
    let ResponseDispatchCommitOutcome::Existing(existing) =
        commit_result.unwrap_or_else(|error| panic!("durable commit retry failed: {error}"))
    else {
        panic!("durable commit retry did not recover the existing dispatch");
    };
    assert_eq!(existing, committed);
    let AutomaticResponseDispatchFenceOutcome::Committed(observed) = fence_result
        .unwrap_or_else(|error| panic!("durable commit fence readback failed: {error}"))
    else {
        panic!("fence did not recover the durable committed dispatch");
    };
    assert_eq!(observed, Box::new(committed));
    assert_eq!(durable_dispatch_fence_counts(&path, &dispatch), (1, 0));
}

#[test]
fn automatic_dispatch_fence_rejects_alternate_id_for_same_action() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("alternate-id.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let created_at_unix_ms = now_unix_ms();
    let first = dispatch_request(
        "action-alternate-id",
        "dispatch-alternate-id-first",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let alternate = dispatch_request(
        "action-alternate-id",
        "dispatch-alternate-id-second",
        created_at_unix_ms,
        created_at_unix_ms + 1,
        created_at_unix_ms + 10_000,
    );
    store
        .fence_uncommitted_automatic_dispatch(&automatic_fence_request(&first))
        .unwrap_or_else(|error| panic!("first automatic dispatch fence failed: {error}"));

    let error = rejected(
        store.fence_uncommitted_automatic_dispatch(&automatic_fence_request(&alternate)),
        "alternate dispatch identifier must not replace the existing fence",
    );
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    assert_eq!(
        rejected(
            store.commit_dispatch(&alternate),
            "alternate dispatch commit must remain fenced",
        )
        .kind(),
        PortErrorKind::Conflict
    );
}

#[test]
fn automatic_dispatch_fences_are_tenant_independent() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("tenant-fences.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let created_at_unix_ms = now_unix_ms();
    for tenant in ["tenant-fence-one", "tenant-fence-two"] {
        let dispatch = dispatch_request_for_tenant(
            tenant,
            "action-shared-fence",
            "dispatch-shared-fence",
            created_at_unix_ms,
            created_at_unix_ms,
            created_at_unix_ms + 10_000,
        );
        let outcome = store
            .fence_uncommitted_automatic_dispatch(&automatic_fence_request(&dispatch))
            .unwrap_or_else(|error| panic!("tenant automatic dispatch fence failed: {error}"));
        assert!(matches!(
            outcome,
            AutomaticResponseDispatchFenceOutcome::Fenced(_)
        ));
    }
}

#[test]
fn automatic_dispatch_fence_retry_recovers_after_persisted_result_is_lost() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("persisted-fence-retry.db");
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-persisted-fence",
        "dispatch-persisted-fence",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let request = automatic_fence_request(&dispatch);
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let _lost_result = store
        .fence_uncommitted_automatic_dispatch(&request)
        .unwrap_or_else(|error| panic!("automatic dispatch fence failed: {error}"));
    drop(store);

    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store reopen failed: {error}"));
    let retried = reopened
        .fence_uncommitted_automatic_dispatch(&request)
        .unwrap_or_else(|error| panic!("automatic dispatch fence retry failed: {error}"));
    assert!(matches!(
        retried,
        AutomaticResponseDispatchFenceOutcome::ExistingFence(_)
    ));
    assert_eq!(
        rejected(
            reopened.commit_dispatch(&dispatch),
            "reopened automatic dispatch commit must remain fenced",
        )
        .kind(),
        PortErrorKind::Conflict
    );
}

#[test]
fn automatic_dispatch_fence_retry_rejects_corrupt_persisted_hash() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("corrupt-persisted-fence-hash.db");
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-corrupt-fence-hash",
        "dispatch-corrupt-fence-hash",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let request = automatic_fence_request(&dispatch);
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    store
        .fence_uncommitted_automatic_dispatch(&request)
        .unwrap_or_else(|error| panic!("automatic dispatch fence failed: {error}"));
    drop(store);

    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("raw sqlite open failed: {error}"));
    connection
        .execute(
            "UPDATE security_response_dispatch_fences SET prepared_binding_hash = zeroblob(32)",
            [],
        )
        .unwrap_or_else(|error| panic!("fence hash corruption failed: {error}"));
    drop(connection);

    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store reopen failed: {error}"));
    let error = rejected(
        reopened.fence_uncommitted_automatic_dispatch(&request),
        "corrupt persisted fence hash must fail",
    );
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn dispatch_readiness_rejects_canonical_but_invalid_fence_binding() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("invalid-persisted-fence-binding.db");
    let created_at_unix_ms = now_unix_ms();
    let dispatch = dispatch_request(
        "action-invalid-fence-binding",
        "dispatch-invalid-fence-binding",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let request = automatic_fence_request(&dispatch);
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    store
        .fence_uncommitted_automatic_dispatch(&request)
        .unwrap_or_else(|error| panic!("automatic dispatch fence failed: {error}"));
    drop(store);

    let mut invalid_binding = request.prepared_dispatch_binding.clone();
    invalid_binding.governed_intent_hash = Digest32::new([0_u8; 32]);
    let body = chio_core::canonical_json_bytes(&invalid_binding)
        .unwrap_or_else(|error| panic!("invalid fence binding canonicalization failed: {error}"));
    let hash = chio_core::sha256(&body);
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("raw sqlite open failed: {error}"));
    connection
        .execute(
            "UPDATE security_response_dispatch_fences SET prepared_binding_body = ?1, prepared_binding_hash = ?2",
            rusqlite::params![body, hash.as_bytes().as_slice()],
        )
        .unwrap_or_else(|error| panic!("fence binding corruption failed: {error}"));
    drop(connection);

    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store reopen failed: {error}"));
    let error = rejected(
        reopened.ensure_dispatch_ready(),
        "invalid persisted fence binding must fail readiness",
    );
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn load_dispatch_reports_missing_explicitly() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("missing-dispatch.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let key = ResponseDispatchKey {
        tenant_id: TenantId::new("tenant-dispatch")
            .unwrap_or_else(|error| panic!("invalid tenant id: {error}")),
        dispatch_id: record_id("missing-dispatch"),
    };
    assert_eq!(
        store
            .load_dispatch(&key)
            .unwrap_or_else(|error| panic!("missing dispatch load failed: {error}")),
        ResponseDispatchLoadOutcome::Missing
    );
}

#[test]
fn historical_governed_commit_is_unclaimable_until_zero_effect_terminalization() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("historical-dispatch.db"))
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let trusted_now = now_unix_ms();
    let created_at_unix_ms = trusted_now.saturating_sub(10_000);
    let plan = response_plan_with_approval(
        "action-historical-dispatch",
        created_at_unix_ms,
        1_000,
        ResponseApprovalRequirement::Governed {
            policy_id: record_id("historical-dispatch-policy"),
        },
    );
    let request = prepare_response_dispatch(ResponseDispatchPreparationRequest {
        plan: plan.clone(),
        dispatch_id: record_id("historical-governed-dispatch"),
        authorization_capability_hash: digest(30),
        governed_intent_hash: digest(32),
        policy_decision_hash: digest(33),
        executor_authority_id: record_id("executor-authority"),
        executor_authority_generation: 4,
        approval: ResponseDispatchApproval::Governed {
            admission_operation_id: record_id("historical-admission-operation"),
            admission_operation_version: 1,
            approval_set_hash: digest(34),
        },
        authorized_at_unix_ms: created_at_unix_ms,
        initial_lease: ResponseDispatchLease {
            lease_owner_id: LeaseOwnerId::new("historical-response-worker")
                .unwrap_or_else(|error| panic!("invalid lease owner: {error}")),
            lease_expires_at_unix_ms: plan.expires_at_unix_ms,
        },
        commit_mode: ResponseDispatchCommitMode::GovernedCommittedExpiredResume,
    })
    .unwrap_or_else(|error| panic!("historical dispatch preparation failed: {error}"));
    let committed = store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("historical dispatch commit failed: {error}"));
    let committed_record = match committed {
        ResponseDispatchCommitOutcome::Committed(record) => record,
        ResponseDispatchCommitOutcome::Existing(_) => {
            panic!("first historical dispatch unexpectedly existed")
        }
    };

    let claims = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: plan.tenant_id.clone(),
            claim_id: record_id("historical-dispatch-claim"),
            lease_owner_id: LeaseOwnerId::new("historical-scheduler")
                .unwrap_or_else(|error| panic!("invalid scheduler owner: {error}")),
            now_unix_ms: trusted_now,
            lease_expires_at_unix_ms: trusted_now.saturating_add(5_000),
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("historical dispatch claim failed: {error}"));
    assert!(claims.is_empty());

    let recovered = store
        .recover_dispatch_work(&ResponseDispatchRecoveryRequest {
            key: request.authorization.body.key.clone(),
            action_id: plan.action_id.clone(),
            recovery_id: record_id("historical-dispatch-recovery"),
            lease_owner_id: LeaseOwnerId::new("historical-recovery-worker")
                .unwrap_or_else(|error| panic!("invalid recovery owner: {error}")),
            expected_fencing_token: Some(committed_record.initial_work.fencing_token),
            now_unix_ms: trusted_now,
            lease_expires_at_unix_ms: trusted_now.saturating_add(5_000),
        })
        .unwrap_or_else(|error| panic!("historical dispatch recovery failed: {error}"));
    let recovery_work = match recovered {
        ResponseDispatchRecoveryOutcome::LiveLease(work)
        | ResponseDispatchRecoveryOutcome::Takeover(work) => work,
    };

    let key = ResponsePlanKey {
        tenant_id: plan.tenant_id.clone(),
        action_id: plan.action_id.clone(),
    };
    let current = store
        .load_plan(&key)
        .unwrap_or_else(|error| panic!("historical response load failed: {error}"))
        .unwrap_or_else(|| panic!("historical response is missing"));
    let failed = ResponseStateMachine::new(Arc::clone(&store))
        .fail_expired_dispatch_committed_resume_scheduled(
            &current,
            &recovery_work,
            current.generation,
            trusted_now,
        )
        .unwrap_or_else(|error| panic!("historical response terminalization failed: {error}"));
    let snapshot = decode_response_record(&failed)
        .unwrap_or_else(|error| panic!("historical response decode failed: {error}"));
    assert_eq!(snapshot.state, ResponseState::Failed);
    assert!(plan.effects.as_slice().iter().all(|effect| {
        snapshot.effect_progress(&effect.effect_id) == Some(ResponseEffectProgress::Planned)
    }));
}

#[test]
fn live_dispatch_recovery_rejects_unfenced_wrong_owner_and_stale_fencing_token() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let created_at_unix_ms = now_unix_ms();
    let request = dispatch_request(
        "action-live-recovery-binding",
        "active-response-live-recovery-binding",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let store = SqliteSecurityStateStore::open(directory.path().join("recovery-binding.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let initial_work = match store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("dispatch commit failed: {error}"))
    {
        ResponseDispatchCommitOutcome::Committed(record) => record.initial_work,
        ResponseDispatchCommitOutcome::Existing(_) => {
            panic!("first bound recovery dispatch unexpectedly existed")
        }
    };
    let base = ResponseDispatchRecoveryRequest {
        key: request.authorization.body.key.clone(),
        action_id: request.authorization.body.action_id.clone(),
        recovery_id: record_id("bound-live-recovery"),
        lease_owner_id: initial_work.lease_owner_id.clone(),
        expected_fencing_token: Some(initial_work.fencing_token),
        now_unix_ms: created_at_unix_ms,
        lease_expires_at_unix_ms: initial_work.lease_expires_at_unix_ms,
    };

    let mut unfenced = base.clone();
    unfenced.recovery_id = record_id("unfenced-live-recovery");
    unfenced.expected_fencing_token = None;
    let unfenced_error = match store.recover_dispatch_work(&unfenced) {
        Ok(_) => panic!("unfenced live recovery unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(unfenced_error.kind(), PortErrorKind::InvalidData);

    let mut wrong_owner = base.clone();
    wrong_owner.recovery_id = record_id("wrong-owner-live-recovery");
    wrong_owner.lease_owner_id = LeaseOwnerId::new("different-response-worker")
        .unwrap_or_else(|error| panic!("invalid wrong lease owner: {error}"));
    let wrong_owner_error = match store.recover_dispatch_work(&wrong_owner) {
        Ok(_) => panic!("wrong-owner live recovery unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(wrong_owner_error.kind(), PortErrorKind::Conflict);

    let mut stale_fence = base;
    stale_fence.recovery_id = record_id("stale-fence-live-recovery");
    stale_fence.expected_fencing_token = Some(initial_work.fencing_token.saturating_add(1));
    let stale_fence_error = match store.recover_dispatch_work(&stale_fence) {
        Ok(_) => panic!("stale-fence live recovery unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(stale_fence_error.kind(), PortErrorKind::Conflict);
}

#[test]
fn exact_dispatch_recovery_is_live_idempotent_and_fenced_after_restart() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("response-recovery.db");
    let created_at_unix_ms = now_unix_ms();
    let initial_lease_expires_at_unix_ms = created_at_unix_ms + 2_000;
    let request = dispatch_request(
        "action-recovery",
        "active-response-recovery",
        created_at_unix_ms,
        created_at_unix_ms,
        initial_lease_expires_at_unix_ms,
    );
    let key = request.authorization.body.key.clone();
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let committed = store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("dispatch commit failed: {error}"));
    let initial_work = match committed {
        ResponseDispatchCommitOutcome::Committed(record) => record.initial_work,
        ResponseDispatchCommitOutcome::Existing(_) => {
            panic!("first recovery dispatch unexpectedly existed")
        }
    };
    let live_request = ResponseDispatchRecoveryRequest {
        key: key.clone(),
        action_id: request.authorization.body.action_id.clone(),
        recovery_id: record_id("recovery-live"),
        lease_owner_id: initial_work.lease_owner_id.clone(),
        expected_fencing_token: Some(initial_work.fencing_token),
        now_unix_ms: now_unix_ms(),
        lease_expires_at_unix_ms: initial_work.lease_expires_at_unix_ms,
    };
    let live = store
        .recover_dispatch_work(&live_request)
        .unwrap_or_else(|error| panic!("live lease recovery failed: {error}"));
    assert_eq!(
        live,
        ResponseDispatchRecoveryOutcome::LiveLease(initial_work.clone())
    );
    assert_eq!(
        store
            .recover_dispatch_work(&live_request)
            .unwrap_or_else(|error| panic!("ack-loss live recovery retry failed: {error}")),
        live
    );

    let mut mismatched_retry = live_request.clone();
    mismatched_retry.action_id =
        ActionId::new("action-wrong").unwrap_or_else(|error| panic!("invalid action id: {error}"));
    let mismatch = match store.recover_dispatch_work(&mismatched_retry) {
        Ok(_) => panic!("mismatched recovery retry unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(mismatch.kind(), PortErrorKind::Conflict);

    drop(store);
    let sleep_ms = initial_lease_expires_at_unix_ms
        .saturating_sub(now_unix_ms())
        .saturating_add(50);
    thread::sleep(Duration::from_millis(sleep_ms));

    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store reopen failed: {error}"));
    let takeover_now = now_unix_ms();
    let takeover_request = ResponseDispatchRecoveryRequest {
        key,
        action_id: request.authorization.body.action_id,
        recovery_id: record_id("recovery-takeover"),
        lease_owner_id: LeaseOwnerId::new("recovery-worker")
            .unwrap_or_else(|error| panic!("invalid recovery owner: {error}")),
        expected_fencing_token: Some(initial_work.fencing_token),
        now_unix_ms: takeover_now,
        lease_expires_at_unix_ms: takeover_now + 5_000,
    };
    let takeover = reopened
        .recover_dispatch_work(&takeover_request)
        .unwrap_or_else(|error| panic!("expired lease takeover failed: {error}"));
    let takeover_work = match &takeover {
        ResponseDispatchRecoveryOutcome::Takeover(work) => work,
        ResponseDispatchRecoveryOutcome::LiveLease(_) => {
            panic!("expired lease recovery returned the stale live lease")
        }
    };
    assert!(takeover_work.fencing_token > initial_work.fencing_token);
    assert_eq!(
        takeover_work.lease_owner_id,
        takeover_request.lease_owner_id
    );
    assert_eq!(
        reopened
            .recover_dispatch_work(&takeover_request)
            .unwrap_or_else(|error| panic!("ack-loss takeover retry failed: {error}")),
        takeover
    );

    let mut stale = takeover_request;
    stale.recovery_id = record_id("recovery-stale-fence");
    let stale_error = match reopened.recover_dispatch_work(&stale) {
        Ok(_) => panic!("stale fencing recovery unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(stale_error.kind(), PortErrorKind::Conflict);
}

#[test]
fn dispatch_recovery_rejects_non_due_work_without_a_live_lease() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let created_at_unix_ms = now_unix_ms();
    let request = dispatch_request(
        "action-not-due",
        "active-response-not-due",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let store = SqliteSecurityStateStore::open(directory.path().join("not-due.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    let initial_work = match store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("dispatch commit failed: {error}"))
    {
        ResponseDispatchCommitOutcome::Committed(record) => record.initial_work,
        ResponseDispatchCommitOutcome::Existing(_) => {
            panic!("first not-due dispatch unexpectedly existed")
        }
    };
    store
        .release_lease(&SchedulerLeaseReleaseRequest {
            work: initial_work.clone(),
            clear_retry_state: false,
            transition_id: record_id("release-before-due"),
        })
        .unwrap_or_else(|error| panic!("initial lease release failed: {error}"));
    let recovery_now = now_unix_ms();
    let recovery = ResponseDispatchRecoveryRequest {
        key: request.authorization.body.key,
        action_id: request.authorization.body.action_id,
        recovery_id: record_id("recovery-before-due"),
        lease_owner_id: LeaseOwnerId::new("early-recovery-worker")
            .unwrap_or_else(|error| panic!("invalid recovery owner: {error}")),
        expected_fencing_token: Some(initial_work.fencing_token),
        now_unix_ms: recovery_now,
        lease_expires_at_unix_ms: recovery_now + 5_000,
    };
    let error = match store.recover_dispatch_work(&recovery) {
        Ok(_) => panic!("non-due recovery unexpectedly allocated work"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), PortErrorKind::Conflict);
}

#[test]
fn response_receipt_cursor_is_plan_bound_and_exactly_cas_idempotent() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let created_at_unix_ms = now_unix_ms();
    let request = dispatch_request(
        "action-receipt-cursor",
        "active-response-receipt-cursor",
        created_at_unix_ms,
        created_at_unix_ms,
        created_at_unix_ms + 10_000,
    );
    let store = SqliteSecurityStateStore::open(directory.path().join("receipt-cursor.db"))
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("dispatch commit failed: {error}"));
    let snapshot = decode_response_record(&request.response_plan)
        .unwrap_or_else(|error| panic!("response plan decode failed: {error}"));
    let key = ResponsePlanKey {
        tenant_id: snapshot.plan.tenant_id.clone(),
        action_id: snapshot.plan.action_id.clone(),
    };
    let initial = ResponseReceiptCursor {
        tenant_id: key.tenant_id.clone(),
        action_id: key.action_id.clone(),
        plan_hash: snapshot.plan.plan_hash,
        generation: 0,
        current_evidence_id: snapshot.plan.trigger_finding_receipt_id.clone(),
    };
    let mut wrong_plan = initial.clone();
    wrong_plan.plan_hash = digest(99);
    let wrong_plan_error = match store.initialize_receipt_cursor(&wrong_plan) {
        Ok(_) => panic!("wrong-plan receipt cursor unexpectedly initialized"),
        Err(error) => error,
    };
    assert_eq!(wrong_plan_error.kind(), PortErrorKind::InvalidData);
    assert_eq!(
        store
            .initialize_receipt_cursor(&initial)
            .unwrap_or_else(|error| panic!("receipt cursor initialization failed: {error}")),
        CreateOutcome::Created
    );
    assert_eq!(
        store
            .initialize_receipt_cursor(&initial)
            .unwrap_or_else(|error| panic!("receipt cursor replay failed: {error}")),
        CreateOutcome::Existing
    );

    let next = ResponseReceiptCursor {
        generation: 1,
        current_evidence_id: OpaqueReceiptRef::new("response-plan-evidence")
            .unwrap_or_else(|error| panic!("invalid response evidence id: {error}")),
        ..initial.clone()
    };
    let transition_id = record_id("receipt-cursor-transition");
    let valid = ResponseReceiptCursorCasRequest {
        cursor: next.clone(),
        expected_generation: 0,
        expected_evidence_id: initial.current_evidence_id.clone(),
        transition_id: transition_id.clone(),
    };
    let mut wrong_prior = valid.clone();
    wrong_prior.expected_evidence_id = OpaqueReceiptRef::new("wrong-prior-evidence")
        .unwrap_or_else(|error| panic!("invalid wrong evidence id: {error}"));
    let wrong_prior_error = match store.compare_and_swap_receipt_cursor(&wrong_prior) {
        Ok(_) => panic!("wrong-prior receipt cursor CAS unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(wrong_prior_error.kind(), PortErrorKind::Conflict);
    assert_eq!(
        store
            .compare_and_swap_receipt_cursor(&valid)
            .unwrap_or_else(|error| panic!("receipt cursor CAS failed: {error}")),
        next
    );
    assert_eq!(
        store
            .compare_and_swap_receipt_cursor(&valid)
            .unwrap_or_else(|error| panic!("receipt cursor CAS replay failed: {error}")),
        next
    );
    assert_eq!(
        store
            .load_receipt_cursor(&key)
            .unwrap_or_else(|error| panic!("receipt cursor load failed: {error}")),
        Some(next)
    );
}

#[test]
fn dispatch_readiness_rejects_a_corrupt_schema() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("corrupt-dispatch-schema.db");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store open failed: {error}"));
    store
        .ensure_dispatch_ready()
        .unwrap_or_else(|error| panic!("fresh dispatch schema is not ready: {error}"));
    drop(store);

    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("raw sqlite open failed: {error}"));
    connection
        .execute_batch(
            "DROP TABLE security_response_dispatches;
             CREATE TABLE security_response_dispatches (broken TEXT);",
        )
        .unwrap_or_else(|error| panic!("dispatch schema corruption failed: {error}"));
    drop(connection);

    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("security store reopen failed: {error}"));
    assert!(reopened.ensure_dispatch_ready().is_err());
}
