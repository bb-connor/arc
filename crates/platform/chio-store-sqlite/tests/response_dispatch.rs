use chio_quarantine::{
    build_response_plan, decode_response_record, prepare_response_dispatch, EffectMutation,
    EffectMutationRequest, EffectReceiptContext, ResponseDispatchPreparationRequest,
    ResponseStateMachine, ResponseTransitionRequest,
};
use chio_security_types::ports::{
    ActionId, AutomaticResponseDispatchFenceOutcome, AutomaticResponseDispatchFenceRequest,
    CanonicalBody, CreateOutcome, Digest32, EffectId, ErrorCode, LeaseOwnerId, OpaqueReceiptRef,
    PortErrorKind, RecordId, ResponseDispatchApproval, ResponseDispatchCommitMode,
    ResponseDispatchCommitOutcome, ResponseDispatchKey, ResponseDispatchLease,
    ResponseDispatchLoadOutcome, ResponseDispatchRecoveryOutcome, ResponseDispatchRecoveryRequest,
    ResponseDispatchStore, ResponseEffectRecord, ResponsePlanKey, ResponsePlanRecord,
    ResponseReceiptCursor, ResponseReceiptCursorCasRequest, ResponseScheduledMutationCasRequest,
    ResponseSchedulerStore, ResponseStore, ScheduledWork, SchedulerClaimRequest,
    SchedulerLeaseReleaseRequest, SchedulerLeaseRenewRequest, SchedulerRetryRequest, SessionId,
    TenantId, PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind,
    ResponseEffectProgress, ResponseEffectSpec, ResponseMutationLog, ResponseMutationRecord,
    ResponsePlanInput, ResponseState, ResponseTarget,
};
use chio_store_sqlite::{security_state::SecurityStateClock, SqliteSecurityStateStore};
use std::sync::atomic::{AtomicU64, Ordering};
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

struct MutableSecurityStateClock(AtomicU64);

impl MutableSecurityStateClock {
    fn new(now_unix_ms: u64) -> Self {
        Self(AtomicU64::new(now_unix_ms))
    }

    fn set(&self, now_unix_ms: u64) {
        self.0.store(now_unix_ms, Ordering::Release);
    }
}

impl SecurityStateClock for MutableSecurityStateClock {
    fn now_unix_ms(&self) -> chio_security_types::ports::PortResult<u64> {
        Ok(self.0.load(Ordering::Acquire))
    }
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

const TERMINAL_RENEWAL_TEST_LEASE_MS: u64 = 3_600_000;

fn claim_due_planned_response(
    store: &Arc<SqliteSecurityStateStore>,
    action_id: &str,
    claim_id: &str,
    lease_owner_id: &str,
    now_unix_ms: u64,
) -> (ResponsePlanRecord, ScheduledWork) {
    let planned = ResponseStateMachine::new(Arc::clone(store))
        .create(response_plan_with_approval(
            action_id,
            now_unix_ms.saturating_sub(10_000),
            5_000,
            ResponseApprovalRequirement::Automatic,
        ))
        .unwrap_or_else(|error| panic!("response creation failed: {error}"));
    let work = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: planned.tenant_id.clone(),
            claim_id: record_id(claim_id),
            lease_owner_id: LeaseOwnerId::new(lease_owner_id)
                .unwrap_or_else(|error| panic!("invalid lease owner: {error}")),
            now_unix_ms,
            lease_expires_at_unix_ms: now_unix_ms.saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("response work claim failed: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("response work claim missing"));
    (planned, work)
}

fn terminalize_planned_response(
    machine: &ResponseStateMachine<SqliteSecurityStateStore>,
    planned: &ResponsePlanRecord,
    terminal_state: ResponseState,
) -> ResponsePlanRecord {
    let snapshot = decode_response_record(planned)
        .unwrap_or_else(|error| panic!("planned response decode failed: {error}"));
    let created_at_unix_ms = snapshot.plan.created_at_unix_ms;
    let transition = |current: &ResponsePlanRecord,
                      target_state: ResponseState,
                      occurred_at_unix_ms: u64,
                      applying_lease_expires_at_unix_ms: Option<u64>,
                      error_code: Option<ErrorCode>| {
        machine
            .transition(
                current,
                &ResponseTransitionRequest {
                    expected_generation: current.generation,
                    target_state,
                    occurred_at_unix_ms,
                    applying_lease_expires_at_unix_ms,
                    error_code,
                },
            )
            .unwrap_or_else(|error| panic!("response transition failed: {error}"))
    };
    match terminal_state {
        ResponseState::Cancelled => transition(
            planned,
            ResponseState::Cancelled,
            created_at_unix_ms.saturating_add(1),
            None,
            None,
        ),
        ResponseState::Expired => transition(
            planned,
            ResponseState::Expired,
            snapshot.plan.expires_at_unix_ms,
            None,
            None,
        ),
        ResponseState::Failed => transition(
            planned,
            ResponseState::Failed,
            created_at_unix_ms.saturating_add(1),
            None,
            Some(
                ErrorCode::new("response.terminal_renewal_test")
                    .unwrap_or_else(|error| panic!("terminal error code: {error}")),
            ),
        ),
        ResponseState::Lifted => {
            let applying = transition(
                planned,
                ResponseState::Applying,
                created_at_unix_ms.saturating_add(1),
                Some(created_at_unix_ms.saturating_add(100)),
                None,
            );
            let effect_id = snapshot.plan.effects.as_slice()[0].effect_id.clone();
            let requested = machine
                .record_effect(
                    &applying,
                    &EffectMutationRequest {
                        expected_generation: applying.generation,
                        effect_id: effect_id.clone(),
                        occurred_at_unix_ms: created_at_unix_ms.saturating_add(2),
                        mutation: EffectMutation::Requested,
                    },
                )
                .unwrap_or_else(|error| panic!("effect request failed: {error}"));
            let applied = machine
                .record_effect(
                    &requested,
                    &EffectMutationRequest {
                        expected_generation: requested.generation,
                        effect_id: effect_id.clone(),
                        occurred_at_unix_ms: created_at_unix_ms.saturating_add(3),
                        mutation: EffectMutation::Applied {
                            resulting_version_hash: digest(91),
                        },
                    },
                )
                .unwrap_or_else(|error| panic!("effect apply failed: {error}"));
            let active = transition(
                &applied,
                ResponseState::Active,
                created_at_unix_ms.saturating_add(4),
                None,
                None,
            );
            let rolling_back = transition(
                &active,
                ResponseState::RollingBack,
                created_at_unix_ms.saturating_add(5),
                None,
                None,
            );
            let rollback_requested = machine
                .record_effect(
                    &rolling_back,
                    &EffectMutationRequest {
                        expected_generation: rolling_back.generation,
                        effect_id: effect_id.clone(),
                        occurred_at_unix_ms: created_at_unix_ms.saturating_add(6),
                        mutation: EffectMutation::RollbackRequested,
                    },
                )
                .unwrap_or_else(|error| panic!("rollback request failed: {error}"));
            let restored = machine
                .record_effect(
                    &rollback_requested,
                    &EffectMutationRequest {
                        expected_generation: rollback_requested.generation,
                        effect_id,
                        occurred_at_unix_ms: created_at_unix_ms.saturating_add(7),
                        mutation: EffectMutation::RollbackRestored {
                            resulting_version_hash: digest(92),
                        },
                    },
                )
                .unwrap_or_else(|error| panic!("rollback restore failed: {error}"));
            transition(
                &restored,
                ResponseState::Lifted,
                created_at_unix_ms.saturating_add(8),
                None,
                None,
            )
        }
        _ => panic!("nonterminal response state supplied"),
    }
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
    let path = directory.path().join("scheduled-response-cas.db");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
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
    let renewed_transition_id = renewed_snapshot
        .mutations
        .as_slice()
        .last()
        .unwrap_or_else(|| panic!("renewed response mutation missing"))
        .transition_id()
        .clone();
    let renewed_replay_request = ResponseScheduledMutationCasRequest {
        work: work.clone(),
        current: applying.clone(),
        candidate: renewed.clone(),
        transition_id: renewed_transition_id,
    };
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
    assert_eq!(
        store
            .compare_and_swap_scheduled_mutation(&renewed_replay_request)
            .unwrap_or_else(|error| panic!("renewed mutation replay failed: {error}")),
        requested
    );
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
                effect_transition_id: Some(record_id("scheduled-rollback-requested")),
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

    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("scheduled replay corruption connection failed: {error}"));
    connection
        .execute(
            r#"
            UPDATE security_scheduler_leases
            SET lease_expires_at = lease_expires_at + 1
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![work.tenant_id.as_str(), work.action_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("scheduled replay lease corruption failed: {error}"));
    let corrupt_replay_error = rejected(
        store.compare_and_swap_scheduled_mutation(&renewed_replay_request),
        "corrupt-lease scheduled mutation replay unexpectedly succeeded",
    );
    assert_eq!(corrupt_replay_error.kind(), PortErrorKind::IntegrityFailure);
    connection
        .execute(
            r#"
            UPDATE security_scheduler_leases
            SET lease_expires_at = ?3
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![
                work.tenant_id.as_str(),
                work.action_id.as_str(),
                i64::try_from(work.lease_expires_at_unix_ms)
                    .unwrap_or_else(|error| panic!("lease expiry conversion failed: {error}"))
            ],
        )
        .unwrap_or_else(|error| panic!("scheduled replay lease repair failed: {error}"));
    store
        .release_lease(&SchedulerLeaseReleaseRequest {
            work,
            clear_retry_state: false,
            transition_id: record_id("scheduled-replay-terminal-release"),
        })
        .unwrap_or_else(|error| panic!("terminal scheduled lease release failed: {error}"));
    assert_eq!(
        store
            .compare_and_swap_scheduled_mutation(&renewed_replay_request)
            .unwrap_or_else(|error| panic!("released terminal replay failed: {error}")),
        lifted
    );
}

#[test]
fn terminal_response_work_rejects_scheduler_lease_renewal() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("terminal-work-renewal.db"))
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let machine = ResponseStateMachine::new(Arc::clone(&store));
    let terminal_states = [
        ResponseState::Cancelled,
        ResponseState::Expired,
        ResponseState::Failed,
        ResponseState::Lifted,
    ];
    assert!(terminal_states.into_iter().all(ResponseState::is_terminal));
    for (index, terminal_state) in terminal_states.into_iter().enumerate() {
        let action_id = format!("action-terminal-work-renewal-{index}");
        let claim_id = format!("terminal-work-claim-{index}");
        let lease_owner_id = format!("terminal-work-owner-{index}");
        let claim_now_unix_ms = now_unix_ms();
        let (planned, work) = claim_due_planned_response(
            &store,
            &action_id,
            &claim_id,
            &lease_owner_id,
            claim_now_unix_ms,
        );
        let terminal = terminalize_planned_response(&machine, &planned, terminal_state);
        assert_eq!(
            decode_response_record(&terminal)
                .unwrap_or_else(|error| panic!("terminal response decode failed: {error}"))
                .state,
            terminal_state
        );

        let renewal_now_unix_ms = now_unix_ms();
        let error = rejected(
            store.renew_lease(&SchedulerLeaseRenewRequest {
                work: work.clone(),
                now_unix_ms: renewal_now_unix_ms,
                lease_expires_at_unix_ms: work
                    .lease_expires_at_unix_ms
                    .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
                transition_id: record_id(&format!("terminal-work-renewal-{index}")),
            }),
            "terminal response work unexpectedly renewed",
        );
        assert_eq!(error.kind(), PortErrorKind::Conflict);
        store
            .validate_lease(&work)
            .unwrap_or_else(|error| panic!("terminal rejection changed the lease: {error}"));
    }

    let corrupt_path = directory.path().join("corrupt-work-renewal.db");
    let corrupt_store = Arc::new(
        SqliteSecurityStateStore::open(&corrupt_path)
            .unwrap_or_else(|error| panic!("corrupt security store open failed: {error}")),
    );
    let corrupt_claim_now_unix_ms = now_unix_ms();
    let (corrupt_plan, corrupt_work) = claim_due_planned_response(
        &corrupt_store,
        "action-corrupt-work-renewal",
        "corrupt-work-claim",
        "corrupt-work-owner",
        corrupt_claim_now_unix_ms,
    );
    let connection = rusqlite::Connection::open(&corrupt_path)
        .unwrap_or_else(|error| panic!("corrupt state connection failed: {error}"));
    connection
        .execute(
            "UPDATE security_response_plans SET state = 'active' WHERE tenant_id = ?1 AND action_id = ?2",
            rusqlite::params![
                corrupt_plan.tenant_id.as_str(),
                corrupt_plan.action_id.as_str()
            ],
        )
        .unwrap_or_else(|error| panic!("corrupt response state failed: {error}"));
    let state_renewal_now_unix_ms = now_unix_ms();
    let state_error = rejected(
        corrupt_store.renew_lease(&SchedulerLeaseRenewRequest {
            work: corrupt_work.clone(),
            now_unix_ms: state_renewal_now_unix_ms,
            lease_expires_at_unix_ms: corrupt_work
                .lease_expires_at_unix_ms
                .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
            transition_id: record_id("corrupt-state-work-renewal"),
        }),
        "state-corrupt response work unexpectedly renewed",
    );
    assert_eq!(state_error.kind(), PortErrorKind::IntegrityFailure);
    corrupt_store
        .validate_lease(&corrupt_work)
        .unwrap_or_else(|error| panic!("state rejection changed the lease: {error}"));

    let malformed_body = CanonicalBody::new(b"{}".to_vec())
        .unwrap_or_else(|error| panic!("malformed response body: {error}"));
    let malformed_hash = Digest32::new(*chio_core::sha256(malformed_body.as_bytes()).as_bytes());
    connection
        .execute(
            r#"
            UPDATE security_response_plans
            SET state = 'planned', body = ?3, body_hash = ?4
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![
                corrupt_plan.tenant_id.as_str(),
                corrupt_plan.action_id.as_str(),
                malformed_body.as_bytes(),
                malformed_hash.as_bytes().as_slice(),
            ],
        )
        .unwrap_or_else(|error| panic!("corrupt response body failed: {error}"));
    let body_renewal_now_unix_ms = now_unix_ms();
    let body_error = rejected(
        corrupt_store.renew_lease(&SchedulerLeaseRenewRequest {
            work: corrupt_work.clone(),
            now_unix_ms: body_renewal_now_unix_ms,
            lease_expires_at_unix_ms: corrupt_work
                .lease_expires_at_unix_ms
                .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
            transition_id: record_id("corrupt-body-work-renewal"),
        }),
        "body-corrupt response work unexpectedly renewed",
    );
    assert_eq!(body_error.kind(), PortErrorKind::IntegrityFailure);
    corrupt_store
        .validate_lease(&corrupt_work)
        .unwrap_or_else(|error| panic!("body rejection changed the lease: {error}"));
}

#[test]
fn corrupt_scheduler_lease_expiry_blocks_validation_effect_renew_retry_and_release() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("corrupt-work-provenance.db");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let claim_now_unix_ms = now_unix_ms();
    let (_, work) = claim_due_planned_response(
        &store,
        "action-corrupt-work-provenance",
        "corrupt-work-provenance-claim",
        "corrupt-work-provenance-owner",
        claim_now_unix_ms,
    );
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("corrupt provenance connection failed: {error}"));
    connection
        .execute(
            r#"
            UPDATE security_scheduler_leases
            SET lease_expires_at = lease_expires_at + 1
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![work.tenant_id.as_str(), work.action_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("corrupt lease provenance failed: {error}"));

    let identity_error = rejected(
        store.validate_lease_identity(
            &work.tenant_id,
            &work.action_id,
            &work.lease_owner_id,
            work.fencing_token,
        ),
        "expiry-corrupt scheduler identity unexpectedly validated",
    );
    assert_eq!(identity_error.kind(), PortErrorKind::IntegrityFailure);

    let effect_body = CanonicalBody::new(b"{}".to_vec())
        .unwrap_or_else(|error| panic!("effect body failed: {error}"));
    let effect_error = rejected(
        store.persist_effect(&ResponseEffectRecord {
            tenant_id: work.tenant_id.clone(),
            action_id: work.action_id.clone(),
            effect_id: EffectId::new("effect-corrupt-work-provenance")
                .unwrap_or_else(|error| panic!("effect id failed: {error}")),
            generation: 0,
            scheduler_lease_owner_id: work.lease_owner_id.clone(),
            scheduler_fencing_token: work.fencing_token,
            state: record_id("requested"),
            body_hash: Digest32::new(*chio_core::sha256(effect_body.as_bytes()).as_bytes()),
            canonical_body: effect_body,
            encrypted_rollback_ref: None,
        }),
        "expiry-corrupt scheduler lease unexpectedly authorized an effect",
    );
    assert_eq!(effect_error.kind(), PortErrorKind::IntegrityFailure);

    let renewal_now_unix_ms = now_unix_ms();
    let renewal_error = rejected(
        store.renew_lease(&SchedulerLeaseRenewRequest {
            work: work.clone(),
            now_unix_ms: renewal_now_unix_ms,
            lease_expires_at_unix_ms: work
                .lease_expires_at_unix_ms
                .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
            transition_id: record_id("corrupt-provenance-renewal"),
        }),
        "expiry-corrupt scheduler lease unexpectedly renewed",
    );
    assert_eq!(renewal_error.kind(), PortErrorKind::IntegrityFailure);

    let retry_now_unix_ms = now_unix_ms();
    let retry_error = rejected(
        store.record_retry(&SchedulerRetryRequest {
            work: work.clone(),
            expected_attempts: 0,
            error_code: ErrorCode::new("response.corrupt_provenance_test")
                .unwrap_or_else(|error| panic!("retry error code failed: {error}")),
            first_failure_at_unix_ms: retry_now_unix_ms,
            now_unix_ms: retry_now_unix_ms,
            not_before_unix_ms: retry_now_unix_ms.saturating_add(60_000),
            health_event_id: None,
            transition_id: record_id("corrupt-provenance-retry"),
        }),
        "expiry-corrupt scheduler lease unexpectedly recorded a retry",
    );
    assert_eq!(retry_error.kind(), PortErrorKind::IntegrityFailure);

    let release_error = rejected(
        store.release_lease(&SchedulerLeaseReleaseRequest {
            work: work.clone(),
            clear_retry_state: true,
            transition_id: record_id("corrupt-provenance-release"),
        }),
        "expiry-corrupt scheduler lease unexpectedly released",
    );
    assert_eq!(release_error.kind(), PortErrorKind::IntegrityFailure);

    let durable = connection
        .query_row(
            r#"
            SELECT claim_ordinal, lease_owner_id, lease_expires_at, fencing_token,
                   (SELECT COUNT(*) FROM security_scheduler_retries
                    WHERE tenant_id = ?1 AND action_id = ?2),
                   (SELECT COUNT(*) FROM security_response_effects
                    WHERE tenant_id = ?1 AND action_id = ?2),
                   (SELECT COUNT(*) FROM security_transitions
                    WHERE tenant_id = ?1
                      AND transition_id IN (
                          'corrupt-provenance-renewal',
                          'corrupt-provenance-retry',
                          'corrupt-provenance-release'
                      ))
            FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![work.tenant_id.as_str(), work.action_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("corrupt provenance readback failed: {error}"));
    assert_eq!(durable.0, 0);
    assert_eq!(durable.1, work.lease_owner_id.as_str());
    assert_eq!(
        u64::try_from(durable.2)
            .unwrap_or_else(|error| panic!("lease expiry conversion failed: {error}")),
        work.lease_expires_at_unix_ms.saturating_add(1)
    );
    assert_eq!(
        u64::try_from(durable.3)
            .unwrap_or_else(|error| panic!("fencing token conversion failed: {error}")),
        work.fencing_token
    );
    assert_eq!((durable.4, durable.5, durable.6), (0, 0, 0));
}

#[test]
fn scheduler_renewal_replay_rejects_corrupt_lease_provenance() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory
        .path()
        .join("corrupt-renewal-replay-provenance.db");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let claim_now_unix_ms = now_unix_ms();
    let (_, work) = claim_due_planned_response(
        &store,
        "action-corrupt-renewal-replay",
        "corrupt-renewal-replay-claim",
        "corrupt-renewal-replay-owner",
        claim_now_unix_ms,
    );
    let request = SchedulerLeaseRenewRequest {
        work: work.clone(),
        now_unix_ms: now_unix_ms(),
        lease_expires_at_unix_ms: work
            .lease_expires_at_unix_ms
            .saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
        transition_id: record_id("corrupt-renewal-replay-transition"),
    };
    let renewed = store
        .renew_lease(&request)
        .unwrap_or_else(|error| panic!("initial renewal failed: {error}"));
    assert_eq!(
        renewed.lease_expires_at_unix_ms,
        request.lease_expires_at_unix_ms
    );

    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("renewal replay connection failed: {error}"));
    connection
        .execute(
            r#"
            UPDATE security_scheduler_leases
            SET claim_ordinal = 1
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![work.tenant_id.as_str(), work.action_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("corrupt renewed lease provenance failed: {error}"));

    let replay_error = rejected(
        store.renew_lease(&request),
        "provenance-corrupt renewal replay unexpectedly succeeded",
    );
    assert_eq!(replay_error.kind(), PortErrorKind::IntegrityFailure);
    let durable = connection
        .query_row(
            r#"
            SELECT claim_ordinal, lease_expires_at,
                   (SELECT COUNT(*) FROM security_transitions
                    WHERE tenant_id = ?1
                      AND transition_id = 'corrupt-renewal-replay-transition')
            FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![work.tenant_id.as_str(), work.action_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("renewal replay readback failed: {error}"));
    assert_eq!(durable.0, 1);
    assert_eq!(
        u64::try_from(durable.1)
            .unwrap_or_else(|error| panic!("renewed expiry conversion failed: {error}")),
        renewed.lease_expires_at_unix_ms
    );
    assert_eq!(durable.2, 1);
}

#[test]
fn scheduler_claim_replay_rejects_corrupt_lease_provenance() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("corrupt-claim-replay-provenance.db");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let claim_now_unix_ms = now_unix_ms();
    let claim_id = "corrupt-claim-replay-claim";
    let lease_owner_id = "corrupt-claim-replay-owner";
    let (planned, work) = claim_due_planned_response(
        &store,
        "action-corrupt-claim-replay",
        claim_id,
        lease_owner_id,
        claim_now_unix_ms,
    );
    let request = SchedulerClaimRequest {
        tenant_id: planned.tenant_id,
        claim_id: record_id(claim_id),
        lease_owner_id: LeaseOwnerId::new(lease_owner_id)
            .unwrap_or_else(|error| panic!("lease owner failed: {error}")),
        now_unix_ms: claim_now_unix_ms,
        lease_expires_at_unix_ms: claim_now_unix_ms.saturating_add(TERMINAL_RENEWAL_TEST_LEASE_MS),
        max_claims: 1,
    };
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("claim replay connection failed: {error}"));
    connection
        .execute(
            r#"
            UPDATE security_scheduler_leases
            SET claim_ordinal = 1
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![work.tenant_id.as_str(), work.action_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("corrupt claimed lease provenance failed: {error}"));

    let replay_error = rejected(
        store.claim_due(&request),
        "provenance-corrupt claim replay unexpectedly succeeded",
    );
    assert_eq!(replay_error.kind(), PortErrorKind::IntegrityFailure);
    let durable = connection
        .query_row(
            r#"
            SELECT claim_ordinal, lease_expires_at, fencing_token,
                   (SELECT COUNT(*) FROM security_scheduler_claims
                    WHERE tenant_id = ?1 AND claim_id = ?3)
            FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![
                work.tenant_id.as_str(),
                work.action_id.as_str(),
                request.claim_id.as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("claim replay readback failed: {error}"));
    assert_eq!(durable.0, 1);
    assert_eq!(
        u64::try_from(durable.1)
            .unwrap_or_else(|error| panic!("claim expiry conversion failed: {error}")),
        work.lease_expires_at_unix_ms
    );
    assert_eq!(
        u64::try_from(durable.2)
            .unwrap_or_else(|error| panic!("claim token conversion failed: {error}")),
        work.fencing_token
    );
    assert_eq!(durable.3, 1);
}

#[test]
fn scheduler_claim_replay_rejects_a_missing_claim_row() {
    let directory = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("missing-claim-replay.db");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("security store open failed: {error}")),
    );
    let claim_now_unix_ms = now_unix_ms();
    let claim_id = "missing-claim-replay-claim";
    let lease_owner_id = "missing-claim-replay-owner";
    let (planned, work) = claim_due_planned_response(
        &store,
        "action-missing-claim-replay",
        claim_id,
        lease_owner_id,
        claim_now_unix_ms,
    );
    let request = SchedulerClaimRequest {
        tenant_id: planned.tenant_id,
        claim_id: record_id(claim_id),
        lease_owner_id: LeaseOwnerId::new(lease_owner_id)
            .unwrap_or_else(|error| panic!("lease owner failed: {error}")),
        now_unix_ms: claim_now_unix_ms,
        lease_expires_at_unix_ms: work.lease_expires_at_unix_ms,
        max_claims: 1,
    };
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("missing claim replay connection failed: {error}"));
    let deleted = connection
        .execute(
            "DELETE FROM security_scheduler_claims WHERE tenant_id = ?1 AND claim_id = ?2",
            rusqlite::params![request.tenant_id.as_str(), request.claim_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("delete scheduler claim failed: {error}"));
    assert_eq!(deleted, 1);

    let replay_error = rejected(
        store.claim_due(&request),
        "missing-row scheduler claim replay unexpectedly succeeded",
    );
    assert_eq!(replay_error.kind(), PortErrorKind::IntegrityFailure);
    let durable = connection
        .query_row(
            r#"
            SELECT claim_id, claim_ordinal, lease_owner_id,
                   lease_expires_at, fencing_token,
                   (SELECT COUNT(*) FROM security_scheduler_claims
                    WHERE tenant_id = ?1 AND claim_id = ?3)
            FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![
                work.tenant_id.as_str(),
                work.action_id.as_str(),
                request.claim_id.as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("missing claim replay readback failed: {error}"));
    assert_eq!(durable.0, request.claim_id.as_str());
    assert_eq!(durable.1, 0);
    assert_eq!(durable.2, work.lease_owner_id.as_str());
    assert_eq!(
        u64::try_from(durable.3)
            .unwrap_or_else(|error| panic!("claim expiry conversion failed: {error}")),
        work.lease_expires_at_unix_ms
    );
    assert_eq!(
        u64::try_from(durable.4)
            .unwrap_or_else(|error| panic!("claim token conversion failed: {error}")),
        work.fencing_token
    );
    assert_eq!(durable.5, 0);
}

include!("response_dispatch_tail.inc");
