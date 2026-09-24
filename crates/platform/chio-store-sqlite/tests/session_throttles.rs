use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_security_types::ports::{
    empty_session_throttle_snapshot, predict_session_throttle_apply,
    predict_session_throttle_remove, session_throttle_installed_version_hash,
    session_throttle_version_hash, ActionId, CanonicalBody, Digest32, EffectExecutionStatus,
    EffectId, EffectOperation, EffectRequest, EffectResult, EffectResultQuery, LeaseOwnerId,
    PortError, PortErrorKind, RecordId, ResponsePlanRecord, ResponseStore, ScheduledWork,
    SchedulerClaimRequest, SessionId, SessionThrottleApplyRequest, SessionThrottleCommand,
    SessionThrottleConsumeRequest, SessionThrottleContribution, SessionThrottleKey,
    SessionThrottleLimits, SessionThrottleRemoveRequest, SessionThrottleSnapshot,
    SessionThrottleStore, TenantId,
};
use chio_security_types::{ResponseEffectKind, ResponseTarget};
use chio_store_sqlite::SqliteSecurityStateStore;
use tempfile::tempdir;

fn now_unix_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("clock before epoch: {error}"));
    u64::try_from(elapsed.as_millis()).unwrap_or_else(|error| panic!("clock range: {error}"))
}

fn digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(bytes).as_bytes())
}

fn tenant() -> TenantId {
    TenantId::new("tenant-throttle").unwrap_or_else(|error| panic!("tenant id: {error}"))
}

fn session() -> SessionId {
    SessionId::new("session-throttle").unwrap_or_else(|error| panic!("session id: {error}"))
}

fn key() -> SessionThrottleKey {
    SessionThrottleKey {
        tenant_id: tenant(),
        session_id: session(),
    }
}

fn action(value: &str) -> ActionId {
    ActionId::new(value).unwrap_or_else(|error| panic!("action id: {error}"))
}

fn effect(value: &str) -> EffectId {
    EffectId::new(value).unwrap_or_else(|error| panic!("effect id: {error}"))
}

fn record(value: impl Into<String>) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
}

fn open_claimed_store(
    path: &Path,
    actions: &[&str],
) -> (SqliteSecurityStateStore, Vec<ScheduledWork>) {
    let store = SqliteSecurityStateStore::open(path)
        .unwrap_or_else(|error| panic!("open SQLite store: {error}"));
    let now = now_unix_ms();
    for action_name in actions {
        let canonical_body =
            CanonicalBody::new(b"{}".to_vec()).unwrap_or_else(|error| panic!("plan: {error}"));
        store
            .create(&ResponsePlanRecord {
                tenant_id: tenant(),
                action_id: action(action_name),
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
            claim_id: record("session-throttle-claim"),
            lease_owner_id: LeaseOwnerId::new("session-throttle-worker")
                .unwrap_or_else(|error| panic!("lease owner: {error}")),
            now_unix_ms: now,
            lease_expires_at_unix_ms: now.saturating_add(120_000),
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

fn apply_request(
    action_id: ActionId,
    effect_id: EffectId,
    current: &SessionThrottleSnapshot,
    scheduler_fencing_token: u64,
    limits: SessionThrottleLimits,
    suffix: &str,
) -> SessionThrottleApplyRequest {
    let contribution_bytes = canonical_json_bytes(&limits)
        .unwrap_or_else(|error| panic!("canonical throttle limits: {error}"));
    let contribution_hash = digest(&contribution_bytes);
    let expires_at_unix_ms = now_unix_ms().saturating_add(120_000);
    let request = EffectRequest {
        tenant_id: tenant(),
        action_id: action_id.clone(),
        plan_hash: digest(format!("plan:{suffix}").as_bytes()),
        effect_id: effect_id.clone(),
        effect_kind: ResponseEffectKind::ThrottleSession,
        target: ResponseTarget::Session {
            session_id: session(),
        },
        plan_expires_at_unix_ms: expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record(format!("response_effect_command:{suffix}")),
        expected_version_hash: session_throttle_version_hash(current)
            .unwrap_or_else(|error| panic!("base throttle version: {error}")),
        scheduler_lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(
            "throttle-test-worker",
        )
        .unwrap_or_else(|error| panic!("lease owner: {error}")),
        scheduler_fencing_token,
        canonical_contribution: CanonicalBody::new(contribution_bytes)
            .unwrap_or_else(|error| panic!("throttle contribution: {error}")),
        contribution_hash,
    };
    let contribution = SessionThrottleContribution {
        effect_id: effect_id.clone(),
        limits,
        contribution_hash,
        expires_at_unix_ms,
    };
    let resulting_snapshot =
        predict_session_throttle_apply(current, &contribution, scheduler_fencing_token)
            .unwrap_or_else(|error| panic!("predict throttle apply: {error}"));
    SessionThrottleApplyRequest {
        key: key(),
        action_id,
        contribution: contribution.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: SessionThrottleCommand {
            request,
            result: EffectResult {
                effect_id,
                resulting_version_hash: session_throttle_installed_version_hash(
                    &current.key,
                    &contribution,
                )
                .unwrap_or_else(|error| panic!("installed throttle version: {error}")),
                applied: true,
            },
            resulting_snapshot,
        },
    }
}

fn remove_request(
    apply: &SessionThrottleApplyRequest,
    current: &SessionThrottleSnapshot,
    scheduler_fencing_token: u64,
    suffix: &str,
) -> SessionThrottleRemoveRequest {
    let mut request = apply.command.request.clone();
    request.operation = EffectOperation::Remove;
    request.idempotency_key = record(format!("response_effect_command:{suffix}"));
    request.expected_version_hash = apply.command.result.resulting_version_hash;
    request.scheduler_fencing_token = scheduler_fencing_token;
    let resulting_snapshot = predict_session_throttle_remove(
        current,
        &apply.contribution.effect_id,
        scheduler_fencing_token,
    )
    .unwrap_or_else(|error| panic!("predict throttle remove: {error}"));
    SessionThrottleRemoveRequest {
        key: apply.key.clone(),
        action_id: apply.action_id.clone(),
        effect_id: apply.contribution.effect_id.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: SessionThrottleCommand {
            request,
            result: EffectResult {
                effect_id: apply.contribution.effect_id.clone(),
                resulting_version_hash: session_throttle_version_hash(&resulting_snapshot)
                    .unwrap_or_else(|error| panic!("removed throttle version: {error}")),
                applied: false,
            },
            resulting_snapshot,
        },
    }
}

fn query(request: &EffectRequest) -> EffectResultQuery {
    EffectResultQuery {
        tenant_id: request.tenant_id.clone(),
        action_id: request.action_id.clone(),
        plan_hash: request.plan_hash,
        effect_id: request.effect_id.clone(),
        effect_kind: request.effect_kind,
        target: request.target.clone(),
        plan_expires_at_unix_ms: request.plan_expires_at_unix_ms,
        operation: request.operation,
        idempotency_key: request.idempotency_key.clone(),
        expected_version_hash: request.expected_version_hash,
        contribution_hash: request.contribution_hash,
        scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: request.scheduler_fencing_token,
    }
}

fn consume(
    store: &dyn SessionThrottleStore,
    invocation: &str,
    observed_at_unix_ms: u64,
) -> chio_security_types::ports::SessionThrottleDecision {
    store
        .consume_session_invocation(&SessionThrottleConsumeRequest {
            key: key(),
            invocation_id: record(invocation),
            observed_at_unix_ms,
        })
        .unwrap_or_else(|error| panic!("consume session invocation: {error}"))
}

fn require_error<T>(result: Result<T, PortError>) -> PortError {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => error,
    }
}

#[test]
fn overlapping_windows_are_a_conjunction_and_remove_out_of_order() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("session-throttle-overlap.db");
    let first_action = action("throttle-action-first");
    let second_action = action("throttle-action-second");
    let (store, work) = open_claimed_store(&path, &[first_action.as_str(), second_action.as_str()]);
    let empty = empty_session_throttle_snapshot(key())
        .unwrap_or_else(|error| panic!("empty throttle snapshot: {error}"));
    let first = apply_request(
        first_action.clone(),
        effect("throttle-effect-first"),
        &empty,
        work_for(&work, &first_action).fencing_token,
        SessionThrottleLimits {
            window_ms: 1_000,
            max_invocations: 2,
        },
        "throttle-apply-first",
    );
    let after_first = store
        .apply_session_throttle(&first)
        .unwrap_or_else(|error| panic!("apply first throttle: {error}"));
    let second = apply_request(
        second_action.clone(),
        effect("throttle-effect-second"),
        &after_first,
        work_for(&work, &second_action).fencing_token,
        SessionThrottleLimits {
            window_ms: 2_000,
            max_invocations: 3,
        },
        "throttle-apply-second",
    );
    let after_second = store
        .apply_session_throttle(&second)
        .unwrap_or_else(|error| panic!("apply second throttle: {error}"));

    assert!(consume(&store, "invocation-overlap-1", 10_100).allowed);
    assert!(consume(&store, "invocation-overlap-2", 10_200).allowed);
    let denied = consume(&store, "invocation-overlap-3", 10_300);
    assert!(!denied.allowed);
    assert_eq!(denied.windows.as_slice()[0].consumed_before, 2);
    assert_eq!(denied.windows.as_slice()[1].consumed_before, 2);
    assert_eq!(denied.windows.as_slice()[1].consumed_after, 2);

    let remove_first = remove_request(
        &first,
        &after_second,
        work_for(&work, &first_action).fencing_token,
        "throttle-remove-first",
    );
    let after_remove_first = store
        .remove_session_throttle(&remove_first)
        .unwrap_or_else(|error| panic!("remove first throttle: {error}"));
    assert_eq!(after_remove_first.contributions.len(), 1);
    assert!(consume(&store, "invocation-overlap-3", 10_300).allowed);
    assert!(!consume(&store, "invocation-overlap-4", 10_400).allowed);

    let remove_second = remove_request(
        &second,
        &after_remove_first,
        work_for(&work, &second_action).fencing_token,
        "throttle-remove-second",
    );
    let empty_again = store
        .remove_session_throttle(&remove_second)
        .unwrap_or_else(|error| panic!("remove second throttle: {error}"));
    assert!(empty_again.contributions.is_empty());
    let unrestricted = consume(&store, "invocation-unrestricted", 10_500);
    assert!(unrestricted.allowed);
    assert!(unrestricted.windows.is_empty());
}

#[test]
fn deterministic_boundary_rollover_and_invocation_replay_are_exact() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("session-throttle-boundary.db");
    let action_id = action("throttle-action-boundary");
    let (store, work) = open_claimed_store(&path, &[action_id.as_str()]);
    let empty = empty_session_throttle_snapshot(key())
        .unwrap_or_else(|error| panic!("empty throttle snapshot: {error}"));
    let apply = apply_request(
        action_id.clone(),
        effect("throttle-effect-boundary"),
        &empty,
        work_for(&work, &action_id).fencing_token,
        SessionThrottleLimits {
            window_ms: 1_000,
            max_invocations: 1,
        },
        "throttle-apply-boundary",
    );
    store
        .apply_session_throttle(&apply)
        .unwrap_or_else(|error| panic!("apply boundary throttle: {error}"));

    let first = consume(&store, "invocation-boundary", 10_999);
    assert!(first.allowed);
    assert_eq!(first.windows.as_slice()[0].consumed_before, 0);
    assert_eq!(first.windows.as_slice()[0].consumed_after, 1);
    let replay = consume(&store, "invocation-boundary", 10_999);
    assert!(replay.allowed);
    assert!(replay.windows.as_slice()[0].replayed);
    assert_eq!(
        replay.windows.as_slice()[0].identity,
        first.windows.as_slice()[0].identity
    );
    assert!(!consume(&store, "invocation-boundary-denied", 10_999).allowed);

    let rolled = consume(&store, "invocation-boundary-next", 11_000);
    assert!(rolled.allowed);
    assert_ne!(
        rolled.windows.as_slice()[0].identity.window_id,
        first.windows.as_slice()[0].identity.window_id
    );
    assert_eq!(rolled.windows.as_slice()[0].consumed_before, 0);
    assert_eq!(rolled.windows.as_slice()[0].consumed_after, 1);
}

#[test]
fn last_unit_race_allows_exactly_one_invocation() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("session-throttle-race.db");
    let action_id = action("throttle-action-race");
    let (store, work) = open_claimed_store(&path, &[action_id.as_str()]);
    let empty = empty_session_throttle_snapshot(key())
        .unwrap_or_else(|error| panic!("empty throttle snapshot: {error}"));
    let apply = apply_request(
        action_id.clone(),
        effect("throttle-effect-race"),
        &empty,
        work_for(&work, &action_id).fencing_token,
        SessionThrottleLimits {
            window_ms: 60_000,
            max_invocations: 1,
        },
        "throttle-apply-race",
    );
    store
        .apply_session_throttle(&apply)
        .unwrap_or_else(|error| panic!("apply race throttle: {error}"));
    let store = Arc::new(store);

    let participants = 8;
    let barrier = Arc::new(Barrier::new(participants));
    let mut handles = Vec::new();
    for index in 0..participants {
        let store = store.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            consume(
                store.as_ref(),
                format!("invocation-race-{index}").as_str(),
                120_001,
            )
            .allowed
        }));
    }
    let allowed = handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .unwrap_or_else(|_| panic!("race thread panicked"))
        })
        .filter(|allowed| *allowed)
        .count();
    assert_eq!(allowed, 1);
}

#[test]
fn command_recovery_survives_restart_and_rejects_rebinding_and_stale_fence() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("session-throttle-recovery.db");
    let action_id = action("throttle-action-recovery");
    let (store, work) = open_claimed_store(&path, &[action_id.as_str()]);
    let empty = empty_session_throttle_snapshot(key())
        .unwrap_or_else(|error| panic!("empty throttle snapshot: {error}"));
    let apply = apply_request(
        action_id.clone(),
        effect("throttle-effect-recovery"),
        &empty,
        work_for(&work, &action_id).fencing_token,
        SessionThrottleLimits {
            window_ms: 5_000,
            max_invocations: 4,
        },
        "throttle-apply-recovery",
    );
    let result = apply.command.result.clone();
    let recovery_query = query(&apply.command.request);
    store
        .apply_session_throttle(&apply)
        .unwrap_or_else(|error| panic!("persist throttle before lost ack: {error}"));
    drop(store);

    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("reopen throttle store: {error}"));
    assert_eq!(
        reopened.load_session_throttle_result(&query(&apply.command.request)),
        Ok(EffectExecutionStatus::Completed {
            result: result.clone()
        })
    );
    assert_eq!(
        reopened.apply_session_throttle(&apply),
        Ok(apply.command.resulting_snapshot.clone())
    );

    let mut wrong_tenant = query(&apply.command.request);
    wrong_tenant.tenant_id = TenantId::new("tenant-throttle-wrong")
        .unwrap_or_else(|error| panic!("wrong tenant: {error}"));
    wrong_tenant.target = ResponseTarget::Session {
        session_id: session(),
    };
    assert_eq!(
        reopened.load_session_throttle_result(&wrong_tenant),
        Ok(EffectExecutionStatus::NotExecuted)
    );
    let mut wrong_session = apply.clone();
    wrong_session.key.session_id = SessionId::new("session-throttle-wrong")
        .unwrap_or_else(|error| panic!("wrong session: {error}"));
    assert_eq!(
        require_error(reopened.apply_session_throttle(&wrong_session)).kind(),
        PortErrorKind::InvalidData
    );
    let mut stale = apply;
    stale.scheduler_fencing_token = stale.scheduler_fencing_token.saturating_add(1);
    stale.command.request.scheduler_fencing_token = stale.scheduler_fencing_token;
    stale.command.request.idempotency_key = record("response_effect_command:throttle-stale");
    assert_eq!(
        require_error(reopened.apply_session_throttle(&stale)).kind(),
        PortErrorKind::Conflict
    );
    reopened
        .ensure_session_throttles_ready()
        .unwrap_or_else(|error| panic!("throttle readiness after recovery: {error}"));

    let tamper = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open throttle tamper connection: {error}"));
    tamper
        .execute(
            "UPDATE security_session_throttle_commands SET request_body = ?1",
            rusqlite::params![b"{}".as_slice()],
        )
        .unwrap_or_else(|error| panic!("tamper throttle command: {error}"));
    assert_eq!(
        require_error(reopened.load_session_throttle_result(&recovery_query)).kind(),
        PortErrorKind::IntegrityFailure
    );
}
