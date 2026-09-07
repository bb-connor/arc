use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_security_types::ports::{
    containment_installed_version_hash, containment_overlay_version_hash,
    containment_session_target, predict_containment_overlay_apply,
    predict_containment_overlay_remove, ActionId, CanonicalBody, ContainmentOverlayCommand,
    ContainmentOverlayStore, Digest32, EffectExecutionStatus, EffectId, EffectOperation,
    EffectRequest, EffectResult, EffectResultQuery, LeaseOwnerId, OverlayApplyRequest,
    OverlayContribution, OverlayContributions, OverlayRemoveRequest, OverlaySnapshot, PortError,
    PortErrorKind, RecordId, ResponsePlanRecord, ResponseStore, ScheduledWork,
    SchedulerClaimRequest, SessionId, TenantId, TenantScopedId,
};
use chio_security_types::{ResponseEffectKind, ResponseTarget};
use chio_store_sqlite::SqliteSecurityStateStore;
use tempfile::tempdir;

const TEST_EXPIRY_UNIX_MS: u64 = 4_102_444_800_000;

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
    TenantId::new("tenant-containment").unwrap_or_else(|error| panic!("tenant id: {error}"))
}

fn action(value: &str) -> ActionId {
    ActionId::new(value).unwrap_or_else(|error| panic!("action id: {error}"))
}

fn effect(value: &str) -> EffectId {
    EffectId::new(value).unwrap_or_else(|error| panic!("effect id: {error}"))
}

fn record(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
}

fn target() -> TenantScopedId {
    containment_session_target(
        &tenant(),
        &SessionId::new("session-containment")
            .unwrap_or_else(|error| panic!("session id: {error}")),
    )
    .unwrap_or_else(|error| panic!("containment target: {error}"))
}

fn empty_snapshot() -> OverlaySnapshot {
    OverlaySnapshot {
        target: target(),
        generation: 0,
        effective_posture_rank: 0,
        active_contributions: OverlayContributions::new(Vec::new())
            .unwrap_or_else(|error| panic!("empty overlay: {error}")),
        highest_fencing_token: 0,
    }
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
            CanonicalBody::new(b"{}".to_vec()).unwrap_or_else(|error| panic!("plan body: {error}"));
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
            claim_id: record("containment-command-claim"),
            lease_owner_id: LeaseOwnerId::new("containment-command-worker")
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
    current: &OverlaySnapshot,
    scheduler_fencing_token: u64,
    posture_rank: u32,
    suffix: &str,
) -> OverlayApplyRequest {
    let contribution_bytes = format!("{{\"posture_rank\":{posture_rank}}}").into_bytes();
    let contribution_hash = digest(&contribution_bytes);
    let expires_at_unix_ms = TEST_EXPIRY_UNIX_MS;
    let request = EffectRequest {
        tenant_id: tenant(),
        action_id: action_id.clone(),
        plan_hash: digest(format!("plan:{suffix}").as_bytes()),
        effect_id: effect_id.clone(),
        effect_kind: ResponseEffectKind::SuspendSession,
        target: ResponseTarget::Session {
            session_id: SessionId::new("session-containment")
                .unwrap_or_else(|error| panic!("session id: {error}")),
        },
        plan_expires_at_unix_ms: expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record(format!("response_effect_command:{suffix}").as_str()),
        expected_version_hash: containment_overlay_version_hash(current)
            .unwrap_or_else(|error| panic!("base version: {error}")),
        scheduler_lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(
            "containment-test-worker",
        )
        .unwrap_or_else(|error| panic!("lease owner: {error}")),
        scheduler_fencing_token,
        canonical_contribution: CanonicalBody::new(contribution_bytes)
            .unwrap_or_else(|error| panic!("contribution body: {error}")),
        contribution_hash,
    };
    let contribution = OverlayContribution {
        effect_id: effect_id.clone(),
        posture_rank,
        contribution_hash,
        expires_at_unix_ms: Some(expires_at_unix_ms),
    };
    let resulting_snapshot =
        predict_containment_overlay_apply(current, &contribution, scheduler_fencing_token)
            .unwrap_or_else(|error| panic!("predict overlay apply: {error}"));
    OverlayApplyRequest {
        target: current.target.clone(),
        action_id,
        contribution: contribution.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: ContainmentOverlayCommand {
            request,
            result: EffectResult {
                effect_id,
                resulting_version_hash: containment_installed_version_hash(
                    &current.target,
                    &contribution,
                )
                .unwrap_or_else(|error| panic!("installed version: {error}")),
                applied: true,
            },
            resulting_snapshot,
        },
    }
}

fn remove_request(
    apply: &OverlayApplyRequest,
    current: &OverlaySnapshot,
    scheduler_fencing_token: u64,
    suffix: &str,
) -> OverlayRemoveRequest {
    let mut request = apply.command.request.clone();
    request.operation = EffectOperation::Remove;
    request.idempotency_key = record(format!("response_effect_command:{suffix}").as_str());
    request.expected_version_hash = apply.command.result.resulting_version_hash;
    request.scheduler_fencing_token = scheduler_fencing_token;
    let resulting_snapshot = predict_containment_overlay_remove(
        current,
        &apply.contribution.effect_id,
        scheduler_fencing_token,
    )
    .unwrap_or_else(|error| panic!("predict overlay remove: {error}"));
    OverlayRemoveRequest {
        target: apply.target.clone(),
        action_id: apply.action_id.clone(),
        effect_id: apply.contribution.effect_id.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: ContainmentOverlayCommand {
            request,
            result: EffectResult {
                effect_id: apply.contribution.effect_id.clone(),
                resulting_version_hash: containment_overlay_version_hash(&resulting_snapshot)
                    .unwrap_or_else(|error| panic!("removed version: {error}")),
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

fn require_error<T>(result: Result<T, PortError>) -> PortError {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => error,
    }
}

#[test]
fn exact_commands_survive_ack_loss_restart_and_out_of_order_removal() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("containment-commands.db");
    let first_action = action("containment-action-first");
    let second_action = action("containment-action-second");
    let (store, work) = open_claimed_store(&path, &[first_action.as_str(), second_action.as_str()]);
    let first = apply_request(
        first_action.clone(),
        effect("containment-effect-first"),
        &empty_snapshot(),
        work_for(&work, &first_action).fencing_token,
        3,
        "containment-apply-first",
    );
    let first_snapshot = store
        .apply_contribution(&first)
        .unwrap_or_else(|error| panic!("apply first contribution: {error}"));
    assert_eq!(first_snapshot.generation, 1);
    assert_eq!(
        first.command.result.resulting_version_hash,
        containment_installed_version_hash(&first.target, &first.contribution)
            .unwrap_or_else(|error| panic!("apply result commitment: {error}"))
    );
    assert_eq!(
        store
            .apply_contribution(&first)
            .unwrap_or_else(|error| panic!("recover first apply ack: {error}")),
        first_snapshot
    );
    assert_eq!(
        store.load_containment_overlay_result(&query(&first.command.request)),
        Ok(EffectExecutionStatus::Completed {
            result: first.command.result.clone()
        })
    );

    let second = apply_request(
        second_action.clone(),
        effect("containment-effect-second"),
        &first_snapshot,
        work_for(&work, &second_action).fencing_token,
        8,
        "containment-apply-second",
    );
    let both = store
        .apply_contribution(&second)
        .unwrap_or_else(|error| panic!("apply second contribution: {error}"));
    assert_eq!(both.active_contributions.len(), 2);
    assert_eq!(both.effective_posture_rank, 8);
    assert_eq!(
        store
            .apply_contribution(&first)
            .unwrap_or_else(|error| panic!("replay historical first apply: {error}")),
        first_snapshot
    );
    drop(store);

    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("reopen SQLite store: {error}"));
    store
        .ensure_containment_overlays_ready()
        .unwrap_or_else(|error| panic!("containment readiness after restart: {error}"));
    assert_eq!(
        store.load_containment_overlay_result(&query(&first.command.request)),
        Ok(EffectExecutionStatus::Completed {
            result: first.command.result.clone()
        })
    );
    let remove_second = remove_request(
        &second,
        &both,
        work_for(&work, &second_action).fencing_token,
        "containment-remove-second",
    );
    let first_remaining = store
        .remove_contribution(&remove_second)
        .unwrap_or_else(|error| panic!("remove second contribution: {error}"));
    assert_eq!(first_remaining.active_contributions.len(), 1);
    assert_eq!(first_remaining.effective_posture_rank, 3);
    assert_eq!(
        remove_second.command.result.resulting_version_hash,
        containment_overlay_version_hash(&first_remaining)
            .unwrap_or_else(|error| panic!("remove result commitment: {error}"))
    );
    assert_eq!(
        store.load_containment_overlay_result(&query(&remove_second.command.request)),
        Ok(EffectExecutionStatus::Completed {
            result: remove_second.command.result.clone()
        })
    );
    assert_eq!(
        store
            .remove_contribution(&remove_second)
            .unwrap_or_else(|error| panic!("recover remove ack: {error}")),
        first_remaining
    );

    let remove_first = remove_request(
        &first,
        &first_remaining,
        work_for(&work, &first_action).fencing_token,
        "containment-remove-first",
    );
    let empty = store
        .remove_contribution(&remove_first)
        .unwrap_or_else(|error| panic!("remove first contribution: {error}"));
    assert!(empty.active_contributions.is_empty());
    assert_eq!(
        store
            .remove_contribution(&remove_second)
            .unwrap_or_else(|error| panic!("replay historical second removal: {error}")),
        first_remaining
    );
    drop(store);

    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("reopen after removals: {error}"));
    assert_eq!(
        store.load_containment_overlay_result(&query(&remove_first.command.request)),
        Ok(EffectExecutionStatus::Completed {
            result: remove_first.command.result.clone()
        })
    );
    let mut rebound_query = query(&first.command.request);
    rebound_query.contribution_hash = Digest32::new([99_u8; 32]);
    assert_eq!(
        require_error(store.load_containment_overlay_result(&rebound_query)).kind(),
        PortErrorKind::Conflict
    );
}

#[test]
fn stale_fences_and_action_rebinding_fail_closed() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("containment-binding.db");
    let first_action = action("containment-binding-first");
    let second_action = action("containment-binding-second");
    let (store, work) = open_claimed_store(&path, &[first_action.as_str(), second_action.as_str()]);
    let first_work = work_for(&work, &first_action);
    let first = apply_request(
        first_action.clone(),
        effect("containment-binding-effect"),
        &empty_snapshot(),
        first_work.fencing_token,
        5,
        "containment-binding-apply",
    );
    let applied = store
        .apply_contribution(&first)
        .unwrap_or_else(|error| panic!("apply bound contribution: {error}"));

    let mut rebound_target = first.clone();
    rebound_target.target = containment_session_target(
        &tenant(),
        &SessionId::new("hostile-rebound-session")
            .unwrap_or_else(|error| panic!("rebound session: {error}")),
    )
    .unwrap_or_else(|error| panic!("rebound target: {error}"));
    assert_eq!(
        require_error(store.apply_contribution(&rebound_target)).kind(),
        PortErrorKind::InvalidData
    );

    let mut forged_result = first.clone();
    forged_result.command.result.resulting_version_hash = digest(b"forged-result-version");
    assert_eq!(
        require_error(store.apply_contribution(&forged_result)).kind(),
        PortErrorKind::InvalidData
    );

    let mut wrong_base = apply_request(
        first_action.clone(),
        effect("containment-wrong-base-effect"),
        &applied,
        first_work.fencing_token,
        9,
        "containment-wrong-base",
    );
    wrong_base.command.request.expected_version_hash = digest(b"forged-base-version");
    assert_eq!(
        require_error(store.apply_contribution(&wrong_base)).kind(),
        PortErrorKind::Conflict
    );

    let rebound = apply_request(
        second_action.clone(),
        first.contribution.effect_id.clone(),
        &applied,
        work_for(&work, &second_action).fencing_token,
        5,
        "containment-binding-rebound",
    );
    assert_eq!(
        require_error(store.apply_contribution(&rebound)).kind(),
        PortErrorKind::Conflict
    );
    let stale_remove = remove_request(
        &first,
        &applied,
        first_work.fencing_token.saturating_add(1),
        "containment-stale-remove",
    );
    assert_eq!(
        require_error(store.remove_contribution(&stale_remove)).kind(),
        PortErrorKind::Conflict
    );
    assert_eq!(
        store
            .load_effective(&target())
            .unwrap_or_else(|error| panic!("load bound overlay: {error}"))
            .unwrap_or_else(|| panic!("bound overlay missing"))
            .active_contributions
            .len(),
        1
    );
}

#[test]
fn readiness_rejects_derived_state_and_semantically_tampered_results() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("containment-readiness.db");
    let action_id = action("containment-readiness-action");
    let (store, work) = open_claimed_store(&path, &[action_id.as_str()]);
    let apply = apply_request(
        action_id.clone(),
        effect("containment-readiness-effect"),
        &empty_snapshot(),
        work_for(&work, &action_id).fencing_token,
        6,
        "containment-readiness-apply",
    );
    store
        .apply_contribution(&apply)
        .unwrap_or_else(|error| panic!("apply readiness contribution: {error}"));
    store
        .ensure_containment_overlays_ready()
        .unwrap_or_else(|error| panic!("initial containment readiness: {error}"));

    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open corruption connection: {error}"));
    connection
        .execute(
            "UPDATE security_overlay_state SET effective_posture_rank = 0 WHERE tenant_id = ?1 AND target_id = ?2",
            rusqlite::params![tenant().as_str(), target().id.as_str()],
        )
        .unwrap_or_else(|error| panic!("corrupt derived posture: {error}"));
    assert_eq!(
        require_error(store.ensure_containment_overlays_ready()).kind(),
        PortErrorKind::IntegrityFailure
    );
    connection
        .execute(
            "UPDATE security_overlay_state SET effective_posture_rank = 6 WHERE tenant_id = ?1 AND target_id = ?2",
            rusqlite::params![tenant().as_str(), target().id.as_str()],
        )
        .unwrap_or_else(|error| panic!("restore derived posture: {error}"));
    store
        .ensure_containment_overlays_ready()
        .unwrap_or_else(|error| panic!("readiness after posture repair: {error}"));

    let tampered_result = EffectResult {
        effect_id: apply.contribution.effect_id.clone(),
        resulting_version_hash: digest(b"hostile-result-version"),
        applied: true,
    };
    let result_body = canonical_json_bytes(&tampered_result)
        .unwrap_or_else(|error| panic!("canonical tampered result: {error}"));
    let result_hash = digest(&result_body);
    connection
        .execute(
            r#"
            UPDATE security_containment_overlay_commands
            SET result_body = ?1, result_body_hash = ?2
            WHERE tenant_id = ?3 AND idempotency_key = ?4
            "#,
            rusqlite::params![
                result_body,
                result_hash.as_bytes().as_slice(),
                tenant().as_str(),
                apply.command.request.idempotency_key.as_str()
            ],
        )
        .unwrap_or_else(|error| panic!("tamper stored result: {error}"));
    assert_eq!(
        require_error(store.ensure_containment_overlays_ready()).kind(),
        PortErrorKind::IntegrityFailure
    );
    assert_eq!(
        require_error(store.load_containment_overlay_result(&query(&apply.command.request))).kind(),
        PortErrorKind::IntegrityFailure
    );

    let unknown_status_body = br#"{"status":"unknown"}"#.to_vec();
    let unknown_status_hash = digest(&unknown_status_body);
    connection
        .execute(
            r#"
            UPDATE security_containment_overlay_commands
            SET result_body = ?1, result_body_hash = ?2
            WHERE tenant_id = ?3 AND idempotency_key = ?4
            "#,
            rusqlite::params![
                unknown_status_body,
                unknown_status_hash.as_bytes().as_slice(),
                tenant().as_str(),
                apply.command.request.idempotency_key.as_str()
            ],
        )
        .unwrap_or_else(|error| panic!("store unknown result shape: {error}"));
    assert_eq!(
        require_error(store.load_containment_overlay_result(&query(&apply.command.request))).kind(),
        PortErrorKind::IntegrityFailure
    );

    let original_result_body = canonical_json_bytes(&apply.command.result)
        .unwrap_or_else(|error| panic!("canonical original result: {error}"));
    let original_result_hash = digest(&original_result_body);
    connection
        .execute(
            r#"
            UPDATE security_containment_overlay_commands
            SET result_body = ?1, result_body_hash = ?2
            WHERE tenant_id = ?3 AND idempotency_key = ?4
            "#,
            rusqlite::params![
                original_result_body,
                original_result_hash.as_bytes().as_slice(),
                tenant().as_str(),
                apply.command.request.idempotency_key.as_str()
            ],
        )
        .unwrap_or_else(|error| panic!("restore stored result: {error}"));
    store
        .ensure_containment_overlays_ready()
        .unwrap_or_else(|error| panic!("readiness after result repair: {error}"));

    let mut rebound_snapshot = apply.command.resulting_snapshot.clone();
    rebound_snapshot.target = containment_session_target(
        &tenant(),
        &SessionId::new("tampered-snapshot-session")
            .unwrap_or_else(|error| panic!("tampered snapshot session: {error}")),
    )
    .unwrap_or_else(|error| panic!("tampered snapshot target: {error}"));
    let snapshot_body = canonical_json_bytes(&rebound_snapshot)
        .unwrap_or_else(|error| panic!("canonical tampered snapshot: {error}"));
    let snapshot_hash = digest(&snapshot_body);
    connection
        .execute(
            r#"
            UPDATE security_containment_overlay_commands
            SET resulting_snapshot_body = ?1, resulting_snapshot_body_hash = ?2
            WHERE tenant_id = ?3 AND idempotency_key = ?4
            "#,
            rusqlite::params![
                snapshot_body,
                snapshot_hash.as_bytes().as_slice(),
                tenant().as_str(),
                apply.command.request.idempotency_key.as_str()
            ],
        )
        .unwrap_or_else(|error| panic!("tamper stored snapshot: {error}"));
    assert_eq!(
        require_error(store.ensure_containment_overlays_ready()).kind(),
        PortErrorKind::IntegrityFailure
    );
    assert_eq!(
        require_error(store.load_containment_overlay_result(&query(&apply.command.request))).kind(),
        PortErrorKind::IntegrityFailure
    );
}
