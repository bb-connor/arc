use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_security_types::ports::{
    capability_set_suspension_installed_version_hash, capability_set_suspension_version_hash,
    empty_capability_set_suspension_snapshot, predict_capability_set_suspension_apply,
    predict_capability_set_suspension_remove, response_affected_set_hash, ActionId, CanonicalBody,
    CapabilitySetSuspensionApplyRequest, CapabilitySetSuspensionCommand,
    CapabilitySetSuspensionContribution, CapabilitySetSuspensionKey,
    CapabilitySetSuspensionRemoveRequest, CapabilitySetSuspensionSnapshot,
    CapabilitySetSuspensionSpec, CapabilitySetSuspensionStore, CapabilitySuspensionQuery, Digest32,
    EffectExecutionStatus, EffectId, EffectOperation, EffectRequest, EffectResult,
    EffectResultQuery, LeaseOwnerId, PortError, PortErrorKind, RecordId, RecordIdSet,
    ResponsePlanRecord, ResponseStore, ScheduledWork, SchedulerClaimRequest, TenantId,
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
    TenantId::new("tenant-capability-suspension")
        .unwrap_or_else(|error| panic!("tenant id: {error}"))
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

fn affected(values: &[&str]) -> RecordIdSet {
    RecordIdSet::new(values.iter().map(|value| record(*value)).collect())
        .unwrap_or_else(|error| panic!("affected set: {error}"))
}

fn key(affected_ids: &RecordIdSet) -> CapabilitySetSuspensionKey {
    CapabilitySetSuspensionKey {
        tenant_id: tenant(),
        affected_set_hash: response_affected_set_hash(&tenant(), affected_ids)
            .unwrap_or_else(|error| panic!("affected set hash: {error}")),
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
            claim_id: record("capability-suspension-claim"),
            lease_owner_id: LeaseOwnerId::new("capability-suspension-worker")
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
    affected_ids: RecordIdSet,
    current: &CapabilitySetSuspensionSnapshot,
    scheduler_fencing_token: u64,
    suffix: &str,
) -> CapabilitySetSuspensionApplyRequest {
    let spec = CapabilitySetSuspensionSpec {
        affected_ids: affected_ids.clone(),
    };
    let contribution_bytes = canonical_json_bytes(&spec)
        .unwrap_or_else(|error| panic!("canonical suspension contribution: {error}"));
    let contribution_hash = digest(&contribution_bytes);
    let expires_at_unix_ms = now_unix_ms().saturating_add(120_000);
    let request = EffectRequest {
        tenant_id: tenant(),
        action_id: action_id.clone(),
        plan_hash: digest(format!("plan:{suffix}").as_bytes()),
        effect_id: effect_id.clone(),
        effect_kind: ResponseEffectKind::SuspendCapabilitySet,
        target: ResponseTarget::CapabilitySet {
            affected_set_hash: current.key.affected_set_hash,
        },
        plan_expires_at_unix_ms: expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record(format!("response_effect_command:{suffix}")),
        expected_version_hash: capability_set_suspension_version_hash(current)
            .unwrap_or_else(|error| panic!("base suspension version: {error}")),
        scheduler_lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(
            "capability-suspension-test-worker",
        )
        .unwrap_or_else(|error| panic!("lease owner: {error}")),
        scheduler_fencing_token,
        canonical_contribution: CanonicalBody::new(contribution_bytes)
            .unwrap_or_else(|error| panic!("suspension contribution: {error}")),
        contribution_hash,
    };
    let contribution = CapabilitySetSuspensionContribution {
        action_id,
        effect_id: effect_id.clone(),
        affected_ids,
        contribution_hash,
        expires_at_unix_ms,
    };
    let resulting_snapshot =
        predict_capability_set_suspension_apply(current, &contribution, scheduler_fencing_token)
            .unwrap_or_else(|error| panic!("predict suspension apply: {error}"));
    CapabilitySetSuspensionApplyRequest {
        key: current.key.clone(),
        contribution: contribution.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: CapabilitySetSuspensionCommand {
            request,
            result: EffectResult {
                effect_id,
                resulting_version_hash: capability_set_suspension_installed_version_hash(
                    &current.key,
                    &contribution,
                )
                .unwrap_or_else(|error| panic!("installed suspension version: {error}")),
                applied: true,
            },
            resulting_snapshot,
        },
    }
}

fn remove_request(
    apply: &CapabilitySetSuspensionApplyRequest,
    current: &CapabilitySetSuspensionSnapshot,
    scheduler_fencing_token: u64,
    suffix: &str,
) -> CapabilitySetSuspensionRemoveRequest {
    let mut request = apply.command.request.clone();
    request.operation = EffectOperation::Remove;
    request.idempotency_key = record(format!("response_effect_command:{suffix}"));
    request.expected_version_hash = apply.command.result.resulting_version_hash;
    request.scheduler_fencing_token = scheduler_fencing_token;
    let resulting_snapshot = predict_capability_set_suspension_remove(
        current,
        &apply.contribution.action_id,
        &apply.contribution.effect_id,
        scheduler_fencing_token,
    )
    .unwrap_or_else(|error| panic!("predict suspension remove: {error}"));
    CapabilitySetSuspensionRemoveRequest {
        key: apply.key.clone(),
        action_id: apply.contribution.action_id.clone(),
        effect_id: apply.contribution.effect_id.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: CapabilitySetSuspensionCommand {
            request,
            result: EffectResult {
                effect_id: apply.contribution.effect_id.clone(),
                resulting_version_hash: capability_set_suspension_version_hash(&resulting_snapshot)
                    .unwrap_or_else(|error| panic!("removed suspension version: {error}")),
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

fn decision(
    store: &dyn CapabilitySetSuspensionStore,
    capability_id: &str,
) -> chio_security_types::ports::CapabilitySuspensionDecision {
    store
        .evaluate_capability_suspension(&CapabilitySuspensionQuery {
            tenant_id: tenant(),
            capability_id: record(capability_id),
        })
        .unwrap_or_else(|error| panic!("evaluate capability suspension: {error}"))
}

fn require_error<T>(result: Result<T, PortError>) -> PortError {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => error,
    }
}

#[test]
fn overlapping_sets_compose_and_remove_only_the_exact_contribution() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("capability-suspension-overlap.db");
    let first_action = action("capability-suspension-action-first");
    let second_action = action("capability-suspension-action-second");
    let (store, work) = open_claimed_store(&path, &[first_action.as_str(), second_action.as_str()]);
    let first_set = affected(&["capability-a", "capability-shared"]);
    let second_set = affected(&["capability-b", "capability-shared"]);
    let first_empty = empty_capability_set_suspension_snapshot(key(&first_set))
        .unwrap_or_else(|error| panic!("first empty snapshot: {error}"));
    let first = apply_request(
        first_action.clone(),
        effect("capability-suspension-effect-first"),
        first_set,
        &first_empty,
        work_for(&work, &first_action).fencing_token,
        "capability-suspension-apply-first",
    );
    let after_first = store
        .apply_capability_set_suspension(&first)
        .unwrap_or_else(|error| panic!("apply first suspension: {error}"));
    assert_eq!(after_first.contributions.len(), 1);

    let second_empty = empty_capability_set_suspension_snapshot(key(&second_set))
        .unwrap_or_else(|error| panic!("second empty snapshot: {error}"));
    let second = apply_request(
        second_action.clone(),
        effect("capability-suspension-effect-second"),
        second_set,
        &second_empty,
        work_for(&work, &second_action).fencing_token,
        "capability-suspension-apply-second",
    );
    let after_second = store
        .apply_capability_set_suspension(&second)
        .unwrap_or_else(|error| panic!("apply second suspension: {error}"));
    assert_eq!(after_second.contributions.len(), 1);

    assert_eq!(decision(&store, "capability-a").active_matches.len(), 1);
    assert_eq!(decision(&store, "capability-b").active_matches.len(), 1);
    let shared = decision(&store, "capability-shared");
    assert!(shared.denied);
    assert_eq!(shared.active_matches.len(), 2);
    assert!(!decision(&store, "capability-unrelated").denied);

    let remove_first = remove_request(
        &first,
        &after_first,
        work_for(&work, &first_action).fencing_token,
        "capability-suspension-remove-first",
    );
    store
        .remove_capability_set_suspension(&remove_first)
        .unwrap_or_else(|error| panic!("remove first suspension: {error}"));
    assert!(!decision(&store, "capability-a").denied);
    let shared_after_first = decision(&store, "capability-shared");
    assert!(shared_after_first.denied);
    assert_eq!(shared_after_first.active_matches.len(), 1);

    let remove_second = remove_request(
        &second,
        &after_second,
        work_for(&work, &second_action).fencing_token,
        "capability-suspension-remove-second",
    );
    store
        .remove_capability_set_suspension(&remove_second)
        .unwrap_or_else(|error| panic!("remove second suspension: {error}"));
    assert!(!decision(&store, "capability-shared").denied);
}

#[test]
fn journal_survives_restart_and_rejects_set_action_and_fence_rebinding() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("capability-suspension-recovery.db");
    let action_id = action("capability-suspension-action-recovery");
    let (store, work) = open_claimed_store(&path, &[action_id.as_str()]);
    let affected_ids = affected(&["capability-recovery", "capability-recovery-child"]);
    let empty = empty_capability_set_suspension_snapshot(key(&affected_ids))
        .unwrap_or_else(|error| panic!("empty suspension snapshot: {error}"));
    let apply = apply_request(
        action_id.clone(),
        effect("capability-suspension-effect-recovery"),
        affected_ids,
        &empty,
        work_for(&work, &action_id).fencing_token,
        "capability-suspension-apply-recovery",
    );
    let expected_result = apply.command.result.clone();
    store
        .apply_capability_set_suspension(&apply)
        .unwrap_or_else(|error| panic!("persist suspension before lost ack: {error}"));
    drop(store);

    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("reopen suspension store: {error}"));
    assert_eq!(
        reopened.load_capability_set_suspension_result(&query(&apply.command.request)),
        Ok(EffectExecutionStatus::Completed {
            result: expected_result
        })
    );
    assert_eq!(
        reopened.apply_capability_set_suspension(&apply),
        Ok(apply.command.resulting_snapshot.clone())
    );

    let mut wrong_set = apply.clone();
    wrong_set.key.affected_set_hash = digest(b"wrong affected set");
    wrong_set.command.request.target = ResponseTarget::CapabilitySet {
        affected_set_hash: wrong_set.key.affected_set_hash,
    };
    assert_eq!(
        require_error(reopened.apply_capability_set_suspension(&wrong_set)).kind(),
        PortErrorKind::InvalidData
    );
    let mut wrong_action = apply.clone();
    wrong_action.contribution.action_id = action("capability-suspension-action-wrong");
    assert_eq!(
        require_error(reopened.apply_capability_set_suspension(&wrong_action)).kind(),
        PortErrorKind::InvalidData
    );
    let mut stale = apply;
    stale.scheduler_fencing_token = stale.scheduler_fencing_token.saturating_add(1);
    stale.command.request.scheduler_fencing_token = stale.scheduler_fencing_token;
    stale.command.request.idempotency_key =
        record("response_effect_command:capability-suspension-stale");
    assert_eq!(
        require_error(reopened.apply_capability_set_suspension(&stale)).kind(),
        PortErrorKind::Conflict
    );
    reopened
        .ensure_capability_set_suspensions_ready()
        .unwrap_or_else(|error| panic!("suspension readiness after recovery: {error}"));
}

#[test]
fn member_and_command_integrity_corruption_fail_closed() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("capability-suspension-integrity.db");
    let action_id = action("capability-suspension-action-integrity");
    let (store, work) = open_claimed_store(&path, &[action_id.as_str()]);
    let affected_ids = affected(&["capability-integrity", "capability-integrity-child"]);
    let empty = empty_capability_set_suspension_snapshot(key(&affected_ids))
        .unwrap_or_else(|error| panic!("empty suspension snapshot: {error}"));
    let apply = apply_request(
        action_id.clone(),
        effect("capability-suspension-effect-integrity"),
        affected_ids,
        &empty,
        work_for(&work, &action_id).fencing_token,
        "capability-suspension-apply-integrity",
    );
    let result_query = query(&apply.command.request);
    store
        .apply_capability_set_suspension(&apply)
        .unwrap_or_else(|error| panic!("apply integrity suspension: {error}"));

    let tamper = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open suspension tamper connection: {error}"));
    tamper
        .execute(
            r#"
            DELETE FROM security_capability_set_suspension_members
            WHERE capability_id = 'capability-integrity'
            "#,
            [],
        )
        .unwrap_or_else(|error| panic!("tamper suspension member: {error}"));
    assert_eq!(
        require_error(
            store.evaluate_capability_suspension(&CapabilitySuspensionQuery {
                tenant_id: tenant(),
                capability_id: record("capability-integrity"),
            })
        )
        .kind(),
        PortErrorKind::IntegrityFailure
    );
    assert_eq!(
        require_error(store.ensure_capability_set_suspensions_ready()).kind(),
        PortErrorKind::IntegrityFailure
    );

    tamper
        .execute(
            "UPDATE security_capability_set_suspension_commands SET request_body = ?1",
            rusqlite::params![b"{}".as_slice()],
        )
        .unwrap_or_else(|error| panic!("tamper suspension command: {error}"));
    assert_eq!(
        require_error(store.load_capability_set_suspension_result(&result_query)).kind(),
        PortErrorKind::IntegrityFailure
    );
}
