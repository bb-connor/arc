use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_security_types::ports::{
    ActionId, CanonicalBody, CreateOutcome, DestinationId, Digest32, EffectExecutionStatus,
    EffectId, EffectOperation, EffectRequest, EffectResult, EffectResultQuery,
    EgressDestinationQuery, EgressDestinationSet, EgressRestrictionApplyRequest,
    EgressRestrictionCommand, EgressRestrictionContribution, EgressRestrictionRemoveRequest,
    EgressRestrictionSessionKey, EgressRestrictionStore, LeaseOwnerId, PortError, PortErrorKind,
    PortResult, RecordId, ResponsePlanRecord, ResponseStore, ScheduledWork, SchedulerClaimRequest,
    SessionId, TenantId,
};
use chio_security_types::{ResponseEffectKind, ResponseTarget};
use chio_store_sqlite::SqliteSecurityStateStore;
use tempfile::tempdir;

fn now_unix_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("clock before Unix epoch: {error}"));
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}"))
}

fn key() -> EgressRestrictionSessionKey {
    EgressRestrictionSessionKey {
        tenant_id: tenant(),
        session_id: SessionId::new("session-a").unwrap_or_else(|error| panic!("session: {error}")),
    }
}

fn destination(value: &str) -> DestinationId {
    DestinationId::new(value).unwrap_or_else(|error| panic!("destination: {error}"))
}

fn digest(value: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(value).as_bytes())
}

fn contribution(
    effect_id: &str,
    destinations: &[&str],
    expiry: u64,
) -> EgressRestrictionContribution {
    let destinations = EgressDestinationSet::new(
        destinations
            .iter()
            .map(|value| destination(value))
            .collect(),
    )
    .unwrap_or_else(|error| panic!("destinations: {error}"));
    let body = contribution_body(&destinations);
    EgressRestrictionContribution {
        effect_id: EffectId::new(effect_id).unwrap_or_else(|error| panic!("effect id: {error}")),
        destinations,
        contribution_hash: digest(body.as_bytes()),
        expires_at_unix_ms: expiry,
    }
}

fn contribution_body(destinations: &EgressDestinationSet) -> CanonicalBody {
    let value = serde_json::json!({"destinations": destinations});
    let body = chio_core::canonical_json_bytes(&value)
        .unwrap_or_else(|error| panic!("canonical contribution: {error}"));
    CanonicalBody::new(body).unwrap_or_else(|error| panic!("contribution body: {error}"))
}

fn command(
    action_id: &ActionId,
    contribution: &EgressRestrictionContribution,
    operation: EffectOperation,
    fencing_token: u64,
    idempotency_key: &str,
) -> EgressRestrictionCommand {
    EgressRestrictionCommand {
        request: EffectRequest {
            tenant_id: tenant(),
            action_id: action_id.clone(),
            plan_hash: digest(b"plan-a"),
            effect_id: contribution.effect_id.clone(),
            effect_kind: ResponseEffectKind::RestrictEgress,
            target: ResponseTarget::Session {
                session_id: key().session_id,
            },
            plan_expires_at_unix_ms: contribution.expires_at_unix_ms,
            operation,
            idempotency_key: RecordId::new(idempotency_key)
                .unwrap_or_else(|error| panic!("idempotency key: {error}")),
            expected_version_hash: digest(format!("expected-{idempotency_key}").as_bytes()),
            scheduler_lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(
                "egress-test-worker",
            )
            .unwrap_or_else(|error| panic!("lease owner: {error}")),
            scheduler_fencing_token: fencing_token,
            canonical_contribution: contribution_body(&contribution.destinations),
            contribution_hash: contribution.contribution_hash,
        },
        result: EffectResult {
            effect_id: contribution.effect_id.clone(),
            resulting_version_hash: digest(format!("result-{idempotency_key}").as_bytes()),
            applied: matches!(operation, EffectOperation::Apply),
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
        scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: request.scheduler_fencing_token,
        contribution_hash: request.contribution_hash,
    }
}

fn scheduled_action(
    store: &SqliteSecurityStateStore,
    action: &str,
    claim: &str,
    now: u64,
) -> ScheduledWork {
    let action_id = ActionId::new(action).unwrap_or_else(|error| panic!("action id: {error}"));
    let body =
        CanonicalBody::new(b"{}".to_vec()).unwrap_or_else(|error| panic!("plan body: {error}"));
    assert_eq!(
        store
            .create(&ResponsePlanRecord {
                tenant_id: tenant(),
                action_id: action_id.clone(),
                generation: 0,
                state: RecordId::new("active").unwrap_or_else(|error| panic!("state: {error}")),
                canonical_body: body.clone(),
                body_hash: digest(body.as_bytes()),
                due_at_unix_ms: Some(now.saturating_sub(1)),
            })
            .unwrap_or_else(|error| panic!("create response plan: {error}")),
        CreateOutcome::Created
    );
    let claimed = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: tenant(),
            claim_id: RecordId::new(claim).unwrap_or_else(|error| panic!("claim id: {error}")),
            lease_owner_id: LeaseOwnerId::new(format!("worker-{claim}"))
                .unwrap_or_else(|error| panic!("lease owner: {error}")),
            now_unix_ms: now,
            lease_expires_at_unix_ms: now.saturating_add(120_000),
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("claim response plan: {error}"));
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].action_id, action_id);
    claimed[0].clone()
}

fn require_error<T: std::fmt::Debug>(result: PortResult<T>) -> PortError {
    match result {
        Ok(value) => panic!("operation unexpectedly succeeded: {value:?}"),
        Err(error) => error,
    }
}

fn decision(
    store: &SqliteSecurityStateStore,
    destination_id: &str,
) -> chio_security_types::ports::EgressRestrictionDecision {
    store
        .evaluate_destination(&EgressDestinationQuery {
            key: key(),
            destination_id: destination(destination_id),
        })
        .unwrap_or_else(|error| panic!("evaluate destination: {error}"))
}

#[test]
fn restrictions_survive_restart_and_overlap_removes_out_of_order() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("egress.db");
    let now = now_unix_ms();
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let first_work = scheduled_action(&store, "action-first", "claim-first", now);
    let first = contribution("effect-first", &["server-a", "server-b"], now + 60_000);
    let first_request = EgressRestrictionApplyRequest {
        key: key(),
        action_id: first_work.action_id.clone(),
        contribution: first.clone(),
        expected_generation: 0,
        scheduler_fencing_token: first_work.fencing_token,
        command: command(
            &first_work.action_id,
            &first,
            EffectOperation::Apply,
            first_work.fencing_token,
            "response_effect_command:first-apply",
        ),
    };
    let applied_first = store
        .apply_egress_restriction(&first_request)
        .unwrap_or_else(|error| panic!("apply first: {error}"));
    assert_eq!(
        store
            .load_egress_restriction_result(&query(&first_request.command.request))
            .unwrap_or_else(|error| panic!("load first command: {error}")),
        EffectExecutionStatus::Completed {
            result: first_request.command.result.clone()
        }
    );
    assert_eq!(
        store
            .apply_egress_restriction(&first_request)
            .unwrap_or_else(|error| panic!("retry first: {error}")),
        applied_first
    );
    assert!(decision(&store, "server-a").denied);
    assert!(!decision(&store, "server-c").denied);
    store
        .ensure_egress_restrictions_ready()
        .unwrap_or_else(|error| panic!("initial readiness: {error}"));
    drop(store);

    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("reopen store: {error}"));
    assert_eq!(
        store
            .load_egress_restriction_result(&query(&first_request.command.request))
            .unwrap_or_else(|error| panic!("load first command after restart: {error}")),
        EffectExecutionStatus::Completed {
            result: first_request.command.result.clone()
        }
    );
    assert!(decision(&store, "server-a").denied);
    let second_work = scheduled_action(&store, "action-second", "claim-second", now + 1);
    let second = contribution("effect-second", &["server-b", "server-c"], now + 70_000);
    let applied_second = store
        .apply_egress_restriction(&EgressRestrictionApplyRequest {
            key: key(),
            action_id: second_work.action_id.clone(),
            contribution: second.clone(),
            expected_generation: applied_first.generation,
            scheduler_fencing_token: second_work.fencing_token,
            command: command(
                &second_work.action_id,
                &second,
                EffectOperation::Apply,
                second_work.fencing_token,
                "response_effect_command:second-apply",
            ),
        })
        .unwrap_or_else(|error| panic!("apply second: {error}"));
    assert_eq!(
        applied_second.denied_destinations.as_slice(),
        &[
            destination("server-a"),
            destination("server-b"),
            destination("server-c"),
        ]
    );

    let after_first = store
        .remove_egress_restriction(&EgressRestrictionRemoveRequest {
            key: key(),
            action_id: first_work.action_id.clone(),
            effect_id: first.effect_id.clone(),
            expected_generation: applied_second.generation,
            scheduler_fencing_token: first_work.fencing_token,
            command: command(
                &first_work.action_id,
                &first,
                EffectOperation::Remove,
                first_work.fencing_token,
                "response_effect_command:first-remove",
            ),
        })
        .unwrap_or_else(|error| panic!("remove first: {error}"));
    assert!(!decision(&store, "server-a").denied);
    assert!(decision(&store, "server-b").denied);
    assert!(decision(&store, "server-c").denied);

    let remove_second = EgressRestrictionRemoveRequest {
        key: key(),
        action_id: second_work.action_id.clone(),
        effect_id: second.effect_id.clone(),
        expected_generation: after_first.generation,
        scheduler_fencing_token: second_work.fencing_token,
        command: command(
            &second_work.action_id,
            &second,
            EffectOperation::Remove,
            second_work.fencing_token,
            "response_effect_command:second-remove",
        ),
    };
    let empty = store
        .remove_egress_restriction(&remove_second)
        .unwrap_or_else(|error| panic!("remove second: {error}"));
    assert!(empty.denied_destinations.is_empty());
    assert_eq!(
        store
            .remove_egress_restriction(&EgressRestrictionRemoveRequest {
                expected_generation: empty.generation,
                ..remove_second
            })
            .unwrap_or_else(|error| panic!("retry remove second: {error}")),
        empty
    );
}

#[test]
fn action_rebinding_and_stale_scheduler_fences_fail_closed() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("egress-fence.db");
    let now = now_unix_ms();
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let work = scheduled_action(&store, "action-a", "claim-a", now);
    let restriction = contribution("effect-a", &["server-a"], now + 60_000);
    let request = EgressRestrictionApplyRequest {
        key: key(),
        action_id: work.action_id.clone(),
        contribution: restriction.clone(),
        expected_generation: 0,
        scheduler_fencing_token: work.fencing_token,
        command: command(
            &work.action_id,
            &restriction,
            EffectOperation::Apply,
            work.fencing_token,
            "response_effect_command:apply",
        ),
    };
    let applied = store
        .apply_egress_restriction(&request)
        .unwrap_or_else(|error| panic!("apply restriction: {error}"));
    let mut command_collision = request.clone();
    command_collision.command.request.plan_hash = digest(b"rebound-plan");
    let collision = require_error(store.apply_egress_restriction(&command_collision));
    assert_eq!(collision.kind(), PortErrorKind::Conflict);
    let mut rebound_query = query(&request.command.request);
    rebound_query.contribution_hash = digest(b"rebound-contribution");
    let query_collision = require_error(store.load_egress_restriction_result(&rebound_query));
    assert_eq!(query_collision.kind(), PortErrorKind::Conflict);
    let rebound_action =
        ActionId::new("action-rebound").unwrap_or_else(|error| panic!("rebound action: {error}"));
    let mut rebound_request = request.clone();
    rebound_request.action_id = rebound_action.clone();
    rebound_request.command.request.action_id = rebound_action;
    let rebound = require_error(store.apply_egress_restriction(&rebound_request));
    assert_eq!(rebound.kind(), PortErrorKind::Conflict);
    drop(store);

    rusqlite::Connection::open(&path)
        .and_then(|connection| {
            connection.execute(
                "UPDATE security_scheduler_leases SET lease_expires_at = 0 WHERE action_id = 'action-a'",
                [],
            )?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("expire scheduler lease: {error}"));
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("reopen store: {error}"));
    let stale = require_error(
        store.remove_egress_restriction(&EgressRestrictionRemoveRequest {
            key: key(),
            action_id: work.action_id.clone(),
            effect_id: restriction.effect_id.clone(),
            expected_generation: applied.generation,
            scheduler_fencing_token: work.fencing_token,
            command: command(
                &work.action_id,
                &restriction,
                EffectOperation::Remove,
                work.fencing_token,
                "response_effect_command:remove",
            ),
        }),
    );
    assert_eq!(stale.kind(), PortErrorKind::Conflict);
    assert!(decision(&store, "server-a").denied);
}

#[test]
fn readiness_detects_corrupt_derived_generation() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("egress-corrupt.db");
    let now = now_unix_ms();
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let work = scheduled_action(&store, "action-a", "claim-a", now);
    let restriction = contribution("effect-a", &["server-a"], now + 60_000);
    store
        .apply_egress_restriction(&EgressRestrictionApplyRequest {
            key: key(),
            action_id: work.action_id.clone(),
            contribution: restriction.clone(),
            expected_generation: 0,
            scheduler_fencing_token: work.fencing_token,
            command: command(
                &work.action_id,
                &restriction,
                EffectOperation::Apply,
                work.fencing_token,
                "response_effect_command:readiness-apply",
            ),
        })
        .unwrap_or_else(|error| panic!("apply restriction: {error}"));
    store
        .ensure_egress_restrictions_ready()
        .unwrap_or_else(|error| panic!("readiness before corruption: {error}"));
    drop(store);

    corrupt_generation(&path);
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("reopen store: {error}"));
    let error = require_error(store.ensure_egress_restrictions_ready());
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

fn corrupt_generation(path: &Path) {
    rusqlite::Connection::open(path)
        .and_then(|connection| {
            connection.execute(
                "UPDATE security_egress_restriction_state SET generation = 0 WHERE session_id = 'session-a'",
                [],
            )?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("corrupt egress generation: {error}"));
}
