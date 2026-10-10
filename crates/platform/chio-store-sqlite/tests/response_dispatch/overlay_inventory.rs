use super::*;

#[test]
fn overlay_inventory_rejects_unreadable_scheduler_retry_schema() {
    for damage in [
        "DROP TABLE security_scheduler_retries",
        "ALTER TABLE security_scheduler_retries RENAME COLUMN action_id TO damaged_action_id",
    ] {
        let directory = chio_test_support::private_tempdir()
            .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
        let path = directory.path().join("inventory-retry-schema.db");
        let store = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("security store open failed: {error}"));
        let inventory = store
            .active_defense_overlay_inventory()
            .unwrap_or_else(|error| panic!("healthy inventory failed: {error}"));
        assert!(!inventory.has_active_contributions());
        let connection = rusqlite::Connection::open(&path)
            .unwrap_or_else(|error| panic!("inventory fault connection failed: {error}"));
        connection
            .execute_batch(damage)
            .unwrap_or_else(|error| panic!("damage retry schema failed: {error}"));

        let error = rejected(
            store.active_defense_overlay_inventory(),
            "inventory silently accepted unreadable scheduler retry state",
        );
        assert_eq!(error.kind(), PortErrorKind::Unavailable);
    }
}

use chio_security_types::ports::{
    containment_installed_version_hash, containment_overlay_version_hash,
    containment_session_target, empty_session_throttle_snapshot, predict_containment_overlay_apply,
    predict_session_throttle_apply, session_throttle_installed_version_hash,
    session_throttle_version_hash, ContainmentOverlayCommand, ContainmentOverlayStore,
    EffectOperation, EffectRequest, EffectResult, OverlayApplyRequest, OverlayContribution,
    OverlayContributions, OverlaySnapshot, SchedulerWorkKey, SessionThrottleApplyRequest,
    SessionThrottleCommand, SessionThrottleContribution, SessionThrottleKey, SessionThrottleLimits,
    SessionThrottleStore,
};

const INVENTORY_NOW: u64 = 1_000_000;

fn open_inventory_store(
    path: &std::path::Path,
) -> (
    Arc<SqliteSecurityStateStore>,
    Arc<MutableSecurityStateClock>,
) {
    let clock = Arc::new(MutableSecurityStateClock::new(INVENTORY_NOW));
    let store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            path,
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("inventory store open failed: {error}")),
    );
    (store, clock)
}

fn inventory_empty_overlay(tenant_id: &TenantId) -> OverlaySnapshot {
    OverlaySnapshot {
        target: containment_session_target(
            tenant_id,
            &SessionId::new("inventory-session")
                .unwrap_or_else(|error| panic!("inventory session id: {error}")),
        )
        .unwrap_or_else(|error| panic!("inventory containment target: {error}")),
        generation: 0,
        effective_posture_rank: 0,
        active_contributions: OverlayContributions::new(Vec::new())
            .unwrap_or_else(|error| panic!("inventory empty contributions: {error}")),
        highest_fencing_token: 0,
    }
}

fn inventory_throttle_key(tenant_id: &TenantId) -> SessionThrottleKey {
    SessionThrottleKey {
        tenant_id: tenant_id.clone(),
        session_id: SessionId::new("inventory-session")
            .unwrap_or_else(|error| panic!("inventory throttle session id: {error}")),
    }
}

fn inventory_throttle_limits() -> SessionThrottleLimits {
    SessionThrottleLimits {
        window_ms: 1_000,
        max_invocations: 2,
    }
}

fn claim_inventory_response(
    store: &Arc<SqliteSecurityStateStore>,
    tenant: &str,
    action: &str,
) -> (chio_security_types::ResponsePlan, ScheduledWork) {
    let tenant_id =
        TenantId::new(tenant).unwrap_or_else(|error| panic!("inventory tenant id: {error}"));
    let session_id = SessionId::new("inventory-session")
        .unwrap_or_else(|error| panic!("inventory session id: {error}"));
    let containment = CanonicalBody::new(b"{\"posture_rank\":2}".to_vec())
        .unwrap_or_else(|error| panic!("inventory containment body: {error}"));
    let throttle = CanonicalBody::new(
        chio_core::canonical_json_bytes(&inventory_throttle_limits())
            .unwrap_or_else(|error| panic!("inventory throttle encoding: {error}")),
    )
    .unwrap_or_else(|error| panic!("inventory throttle body: {error}"));
    let empty_throttle = empty_session_throttle_snapshot(inventory_throttle_key(&tenant_id))
        .unwrap_or_else(|error| panic!("inventory empty throttle: {error}"));
    let created_at_unix_ms = INVENTORY_NOW - 1_000;
    let plan = build_response_plan(ResponsePlanInput {
        execution: chio_security_types::ResponseExecutionBinding::new(
            chio_security_types::ResponseExecutionMode::Live,
        ),
        action_id: ActionId::new(action)
            .unwrap_or_else(|error| panic!("inventory action id: {error}")),
        trigger_finding_id: record_id("inventory-finding"),
        trigger_finding_hash: digest(31),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("inventory-finding-receipt")
            .unwrap_or_else(|error| panic!("inventory finding receipt: {error}")),
        tenant_id: tenant_id.clone(),
        policy_version: record_id("inventory-policy"),
        policy_hash: digest(32),
        affected_ids: vec![record_id("inventory-affected")],
        effects: vec![
            ResponseEffectSpec {
                kind: ResponseEffectKind::SuspendSession,
                target: ResponseTarget::Session {
                    session_id: session_id.clone(),
                },
                contribution_hash: Digest32::new(
                    *chio_core::sha256(containment.as_bytes()).as_bytes(),
                ),
                canonical_contribution: containment,
                observed_base_version_hash: containment_overlay_version_hash(
                    &inventory_empty_overlay(&tenant_id),
                )
                .unwrap_or_else(|error| panic!("inventory containment version: {error}")),
            },
            ResponseEffectSpec {
                kind: ResponseEffectKind::ThrottleSession,
                target: ResponseTarget::Session { session_id },
                contribution_hash: Digest32::new(
                    *chio_core::sha256(throttle.as_bytes()).as_bytes(),
                ),
                canonical_contribution: throttle,
                observed_base_version_hash: session_throttle_version_hash(&empty_throttle)
                    .unwrap_or_else(|error| panic!("inventory throttle version: {error}")),
            },
        ],
        ttl_ms: 120_000,
        created_at_unix_ms,
        operator_capability: OperatorCapabilityBinding {
            capability_id: record_id("inventory-capability"),
            capability_digest: digest(30),
            expires_at_unix_ms: created_at_unix_ms + 120_000,
            executor_subject: record_id("inventory-executor"),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: record_id("inventory-submitter"),
        reason_hash: digest(33),
    })
    .unwrap_or_else(|error| panic!("inventory plan build failed: {error}"));
    let machine = ResponseStateMachine::new(Arc::clone(store));
    let planned = machine
        .create(
            chio_security_types::FreshLiveAdmission::new(plan.clone())
                .unwrap_or_else(|error| panic!("inventory live admission: {error}")),
        )
        .unwrap_or_else(|error| panic!("inventory response creation failed: {error}"));
    machine
        .transition(
            &planned,
            &ResponseTransitionRequest {
                expected_generation: planned.generation,
                target_state: ResponseState::Applying,
                occurred_at_unix_ms: created_at_unix_ms + 1,
                applying_lease_expires_at_unix_ms: Some(INVENTORY_NOW - 1),
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("inventory response transition failed: {error}"));
    let work = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id,
            claim_id: record_id(&format!("inventory-claim:{tenant}:{action}")),
            lease_owner_id: LeaseOwnerId::new("inventory-worker")
                .unwrap_or_else(|error| panic!("inventory lease owner: {error}")),
            now_unix_ms: INVENTORY_NOW,
            lease_expires_at_unix_ms: INVENTORY_NOW + 60_000,
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("inventory scheduler claim failed: {error}"));
    assert_eq!(work.len(), 1);
    let work = work
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("inventory scheduler claim missing"));
    assert_eq!(work.action_id, plan.action_id);
    (plan, work)
}

fn apply_inventory_containment(
    store: &SqliteSecurityStateStore,
    plan: &chio_security_types::ResponsePlan,
    work: &ScheduledWork,
) {
    let current = inventory_empty_overlay(&plan.tenant_id);
    let effect = &plan.effects.as_slice()[0];
    let contribution = OverlayContribution {
        effect_id: effect.effect_id.clone(),
        posture_rank: 2,
        contribution_hash: effect.contribution_hash,
        expires_at_unix_ms: Some(plan.expires_at_unix_ms),
    };
    let resulting_snapshot =
        predict_containment_overlay_apply(&current, &contribution, work.fencing_token)
            .unwrap_or_else(|error| panic!("predict inventory containment: {error}"));
    store
        .apply_contribution(&OverlayApplyRequest {
            target: current.target.clone(),
            action_id: plan.action_id.clone(),
            contribution: contribution.clone(),
            expected_generation: current.generation,
            scheduler_fencing_token: work.fencing_token,
            command: ContainmentOverlayCommand {
                request: inventory_effect_request(plan, work, 0),
                result: EffectResult {
                    effect_id: effect.effect_id.clone(),
                    resulting_version_hash: containment_installed_version_hash(
                        &current.target,
                        &contribution,
                    )
                    .unwrap_or_else(|error| panic!("inventory installed containment: {error}")),
                    applied: true,
                },
                resulting_snapshot,
            },
        })
        .unwrap_or_else(|error| panic!("inventory containment apply failed: {error}"));
}

fn apply_inventory_throttle(
    store: &SqliteSecurityStateStore,
    plan: &chio_security_types::ResponsePlan,
    work: &ScheduledWork,
) {
    let key = inventory_throttle_key(&plan.tenant_id);
    let current = empty_session_throttle_snapshot(key.clone())
        .unwrap_or_else(|error| panic!("inventory empty throttle: {error}"));
    let effect = &plan.effects.as_slice()[1];
    let contribution = SessionThrottleContribution {
        effect_id: effect.effect_id.clone(),
        limits: inventory_throttle_limits(),
        contribution_hash: effect.contribution_hash,
        expires_at_unix_ms: plan.expires_at_unix_ms,
    };
    let resulting_snapshot =
        predict_session_throttle_apply(&current, &contribution, work.fencing_token)
            .unwrap_or_else(|error| panic!("predict inventory throttle: {error}"));
    store
        .apply_session_throttle(&SessionThrottleApplyRequest {
            key,
            action_id: plan.action_id.clone(),
            contribution: contribution.clone(),
            expected_generation: current.generation,
            scheduler_fencing_token: work.fencing_token,
            command: SessionThrottleCommand {
                request: inventory_effect_request(plan, work, 1),
                result: EffectResult {
                    effect_id: effect.effect_id.clone(),
                    resulting_version_hash: session_throttle_installed_version_hash(
                        &current.key,
                        &contribution,
                    )
                    .unwrap_or_else(|error| panic!("inventory installed throttle: {error}")),
                    applied: true,
                },
                resulting_snapshot,
            },
        })
        .unwrap_or_else(|error| panic!("inventory throttle apply failed: {error}"));
}

fn inventory_effect_request(
    plan: &chio_security_types::ResponsePlan,
    work: &ScheduledWork,
    index: usize,
) -> EffectRequest {
    let effect = &plan.effects.as_slice()[index];
    EffectRequest {
        tenant_id: plan.tenant_id.clone(),
        action_id: plan.action_id.clone(),
        plan_hash: plan.plan_hash,
        effect_id: effect.effect_id.clone(),
        effect_kind: effect.kind,
        target: effect.target.clone(),
        plan_expires_at_unix_ms: plan.expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record_id(&format!(
            "response_effect_command:inventory:{}:{}:{index}",
            plan.tenant_id.as_str(),
            plan.action_id.as_str(),
        )),
        expected_version_hash: effect.observed_base_version_hash,
        scheduler_lease_owner_id: work.lease_owner_id.clone(),
        scheduler_fencing_token: work.fencing_token,
        canonical_contribution: effect.canonical_contribution.clone(),
        contribution_hash: effect.contribution_hash,
    }
}

fn record_inventory_retry(store: &SqliteSecurityStateStore, work: ScheduledWork) {
    store
        .record_retry(&SchedulerRetryRequest {
            transition_id: record_id(&format!(
                "inventory-retry:{}:{}",
                work.tenant_id.as_str(),
                work.action_id.as_str(),
            )),
            work,
            expected_attempts: 0,
            error_code: ErrorCode::new("response.rollback_partial")
                .unwrap_or_else(|error| panic!("inventory retry code: {error}")),
            first_failure_at_unix_ms: INVENTORY_NOW,
            now_unix_ms: INVENTORY_NOW,
            not_before_unix_ms: INVENTORY_NOW + 1_000,
            health_event_id: None,
        })
        .unwrap_or_else(|error| panic!("inventory retry recording failed: {error}"));
}

#[test]
fn overlay_inventory_retries_are_tenant_scoped_and_exclude_unrelated_work() {
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let (store, _) = open_inventory_store(&directory.path().join("inventory-retry-isolation.db"));
    let (plan, contributing) = claim_inventory_response(&store, "tenant-a", "shared-action");
    apply_inventory_containment(&store, &plan, &contributing);
    let (_, foreign) = claim_inventory_response(&store, "tenant-b", "shared-action");
    record_inventory_retry(&store, foreign);
    let (_, unrelated) = claim_inventory_response(&store, "tenant-a", "unrelated-action");
    record_inventory_retry(&store, unrelated);
    let inventory = store
        .active_defense_overlay_inventory()
        .unwrap_or_else(|error| panic!("inventory with unrelated retries failed: {error}"));
    assert_eq!(inventory.containment_contributions, 1);
    assert_eq!(inventory.retrying_contributing_responses, 0);
    assert!(inventory.has_active_contributions());

    record_inventory_retry(&store, contributing);
    let inventory = store
        .active_defense_overlay_inventory()
        .unwrap_or_else(|error| panic!("inventory with contributing retry failed: {error}"));
    assert_eq!(inventory.retrying_contributing_responses, 1);
}

#[test]
fn overlay_inventory_counts_each_response_retry_once_until_cleared() {
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let (store, clock) = open_inventory_store(&directory.path().join("inventory-retry-clear.db"));
    let (plan, work) = claim_inventory_response(&store, "tenant-a", "multi-family-action");
    apply_inventory_containment(&store, &plan, &work);
    apply_inventory_throttle(&store, &plan, &work);
    record_inventory_retry(&store, work);
    let inventory = store
        .active_defense_overlay_inventory()
        .unwrap_or_else(|error| panic!("inventory with multiple families failed: {error}"));
    assert_eq!(inventory.containment_contributions, 1);
    assert_eq!(inventory.session_throttle_contributions, 1);
    assert_eq!(inventory.retrying_contributing_responses, 1);

    let expired_now = plan.expires_at_unix_ms + 1;
    clock.set(expired_now);
    let inventory = store
        .active_defense_overlay_inventory()
        .unwrap_or_else(|error| panic!("inventory with expired contributions failed: {error}"));
    assert_eq!(inventory.retrying_contributing_responses, 1);
    assert!(inventory.has_active_contributions());
    let work = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: plan.tenant_id.clone(),
            claim_id: record_id("inventory-clear-claim"),
            lease_owner_id: LeaseOwnerId::new("inventory-clear-worker")
                .unwrap_or_else(|error| panic!("inventory clear lease owner: {error}")),
            now_unix_ms: expired_now,
            lease_expires_at_unix_ms: expired_now + 60_000,
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("inventory retry recovery claim failed: {error}"));
    assert_eq!(work.len(), 1);
    store
        .release_lease(&SchedulerLeaseReleaseRequest {
            work: work
                .into_iter()
                .next()
                .unwrap_or_else(|| panic!("inventory clear claim missing")),
            clear_retry_state: true,
            transition_id: record_id("inventory-clear-release"),
        })
        .unwrap_or_else(|error| panic!("inventory retry clear failed: {error}"));
    assert_eq!(
        store
            .load_retry(&SchedulerWorkKey {
                tenant_id: plan.tenant_id,
                action_id: plan.action_id,
            })
            .unwrap_or_else(|error| panic!("inventory cleared retry read failed: {error}")),
        None,
    );
    let inventory = store
        .active_defense_overlay_inventory()
        .unwrap_or_else(|error| panic!("inventory after retry clear failed: {error}"));
    assert_eq!(inventory.retrying_contributing_responses, 0);
    assert_eq!(inventory.containment_contributions, 1);
    assert_eq!(inventory.session_throttle_contributions, 1);
    assert!(inventory.has_active_contributions());
}

#[test]
fn overlay_inventory_rejects_corrupt_contribution_state() {
    let directory = chio_test_support::private_tempdir()
        .unwrap_or_else(|error| panic!("temporary directory creation failed: {error}"));
    let path = directory.path().join("inventory-corrupt-overlay.db");
    let (store, _) = open_inventory_store(&path);
    let (plan, work) = claim_inventory_response(&store, "tenant-a", "corrupt-overlay-action");
    apply_inventory_containment(&store, &plan, &work);
    assert!(store
        .active_defense_overlay_inventory()
        .unwrap_or_else(|error| panic!("inventory before corruption failed: {error}"))
        .has_active_contributions());
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("inventory corruption connection failed: {error}"));
    connection
        .execute(
            "UPDATE security_overlay_state SET generation = -1 WHERE tenant_id = ?1",
            [plan.tenant_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("inventory state corruption failed: {error}"));

    let error = rejected(
        store.active_defense_overlay_inventory(),
        "inventory silently accepted corrupt contribution state",
    );
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}
