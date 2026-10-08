use chio_control_plane::security::adapters::effect_port::CapabilitySetSuspensionBackend;
use chio_quarantine::SchedulerTickRequest;
use chio_security_types::ports::{
    capability_set_suspension_version_hash, empty_capability_set_suspension_snapshot,
    issuance_freeze_installed_version_hash, CapabilitySetSuspensionKey,
    CapabilitySetSuspensionSpec, CapabilitySetSuspensionStore, EffectPort,
    LINEAGE_FENCE_RENEWAL_MARGIN_MS,
};

use super::*;

fn second_action() -> ActionId {
    ActionId::new("freeze-composition-second")
        .unwrap_or_else(|error| panic!("second action: {error}"))
}

fn second_plan(harness: &FenceLapseHarness) -> (ResponsePlan, ScheduledWork) {
    let first = &harness.plan;
    let original_freeze = &first.effects.as_slice()[0];
    let mut freeze: IssuanceFreezeSpec =
        serde_json::from_slice(original_freeze.canonical_contribution.as_bytes())
            .unwrap_or_else(|error| panic!("decode original freeze: {error}"));
    freeze.acquisition.request.action_id = second_action();
    let freeze_body = canonical_json_bytes(&freeze)
        .unwrap_or_else(|error| panic!("second freeze contribution: {error}"));
    let affected = RecordIdSet::new(first.affected_ids.as_slice().to_vec())
        .unwrap_or_else(|error| panic!("second affected set: {error}"));
    let affected_set_hash = response_affected_set_hash(&tenant(), &affected)
        .unwrap_or_else(|error| panic!("second affected-set hash: {error}"));
    let suspension_body = canonical_json_bytes(&CapabilitySetSuspensionSpec {
        affected_ids: affected,
    })
    .unwrap_or_else(|error| panic!("second suspension contribution: {error}"));
    let empty_suspensions = empty_capability_set_suspension_snapshot(CapabilitySetSuspensionKey {
        tenant_id: tenant(),
        affected_set_hash,
    })
    .unwrap_or_else(|error| panic!("empty second suspension: {error}"));
    let ttl_ms = PLAN_TTL_MS.saturating_mul(2);
    let plan = build_response_plan(ResponsePlanInput {
        execution: first.execution,
        action_id: second_action(),
        trigger_finding_id: record("freeze-composition-second-finding"),
        trigger_finding_hash: digest(b"freeze-composition-second-finding"),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("freeze-composition-second-receipt")
            .unwrap_or_else(|error| panic!("second finding receipt: {error}")),
        tenant_id: tenant(),
        policy_version: first.policy_version.clone(),
        policy_hash: first.policy_hash,
        affected_ids: first.affected_ids.as_slice().to_vec(),
        effects: vec![
            ResponseEffectSpec {
                kind: ResponseEffectKind::FreezeIssuance,
                target: original_freeze.target.clone(),
                canonical_contribution: CanonicalBody::new(freeze_body.clone())
                    .unwrap_or_else(|error| panic!("second freeze body: {error}")),
                contribution_hash: digest(&freeze_body),
                observed_base_version_hash: original_freeze.observed_base_version_hash,
            },
            ResponseEffectSpec {
                kind: ResponseEffectKind::SuspendCapabilitySet,
                target: ResponseTarget::CapabilitySet { affected_set_hash },
                canonical_contribution: CanonicalBody::new(suspension_body.clone())
                    .unwrap_or_else(|error| panic!("second suspension body: {error}")),
                contribution_hash: digest(&suspension_body),
                observed_base_version_hash: capability_set_suspension_version_hash(
                    &empty_suspensions,
                )
                .unwrap_or_else(|error| panic!("second suspension base: {error}")),
            },
        ],
        ttl_ms,
        created_at_unix_ms: first.created_at_unix_ms,
        operator_capability: OperatorCapabilityBinding {
            expires_at_unix_ms: first
                .created_at_unix_ms
                .saturating_add(ttl_ms)
                .saturating_add(60_000),
            ..first.operator_capability.clone()
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: first.submitter.clone(),
        reason_hash: first.reason_hash,
    })
    .unwrap_or_else(|error| panic!("build second plan: {error}"));
    let dispatch = prepare_response_dispatch(ResponseDispatchPreparationRequest {
        authorization_capability_hash: plan.operator_capability.capability_digest,
        plan: chio_security_types::FreshLiveAdmission::new(plan.clone())
            .unwrap_or_else(|error| panic!("second live plan: {error}")),
        dispatch_id: record("freeze-composition-second-dispatch"),
        governed_intent_hash: digest(b"freeze-composition-second-intent"),
        policy_decision_hash: digest(b"freeze-composition-second-decision"),
        admission_artifact_fingerprint: Some(digest(b"freeze-composition-second-artifact")),
        executor_authority_id: record("freeze-composition-authority"),
        executor_authority_generation: 1,
        approval: ResponseDispatchApproval::Automatic,
        authorized_at_unix_ms: first.created_at_unix_ms,
        initial_lease: ResponseDispatchLease {
            lease_owner_id: worker("freeze-composition-second-worker"),
            lease_expires_at_unix_ms: first.created_at_unix_ms.saturating_add(SCHEDULER_LEASE_MS),
        },
    })
    .unwrap_or_else(|error| panic!("prepare second dispatch: {error}"));
    claim_automatic_preparation(&harness.store, &plan, &dispatch);
    let ResponseDispatchCommitOutcome::Committed(committed) = harness
        .store
        .commit_dispatch(&dispatch)
        .unwrap_or_else(|error| panic!("commit second dispatch: {error}"))
    else {
        panic!("second dispatch unexpectedly existed");
    };
    (plan, committed.initial_work)
}

fn build_scheduler(
    harness: &FenceLapseHarness,
    store: Arc<SqliteSecurityStateStore>,
) -> LapseScheduler {
    let freezes: Arc<dyn IssuanceFreezeStore> = store.clone();
    let suspensions: Arc<dyn CapabilitySetSuspensionStore> = store.clone();
    let authority: Arc<dyn ResponseSchedulerStore> = store.clone();
    let clock: Arc<dyn Clock> = harness.clock.clone();
    let effects = ActiveResponseEffectPort::from_backends(vec![
        Arc::new(
            IssuanceFreezeBackend::new_with_scheduler(
                freezes,
                Arc::clone(&harness.blast),
                Arc::clone(&authority),
            )
            .with_clock(clock),
        ) as Arc<dyn ResponseEffectBackend>,
        Arc::new(CapabilitySetSuspensionBackend::new(suspensions)),
    ])
    .unwrap_or_else(|error| panic!("composition effect router: {error}"))
    .with_plan_authority(authority);
    let executor = ResponseExecutor::new(
        Arc::clone(&store),
        Arc::new(effects),
        Arc::new(AcceptedReceipts),
        Arc::new(DeliveredAlerts),
    );
    ResponseScheduler::new(
        store,
        Arc::new(executor),
        Arc::new(DeliveredHealth),
        SchedulerPolicy {
            lease_duration_ms: SCHEDULER_LEASE_MS,
            base_backoff_ms: 1_000,
            max_backoff_ms: 1_000,
            operator_page_threshold_ms: 3_600_000,
            max_claims: 4,
        },
    )
    .unwrap_or_else(|error| panic!("composition scheduler: {error}"))
}

fn response(store: &SqliteSecurityStateStore, action_id: ActionId) -> ResponseSnapshot {
    let record = store
        .load_plan(&ResponsePlanKey {
            tenant_id: tenant(),
            action_id,
        })
        .unwrap_or_else(|error| panic!("load composition response: {error}"))
        .unwrap_or_else(|| panic!("composition response missing"));
    chio_quarantine::decode_response_record(&record)
        .unwrap_or_else(|error| panic!("decode composition response: {error}"))
}

fn tick(
    harness: &FenceLapseHarness,
    scheduler: &LapseScheduler,
    at: u64,
    label: &str,
) -> Vec<SchedulerWorkOutcome> {
    harness.clock.set(at);
    scheduler
        .tick(&SchedulerTickRequest {
            tenant_id: tenant(),
            claim_id: record(format!("freeze-composition-claim-{label}")),
            lease_owner_id: worker("freeze-composition-restarted-worker"),
            now_unix_ms: at,
        })
        .unwrap_or_else(|error| panic!("composition tick {label}: {error}"))
}

fn raw_freeze_state(
    harness: &FenceLapseHarness,
) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let connection = rusqlite::Connection::open(harness._directory.path().join("fence-lapse.db"))
        .unwrap_or_else(|error| panic!("open freeze state snapshot: {error}"));
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name LIKE 'security_%' ORDER BY name",
    ).unwrap_or_else(|error| panic!("prepare freeze table names: {error}"));
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap_or_else(|error| panic!("freeze table names: {error}"))
        .map(|row| row.unwrap_or_else(|error| panic!("freeze table name: {error}")))
        .collect::<Vec<_>>();
    names
        .into_iter()
        .map(|name| {
            assert!(name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
            let mut statement = connection
                .prepare(&format!("SELECT * FROM {name} ORDER BY rowid"))
                .unwrap_or_else(|error| panic!("prepare raw freeze {name}: {error}"));
            let count = statement.column_count();
            let rows = statement
                .query_map([], |row| {
                    (0..count)
                        .map(|index| row.get::<_, rusqlite::types::Value>(index))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap_or_else(|error| panic!("read raw freeze {name}: {error}"))
                .map(|row| row.unwrap_or_else(|error| panic!("raw freeze {name}: {error}")))
                .collect();
            (name, rows)
        })
        .collect()
}

#[test]
fn same_lineage_plans_survive_renewal_restart_and_the_first_freeze_lift() {
    let harness = FenceLapseHarness::new();
    let (second, second_work) = second_plan(&harness);
    let scheduler = build_scheduler(&harness, Arc::clone(&harness.store));
    assert_eq!(
        harness.plan.effects.as_slice()[0].observed_base_version_hash,
        second.effects.as_slice()[0].observed_base_version_hash,
        "both independently authorized plans observed the same empty lineage freeze"
    );
    assert!(second.expires_at_unix_ms > harness.plan.expires_at_unix_ms);
    harness.activate(&scheduler);
    let first_fence = harness
        .local_fence()
        .unwrap_or_else(|| panic!("first maintained fence missing"));
    assert!(
        first_fence.expires_at_unix_ms > harness.created_at().saturating_add(INITIAL_FENCE_MS),
        "normal scheduler maintenance already renewed the first contribution"
    );
    let second_at = harness.created_at().saturating_add(2_001);
    harness.clock.set(second_at);
    let outcome = scheduler
        .process(&second_work, second_at)
        .unwrap_or_else(|error| panic!("normal second executor: {error}"));
    assert_eq!(harness.local_fence(), Some(first_fence.clone()));
    assert_eq!(harness.external_fence(), Some(first_fence));
    assert_eq!(
        outcome_label(&outcome),
        "retry:response.execution_incomplete",
        "a second authorized lineage freeze must install before the real executor continues to its suspension"
    );
    let current = response(&harness.store, second_action());
    assert_eq!(
        current.effect_progress(&second.effects.as_slice()[0].effect_id),
        Some(ResponseEffectProgress::Applied)
    );
    assert_eq!(
        current.effect_progress(&second.effects.as_slice()[1].effect_id),
        Some(ResponseEffectProgress::Planned),
        "the executor has not bypassed its leading freeze"
    );
    let outcomes = tick(
        &harness,
        &scheduler,
        harness.created_at().saturating_add(4_000),
        "activate-second",
    );
    assert_eq!(
        outcomes,
        vec![SchedulerWorkOutcome::Completed {
            action_id: second_action(),
            state: ResponseState::Active,
        }]
    );
    drop(scheduler);
    let clock: Arc<dyn Clock> = harness.clock.clone();
    let reopened = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            harness._directory.path().join("fence-lapse.db"),
            clock,
        )
        .unwrap_or_else(|error| panic!("restart composition store: {error}")),
    );
    let restarted = build_scheduler(&harness, Arc::clone(&reopened));
    for round in 0..2 {
        let contributions = harness.local_contributions();
        assert_eq!(contributions.len(), 2);
        let at = contributions
            .iter()
            .map(|entry| entry.external_fence.expires_at_unix_ms)
            .max()
            .unwrap_or_else(|| panic!("renewable fences missing"))
            .saturating_sub(LINEAGE_FENCE_RENEWAL_MARGIN_MS)
            .saturating_add(1);
        let outcomes = tick(&harness, &restarted, at, &format!("maintenance-{round}"));
        assert_eq!(
            outcomes.len(),
            2,
            "both fences reached their renewal horizon"
        );
        assert!(outcomes.iter().all(|outcome| matches!(
            outcome,
            SchedulerWorkOutcome::Completed {
                state: ResponseState::Active,
                ..
            }
        )));
        for entry in harness.local_contributions() {
            let actual = LineageFenceStore::query(
                reopened.as_ref(),
                &TenantScopedId {
                    tenant_id: tenant(),
                    id: record(entry.action_id.as_str()),
                },
            )
            .unwrap_or_else(|error| panic!("read renewed external fence: {error}"));
            assert_eq!(actual, Some(entry.external_fence));
        }
    }
    let lift_at = harness.plan.expires_at_unix_ms.saturating_add(1_000);
    assert!(lift_at < second.expires_at_unix_ms);
    let outcomes = tick(&harness, &restarted, lift_at, "lift-first");
    assert_eq!(
        outcomes,
        vec![SchedulerWorkOutcome::Completed {
            action_id: action(),
            state: ResponseState::Lifted,
        }]
    );
    assert_eq!(response(&reopened, action()).state, ResponseState::Lifted);
    assert_eq!(
        response(&reopened, second_action()).state,
        ResponseState::Active
    );
    let remaining = harness.local_contributions();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].action_id, second_action());
    assert_eq!(
        remaining[0].effect_id,
        second.effects.as_slice()[0].effect_id
    );
    assert!(remaining[0].external_fence.expires_at_unix_ms > lift_at);
    assert_eq!(
        harness.external_fence(),
        None,
        "only the first action's fence was released"
    );
    assert_eq!(
        LineageFenceStore::query(
            reopened.as_ref(),
            &TenantScopedId {
                tenant_id: tenant(),
                id: record(second_action().as_str())
            },
        )
        .unwrap_or_else(|error| panic!("remaining external fence: {error}")),
        Some(remaining[0].external_fence.clone())
    );
    let ResponseTarget::CapabilitySet { affected_set_hash } = second.effects.as_slice()[1].target
    else {
        panic!("second capability-set target missing");
    };
    let suspension = reopened
        .load_capability_set_suspensions(&CapabilitySetSuspensionKey {
            tenant_id: tenant(),
            affected_set_hash,
        })
        .unwrap_or_else(|error| panic!("remaining capability suspension: {error}"))
        .unwrap_or_else(|| panic!("second suspension missing after first lift"));
    assert_eq!(suspension.contributions.len(), 1);
    assert_eq!(
        suspension.contributions.as_slice()[0].action_id,
        second_action()
    );
    assert_eq!(
        suspension.contributions.as_slice()[0].effect_id,
        second.effects.as_slice()[1].effect_id
    );
}

#[test]
fn lifted_freeze_refuses_fresh_apply_while_original_window_and_lease_are_live() {
    let harness = FenceLapseHarness::new();
    let authority: Arc<dyn ResponseSchedulerStore> = harness.store.clone();
    let effects = ActiveResponseEffectPort::from_backends(vec![
        Arc::new(harness.backend()) as Arc<dyn ResponseEffectBackend>
    ])
    .unwrap_or_else(|error| panic!("freeze finality router: {error}"))
    .with_plan_authority(authority);
    let planned = &harness.plan.effects.as_slice()[0];
    let apply = EffectRequest {
        tenant_id: tenant(),
        action_id: action(),
        plan_hash: harness.plan.plan_hash,
        effect_id: planned.effect_id.clone(),
        effect_kind: planned.kind,
        target: planned.target.clone(),
        plan_expires_at_unix_ms: harness.plan.expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record("response_effect_command:freeze-finality-apply"),
        expected_version_hash: planned.observed_base_version_hash,
        scheduler_lease_owner_id: harness.initial_work.lease_owner_id.clone(),
        scheduler_fencing_token: harness.initial_work.fencing_token,
        canonical_contribution: planned.canonical_contribution.clone(),
        contribution_hash: planned.contribution_hash,
    };
    let applied = effects
        .execute(&apply)
        .unwrap_or_else(|error| panic!("original freeze Apply: {error}"));
    assert!(applied.applied);
    let current = harness.local_contributions();
    assert_eq!(current.len(), 1);
    let installed = issuance_freeze_installed_version_hash(&key(), &current[0])
        .unwrap_or_else(|error| panic!("exact installed freeze hash: {error}"));
    assert_eq!(installed, applied.resulting_version_hash);
    let mut remove = apply.clone();
    remove.operation = EffectOperation::Remove;
    remove.expected_version_hash = installed;
    remove.idempotency_key = record("response_effect_command:freeze-finality-remove");
    let removed = effects
        .execute(&remove)
        .unwrap_or_else(|error| panic!("original freeze Remove: {error}"));
    assert!(!removed.applied);
    assert!(harness.local_contributions().is_empty());
    assert_eq!(harness.external_fence(), None);
    let before = harness.response();
    let pending = harness
        .store
        .load_pending_issuance_freeze_release(&key(), &action(), &planned.effect_id)
        .unwrap_or_else(|error| panic!("pending freeze release: {error}"));
    assert_eq!(pending, None);
    let completed = harness
        .store
        .load_completed_issuance_freeze_release(
            &key(),
            &action(),
            &planned.effect_id,
            harness.plan.plan_hash,
        )
        .unwrap_or_else(|error| panic!("completed freeze release: {error}"))
        .unwrap_or_else(|| panic!("genuine completed Remove evidence missing"));
    assert_eq!(completed.request, remove);
    assert_eq!(completed.result, removed);
    let original_spec: IssuanceFreezeSpec =
        serde_json::from_slice(apply.canonical_contribution.as_bytes())
            .unwrap_or_else(|error| panic!("original freeze spec: {error}"));
    assert!(harness.clock.now() < original_spec.acquisition.expires_at_unix_ms);
    assert!(harness.clock.now() < apply.plan_expires_at_unix_ms);
    assert!(harness.clock.now() < harness.initial_work.lease_expires_at_unix_ms);
    harness
        .store
        .validate_lease(&harness.initial_work)
        .unwrap_or_else(|error| panic!("still-live original lease: {error}"));
    let durable_before = raw_freeze_state(&harness);
    let mut fresh = apply;
    fresh.idempotency_key = record("response_effect_command:freeze-finality-fresh-apply");
    let refused = effects.execute(&fresh).err().unwrap_or_else(|| {
        panic!("a lifted freeze was admitted again under live original authority")
    });
    assert_eq!(refused.kind(), PortErrorKind::Conflict);
    assert_eq!(refused.code().as_str(), "store.conflict");
    assert_eq!(raw_freeze_state(&harness), durable_before);
    assert_eq!(harness.response(), before);
    assert!(harness.local_contributions().is_empty());
    assert_eq!(harness.external_fence(), None);
    assert_eq!(
        effects
            .load_result(&query(&fresh))
            .unwrap_or_else(|error| panic!("fresh freeze readback: {error}")),
        EffectExecutionStatus::NotExecuted
    );
    assert_eq!(
        effects
            .execute(&remove)
            .unwrap_or_else(|error| panic!("exact Remove replay: {error}")),
        removed
    );
    assert_eq!(raw_freeze_state(&harness), durable_before);
    assert_eq!(
        harness
            .store
            .load_completed_issuance_freeze_release(
                &key(),
                &action(),
                &planned.effect_id,
                harness.plan.plan_hash
            )
            .unwrap_or_else(|error| panic!("unchanged completed release: {error}")),
        Some(completed)
    );
}
