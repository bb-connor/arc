use super::*;
use chio_kernel::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetCaptureHoldRequest,
    BudgetCaptureInvocationRequest, BudgetInvocationQuota, BudgetInvocationReservationState,
    BudgetQuotaKey, BudgetQuotaProfile, BudgetReconcileHoldRequest, BudgetReleaseHoldRequest,
    BudgetReverseHoldRequest,
};
use chio_kernel::supplemental_quota::CanonicalRevocationSet;
use chio_kernel::InMemoryBudgetStore;

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

fn usage_record(
    capability_id: &str,
    grant_index: u32,
    invocation_count: u32,
    updated_at: i64,
    seq: u64,
    total_cost_exposed: u64,
    total_cost_realized_spend: u64,
) -> BudgetUsageRecord {
    BudgetUsageRecord {
        capability_id: capability_id.to_string(),
        grant_index,
        invocation_count,
        updated_at,
        seq,
        total_cost_exposed,
        total_cost_realized_spend,
    }
}

fn assert_usage_totals(record: &BudgetUsageRecord, exposed: u64, realized: u64) {
    assert_eq!(record.total_cost_exposed, exposed);
    assert_eq!(record.total_cost_realized_spend, realized);
    assert_eq!(record.committed_cost_units().unwrap(), exposed + realized);
}

fn authority(authority_id: &str, lease_id: &str, lease_epoch: u64) -> BudgetEventAuthority {
    BudgetEventAuthority {
        authority_id: authority_id.to_string(),
        lease_id: lease_id.to_string(),
        lease_epoch,
    }
}

fn persisted_quota(
    profile: BudgetQuotaProfile,
    owner_id: &str,
    grant_index: Option<u32>,
    max_invocations: u32,
) -> BudgetInvocationQuota {
    let key =
        BudgetQuotaKey::from_persisted_parts(profile, owner_id.to_string(), grant_index).unwrap();
    BudgetInvocationQuota::from_persisted_parts(key, max_invocations).unwrap()
}

fn composite_authorize_input(
    hold_id: &str,
    event_id: &str,
    aggregate_max: u32,
) -> SqliteCompositeAuthorizeInput {
    SqliteCompositeAuthorizeInput {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        requested_exposure_units: 100,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(1_000),
        hold_id: hold_id.to_string(),
        event_id: event_id.to_string(),
        authority: None,
        invocation_quotas: vec![
            persisted_quota(BudgetQuotaProfile::GrantInvocation, "leaf", Some(0), 2),
            persisted_quota(
                BudgetQuotaProfile::AggregateCapabilityInvocation,
                "leaf",
                None,
                aggregate_max,
            ),
            persisted_quota(
                BudgetQuotaProfile::SupplementalBrokerExecution,
                &"22".repeat(32),
                None,
                2,
            ),
        ],
        revocation_set: CanonicalRevocationSet::from_persisted_parts(
            vec!["leaf".to_string()],
            "baaba5816d4ef1572cfbb26a183f273ea200681234cdd767ab965b9efbaeb12f".to_string(),
        )
        .unwrap(),
        authorization_artifact_digests: Vec::new(),
    }
}

fn import_integrity_record(event_id: &str, event_seq: u64) -> BudgetMutationRecord {
    BudgetMutationRecord {
        event_id: event_id.to_string(),
        hold_id: None,
        capability_id: "cap-import-integrity".to_string(),
        grant_index: 0,
        kind: BudgetMutationKind::IncrementInvocation,
        allowed: Some(true),
        recorded_at: 100,
        event_seq,
        usage_seq: Some(event_seq),
        exposure_units: 0,
        realized_spend_units: 0,
        max_invocations: Some(10),
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_counts_after: Vec::new(),
        invocation_state: BudgetInvocationReservationState::Captured,
        monetary_state: BudgetMonetaryHoldState::None,
        revocation_set: None,
        total_cost_exposed_after: 0,
        total_cost_realized_spend_after: 0,
        authority: Some(authority("budget-primary", "lease-1", 1)),
    }
}

fn replication_floor(store: &SqliteBudgetStore) -> i64 {
    store
        .connection()
        .unwrap()
        .query_row(
            "SELECT next_seq FROM budget_replication_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn persisted_hold_disposition(store: &SqliteBudgetStore, hold_id: &str) -> HoldDisposition {
    let disposition = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT disposition FROM budget_authorization_holds WHERE hold_id = ?1",
            params![hold_id],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    HoldDisposition::parse(&disposition).unwrap()
}

#[test]
fn sqlite_budget_store_persists_across_reopen() {
    let path = unique_db_path("chio-budgets");
    {
        let store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store.try_increment("cap-1", 0, Some(2)).unwrap());
        assert!(store.try_increment("cap-1", 0, Some(2)).unwrap());
        assert!(!store.try_increment("cap-1", 0, Some(2)).unwrap());
    }

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    let records = reopened.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].invocation_count, 2);

    let _ = fs::remove_file(path);
}

#[test]
fn composite_authorization_is_atomic_idempotent_and_restart_durable_sqlite() {
    let path = unique_db_path("chio-composite-budget-restart");
    let first_request = composite_authorize_input("hold-composite-1", "event-composite-1", 1);
    let first = {
        let store = SqliteBudgetStore::open(&path).unwrap();
        store
            .authorize_composite_hold(first_request.clone())
            .unwrap()
    };
    let BudgetAuthorizeHoldDecision::Authorized(first) = first else {
        panic!("first composite authorization should pass");
    };
    assert_eq!(first.invocation_counts_after.len(), 3);
    assert!(first
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 1 && usage.captured_invocations_after == 0
        ));
    assert_eq!(
        first.invocation_state,
        BudgetInvocationReservationState::Authorized
    );

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    let retry = reopened.authorize_composite_hold(first_request).unwrap();
    assert_eq!(
        retry,
        BudgetAuthorizeHoldDecision::Authorized(first.clone())
    );

    let denied = reopened
        .authorize_composite_hold(composite_authorize_input(
            "hold-composite-2",
            "event-composite-2",
            1,
        ))
        .unwrap();
    let BudgetAuthorizeHoldDecision::Denied(denied) = denied else {
        panic!("exhausted aggregate quota should deny");
    };
    assert_eq!(denied.invocation_counts_after.len(), 3);
    assert!(denied
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 1 && usage.captured_invocations_after == 0
        ));
    assert_eq!(
        denied.invocation_state,
        BudgetInvocationReservationState::Denied
    );
    assert_eq!(
        reopened
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        1
    );

    let _ = fs::remove_file(path);
}

#[test]
fn composite_quota_maximum_is_pinned_even_by_a_denial() {
    let path = unique_db_path("chio-composite-budget-pinned-maximum");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let denied = store
        .authorize_composite_hold(composite_authorize_input(
            "hold-pinned-1",
            "event-pinned-1",
            0,
        ))
        .unwrap();
    assert!(!denied.is_authorized());

    let error = store
        .authorize_composite_hold(composite_authorize_input(
            "hold-pinned-2",
            "event-pinned-2",
            1,
        ))
        .expect_err("a quota maximum must be immutable after its first presentation");
    assert!(error.to_string().contains("different maximum"));
    let bypass = store
        .try_increment("leaf", 0, Some(10))
        .expect_err("a composite-managed grant must reject legacy counter writes");
    assert!(bypass
        .to_string()
        .contains("requires composite invocation admission"));

    let _ = fs::remove_file(path);
}

#[test]
fn admission_managed_budget_store_rejects_legacy_projection_imports() {
    let path = unique_db_path("chio-admission-managed-budget-import");
    let _authority = crate::SqliteAdmissionCaptureAuthority::open(&path).unwrap();
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store.is_admission_authority_managed().unwrap());

    let usage = usage_record("legacy-capability", 0, 1, 10, 1, 0, 0);
    let event = import_integrity_record("legacy-event", 1);
    for error in [
        store.upsert_usage(&usage).unwrap_err(),
        store
            .import_snapshot_records(std::slice::from_ref(&usage), std::slice::from_ref(&event))
            .unwrap_err(),
        store.import_mutation_record(&event).unwrap_err(),
        store.record_abandoned_event_seqs(&[1]).unwrap_err(),
        store
            .record_abandoned_event_seq_ranges(&[(1, 1)])
            .unwrap_err(),
        store
            .record_budget_import_floors(std::slice::from_ref(&event))
            .unwrap_err(),
    ] {
        assert!(error
            .to_string()
            .contains("managed by the `combined-admission-capture-v1` admission authority"));
    }

    assert!(store.list_all_usages().unwrap().is_empty());
    assert!(store
        .list_mutation_events(10, None, None)
        .unwrap()
        .is_empty());

    let _ = fs::remove_file(path);
}

#[test]
fn admission_managed_sequence_ignores_transport_cache_drift() {
    let path = unique_db_path("chio-admission-managed-sequence-cache");
    let _authority = crate::SqliteAdmissionCaptureAuthority::open(&path).unwrap();
    let store = SqliteBudgetStore::open(&path).unwrap();
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE budget_replication_meta SET next_seq = 900 WHERE singleton = 1",
            [],
        )
        .unwrap();

    store
        .authorize_composite_hold(composite_authorize_input(
            "hold-managed-sequence",
            "event-managed-sequence",
            2,
        ))
        .unwrap();

    assert_eq!(
        store
            .mutation_event_seq_for_event_id("event-managed-sequence")
            .unwrap(),
        Some(1)
    );
    assert_eq!(replication_floor(&store), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn composite_quota_maximum_cannot_be_changed_by_direct_sql() {
    let path = unique_db_path("chio-composite-budget-immutable-maximum");
    let store = SqliteBudgetStore::open(&path).unwrap();
    store
        .authorize_composite_hold(composite_authorize_input(
            "hold-immutable-1",
            "event-immutable-1",
            2,
        ))
        .unwrap();

    let connection = store.connection().unwrap();
    let error = connection
        .execute(
            r#"
            UPDATE budget_invocation_quota_usage
            SET max_invocations = 99
            WHERE profile = 'chio.aggregate-capability-invocation.v1'
              AND owner_id = 'leaf'
              AND grant_index_key = -1
            "#,
            [],
        )
        .expect_err("direct SQL must not change a pinned quota maximum");
    assert!(error
        .to_string()
        .contains("immutable invocation quota maximum"));
    drop(connection);

    let _ = fs::remove_file(path);
}

#[test]
fn composite_authorization_migrates_legacy_usage_without_resetting_reports() {
    let path = unique_db_path("chio-composite-budget-legacy-migration");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store.try_increment("leaf", 0, Some(10)).unwrap());
    drop(store);

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    let decision = reopened
        .authorize_composite_hold(composite_authorize_input(
            "hold-migrated-1",
            "event-migrated-1",
            2,
        ))
        .unwrap();
    let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
        panic!("legacy usage below every maximum should migrate and authorize");
    };
    let primary = authorized
        .invocation_counts_after
        .iter()
        .find(|usage| usage.quota.key().profile() == BudgetQuotaProfile::GrantInvocation)
        .unwrap();
    assert_eq!(primary.reserved_invocations_after, 1);
    assert_eq!(primary.captured_invocations_after, 1);
    assert_eq!(
        reopened
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        2
    );

    let _ = fs::remove_file(path);
}

#[test]
fn concurrent_composite_authorizations_admit_exactly_one_final_unit() {
    let path = unique_db_path("chio-composite-budget-concurrency");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let stores = [
        SqliteBudgetStore::open(&path).unwrap(),
        SqliteBudgetStore::open(&path).unwrap(),
    ];
    let mut threads = Vec::new();
    for (index, store) in stores.into_iter().enumerate() {
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            store
                .authorize_composite_hold(composite_authorize_input(
                    &format!("hold-race-{index}"),
                    &format!("event-race-{index}"),
                    1,
                ))
                .unwrap()
                .is_authorized()
        }));
    }
    let outcomes = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|allowed| **allowed).count(), 1);

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        1
    );
    let _ = fs::remove_file(path);
}

#[test]
fn composite_invocation_capture_is_atomic_idempotent_and_restart_durable() {
    let path = unique_db_path("chio-composite-budget-capture");
    let capture_request = BudgetCaptureInvocationRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        hold_id: Some("hold-capture-1".to_string()),
        event_id: Some("event-capture-1".to_string()),
        authority: None,
    };
    let captured = {
        let store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store
            .authorize_composite_hold(composite_authorize_input(
                "hold-capture-1",
                "event-authorize-capture-1",
                2,
            ))
            .unwrap()
            .is_authorized());
        store
            .capture_invocation_reservations(capture_request.clone())
            .unwrap()
    };
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Exposed);
    assert!(captured
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 1
        ));

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .capture_invocation_reservations(capture_request)
            .unwrap(),
        captured
    );
    assert_eq!(
        reopened
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        1
    );

    let _ = fs::remove_file(path);
}

#[test]
fn composite_invocation_only_capture_terminalizes_the_base_hold() {
    let path = unique_db_path("chio-composite-budget-invocation-only");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let mut authorization = composite_authorize_input(
        "hold-invocation-only-1",
        "event-authorize-invocation-only-1",
        1,
    );
    authorization.requested_exposure_units = 0;
    authorization.max_cost_per_invocation = None;
    authorization.max_total_cost_units = None;
    let authorized = store.authorize_composite_hold(authorization).unwrap();
    let BudgetAuthorizeHoldDecision::Authorized(authorized) = authorized else {
        panic!("invocation-only composite authorization should pass");
    };
    assert_eq!(authorized.monetary_state, BudgetMonetaryHoldState::None);

    let capture_request = BudgetCaptureInvocationRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        hold_id: Some("hold-invocation-only-1".to_string()),
        event_id: Some("event-capture-invocation-only-1".to_string()),
        authority: None,
    };
    let captured = store
        .capture_invocation_reservations(capture_request.clone())
        .unwrap();
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::None);
    assert!(captured
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 1
        ));
    assert_eq!(
        persisted_hold_disposition(&store, "hold-invocation-only-1"),
        HoldDisposition::Captured
    );

    drop(store);
    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .capture_invocation_reservations(capture_request)
            .unwrap(),
        captured
    );
    let _ = fs::remove_file(path);
}

#[test]
fn artifact_bound_hold_rejects_ordinary_invocation_capture() {
    let path = unique_db_path("chio-composite-budget-combined-only");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let mut authorization =
        composite_authorize_input("hold-combined-only-1", "event-authorize-combined-only-1", 2);
    authorization.authorization_artifact_digests = vec!["11".repeat(32)];
    assert!(store
        .authorize_composite_hold(authorization)
        .unwrap()
        .is_authorized());
    let error = store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "leaf".to_string(),
            grant_index: 0,
            hold_id: Some("hold-combined-only-1".to_string()),
            event_id: Some("event-capture-combined-only-1".to_string()),
            authority: None,
        })
        .expect_err("artifact-bound capture must use AdmissionCaptureAuthority");
    assert!(error
        .to_string()
        .contains("combined admission capture authority"));
    let _ = fs::remove_file(path);
}

#[test]
fn composite_reverse_restores_every_reserved_quota_and_survives_restart() {
    let path = unique_db_path("chio-composite-budget-reverse");
    let reverse_request = BudgetReverseHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        reversed_exposure_units: 100,
        hold_id: Some("hold-reverse-composite-1".to_string()),
        event_id: Some("event-reverse-composite-1".to_string()),
        authority: None,
    };
    let reversed = {
        let store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store
            .authorize_composite_hold(composite_authorize_input(
                "hold-reverse-composite-1",
                "event-authorize-reverse-composite-1",
                1,
            ))
            .unwrap()
            .is_authorized());
        store.reverse_budget_hold(reverse_request.clone()).unwrap()
    };
    assert_eq!(
        reversed.invocation_state,
        BudgetInvocationReservationState::Reversed
    );
    assert_eq!(reversed.monetary_state, BudgetMonetaryHoldState::Reversed);
    assert!(reversed
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 0
        ));

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened.reverse_budget_hold(reverse_request).unwrap(),
        reversed
    );
    assert_eq!(
        reopened
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        0
    );
    assert!(reopened
        .authorize_composite_hold(composite_authorize_input(
            "hold-reverse-composite-2",
            "event-authorize-reverse-composite-2",
            1,
        ))
        .unwrap()
        .is_authorized());

    let _ = fs::remove_file(path);
}

#[test]
fn composite_reconcile_preserves_captured_invocation_evidence() {
    let path = unique_db_path("chio-composite-budget-reconcile");
    let reconcile_request = BudgetReconcileHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 30,
        hold_id: Some("hold-reconcile-composite-1".to_string()),
        event_id: Some("event-reconcile-composite-1".to_string()),
        authority: None,
    };
    let reconciled = {
        let store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store
            .authorize_composite_hold(composite_authorize_input(
                "hold-reconcile-composite-1",
                "event-authorize-reconcile-composite-1",
                2,
            ))
            .unwrap()
            .is_authorized());
        store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "leaf".to_string(),
                grant_index: 0,
                hold_id: Some("hold-reconcile-composite-1".to_string()),
                event_id: Some("event-capture-reconcile-composite-1".to_string()),
                authority: None,
            })
            .unwrap();
        store
            .reconcile_budget_hold(reconcile_request.clone())
            .unwrap()
    };
    assert_eq!(
        reconciled.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(
        reconciled.monetary_state,
        BudgetMonetaryHoldState::Reconciled
    );
    assert_eq!(reconciled.committed_cost_units_after, 30);
    assert!(reconciled
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 1
        ));

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened.reconcile_budget_hold(reconcile_request).unwrap(),
        reconciled
    );

    let _ = fs::remove_file(path);
}

#[test]
fn composite_reconcile_before_invocation_capture_consumes_reserved_capacity() {
    let path = unique_db_path("chio-composite-budget-reconcile-first");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-reconcile-first-1",
            "event-authorize-reconcile-first-1",
            1,
        ))
        .unwrap()
        .is_authorized());

    let reconcile_request = BudgetReconcileHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 30,
        hold_id: Some("hold-reconcile-first-1".to_string()),
        event_id: Some("event-reconcile-first-1".to_string()),
        authority: None,
    };
    let reconciled = store
        .reconcile_budget_hold(reconcile_request.clone())
        .unwrap();
    assert_eq!(
        reconciled.invocation_state,
        BudgetInvocationReservationState::Authorized
    );
    assert_eq!(
        reconciled.monetary_state,
        BudgetMonetaryHoldState::Reconciled
    );
    assert!(reconciled
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 1 && usage.captured_invocations_after == 0
        ));

    let capture_request = BudgetCaptureInvocationRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        hold_id: Some("hold-reconcile-first-1".to_string()),
        event_id: Some("event-capture-reconcile-first-1".to_string()),
        authority: None,
    };
    let captured = store
        .capture_invocation_reservations(capture_request.clone())
        .unwrap();
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Reconciled);
    assert!(captured
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 1
        ));
    assert_eq!(
        store
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        1
    );
    assert_eq!(
        persisted_hold_disposition(&store, "hold-reconcile-first-1"),
        HoldDisposition::Reconciled
    );
    drop(store);
    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened.reconcile_budget_hold(reconcile_request).unwrap(),
        reconciled
    );
    assert_eq!(
        reopened
            .capture_invocation_reservations(capture_request)
            .unwrap(),
        captured
    );

    let _ = fs::remove_file(path);
}

#[test]
fn composite_partial_release_preserves_invocation_state_and_remaining_exposure() {
    let path = unique_db_path("chio-composite-budget-release");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-release-composite-1",
            "event-authorize-release-composite-1",
            2,
        ))
        .unwrap()
        .is_authorized());
    store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "leaf".to_string(),
            grant_index: 0,
            hold_id: Some("hold-release-composite-1".to_string()),
            event_id: Some("event-capture-release-composite-1".to_string()),
            authority: None,
        })
        .unwrap();
    let partial = store
        .release_budget_hold(BudgetReleaseHoldRequest {
            capability_id: "leaf".to_string(),
            grant_index: 0,
            released_exposure_units: 40,
            hold_id: Some("hold-release-composite-1".to_string()),
            event_id: Some("event-release-composite-1".to_string()),
            authority: None,
        })
        .unwrap();
    assert_eq!(
        partial.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(partial.monetary_state, BudgetMonetaryHoldState::Exposed);
    assert_eq!(partial.committed_cost_units_after, 60);

    let final_request = BudgetReleaseHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        released_exposure_units: 60,
        hold_id: Some("hold-release-composite-1".to_string()),
        event_id: Some("event-release-composite-2".to_string()),
        authority: None,
    };
    let released = store.release_budget_hold(final_request.clone()).unwrap();
    assert_eq!(
        released.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(released.monetary_state, BudgetMonetaryHoldState::Released);
    assert_eq!(released.committed_cost_units_after, 0);
    drop(store);

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened.release_budget_hold(final_request).unwrap(),
        released
    );
    let _ = fs::remove_file(path);
}

#[test]
fn composite_full_release_before_invocation_capture_consumes_reserved_capacity() {
    let path = unique_db_path("chio-composite-budget-release-first");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-release-first-1",
            "event-authorize-release-first-1",
            1,
        ))
        .unwrap()
        .is_authorized());

    let release_request = BudgetReleaseHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        released_exposure_units: 100,
        hold_id: Some("hold-release-first-1".to_string()),
        event_id: Some("event-release-first-1".to_string()),
        authority: None,
    };
    let released = store.release_budget_hold(release_request.clone()).unwrap();
    assert_eq!(
        released.invocation_state,
        BudgetInvocationReservationState::Authorized
    );
    assert_eq!(released.monetary_state, BudgetMonetaryHoldState::Released);
    assert!(released
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 1 && usage.captured_invocations_after == 0
        ));

    let capture_request = BudgetCaptureInvocationRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        hold_id: Some("hold-release-first-1".to_string()),
        event_id: Some("event-capture-release-first-1".to_string()),
        authority: None,
    };
    let captured = store
        .capture_invocation_reservations(capture_request.clone())
        .unwrap();
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Released);
    assert!(captured
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 1
        ));
    assert_eq!(
        store
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        1
    );
    assert_eq!(
        persisted_hold_disposition(&store, "hold-release-first-1"),
        HoldDisposition::Released
    );
    drop(store);
    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened.release_budget_hold(release_request).unwrap(),
        released
    );
    assert_eq!(
        reopened
            .capture_invocation_reservations(capture_request)
            .unwrap(),
        captured
    );

    let _ = fs::remove_file(path);
}

#[test]
fn composite_monetary_capture_preserves_captured_invocation_evidence() {
    let path = unique_db_path("chio-composite-budget-monetary-capture");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-monetary-capture-1",
            "event-authorize-monetary-capture-1",
            2,
        ))
        .unwrap()
        .is_authorized());
    store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "leaf".to_string(),
            grant_index: 0,
            hold_id: Some("hold-monetary-capture-1".to_string()),
            event_id: Some("event-invocation-monetary-capture-1".to_string()),
            authority: None,
        })
        .unwrap();
    let captured = store
        .capture_budget_hold(BudgetCaptureHoldRequest {
            capability_id: "leaf".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 25,
            hold_id: Some("hold-monetary-capture-1".to_string()),
            event_id: Some("event-monetary-capture-1".to_string()),
            authority: None,
        })
        .unwrap();
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Captured);
    assert_eq!(captured.committed_cost_units_after, 25);
    assert!(captured
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 1
        ));
    let _ = fs::remove_file(path);
}

#[test]
fn composite_monetary_capture_before_invocation_capture_consumes_reserved_capacity() {
    let path = unique_db_path("chio-composite-budget-monetary-capture-first");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-monetary-capture-first-1",
            "event-authorize-monetary-capture-first-1",
            1,
        ))
        .unwrap()
        .is_authorized());

    let monetary_capture_request = BudgetCaptureHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 25,
        hold_id: Some("hold-monetary-capture-first-1".to_string()),
        event_id: Some("event-monetary-capture-first-1".to_string()),
        authority: None,
    };
    let monetary_captured = store
        .capture_budget_hold(monetary_capture_request.clone())
        .unwrap();
    assert_eq!(
        monetary_captured.invocation_state,
        BudgetInvocationReservationState::Authorized
    );
    assert_eq!(
        monetary_captured.monetary_state,
        BudgetMonetaryHoldState::Captured
    );
    assert!(monetary_captured
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 1 && usage.captured_invocations_after == 0
        ));

    let capture_request = BudgetCaptureInvocationRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        hold_id: Some("hold-monetary-capture-first-1".to_string()),
        event_id: Some("event-capture-monetary-capture-first-1".to_string()),
        authority: None,
    };
    let captured = store
        .capture_invocation_reservations(capture_request.clone())
        .unwrap();
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Captured);
    assert!(captured
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 1
        ));
    assert_eq!(
        store
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        1
    );
    assert_eq!(
        persisted_hold_disposition(&store, "hold-monetary-capture-first-1"),
        HoldDisposition::Captured
    );
    drop(store);
    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .capture_budget_hold(monetary_capture_request)
            .unwrap(),
        monetary_captured
    );
    assert_eq!(
        reopened
            .capture_invocation_reservations(capture_request)
            .unwrap(),
        captured
    );

    let _ = fs::remove_file(path);
}

#[test]
fn budget_usage_query_rejects_negative_persisted_counter() {
    let path = unique_db_path("chio-budget-negative-usage");
    let store = SqliteBudgetStore::open(&path).unwrap();
    store
        .upsert_usage(&usage_record("cap-negative", 0, 1, 10, 1, 0, 0))
        .unwrap();
    {
        let connection = store.connection().unwrap();
        connection
            .execute(
                r#"
                    UPDATE capability_grant_budgets
                    SET invocation_count = -1
                    WHERE capability_id = 'cap-negative' AND grant_index = 0
                    "#,
                [],
            )
            .unwrap();
    }

    let error = store
        .list_all_usages()
        .expect_err("negative persisted budget counters must fail closed");
    assert!(
        error
            .to_string()
            .contains("budget field `invocation_count` was negative"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_budget_store_rejects_pre_split_budget_schema() {
    let path = unique_db_path("chio-budget-pre-split-schema");
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                r#"
                    CREATE TABLE capability_grant_budgets (
                        capability_id TEXT NOT NULL,
                        grant_index INTEGER NOT NULL,
                        invocation_count INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        total_cost_charged INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (capability_id, grant_index)
                    );
                    INSERT INTO capability_grant_budgets (
                        capability_id,
                        grant_index,
                        invocation_count,
                        updated_at,
                        total_cost_charged
                    ) VALUES ('cap-1', 0, 1, 10, 55);
                    "#,
            )
            .unwrap();
    }

    let error = match SqliteBudgetStore::open(&path) {
        Ok(_) => panic!("pre-split budget schema should be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains(
        "missing split cost columns `total_cost_exposed` and `total_cost_realized_spend`"
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_budget_store_upsert_usage_keeps_newer_seq_state() {
    let path = unique_db_path("chio-budget-upsert");
    let store = SqliteBudgetStore::open(&path).unwrap();
    store
        .upsert_usage(&usage_record("cap-1", 0, 3, 10, 3, 300, 0))
        .unwrap();
    store
        .upsert_usage(&usage_record("cap-1", 0, 2, 9, 2, 200, 0))
        .unwrap();

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 3);
    assert_usage_totals(&records[0], 300, 0);
    assert_eq!(records[0].seq, 3);

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_budget_store_uses_seq_for_same_key_delta_queries() {
    let path = unique_db_path("chio-budget-seq-delta");
    let store = SqliteBudgetStore::open(&path).unwrap();

    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());
    let first = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(first.len(), 1);
    let first_seq = first[0].seq;

    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());
    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());

    let delta = store.list_usages_after(10, Some(first_seq)).unwrap();
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].invocation_count, 3);
    assert!(delta[0].seq > first_seq);

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_budget_store_preserves_imported_seq_across_failover_writes() {
    let path = unique_db_path("chio-budget-seq-floor");
    let store = SqliteBudgetStore::open(&path).unwrap();

    store
        .upsert_usage(&usage_record("cap-1", 0, 3, 10, 42, 0, 0))
        .unwrap();
    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].invocation_count, 4);
    assert_eq!(records[0].seq, 43);

    let _ = fs::remove_file(path);
}

// --- try_charge_cost tests ---

#[test]
fn budget_store_try_charge_cost_within_limits_returns_true_sqlite() {
    let path = unique_db_path("chio-charge-cost-ok");
    let store = SqliteBudgetStore::open(&path).unwrap();
    // 100 units, cap is 200 per invocation, total cap is 1000
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap();
    assert!(ok);

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 1);
    assert_usage_totals(&records[0], 100, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_exceeds_per_invocation_cap_sqlite() {
    let path = unique_db_path("chio-charge-cost-per-inv");
    let store = SqliteBudgetStore::open(&path).unwrap();
    // 500 units > max_cost_per_invocation of 200
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 500, Some(200), Some(1000))
        .unwrap();
    assert!(!ok);

    // Nothing should have been charged
    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert!(records.is_empty() || records[0].invocation_count == 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_exceeds_total_cap_sqlite() {
    let path = unique_db_path("chio-charge-cost-total");
    let store = SqliteBudgetStore::open(&path).unwrap();
    // First charge 900 of 1000 budget
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 900, Some(1000), Some(1000))
        .unwrap());
    // Second charge of 200 would exceed the total cap of 1000
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 200, Some(1000), Some(1000))
        .unwrap();
    assert!(!ok);

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_usage_totals(&records[0], 900, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_atomic_increment_sqlite() {
    let path = unique_db_path("chio-charge-cost-atomic");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, None, 100, Some(200), Some(1000))
        .unwrap());
    assert!(store
        .try_charge_cost("cap-1", 0, None, 150, Some(200), Some(1000))
        .unwrap());

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 2);
    assert_usage_totals(&records[0], 250, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_within_limits_returns_true_inmemory() {
    let store = InMemoryBudgetStore::new();
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap();
    assert!(ok);

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 1);
    assert_usage_totals(&records[0], 100, 0);
}

#[test]
fn budget_store_try_charge_cost_exceeds_per_invocation_cap_inmemory() {
    let store = InMemoryBudgetStore::new();
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 500, Some(200), Some(1000))
        .unwrap();
    assert!(!ok);
}

#[test]
fn budget_store_try_charge_cost_exceeds_total_cap_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 900, Some(1000), Some(1000))
        .unwrap());
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 200, Some(1000), Some(1000))
        .unwrap();
    assert!(!ok);
}

#[test]
fn budget_usage_record_includes_split_cost_state() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, None, 42, None, None)
        .unwrap());
    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_usage_totals(&records[0], 42, 0);
}

#[test]
fn budget_store_reverse_charge_cost_restores_prior_state_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reverse_charge_cost("cap-1", 0, 100).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 0);
    assert_usage_totals(&record, 0, 0);
}

#[test]
fn budget_store_reverse_charge_cost_restores_prior_state_sqlite() {
    let path = unique_db_path("chio-reverse-charge");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reverse_charge_cost("cap-1", 0, 100).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 0);
    assert_usage_totals(&record, 0, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_reduce_charge_cost_releases_exposure_only_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reduce_charge_cost("cap-1", 0, 25).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 75, 0);
}

#[test]
fn budget_store_reduce_charge_cost_releases_exposure_only_sqlite() {
    let path = unique_db_path("chio-reduce-charge");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reduce_charge_cost("cap-1", 0, 25).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 75, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_settle_charge_cost_moves_exposure_to_realized_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.settle_charge_cost("cap-1", 0, 100, 75).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 0, 75);
}

#[test]
fn budget_store_settle_charge_cost_moves_exposure_to_realized_sqlite() {
    let path = unique_db_path("chio-settle-charge");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.settle_charge_cost("cap-1", 0, 100, 75).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 0, 75);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_with_ids_is_idempotent_inmemory() {
    let store = InMemoryBudgetStore::new();
    let hold_id = "hold-cap-1-0";
    let event_id = "hold-cap-1-0:authorize";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());
    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());

    let usage = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-1"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, event_id);
    assert_eq!(events[0].hold_id.as_deref(), Some(hold_id));
    assert_eq!(events[0].kind, BudgetMutationKind::AuthorizeExposure);
    assert_eq!(events[0].allowed, Some(true));
}

#[test]
fn budget_store_event_retry_after_reopen_is_idempotent_sqlite() {
    let path = unique_db_path("chio-charge-cost-idempotent");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-1-0";
    let event_id = "hold-cap-1-0:authorize";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());

    let before_reopen = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(before_reopen.invocation_count, 1);
    assert_usage_totals(&before_reopen, 100, 0);
    drop(store);

    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());

    let usage = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-1"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, event_id);
    assert_eq!(events[0].hold_id.as_deref(), Some(hold_id));
    assert_eq!(events[0].kind, BudgetMutationKind::AuthorizeExposure);
    assert_eq!(events[0].allowed, Some(true));

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_settle_with_ids_is_idempotent_and_append_only_sqlite() {
    let path = unique_db_path("chio-settle-charge-idempotent");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-1-0";
    let authorize_event_id = "hold-cap-1-0:authorize";
    let reconcile_event_id = "hold-cap-1-0:reconcile";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(authorize_event_id),
        )
        .unwrap());
    store
        .settle_charge_cost_with_ids("cap-1", 0, 100, 75, Some(hold_id), Some(reconcile_event_id))
        .unwrap();
    store
        .settle_charge_cost_with_ids("cap-1", 0, 100, 75, Some(hold_id), Some(reconcile_event_id))
        .unwrap();

    let usage = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 0, 75);

    let events = store
        .list_mutation_events(10, Some("cap-1"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_id, authorize_event_id);
    assert_eq!(events[1].event_id, reconcile_event_id);
    assert_eq!(events[1].hold_id.as_deref(), Some(hold_id));
    assert_eq!(events[1].kind, BudgetMutationKind::ReconcileSpend);
    assert_eq!(events[1].exposure_units, 100);
    assert_eq!(events[1].realized_spend_units, 75);
    assert_eq!(events[1].total_cost_exposed_after, 0);
    assert_eq!(events[1].total_cost_realized_spend_after, 75);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_capture_is_terminal_truthful_and_exact_after_reopen_sqlite() {
    let path = unique_db_path("chio-capture-charge-exact");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-capture-0";
    let authorize_event_id = "hold-cap-capture-0:authorize";
    let capture_event_id = "hold-cap-capture-0:capture";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-capture",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(authorize_event_id),
        )
        .unwrap());
    let request = BudgetCaptureHoldRequest {
        capability_id: "cap-capture".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 70,
        hold_id: Some(hold_id.to_string()),
        event_id: Some(capture_event_id.to_string()),
        authority: None,
    };
    let captured = store.capture_budget_hold(request.clone()).unwrap();
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Captured);
    assert_eq!(captured.exposure_units, 100);
    assert_eq!(captured.realized_spend_units, 70);
    assert_eq!(captured.committed_cost_units_after, 70);
    assert_eq!(captured.invocation_count_after, 1);

    let usage = store.get_usage("cap-capture", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 0, 70);
    {
        let mut connection = store.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .unwrap();
        let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)
            .unwrap()
            .expect("captured hold state");
        assert_eq!(hold.remaining_exposure_units, 0);
        assert_eq!(hold.disposition, HoldDisposition::Captured);
    }
    let events = store
        .list_mutation_events(10, Some("cap-capture"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].event_id, capture_event_id);
    assert_eq!(events[1].kind, BudgetMutationKind::CaptureExposure);
    assert_eq!(events[1].monetary_state, BudgetMonetaryHoldState::Captured);
    drop(store);

    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost_with_ids(
            "cap-capture",
            0,
            Some(10),
            10,
            Some(200),
            Some(1000),
            Some("hold-cap-capture-1"),
            Some("hold-cap-capture-1:authorize"),
        )
        .unwrap());
    let usage_before_retry = store.get_usage("cap-capture", 0).unwrap().unwrap();
    assert_eq!(usage_before_retry.invocation_count, 2);
    assert_usage_totals(&usage_before_retry, 10, 70);

    assert_eq!(store.capture_budget_hold(request).unwrap(), captured);
    assert_eq!(
        store.get_usage("cap-capture", 0).unwrap().unwrap(),
        usage_before_retry
    );
    assert_eq!(
        store
            .list_mutation_events(10, Some("cap-capture"), Some(0))
            .unwrap()
            .len(),
        3
    );

    let reconcile_error = store
        .settle_charge_cost_with_ids(
            "cap-capture",
            0,
            100,
            70,
            Some(hold_id),
            Some("hold-cap-capture-0:reconcile"),
        )
        .expect_err("a captured hold must not be reconciled again");
    assert!(reconcile_error.to_string().contains("is no longer open"));
    assert_eq!(
        store.get_usage("cap-capture", 0).unwrap().unwrap(),
        usage_before_retry
    );
    assert_eq!(
        store
            .list_mutation_events(10, Some("cap-capture"), Some(0))
            .unwrap()
            .len(),
        3
    );

    let _ = fs::remove_file(path);
}

#[test]
fn high_level_authorize_retry_returns_original_allowed_snapshot_after_later_write() {
    let path = unique_db_path("chio-budget-authorize-allowed-snapshot-retry");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let leased = authority("budget-primary", "lease-1", 1);
    let request = BudgetAuthorizeHoldRequest::legacy(
        "cap-authorize-snapshot".to_string(),
        0,
        Some(5),
        100,
        Some(100),
        Some(500),
        Some("hold-authorize-snapshot-0".to_string()),
        Some("event-authorize-snapshot".to_string()),
        Some(leased.clone()),
    );
    let first = store.authorize_budget_hold(request.clone()).unwrap();
    assert!(first.is_authorized());
    let later = BudgetAuthorizeHoldRequest::legacy(
        "cap-authorize-snapshot".to_string(),
        0,
        Some(5),
        50,
        Some(100),
        Some(500),
        Some("hold-authorize-snapshot-1".to_string()),
        Some("event-authorize-snapshot-later".to_string()),
        Some(leased.clone()),
    );
    assert!(store.authorize_budget_hold(later).unwrap().is_authorized());

    assert_eq!(store.authorize_budget_hold(request).unwrap(), first);
    let BudgetAuthorizeHoldDecision::Authorized(first) = first else {
        panic!("first authorization must be allowed");
    };
    assert_eq!(first.committed_cost_units_after, 100);
    assert_eq!(first.invocation_count_after, 1);
    assert_eq!(first.metadata.authority.as_ref(), Some(&leased));
    assert_eq!(
        first.metadata.event_id.as_deref(),
        Some("event-authorize-snapshot")
    );
    assert!(first.metadata.budget_commit_index.is_some());

    let zero_with_limit = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-authorize-zero-limit".to_string(),
            0,
            Some(1),
            0,
            Some(0),
            None,
            Some("hold-authorize-zero-limit".to_string()),
            Some("event-authorize-zero-limit".to_string()),
            None,
        ))
        .unwrap();
    let BudgetAuthorizeHoldDecision::Authorized(zero_with_limit) = zero_with_limit else {
        panic!("zero-exposure authorization with a monetary limit must be allowed");
    };
    assert_eq!(
        zero_with_limit.monetary_state,
        BudgetMonetaryHoldState::Exposed
    );

    let _ = fs::remove_file(path);
}

#[test]
fn denied_authorization_claim_survives_reopen_and_freezes_retry_snapshot() {
    let path = unique_db_path("chio-budget-authorize-denied-claim-reopen");
    let leased = authority("budget-primary", "lease-1", 1);
    let request = BudgetAuthorizeHoldRequest::legacy(
        "cap-authorize-denied".to_string(),
        0,
        Some(5),
        100,
        Some(50),
        Some(500),
        Some("hold-authorize-denied".to_string()),
        Some("event-authorize-denied".to_string()),
        Some(leased.clone()),
    );
    let store = SqliteBudgetStore::open(&path).unwrap();
    let first = store.authorize_budget_hold(request.clone()).unwrap();
    assert!(matches!(first, BudgetAuthorizeHoldDecision::Denied(_)));
    drop(store);

    let store = SqliteBudgetStore::open(&path).unwrap();
    let events_before = store
        .list_mutation_events(10, Some("cap-authorize-denied"), Some(0))
        .unwrap();
    let collision = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-authorize-denied".to_string(),
            0,
            Some(5),
            100,
            Some(50),
            Some(500),
            Some("hold-authorize-denied".to_string()),
            Some("event-authorize-denied-rebound".to_string()),
            Some(leased.clone()),
        ))
        .expect_err("a denied hold ID must not be rebound under a fresh event or maxima");
    assert!(matches!(collision, BudgetStoreError::Invariant(_)));
    assert!(store
        .get_usage("cap-authorize-denied", 0)
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .list_mutation_events(10, Some("cap-authorize-denied"), Some(0))
            .unwrap(),
        events_before
    );
    let (claim_count, open_hold_count): (i64, i64) = store
        .connection()
        .unwrap()
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM budget_authorization_claims WHERE hold_id = 'hold-authorize-denied'),
                (SELECT COUNT(*) FROM budget_authorization_holds WHERE hold_id = 'hold-authorize-denied')
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((claim_count, open_hold_count), (1, 0));

    assert!(store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-authorize-denied".to_string(),
            0,
            Some(5),
            40,
            Some(50),
            Some(500),
            Some("hold-authorize-denied-later".to_string()),
            Some("event-authorize-denied-later".to_string()),
            Some(leased.clone()),
        ))
        .unwrap()
        .is_authorized());
    assert_eq!(store.authorize_budget_hold(request).unwrap(), first);
    let BudgetAuthorizeHoldDecision::Denied(first) = first else {
        panic!("first authorization must remain denied");
    };
    assert_eq!(first.committed_cost_units_after, 0);
    assert_eq!(first.invocation_count_after, 0);
    assert_eq!(
        first.invocation_state,
        BudgetInvocationReservationState::Denied
    );
    assert_eq!(first.metadata.authority.as_ref(), Some(&leased));

    let _ = fs::remove_file(path);
}

#[test]
fn imported_denied_authorization_claim_rejects_rebind_atomically() {
    let leader_path = unique_db_path("chio-budget-import-denied-claim-leader");
    let follower_path = unique_db_path("chio-budget-import-denied-claim-follower");
    let leader = SqliteBudgetStore::open(&leader_path).unwrap();
    let request = BudgetAuthorizeHoldRequest::legacy(
        "cap-import-denied-claim".to_string(),
        0,
        Some(5),
        40,
        Some(20),
        Some(100),
        Some("hold-import-denied-claim".to_string()),
        Some("event-import-denied-claim".to_string()),
        None,
    );
    assert!(matches!(
        leader.authorize_budget_hold(request).unwrap(),
        BudgetAuthorizeHoldDecision::Denied(_)
    ));
    let event = leader
        .list_mutation_events(10, Some("cap-import-denied-claim"), Some(0))
        .unwrap()
        .pop()
        .expect("denied authorization event");

    let follower = SqliteBudgetStore::open(&follower_path).unwrap();
    follower.import_snapshot_records(&[], &[event]).unwrap();
    let events_before = follower
        .list_mutation_events(10, Some("cap-import-denied-claim"), Some(0))
        .unwrap();
    let error = follower
        .try_charge_cost_with_ids(
            "cap-import-denied-claim",
            0,
            Some(5),
            40,
            Some(20),
            Some(100),
            Some("hold-import-denied-claim"),
            Some("event-import-denied-claim-rebound"),
        )
        .expect_err("an imported denied claim must permanently bind its hold ID");
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert!(follower
        .get_usage("cap-import-denied-claim", 0)
        .unwrap()
        .is_none());
    assert_eq!(
        follower
            .list_mutation_events(10, Some("cap-import-denied-claim"), Some(0))
            .unwrap(),
        events_before
    );

    let _ = fs::remove_file(leader_path);
    let _ = fs::remove_file(follower_path);
}

#[test]
fn authorization_claim_migration_backfills_existing_authorization_event() {
    let path = unique_db_path("chio-budget-authorization-claim-migration");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-claim-migration".to_string(),
            0,
            Some(2),
            10,
            Some(10),
            Some(20),
            Some("hold-claim-migration".to_string()),
            Some("event-claim-migration".to_string()),
            None,
        ))
        .unwrap()
        .is_authorized());
    store
        .connection()
        .unwrap()
        .execute("DROP TABLE budget_authorization_claims", [])
        .unwrap();
    drop(store);

    let store = SqliteBudgetStore::open(&path).unwrap();
    let claim_count: i64 = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM budget_authorization_claims WHERE hold_id = 'hold-claim-migration'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(claim_count, 1);
    let error = store
        .try_charge_cost_with_ids(
            "cap-claim-migration",
            0,
            Some(2),
            10,
            Some(10),
            Some(20),
            Some("hold-claim-migration"),
            Some("event-claim-migration-rebound"),
        )
        .expect_err("migration-backfilled claim must close the fresh-event bypass");
    assert!(matches!(error, BudgetStoreError::Invariant(_)));

    let _ = fs::remove_file(path);
}

#[test]
fn allowed_authorization_claim_rejects_fresh_event_and_maximum_bypass() {
    let path = unique_db_path("chio-budget-authorize-allowed-claim-rebind");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let request = BudgetAuthorizeHoldRequest::legacy(
        "cap-authorize-claimed".to_string(),
        0,
        Some(1),
        25,
        Some(25),
        Some(25),
        Some("hold-authorize-claimed".to_string()),
        Some("event-authorize-claimed".to_string()),
        None,
    );
    let first = store.authorize_budget_hold(request.clone()).unwrap();
    assert!(first.is_authorized());
    let usage_before = store
        .get_usage("cap-authorize-claimed", 0)
        .unwrap()
        .unwrap();
    let events_before = store
        .list_mutation_events(10, Some("cap-authorize-claimed"), Some(0))
        .unwrap();

    for max_invocations in [Some(1), None] {
        let error = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
                "cap-authorize-claimed".to_string(),
                0,
                max_invocations,
                25,
                Some(25),
                Some(25),
                Some("hold-authorize-claimed".to_string()),
                Some(format!(
                    "event-authorize-claimed-rebound-{max_invocations:?}"
                )),
                None,
            ))
            .expect_err("a claimed allowed hold must reject every fresh event");
        assert!(matches!(error, BudgetStoreError::Invariant(_)));
    }
    assert_eq!(
        store
            .get_usage("cap-authorize-claimed", 0)
            .unwrap()
            .unwrap(),
        usage_before
    );
    assert_eq!(
        store
            .list_mutation_events(10, Some("cap-authorize-claimed"), Some(0))
            .unwrap(),
        events_before
    );
    assert_eq!(store.authorize_budget_hold(request).unwrap(), first);

    let _ = fs::remove_file(path);
}

#[test]
fn high_level_reverse_retry_returns_original_persisted_snapshot_after_later_write() {
    let path = unique_db_path("chio-budget-reverse-snapshot-retry");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let leased = authority("budget-primary", "lease-1", 1);
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-reverse-snapshot",
            0,
            Some(5),
            100,
            Some(100),
            Some(500),
            Some("hold-reverse-snapshot-0"),
            Some("event-reverse-snapshot-authorize"),
            Some(&leased),
        )
        .unwrap());
    let request = BudgetReverseHoldRequest {
        capability_id: "cap-reverse-snapshot".to_string(),
        grant_index: 0,
        reversed_exposure_units: 100,
        hold_id: Some("hold-reverse-snapshot-0".to_string()),
        event_id: Some("event-reverse-snapshot".to_string()),
        authority: Some(leased.clone()),
    };
    let first = store.reverse_budget_hold(request.clone()).unwrap();
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-reverse-snapshot",
            0,
            Some(5),
            50,
            Some(100),
            Some(500),
            Some("hold-reverse-snapshot-1"),
            Some("event-reverse-snapshot-later"),
            Some(&leased),
        )
        .unwrap());

    assert_eq!(store.reverse_budget_hold(request).unwrap(), first);
    assert_eq!(first.metadata.authority.as_ref(), Some(&leased));
    assert_eq!(
        first.metadata.event_id.as_deref(),
        Some("event-reverse-snapshot")
    );
    assert_eq!(first.monetary_state, BudgetMonetaryHoldState::Reversed);
    assert!(first.metadata.budget_commit_index.is_some());

    let _ = fs::remove_file(path);
}

#[test]
fn high_level_release_retry_returns_original_persisted_snapshot_after_later_write() {
    let path = unique_db_path("chio-budget-release-snapshot-retry");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let leased = authority("budget-primary", "lease-1", 1);
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-release-snapshot",
            0,
            Some(5),
            100,
            Some(100),
            Some(500),
            Some("hold-release-snapshot-0"),
            Some("event-release-snapshot-authorize"),
            Some(&leased),
        )
        .unwrap());
    let request = BudgetReleaseHoldRequest {
        capability_id: "cap-release-snapshot".to_string(),
        grant_index: 0,
        released_exposure_units: 100,
        hold_id: Some("hold-release-snapshot-0".to_string()),
        event_id: Some("event-release-snapshot".to_string()),
        authority: Some(leased.clone()),
    };
    let first = store.release_budget_hold(request.clone()).unwrap();
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-release-snapshot",
            0,
            Some(5),
            50,
            Some(100),
            Some(500),
            Some("hold-release-snapshot-1"),
            Some("event-release-snapshot-later"),
            Some(&leased),
        )
        .unwrap());

    assert_eq!(store.release_budget_hold(request).unwrap(), first);
    assert_eq!(first.metadata.authority.as_ref(), Some(&leased));
    assert_eq!(
        first.metadata.event_id.as_deref(),
        Some("event-release-snapshot")
    );
    assert_eq!(first.monetary_state, BudgetMonetaryHoldState::Released);
    assert!(first.metadata.budget_commit_index.is_some());

    let _ = fs::remove_file(path);
}

#[test]
fn high_level_reconcile_retry_returns_original_persisted_snapshot_after_later_write() {
    let path = unique_db_path("chio-budget-reconcile-snapshot-retry");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let leased = authority("budget-primary", "lease-1", 1);
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-reconcile-snapshot",
            0,
            Some(5),
            100,
            Some(100),
            Some(500),
            Some("hold-reconcile-snapshot-0"),
            Some("event-reconcile-snapshot-authorize"),
            Some(&leased),
        )
        .unwrap());
    let request = BudgetReconcileHoldRequest {
        capability_id: "cap-reconcile-snapshot".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 70,
        hold_id: Some("hold-reconcile-snapshot-0".to_string()),
        event_id: Some("event-reconcile-snapshot".to_string()),
        authority: Some(leased.clone()),
    };
    let first = store.reconcile_budget_hold(request.clone()).unwrap();
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-reconcile-snapshot",
            0,
            Some(5),
            50,
            Some(100),
            Some(500),
            Some("hold-reconcile-snapshot-1"),
            Some("event-reconcile-snapshot-later"),
            Some(&leased),
        )
        .unwrap());

    assert_eq!(store.reconcile_budget_hold(request).unwrap(), first);
    assert_eq!(first.metadata.authority.as_ref(), Some(&leased));
    assert_eq!(
        first.metadata.event_id.as_deref(),
        Some("event-reconcile-snapshot")
    );
    assert_eq!(first.monetary_state, BudgetMonetaryHoldState::Reconciled);
    assert!(first.metadata.budget_commit_index.is_some());

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_reduce_charge_cost_allows_zero_invocation_release_sqlite() {
    let path = unique_db_path("chio-reduce-charge-zero-invocations");
    let store = SqliteBudgetStore::open(&path).unwrap();
    store
        .upsert_usage(&usage_record("cap-zero", 0, 0, 10, 10, 40, 0))
        .unwrap();

    store.reduce_charge_cost("cap-zero", 0, 25).unwrap();

    let usage = store.get_usage("cap-zero", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_usage_totals(&usage, 15, 0);

    let events = store
        .list_mutation_events(10, Some("cap-zero"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, BudgetMutationKind::ReleaseExposure);
    assert_eq!(events[0].invocation_count_after, 0);
    assert_eq!(events[0].total_cost_exposed_after, 15);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_list_mutation_events_preserves_append_order_sqlite() {
    let path = unique_db_path("chio-budget-event-order");
    let store = SqliteBudgetStore::open(&path).unwrap();

    assert!(store
        .try_charge_cost_with_ids(
            "cap-order",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some("hold-cap-order-0"),
            Some("z-authorize"),
        )
        .unwrap());
    store
        .reduce_charge_cost_with_ids(
            "cap-order",
            0,
            25,
            Some("hold-cap-order-0"),
            Some("a-release"),
        )
        .unwrap();

    let events = store
        .list_mutation_events(10, Some("cap-order"), Some(0))
        .unwrap();
    let event_ids = events
        .iter()
        .map(|record| record.event_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(event_ids, vec!["z-authorize", "a-release"]);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_hold_authority_requires_exact_lease_inmemory() {
    let store = InMemoryBudgetStore::new();
    let hold_id = "hold-cap-lease-0";
    let authorize_event_id = "hold-cap-lease-0:authorize";
    let release_event_id = "hold-cap-lease-0:release";
    let reconcile_event_id = "hold-cap-lease-0:reconcile";
    let initial = authority("budget-primary", "lease-7", 7);
    let advanced = authority("budget-primary", "lease-7", 8);
    let stale = authority("budget-primary", "lease-7", 6);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(authorize_event_id),
            Some(&initial),
        )
        .unwrap());

    let missing = store
        .reduce_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            25,
            Some(hold_id),
            Some("hold-cap-lease-0:release-missing"),
            None,
        )
        .expect_err("missing lease metadata should fail closed");
    assert!(missing
        .to_string()
        .contains("requires authority lease metadata"));

    let stale_error = store
        .reduce_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            25,
            Some(hold_id),
            Some("hold-cap-lease-0:release-stale"),
            Some(&stale),
        )
        .expect_err("stale lease epoch should fail closed");
    assert!(stale_error.to_string().contains("lease epoch regressed"));

    let advanced_error = store
        .reduce_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            25,
            Some(hold_id),
            Some(release_event_id),
            Some(&advanced),
        )
        .expect_err("advanced lease epoch should fail closed");
    assert!(advanced_error
        .to_string()
        .contains("advanced beyond the open lease"));

    store
        .reduce_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            25,
            Some(hold_id),
            Some(release_event_id),
            Some(&initial),
        )
        .unwrap();
    store
        .settle_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            75,
            75,
            Some(hold_id),
            Some(reconcile_event_id),
            Some(&initial),
        )
        .unwrap();

    let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 0, 75);

    let events = store
        .list_mutation_events(10, Some("cap-lease"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].authority.as_ref(), Some(&initial));
    assert_eq!(events[1].authority.as_ref(), Some(&initial));
    assert_eq!(events[2].authority.as_ref(), Some(&initial));
}

#[test]
fn budget_store_event_id_retry_rejects_authority_rollover_sqlite() {
    let path = unique_db_path("chio-hold-authority-event-reuse");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-lease-0";
    let event_id = "hold-cap-lease-0:authorize";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());

    let authority_error = store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .expect_err("reused event id under a different authority should fail closed");
    assert!(matches!(authority_error, BudgetStoreError::Invariant(_)));

    let error = store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            101,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .expect_err("reused event id with a different mutation should fail closed");
    assert!(matches!(error, BudgetStoreError::Invariant(_)));

    let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-lease"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].authority.as_ref(), Some(&initial));

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_deleted_provisional_event_allows_retry_after_compensation_sqlite() {
    let path = unique_db_path("chio-hold-authority-compensation");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-lease-0";
    let event_id = "hold-cap-lease-0:authorize";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            100,
            Some(hold_id),
            Some("hold-cap-lease-0:authorize:rollback:1"),
            Some(&initial),
        )
        .unwrap();
    store.delete_hold(hold_id).unwrap();
    store.delete_mutation_event(event_id).unwrap();

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .unwrap());

    let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-lease"), Some(0))
        .unwrap();
    let event_ids = events
        .iter()
        .map(|record| record.event_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        event_ids,
        vec![
            "hold-cap-lease-0:authorize:rollback:1",
            "hold-cap-lease-0:authorize"
        ]
    );

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_rollback_artifact_allows_retry_with_new_authority_sqlite() {
    let path = unique_db_path("chio-hold-authority-rollback-retry");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-lease-0";
    let event_id = "hold-cap-lease-0:authorize";
    let rollback_event_id = "hold-cap-lease-0:authorize:rollback:2";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            100,
            Some(hold_id),
            Some(rollback_event_id),
            Some(&initial),
        )
        .unwrap();

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .unwrap());

    let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-lease"), Some(0))
        .unwrap();
    let authorize = events
        .iter()
        .find(|record| record.event_id == event_id)
        .expect("replacement authorize event");
    assert_eq!(authorize.authority.as_ref(), Some(&changed));

    let _ = fs::remove_file(path);
}

#[test]
fn unrelated_typed_reverse_with_rollback_prefix_cannot_rebind_authorization_claim() {
    let path = unique_db_path("chio-hold-forged-rollback-prefix");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-target-0";
    let event_id = "hold-target-0:authorize";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-target",
            0,
            Some(10),
            100,
            Some(200),
            Some(1_000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-unrelated",
            0,
            Some(10),
            1,
            Some(10),
            Some(100),
            Some("hold-unrelated-0"),
            Some("hold-unrelated-0:authorize"),
            Some(&changed),
        )
        .unwrap());
    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-unrelated",
            0,
            1,
            Some("hold-unrelated-0"),
            Some("hold-target-0:authorize:rollback:forged"),
            Some(&changed),
        )
        .unwrap();

    let error = store
        .try_charge_cost_with_ids_and_authority(
            "cap-target",
            0,
            Some(10),
            100,
            Some(200),
            Some(1_000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .expect_err("an unrelated prefixed reverse must not unlock authority rebinding");
    assert!(matches!(error, BudgetStoreError::Invariant(_)));

    let target_events = store
        .list_mutation_events(10, Some("cap-target"), Some(0))
        .unwrap();
    assert_eq!(target_events.len(), 1);
    assert_eq!(target_events[0].event_id, event_id);
    assert_eq!(target_events[0].authority.as_ref(), Some(&initial));
    let usage = store.get_usage("cap-target", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn compensated_authorization_resolves_current_authority_but_exact_retry_stays_frozen() {
    let path = unique_db_path("chio-hold-authority-source-after-compensation");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-authority-source";
    let event_id = "hold-authority-source:authorize";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-authority-source",
            0,
            Some(10),
            50,
            Some(100),
            Some(500),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    let persisted_hint = store
        .authorization_authority_source(Some(hold_id), event_id)
        .unwrap();
    assert_eq!(
        persisted_hint,
        SqliteBudgetAuthorizationAuthority::Persisted(Some(initial.clone()))
    );

    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-authority-source",
            0,
            50,
            Some(hold_id),
            Some("hold-authority-source:authorize:rollback:1"),
            Some(&initial),
        )
        .unwrap();
    assert_eq!(
        store
            .authorization_authority_source(Some(hold_id), event_id)
            .unwrap(),
        SqliteBudgetAuthorizationAuthority::Current
    );

    let stale_candidate = match persisted_hint {
        SqliteBudgetAuthorizationAuthority::Persisted(_) => {
            SqliteBudgetCurrentAuthority::Unavailable
        }
        SqliteBudgetAuthorizationAuthority::Current => {
            panic!("pre-compensation source unexpectedly required current authority")
        }
    };
    let unavailable_error = store
        .try_charge_cost_with_ids_and_current_authority_outcome(
            "cap-authority-source",
            0,
            Some(10),
            50,
            Some(100),
            Some(500),
            Some(hold_id),
            Some(event_id),
            stale_candidate,
        )
        .expect_err("a stale persisted-authority hint must not survive compensation");
    assert!(matches!(unavailable_error, BudgetStoreError::Invariant(_)));

    let downgrade_error = store
        .try_charge_cost_with_ids_and_current_authority_outcome(
            "cap-authority-source",
            0,
            Some(10),
            50,
            Some(100),
            Some(500),
            Some(hold_id),
            Some(event_id),
            SqliteBudgetCurrentAuthority::Resolved(None),
        )
        .expect_err("a compensated HA claim must not downgrade to detached authority");
    assert!(matches!(downgrade_error, BudgetStoreError::Invariant(_)));

    let replacement = store
        .try_charge_cost_with_ids_and_current_authority_outcome(
            "cap-authority-source",
            0,
            Some(10),
            50,
            Some(100),
            Some(500),
            Some(hold_id),
            Some(event_id),
            SqliteBudgetCurrentAuthority::Resolved(Some(changed.clone())),
        )
        .unwrap();
    assert!(replacement.allowed);
    assert!(replacement.event_created);
    assert_eq!(replacement.authority.as_ref(), Some(&changed));

    let events = store
        .list_mutation_events(10, Some("cap-authority-source"), Some(0))
        .unwrap();
    let authorize = events
        .iter()
        .find(|event| event.event_id == event_id)
        .expect("replacement authorization event");
    assert_eq!(authorize.authority.as_ref(), Some(&changed));

    let _ = fs::remove_file(path);
}

#[test]
fn authorization_write_outcome_marks_only_the_transaction_that_created_the_event() {
    let path = unique_db_path("chio-hold-created-outcome");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let authority = authority("budget-primary", "lease-7", 7);

    let first = store
        .try_charge_cost_with_ids_and_authority_outcome(
            "cap-created-outcome",
            0,
            Some(10),
            25,
            Some(50),
            Some(500),
            Some("hold-created-outcome"),
            Some("hold-created-outcome:authorize"),
            Some(&authority),
        )
        .unwrap();
    assert!(first.allowed);
    assert!(first.event_created);

    let retry = store
        .try_charge_cost_with_ids_and_authority_outcome(
            "cap-created-outcome",
            0,
            Some(10),
            25,
            Some(50),
            Some(500),
            Some("hold-created-outcome"),
            Some("hold-created-outcome:authorize"),
            Some(&authority),
        )
        .unwrap();
    assert!(retry.allowed);
    assert!(!retry.event_created);

    let usage = store.get_usage("cap-created-outcome", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 25, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_retry_after_rollback_replaces_orphaned_open_hold_once_sqlite() {
    let path = unique_db_path("chio-hold-rollback-orphan-retry");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-orphan-0";
    let event_id = "hold-cap-orphan-0:authorize";
    let rollback_event_id = "hold-cap-orphan-0:authorize:rollback:5";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    for _ in 0..3 {
        assert!(store
            .try_increment_with_event_id("cap-orphan", 0, Some(10), None)
            .unwrap());
    }
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-orphan",
            0,
            Some(10),
            75,
            Some(100),
            Some(400),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-orphan",
            0,
            75,
            Some(hold_id),
            Some(rollback_event_id),
            Some(&initial),
        )
        .unwrap();

    {
        let mut connection = store.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                params![event_id],
            )
            .unwrap();
        SqliteBudgetStore::upsert_hold(
            &transaction,
            hold_id,
            "cap-orphan",
            0,
            75,
            75,
            HoldDisposition::Open,
            Some(&initial),
        )
        .unwrap();
        transaction.commit().unwrap();
    }

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-orphan",
            0,
            Some(10),
            75,
            Some(100),
            Some(400),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .unwrap());

    let usage = store.get_usage("cap-orphan", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 4);
    assert_usage_totals(&usage, 75, 0);

    let events = store
        .list_mutation_events(20, Some("cap-orphan"), Some(0))
        .unwrap();
    let rollback = events
        .iter()
        .find(|record| record.event_id == rollback_event_id)
        .expect("rollback event");
    let retry = events
        .iter()
        .find(|record| record.event_id == event_id)
        .expect("retry authorize event");
    assert!(retry.event_seq > rollback.event_seq);
    assert_eq!(retry.authority.as_ref(), Some(&changed));

    {
        let mut connection = store.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)
            .unwrap()
            .expect("retry open hold");
        assert_eq!(hold.remaining_exposure_units, 75);
        assert_eq!(hold.disposition, HoldDisposition::Open);
    }

    {
        let mut connection = store.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                params![event_id],
            )
            .unwrap();
        transaction.commit().unwrap();
    }

    let missing_replacement = store
        .try_charge_cost_with_ids_and_authority(
            "cap-orphan",
            0,
            Some(10),
            75,
            Some(100),
            Some(400),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .expect_err("a replacement authorization event cannot be recreated without compensation");
    assert!(matches!(
        missing_replacement,
        BudgetStoreError::Invariant(_)
    ));
    let events = store
        .list_mutation_events(20, Some("cap-orphan"), Some(0))
        .unwrap();
    assert!(events.iter().all(|record| record.event_id != event_id));
    let unchanged = store.get_usage("cap-orphan", 0).unwrap().unwrap();
    assert_eq!(unchanged, usage);

    let _ = fs::remove_file(path);
}

#[test]
fn import_mutation_record_keeps_duplicate_release_events_idempotent_sqlite() {
    let path = unique_db_path("chio-budget-import-release-idempotent");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-import-0";
    let authorize_event_id = "hold-cap-import-0:authorize";
    let release_event_id = "hold-cap-import-0:release";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-import",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(authorize_event_id),
        )
        .unwrap());
    store
        .reduce_charge_cost_with_ids("cap-import", 0, 100, Some(hold_id), Some(release_event_id))
        .unwrap();

    let release_record = store
        .list_mutation_events(10, Some("cap-import"), Some(0))
        .unwrap()
        .into_iter()
        .find(|record| record.event_id == release_event_id)
        .expect("release event record");

    store.import_mutation_record(&release_record).unwrap();

    let usage = store.get_usage("cap-import", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 0, 0);

    {
        let mut connection = store.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)
            .unwrap()
            .expect("released hold state");
        assert_eq!(hold.remaining_exposure_units, 0);
        assert_eq!(hold.disposition, HoldDisposition::Released);
    }

    let events = store
        .list_mutation_events(10, Some("cap-import"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_id, authorize_event_id);
    assert_eq!(events[1].event_id, release_event_id);

    let _ = fs::remove_file(path);
}

#[test]
fn import_mutation_record_preserves_captured_hold_state_sqlite() {
    let source_path = unique_db_path("chio-budget-import-capture-source");
    let target_path = unique_db_path("chio-budget-import-capture-target");
    let source = SqliteBudgetStore::open(&source_path).unwrap();
    let hold_id = "hold-cap-import-capture-0";

    assert!(source
        .try_charge_cost_with_ids(
            "cap-import-capture",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some("hold-cap-import-capture-0:authorize"),
        )
        .unwrap());
    source
        .capture_budget_hold(BudgetCaptureHoldRequest {
            capability_id: "cap-import-capture".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 60,
            hold_id: Some(hold_id.to_string()),
            event_id: Some("hold-cap-import-capture-0:capture".to_string()),
            authority: None,
        })
        .unwrap();
    let records = source
        .list_mutation_events(10, Some("cap-import-capture"), Some(0))
        .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].kind, BudgetMutationKind::CaptureExposure);
    assert_eq!(records[1].monetary_state, BudgetMonetaryHoldState::Captured);

    let target = SqliteBudgetStore::open(&target_path).unwrap();
    target.import_mutation_record(&records[0]).unwrap();
    target.import_mutation_record(&records[1]).unwrap();
    target.import_mutation_record(&records[1]).unwrap();

    {
        let mut connection = target.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .unwrap();
        let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)
            .unwrap()
            .expect("imported captured hold state");
        assert_eq!(hold.remaining_exposure_units, 0);
        assert_eq!(hold.disposition, HoldDisposition::Captured);
    }
    let imported = target
        .list_mutation_events(10, Some("cap-import-capture"), Some(0))
        .unwrap();
    assert_eq!(imported.len(), 2);
    assert_eq!(imported[1].kind, BudgetMutationKind::CaptureExposure);
    assert_eq!(
        imported[1].monetary_state,
        BudgetMonetaryHoldState::Captured
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(target_path);
}

#[test]
fn import_mutation_record_rejects_out_of_range_sqlite_integers_before_floor_raise() {
    let mut candidates = Vec::new();

    let mut record = import_integrity_record("overflow-event-seq", 2);
    record.event_seq = u64::MAX;
    candidates.push(("event_seq", record));

    let mut record = import_integrity_record("overflow-usage-seq", 2);
    record.usage_seq = Some(u64::MAX);
    candidates.push(("usage_seq", record));

    let mut record = import_integrity_record("overflow-exposure", 2);
    record.exposure_units = u64::MAX;
    candidates.push(("exposure_units", record));

    let mut record = import_integrity_record("overflow-realized", 2);
    record.realized_spend_units = u64::MAX;
    candidates.push(("realized_spend_units", record));

    let mut record = import_integrity_record("overflow-max-per", 2);
    record.max_cost_per_invocation = Some(u64::MAX);
    candidates.push(("max_cost_per_invocation", record));

    let mut record = import_integrity_record("overflow-max-total", 2);
    record.max_total_cost_units = Some(u64::MAX);
    candidates.push(("max_total_cost_units", record));

    let mut record = import_integrity_record("overflow-exposed-total", 2);
    record.total_cost_exposed_after = u64::MAX;
    candidates.push(("total_cost_exposed_after", record));

    let mut record = import_integrity_record("overflow-realized-total", 2);
    record.total_cost_realized_spend_after = u64::MAX;
    candidates.push(("total_cost_realized_spend_after", record));

    let mut record = import_integrity_record("overflow-lease-epoch", 2);
    record.authority.as_mut().unwrap().lease_epoch = u64::MAX;
    candidates.push(("lease_epoch", record));

    for (field, record) in candidates {
        let path = unique_db_path(&format!("chio-budget-import-overflow-{field}"));
        let store = SqliteBudgetStore::open(&path).unwrap();
        store
            .import_mutation_record(&import_integrity_record("baseline", 1))
            .unwrap();

        let error = store
            .import_mutation_record(&record)
            .expect_err("out-of-range imported integer must fail closed");
        assert!(
            matches!(error, BudgetStoreError::Overflow(_)),
            "{field} returned the wrong error: {error}"
        );
        assert_eq!(
            replication_floor(&store),
            1,
            "{field} advanced the replication floor before rejection"
        );
        assert_eq!(
            store.max_mutation_event_seq().unwrap(),
            1,
            "{field} persisted a rejected mutation"
        );

        let _ = fs::remove_file(path);
    }
}

#[test]
fn imported_usage_rejects_out_of_range_sqlite_integers_before_floor_raise() {
    let mut records = Vec::new();

    let mut record = usage_record("cap-overflow-seq", 0, 1, 100, 1, 0, 0);
    record.seq = u64::MAX;
    records.push(("seq", record));

    let mut record = usage_record("cap-overflow-exposed", 0, 1, 100, 1, 0, 0);
    record.total_cost_exposed = u64::MAX;
    records.push(("total_cost_exposed", record));

    let mut record = usage_record("cap-overflow-realized", 0, 1, 100, 1, 0, 0);
    record.total_cost_realized_spend = u64::MAX;
    records.push(("total_cost_realized_spend", record));

    for (field, record) in records {
        let path = unique_db_path(&format!("chio-budget-usage-overflow-{field}"));
        let store = SqliteBudgetStore::open(&path).unwrap();

        let error = store
            .upsert_usage(&record)
            .expect_err("out-of-range imported usage must fail closed");
        assert!(
            matches!(error, BudgetStoreError::Overflow(_)),
            "{field} returned the wrong error: {error}"
        );
        assert_eq!(replication_floor(&store), 0, "{field} advanced the floor");
        assert!(store.list_all_usages().unwrap().is_empty());

        let _ = fs::remove_file(path);
    }
}

#[test]
fn imported_duplicate_identity_binds_sequences_time_states_and_authority() {
    let path = unique_db_path("chio-budget-import-exact-identity");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let original = import_integrity_record("exact-event", 1);
    store.import_mutation_record(&original).unwrap();
    store.import_mutation_record(&original).unwrap();

    let mut variants = Vec::new();

    let mut record = original.clone();
    record.event_seq = 2;
    record.usage_seq = Some(2);
    variants.push(("event_seq", record));

    let mut record = original.clone();
    record.usage_seq = Some(2);
    variants.push(("usage_seq", record));

    let mut record = original.clone();
    record.recorded_at += 1;
    variants.push(("recorded_at", record));

    let mut record = original.clone();
    record.invocation_state = BudgetInvocationReservationState::Denied;
    variants.push(("invocation_state", record));

    let mut record = original.clone();
    record.monetary_state = BudgetMonetaryHoldState::Captured;
    variants.push(("monetary_state", record));

    let mut record = original.clone();
    record.authority.as_mut().unwrap().lease_epoch += 1;
    variants.push(("authority", record));

    for (field, record) in variants {
        let error = store
            .import_mutation_record(&record)
            .expect_err("changed duplicate identity must fail closed");
        assert!(
            matches!(error, BudgetStoreError::Invariant(_)),
            "{field} returned the wrong error: {error}"
        );
        assert_eq!(
            replication_floor(&store),
            1,
            "{field} advanced the floor before duplicate rejection"
        );
        assert_eq!(
            store
                .mutation_event_seq_for_event_id("exact-event")
                .unwrap(),
            Some(1)
        );
    }

    let _ = fs::remove_file(path);
}

#[test]
fn capture_fails_closed_when_replication_sequence_is_exhausted() {
    let path = unique_db_path("chio-budget-capture-sequence-exhausted");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-sequence-exhausted";
    assert!(store
        .try_charge_cost_with_ids(
            "cap-sequence-exhausted",
            0,
            Some(2),
            100,
            Some(100),
            Some(200),
            Some(hold_id),
            Some("event-sequence-exhausted-authorize"),
        )
        .unwrap());
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE budget_replication_meta SET next_seq = ?1 WHERE singleton = 1",
            params![i64::MAX],
        )
        .unwrap();

    let error = store
        .capture_budget_hold(BudgetCaptureHoldRequest {
            capability_id: "cap-sequence-exhausted".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 60,
            hold_id: Some(hold_id.to_string()),
            event_id: Some("event-sequence-exhausted-capture".to_string()),
            authority: None,
        })
        .expect_err("sequence exhaustion must reject capture");
    assert!(
        error
            .to_string()
            .contains("budget replication sequence exceeds SQLite INTEGER"),
        "unexpected error: {error}"
    );
    assert_eq!(replication_floor(&store), i64::MAX);
    let usage = store
        .get_usage("cap-sequence-exhausted", 0)
        .unwrap()
        .unwrap();
    assert_usage_totals(&usage, 100, 0);
    let mut connection = store.connection().unwrap();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .unwrap();
    let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)
        .unwrap()
        .unwrap();
    assert_eq!(hold.remaining_exposure_units, 100);
    assert_eq!(hold.disposition, HoldDisposition::Open);

    let _ = fs::remove_file(path);
}

#[test]
fn abandoned_sequence_snapshot_rejects_out_of_range_before_mutation() {
    let path = unique_db_path("chio-budget-abandoned-sequence-overflow");
    let store = SqliteBudgetStore::open(&path).unwrap();
    store.record_abandoned_event_seqs(&[1]).unwrap();

    let error = store
        .record_abandoned_event_seqs(&[2, u64::MAX])
        .expect_err("out-of-range abandoned sequence must fail closed");
    assert!(matches!(error, BudgetStoreError::Overflow(_)));
    assert_eq!(store.list_abandoned_event_seqs().unwrap(), vec![1]);

    let _ = fs::remove_file(path);
}

#[test]
fn abandoned_sequence_range_snapshot_rejects_out_of_range_before_mutation() {
    let path = unique_db_path("chio-budget-abandoned-range-overflow");
    let store = SqliteBudgetStore::open(&path).unwrap();
    store
        .import_mutation_record(&import_integrity_record("range-boundary", 2))
        .unwrap();
    store.record_abandoned_event_seq_ranges(&[(1, 1)]).unwrap();

    let cases = [vec![(2, 2), (4, u64::MAX)], vec![(u64::MAX, u64::MAX)]];
    for ranges in cases {
        let error = store
            .record_abandoned_event_seq_ranges(&ranges)
            .expect_err("out-of-range abandoned sequence range must fail closed");
        assert!(matches!(error, BudgetStoreError::Overflow(_)));
        assert_eq!(store.list_abandoned_event_seqs().unwrap(), vec![1]);
    }

    let _ = fs::remove_file(path);
}

#[test]
fn abandoned_sequence_range_snapshot_rejects_noncanonical_work_before_mutation() {
    let path = unique_db_path("chio-budget-abandoned-range-bounds");
    let store = SqliteBudgetStore::open(&path).unwrap();
    store
        .import_mutation_record(&import_integrity_record("range-canonical-boundary", 2))
        .unwrap();
    store.record_abandoned_event_seq_ranges(&[(1, 1)]).unwrap();

    let invalid = [
        ("unsorted", vec![(10, 10), (3, 3)]),
        ("overlap", vec![(3, 5), (5, 7)]),
        ("adjacent", vec![(3, 5), (6, 7)]),
    ];
    for (case, ranges) in invalid {
        let error = store
            .record_abandoned_event_seq_ranges(&ranges)
            .expect_err("invalid abandoned range snapshot must fail closed");
        assert!(
            matches!(error, BudgetStoreError::Invariant(_)),
            "{case} returned the wrong error: {error}"
        );
        assert_eq!(
            store.list_abandoned_event_seqs().unwrap(),
            vec![1],
            "{case} partially mutated the abandoned sequence set"
        );
    }

    let _ = fs::remove_file(path);
}

#[test]
fn budget_import_floor_snapshot_rejects_out_of_range_before_mutation() {
    let path = unique_db_path("chio-budget-import-floor-overflow");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let mut event = import_integrity_record("overflow-import-floor", u64::MAX);
    event.usage_seq = None;

    let error = store
        .record_budget_import_floors(&[event])
        .expect_err("out-of-range imported floor must fail closed");
    assert!(matches!(error, BudgetStoreError::Overflow(_)));
    assert_eq!(store.budget_import_floor("budget-primary").unwrap(), 0);
    let count: i64 = store
        .connection()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM budget_import_floors", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn import_snapshot_records_replay_is_idempotent_when_peer_cursor_is_lost_sqlite() {
    let source_path = unique_db_path("chio-budget-import-replay-source");
    let target_path = unique_db_path("chio-budget-import-replay-target");
    let source = SqliteBudgetStore::open(&source_path).unwrap();

    assert!(source
        .try_charge_cost_with_ids(
            "cap-import-replay",
            0,
            Some(5),
            25,
            Some(50),
            Some(250),
            Some("hold-import-replay-0"),
            Some("hold-import-replay-0:authorize"),
        )
        .unwrap());
    let usage = source
        .get_usage("cap-import-replay", 0)
        .unwrap()
        .expect("source usage");
    let events = source
        .list_mutation_events(10, Some("cap-import-replay"), Some(0))
        .unwrap();

    let target = SqliteBudgetStore::open(&target_path).unwrap();
    target
        .import_snapshot_records(std::slice::from_ref(&usage), &events)
        .unwrap();
    target
        .import_snapshot_records(std::slice::from_ref(&usage), &events)
        .unwrap();

    let replicated_usage = target
        .get_usage("cap-import-replay", 0)
        .unwrap()
        .expect("replicated usage");
    assert_eq!(replicated_usage.invocation_count, 1);
    assert_usage_totals(&replicated_usage, 25, 0);
    let replicated_events = target
        .list_mutation_events(10, Some("cap-import-replay"), Some(0))
        .unwrap();
    assert_eq!(replicated_events.len(), 1);
    assert_eq!(
        replicated_events[0].event_id,
        "hold-import-replay-0:authorize"
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(target_path);
}

#[test]
fn import_snapshot_records_rejects_changed_duplicate_transport_identity_without_mutation_sqlite() {
    let source_path = unique_db_path("chio-budget-import-transport-source");
    let target_path = unique_db_path("chio-budget-import-transport-target");
    let source = SqliteBudgetStore::open(&source_path).unwrap();

    assert!(source
        .try_charge_cost_with_ids(
            "cap-import-transport",
            0,
            Some(10),
            25,
            Some(100),
            Some(500),
            Some("hold-import-transport-0"),
            Some("hold-import-transport-0:authorize"),
        )
        .unwrap());
    let usage = source
        .get_usage("cap-import-transport", 0)
        .unwrap()
        .expect("source usage");
    let events = source
        .list_mutation_events(10, Some("cap-import-transport"), Some(0))
        .unwrap();
    let mut replayed_event = events[0].clone();
    replayed_event.recorded_at = replayed_event.recorded_at.saturating_add(30);
    replayed_event.event_seq = replayed_event.event_seq.saturating_add(5);
    replayed_event.usage_seq = replayed_event.usage_seq.map(|seq| seq.saturating_add(5));

    let target = SqliteBudgetStore::open(&target_path).unwrap();
    target
        .import_snapshot_records(std::slice::from_ref(&usage), &events)
        .unwrap();
    let floor_before = replication_floor(&target);
    let usage_before = target
        .get_usage("cap-import-transport", 0)
        .unwrap()
        .unwrap();
    let events_before = target
        .list_mutation_events(10, Some("cap-import-transport"), Some(0))
        .unwrap();
    let error = target
        .import_snapshot_records(std::slice::from_ref(&usage), &[replayed_event])
        .expect_err("changed duplicate transport identity must fail closed");
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(replication_floor(&target), floor_before);
    assert_eq!(
        target
            .get_usage("cap-import-transport", 0)
            .unwrap()
            .unwrap(),
        usage_before
    );

    let replicated_events = target
        .list_mutation_events(10, Some("cap-import-transport"), Some(0))
        .unwrap();
    assert_eq!(replicated_events, events_before);

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(target_path);
}

#[test]
fn import_snapshot_records_rolls_back_usage_rows_when_mutation_conflicts_sqlite() {
    let path = unique_db_path("chio-budget-import-atomic");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let initial_authority = authority("budget-primary", "lease-1", 1);
    let conflicting_authority = authority("budget-primary", "lease-2", 2);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-import",
            0,
            Some(10),
            25,
            Some(100),
            Some(500),
            Some("hold-cap-import-atomic-0"),
            Some("hold-cap-import-atomic-0:authorize"),
            Some(&initial_authority),
        )
        .unwrap());

    let mut conflicting_event = store
        .list_mutation_events(10, Some("cap-import"), Some(0))
        .unwrap()
        .into_iter()
        .find(|record| record.event_id == "hold-cap-import-atomic-0:authorize")
        .expect("existing authorize event");
    conflicting_event.authority = Some(conflicting_authority);

    let imported_usage = usage_record("cap-import-rollback", 0, 2, unix_now(), 88, 40, 5);

    let error = store
        .import_snapshot_records(&[imported_usage], &[conflicting_event])
        .expect_err("conflicting event import should fail atomically");
    assert!(error
        .to_string()
        .contains("reused for a different mutation"));
    assert!(store.get_usage("cap-import-rollback", 0).unwrap().is_none());

    let existing = store.get_usage("cap-import", 0).unwrap().unwrap();
    assert_eq!(existing.invocation_count, 1);
    assert_usage_totals(&existing, 25, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_open_hold_rejects_missing_authorize_event_without_compensation_sqlite() {
    let path = unique_db_path("chio-hold-authority-recover-missing-event");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-recover-0";
    let event_id = "hold-cap-recover-0:authorize";
    let authority = authority("budget-primary", "lease-7", 7);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-recover",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&authority),
        )
        .unwrap());
    let usage_before = store.get_usage("cap-recover", 0).unwrap().unwrap();
    store.delete_mutation_event(event_id).unwrap();

    let error = store
        .try_charge_cost_with_ids_and_authority(
            "cap-recover",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&authority),
        )
        .expect_err("an authorize event cannot be recreated without a rollback artifact");
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(
        store.get_usage("cap-recover", 0).unwrap().unwrap(),
        usage_before
    );

    let events = store
        .list_mutation_events(10, Some("cap-recover"), Some(0))
        .unwrap();
    assert!(events.is_empty());

    let _ = fs::remove_file(path);
}

#[test]
fn upsert_usage_preserves_newer_split_cost_state() {
    let path = unique_db_path("chio-budget-upsert-cost");
    let store = SqliteBudgetStore::open(&path).unwrap();

    // Higher-seq record written first
    store
        .upsert_usage(&usage_record("cap-1", 0, 5, 10, 10, 500, 0))
        .unwrap();

    // Lower-seq record written second (stale replica)
    store
        .upsert_usage(&usage_record("cap-1", 0, 3, 12, 5, 300, 0))
        .unwrap();

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_usage_totals(&records[0], 500, 0);
    assert_eq!(records[0].seq, 10);

    let _ = fs::remove_file(path);
}

#[test]
fn upsert_usage_does_not_resurrect_split_cost_state_from_stale_seq() {
    let path = unique_db_path("chio-budget-upsert-split");
    let store = SqliteBudgetStore::open(&path).unwrap();

    store
        .upsert_usage(&usage_record("cap-1", 0, 1, 20, 20, 0, 75))
        .unwrap();
    store
        .upsert_usage(&usage_record("cap-1", 0, 1, 10, 10, 100, 0))
        .unwrap();

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_usage_totals(&records[0], 0, 75);
    assert_eq!(records[0].seq, 20);

    let _ = fs::remove_file(path);
}

/// Documents the HA overrun bound for monetary budget enforcement.
///
/// In a split-brain scenario across N nodes, each node may independently
/// approve one invocation at max_cost_per_invocation before the LWW merge
/// propagates. The worst-case overrun is bounded by:
///   overrun <= max_cost_per_invocation * node_count
///
/// This test asserts the bound holds for a simulated 2-node split-brain.
#[test]
fn concurrent_charge_overrun_bound() {
    let path_a = unique_db_path("chio-overrun-node-a");
    let path_b = unique_db_path("chio-overrun-node-b");

    let max_per_invocation: u64 = 100;
    let total_budget: u64 = 150; // Tight: allows 1 full invocation + small buffer
    let node_count: u64 = 2;

    // Both nodes start fresh (simulating split-brain: neither sees the other's write)
    let node_a = SqliteBudgetStore::open(&path_a).unwrap();
    let node_b = SqliteBudgetStore::open(&path_b).unwrap();

    // Both nodes independently approve an invocation of max_per_invocation
    let approved_a = node_a
        .try_charge_cost(
            "cap-split",
            0,
            None,
            max_per_invocation,
            Some(max_per_invocation),
            Some(total_budget),
        )
        .unwrap();
    let approved_b = node_b
        .try_charge_cost(
            "cap-split",
            0,
            None,
            max_per_invocation,
            Some(max_per_invocation),
            Some(total_budget),
        )
        .unwrap();

    // Both nodes approved (split-brain; each sees a fresh slate)
    assert!(approved_a, "node A should approve");
    assert!(approved_b, "node B should approve");

    // The actual combined spend exceeds the total budget
    let combined_spend = max_per_invocation * node_count;
    // The overrun is bounded by max_cost_per_invocation * node_count
    let max_overrun = max_per_invocation * node_count;
    assert!(
        combined_spend <= max_overrun,
        "HA overrun bound violated: combined_spend={combined_spend} > max_overrun={max_overrun}"
    );

    // After LWW merge converges, outstanding exposure remains conservatively bounded.
    let record_a = node_a.list_usages(1, Some("cap-split")).unwrap();
    let record_b = node_b.list_usages(1, Some("cap-split")).unwrap();
    let total_after_merge = record_a[0].total_cost_exposed + record_b[0].total_cost_exposed;
    assert!(
        total_after_merge <= max_overrun,
        "post-merge total {total_after_merge} exceeds bound {max_overrun}"
    );

    let _ = fs::remove_file(path_a);
    let _ = fs::remove_file(path_b);
}

#[test]
fn budget_store_zero_max_total_denies_any_charge_inmemory() {
    // A grant with max_total_cost = 0 must deny even a charge of 1 unit.
    let store = InMemoryBudgetStore::new();
    let ok = store
        .try_charge_cost("cap-zero-budget", 0, None, 1, None, Some(0))
        .unwrap();
    assert!(
        !ok,
        "any charge against a zero-unit total budget must be denied"
    );
    let records = store.list_usages(10, Some("cap-zero-budget")).unwrap();
    assert!(
        records.is_empty() || records[0].invocation_count == 0,
        "no invocations should be recorded against a zero-unit budget"
    );
}

#[test]
fn budget_store_zero_max_total_denies_any_charge_sqlite() {
    let path = unique_db_path("chio-zero-budget-sqlite");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let ok = store
        .try_charge_cost("cap-zero-budget", 0, None, 1, None, Some(0))
        .unwrap();
    assert!(
        !ok,
        "any charge against a zero-unit total budget must be denied"
    );
    let records = store.list_usages(10, Some("cap-zero-budget")).unwrap();
    assert!(
        records.is_empty() || records[0].invocation_count == 0,
        "no invocations should be recorded against a zero-unit budget"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_zero_cost_invocation_succeeds_and_records_zero_inmemory() {
    // A zero-cost invocation against a monetary grant should succeed and
    // record cost_charged = 0.
    let store = InMemoryBudgetStore::new();
    let ok = store
        .try_charge_cost("cap-zero-cost", 0, None, 0, None, Some(1000))
        .unwrap();
    assert!(
        ok,
        "zero-cost invocation should succeed when budget is available"
    );
    let records = store.list_usages(10, Some("cap-zero-cost")).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].invocation_count, 1);
    assert_usage_totals(&records[0], 0, 0);
}

#[test]
fn budget_store_zero_cost_invocation_succeeds_and_records_zero_sqlite() {
    let path = unique_db_path("chio-zero-cost-sqlite");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let ok = store
        .try_charge_cost("cap-zero-cost", 0, None, 0, None, Some(1000))
        .unwrap();
    assert!(
        ok,
        "zero-cost invocation should succeed when budget is available"
    );
    let records = store.list_usages(10, Some("cap-zero-cost")).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].invocation_count, 1);
    assert_usage_totals(&records[0], 0, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn max_mutation_event_seq_reports_head() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-head");
    let store = SqliteBudgetStore::open(&path)?;
    assert_eq!(store.max_mutation_event_seq()?, 0);
    // A single authorize charge allocates event_seq 1.
    store.try_charge_cost("cap-a", 0, Some(5), 3, None, None)?;
    assert_eq!(store.max_mutation_event_seq()?, 1);
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_ack_heads_reports_contiguous_prefix_only() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-ack-heads");
    let store = SqliteBudgetStore::open(&path)?;

    // Import events {40, 42} for origin O (41 skipped) via the snapshot path,
    // which is how a peer's log arrives; floor defaults to 0.
    let event = |seq: u64| BudgetMutationRecord {
        event_id: format!("evt-{seq}"),
        hold_id: None,
        capability_id: "cap-o".to_string(),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_counts_after: Vec::new(),
        invocation_state: BudgetInvocationReservationState::Absent,
        monetary_state: BudgetMonetaryHoldState::Exposed,
        revocation_set: None,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: "http://origin-o".to_string(),
            lease_id: "http://origin-o#term-1".to_string(),
            lease_epoch: 1,
        }),
    };
    // Missing prefix (holds only {42,43}): with floor 0, no row is in the
    // island=0 group, so the origin is absent -> caller defaults to floor 0.
    store.import_snapshot_records(&[], &[event(42), event(43)])?;
    let heads = store.budget_ack_heads()?;
    assert!(
        heads.iter().all(|(origin, _)| origin != "http://origin-o"),
        "a missing prefix must not be laundered into an ack head"
    );

    // Now add the contiguous prefix 1..=41 for the same origin: the head is
    // the last contiguous seq before the 42/43 island, i.e. 43 becomes reachable.
    let contiguous: Vec<_> = (1..=41).map(event).collect();
    store.import_snapshot_records(&[], &contiguous)?;
    let heads = store.budget_ack_heads()?;
    let head = heads
        .iter()
        .find(|(origin, _)| origin == "http://origin-o")
        .map(|(_, seq)| *seq)
        .ok_or("origin O must now have a contiguous ack head")?;
    assert_eq!(head, 43, "1..=43 is now gap-free, so the head is 43");

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_ack_heads_caps_partial_head_at_interior_gap() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-ack-heads-partial");
    let store = SqliteBudgetStore::open(&path)?;

    let event = |seq: u64| BudgetMutationRecord {
        event_id: format!("evt-{seq}"),
        hold_id: None,
        capability_id: "cap-p".to_string(),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_counts_after: Vec::new(),
        invocation_state: BudgetInvocationReservationState::Absent,
        monetary_state: BudgetMonetaryHoldState::Exposed,
        revocation_set: None,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: "http://origin-p".to_string(),
            lease_id: "http://origin-p#term-1".to_string(),
            lease_epoch: 1,
        }),
    };

    // Import {1,2,3,5,6} from floor 0: the run reaches down to the floor and is
    // gap-free through 3, then an interior gap at 4 splits off the {5,6} island.
    // The contiguous ack head must be the last gap-free seq (3), NOT the max
    // present seq (6): a mid-stream hole yields a PARTIAL head.
    store.import_snapshot_records(&[], &[event(1), event(2), event(3), event(5), event(6)])?;
    let heads = store.budget_ack_heads()?;
    let head = heads
        .iter()
        .find(|(origin, _)| origin == "http://origin-p")
        .map(|(_, seq)| *seq)
        .ok_or("origin P has a contiguous prefix from the floor, so it must report a head")?;
    assert_eq!(
        head, 3,
        "an interior gap at 4 caps the head at 3, not the max present seq 6"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_ack_heads_stays_pinned_at_a_post_watermark_gap() -> Result<(), Box<dyn std::error::Error>>
{
    // Once the watermark W has advanced over a contiguous prefix and a REAL hole
    // sits at
    // W+1, the head is pinned at W. The status-path fast path probes only the
    // single W+1 slot and short-circuits the O(suffix) window scan, so it must
    // (a) keep returning W across repeated polls (never advance over the gap) and
    // (b) advance correctly the moment the gap is filled - the result must match
    // the genesis-anchored gaps-and-islands computation exactly.
    let path = unique_db_path("chio-ack-heads-post-watermark-gap");
    let store = SqliteBudgetStore::open(&path)?;

    let origin = "http://origin-g";
    let event = |seq: u64| BudgetMutationRecord {
        event_id: format!("evt-{seq}"),
        hold_id: None,
        capability_id: "cap-g".to_string(),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_counts_after: Vec::new(),
        invocation_state: BudgetInvocationReservationState::Absent,
        monetary_state: BudgetMonetaryHoldState::Exposed,
        revocation_set: None,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: origin.to_string(),
            lease_id: format!("{origin}#term-1"),
            lease_epoch: 1,
        }),
    };
    let origin_head = |heads: &[(String, u64)]| -> Option<u64> {
        heads
            .iter()
            .find(|(id, _)| id == origin)
            .map(|(_, seq)| *seq)
    };

    // Contiguous {1,2,3}: the head reaches 3 and the durable watermark advances to 3.
    store.import_snapshot_records(&[], &[event(1), event(2), event(3)])?;
    assert_eq!(origin_head(&store.budget_ack_heads()?), Some(3));

    // A hole at 4 (== W+1) with a later island {5,6}: the head must stay pinned at
    // 3 no matter how many times it is polled, and must never jump over the gap.
    store.import_snapshot_records(&[], &[event(5), event(6)])?;
    for _ in 0..3 {
        assert_eq!(
            origin_head(&store.budget_ack_heads()?),
            Some(3),
            "a permanent hole at W+1 keeps the head pinned at W (fail-closed, no over-count)"
        );
    }

    // Filling the gap at 4 lets the head advance across the now-contiguous 4,5,6.
    store.import_snapshot_records(&[], &[event(4)])?;
    assert_eq!(
        origin_head(&store.budget_ack_heads()?),
        Some(6),
        "filling W+1 advances the head over the now-contiguous 4,5,6"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn list_abandoned_event_seqs_in_range_bounds_upper_and_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    // The budget delta endpoint must never serialize an unbounded abandoned window.
    // The bounded query enforces
    // BOTH an upper bound (<= page_max) and a row cap in SQL, so a rollback storm
    // cannot materialize millions of tombstones into one response and blow past
    // the peer-response byte cap.
    let path = unique_db_path("chio-abandoned-in-range");
    let store = SqliteBudgetStore::open(&path)?;

    let seqs: Vec<u64> = (1..=1000).collect();
    store.record_abandoned_event_seqs(&seqs)?;

    // Upper bound: only (10, 20], ascending.
    let bounded = store.list_abandoned_event_seqs_in_range(10, 20, 100)?;
    assert_eq!(bounded, (11..=20).collect::<Vec<u64>>());

    // Row cap: a huge window returns at most `limit` rows, never the whole window.
    let capped = store.list_abandoned_event_seqs_in_range(0, 1000, 5)?;
    assert_eq!(capped, vec![1, 2, 3, 4, 5]);

    // Contrast: the unbounded method returns the whole window (the oversized-response
    // risk the bounded query removes).
    assert_eq!(store.list_abandoned_event_seqs_after(0)?.len(), 1000);

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn abandoned_seq_ranges_round_trip_and_advance_the_head() -> Result<(), Box<dyn std::error::Error>>
{
    // The cluster snapshot carries abandoned seqs RANGE-ENCODED so a rollback storm's
    // long contiguous run stays a handful of small pairs instead of an unbounded
    // integer list that could exceed MAX_PEER_RESPONSE_BYTES and stall recovery.
    // list_abandoned_event_seq_ranges must COLLAPSE contiguous runs, and
    // record_abandoned_event_seq_ranges must preserve them compactly while exposing
    // the identical bounded sequence set.
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };

    // Enumerated form -> range-encoded runs: {2,3,4},{7},{9,10} collapse to 3 pairs.
    let source_path = unique_db_path("chio-abandoned-ranges-source");
    let source = SqliteBudgetStore::open(&source_path)?;
    source.record_abandoned_event_seqs(&[2, 3, 4, 7, 9, 10])?;
    assert_eq!(
        source.list_abandoned_event_seq_ranges()?,
        vec![(2, 4), (7, 7), (9, 10)],
        "contiguous abandoned seqs must collapse to inclusive runs"
    );

    // Range form -> bounded sequence set on a fresh follower.
    let follower_path = unique_db_path("chio-abandoned-ranges-follower");
    let follower = SqliteBudgetStore::open(&follower_path)?;
    follower.import_snapshot_records(&[], &[ack_head_event(11, "boundary", "http://o")])?;
    follower.record_abandoned_event_seq_ranges(&[(2, 4), (7, 7), (9, 10)])?;
    assert_eq!(
        follower.list_abandoned_event_seqs()?,
        vec![2, 3, 4, 7, 9, 10],
        "a follower exposes the compact runs as the identical bounded seq set"
    );

    // A single LARGE contiguous run collapses to ONE pair (the rollback-storm case):
    // recorded as one durable compact row.
    let storm_path = unique_db_path("chio-abandoned-ranges-storm");
    let storm = SqliteBudgetStore::open(&storm_path)?;
    storm.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://o"),
            ack_head_event(50_002, "e-tail", "http://o"),
        ],
    )?;
    storm.record_abandoned_event_seq_ranges(&[(2, 50_001)])?;
    let ranges = storm.list_abandoned_event_seq_ranges()?;
    assert_eq!(
        ranges,
        vec![(2, 50_001)],
        "a 50k-seq rollback storm stays a single (start, end) pair"
    );
    assert_eq!(storm.list_abandoned_event_seqs()?.len(), 50_000);

    // Head advance: present {1, 50002} with the whole (2, 50001) run abandoned makes
    // [1..=50002] contiguous, so the head advances across the run - exactly as if each
    // seq had been recorded individually.
    assert_eq!(
        head_for(&storm.budget_ack_heads()?, "http://o"),
        Some(50_002),
        "the abandoned RANGE fills every hole so the head advances past the whole run"
    );

    let _ = fs::remove_file(&source_path);
    let _ = fs::remove_file(&follower_path);
    let _ = fs::remove_file(&storm_path);
    Ok(())
}

#[test]
fn compact_abandoned_billion_span_stays_constant_size_and_advances_ack_head(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-abandoned-ranges-billion");
    let store = SqliteBudgetStore::open(&path)?;
    let tail = 2_000_000_001u64;
    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "billion-head", "http://compact-origin"),
            ack_head_event(tail, "billion-tail", "http://compact-origin"),
        ],
    )?;

    let live_overlap = store
        .record_abandoned_event_seq_ranges(&[(tail - 1, tail)])
        .expect_err("an abandoned range must not overlap a live mutation event");
    assert!(matches!(live_overlap, BudgetStoreError::Invariant(_)));
    assert!(store.list_abandoned_event_seq_ranges()?.is_empty());

    store.record_abandoned_event_seq_ranges(&[(2, 1_000_000_001)])?;
    store.record_abandoned_event_seq_ranges(&[(500_000_000, 1_500_000_000)])?;
    store.record_abandoned_event_seq_ranges(&[(1_500_000_001, 2_000_000_000)])?;
    assert_eq!(
        store.list_abandoned_event_seq_ranges()?,
        vec![(2, 2_000_000_000)]
    );
    let (range_rows, point_rows): (i64, i64) = store.connection()?.query_row(
        r#"
        SELECT
            (SELECT COUNT(*) FROM budget_abandoned_event_ranges),
            (SELECT COUNT(*) FROM budget_abandoned_event_seqs)
        "#,
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!((range_rows, point_rows), (1, 0));
    assert_eq!(
        store.list_abandoned_event_seqs_in_range(0, tail, 5)?,
        vec![2, 3, 4, 5, 6]
    );
    assert!(matches!(
        store.list_abandoned_event_seqs(),
        Err(BudgetStoreError::Invariant(_))
    ));

    let heads = store.budget_ack_heads()?;
    assert_eq!(
        heads
            .iter()
            .find(|(origin, _)| origin == "http://compact-origin")
            .map(|(_, seq)| *seq),
        Some(tail)
    );

    let imported_collision = store
        .import_mutation_record(&ack_head_event(
            1_000_000,
            "inside-compact-range",
            "http://compact-origin",
        ))
        .expect_err("an imported live event must not reuse an abandoned range slot");
    assert!(matches!(imported_collision, BudgetStoreError::Invariant(_)));
    assert!(store
        .list_mutation_events(10, None, None)?
        .iter()
        .all(|event| event.event_id != "inside-compact-range"));

    assert!(store.try_increment_with_event_id(
        "cap-after-compact-range",
        0,
        None,
        Some("event-after-compact-range"),
    )?);
    let allocated = store
        .list_mutation_events(10, Some("cap-after-compact-range"), Some(0))?
        .into_iter()
        .find(|event| event.event_id == "event-after-compact-range")
        .expect("allocated event after compact range");
    assert_eq!(allocated.event_seq, tail + 1);

    let ranges_before = store.list_abandoned_event_seq_ranges()?;
    let future = store
        .record_abandoned_event_seq_ranges(&[(tail + 2, tail + 10)])
        .expect_err("a future abandoned range must not raise the allocation floor");
    assert!(matches!(future, BudgetStoreError::Invariant(_)));
    assert_eq!(store.list_abandoned_event_seq_ranges()?, ranges_before);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn budget_ack_heads_recognizes_multi_authority_global_contiguity(
) -> Result<(), Box<dyn std::error::Error>> {
    // event_seq is a single store-wide sequence, so multiple authorities share
    // one global stream and an origin's events are a sparse subsequence of it.
    // budget_ack_heads must anchor on the GLOBAL contiguous head, not a per-origin
    // island.
    let path = unique_db_path("chio-ack-heads-multi");
    let store = SqliteBudgetStore::open(&path)?;

    let event = |seq: u64, origin: &str| BudgetMutationRecord {
        event_id: format!("evt-{origin}-{seq}"),
        hold_id: None,
        capability_id: "cap-m".to_string(),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_counts_after: Vec::new(),
        invocation_state: BudgetInvocationReservationState::Absent,
        monetary_state: BudgetMonetaryHoldState::Exposed,
        revocation_set: None,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: origin.to_string(),
            lease_id: format!("{origin}#term-1"),
            lease_epoch: 1,
        }),
    };
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };
    let a = "http://origin-a";
    let b = "http://origin-b";

    // Interleaved gap-free global prefix 1..=5: A owns {1,2,5}, B owns {3,4}.
    // Even though A's own seqs (1,2,5) are NOT consecutive integers, the GLOBAL
    // stream is gap-free, so both origins are acked at their true max within the
    // global head (5): A -> 5, B -> 4. A per-origin island query would wrongly
    // cap A at 2 (the 5 looks like a gap in A's own order).
    store.import_snapshot_records(
        &[],
        &[
            event(1, a),
            event(2, a),
            event(3, b),
            event(4, b),
            event(5, a),
        ],
    )?;
    let heads = store.budget_ack_heads()?;
    assert_eq!(
        head_for(&heads, a),
        Some(5),
        "origin A's sparse block must be acked to the global head, not its own island"
    );
    assert_eq!(
        head_for(&heads, b),
        Some(4),
        "the authority-change origin B (block starts at global 3) must be acked"
    );

    let _ = fs::remove_file(&path);

    // Global hole: A owns {1,2}, B owns {4,5} -> global seq 3 missing.
    // The global head is 2, so A -> 2 and B is ABSENT. A naive MAX-per-origin
    // ack head would over-report B = 5 past the hole (a double-spend risk).
    let path = unique_db_path("chio-ack-heads-multi-hole");
    let store = SqliteBudgetStore::open(&path)?;
    store.import_snapshot_records(&[], &[event(1, a), event(2, a), event(4, b), event(5, b)])?;
    let heads = store.budget_ack_heads()?;
    assert_eq!(
        head_for(&heads, a),
        Some(2),
        "origin A is gap-free through the global head 2"
    );
    assert_eq!(
        head_for(&heads, b),
        None,
        "origin B (all events above the global hole at 3) must be absent, never acked past the hole"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

fn ack_head_event(seq: u64, event_id: &str, origin: &str) -> BudgetMutationRecord {
    BudgetMutationRecord {
        event_id: event_id.to_string(),
        hold_id: None,
        capability_id: "cap-w".to_string(),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_counts_after: Vec::new(),
        invocation_state: BudgetInvocationReservationState::Absent,
        monetary_state: BudgetMonetaryHoldState::Exposed,
        revocation_set: None,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: origin.to_string(),
            lease_id: format!("{origin}#term-1"),
            lease_epoch: 1,
        }),
    }
}

#[test]
fn mutation_event_seq_for_event_id_returns_this_events_seq_not_authority_max(
) -> Result<(), Box<dyn std::error::Error>> {
    // The quorum-witness token must wait on THIS write's own event_seq (looked up
    // by event_id), not MAX(event_seq) for the authority, which a later
    // same-authority commit raises.
    let path = unique_db_path("chio-event-seq-by-id");
    let store = SqliteBudgetStore::open(&path)?;
    // Two events under the SAME authority: e1 at seq 1, e2 at seq 2.
    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://a"),
            ack_head_event(2, "e2", "http://a"),
        ],
    )?;
    assert_eq!(store.mutation_event_seq_for_event_id("e1")?, Some(1));
    assert_eq!(store.mutation_event_seq_for_event_id("e2")?, Some(2));
    assert_eq!(store.mutation_event_seq_for_event_id("missing")?, None);
    // The authority MAX is 2 - the WRONG seq for e1's quorum wait; the by-id
    // lookup returns 1, so e1's wait targets its own event.
    assert_eq!(store.max_mutation_event_seq_for_authority("http://a")?, 2);

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_ack_head_watermark_recomputes_after_delete_caps_below_hole(
) -> Result<(), Box<dyn std::error::Error>> {
    // budget_ack_heads maintains the contiguous head from a durable watermark for
    // O(new rows) cost, but a DELETE that punches a hole
    // below the watermark must reset it so the next call re-verifies and caps the
    // head below the hole (never a stale-high head that over-counts).
    let path = unique_db_path("chio-ack-watermark-delete");
    let store = SqliteBudgetStore::open(&path)?;
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };
    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://o"),
            ack_head_event(2, "e2", "http://o"),
            ack_head_event(3, "e3", "http://o"),
        ],
    )?;
    // Contiguous 1..3 -> head 3. Called twice to prove the watermark is stable
    // (the second call is a no-op advance, not a regression).
    assert_eq!(head_for(&store.budget_ack_heads()?, "http://o"), Some(3));
    assert_eq!(head_for(&store.budget_ack_heads()?, "http://o"), Some(3));

    // Delete the middle event (seq 2): the watermark reset forces re-verification
    // and the head caps at 1, NOT the stale-high 3.
    store.delete_mutation_event("e2")?;
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(1),
        "a hole punched below the watermark must cap the head at 1, never stay at 3"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_mutation_events_delete_trigger_resets_watermark_even_without_manual_call(
) -> Result<(), Box<dyn std::error::Error>> {
    // Defense-in-depth: every known DELETE FROM budget_mutation_events call site
    // pairs the delete with a manual reset_budget_ack_head_watermark call in the
    // same transaction. This test proves the invariant does NOT depend on that
    // discipline: a raw SQL delete that deliberately bypasses the manual reset
    // path (simulating a future call site that forgets it, or an out-of-band /
    // operator delete) must still zero the watermark, because the
    // budget_mutation_events_reset_ack_head_watermark AFTER DELETE trigger fires
    // structurally on the table itself.
    //
    // Without the trigger this test fails: head_seq would stay stale-high at 3
    // and budget_ack_heads would over-count origin "http://o" up to a seq (3)
    // whose row 2 no longer exists - a witness over-count / data-loss double-spend.
    let path = unique_db_path("chio-ack-watermark-trigger-raw-delete");
    let store = SqliteBudgetStore::open(&path)?;
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };

    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://o"),
            ack_head_event(2, "e2", "http://o"),
            ack_head_event(3, "e3", "http://o"),
        ],
    )?;
    // Advance the watermark to 3 via the normal incremental path.
    assert_eq!(head_for(&store.budget_ack_heads()?, "http://o"), Some(3));
    {
        let connection = store.connection()?;
        let watermark: i64 = connection.query_row(
            "SELECT head_seq FROM budget_ack_head_watermark WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(watermark, 3, "watermark must have advanced to 3");
    }

    // Delete row seq 2 directly via raw SQL, bypassing delete_mutation_event
    // (and therefore bypassing reset_budget_ack_head_watermark entirely) to
    // isolate the trigger as the sole thing that can reset the watermark here.
    {
        let connection = store.connection()?;
        let deleted = connection.execute(
            "DELETE FROM budget_mutation_events WHERE event_id = ?1",
            params!["e2"],
        )?;
        assert_eq!(deleted, 1, "raw delete must remove exactly one row");
    }

    // The trigger fired in the same transaction as the raw DELETE (SQLite AFTER
    // triggers run within the firing statement), so head_seq is already 0 with
    // no further application-level call.
    {
        let connection = store.connection()?;
        let watermark: i64 = connection.query_row(
            "SELECT head_seq FROM budget_ack_head_watermark WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            watermark, 0,
            "the AFTER DELETE trigger must reset head_seq to 0 on any delete, \
             even one that bypasses reset_budget_ack_head_watermark"
        );
    }

    // budget_ack_heads must therefore re-verify from genesis and cap at 1, not
    // report a stale-high (or worse, unreset) head past the punched hole at 2.
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(1),
        "re-verification from a reset watermark must cap the head at 1, not stay at 3"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn ack_head_reset_trigger_is_idempotent_across_reopens_and_concurrent_opens(
) -> Result<(), Box<dyn std::error::Error>> {
    // open() must not DROP+CREATE the ack-reset trigger on every open. Repeated and
    // concurrent opens must not error (no "trigger
    // already exists" race) and must not churn the trigger, while it still exists
    // exactly once with the current per-origin-clearing body.
    let path = unique_db_path("chio-trigger-idempotent");
    // First open creates the trigger.
    {
        let _ = SqliteBudgetStore::open(&path)?;
    }
    // Many concurrent opens: the steady-state path is a single sqlite_master read
    // with no DDL, so none of these may fail or churn the trigger.
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || SqliteBudgetStore::open(&path).map(|_| ()))
        })
        .collect();
    for handle in handles {
        handle
            .join()
            .expect("open thread panicked")
            .expect("a concurrent open must not error on the trigger migration");
    }

    let store = SqliteBudgetStore::open(&path)?;
    // The trigger exists exactly once and clears the per-origin heads (new body).
    {
        let connection = store.connection()?;
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' \
             AND name = 'budget_mutation_events_reset_ack_head_watermark'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 1, "the reset trigger must exist exactly once");
        let sql: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' \
             AND name = 'budget_mutation_events_reset_ack_head_watermark'",
            [],
            |row| row.get(0),
        )?;
        assert!(
            sql.contains("budget_origin_ack_heads"),
            "the trigger must be the current version that clears the per-origin heads"
        );
    }

    // Functional: after all the reopens the trigger still resets the watermark on
    // delete, so the ack head re-verifies and caps below a punched hole.
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };
    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "t1", "http://o"),
            ack_head_event(2, "t2", "http://o"),
            ack_head_event(3, "t3", "http://o"),
        ],
    )?;
    assert_eq!(head_for(&store.budget_ack_heads()?, "http://o"), Some(3));
    store.delete_mutation_event("t2")?;
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(1),
        "the reset trigger must still fire after repeated/concurrent reopens"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn abandoned_seqs_advance_the_head_but_genuine_gaps_still_cap(
) -> Result<(), Box<dyn std::error::Error>> {
    // An abandoned/tombstoned seq (a rolled-back-then-re-appended write's original
    // seq) is treated as FILLED so the global contiguous ack head advances past it
    // (no permanent stall). A GENUINELY missing seq (never recorded abandoned) still
    // caps the head (never over-counts a data-losing node).
    let path = unique_db_path("chio-abandoned-fills-hole");
    let store = SqliteBudgetStore::open(&path)?;
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };

    // Present {1, 3} with a hole at 2: without an abandoned record the head caps
    // at 1 (fail-closed).
    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://o"),
            ack_head_event(3, "e3", "http://o"),
        ],
    )?;
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(1),
        "a genuine gap at 2 must cap the head at 1"
    );

    // Record 2 as abandoned: the head now advances to 3 (2 is a filled tombstone).
    store.record_abandoned_event_seqs(&[2])?;
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(3),
        "an abandoned seq is filled, so the head advances past it"
    );

    // Add {5} (a NEW genuine hole at 4, not abandoned): the head still caps at 3.
    store.import_snapshot_records(&[], &[ack_head_event(5, "e5", "http://o")])?;
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(3),
        "a genuine missing seq 4 (not abandoned) must still cap the head at 3"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rollback_retry_records_abandoned_seq_and_head_does_not_stall() {
    // End-to-end: an authorize, its rollback, and a retry under a new lease. The
    // retry auto-deletes the rolled-back authorize and re-appends it at a fresh seq;
    // the freed seq is recorded abandoned so the global contiguous ack head advances
    // to the re-appended event instead of stalling at the hole.
    let path = unique_db_path("chio-rollback-retry-no-stall");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-x";
    let event_id = "evt-x:authorize";
    let initial = authority("budget-primary", "lease-1", 1);
    let changed = authority("budget-primary", "lease-2", 2);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-x",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    assert!(
        store.list_abandoned_event_seqs().unwrap().is_empty(),
        "no seq is abandoned before the rollback-retry"
    );
    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-x",
            0,
            100,
            Some(hold_id),
            Some("evt-x:authorize:rollback:1"),
            Some(&initial),
        )
        .unwrap();
    // Retry the SAME event_id WITHOUT a manual delete: existing_event_allowed
    // auto-deletes the stale authorize (abandoning its seq 1) and re-appends it.
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-x",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .unwrap());

    assert_eq!(
        store.list_abandoned_event_seqs().unwrap(),
        vec![1],
        "the rolled-back authorize's freed seq 1 must be recorded abandoned"
    );

    // The contiguous ack head advances to the max present event_seq (the re-
    // appended authorize): the abandoned seq 1 is filled, so no permanent stall.
    let max_seq = store.max_mutation_event_seq().unwrap();
    let heads = store.budget_ack_heads().unwrap();
    let origin_head = heads
        .iter()
        .find(|(origin, _)| origin == "budget-primary")
        .map(|(_, seq)| *seq);
    assert_eq!(
        origin_head,
        Some(max_seq),
        "the ack head must advance past the abandoned seq to the re-appended event, not stall"
    );

    let _ = fs::remove_file(&path);
}

#[test]
fn follower_replace_self_records_abandoned_seq_and_head_advances() {
    // An ALREADY-SYNCED follower holds E@X before the leader's rollback-retry, so
    // its pull cursor is already
    // past X and the delta's abandoned_seqs (which are strictly ABOVE the cursor)
    // exclude X. When it later imports the re-appended E@Y, the REPLACE path
    // deletes its local E@X; it must self-record X abandoned in the same
    // transaction so its contiguous ack head advances past the hole WITHOUT
    // waiting for a snapshot. Only the specifically-superseded seq is recorded, so
    // a genuine gap is never filled and the witness never over-counts.
    let leader_path = unique_db_path("chio-follower-replace-leader");
    let follower_path = unique_db_path("chio-follower-replace-follower");
    let leader = SqliteBudgetStore::open(&leader_path).unwrap();
    let follower = SqliteBudgetStore::open(&follower_path).unwrap();
    let hold_id = "hold-fr";
    let event_id = "evt-fr:authorize";
    let initial = authority("budget-primary", "lease-1", 1);
    let changed = authority("budget-primary", "lease-2", 2);

    // Leader authorizes E (seq 1), then rolls it back (rollback marker at seq 2).
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-fr",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    leader
        .reverse_charge_cost_with_ids_and_authority(
            "cap-fr",
            0,
            100,
            Some(hold_id),
            Some("evt-fr:authorize:rollback:1"),
            Some(&initial),
        )
        .unwrap();

    // Follower syncs the PRE-retry state (E@1 + the rollback marker), ascending.
    let pre_retry = leader.list_mutation_events_after_seq(100, 0).unwrap();
    follower.import_snapshot_records(&[], &pre_retry).unwrap();
    assert!(
        follower.list_abandoned_event_seqs().unwrap().is_empty(),
        "no abandoned seq before the leader's retry"
    );

    // Leader retries under the NEW lease: deletes E@1 (abandons 1), re-appends E@3.
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-fr",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .unwrap());
    assert_eq!(leader.list_abandoned_event_seqs().unwrap(), vec![1]);

    // Follower imports the re-appended authorize (the leader's delta). Its cursor
    // is already past seq 1, so the delta would NOT carry seq 1 as abandoned - the
    // REPLACE path must record it locally.
    let reappended = leader
        .list_mutation_events_after_seq(100, 0)
        .unwrap()
        .into_iter()
        .find(|record| record.event_id == event_id)
        .expect("the re-appended authorize event");
    assert!(
        reappended.event_seq > 1,
        "re-appended at a fresh higher seq"
    );
    follower.import_mutation_record(&reappended).unwrap();

    // The follower self-recorded the superseded seq 1 abandoned, so its head
    // advances to the re-appended event instead of stalling at the hole.
    assert_eq!(
        follower.list_abandoned_event_seqs().unwrap(),
        vec![1],
        "the follower REPLACE path self-records the superseded seq abandoned"
    );
    let follower_max = follower.max_mutation_event_seq().unwrap();
    let heads = follower.budget_ack_heads().unwrap();
    let head = heads
        .iter()
        .find(|(origin, _)| origin == "budget-primary")
        .map(|(_, seq)| *seq);
    assert_eq!(
        head,
        Some(follower_max),
        "the follower head advances past the abandoned hole with no snapshot needed"
    );

    let _ = fs::remove_file(&leader_path);
    let _ = fs::remove_file(&follower_path);
}

#[test]
fn follower_replace_inserts_reappended_event_and_head_reaches_new_seq() {
    // Exercises the follower REPLACE path. An ALREADY-SYNCED follower holds the
    // ORIGINAL authorize E@1 (its pull cursor is already past 1). When it imports
    // the leader's re-appended E@new (same event_id, fresh higher seq), the REPLACE
    // path deletes E@1 and tombstones seq 1, then MUST re-insert E@new so the
    // follower actually holds the retried write and its budget_ack_heads head
    // ADVANCES to the new seq. Without the re-insert, E@new is ABSENT and the head
    // halts at the rollback marker (never witnessing the retried write -> quorum
    // waits time out). This asserts the ABSOLUTE new seq (not head == max, which
    // passes even with E@new missing because both degrade to the rollback marker
    // together).
    let leader_path = unique_db_path("chio-follower-replace-leader");
    let follower_path = unique_db_path("chio-follower-replace-follower");
    let leader = SqliteBudgetStore::open(&leader_path).unwrap();
    let follower = SqliteBudgetStore::open(&follower_path).unwrap();
    let hold_id = "hold-fr";
    let event_id = "evt-fr:authorize";
    let initial = authority("budget-primary", "lease-1", 1);
    let changed = authority("budget-primary", "lease-2", 2);

    // Leader authorizes E (seq 1), then rolls it back (rollback marker at seq 2).
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-fr",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    leader
        .reverse_charge_cost_with_ids_and_authority(
            "cap-fr",
            0,
            100,
            Some(hold_id),
            Some("evt-fr:authorize:rollback:1"),
            Some(&initial),
        )
        .unwrap();

    // Follower syncs the PRE-retry state (E@1 + the rollback marker), and confirms it
    // holds the ORIGINAL authorize at seq 1 with no abandoned slot yet.
    let pre_retry = leader.list_mutation_events_after_seq(100, 0).unwrap();
    follower.import_snapshot_records(&[], &pre_retry).unwrap();
    assert_eq!(
        follower.mutation_event_seq_for_event_id(event_id).unwrap(),
        Some(1),
        "follower holds the ORIGINAL authorize at seq 1 pre-retry"
    );
    assert!(follower.list_abandoned_event_seqs().unwrap().is_empty());

    // Leader retries under the NEW lease: deletes E@1 (abandons 1), re-appends E@new.
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-fr",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .unwrap());
    let reappended = leader
        .list_mutation_events_after_seq(100, 0)
        .unwrap()
        .into_iter()
        .find(|record| record.event_id == event_id)
        .expect("the re-appended authorize event");
    let new_seq = reappended.event_seq;
    assert!(
        new_seq > 2,
        "re-appended strictly above the rollback marker"
    );

    // Follower imports the re-appended authorize. The REPLACE path deletes E@1,
    // tombstones seq 1, and re-inserts E@new.
    follower.import_mutation_record(&reappended).unwrap();

    // The re-appended event is PRESENT at its new seq (exactly one row: the
    // unique event_seq index would reject a duplicate).
    assert_eq!(
        follower.mutation_event_seq_for_event_id(event_id).unwrap(),
        Some(new_seq),
        "the follower re-inserts the re-appended event at its fresh seq"
    );
    // The follower's max advances to the re-appended seq (E@new is held, not lost).
    assert_eq!(
        follower.max_mutation_event_seq().unwrap(),
        new_seq,
        "the follower's max advances to the re-appended seq"
    );
    // The contiguous ack head ADVANCES to the ABSOLUTE new seq, so the
    // follower witnesses the retried write.
    let head = follower
        .budget_ack_heads()
        .unwrap()
        .into_iter()
        .find(|(origin, _)| origin == "budget-primary")
        .map(|(_, seq)| seq);
    assert_eq!(
        head,
        Some(new_seq),
        "the follower's ack head reaches the re-appended seq, not the rollback marker"
    );
    // The superseded OLD seq stays abandoned (a FILLED-but-not-live slot: it lets the
    // head cross the hole but contributes no origin ack, so no over-count).
    assert_eq!(
        follower.list_abandoned_event_seqs().unwrap(),
        vec![1],
        "the superseded old seq stays abandoned, never a live witness"
    );

    let _ = fs::remove_file(&leader_path);
    let _ = fs::remove_file(&follower_path);
}

#[test]
fn same_authority_rollback_retry_reinserts_reappended_event_and_head_advances() {
    // Exercises the SAME-AUTHORITY re-append. When the leader keeps its lease and
    // retries a rolled-back authorize, the re-appended event is byte-identical to
    // the original EXCEPT its fresh higher event_seq, so `same_imported_mutation`
    // (authority/content-only, ignores event_seq) reports it a duplicate. If the
    // importer short-circuited on that, it would never store the re-appended row, so
    // the follower's ack head would stall at the rollback marker (seq 2) and it could
    // not witness the retried write until a full snapshot rebuild. Gating the replace
    // path on `record.event_seq > existing.event_seq` makes a differing seq force the
    // replace + reinsert even when authority/content match; without it the follower
    // still holds E@1 and its head is 2.
    let leader_path = unique_db_path("chio-same-authority-retry-leader");
    let follower_path = unique_db_path("chio-same-authority-retry-follower");
    let leader = SqliteBudgetStore::open(&leader_path).unwrap();
    let follower = SqliteBudgetStore::open(&follower_path).unwrap();
    let hold_id = "hold-sa";
    let event_id = "evt-sa:authorize";
    // ONE authority reused across the original authorize AND the retry: the leader
    // never changed leases, so the re-appended event's authority is byte-identical.
    let leased = authority("budget-primary", "lease-1", 1);

    // Leader authorizes E (seq 1), then rolls it back (rollback marker at seq 2).
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-sa",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&leased),
        )
        .unwrap());
    leader
        .reverse_charge_cost_with_ids_and_authority(
            "cap-sa",
            0,
            100,
            Some(hold_id),
            Some("evt-sa:authorize:rollback:1"),
            Some(&leased),
        )
        .unwrap();

    // Follower syncs the PRE-retry state (E@1 + the rollback marker) and confirms it
    // holds the ORIGINAL authorize at seq 1 with no abandoned slot yet.
    let pre_retry = leader.list_mutation_events_after_seq(100, 0).unwrap();
    follower.import_snapshot_records(&[], &pre_retry).unwrap();
    assert_eq!(
        follower.mutation_event_seq_for_event_id(event_id).unwrap(),
        Some(1),
        "follower holds the ORIGINAL authorize at seq 1 pre-retry"
    );
    assert!(follower.list_abandoned_event_seqs().unwrap().is_empty());

    // Leader retries under the SAME lease: the rollback decremented the usage
    // counters, so this is a GENUINE re-append (not the idempotent no-op) - it
    // deletes E@1 (abandons 1) and re-appends E@new at a fresh higher seq.
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-sa",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&leased),
        )
        .unwrap());
    let reappended = leader
        .list_mutation_events_after_seq(100, 0)
        .unwrap()
        .into_iter()
        .find(|record| record.event_id == event_id)
        .expect("the re-appended authorize event");
    let new_seq = reappended.event_seq;
    assert!(
        new_seq > 2,
        "re-appended strictly above the rollback marker (leader really re-appended, not idempotent)"
    );
    // Sanity: the re-appended event carries the SAME authority as the original, so
    // `same_imported_mutation` would call it a duplicate on authority/content alone.
    assert_eq!(
        reappended.authority.as_ref(),
        Some(&leased),
        "the retry kept the original lease (same-authority re-append)"
    );

    // Follower imports the same-authority re-append.
    follower.import_mutation_record(&reappended).unwrap();

    // The re-appended event is PRESENT at its new seq (exactly one row: the
    // unique event_seq index would reject a duplicate).
    assert_eq!(
        follower.mutation_event_seq_for_event_id(event_id).unwrap(),
        Some(new_seq),
        "the follower re-inserts the same-authority re-append at its fresh seq"
    );
    assert_eq!(
        follower.max_mutation_event_seq().unwrap(),
        new_seq,
        "the follower's max advances to the re-appended seq"
    );
    // The contiguous ack head ADVANCES to the ABSOLUTE new seq (not the
    // rollback marker), so the follower witnesses the retried write.
    let head = follower
        .budget_ack_heads()
        .unwrap()
        .into_iter()
        .find(|(origin, _)| origin == "budget-primary")
        .map(|(_, seq)| seq);
    assert_eq!(
        head,
        Some(new_seq),
        "the follower's ack head reaches the re-appended seq, not the rollback marker"
    );
    // The superseded OLD seq stays abandoned: a FILLED-but-not-live slot that lets
    // the head cross the hole but contributes NO origin ack, so no over-count.
    assert_eq!(
        follower.list_abandoned_event_seqs().unwrap(),
        vec![1],
        "the superseded old seq stays abandoned, never a live witness"
    );

    let _ = fs::remove_file(&leader_path);
    let _ = fs::remove_file(&follower_path);
}

#[test]
fn mutation_event_witness_returns_stored_origin_authority() -> Result<(), Box<dyn std::error::Error>>
{
    // The witness identity for an idempotent retry comes from the event's STORED
    // origin authority, not the current lease, so a retry
    // after leadership moved targets the origin peers advertise it under.
    let path = unique_db_path("chio-stored-witness");
    let store = SqliteBudgetStore::open(&path)?;
    let old_leader = authority("http://old-leader", "http://old-leader#term-3", 3);
    store.try_charge_cost_with_ids_and_authority(
        "cap",
        0,
        Some(10),
        5,
        None,
        None,
        None,
        Some("evt-1"),
        Some(&old_leader),
    )?;

    let (seq, authority_id, lease_epoch) = store
        .mutation_event_witness_for_event_id("evt-1")?
        .ok_or("the written event must be found")?;
    assert!(seq > 0, "a real event carries a positive seq");
    assert_eq!(
        authority_id.as_deref(),
        Some("http://old-leader"),
        "the witness must carry the STORED origin, not the current leader"
    );
    assert_eq!(lease_epoch, Some(3), "and the stored lease epoch");

    // An absent event returns None so the caller falls back to the current lease.
    assert!(store
        .mutation_event_witness_for_event_id("evt-absent")?
        .is_none());

    let _ = fs::remove_file(&path);
    Ok(())
}
