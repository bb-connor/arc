use super::*;
use chio_kernel::budget_store::{
    BudgetAdmissionOperationBinding, BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
    BudgetCaptureHoldRequest, BudgetCaptureInvocationRequest, BudgetInvocationQuota,
    BudgetInvocationReservationState, BudgetQuotaKey, BudgetQuotaProfile,
    BudgetReconcileHoldRequest, BudgetReleaseHoldRequest, BudgetReverseHoldRequest,
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

#[cfg(unix)]
#[test]
fn sqlite_budget_store_creates_private_database_file() {
    use std::os::unix::fs::PermissionsExt;

    let path = unique_db_path("chio-budgets-private");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;

    assert_eq!(mode, 0o600);

    drop(store);
    let _ = fs::remove_file(path);
}

fn test_row_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value = row.get::<_, i64>(index)?;
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn test_row_optional_u64(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<u64>> {
    row.get::<_, Option<i64>>(index)?
        .map(|value| {
            u64::try_from(value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    index,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })
        })
        .transpose()
}

#[test]
fn wal_mode_retry_accepts_non_wal_successes_before_convergence() {
    let mut modes = ["delete", "delete", "wal"].into_iter();
    let mut attempts = 0;
    let mut waits = 0;

    super::store::retry_write_ahead_logging(
        || {
            attempts += 1;
            Ok(modes.next().expect("retry sequence exhausted").to_string())
        },
        || true,
        || waits += 1,
    )
    .unwrap();

    assert_eq!(attempts, 3);
    assert_eq!(waits, 2);
}

#[test]
fn wal_mode_retry_classifies_expired_non_wal_success_as_invariant() {
    let mut modes = ["delete", "truncate"].into_iter();
    let mut retry_availability = [true, false].into_iter();
    let mut waits = 0;

    let error = super::store::retry_write_ahead_logging(
        || Ok(modes.next().expect("retry sequence exhausted").to_string()),
        || {
            retry_availability
                .next()
                .expect("deadline sequence exhausted")
        },
        || waits += 1,
    )
    .expect_err("an expired non-WAL mode must fail closed");

    match error {
        BudgetStoreError::Invariant(message) => assert_eq!(
            message,
            "sqlite budget store requires WAL mode, got `truncate`"
        ),
        other => panic!("expected WAL invariant error, got {other}"),
    }
    assert_eq!(waits, 1);
}

#[test]
fn budget_store_profile_reflects_instance_durability() {
    let memory = SqliteBudgetStore::open_in_memory().unwrap();
    assert_eq!(
        memory.authority_profile(),
        BudgetStoreProfile::EphemeralLocal
    );
    assert!(!memory.supports_durable_atomic_payment_journal());
    assert!(SqliteBudgetStore::open(":memory:").is_err());
    assert!(SqliteBudgetStore::open("file::memory:?cache=shared").is_err());
    assert!(SqliteBudgetStore::open("file:budget?mode=memory&cache=shared").is_err());
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

fn compatibility_quota_usage_record(
    capability_id: &str,
    grant_index: u32,
    max_invocations: u32,
    captured_invocations: u32,
    updated_at: i64,
    seq: u64,
) -> BudgetInvocationQuotaUsageRecord {
    BudgetInvocationQuotaUsageRecord {
        usage: BudgetInvocationQuotaUsage {
            quota: persisted_quota(
                BudgetQuotaProfile::GrantInvocation,
                capability_id,
                Some(grant_index),
                max_invocations,
            ),
            reserved_invocations_after: 0,
            captured_invocations_after: captured_invocations,
        },
        updated_at,
        seq,
    }
}

fn import_usage_with_immutable_maximum(
    store: &SqliteBudgetStore,
    usage: &BudgetUsageRecord,
    maximum: u32,
) -> Result<(), BudgetStoreError> {
    let quota = compatibility_quota_usage_record(
        &usage.capability_id,
        usage.grant_index,
        maximum,
        usage.invocation_count,
        usage.updated_at,
        usage.seq,
    );
    store.import_snapshot_records_with_invocation_quotas(
        std::slice::from_ref(usage),
        std::slice::from_ref(&quota),
        &[],
    )
}

fn import_events_with_quota_authority(
    store: &SqliteBudgetStore,
    events: &[BudgetMutationRecord],
) -> Result<(), BudgetStoreError> {
    let mut authorities = std::collections::BTreeMap::<(String, u32), (u32, u32, i64, u64)>::new();
    let mut usages = std::collections::BTreeMap::<(String, u32), BudgetUsageRecord>::new();
    for event in events.iter().filter(|event| {
        matches!(
            event.kind,
            BudgetMutationKind::IncrementInvocation | BudgetMutationKind::AuthorizeExposure
        )
    }) {
        let maximum = event.max_invocations.unwrap_or(u32::MAX);
        let key = (event.capability_id.clone(), event.grant_index);
        let entry = authorities.entry(key.clone()).or_insert((
            maximum,
            event.invocation_count_after,
            event.recorded_at,
            event.event_seq,
        ));
        if entry.0 != maximum {
            return Err(BudgetStoreError::Invariant(
                "test import contains conflicting invocation maxima".to_string(),
            ));
        }
        if event.event_seq > entry.3 {
            entry.1 = event.invocation_count_after;
            entry.2 = event.recorded_at;
            entry.3 = event.event_seq;
        }
        if let Some(usage_seq) = event.usage_seq {
            let usage = BudgetUsageRecord {
                capability_id: event.capability_id.clone(),
                grant_index: event.grant_index,
                invocation_count: event.invocation_count_after,
                updated_at: event.recorded_at,
                seq: usage_seq,
                total_cost_exposed: event.total_cost_exposed_after,
                total_cost_realized_spend: event.total_cost_realized_spend_after,
            };
            if usages
                .get(&key)
                .is_none_or(|existing| existing.seq <= usage_seq)
            {
                usages.insert(key, usage);
            }
        }
    }
    let quotas = authorities
        .into_iter()
        .map(
            |((capability_id, grant_index), (maximum, captured, updated_at, seq))| {
                compatibility_quota_usage_record(
                    &capability_id,
                    grant_index,
                    maximum,
                    captured,
                    updated_at,
                    seq,
                )
            },
        )
        .collect::<Vec<_>>();
    let usages = usages.into_values().collect::<Vec<_>>();
    store.import_snapshot_records_with_invocation_quotas(&usages, &quotas, events)
}

fn composite_admission_binding(hold_id: &str) -> BudgetAdmissionOperationBinding {
    BudgetAdmissionOperationBinding::new(format!("operation:{hold_id}"), "11".repeat(32)).unwrap()
}

fn alternate_operation_binding(hold_id: &str) -> BudgetAdmissionOperationBinding {
    BudgetAdmissionOperationBinding::new(format!("other-operation:{hold_id}"), "11".repeat(32))
        .unwrap()
}

fn alternate_request_binding(hold_id: &str) -> BudgetAdmissionOperationBinding {
    BudgetAdmissionOperationBinding::new(
        composite_admission_binding(hold_id)
            .operation_id()
            .to_string(),
        "22".repeat(32),
    )
    .unwrap()
}

fn assert_ownership_conflict<T: std::fmt::Debug>(result: Result<T, BudgetStoreError>, field: &str) {
    let error = result.expect_err("different admission ownership must conflict");
    assert!(
        error.to_string().contains(field),
        "ownership conflict should name {field}: {error}"
    );
}

fn composite_authorize_input(
    hold_id: &str,
    event_id: &str,
    aggregate_max: u32,
) -> SqliteCompositeAuthorizeInput {
    let admission_operation = composite_admission_binding(hold_id);
    SqliteCompositeAuthorizeInput {
        operation_id: admission_operation.operation_id().to_string(),
        request_binding_hash: admission_operation.request_binding_hash().to_string(),
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
        partition_escrow_evidence: None,
    }
}

#[test]
fn operation_owned_reservation_stamp_is_exact_restart_durable_and_reapable() {
    let path = unique_db_path("chio-composite-reservation-stamp");
    let hold_id = "hold-composite-reservation-stamp";
    let binding = composite_admission_binding(hold_id);
    let envelope = ReservedHoldEnvelope {
        budget_total: Some(1_000),
        delegation_depth: 2,
        root_budget_holder: "root-capability".to_string(),
    };
    {
        let store = SqliteBudgetStore::open(&path).unwrap();
        let decision = store
            .authorize_composite_hold(composite_authorize_input(
                hold_id,
                "event-composite-reservation-authorize",
                2,
            ))
            .unwrap();
        assert!(matches!(
            decision,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        store
            .mark_admission_operation_hold_reserved(
                hold_id,
                &binding,
                1_234,
                Some("USD"),
                Some("payment-reference"),
                &envelope,
            )
            .unwrap();
        store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "leaf".to_string(),
                grant_index: 0,
                hold_id: Some(hold_id.to_string()),
                event_id: Some("event-composite-reservation-capture".to_string()),
                authority: None,
                admission_operation: Some(binding.clone()),
            })
            .unwrap();
    }
    {
        let store = SqliteBudgetStore::open(&path).unwrap();
        let snapshot = store.get_budget_hold(hold_id).unwrap().unwrap();
        assert_eq!(snapshot.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(snapshot.reserved_until, Some(1_234));
        assert_eq!(snapshot.reserved_currency.as_deref(), Some("USD"));
        assert_eq!(
            snapshot.reserved_payment_reference.as_deref(),
            Some("payment-reference")
        );
        assert_eq!(snapshot.reserved_budget_total, Some(1_000));
        assert_eq!(snapshot.reserved_delegation_depth, Some(2));
        assert_eq!(
            snapshot.reserved_root_budget_holder.as_deref(),
            Some("root-capability")
        );
        store
            .mark_admission_operation_hold_reserved(
                hold_id,
                &binding,
                1_234,
                Some("USD"),
                Some("payment-reference"),
                &envelope,
            )
            .unwrap();
        assert!(matches!(
            store.mark_admission_operation_hold_reserved(
                hold_id,
                &alternate_operation_binding(hold_id),
                1_234,
                Some("USD"),
                Some("payment-reference"),
                &envelope,
            ),
            Err(BudgetStoreError::Conflict(_))
        ));
        assert_eq!(store.reap_expired_reserved_holds(1_234).unwrap(), 1);
        let expired = store.get_budget_hold(hold_id).unwrap().unwrap();
        assert_eq!(expired.disposition, BudgetHoldDispositionView::Expired);
        assert_eq!(expired.reserved_until, Some(1_234));
        assert_eq!(expired.reserved_currency.as_deref(), Some("USD"));
        assert_eq!(store.reap_expired_reserved_holds(1_234).unwrap(), 0);
        assert!(matches!(
            store.get_usage("leaf", 0),
            Ok(Some(usage)) if usage.total_cost_realized_spend == 100
        ));
    }
    let _ = fs::remove_file(path);
}

#[test]
fn operation_owned_expiry_rolls_back_settlement_when_expired_marker_fails() {
    let path = unique_db_path("chio-composite-reservation-expiry-atomicity");
    let hold_id = "hold-composite-reservation-expiry-atomicity";
    let binding = composite_admission_binding(hold_id);
    {
        let store = SqliteBudgetStore::open(&path).unwrap();
        let decision = store
            .authorize_composite_hold(composite_authorize_input(
                hold_id,
                "event-composite-reservation-expiry-atomicity-authorize",
                2,
            ))
            .unwrap();
        assert!(matches!(
            decision,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        store
            .mark_admission_operation_hold_reserved(
                hold_id,
                &binding,
                1_234,
                Some("USD"),
                None,
                &ReservedHoldEnvelope {
                    budget_total: Some(1_000),
                    delegation_depth: 0,
                    root_budget_holder: "root-capability".to_string(),
                },
            )
            .unwrap();
        store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "leaf".to_string(),
                grant_index: 0,
                hold_id: Some(hold_id.to_string()),
                event_id: Some("event-composite-reservation-expiry-atomicity-capture".to_string()),
                authority: None,
                admission_operation: Some(binding),
            })
            .unwrap();
        store
            .connection()
            .unwrap()
            .execute_batch(
                r#"
                CREATE TRIGGER fail_composite_expired_marker
                BEFORE UPDATE OF disposition ON budget_authorization_holds
                WHEN NEW.hold_id = 'hold-composite-reservation-expiry-atomicity'
                     AND NEW.disposition = 'expired'
                BEGIN
                    SELECT RAISE(ABORT, 'injected composite expired marker failure');
                END;
                "#,
            )
            .unwrap();

        let error = store
            .reap_expired_reserved_holds(1_234)
            .expect_err("the injected expired marker failure must abort the TTL transaction");
        assert!(error
            .to_string()
            .contains("injected composite expired marker failure"));
    }

    // Reopen after the failed transaction. Worst-case settlement and its event
    // must have rolled back with the Expired marker, leaving the reservation
    // selected by a later TTL pass rather than stranded as merely Reconciled.
    {
        let store = SqliteBudgetStore::open(&path).unwrap();
        let snapshot = store.get_budget_hold(hold_id).unwrap().unwrap();
        assert_eq!(snapshot.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(snapshot.remaining_exposure_units, 100);
        let usage = store.get_usage("leaf", 0).unwrap().unwrap();
        assert_eq!(usage.total_cost_exposed, 100);
        assert_eq!(usage.total_cost_realized_spend, 0);

        store
            .connection()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_composite_expired_marker;")
            .unwrap();
        assert_eq!(store.reap_expired_reserved_holds(1_234).unwrap(), 1);
        let expired = store.get_budget_hold(hold_id).unwrap().unwrap();
        assert_eq!(expired.disposition, BudgetHoldDispositionView::Expired);
        assert_eq!(expired.remaining_exposure_units, 0);
        let usage = store.get_usage("leaf", 0).unwrap().unwrap();
        assert_eq!(usage.total_cost_exposed, 0);
        assert_eq!(usage.total_cost_realized_spend, 100);
    }
    {
        let store = SqliteBudgetStore::open(&path).unwrap();
        assert_eq!(
            store.get_budget_hold(hold_id).unwrap().unwrap().disposition,
            BudgetHoldDispositionView::Expired
        );
        assert_eq!(store.reap_expired_reserved_holds(1_234).unwrap(), 0);
    }
    let _ = fs::remove_file(path);
}

#[test]
fn zero_exposure_operation_owned_reservation_reaps_without_legacy_fallback() {
    let path = unique_db_path("chio-zero-composite-reservation-stamp");
    let hold_id = "hold-zero-composite-reservation-stamp";
    let binding = composite_admission_binding(hold_id);
    let mut request =
        composite_authorize_input(hold_id, "event-zero-composite-reservation-authorize", 2);
    request.requested_exposure_units = 0;
    request.max_cost_per_invocation = None;
    request.max_total_cost_units = None;
    let store = SqliteBudgetStore::open(&path).unwrap();
    let decision = store.authorize_composite_hold(request).unwrap();
    assert!(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    store
        .mark_admission_operation_hold_reserved(
            hold_id,
            &binding,
            2_345,
            None,
            None,
            &ReservedHoldEnvelope {
                budget_total: None,
                delegation_depth: 0,
                root_budget_holder: "root-capability".to_string(),
            },
        )
        .unwrap();
    store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "leaf".to_string(),
            grant_index: 0,
            hold_id: Some(hold_id.to_string()),
            event_id: Some("event-zero-composite-reservation-capture".to_string()),
            authority: None,
            admission_operation: Some(binding),
        })
        .unwrap();
    let snapshot = store.get_budget_hold(hold_id).unwrap().unwrap();
    assert_eq!(snapshot.authorized_exposure_units, 0);
    assert_eq!(snapshot.remaining_exposure_units, 0);
    assert_eq!(snapshot.disposition, BudgetHoldDispositionView::Open);
    assert_eq!(snapshot.reserved_until, Some(2_345));
    assert_eq!(snapshot.reserved_currency, None);
    assert_eq!(store.reap_expired_reserved_holds(2_345).unwrap(), 1);
    let expired = store.get_budget_hold(hold_id).unwrap().unwrap();
    assert_eq!(expired.disposition, BudgetHoldDispositionView::Expired);
    assert_eq!(expired.reserved_until, Some(2_345));
    let _ = fs::remove_file(path);
}

fn ownership_composite_authorize_input(
    hold_id: &str,
    event_id: &str,
) -> SqliteCompositeAuthorizeInput {
    let mut request = composite_authorize_input(hold_id, event_id, 8);
    request.invocation_quotas = vec![
        persisted_quota(BudgetQuotaProfile::GrantInvocation, "leaf", Some(0), 8),
        persisted_quota(
            BudgetQuotaProfile::AggregateCapabilityInvocation,
            "leaf",
            None,
            8,
        ),
        persisted_quota(
            BudgetQuotaProfile::SupplementalBrokerExecution,
            &"22".repeat(32),
            None,
            8,
        ),
    ];
    request
}

fn import_integrity_record(event_id: &str, event_seq: u64) -> BudgetMutationRecord {
    BudgetMutationRecord {
        event_id: event_id.to_string(),
        hold_id: None,
        admission_operation: None,
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

#[test]
fn mutation_replication_preserves_and_conflict_checks_admission_ownership() {
    let path = unique_db_path("chio-budget-replication-admission-owner");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let mut record = import_integrity_record("event-replicated-admission-owner", 1);
    record.admission_operation = Some(
        BudgetAdmissionOperationBinding::new(
            "operation-replicated-owner".to_string(),
            "55".repeat(32),
        )
        .unwrap(),
    );

    import_events_with_quota_authority(&store, std::slice::from_ref(&record)).unwrap();
    assert_eq!(
        store.list_mutation_events_after_seq(10, 0).unwrap(),
        vec![record.clone()]
    );

    let mut conflicting = record;
    conflicting.admission_operation = Some(
        BudgetAdmissionOperationBinding::new(
            "operation-replicated-other".to_string(),
            "55".repeat(32),
        )
        .unwrap(),
    );
    let error = import_events_with_quota_authority(&store, std::slice::from_ref(&conflicting))
        .expect_err("replicated mutation ownership must be immutable");
    assert!(error.to_string().contains("different mutation"), "{error}");

    let _ = fs::remove_file(path);
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

fn persisted_admission_ownership(
    store: &SqliteBudgetStore,
    table: &str,
    key_column: &str,
    key: &str,
) -> (String, String) {
    store
        .connection()
        .unwrap()
        .query_row(
            &format!(
                "SELECT operation_id, request_binding_hash FROM {table} WHERE {key_column} = ?1"
            ),
            params![key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
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
fn compatibility_increment_freezes_maximum_even_when_first_attempt_is_denied() {
    let path = unique_db_path("chio-budget-compatibility-immutable-maximum");
    let store = SqliteBudgetStore::open(&path).unwrap();

    assert!(!store.try_increment("cap-immutable", 0, Some(0)).unwrap());
    let error = store
        .try_increment("cap-immutable", 0, Some(1))
        .expect_err("the compatibility wrapper must not reopen a denied immutable quota");
    assert!(error
        .to_string()
        .contains("presented with a different maximum"));

    let count = store
        .connection()
        .unwrap()
        .query_row(
            r#"
            SELECT captured_invocations
            FROM budget_invocation_quota_usage
            WHERE profile = 'chio.grant-invocation.v1'
              AND owner_id = 'cap-immutable'
              AND grant_index_key = 0
            "#,
            [],
            |row| row.get::<_, u32>(0),
        )
        .unwrap();
    assert_eq!(count, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn compatibility_increment_denial_preserves_quota_state_and_replays_exactly(
) -> Result<(), BudgetStoreError> {
    let path = unique_db_path("chio-budget-compatibility-denial-replay");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store.try_increment_with_event_id(
        "cap-increment-denial-replay",
        0,
        Some(1),
        Some("event-increment-allowed"),
    )?);

    let before = store.connection()?.query_row(
        r#"
            SELECT reserved_invocations, captured_invocations, updated_at, seq
            FROM budget_invocation_quota_usage
            WHERE profile = 'chio.grant-invocation.v1'
              AND owner_id = 'cap-increment-denial-replay'
              AND grant_index_key = 0
            "#,
        [],
        |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                test_row_u64(row, 3)?,
            ))
        },
    )?;
    assert_eq!(before.0, 0);
    assert_eq!(before.1, 1);

    assert!(!store.try_increment_with_event_id(
        "cap-increment-denial-replay",
        0,
        Some(1),
        Some("event-increment-denied"),
    )?);
    let after = store.connection()?.query_row(
        r#"
            SELECT reserved_invocations, captured_invocations, updated_at, seq
            FROM budget_invocation_quota_usage
            WHERE profile = 'chio.grant-invocation.v1'
              AND owner_id = 'cap-increment-denial-replay'
              AND grant_index_key = 0
            "#,
        [],
        |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                test_row_u64(row, 3)?,
            ))
        },
    )?;
    assert_eq!(
        after, before,
        "denial must not rewrite quota authority state"
    );

    let events = store.list_mutation_events(10, Some("cap-increment-denial-replay"), Some(0))?;
    let allowed = events
        .iter()
        .find(|event| event.event_id == "event-increment-allowed")
        .ok_or_else(|| {
            BudgetStoreError::Invariant(
                "allowed compatibility mutation event was not persisted".to_string(),
            )
        })?;
    assert_eq!(allowed.usage_seq, Some(allowed.event_seq));
    let denied = events
        .iter()
        .find(|event| event.event_id == "event-increment-denied")
        .ok_or_else(|| {
            BudgetStoreError::Invariant(
                "denied compatibility mutation event was not persisted".to_string(),
            )
        })?;
    assert_eq!(denied.allowed, Some(false));
    assert_eq!(denied.usage_seq, None);
    let denied_seq = denied.event_seq;
    let hold_count = store.connection()?.query_row(
        "SELECT COUNT(*) FROM budget_authorization_holds",
        [],
        |row| row.get::<_, u32>(0),
    )?;
    assert_eq!(hold_count, 0, "try_increment must not synthesize a hold");

    assert!(matches!(
        store.try_increment_with_event_id(
            "cap-increment-denial-replay",
            0,
            Some(2),
            Some("event-increment-denied"),
        ),
        Err(BudgetStoreError::Conflict(_))
    ));
    let unchanged = store
        .connection()?
        .query_row(
            "SELECT reserved_invocations, captured_invocations, updated_at, seq FROM budget_invocation_quota_usage WHERE profile = 'chio.grant-invocation.v1' AND owner_id = 'cap-increment-denial-replay' AND grant_index_key = 0",
            [],
            |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?, row.get::<_, i64>(2)?, test_row_u64(row, 3)?)),
        )?;
    assert_eq!(unchanged, before);

    drop(store);
    let reopened = SqliteBudgetStore::open(&path)?;
    assert!(!reopened.try_increment_with_event_id(
        "cap-increment-denial-replay",
        0,
        Some(1),
        Some("event-increment-denied"),
    )?);
    let replayed =
        reopened.list_mutation_events(10, Some("cap-increment-denial-replay"), Some(0))?;
    let replayed_denial_seq = replayed
        .iter()
        .find(|event| event.event_id == "event-increment-denied")
        .map(|event| event.event_seq)
        .ok_or_else(|| {
            BudgetStoreError::Invariant(
                "replayed compatibility denial event was not persisted".to_string(),
            )
        })?;
    assert_eq!(replayed_denial_seq, denied_seq);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn compatibility_increment_rejects_counter_overflow_without_authorizing() {
    let path = unique_db_path("chio-budget-compatibility-overflow");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store.try_increment("cap-overflow", 0, None).unwrap());
    let connection = store.connection().unwrap();
    connection
        .execute(
            r#"
            UPDATE capability_grant_budgets
            SET invocation_count = 4294967295
            WHERE capability_id = 'cap-overflow' AND grant_index = 0
            "#,
            [],
        )
        .unwrap();
    connection
        .execute(
            r#"
            UPDATE budget_invocation_quota_usage
            SET captured_invocations = 4294967295
            WHERE profile = 'chio.grant-invocation.v1'
              AND owner_id = 'cap-overflow'
              AND grant_index_key = 0
            "#,
            [],
        )
        .unwrap();
    drop(connection);

    let error = store
        .try_increment("cap-overflow", 0, None)
        .expect_err("u32 counter exhaustion must fail closed");
    assert!(matches!(error, BudgetStoreError::Overflow(_)));

    let _ = fs::remove_file(path);
}

#[test]
fn composite_authorization_is_atomic_idempotent_and_restart_durable_sqlite(
) -> Result<(), BudgetStoreError> {
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

    let connection = rusqlite::Connection::open(&path).unwrap();
    let ownership_counts: (i64, i64, i64) = connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*)
                 FROM budget_composite_authorizations
                 WHERE hold_id = 'hold-composite-1'),
                (SELECT COUNT(*)
                 FROM budget_authorization_holds AS hold
                 JOIN budget_composite_authorizations AS authorization
                   ON authorization.hold_id = hold.hold_id
                  AND authorization.operation_id IS hold.operation_id
                  AND authorization.request_binding_hash IS hold.request_binding_hash
                  AND authorization.capability_id IS hold.capability_id
                  AND authorization.grant_index IS hold.grant_index
                  AND authorization.requested_exposure_units IS hold.authorized_exposure_units
                 WHERE hold.hold_id = 'hold-composite-1'),
                (SELECT COUNT(*)
                 FROM budget_authorization_claims
                 WHERE hold_id = 'hold-composite-1')
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(ownership_counts, (1, 1, 0));
    drop(connection);

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
    let denial_seq = denied.metadata.budget_commit_index.ok_or_else(|| {
        BudgetStoreError::Invariant("a durable denial must expose its event sequence".to_string())
    })?;
    let denial_event = reopened
        .list_mutation_events(10, Some("leaf"), Some(0))?
        .into_iter()
        .find(|event| event.event_id == "event-composite-2")
        .ok_or_else(|| {
            BudgetStoreError::Invariant("composite denial event was not persisted".to_string())
        })?;
    assert_eq!(denial_event.event_seq, denial_seq);
    assert_eq!(denial_event.usage_seq, None);
    assert_eq!(
        reopened
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        1
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn monetary_composite_denial_preserves_rows_and_replays_frozen_snapshot_after_reopen(
) -> Result<(), BudgetStoreError> {
    let path = unique_db_path("chio-composite-monetary-denial-replay");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-monetary-row-baseline",
            "event-monetary-row-baseline",
            3,
        ))?
        .is_authorized());
    let rows_before = {
        let connection = store.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT profile, owner_id, grant_index_key, reserved_invocations, captured_invocations, updated_at, seq FROM budget_invocation_quota_usage ORDER BY profile, owner_id, grant_index_key",
            )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, i64>(5)?,
                    test_row_u64(row, 6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };

    let mut denied_request =
        composite_authorize_input("hold-monetary-row-denied", "event-monetary-row-denied", 3);
    denied_request.requested_exposure_units = 101;
    denied_request.max_cost_per_invocation = Some(100);
    let denied = store.authorize_composite_hold(denied_request.clone())?;
    let BudgetAuthorizeHoldDecision::Denied(denied_snapshot) = &denied else {
        return Err(BudgetStoreError::Invariant(
            "monetary overspend authorized the composite hold".to_string(),
        ));
    };
    let denial_seq = denied_snapshot
        .metadata
        .budget_commit_index
        .ok_or_else(|| {
            BudgetStoreError::Invariant(
                "a durable denial must expose its event sequence".to_string(),
            )
        })?;
    let rows_after = {
        let connection = store.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT profile, owner_id, grant_index_key, reserved_invocations, captured_invocations, updated_at, seq FROM budget_invocation_quota_usage ORDER BY profile, owner_id, grant_index_key",
            )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, i64>(5)?,
                    test_row_u64(row, 6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    assert_eq!(
        rows_after, rows_before,
        "denial must not rewrite quota rows"
    );

    let persisted: (Option<i64>, u64, Option<u64>) = store.connection()?.query_row(
        r#"
            SELECT authorization.allowed, event.event_seq, event.usage_seq
            FROM budget_composite_authorizations AS authorization
            JOIN budget_mutation_events AS event
              ON event.event_id = authorization.event_id
            WHERE authorization.event_id = 'event-monetary-row-denied'
            "#,
        [],
        |row| {
            Ok((
                row.get(0)?,
                test_row_u64(row, 1)?,
                test_row_optional_u64(row, 2)?,
            ))
        },
    )?;
    assert_eq!(persisted, (Some(0), denial_seq, None));
    assert_eq!(
        store.query_composite_authorization("event-monetary-row-denied")?,
        Some(denied.clone()),
        "the durable denial query must preserve its decision event index"
    );
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-monetary-row-later",
            "event-monetary-row-later",
            3,
        ))?
        .is_authorized());

    drop(store);
    let reopened = SqliteBudgetStore::open(&path)?;
    assert_eq!(
        reopened.authorize_composite_hold(denied_request.clone())?,
        denied,
        "replay must return the original denial after later live usage"
    );
    denied_request.requested_exposure_units = 99;
    assert!(matches!(
        reopened.authorize_composite_hold(denied_request),
        Err(BudgetStoreError::Conflict(_))
    ));

    let _ = fs::remove_file(path);
    Ok(())
}

include!("part_01_tail.inc");
