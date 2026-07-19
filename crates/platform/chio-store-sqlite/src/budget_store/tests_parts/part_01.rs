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
    }
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
fn broker_composite_hold_denies_quota_and_monetary_overspend() {
    let quota_path = unique_db_path("chio-broker-quota-overspend");
    let quota_store = SqliteBudgetStore::open(&quota_path).unwrap();
    assert!(quota_store
        .authorize_composite_hold(composite_authorize_input(
            "hold-broker-quota-first",
            "event-broker-quota-first",
            1,
        ))
        .unwrap()
        .is_authorized());
    let quota_denied = quota_store
        .authorize_composite_hold(composite_authorize_input(
            "hold-broker-quota-overspend",
            "event-broker-quota-overspend",
            1,
        ))
        .unwrap();
    let BudgetAuthorizeHoldDecision::Denied(quota_denied) = quota_denied else {
        panic!("exhausted broker composite quota authorized a second hold");
    };
    assert!(quota_denied
        .invocation_counts_after
        .iter()
        .all(|usage| usage.invocation_count_after().unwrap() <= usage.quota.max_invocations()));
    let _ = fs::remove_file(quota_path);

    let monetary_path = unique_db_path("chio-broker-monetary-overspend");
    let monetary_store = SqliteBudgetStore::open(&monetary_path).unwrap();
    let mut monetary_overspend = composite_authorize_input(
        "hold-broker-monetary-overspend",
        "event-broker-monetary-overspend",
        2,
    );
    monetary_overspend.requested_exposure_units = 101;
    monetary_overspend.max_cost_per_invocation = Some(100);
    assert!(matches!(
        monetary_store
            .authorize_composite_hold(monetary_overspend)
            .unwrap(),
        BudgetAuthorizeHoldDecision::Denied(_)
    ));
    assert!(monetary_store.list_all_usages().unwrap().is_empty());
    let _ = fs::remove_file(monetary_path);
}

#[test]
fn broker_logical_operation_charges_parent_and_broker_quotas_once() {
    let path = unique_db_path("chio-broker-operation-single-charge");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let first_request =
        composite_authorize_input("hold-broker-single-charge", "event-broker-single-charge", 2);
    let first = store
        .authorize_composite_hold(first_request.clone())
        .unwrap();
    let BudgetAuthorizeHoldDecision::Authorized(first_authorized) = &first else {
        panic!("first broker composite hold was not authorized");
    };
    assert!(first_authorized
        .invocation_counts_after
        .iter()
        .all(|usage| usage.invocation_count_after().unwrap() == 1));

    let mut rebound =
        composite_authorize_input("hold-broker-double-charge", "event-broker-double-charge", 2);
    rebound.operation_id = first_request.operation_id.clone();
    rebound.request_binding_hash = first_request.request_binding_hash.clone();
    let conflict = store
        .authorize_composite_hold(rebound)
        .expect_err("one broker operation must not authorize a second multi-key hold");
    assert!(conflict.to_string().contains("operation_id"));

    assert_eq!(
        store.authorize_composite_hold(first_request).unwrap(),
        first
    );
    let replayed = store
        .query_composite_authorization("event-broker-single-charge")
        .unwrap()
        .unwrap();
    let BudgetAuthorizeHoldDecision::Authorized(replayed) = replayed else {
        panic!("broker composite hold replay lost its authorization");
    };
    let parent = replayed
        .invocation_counts_after
        .iter()
        .find(|usage| {
            usage.quota.key().profile() == BudgetQuotaProfile::AggregateCapabilityInvocation
        })
        .unwrap();
    let broker = replayed
        .invocation_counts_after
        .iter()
        .find(|usage| {
            usage.quota.key().profile() == BudgetQuotaProfile::SupplementalBrokerExecution
        })
        .unwrap();
    assert_ne!(parent.quota.key(), broker.quota.key());
    assert_eq!(parent.invocation_count_after().unwrap(), 1);
    assert_eq!(broker.invocation_count_after().unwrap(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn aggregate_family_authorization_requires_and_persists_root_evidence() {
    let path = unique_db_path("chio-composite-family-root-evidence");
    let mut request = composite_authorize_input(
        "hold-composite-family-root",
        "event-composite-family-root",
        2,
    );
    request.invocation_quotas = vec![
        persisted_quota(BudgetQuotaProfile::GrantInvocation, "leaf", Some(0), 2),
        persisted_quota(
            BudgetQuotaProfile::AggregateFamilyInvocation,
            &"22".repeat(32),
            None,
            2,
        ),
    ];
    request.revocation_set =
        CanonicalRevocationSet::new("leaf", &["family-root".to_string()], &[]).unwrap();
    let evidence = SqliteAggregateFamilyEvidence {
        root_capability_id: "family-root".to_string(),
        root_binding_digest: "44".repeat(32),
    };

    let store = SqliteBudgetStore::open(&path).unwrap();
    let error = store
        .authorize_composite_hold(request.clone())
        .expect_err("the non-family authorization method must fail closed");
    assert!(error
        .to_string()
        .contains("requires root capability ID and binding digest evidence"));

    let decision = store
        .authorize_aggregate_family_composite_hold(request.clone(), evidence.clone())
        .unwrap();
    assert!(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    let stored = store
        .query_composite_authorization_input(&request.event_id)
        .unwrap()
        .expect("persisted aggregate-family authorization input");
    assert_eq!(stored.authorization, request);
    assert_eq!(stored.aggregate_family_evidence, Some(evidence.clone()));
    drop(store);

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    let recovered = reopened
        .query_composite_authorization_input("event-composite-family-root")
        .unwrap()
        .expect("restart-durable aggregate-family authorization input");
    assert_eq!(recovered.aggregate_family_evidence, Some(evidence));
    let _ = fs::remove_file(path);
}

#[test]
fn composite_authorization_retry_requires_exact_admission_ownership() {
    let path = unique_db_path("chio-composite-budget-authorization-ownership");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let request = composite_authorize_input(
        "hold-authorization-ownership",
        "event-authorization-ownership",
        2,
    );
    let expected_operation_id = request.operation_id.clone();
    let expected_request_binding_hash = request.request_binding_hash.clone();
    let first = store.authorize_composite_hold(request.clone()).unwrap();
    assert_eq!(
        store.authorize_composite_hold(request.clone()).unwrap(),
        first,
        "an exact ownership retry must return the frozen decision"
    );

    let mut wrong_operation = request.clone();
    wrong_operation.operation_id = "different-operation".to_string();
    assert_ownership_conflict(
        store.authorize_composite_hold(wrong_operation),
        "operation_id",
    );

    let mut wrong_request_binding = request.clone();
    wrong_request_binding.request_binding_hash = "22".repeat(32);
    assert_ownership_conflict(
        store.authorize_composite_hold(wrong_request_binding),
        "request_binding_hash",
    );

    let expected = (expected_operation_id, expected_request_binding_hash);
    assert_eq!(
        persisted_admission_ownership(
            &store,
            "budget_authorization_holds",
            "hold_id",
            "hold-authorization-ownership",
        ),
        expected
    );
    assert_eq!(
        persisted_admission_ownership(
            &store,
            "budget_composite_authorizations",
            "hold_id",
            "hold-authorization-ownership",
        ),
        expected
    );
    assert_eq!(
        persisted_admission_ownership(
            &store,
            "budget_composite_holds",
            "hold_id",
            "hold-authorization-ownership",
        ),
        expected
    );
    assert_eq!(
        persisted_admission_ownership(
            &store,
            "budget_mutation_events",
            "event_id",
            "event-authorization-ownership",
        ),
        expected
    );
    assert_eq!(
        persisted_admission_ownership(
            &store,
            "budget_composite_mutation_snapshots",
            "event_id",
            "event-authorization-ownership",
        ),
        expected
    );

    drop(store);
    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(reopened.authorize_composite_hold(request).unwrap(), first);
    let _ = fs::remove_file(path);
}

#[test]
fn composite_hold_mutation_retries_require_exact_admission_ownership() {
    let path = unique_db_path("chio-composite-budget-mutation-ownership");
    let store = SqliteBudgetStore::open(&path).unwrap();

    let capture_hold = "hold-ownership-invocation-capture";
    assert!(store
        .authorize_composite_hold(ownership_composite_authorize_input(
            capture_hold,
            "event-authorize-ownership-invocation-capture",
        ))
        .unwrap()
        .is_authorized());
    let capture = BudgetCaptureInvocationRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        hold_id: Some(capture_hold.to_string()),
        event_id: Some("event-ownership-invocation-capture".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding(capture_hold)),
    };
    assert!(store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            admission_operation: None,
            ..capture.clone()
        })
        .is_err());
    assert_eq!(store.query_invocation_capture(&capture).unwrap(), None);
    let captured = store
        .capture_invocation_reservations(capture.clone())
        .unwrap();
    assert_eq!(
        store.query_invocation_capture(&capture).unwrap(),
        Some(captured.clone())
    );
    assert_eq!(
        store
            .capture_invocation_reservations(capture.clone())
            .unwrap(),
        captured
    );
    assert_ownership_conflict(
        store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            admission_operation: Some(alternate_operation_binding(capture_hold)),
            ..capture.clone()
        }),
        "operation_id",
    );
    assert_ownership_conflict(
        store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            admission_operation: Some(alternate_request_binding(capture_hold)),
            ..capture.clone()
        }),
        "request_binding_hash",
    );
    assert_ownership_conflict(
        store.query_invocation_capture(&BudgetCaptureInvocationRequest {
            admission_operation: Some(alternate_request_binding(capture_hold)),
            ..capture
        }),
        "request_binding_hash",
    );

    let reverse_hold = "hold-ownership-reverse";
    assert!(store
        .authorize_composite_hold(ownership_composite_authorize_input(
            reverse_hold,
            "event-authorize-ownership-reverse",
        ))
        .unwrap()
        .is_authorized());
    let reverse = BudgetReverseHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        reversed_exposure_units: 100,
        hold_id: Some(reverse_hold.to_string()),
        event_id: Some("event-ownership-reverse".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding(reverse_hold)),
    };
    assert!(store
        .reverse_budget_hold(BudgetReverseHoldRequest {
            admission_operation: None,
            ..reverse.clone()
        })
        .is_err());
    let reversed = store.reverse_budget_hold(reverse.clone()).unwrap();
    assert_eq!(
        store.reverse_budget_hold(reverse.clone()).unwrap(),
        reversed
    );
    assert_ownership_conflict(
        store.reverse_budget_hold(BudgetReverseHoldRequest {
            admission_operation: Some(alternate_operation_binding(reverse_hold)),
            ..reverse.clone()
        }),
        "operation_id",
    );
    assert_ownership_conflict(
        store.reverse_budget_hold(BudgetReverseHoldRequest {
            admission_operation: Some(alternate_request_binding(reverse_hold)),
            ..reverse
        }),
        "request_binding_hash",
    );

    let release_hold = "hold-ownership-release";
    assert!(store
        .authorize_composite_hold(ownership_composite_authorize_input(
            release_hold,
            "event-authorize-ownership-release",
        ))
        .unwrap()
        .is_authorized());
    let release = BudgetReleaseHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        released_exposure_units: 40,
        hold_id: Some(release_hold.to_string()),
        event_id: Some("event-ownership-release".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding(release_hold)),
    };
    assert!(store
        .release_budget_hold(BudgetReleaseHoldRequest {
            admission_operation: None,
            ..release.clone()
        })
        .is_err());
    let released = store.release_budget_hold(release.clone()).unwrap();
    assert_eq!(
        store.release_budget_hold(release.clone()).unwrap(),
        released
    );
    assert_ownership_conflict(
        store.release_budget_hold(BudgetReleaseHoldRequest {
            admission_operation: Some(alternate_operation_binding(release_hold)),
            ..release.clone()
        }),
        "operation_id",
    );
    assert_ownership_conflict(
        store.release_budget_hold(BudgetReleaseHoldRequest {
            admission_operation: Some(alternate_request_binding(release_hold)),
            ..release
        }),
        "request_binding_hash",
    );

    let reconcile_hold = "hold-ownership-reconcile";
    assert!(store
        .authorize_composite_hold(ownership_composite_authorize_input(
            reconcile_hold,
            "event-authorize-ownership-reconcile",
        ))
        .unwrap()
        .is_authorized());
    let reconcile = BudgetReconcileHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 30,
        hold_id: Some(reconcile_hold.to_string()),
        event_id: Some("event-ownership-reconcile".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding(reconcile_hold)),
    };
    assert!(store
        .reconcile_budget_hold(BudgetReconcileHoldRequest {
            admission_operation: None,
            ..reconcile.clone()
        })
        .is_err());
    let reconciled = store.reconcile_budget_hold(reconcile.clone()).unwrap();
    assert_eq!(
        store.reconcile_budget_hold(reconcile.clone()).unwrap(),
        reconciled
    );
    assert_ownership_conflict(
        store.reconcile_budget_hold(BudgetReconcileHoldRequest {
            admission_operation: Some(alternate_operation_binding(reconcile_hold)),
            ..reconcile.clone()
        }),
        "operation_id",
    );
    assert_ownership_conflict(
        store.reconcile_budget_hold(BudgetReconcileHoldRequest {
            admission_operation: Some(alternate_request_binding(reconcile_hold)),
            ..reconcile
        }),
        "request_binding_hash",
    );

    let monetary_capture_hold = "hold-ownership-monetary-capture";
    assert!(store
        .authorize_composite_hold(ownership_composite_authorize_input(
            monetary_capture_hold,
            "event-authorize-ownership-monetary-capture",
        ))
        .unwrap()
        .is_authorized());
    let monetary_capture = BudgetCaptureHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 30,
        hold_id: Some(monetary_capture_hold.to_string()),
        event_id: Some("event-ownership-monetary-capture".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding(monetary_capture_hold)),
    };
    assert!(store
        .capture_budget_hold(BudgetCaptureHoldRequest {
            admission_operation: None,
            ..monetary_capture.clone()
        })
        .is_err());
    let monetary_captured = store.capture_budget_hold(monetary_capture.clone()).unwrap();
    assert_eq!(
        store.capture_budget_hold(monetary_capture.clone()).unwrap(),
        monetary_captured
    );
    assert_ownership_conflict(
        store.capture_budget_hold(BudgetCaptureHoldRequest {
            admission_operation: Some(alternate_operation_binding(monetary_capture_hold)),
            ..monetary_capture.clone()
        }),
        "operation_id",
    );
    assert_ownership_conflict(
        store.capture_budget_hold(BudgetCaptureHoldRequest {
            admission_operation: Some(alternate_request_binding(monetary_capture_hold)),
            ..monetary_capture
        }),
        "request_binding_hash",
    );

    for (event_id, hold_id) in [
        ("event-ownership-invocation-capture", capture_hold),
        ("event-ownership-reverse", reverse_hold),
        ("event-ownership-release", release_hold),
        ("event-ownership-reconcile", reconcile_hold),
        ("event-ownership-monetary-capture", monetary_capture_hold),
    ] {
        let expected = (
            composite_admission_binding(hold_id)
                .operation_id()
                .to_string(),
            composite_admission_binding(hold_id)
                .request_binding_hash()
                .to_string(),
        );
        assert_eq!(
            persisted_admission_ownership(&store, "budget_mutation_events", "event_id", event_id,),
            expected
        );
        assert_eq!(
            persisted_admission_ownership(
                &store,
                "budget_composite_mutation_snapshots",
                "event_id",
                event_id,
            ),
            expected
        );
    }

    let _ = fs::remove_file(path);
}

#[test]
fn composite_denial_records_evidence_and_pins_quota_and_grant_authority() {
    let path = unique_db_path("chio-composite-budget-denial-pins-authority");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let denied = store
        .authorize_composite_hold(composite_authorize_input(
            "hold-denied-no-write",
            "event-denied-no-write",
            0,
        ))
        .unwrap();
    assert!(!denied.is_authorized());
    assert_eq!(
        store
            .authorize_composite_hold(composite_authorize_input(
                "hold-denied-no-write",
                "event-denied-no-write",
                0,
            ))
            .unwrap(),
        denied,
        "the durable denial evidence must remain exactly replayable"
    );

    let connection = rusqlite::Connection::open(&path).unwrap();
    let quota_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM budget_invocation_quota_usage",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let managed_grant_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM budget_composite_managed_grants",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let active_hold_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM budget_composite_holds", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(quota_count, 3);
    assert_eq!(managed_grant_count, 1);
    assert_eq!(active_hold_count, 0);
    drop(connection);
    assert!(store.list_all_usages().unwrap().is_empty());

    let maximum_error = store
        .authorize_composite_hold(composite_authorize_input(
            "hold-after-denial",
            "event-after-denial",
            1,
        ))
        .expect_err("a denial must freeze its authenticated quota maximum");
    assert!(maximum_error
        .to_string()
        .contains("presented with a different maximum"));
    let bypass = store
        .try_increment("leaf", 0, Some(10))
        .expect_err("a denied composite hold must establish managed grant ownership");
    assert!(bypass
        .to_string()
        .contains("requires composite invocation admission"));

    drop(store);
    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .authorize_composite_hold(composite_authorize_input(
                "hold-denied-no-write",
                "event-denied-no-write",
                0,
            ))
            .unwrap(),
        denied
    );

    let _ = fs::remove_file(path);
}

#[test]
fn composite_base_hold_identity_corruption_fails_reopen() {
    let path = unique_db_path("chio-composite-base-hold-corruption");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-corrupt-base-identity",
            "event-corrupt-base-identity",
            2,
        ))
        .unwrap()
        .is_authorized());
    drop(store);

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute(
            r#"
            UPDATE budget_authorization_holds
            SET capability_id = 'rebound-capability'
            WHERE hold_id = 'hold-corrupt-base-identity'
            "#,
            [],
        )
        .unwrap();
    drop(connection);

    let error = SqliteBudgetStore::open(&path)
        .err()
        .expect("reopen must reject a rebound composite base-hold identity");
    assert!(error
        .to_string()
        .contains("inconsistent composite admission ownership"));
    let _ = fs::remove_file(path);
}

#[test]
fn composite_hold_with_legacy_claim_corruption_fails_reopen() {
    let path = unique_db_path("chio-composite-legacy-claim-corruption");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-corrupt-legacy-claim",
            "event-corrupt-legacy-claim",
            2,
        ))
        .unwrap()
        .is_authorized());
    drop(store);

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch("DROP TRIGGER budget_legacy_claim_rejects_composite_hold_id_v2;")
        .unwrap();
    connection
        .execute(
            r#"
            INSERT INTO budget_authorization_claims (
                hold_id, event_id, capability_id, grant_index,
                requested_exposure_units, max_invocations,
                max_exposure_per_invocation, max_total_exposure_units,
                authority_id, lease_id, lease_epoch, allowed, created_at
            ) VALUES (
                'hold-corrupt-legacy-claim', 'event-forged-legacy-claim',
                'leaf', 0, 100, 2, 100, 1000,
                NULL, NULL, NULL, 1, 0
            )
            "#,
            [],
        )
        .unwrap();
    drop(connection);

    let error = SqliteBudgetStore::open(&path)
        .err()
        .expect("reopen must reject a composite hold with a legacy claim");
    assert!(error
        .to_string()
        .contains("inconsistent composite admission ownership"));
    let _ = fs::remove_file(path);
}

#[test]
fn pre_admission_ownership_composite_schema_fails_with_explicit_migration_error() {
    let path = unique_db_path("chio-composite-pre-admission-ownership-schema");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-pre-admission-ownership",
            "event-pre-admission-ownership",
            2,
        ))
        .unwrap()
        .is_authorized());
    drop(store);

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(
            r#"
            DROP TRIGGER budget_composite_authorization_immutable;
            DROP TRIGGER budget_composite_authorization_delete_forbidden;
            DROP TRIGGER budget_composite_authorization_requires_owned_base_hold_v2;
            ALTER TABLE budget_composite_authorizations DROP COLUMN operation_id;
            ALTER TABLE budget_composite_authorizations DROP COLUMN request_binding_hash;
            "#,
        )
        .unwrap();
    drop(connection);

    let error = SqliteBudgetStore::open(&path)
        .err()
        .expect("pre-ownership composite rows must fail closed during migration");
    assert!(error
        .to_string()
        .contains("ownership cannot be inferred safely"));
    let _ = fs::remove_file(path);
}

#[test]
fn denied_composite_hold_id_cannot_be_reused_by_legacy_authorization() {
    let path = unique_db_path("chio-composite-denied-hold-namespace");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let denied = store
        .authorize_composite_hold(composite_authorize_input(
            "hold-shared-namespace",
            "event-composite-denied-namespace",
            0,
        ))
        .unwrap();
    assert!(!denied.is_authorized());

    let error = store
        .try_charge_cost_with_ids(
            "different-capability",
            7,
            Some(3),
            1,
            None,
            None,
            Some("hold-shared-namespace"),
            Some("event-legacy-after-denial"),
        )
        .expect_err("a denied composite record must retain global hold-id ownership");
    assert!(error.to_string().contains("composite authorization"));

    let _ = fs::remove_file(path);
}

#[test]
fn legacy_hold_id_cannot_be_reused_by_composite_authorization() {
    let path = unique_db_path("chio-legacy-hold-composite-namespace");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost_with_ids(
            "legacy-capability",
            0,
            Some(3),
            1,
            None,
            None,
            Some("hold-inverse-namespace"),
            Some("event-legacy-first"),
        )
        .unwrap());

    let request =
        composite_authorize_input("hold-inverse-namespace", "event-composite-after-legacy", 1);
    let error = store
        .authorize_composite_hold(request)
        .expect_err("a legacy record must retain global hold-id ownership");
    assert!(error.to_string().contains("collides with a legacy hold"));

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
fn invocation_quota_authority_cannot_be_deleted_by_direct_sql() {
    let path = unique_db_path("chio-budget-quota-delete-guard");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(!store.try_increment("cap-delete-guard", 0, Some(0)).unwrap());

    let connection = store.connection().unwrap();
    let error = connection
        .execute(
            r#"
            DELETE FROM budget_invocation_quota_usage
            WHERE profile = 'chio.grant-invocation.v1'
              AND owner_id = 'cap-delete-guard'
              AND grant_index_key = 0
            "#,
            [],
        )
        .expect_err("direct SQL must not erase immutable quota authority");
    assert!(error
        .to_string()
        .contains("immutable invocation quota authority"));
    drop(connection);

    assert!(!store.try_increment("cap-delete-guard", 0, Some(0)).unwrap());
    let error = store
        .try_increment("cap-delete-guard", 0, Some(1))
        .expect_err("the original maximum must remain frozen");
    assert!(error
        .to_string()
        .contains("presented with a different maximum"));

    let _ = fs::remove_file(path);
}

#[test]
fn composite_managed_grant_authority_cannot_be_changed_by_direct_sql() {
    let path = unique_db_path("chio-budget-managed-grant-delete-guard");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let denied = store
        .authorize_composite_hold(composite_authorize_input(
            "hold-managed-delete-guard",
            "event-managed-delete-guard",
            0,
        ))
        .unwrap();
    assert!(!denied.is_authorized());

    let connection = store.connection().unwrap();
    let delete_error = connection
        .execute(
            "DELETE FROM budget_composite_managed_grants WHERE capability_id = 'leaf' AND grant_index = 0",
            [],
        )
        .expect_err("direct SQL must not erase composite grant ownership");
    assert!(delete_error
        .to_string()
        .contains("immutable composite grant authority"));
    let update_error = connection
        .execute(
            "UPDATE budget_composite_managed_grants SET capability_id = 'replacement' WHERE capability_id = 'leaf' AND grant_index = 0",
            [],
        )
        .expect_err("direct SQL must not rebind composite grant ownership");
    assert!(update_error
        .to_string()
        .contains("immutable composite grant authority"));
    drop(connection);

    let bypass = store
        .try_increment("leaf", 0, Some(0))
        .expect_err("composite ownership must remain authoritative");
    assert!(bypass
        .to_string()
        .contains("requires composite invocation admission"));

    let _ = fs::remove_file(path);
}

#[test]
fn denied_composite_authorization_still_freezes_every_quota_maximum() {
    let path = unique_db_path("chio-composite-denied-immutable-maximum");
    let store = SqliteBudgetStore::open(&path).unwrap();

    let denied = store
        .authorize_composite_hold(composite_authorize_input(
            "hold-denied-immutable-1",
            "event-denied-immutable-1",
            0,
        ))
        .unwrap();
    assert!(matches!(denied, BudgetAuthorizeHoldDecision::Denied(_)));

    let bypass_error = store
        .try_increment("leaf", 0, Some(2))
        .expect_err("a denied composite admission must still close the legacy authority path");
    assert!(bypass_error
        .to_string()
        .contains("requires composite invocation admission"));

    let error = store
        .authorize_composite_hold(composite_authorize_input(
            "hold-denied-immutable-2",
            "event-denied-immutable-2",
            1,
        ))
        .expect_err("a denied quota must retain its first authenticated maximum");
    assert!(error
        .to_string()
        .contains("presented with a different maximum"));

    let _ = fs::remove_file(path);
}

#[test]
fn composite_authorization_migrates_legacy_usage_without_resetting_reports() {
    let path = unique_db_path("chio-composite-budget-legacy-migration");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store.try_increment("leaf", 0, Some(10)).unwrap());
    drop(store);

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    let mut request = composite_authorize_input("hold-migrated-1", "event-migrated-1", 2);
    request.invocation_quotas[0] =
        persisted_quota(BudgetQuotaProfile::GrantInvocation, "leaf", Some(0), 10);
    let decision = reopened.authorize_composite_hold(request).unwrap();
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
fn composite_adoption_cannot_replace_compatibility_quota_maximum() {
    let path = unique_db_path("chio-composite-budget-legacy-maximum-conflict");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store.try_increment("leaf", 0, Some(10)).unwrap());

    let error = store
        .authorize_composite_hold(composite_authorize_input(
            "hold-migrated-conflict",
            "event-migrated-conflict",
            2,
        ))
        .expect_err("composite adoption must retain the compatibility authority maximum");
    assert!(error
        .to_string()
        .contains("presented with a different maximum"));
    assert_eq!(
        store
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        1
    );

    let _ = fs::remove_file(path);
}
