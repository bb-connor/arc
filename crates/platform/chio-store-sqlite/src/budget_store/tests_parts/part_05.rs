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
    import_events_with_quota_authority(&follower, &pre_retry).unwrap();
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
    import_events_with_quota_authority(&follower, std::slice::from_ref(&reappended)).unwrap();

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
    import_events_with_quota_authority(&follower, &pre_retry).unwrap();
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
    import_events_with_quota_authority(&follower, std::slice::from_ref(&reappended)).unwrap();

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

type DurableQuotaRow = (String, String, i64, u32, u32, u32, i64, u64);
type LegacyProjectionRow = (String, i64, u32, i64, u64, u64, u64);

#[derive(Debug, PartialEq, Eq)]
struct DurableBudgetState {
    quota_rows: Vec<DurableQuotaRow>,
    legacy_usage_rows: Vec<LegacyProjectionRow>,
    composite_authorizations: u32,
    mutation_events: u32,
    authorization_holds: u32,
    composite_holds: u32,
    managed_grants: u32,
    replication_floor: i64,
}

fn durable_budget_state(
    store: &SqliteBudgetStore,
) -> Result<DurableBudgetState, Box<dyn std::error::Error>> {
    let connection = store.connection()?;
    let quota_rows = {
        let mut statement = connection.prepare(
            r#"
                SELECT profile, owner_id, grant_index_key, max_invocations,
                       reserved_invocations, captured_invocations, updated_at, seq
                FROM budget_invocation_quota_usage
                ORDER BY profile, owner_id, grant_index_key
                "#,
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    test_row_u64(row, 7)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    let legacy_usage_rows = {
        let mut statement = connection.prepare(
            r#"
                SELECT capability_id, grant_index, invocation_count, updated_at, seq,
                       total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                ORDER BY capability_id, grant_index
                "#,
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    test_row_u64(row, 4)?,
                    test_row_u64(row, 5)?,
                    test_row_u64(row, 6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    let (
        composite_authorizations,
        mutation_events,
        authorization_holds,
        composite_holds,
        managed_grants,
        replication_floor,
    ) = connection.query_row(
        r#"
            SELECT
                (SELECT COUNT(*) FROM budget_composite_authorizations),
                (SELECT COUNT(*) FROM budget_mutation_events),
                (SELECT COUNT(*) FROM budget_authorization_holds),
                (SELECT COUNT(*) FROM budget_composite_holds),
                (SELECT COUNT(*) FROM budget_composite_managed_grants),
                (SELECT next_seq FROM budget_replication_meta WHERE singleton = 1)
            "#,
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    Ok(DurableBudgetState {
        quota_rows,
        legacy_usage_rows,
        composite_authorizations,
        mutation_events,
        authorization_holds,
        composite_holds,
        managed_grants,
        replication_floor,
    })
}

#[test]
fn capture_compatibility_rejects_reserved_authority() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-capture-compatibility-reserved-authority");
    let store = SqliteBudgetStore::open(&path)?;
    let request = composite_authorize_input(
        "hold-capture-compatibility-reserved",
        "event-capture-compatibility-reserved",
        2,
    );
    assert!(store
        .authorize_composite_hold(request.clone())?
        .is_authorized());
    let before = durable_budget_state(&store)?;

    {
        let mut connection = store.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let attempted_event_seq = allocate_budget_replication_seq(&transaction)?;
        let primary_quota = request.invocation_quotas[0].clone();
        let error = SqliteBudgetStore::compare_and_mutate_invocation_quotas(
            &transaction,
            std::slice::from_ref(&primary_quota),
            primary_quota.key(),
            1,
            super::store::SqliteInvocationQuotaMutationContext {
                mode: super::store::SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                action: super::store::SqliteInvocationQuotaMutationAction::Attempt {
                    external_denied: false,
                },
                event_seq: attempted_event_seq,
                updated_at: unix_now(),
            },
        )
        .err()
        .ok_or("compatibility capture unexpectedly consumed reserved authority")?;
        assert!(matches!(error, BudgetStoreError::Invariant(_)));
        transaction.rollback()?;
    }

    assert_eq!(durable_budget_state(&store)?, before);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn composite_reserve_cas_miss_rolls_back_batch_event_and_sequence(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-composite-reserve-cas-rollback");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-composite-cas-baseline",
            "event-composite-cas-baseline",
            2,
        ))?
        .is_authorized());
    store.connection()?.execute_batch(
        r#"
            CREATE TRIGGER ignore_aggregate_quota_update
            BEFORE UPDATE ON budget_invocation_quota_usage
            WHEN OLD.profile = 'chio.aggregate-capability-invocation.v1'
              AND OLD.owner_id = 'leaf'
              AND OLD.grant_index_key = -1
            BEGIN
                SELECT RAISE(IGNORE);
            END;
            "#,
    )?;
    let before = durable_budget_state(&store)?;

    let error = store
        .authorize_composite_hold(composite_authorize_input(
            "hold-composite-cas-rejected",
            "event-composite-cas-rejected",
            2,
        ))
        .err()
        .ok_or("missed quota compare-and-swap unexpectedly authorized the hold")?;
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(durable_budget_state(&store)?, before);
    assert_eq!(
        store.query_composite_authorization("event-composite-cas-rejected")?,
        None
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn composite_quota_insert_miss_rolls_back_batch_event_and_sequence(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-composite-quota-insert-rollback");
    let store = SqliteBudgetStore::open(&path)?;
    store.connection()?.execute_batch(
        r#"
        CREATE TRIGGER ignore_aggregate_quota_insert
        BEFORE INSERT ON budget_invocation_quota_usage
        WHEN NEW.profile = 'chio.aggregate-capability-invocation.v1'
          AND NEW.owner_id = 'leaf'
          AND NEW.grant_index_key = -1
        BEGIN
            SELECT RAISE(IGNORE);
        END;
        "#,
    )?;
    let before = durable_budget_state(&store)?;

    let error = store
        .authorize_composite_hold(composite_authorize_input(
            "hold-composite-insert-rejected",
            "event-composite-insert-rejected",
            2,
        ))
        .err()
        .ok_or("ignored quota insert unexpectedly authorized the hold")?;
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(durable_budget_state(&store)?, before);
    assert_eq!(
        store.query_composite_authorization("event-composite-insert-rejected")?,
        None
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn composite_projection_cas_miss_rolls_back_quota_batch_event_and_sequence(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-composite-projection-cas-rollback");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-composite-projection-baseline",
            "event-composite-projection-baseline",
            2,
        ))?
        .is_authorized());
    store.connection()?.execute_batch(
        r#"
        CREATE TRIGGER ignore_composite_projection_update
        BEFORE UPDATE ON capability_grant_budgets
        WHEN OLD.capability_id = 'leaf' AND OLD.grant_index = 0
        BEGIN
            SELECT RAISE(IGNORE);
        END;
        "#,
    )?;
    let before = durable_budget_state(&store)?;

    let error = store
        .authorize_composite_hold(composite_authorize_input(
            "hold-composite-projection-rejected",
            "event-composite-projection-rejected",
            2,
        ))
        .err()
        .ok_or("ignored legacy projection update unexpectedly authorized the hold")?;
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(durable_budget_state(&store)?, before);
    assert_eq!(
        store.query_composite_authorization("event-composite-projection-rejected")?,
        None
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn composite_projection_sequence_cas_miss_rolls_back_quota_batch(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-composite-projection-sequence-cas-rollback");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-composite-sequence-baseline",
            "event-composite-sequence-baseline",
            2,
        ))?
        .is_authorized());
    store.connection()?.execute_batch(
        r#"
        CREATE TRIGGER drift_projection_sequence_during_quota_update
        BEFORE UPDATE ON budget_invocation_quota_usage
        WHEN OLD.profile = 'chio.aggregate-capability-invocation.v1'
          AND OLD.owner_id = 'leaf'
          AND OLD.grant_index_key = -1
        BEGIN
            UPDATE capability_grant_budgets
            SET seq = seq + 100
            WHERE capability_id = 'leaf' AND grant_index = 0;
        END;
        "#,
    )?;
    let before = durable_budget_state(&store)?;

    let error = store
        .authorize_composite_hold(composite_authorize_input(
            "hold-composite-sequence-rejected",
            "event-composite-sequence-rejected",
            2,
        ))
        .err()
        .ok_or("projection sequence drift unexpectedly authorized the hold")?;
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(durable_budget_state(&store)?, before);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn compatibility_projection_cas_miss_rolls_back_quota_event_and_sequence(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-compatibility-projection-cas-rollback");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store.try_increment_with_event_id(
        "cap-compatibility-projection",
        0,
        Some(2),
        Some("event-compatibility-projection-baseline"),
    )?);
    store.connection()?.execute_batch(
        r#"
        CREATE TRIGGER ignore_compatibility_projection_update
        BEFORE UPDATE ON capability_grant_budgets
        WHEN OLD.capability_id = 'cap-compatibility-projection' AND OLD.grant_index = 0
        BEGIN
            SELECT RAISE(IGNORE);
        END;
        "#,
    )?;
    let before = durable_budget_state(&store)?;

    let error = store
        .try_increment_with_event_id(
            "cap-compatibility-projection",
            0,
            Some(2),
            Some("event-compatibility-projection-rejected"),
        )
        .err()
        .ok_or("ignored legacy projection update unexpectedly captured quota")?;
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(durable_budget_state(&store)?, before);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn composite_marker_insert_miss_rolls_back_all_durable_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-composite-marker-insert-rollback");
    let store = SqliteBudgetStore::open(&path)?;
    store.connection()?.execute_batch(
        r#"
        CREATE TRIGGER ignore_composite_marker_insert
        BEFORE INSERT ON budget_composite_managed_grants
        WHEN NEW.capability_id = 'leaf' AND NEW.grant_index = 0
        BEGIN
            SELECT RAISE(IGNORE);
        END;
        "#,
    )?;
    let before = durable_budget_state(&store)?;

    let error = store
        .authorize_composite_hold(composite_authorize_input(
            "hold-composite-marker-rejected",
            "event-composite-marker-rejected",
            2,
        ))
        .err()
        .ok_or("ignored managed marker insert unexpectedly committed authorization")?;
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(durable_budget_state(&store)?, before);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn composite_exact_replay_requires_managed_grant_marker() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-composite-replay-missing-marker");
    let store = SqliteBudgetStore::open(&path)?;
    let request = composite_authorize_input(
        "hold-composite-replay-missing-marker",
        "event-composite-replay-missing-marker",
        2,
    );
    assert!(store
        .authorize_composite_hold(request.clone())?
        .is_authorized());
    store.connection()?.execute_batch(
        r#"
        DROP TRIGGER budget_composite_managed_grant_delete_forbidden;
        DELETE FROM budget_composite_managed_grants
        WHERE capability_id = 'leaf' AND grant_index = 0;
        "#,
    )?;
    let before = durable_budget_state(&store)?;

    let error = store
        .authorize_composite_hold(request)
        .err()
        .ok_or("exact replay unexpectedly accepted a missing managed-grant marker")?;
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(durable_budget_state(&store)?, before);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn composite_adoption_rejects_open_compatibility_hold_without_stranding_it(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-composite-adoption-open-compatibility-hold");
    let store = SqliteBudgetStore::open(&path)?;
    let legacy_hold_id = "hold-open-compatibility";
    assert!(store.try_charge_cost_with_ids(
        "leaf",
        0,
        Some(4),
        10,
        Some(100),
        Some(1_000),
        Some(legacy_hold_id),
        Some("event-open-compatibility-authorize"),
    )?);
    let before = durable_budget_state(&store)?;
    let mut request = composite_authorize_input(
        "hold-composite-adoption-rejected",
        "event-composite-adoption-rejected",
        4,
    );
    request.requested_exposure_units = 101;
    request.max_cost_per_invocation = Some(100);

    let error = store
        .authorize_composite_hold(request)
        .err()
        .ok_or("composite adoption unexpectedly accepted an open compatibility hold")?;
    assert!(matches!(error, BudgetStoreError::Conflict(_)));
    assert_eq!(durable_budget_state(&store)?, before);
    store.reverse_charge_cost_with_ids(
        "leaf",
        0,
        10,
        Some(legacy_hold_id),
        Some("event-open-compatibility-reverse"),
    )?;

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn compatibility_replay_cannot_repair_missing_quota_after_composite_adoption(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-compatibility-replay-after-composite-adoption");
    let store = SqliteBudgetStore::open(&path)?;
    let compatibility_event_id = "event-compatibility-before-composite";
    assert!(store.try_increment_with_event_id("leaf", 0, Some(4), Some(compatibility_event_id),)?);
    let mut composite_request = composite_authorize_input(
        "hold-composite-after-compatibility",
        "event-composite-after-compatibility",
        4,
    );
    composite_request.invocation_quotas[0] =
        persisted_quota(BudgetQuotaProfile::GrantInvocation, "leaf", Some(0), 4);
    assert!(store
        .authorize_composite_hold(composite_request)?
        .is_authorized());
    store.connection()?.execute_batch(
        r#"
        DROP TRIGGER budget_invocation_quota_delete_forbidden;
        DELETE FROM budget_invocation_quota_usage
        WHERE profile = 'chio.grant-invocation.v1'
          AND owner_id = 'leaf'
          AND grant_index_key = 0;
        "#,
    )?;
    let before = durable_budget_state(&store)?;

    let error = store
        .try_increment_with_event_id("leaf", 0, Some(4), Some(compatibility_event_id))
        .err()
        .ok_or("compatibility replay unexpectedly repaired composite-managed authority")?;
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(durable_budget_state(&store)?, before);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn legacy_only_reverse_migrates_quota_before_decrementing() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-legacy-only-reverse-quota-migration");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store.try_increment_with_event_id(
        "cap-legacy-only-reverse",
        0,
        Some(2),
        Some("event-legacy-only-reverse-capture"),
    )?);
    store.connection()?.execute_batch(
        r#"
        DROP TRIGGER budget_invocation_quota_delete_forbidden;
        DELETE FROM budget_invocation_quota_usage
        WHERE profile = 'chio.grant-invocation.v1'
          AND owner_id = 'cap-legacy-only-reverse'
          AND grant_index_key = 0;
        "#,
    )?;

    store.reverse_charge_cost_with_ids(
        "cap-legacy-only-reverse",
        0,
        0,
        None,
        Some("event-legacy-only-reverse"),
    )?;
    let quota: (u32, u32, u32) = store.connection()?.query_row(
        r#"
        SELECT max_invocations, reserved_invocations, captured_invocations
        FROM budget_invocation_quota_usage
        WHERE profile = 'chio.grant-invocation.v1'
          AND owner_id = 'cap-legacy-only-reverse'
          AND grant_index_key = 0
        "#,
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(quota, (2, 0, 0));
    assert_eq!(
        store
            .get_usage("cap-legacy-only-reverse", 0)?
            .ok_or("legacy projection disappeared during reverse migration")?
            .invocation_count,
        0
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn legacy_only_reaper_migrates_quota_before_recovery() -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::budget_store::CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX;

    let path = unique_db_path("chio-legacy-only-reaper-quota-migration");
    let store = SqliteBudgetStore::open(&path)?;
    let hold_id = "hold-legacy-only-reaper";
    let authorize_event_id =
        format!("{hold_id}{CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX}");
    assert!(store.try_charge_cost_with_ids(
        "cap-legacy-only-reaper",
        0,
        Some(2),
        10,
        Some(100),
        Some(1_000),
        Some(hold_id),
        Some(&authorize_event_id),
    )?);
    store.connection()?.execute_batch(
        r#"
        DROP TRIGGER budget_invocation_quota_delete_forbidden;
        DELETE FROM budget_invocation_quota_usage
        WHERE profile = 'chio.grant-invocation.v1'
          AND owner_id = 'cap-legacy-only-reaper'
          AND grant_index_key = 0;
        "#,
    )?;

    assert_eq!(store.recover_unstamped_caller_reservations()?, 1);
    let quota: (u32, u32, u32) = store.connection()?.query_row(
        r#"
        SELECT max_invocations, reserved_invocations, captured_invocations
        FROM budget_invocation_quota_usage
        WHERE profile = 'chio.grant-invocation.v1'
          AND owner_id = 'cap-legacy-only-reaper'
          AND grant_index_key = 0
        "#,
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(quota, (2, 0, 0));
    let usage = store
        .get_usage("cap-legacy-only-reaper", 0)?
        .ok_or("legacy projection disappeared during reaper migration")?;
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.total_cost_exposed, 0);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn exact_reverse_replay_rejects_structured_projection_divergence(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-reverse-replay-structured-divergence");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store.try_increment_with_event_id(
        "cap-reverse-replay-divergence",
        0,
        Some(2),
        Some("event-reverse-replay-capture"),
    )?);
    let reverse_event_id = "event-reverse-replay-divergence";
    store.reverse_charge_cost_with_ids(
        "cap-reverse-replay-divergence",
        0,
        0,
        None,
        Some(reverse_event_id),
    )?;
    store.connection()?.execute(
        r#"
        UPDATE budget_invocation_quota_usage
        SET captured_invocations = 1
        WHERE profile = 'chio.grant-invocation.v1'
          AND owner_id = 'cap-reverse-replay-divergence'
          AND grant_index_key = 0
        "#,
        [],
    )?;
    let before = durable_budget_state(&store)?;

    let error = store
        .reverse_charge_cost_with_ids(
            "cap-reverse-replay-divergence",
            0,
            0,
            None,
            Some(reverse_event_id),
        )
        .err()
        .ok_or("exact reverse replay unexpectedly ignored quota divergence")?;
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(durable_budget_state(&store)?, before);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn immutable_quota_maximum_mismatch_is_an_invariant_error() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-immutable-quota-maximum-invariant");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store.try_increment_with_event_id(
        "cap-immutable-maximum-invariant",
        0,
        Some(1),
        Some("event-immutable-maximum-first"),
    )?);
    let before = durable_budget_state(&store)?;

    let error = store
        .try_increment_with_event_id(
            "cap-immutable-maximum-invariant",
            0,
            Some(2),
            Some("event-immutable-maximum-mismatch"),
        )
        .err()
        .ok_or("immutable quota maximum unexpectedly changed")?;
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(durable_budget_state(&store)?, before);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn exhausted_quota_denial_precedes_unbounded_monetary_overflow(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-exhausted-quota-before-monetary-overflow");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-overflow-order-baseline",
            "event-overflow-order-baseline",
            1,
        ))?
        .is_authorized());
    let usage_before = store
        .get_usage("leaf", 0)?
        .ok_or("baseline usage is missing")?;
    let mut request = composite_authorize_input(
        "hold-overflow-order-denied",
        "event-overflow-order-denied",
        1,
    );
    request.requested_exposure_units = u64::MAX;
    request.max_cost_per_invocation = None;
    request.max_total_cost_units = None;

    let decision = store.authorize_composite_hold(request)?;
    let BudgetAuthorizeHoldDecision::Denied(denied) = decision else {
        return Err("exhausted quota did not produce a durable denial".into());
    };
    assert_eq!(denied.invocation_count_after, usage_before.invocation_count);
    assert!(denied.metadata.budget_commit_index.is_some());
    assert_eq!(
        store
            .get_usage("leaf", 0)?
            .ok_or("denial removed baseline usage")?,
        usage_before
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn exhausted_compatibility_quota_denial_precedes_unbounded_cost_overflow(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-exhausted-compatibility-before-cost-overflow");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store.try_charge_cost_with_ids(
        "cap-compatibility-overflow-order",
        0,
        Some(1),
        1,
        None,
        None,
        None,
        Some("event-compatibility-overflow-baseline"),
    )?);
    let usage_before = store
        .get_usage("cap-compatibility-overflow-order", 0)?
        .ok_or("baseline compatibility usage is missing")?;

    assert!(!store.try_charge_cost_with_ids(
        "cap-compatibility-overflow-order",
        0,
        Some(1),
        u64::MAX,
        None,
        None,
        None,
        Some("event-compatibility-overflow-denied"),
    )?);
    assert_eq!(
        store
            .get_usage("cap-compatibility-overflow-order", 0)?
            .ok_or("denial removed compatibility usage")?,
        usage_before
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn composite_capture_quota_cas_miss_rolls_back_projection_hold_and_sequence(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-composite-capture-quota-cas-rollback");
    let store = SqliteBudgetStore::open(&path)?;
    let hold_id = "hold-composite-capture-cas";
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            hold_id,
            "event-composite-capture-cas-authorize",
            2,
        ))?
        .is_authorized());
    store.connection()?.execute_batch(
        r#"
        CREATE TRIGGER ignore_capture_aggregate_quota_update
        BEFORE UPDATE ON budget_invocation_quota_usage
        WHEN OLD.profile = 'chio.aggregate-capability-invocation.v1'
          AND OLD.owner_id = 'leaf'
          AND OLD.grant_index_key = -1
        BEGIN
            SELECT RAISE(IGNORE);
        END;
        "#,
    )?;
    let before = durable_budget_state(&store)?;

    let error = store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "leaf".to_string(),
            grant_index: 0,
            hold_id: Some(hold_id.to_string()),
            event_id: Some("event-composite-capture-cas-rejected".to_string()),
            authority: None,
            admission_operation: Some(composite_admission_binding(hold_id)),
        })
        .err()
        .ok_or("ignored quota update unexpectedly captured composite reservations")?;
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(durable_budget_state(&store)?, before);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn composite_exact_replay_rejects_diverged_primary_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-composite-replay-diverged-primary");
    let store = SqliteBudgetStore::open(&path)?;
    let request = composite_authorize_input(
        "hold-composite-replay-diverged-primary",
        "event-composite-replay-diverged-primary",
        2,
    );
    assert!(store
        .authorize_composite_hold(request.clone())?
        .is_authorized());
    store.connection()?.execute(
        r#"
            UPDATE budget_invocation_quota_usage
            SET reserved_invocations = 0
            WHERE profile = 'chio.grant-invocation.v1'
              AND owner_id = 'leaf'
              AND grant_index_key = 0
            "#,
        [],
    )?;
    let before_replay = durable_budget_state(&store)?;

    let error = store
        .authorize_composite_hold(request)
        .err()
        .ok_or("exact replay unexpectedly accepted a diverged primary projection")?;
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(
        durable_budget_state(&store)?,
        before_replay,
        "replay must neither repair the corrupt counter nor allocate a sequence"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn composite_exact_replay_rejects_missing_structured_quota_without_repair(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-composite-replay-missing-quota");
    let store = SqliteBudgetStore::open(&path)?;
    let request = composite_authorize_input(
        "hold-composite-replay-missing-quota",
        "event-composite-replay-missing-quota",
        2,
    );
    assert!(store
        .authorize_composite_hold(request.clone())?
        .is_authorized());
    store.connection()?.execute_batch(
        r#"
        DROP TRIGGER budget_invocation_quota_delete_forbidden;
        DELETE FROM budget_invocation_quota_usage
        WHERE profile = 'chio.aggregate-capability-invocation.v1'
          AND owner_id = 'leaf'
          AND grant_index_key = -1;
        "#,
    )?;
    let before_replay = durable_budget_state(&store)?;

    let error = store
        .authorize_composite_hold(request)
        .err()
        .ok_or("exact replay unexpectedly repaired missing structured quota authority")?;
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert_eq!(
        durable_budget_state(&store)?,
        before_replay,
        "replay must not synthesize missing authority or allocate a sequence"
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn composite_authority_retry_is_exact_across_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-composite-authority-reopen-retry");
    let authority_a = authority("budget-primary", "lease-a", 1);
    let authority_b = authority("budget-primary", "lease-b", 2);
    let mut request = composite_authorize_input(
        "hold-composite-authority-reopen",
        "event-composite-authority-reopen",
        2,
    );
    request.authority = Some(authority_a);
    let store = SqliteBudgetStore::open(&path)?;
    let first = store.authorize_composite_hold(request.clone())?;
    let before_reopen = durable_budget_state(&store)?;
    drop(store);

    let reopened = SqliteBudgetStore::open(&path)?;
    assert_eq!(reopened.authorize_composite_hold(request.clone())?, first);
    assert_eq!(durable_budget_state(&reopened)?, before_reopen);

    let before_conflict = durable_budget_state(&reopened)?;
    request.authority = Some(authority_b);
    let error = reopened
        .authorize_composite_hold(request)
        .err()
        .ok_or("authority mismatch unexpectedly replayed as exact")?;
    assert!(matches!(error, BudgetStoreError::Conflict(_)));
    assert_eq!(durable_budget_state(&reopened)?, before_conflict);

    let _ = fs::remove_file(path);
    Ok(())
}
