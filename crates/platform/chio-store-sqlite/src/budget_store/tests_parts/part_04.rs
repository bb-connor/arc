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
            admission_operation: None,
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
    import_events_with_quota_authority(&store, &[import_integrity_record("range-boundary", 2)])
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
    import_events_with_quota_authority(
        &store,
        &[import_integrity_record("range-canonical-boundary", 2)],
    )
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
    let quotas = source
        .list_compatibility_invocation_quota_usages_after(10, None)
        .unwrap();

    let target = SqliteBudgetStore::open(&target_path).unwrap();
    target
        .import_snapshot_records_with_invocation_quotas(
            std::slice::from_ref(&usage),
            &quotas,
            &events,
        )
        .unwrap();
    target
        .import_snapshot_records_with_invocation_quotas(
            std::slice::from_ref(&usage),
            &quotas,
            &events,
        )
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
    let quotas = source
        .list_compatibility_invocation_quota_usages_after(10, None)
        .unwrap();
    let mut replayed_event = events[0].clone();
    replayed_event.recorded_at = replayed_event.recorded_at.saturating_add(30);
    replayed_event.event_seq = replayed_event.event_seq.saturating_add(5);
    replayed_event.usage_seq = replayed_event.usage_seq.map(|seq| seq.saturating_add(5));

    let target = SqliteBudgetStore::open(&target_path).unwrap();
    target
        .import_snapshot_records_with_invocation_quotas(
            std::slice::from_ref(&usage),
            &quotas,
            &events,
        )
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
        .import_snapshot_records_with_invocation_quotas(
            std::slice::from_ref(&usage),
            &quotas,
            &[replayed_event],
        )
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

    let imported_usage = usage_record("cap-import-rollback", 0, 0, unix_now(), 88, 40, 5);

    let quota = store
        .get_compatibility_invocation_quota_usage("cap-import", 0)
        .unwrap()
        .unwrap();
    let error = store
        .import_snapshot_records_with_invocation_quotas(
            &[imported_usage],
            &[quota],
            &[conflicting_event],
        )
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
    import_usage_with_immutable_maximum(
        &store,
        &usage_record("cap-1", 0, 5, 10, 10, 500, 0),
        u32::MAX,
    )
    .unwrap();

    // Lower-seq record written second (stale replica)
    import_usage_with_immutable_maximum(
        &store,
        &usage_record("cap-1", 0, 3, 12, 5, 300, 0),
        u32::MAX,
    )
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

    import_usage_with_immutable_maximum(
        &store,
        &usage_record("cap-1", 0, 1, 20, 20, 0, 75),
        u32::MAX,
    )
    .unwrap();
    import_usage_with_immutable_maximum(
        &store,
        &usage_record("cap-1", 0, 1, 10, 10, 100, 0),
        u32::MAX,
    )
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
        admission_operation: None,
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
    import_events_with_quota_authority(&store, &[event(42), event(43)])?;
    let heads = store.budget_ack_heads()?;
    assert!(
        heads.iter().all(|(origin, _)| origin != "http://origin-o"),
        "a missing prefix must not be laundered into an ack head"
    );

    // Now add the contiguous prefix 1..=41 for the same origin: the head is
    // the last contiguous seq before the 42/43 island, i.e. 43 becomes reachable.
    let contiguous: Vec<_> = (1..=41).map(event).collect();
    import_events_with_quota_authority(&store, &contiguous)?;
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
        admission_operation: None,
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
    import_events_with_quota_authority(
        &store,
        &[event(1), event(2), event(3), event(5), event(6)],
    )?;
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
        admission_operation: None,
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
    import_events_with_quota_authority(&store, &[event(1), event(2), event(3)])?;
    assert_eq!(origin_head(&store.budget_ack_heads()?), Some(3));

    // A hole at 4 (== W+1) with a later island {5,6}: the head must stay pinned at
    // 3 no matter how many times it is polled, and must never jump over the gap.
    import_events_with_quota_authority(&store, &[event(5), event(6)])?;
    for _ in 0..3 {
        assert_eq!(
            origin_head(&store.budget_ack_heads()?),
            Some(3),
            "a permanent hole at W+1 keeps the head pinned at W (fail-closed, no over-count)"
        );
    }

    // Filling the gap at 4 lets the head advance across the now-contiguous 4,5,6.
    import_events_with_quota_authority(&store, &[event(4)])?;
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
    import_events_with_quota_authority(&follower, &[ack_head_event(11, "boundary", "http://o")])?;
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
    import_events_with_quota_authority(
        &storm,
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
    import_events_with_quota_authority(
        &store,
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

    let imported_collision = import_events_with_quota_authority(
        &store,
        &[ack_head_event(
            1_000_000,
            "inside-compact-range",
            "http://compact-origin",
        )],
    )
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
        admission_operation: None,
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
    import_events_with_quota_authority(
        &store,
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
    import_events_with_quota_authority(
        &store,
        &[event(1, a), event(2, a), event(4, b), event(5, b)],
    )?;
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
        admission_operation: None,
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
    import_events_with_quota_authority(
        &store,
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
    import_events_with_quota_authority(
        &store,
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

    import_events_with_quota_authority(
        &store,
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
    import_events_with_quota_authority(
        &store,
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
    import_events_with_quota_authority(
        &store,
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
    import_events_with_quota_authority(&store, &[ack_head_event(5, "e5", "http://o")])?;
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
    import_events_with_quota_authority(&follower, &pre_retry).unwrap();
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
    import_events_with_quota_authority(&follower, std::slice::from_ref(&reappended)).unwrap();

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
