use super::tests::ack_head_event;
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn import_floor_refuses_invalid_sequence_without_advancing_any_origin() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteBudgetStore::open(directory.path().join("budget.db"))?;
    store.record_budget_import_floors(&[ack_head_event(5, "initial", "origin-a")])?;
    for seq in [0, i64::MAX as u64 + 1, u64::MAX] {
        let batch = [
            ack_head_event(20, "valid", "origin-a"),
            ack_head_event(seq, "invalid", "origin-b"),
        ];
        let result = store.record_budget_import_floors(&batch);
        if seq == 0 {
            assert!(matches!(result, Err(BudgetStoreError::Invariant(message))
                if message == "budget import event sequence must be positive"));
        } else {
            assert!(matches!(result, Err(BudgetStoreError::Overflow(message))
                if message.contains("event_seq") && message.contains("SQLite INTEGER range")));
        }
        assert_eq!(store.budget_import_floor("origin-a")?, 4);
        assert_eq!(store.budget_import_floor("origin-b")?, 0);
    }
    Ok(())
}

#[test]
fn import_floor_is_exact_monotonic_and_persistent() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("budget.db");
    let store = SqliteBudgetStore::open(&path)?;
    store.record_budget_import_floors(&[
        ack_head_event(8, "later", "origin"),
        ack_head_event(1, "first", "origin"),
    ])?;
    assert_eq!(store.budget_import_floor("origin")?, 0);
    store.record_budget_import_floors(&[ack_head_event(i64::MAX as u64, "last", "origin")])?;
    store.record_budget_import_floors(&[ack_head_event(2, "old", "origin")])?;
    assert_eq!(store.budget_import_floor("origin")?, i64::MAX as u64 - 1);
    drop(store);
    assert_eq!(
        SqliteBudgetStore::open(&path)?.budget_import_floor("origin")?,
        i64::MAX as u64 - 1
    );
    Ok(())
}

#[test]
fn import_floor_refuses_empty_authority_without_persisting_it() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteBudgetStore::open(directory.path().join("budget.db"))?;
    assert!(
        matches!(store.record_budget_import_floors(&[ack_head_event(2, "invalid", " ")]),
        Err(BudgetStoreError::Invariant(message)) if message == "budget import authority must be nonempty")
    );
    assert_eq!(store.budget_import_floor(" ")?, 0);
    Ok(())
}

#[test]
fn verified_snapshot_refuses_corrupted_local_provenance_without_replacing_it() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("budget.db");
    let store = SqliteBudgetStore::open(&path)?;
    let authority =
        crate::authority::SqliteCapabilityAuthority::open(directory.path().join("authority.db"))?;
    let snapshot = BudgetStoreSnapshot {
        usages: vec![],
        usage_history_anchors: vec![],
        mutation_events: vec![],
        abandoned_seq_ranges: vec![],
        covered_head: 0,
        origin_ack_heads: vec![],
    };
    let chain = authority.commit_budget_snapshot_anchor_set(
        &budget_snapshot_anchor_set_digest(&[])?,
        "https://leader",
        1,
        10,
    )?;
    let provenance = BudgetSnapshotAnchorProvenance {
        schema: "chio.budget-snapshot-anchor-provenance.v1".into(),
        cluster_authenticator: budget_snapshot_anchor_authenticator("cluster-root", &chain)?,
        chain,
    };
    let import = || {
        store.import_budget_snapshot_with_anchor_provenance(
            &snapshot,
            &provenance,
            "https://leader",
            1,
            "cluster-root",
        )
    };
    import()?;
    let connection = Connection::open(&path)?;
    // Model on-disk corruption beyond the table's CHECK constraint.
    connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
    for seq in [0, -1, i64::MAX] {
        connection.execute(
            "UPDATE budget_snapshot_anchor_provenance SET commit_sequence = ?1",
            [seq],
        )?;
        let expected = if seq > 0 {
            "budget snapshot anchor provenance rewinds the persisted leader chain"
        } else {
            "persisted budget snapshot anchor provenance sequence is invalid"
        };
        assert!(
            matches!(import(), Err(BudgetStoreError::Invariant(message)) if message == expected)
        );
        let persisted: i64 = connection.query_row(
            "SELECT commit_sequence FROM budget_snapshot_anchor_provenance",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(persisted, seq);
    }
    connection.execute(
        "UPDATE budget_snapshot_anchor_provenance SET commit_sequence = 1",
        [],
    )?;
    import()?;
    Ok(())
}
