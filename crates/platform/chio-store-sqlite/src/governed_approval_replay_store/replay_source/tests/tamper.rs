use super::*;

#[test]
fn partial_or_substituted_seals_fail_live_retry_and_startup_without_repair() -> TestResult {
    for mutation in [
        "DROP TABLE chio_governed_approval_replay_source_seal",
        "DROP TRIGGER chio_governed_approval_replay_source_entries_no_delete",
        "DROP TRIGGER chio_governed_approval_replay_source_seal_no_delete;
         DELETE FROM chio_governed_approval_replay_source_seal",
        "DROP TRIGGER chio_governed_approval_replay_source_entries_no_update;
         UPDATE chio_governed_approval_replay_entries SET dispatch_reservation_id = NULL",
        "DROP TRIGGER chio_governed_approval_replay_source_clock_no_update;
         UPDATE chio_governed_approval_replay_clock SET pruned_through = -9223372036854775808",
        "DROP TRIGGER chio_governed_approval_replay_source_limits_no_update;
         UPDATE chio_governed_approval_replay_limits SET capacity = capacity + 1",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("approval.db");
        let store = SqliteGovernedApprovalReplayStore::open(&path)?;
        assert!(reserve(&store, "reserved")?);
        let expected = store.preview_legacy_replay_source(&binding()?)?;
        store.seal_expected_legacy_replay_source(&expected)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(mutation)?;
        assert!(
            store.verify_legacy_replay_source_seal(&expected).is_err(),
            "{mutation}"
        );
        assert!(store.seal_expected_legacy_replay_source(&expected).is_err());
        assert!(reserve(&store, "new").is_err());
        assert!(SqliteGovernedApprovalReplayStore::open(&path).is_err());
    }
    Ok(())
}

#[test]
fn restored_barriers_do_not_hide_changed_inventory_or_changed_artifact() -> TestResult {
    for (table, column, new_value) in [
        ("entries", "dispatch_reservation_id", "NULL"),
        (
            "clock",
            "wall_clock_high_water",
            "wall_clock_high_water + 1",
        ),
        ("clock", "pruned_through", "-9223372036854775808"),
        ("limits", "capacity", "capacity + 1"),
        ("source_seal", "canonical_bytes", "x'7b7d'"),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("approval.db");
        let store = SqliteGovernedApprovalReplayStore::open(&path)?;
        assert!(reserve(&store, "reserved")?);
        let expected = store.preview_legacy_replay_source(&binding()?)?;
        store.seal_expected_legacy_replay_source(&expected)?;
        let connection = Connection::open(&path)?;
        // Simulate privileged schema tampering, then restore the exact trigger.
        // Schema matching alone must not cause a substituted inventory to pass.
        let name = if table == "source_seal" {
            "seal"
        } else {
            table
        };
        let trigger = format!("chio_governed_approval_replay_source_{name}_no_update");
        let sql: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE name = ?1",
            [&trigger],
            |row| row.get(0),
        )?;
        connection.execute_batch(&format!("DROP TRIGGER {trigger}; UPDATE chio_governed_approval_replay_{table} SET {column} = {new_value}; {sql}"))?;
        schema::verify(&connection, true)?;
        assert!(store.verify_legacy_replay_source_seal(&expected).is_err());
        assert!(SqliteGovernedApprovalReplayStore::open(&path).is_err());
    }
    Ok(())
}

#[test]
fn unexpected_catalog_objects_and_incomplete_evidence_are_not_repaired() -> TestResult {
    for sql in [
        "CREATE INDEX extra_replay_index ON chio_governed_approval_replay_entries(request_id)",
        "CREATE TRIGGER chio_governed_approval_replay_source_incomplete BEFORE INSERT ON chio_governed_approval_replay_entries BEGIN SELECT 1; END",
        "CREATE TABLE chio_governed_approval_replay_source_seal (singleton INTEGER)",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("approval.db");
        let store = SqliteGovernedApprovalReplayStore::open(&path)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(sql)?;
        assert!(store.preview_legacy_replay_source(&binding()?).is_err());
        if schema::has_evidence(&connection)? {
            assert!(reserve(&store, "new").is_err());
            assert!(SqliteGovernedApprovalReplayStore::open(&path).is_err());
        }
    }
    Ok(())
}

#[test]
fn copied_file_is_not_the_sealed_source_and_aliases_are_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approval.db");
    let store = SqliteGovernedApprovalReplayStore::open(&path)?;
    assert!(reserve(&store, "reserved")?);
    let expected = store.preview_legacy_replay_source(&binding()?)?;
    store.seal_expected_legacy_replay_source(&expected)?;
    drop(store);
    let copy = directory.path().join("copy.db");
    std::fs::copy(&path, &copy)?;
    assert!(SqliteGovernedApprovalReplayStore::open(&copy).is_err());
    let symbolic = directory.path().join("symbolic.db");
    std::os::unix::fs::symlink(&path, &symbolic)?;
    assert!(SqliteGovernedApprovalReplayStore::open(&symbolic).is_err());
    let hard = directory.path().join("hard.db");
    std::fs::hard_link(&path, &hard)?;
    assert!(SqliteGovernedApprovalReplayStore::open(&hard).is_err());
    assert!(SqliteGovernedApprovalReplayStore::open(&path).is_err());
    Ok(())
}

#[test]
fn changed_journal_mode_is_refused_without_startup_normalization() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approval.db");
    let store = SqliteGovernedApprovalReplayStore::open(&path)?;
    let expected = store.preview_legacy_replay_source(&binding()?)?;
    store.seal_expected_legacy_replay_source(&expected)?;
    drop(store);
    let connection = Connection::open(&path)?;
    connection.pragma_update(None, "journal_mode", "DELETE")?;
    assert!(SqliteGovernedApprovalReplayStore::open(&path).is_err());
    let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    assert_eq!(journal, "delete");
    Ok(())
}

#[test]
fn path_replacement_and_memory_sources_cannot_be_sealed() -> TestResult {
    let memory = SqliteGovernedApprovalReplayStore::open_in_memory()?;
    assert!(memory.preview_legacy_replay_source(&binding()?).is_err());
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approval.db");
    let store = SqliteGovernedApprovalReplayStore::open(&path)?;
    let expected = store.preview_legacy_replay_source(&binding()?)?;
    std::fs::rename(&path, directory.path().join("moved.db"))?;
    std::fs::File::create(&path)?;
    assert!(store.preview_legacy_replay_source(&binding()?).is_err());
    assert!(store.seal_expected_legacy_replay_source(&expected).is_err());
    Ok(())
}
