use super::*;

#[test]
fn current_schema_with_missing_migration_barrier_is_not_repaired() -> AnchoredTestResult {
    let fixture = fixture();
    let Closed {
        _temp,
        database,
        lock_root,
        fence: _fence,
        _clock,
    } = fixture.close();
    let connection = Connection::open(&database)?;
    connection.execute_batch("DROP TRIGGER security_participant_migration_rows_no_replace")?;
    assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
    assert!(SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &lock_root,
        chio_test_support::clock::clock()
    )
    .is_err());
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name = 'security_participant_migration_rows_no_replace'", [], |row| row.get::<_, i64>(0))?, 0);
    Ok(())
}
