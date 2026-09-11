use super::*;

#[derive(Clone, Copy)]
enum FixtureJournalMode {
    Delete,
    Wal,
}

/// Pool initialization workers can briefly retain their connection after the
/// public pool handle is dropped. Establish the fixture's actual journal mode
/// before testing the opener, without retrying the opener or any policy check.
fn establish_fixture_journal_mode(
    connection: &Connection,
    mode: FixtureJournalMode,
    timeout: std::time::Duration,
) -> AnchoredTestResult {
    let (statement, expected) = match mode {
        FixtureJournalMode::Delete => ("PRAGMA journal_mode = DELETE", "delete"),
        FixtureJournalMode::Wal => ("PRAGMA journal_mode = WAL", "wal"),
    };
    let started = std::time::Instant::now();
    loop {
        match connection.query_row(statement, [], |row| row.get::<_, String>(0)) {
            Ok(actual) if actual == expected => return Ok(()),
            Ok(actual) => {
                return Err(format!("journal fixture requested {expected}, got {actual}").into())
            }
            Err(error)
                if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy)
                    && started.elapsed() < timeout =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(error) => {
                return Err(format!("establish {expected} journal fixture: {error}").into())
            }
        }
    }
}

fn locked_journal_fixture() -> AnchoredTestResult<(tempfile::TempDir, Connection, Connection)> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal-fixture.db");
    let connection = Connection::open(&path)?;
    connection.execute_batch("PRAGMA journal_mode = WAL; CREATE TABLE probe(value INTEGER);")?;
    connection.busy_timeout(std::time::Duration::from_millis(5))?;
    let blocker = Connection::open(&path)?;
    blocker.execute_batch("BEGIN; SELECT * FROM probe;")?;
    Ok((directory, connection, blocker))
}

#[test]
fn journal_fixture_waits_for_connection_quiescence() -> AnchoredTestResult {
    let (_directory, connection, blocker) = locked_journal_fixture()?;
    std::thread::scope(|scope| {
        scope.spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(25));
            drop(blocker);
        });
        establish_fixture_journal_mode(
            &connection,
            FixtureJournalMode::Delete,
            std::time::Duration::from_secs(2),
        )
    })?;
    let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    assert_eq!(mode, "delete");
    Ok(())
}

#[test]
fn journal_fixture_never_accepts_a_permanently_busy_source() -> AnchoredTestResult {
    let (_directory, connection, _blocker) = locked_journal_fixture()?;
    assert!(establish_fixture_journal_mode(
        &connection,
        FixtureJournalMode::Delete,
        std::time::Duration::from_millis(20)
    )
    .is_err());
    let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    assert_eq!(mode, "wal");
    Ok(())
}

#[test]
fn local_rows_and_global_references_are_verified_without_relying_on_external_write_detection(
) -> AnchoredTestResult {
    for (trigger, mutation) in [
        ("governed_approval_replay_migration_expectations_immutable", "UPDATE governed_approval_replay_migration_expectations SET canonical_source = CAST('{}' AS BLOB)"),
        ("governed_approval_replay_migration_events_immutable", "UPDATE governed_approval_replay_migration_events SET observed_at_unix_ms = observed_at_unix_ms + 1"),
        ("governed_approval_replay_legacy_tombstones_immutable", "UPDATE governed_approval_replay_legacy_tombstones SET historical_reservation_id = NULL WHERE request_id = 'reserved'"),
        ("governed_approval_replay_legacy_tombstones_immutable", "UPDATE governed_approval_replay_legacy_tombstones SET subject_id = 'not-wildcard' WHERE request_id = 'wildcard'"),
        ("governed_approval_replay_legacy_tombstones_immutable", "UPDATE governed_approval_replay_legacy_tombstones SET expires_at = expires_at + 1"),
        ("governed_approval_replay_legacy_tombstones_no_delete", "DELETE FROM governed_approval_replay_legacy_tombstones WHERE request_id = 'committed'"),
        ("authority_global_commits_no_delete", "DELETE FROM authority_global_commits WHERE projection_kind = 'governed_approval_replay_migration'"),
        ("authority_global_commits_immutable", "UPDATE authority_global_commits SET projection_reference_digest = printf('%064d', 0) WHERE projection_kind = 'governed_approval_replay_migration'"),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let expected = pin(&fixture, &source)?;
        import(&fixture, &source, &expected)?;
        {
            let connection = fixture.store.connection()?;
            let ddl: String = connection.query_row("SELECT sql FROM sqlite_schema WHERE name = ?1", [trigger], |row| row.get(0))?;
            connection.execute_batch(&format!("DROP TRIGGER {trigger}; {mutation}; {ddl};"))?;
            assert!(crate::admission_operation_store::verify_governed_approval_replay_projection_coverage(&connection).is_err(), "{mutation}");
        }
        assert!(load(&fixture).is_err(), "{mutation}");
        assert!(import(&fixture, &source, &expected).is_err(), "{mutation}");
        drop(source);
        let Fixture { _temp, database, lock_root, authority, store, .. } = fixture;
        drop(store);
        drop(authority);
        assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err(), "{mutation}");
    }
    Ok(())
}

#[test]
fn sealed_sources_cannot_be_discovered_or_repaired_after_import() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let expected = pin(&fixture, &source)?;
    import(&fixture, &source, &expected)?;
    assert!(source
        .raw
        .preview_unsealed(expected.snapshot().binding())
        .is_err());
    let connection = Connection::open(&source.path)?;
    let barrier: String = connection.query_row("SELECT name FROM sqlite_schema WHERE type = 'trigger' AND tbl_name = 'chio_governed_approval_replay_entries' ORDER BY name LIMIT 1", [], |row| row.get(0))?;
    connection.execute_batch(&format!("DROP TRIGGER {barrier}"))?;
    let before = global_count(&fixture);
    let calls = source.calls().len();
    assert!(import(&fixture, &source, &expected).is_err());
    assert_eq!(&source.calls()[calls..], ["verify"]);
    assert_eq!(global_count(&fixture), before);
    assert!(SqliteGovernedApprovalReplaySource::open(&source.path).is_err());
    let remains_missing: bool = connection.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = ?1)",
        [barrier],
        |row| row.get(0),
    )?;
    assert!(remains_missing);
    Ok(())
}

#[test]
fn destination_immutable_guards_reject_replace_update_and_delete() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let expected = pin(&fixture, &source)?;
    import(&fixture, &source, &expected)?;
    let connection = fixture.store.connection()?;
    connection.execute_batch("PRAGMA recursive_triggers = OFF")?;
    for table in TABLES {
        for sql in [
            format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
            format!("UPDATE {table} SET approval_authority_id = approval_authority_id"),
            format!("DELETE FROM {table}"),
        ] {
            assert!(connection.execute(&sql, []).is_err(), "{sql}");
        }
    }
    crate::admission_operation_store::verify_governed_approval_replay_projection_coverage(
        &connection,
    )?;
    Ok(())
}

#[test]
fn migration_opener_does_not_create_or_repair_sources() -> AnchoredTestResult {
    let fixture = fixture();
    let absent = fixture._temp.path().join("absent.db");
    assert!(SqliteGovernedApprovalReplaySource::open(&absent).is_err());
    assert!(!absent.exists());
    let source = Source::new(&fixture, false)
        .map_err(|error| format!("prepare migration fixture source: {error}"))?;
    let path = source.path.clone();
    drop(source);
    let connection = Connection::open(&path)
        .map_err(|error| format!("open migration fixture mutator: {error}"))?;
    connection.busy_timeout(std::time::Duration::from_millis(5))?;
    establish_fixture_journal_mode(
        &connection,
        FixtureJournalMode::Delete,
        std::time::Duration::from_secs(5),
    )?;
    assert!(SqliteGovernedApprovalReplaySource::open(&path).is_err());
    let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    assert_eq!(mode, "delete");
    establish_fixture_journal_mode(
        &connection,
        FixtureJournalMode::Wal,
        std::time::Duration::from_secs(5),
    )?;
    connection
        .execute_batch("DROP TABLE chio_governed_approval_replay_limits;")
        .map_err(|error| format!("establish missing-schema fixture: {error}"))?;
    assert!(SqliteGovernedApprovalReplaySource::open(&path).is_err());
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name = 'chio_governed_approval_replay_limits'", [], |row| row.get::<_, i64>(0))?, 0);
    Ok(())
}

#[test]
fn ordinary_sealed_reopen_must_not_repair_a_cleared_application_identity() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let expected = pin(&fixture, &source)?;
    import(&fixture, &source, &expected)?;
    let connection = Connection::open(&source.path)?;
    connection.execute_batch("PRAGMA application_id = 0")?;
    assert!(SqliteGovernedApprovalReplayStore::open(&source.path).is_err());
    assert_eq!(
        connection.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?,
        0
    );
    assert!(source.raw.verify_exact(expected.snapshot()).is_err());
    Ok(())
}

#[test]
fn source_inspection_rejects_damaged_metadata_without_adopting_or_stamping_it() -> AnchoredTestResult
{
    for mutation in ["PRAGMA application_id = 0", "UPDATE chio_store_schema_versions SET version = 0 WHERE store_key = 'governed_approval_replay'",
        "DROP TABLE chio_store_schema_versions; CREATE TABLE chio_store_schema_versions(store_key TEXT, version INTEGER); INSERT INTO chio_store_schema_versions VALUES ('governed_approval_replay', 1), ('governed_approval_replay', 0)"] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let path = source.path.clone();
        let connection = Connection::open(&path)?;
        connection.execute_batch(mutation)?;
        let app_id: i32 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        assert!(pin(&fixture, &source).is_err());
        assert!(SqliteGovernedApprovalReplaySource::open(&path).is_err());
        assert_eq!(connection.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0))?, app_id);
        assert_eq!(counts(&fixture), [0, 0, 0]);
    }
    Ok(())
}
