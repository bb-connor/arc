use super::*;

#[test]
fn byte_corruption_and_missing_global_references_fail_without_external_write_detection(
) -> AnchoredTestResult {
    for (trigger, mutation) in [
        ("security_participant_migration_rows_immutable", "UPDATE security_participant_migration_rows SET canonical_row = CAST('[]' AS BLOB) WHERE table_name = 'security_declassification_tombstones'"),
        ("security_participant_migration_rows_no_delete", "DELETE FROM security_participant_migration_rows WHERE table_name = 'security_declassification_uses'"),
        ("security_participant_migration_rows_immutable", "UPDATE security_participant_migration_rows SET row_index = row_index + 100"),
        ("security_participant_migration_rows_immutable", "UPDATE security_participant_migration_rows SET table_name = 'unknown' WHERE table_name = 'security_declassification_tombstones'"),
        ("security_participant_migration_expectations_immutable", "UPDATE security_participant_migration_expectations SET source_inode = '0'"),
        ("security_participant_migration_expectations_immutable", "UPDATE security_participant_migration_expectations SET canonical_source = CAST('{}' AS BLOB)"),
        ("security_participant_migration_events_immutable", "UPDATE security_participant_migration_events SET observed_at_unix_ms = observed_at_unix_ms + 1"),
        ("authority_global_commits_no_delete", "DELETE FROM authority_global_commits WHERE projection_kind = 'security_participant_migration'"),
        ("authority_global_commits_immutable", "UPDATE authority_global_commits SET projection_reference_digest = printf('%064d', 0) WHERE projection_kind = 'security_participant_migration'"),
    ] {
        let fixture = fixture();
        let source = source(&fixture)?;
        let expected = pin(&fixture, &source)?;
        import(&fixture, &source, &expected)?;
        {
            let connection = fixture.store.connection()?;
            let ddl: String = connection.query_row("SELECT sql FROM sqlite_schema WHERE name = ?1", [trigger], |row| row.get(0))?;
            connection.execute_batch(&format!("DROP TRIGGER {trigger}; {mutation}; {ddl};"))?;
            assert!(verify_security_participant_migration_coverage(&connection).is_err(), "{mutation}");
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
fn immutable_history_rejects_replace_ignore_and_late_row_insertion() -> AnchoredTestResult {
    let fixture = fixture();
    let source = source(&fixture)?;
    let expected = pin(&fixture, &source)?;
    let imported = import(&fixture, &source, &expected)?;
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch("PRAGMA recursive_triggers = OFF")?;
        for table in [
            "security_participant_migration_expectations",
            "security_participant_migration_events",
            "security_participant_migration_rows",
        ] {
            for sql in [
                format!("UPDATE {table} SET security_authority_id = security_authority_id"),
                format!("DELETE FROM {table}"),
                format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
                format!("INSERT OR IGNORE INTO {table} SELECT * FROM {table}"),
            ] {
                assert!(connection.execute_batch(&sql).is_err(), "{sql}");
            }
        }
        assert!(connection.execute_batch("INSERT INTO security_participant_migration_rows VALUES ('security-authority', 'future', 0, X'5b5d')").is_err());
        verify_security_participant_migration_coverage(&connection)?;
    }
    assert_eq!(load(&fixture)?, Some(imported));
    Ok(())
}

#[test]
fn archived_rows_do_not_allow_repairing_a_damaged_source_seal() -> AnchoredTestResult {
    let fixture = fixture();
    let source = source(&fixture)?;
    let expected = pin(&fixture, &source)?;
    let imported = import(&fixture, &source, &expected)?;
    let connection = Connection::open(fixture._temp.path().join("security-source.db"))?;
    let trigger: String = connection.query_row(
        "SELECT name FROM sqlite_schema WHERE type = 'trigger'
        AND name GLOB '*security_participant_source*' ORDER BY name LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch(&format!("DROP TRIGGER {trigger}"))?;
    let before = global_count(&fixture)?;
    assert!(import(&fixture, &source, &expected).is_err());
    assert_eq!(load(&fixture)?, Some(imported));
    assert_eq!(global_count(&fixture)?, before);
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name = ?1",
            [trigger],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
}

#[test]
fn pending_pin_budget_is_reserved_before_any_source_is_retired() -> AnchoredTestResult {
    let fixture = fixture();
    for index in 0..16 {
        let path = fixture._temp.path().join(format!("source-{index}.db"));
        drop(crate::SqliteSecurityStateStore::open(&path)?);
        let source = SqliteSecurityParticipantSource::open(&path)?;
        fixture.store.expect_security_participant_source(
            &identifier("source_id", &format!("source-{index}")),
            &identifier("security_authority_id", &format!("authority-{index}")),
            &source,
            &fixture.fence,
            now_ms(),
        )?;
        assert!(source.load_seal()?.is_none());
    }
    let source = source(&fixture)?;
    let before = global_count(&fixture)?;
    assert!(pin(&fixture, &source).is_err());
    assert!(source.load_seal()?.is_none());
    assert_eq!(global_count(&fixture)?, before);
    assert!(load(&fixture)?.is_none());
    Ok(())
}

#[test]
fn restoring_destination_before_import_is_rejected_by_independent_anchor() -> AnchoredTestResult {
    let fixture = fixture();
    let source = source(&fixture)?;
    let expected = pin(&fixture, &source)?;
    let backup = fixture._temp.path().join("before-import.db");
    fixture.store.connection()?.execute(
        "VACUUM INTO ?1",
        [backup.to_str().ok_or("non-UTF8 fixture path")?],
    )?;
    import(&fixture, &source, &expected)?;
    drop(source);
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    // Replace only this private test database; its separately committed anchor
    // remains at the acknowledged import, as after a stale database restore.
    fs::copy(&backup, &database)?;
    assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
    Ok(())
}
