use super::*;

#[test]
fn local_rows_and_global_references_are_verified_without_external_write_detection(
) -> AnchoredTestResult {
    for (trigger, mutation) in [
        ("dpop_replay_migration_expectations_immutable", "UPDATE dpop_replay_migration_expectations SET canonical_source = CAST('{}' AS BLOB)"),
        ("dpop_replay_migration_expectations_immutable", "UPDATE dpop_replay_migration_expectations SET source_instance_id = 'replacement'"),
        ("dpop_replay_migration_events_immutable", "UPDATE dpop_replay_migration_events SET observed_at_unix_ms = observed_at_unix_ms + 1"),
        ("dpop_replay_legacy_tombstones_immutable", "UPDATE dpop_replay_legacy_tombstones SET canonical_marker = CAST('{}' AS BLOB) WHERE nonce = 'local'"),
        ("dpop_replay_legacy_tombstones_immutable", "UPDATE dpop_replay_legacy_tombstones SET source_instance_id = 'replacement'"),
        ("dpop_replay_legacy_tombstones_no_delete", "DELETE FROM dpop_replay_legacy_tombstones WHERE nonce = 'signed'"),
        ("authority_global_commits_no_delete", "DELETE FROM authority_global_commits WHERE projection_kind = 'dpop_replay_migration'"),
        ("authority_global_commits_immutable", "UPDATE authority_global_commits SET projection_reference_digest = printf('%064d', 0) WHERE projection_kind = 'dpop_replay_migration'"),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let expected = pin(&fixture, &source)?;
        import(&fixture, &source, &expected)?;
        {
            let connection = fixture.store.connection()?;
            let ddl: String = connection.query_row("SELECT sql FROM sqlite_schema WHERE name = ?1", [trigger], |row| row.get(0))?;
            connection.execute_batch(&format!("DROP TRIGGER {trigger}; {mutation}; {ddl};"))?;
            assert!(crate::admission_operation_store::verify_dpop_replay_projection_coverage(&connection).is_err(), "{mutation}");
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
fn immutable_guards_reject_replace_update_and_delete() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    import(&fixture, &source, &pin(&fixture, &source)?)?;
    let connection = fixture.store.connection()?;
    connection.execute_batch("PRAGMA recursive_triggers = OFF")?;
    for table in TABLES {
        for sql in [
            format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
            format!("UPDATE {table} SET dpop_authority_id = dpop_authority_id"),
            format!("DELETE FROM {table}"),
        ] {
            assert!(connection.execute(&sql, []).is_err(), "{sql}");
        }
    }
    crate::admission_operation_store::verify_dpop_replay_projection_coverage(&connection)?;
    Ok(())
}

#[test]
fn oversized_and_wrong_storage_types_refuse_before_canonical_decode() -> AnchoredTestResult {
    for (table, column, value) in [
        (
            "dpop_replay_migration_expectations",
            "canonical_source",
            "zeroblob(16777217)",
        ),
        (
            "dpop_replay_migration_expectations",
            "canonical_source",
            "'{}'",
        ),
        (
            "dpop_replay_legacy_tombstones",
            "canonical_marker",
            "zeroblob(131073)",
        ),
        (
            "dpop_replay_legacy_tombstones",
            "nonce",
            "CAST(zeroblob(4097) AS TEXT)",
        ),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        import(&fixture, &source, &pin(&fixture, &source)?)?;
        let connection = fixture.store.connection()?;
        let trigger = format!("{table}_immutable");
        let ddl: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE name = ?1",
            [&trigger],
            |row| row.get(0),
        )?;
        let predicate = if column == "nonce" {
            " WHERE nonce = 'local'"
        } else {
            ""
        };
        connection.execute_batch(&format!("PRAGMA ignore_check_constraints = ON; DROP TRIGGER {trigger}; UPDATE {table} SET {column} = {value}{predicate}; {ddl}; PRAGMA ignore_check_constraints = OFF;"))?;
        let error =
            crate::admission_operation_store::verify_dpop_replay_projection_coverage(&connection)
                .expect_err("invalid storage")
                .to_string();
        assert!(error.contains("invalid storage types or sizes"), "{error}");
    }
    Ok(())
}

#[test]
fn current_schema_damage_is_not_repaired_on_reopen() -> AnchoredTestResult {
    for sql in [
        "DROP TRIGGER dpop_replay_migration_expectations_immutable",
        "DROP TABLE dpop_replay_legacy_tombstones",
        "CREATE TABLE dpop_replay_unqualified(value TEXT)",
    ] {
        let fixture = fixture();
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
        let connection = Connection::open(&database)?;
        connection.execute_batch(sql)?;
        let before: i64 =
            connection.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| row.get(0))?;
        assert!(
            SqliteAuthorityStore::open_serving(&database, &lock_root).is_err(),
            "{sql}"
        );
        assert!(
            SqliteAuthorityStore::provision(&database, &lock_root).is_err(),
            "{sql}"
        );
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| row
                .get::<_, i64>(0))?,
            before
        );
    }
    Ok(())
}

#[test]
fn aggregate_expectation_limits_are_checked_before_decoding_any_source() -> AnchoredTestResult {
    // Deliberately undecodable data exercises the early storage bound, not a
    // qualified source profile. No source is sealed by this negative fixture.
    for (rows, bytes) in [(129, 1), (5, 16 * 1024 * 1024)] {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch("PRAGMA foreign_keys = OFF")?;
        connection.execute_batch(crate::admission_operation_store::DPOP_REPLAY_MIGRATION_SCHEMA)?;
        for index in 0..rows {
            connection.execute("INSERT INTO dpop_replay_migration_expectations VALUES (?1, ?1, ?1, 'destination', zeroblob(?2), printf('%064d', 0), printf('%064d', 0))", params![format!("authority-{index}"), bytes])?;
        }
        let error =
            crate::admission_operation_store::verify_dpop_replay_projection_coverage(&connection)
                .expect_err("aggregate bound")
                .to_string();
        assert!(
            error.contains("expectation aggregate limit exceeded"),
            "{error}"
        );
    }
    Ok(())
}
