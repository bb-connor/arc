use super::*;

fn assert_barrier_error(result: rusqlite::Result<usize>, sql: &str) {
    match result {
        Err(rusqlite::Error::SqliteFailure(error, Some(message))) => {
            assert_eq!(
                error.code,
                rusqlite::ErrorCode::ConstraintViolation,
                "{sql}"
            );
            assert_eq!(
                error.extended_code,
                rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER,
                "{sql}"
            );
            assert!(
                message.contains("runtime replay source is sealed"),
                "{sql}: {message}"
            );
        }
        other => panic!("sealed legacy mutation must abort through its barrier: {sql}: {other:?}"),
    }
}

fn mutation_sql() -> Vec<String> {
    let mut statements = Vec::new();
    for (table, key, _) in TABLES {
        for (verb, resource) in [
            ("INSERT", "new-resource"),
            ("INSERT OR IGNORE", "new-resource"),
            ("INSERT OR IGNORE", "resource-a"),
            ("INSERT OR REPLACE", "resource-a"),
            ("REPLACE", "resource-a"),
        ] {
            statements.push(format!(
                "{verb} INTO {table} ({key}, admission_id) VALUES ('{resource}', 'replacement-admission')"
            ));
        }
        for verb in ["UPDATE", "UPDATE OR IGNORE", "UPDATE OR REPLACE"] {
            statements.push(format!(
                "{verb} {table} SET admission_id = 'replacement-admission' WHERE {key} = 'resource-a'"
            ));
        }
        statements.push(format!("DELETE FROM {table} WHERE {key} = 'resource-a'"));
    }
    statements
}

#[test]
fn preopened_raw_connections_and_prepared_statements_cannot_mutate_any_replay_table() -> TestResult
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("prepared-legacy-writers.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    seed_inventory(&store)?;
    let prepared_connection = Connection::open(&path)?;
    let direct_connection = Connection::open(&path)?;
    let sql = mutation_sql();
    let mut prepared = sql
        .iter()
        .map(|sql| prepared_connection.prepare(sql))
        .collect::<Result<Vec<_>, _>>()?;
    let seal = store.seal_legacy_replay_source(&binding()?)?;
    let before = raw_snapshot(&direct_connection)?;
    for (statement, sql) in prepared.iter_mut().zip(&sql) {
        assert_barrier_error(statement.execute([]), sql);
        assert_barrier_error(direct_connection.execute(sql, []), sql);
        assert_eq!(raw_snapshot(&direct_connection)?, before);
    }
    assert_inventory(&seal);
    store.verify_legacy_replay_source_seal(&seal)?;
    Ok(())
}

#[test]
fn preopened_typed_legacy_handle_cannot_consume_or_release_after_seal() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("typed-legacy-writer.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let legacy = SqliteRuntimeOrchestrationStore::open(&path)?;
    seed_inventory(&legacy)?;
    let seal = store.seal_legacy_replay_source(&binding()?)?;
    let raw = Connection::open(&path)?;
    let before = raw_snapshot(&raw)?;
    for result in [
        legacy.consume_destructive_lease("new-lease", "new-admission"),
        legacy.consume_destructive_lease("resource-a", "admission-lease"),
        legacy.release_destructive_lease("resource-a", "admission-lease"),
        legacy.consume_treaty_continuation("new-treaty", "new-admission"),
        legacy.consume_treaty_continuation("resource-a", "admission-treaty"),
        legacy.release_treaty_continuation("resource-a", "admission-treaty"),
        legacy.consume_swarm_continuation("new-swarm", "new-admission"),
        legacy.consume_swarm_continuation("resource-a", "admission-swarm"),
        legacy.release_swarm_continuation("resource-a", "admission-swarm"),
    ] {
        assert_code(result, "runtime_replay_source_sealed");
    }
    assert_eq!(raw_snapshot(&raw)?, before);
    legacy.verify_legacy_replay_source_seal(&seal)?;
    Ok(())
}

#[test]
fn singleton_seal_rejects_direct_insert_replace_update_and_delete() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("immutable-seal.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let raw = Connection::open(&path)?;
    let seal = store.seal_legacy_replay_source(&binding()?)?;
    let before = raw_snapshot(&raw)?;
    for sql in [
        "INSERT INTO runtime_replay_source_seal(singleton, canonical_bytes) VALUES(1, X'00')",
        "INSERT OR IGNORE INTO runtime_replay_source_seal(singleton, canonical_bytes) VALUES(1, X'00')",
        "INSERT OR REPLACE INTO runtime_replay_source_seal(singleton, canonical_bytes) VALUES(1, X'00')",
        "UPDATE runtime_replay_source_seal SET canonical_bytes = X'00' WHERE singleton = 1",
        "DELETE FROM runtime_replay_source_seal WHERE singleton = 1",
    ] {
        assert_barrier_error(raw.execute(sql, []), sql);
        assert_eq!(raw_snapshot(&raw)?, before);
    }
    store.verify_legacy_replay_source_seal(&seal)?;
    Ok(())
}

#[test]
fn stale_wal_reader_cannot_upgrade_to_a_legacy_writer_after_seal() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("stale-wal.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    seed_inventory(&store)?;
    let stale = Connection::open(&path)?;
    stale.execute_batch("BEGIN DEFERRED")?;
    assert_eq!(
        stale.query_row("SELECT COUNT(*) FROM runtime_consumed_leases", [], |row| {
            row.get::<_, i64>(0)
        })?,
        2
    );
    let seal = store.seal_legacy_replay_source(&binding()?)?;
    for (table, key, _) in TABLES {
        let sql = format!(
            "INSERT INTO {table}({key}, admission_id) VALUES ('stale-write', 'stale-owner')"
        );
        let error = stale
            .execute(&sql, [])
            .err()
            .ok_or("stale WAL writer unexpectedly committed")?;
        match error {
            rusqlite::Error::SqliteFailure(error, _) => assert!(
                matches!(
                    error.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::ConstraintViolation
                ),
                "unexpected stale snapshot failure: {error:?}"
            ),
            other => return Err(other.into()),
        }
    }
    stale.execute_batch("ROLLBACK")?;
    for (table, key, _) in TABLES {
        let sql = format!(
            "INSERT INTO {table}({key}, admission_id) VALUES ('fresh-write', 'fresh-owner')"
        );
        assert_barrier_error(stale.execute(&sql, []), &sql);
    }
    store.verify_legacy_replay_source_seal(&seal)?;
    assert_inventory(&seal);
    Ok(())
}

#[test]
fn concurrent_seal_includes_a_legacy_writer_committed_under_an_existing_write_lock() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("competing-writer.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let raw = Connection::open(&path)?;
    raw.execute_batch("BEGIN IMMEDIATE")?;
    raw.execute(
        "INSERT INTO runtime_consumed_leases(lease_id, admission_id) VALUES (?1, ?2)",
        params!["already-in-flight", "legacy-writer"],
    )?;
    let binding = binding()?;
    let start = std::sync::Barrier::new(2);
    let seal = std::thread::scope(|scope| -> TestResult<RuntimeReplaySourceSeal> {
        let worker = scope.spawn(|| {
            start.wait();
            store.seal_legacy_replay_source(&binding)
        });
        start.wait();
        raw.execute_batch("COMMIT")?;
        Ok(worker.join().map_err(|_| "seal worker panicked")??)
    })?;
    assert_eq!(seal.markers().len(), 1);
    let marker = seal
        .markers()
        .first()
        .ok_or("committed legacy marker omitted")?;
    assert_eq!(marker.kind(), RuntimeReplayMarkerKind::DestructiveLease);
    assert_eq!(marker.resource_id(), "already-in-flight");
    assert_eq!(marker.admission_id(), "legacy-writer");
    store.verify_legacy_replay_source_seal(&seal)?;
    Ok(())
}
