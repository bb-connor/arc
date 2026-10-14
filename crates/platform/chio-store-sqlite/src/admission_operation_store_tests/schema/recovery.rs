//! An exact predecessor catalog and a populated, byte-preserving native recovery upgrade.
use super::*;

/// Disposable predecessor construction must never erase recovery custody or
/// an authenticated global reference. Production migrations do not use this.
pub(super) fn remove_empty_recovery_tables(connection: &Connection) -> rusqlite::Result<()> {
    for table in [
        "admission_operation_recovery_events",
        "admission_operation_recovery_records",
    ] {
        assert_eq!(
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get::<_, i64>(0)
            })?,
            0,
            "predecessor fixture cannot discard recovery history"
        );
    }
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = 'recovery'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        0,
        "predecessor fixture cannot discard global recovery references"
    );
    let indexed: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table'
         AND name = 'security_participant_state_imported_scope_index')",
        [],
        |row| row.get(0),
    )?;
    if indexed {
        remove_empty_imported_scope_index(connection)?;
    }
    connection.execute_batch(
        "DROP TABLE admission_operation_recovery_events;
         DROP TABLE admission_operation_recovery_records;",
    )
}

/// The native v29 catalog is the current catalog without this table. It may be
/// removed alone only while it holds no row.
pub(in crate::admission_operation_store::tests) fn remove_empty_imported_scope_index(
    connection: &Connection,
) -> rusqlite::Result<()> {
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM security_participant_state_imported_scope_index",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        0,
        "predecessor fixture cannot discard an imported scope index"
    );
    connection.execute_batch("DROP TABLE security_participant_state_imported_scope_index")
}

fn rows(connection: &Connection, table: &str) -> AnchoredTestResult<Vec<Vec<Value>>> {
    assert!(matches!(
        table,
        "admission_operations" | "admission_operation_commits" | "authority_global_commits"
    ));
    let mut statement = connection.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
    let columns = statement.column_count();
    let rows = statement
        .query_map([], |row| {
            (0..columns)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[test]
fn recovery_populated_v34_upgrade_preserves_original_operations_and_global_chain(
) -> AnchoredTestResult {
    let f = pre_recovery_fixture();
    let operation = prepared_operation(
        &f.fence,
        AdmissionOperationKind::ToolDispatch,
        "predecessor-operation",
        "predecessor-capability",
    );
    f.store.begin(&operation, &f.fence, now_ms())?;
    let _lease = claim(&f, &operation, "predecessor-owner", now_ms());
    let before = {
        let db = f.store.connection()?;
        [
            rows(&db, "admission_operations")?,
            rows(&db, "admission_operation_commits")?,
            rows(&db, "authority_global_commits")?,
        ]
    };
    let Fixture {
        _temp,
        database,
        lock_root,
        store,
        authority,
        ..
    } = f;
    drop(store);
    drop(authority);
    install_v34_fixture(&database)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let db = Connection::open(&database)?;
    for (index, table) in [
        "admission_operations",
        "admission_operation_commits",
        "authority_global_commits",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            before[index],
            rows(&db, table)?,
            "rewrote predecessor: {table}"
        );
    }
    assert!(matches!(
        crate::check_schema_version(&db, "admission_operation", 34, &["admission_operations"]),
        Err(crate::SchemaVersionError::FutureSchema {
            found: crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
            supported: 34
        })
    ));
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    assert!(!db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    drop(db);
    let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    assert_eq!(
        reopened
            .admission_operation_store()
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    Ok(())
}

fn install_v34_fixture(database: &std::path::Path) -> AnchoredTestResult {
    let db = Connection::open(database)?;
    let tx = db.unchecked_transaction()?;
    remove_empty_recovery_tables(&tx)?;
    tx.execute_batch(
        "DROP TRIGGER authority_global_commits_immutable;
        DROP TRIGGER authority_global_commits_no_delete;
        DROP INDEX authority_global_commits_projection;
        ALTER TABLE authority_global_commits RENAME TO global_upgrade_fixture;",
    )?;
    tx.execute_batch(include_str!("../fixtures/recovery-v34-global.sql"))?;
    tx.execute_batch(
        "INSERT INTO authority_global_commits SELECT * FROM global_upgrade_fixture;
        DROP TABLE global_upgrade_fixture;
        UPDATE chio_store_schema_versions SET version=34 WHERE store_key='admission_operation';",
    )?;
    tx.commit()?;
    Ok(())
}

#[test]
#[ignore = "only the fresh-process migration parent starts this child"]
fn recovery_migration_crash_child() -> AnchoredTestResult {
    let database =
        std::env::var_os("CHIO_RECOVERY_CRASH_MIGRATION_DATABASE").ok_or("migration database")?;
    let locks = std::env::var_os("CHIO_RECOVERY_CRASH_MIGRATION_LOCKS").ok_or("migration locks")?;
    SqliteAuthorityStore::provision(PathBuf::from(database), PathBuf::from(locks))?;
    Err("migration child did not reach its cutpoint".into())
}

#[cfg(unix)]
#[test]
fn recovery_os_death_before_upgrade_commit_is_restartable_and_byte_preserving() -> AnchoredTestResult
{
    use std::os::unix::process::ExitStatusExt;
    use std::time::{Duration, Instant};
    let f = pre_recovery_fixture();
    let operation = prepared_operation(
        &f.fence,
        AdmissionOperationKind::ToolDispatch,
        "interrupted-migration",
        "interrupted-capability",
    );
    f.store.begin(&operation, &f.fence, now_ms())?;
    let Fixture {
        _temp,
        database,
        lock_root,
        store,
        authority,
        ..
    } = f;
    drop(store);
    drop(authority);
    install_v34_fixture(&database)?;
    let db = Connection::open(&database)?;
    let before = [
        rows(&db, "admission_operations")?,
        rows(&db, "admission_operation_commits")?,
        rows(&db, "authority_global_commits")?,
    ];
    drop(db);
    let marker = _temp.path().join("migration-cutpoint");
    let log = std::fs::File::create(_temp.path().join("migration-child.log"))?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "admission_operation_store::tests::schema::recovery::recovery_migration_crash_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("CHIO_RECOVERY_CRASH_MIGRATION_DATABASE", &database)
        .env("CHIO_RECOVERY_CRASH_MIGRATION_LOCKS", &lock_root)
        .env("CHIO_RECOVERY_MIGRATION_MARKER", &marker)
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(60) {
            child.kill()?;
            child.wait()?;
            return Err("migration child exceeded its bound".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.signal(), Some(6));
    assert_eq!(std::fs::read(marker)?, b"verified-upgrade-before-commit");
    let db = Connection::open(&database)?;
    assert_eq!(
        db.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key='admission_operation'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        34
    );
    for (index, table) in [
        "admission_operations",
        "admission_operation_commits",
        "authority_global_commits",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            before[index],
            rows(&db, table)?,
            "crash rewrote predecessor: {table}"
        );
    }
    assert!(!db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='admission_operation_recovery_records')", [], |row| row.get::<_, bool>(0))?);
    drop(db);
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    assert_eq!(
        reopened
            .admission_operation_store()
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    Ok(())
}

#[test]
fn experimental_recovery_formats_are_refused_without_rewriting_native_history() -> AnchoredTestResult
{
    for version in 35..ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION {
        let f = fixture();
        let operation = prepared_operation(
            &f.fence,
            AdmissionOperationKind::ToolDispatch,
            "retained-original",
            "retained-capability",
        );
        f.store.begin(&operation, &f.fence, now_ms())?;
        let Fixture {
            _temp,
            database,
            lock_root,
            store,
            authority,
            ..
        } = f;
        drop(store);
        drop(authority);
        let db = Connection::open(&database)?;
        db.execute("UPDATE chio_store_schema_versions SET version=?1 WHERE store_key='admission_operation'", [version])?;
        let before = [
            rows(&db, "admission_operations")?,
            rows(&db, "admission_operation_commits")?,
            rows(&db, "authority_global_commits")?,
        ];
        drop(db);
        assert!(
            SqliteAuthorityStore::provision(&database, &lock_root).is_err(),
            "unsupported format {version}"
        );
        let db = Connection::open(&database)?;
        assert_eq!(db.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key='admission_operation'", [], |r| r.get::<_, i32>(0))?, version);
        for (i, table) in [
            "admission_operations",
            "admission_operation_commits",
            "authority_global_commits",
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                rows(&db, table)?,
                before[i],
                "refusal rewrote {table} in format {version}"
            );
        }
    }
    Ok(())
}
