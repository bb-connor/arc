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
    connection.execute_batch(
        "DROP TABLE admission_operation_recovery_events;
         DROP TABLE admission_operation_recovery_records;",
    )
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
    let f = fixture();
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
        ALTER TABLE authority_global_commits RENAME TO global_v35_fixture;",
    )?;
    tx.execute_batch(include_str!("../fixtures/recovery-v34-global.sql"))?;
    tx.execute_batch(
        "INSERT INTO authority_global_commits SELECT * FROM global_v35_fixture;
        DROP TABLE global_v35_fixture;
        UPDATE chio_store_schema_versions SET version=34 WHERE store_key='admission_operation';",
    )?;
    tx.commit()?;
    Ok(())
}

/// A modeled predecessor may remove the successor catalog only when no
/// successor custody or encoding has ever been published on this fixture.
fn remove_empty_captured_terminal_format(connection: &Connection) -> AnchoredTestResult {
    crate::admission_operation_store::schema::require_predecessor_knowledge_encoding_absence(
        connection,
    )?;
    let future: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records
         WHERE record_key GLOB 'captured-terminal:*' OR record_key GLOB 'captured-release:*'
           OR json_type(CAST(payload AS TEXT),'$.knowledge_join_encoding') IS NOT NULL
           OR json_type(CAST(payload AS TEXT),'$.checkpoint_restore_encoding') IS NOT NULL
           OR (record_key GLOB 'workflow-quota:*' AND (
             json_type(CAST(payload AS TEXT),'$.native_terminal') IS NOT NULL
             OR json_type(CAST(payload AS TEXT),'$.native_release') IS NOT NULL))
           OR (record_key GLOB 'recovery-workflow-allocation:*'
             AND json_type(CAST(payload AS TEXT),'$.retirement.captured_terminal') IS NOT NULL)
           OR (record_key GLOB 'command:*'
             AND json_type(CAST(payload AS TEXT),'$.reported_decision') IS NOT NULL))
         OR EXISTS(SELECT 1 FROM admission_operation_recovery_events
           WHERE record_key GLOB 'captured-terminal:*' OR record_key GLOB 'captured-release:*')
         OR EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind='recovery'
           AND (projection_key GLOB 'captured-terminal:*' OR projection_key GLOB 'captured-release:*'))",
        [],
        |row| row.get(0),
    )?;
    assert!(
        !future,
        "predecessor fixture cannot erase captured terminal or encoded history"
    );
    connection.execute_batch(
        "DROP TRIGGER admission_operation_recovery_terminal_shape_insert;
         DROP TRIGGER admission_operation_recovery_terminal_immutable;
         DROP TRIGGER admission_operation_recovery_terminal_quota_immutable;
         DROP TRIGGER admission_operation_recovery_terminal_workflow_immutable;
         DROP INDEX admission_operation_recovery_first_report;
         DROP TRIGGER admission_operation_recovery_codec_guard_insert;
         DROP TRIGGER admission_operation_recovery_codec_guard_update;
         DROP TRIGGER admission_operation_recovery_encoding_chunk_immutable;
         DROP INDEX idx_recovery_knowledge_journal_chunk_authority;
         DROP INDEX admission_operation_recovery_reference_capacity;",
    )?;
    Ok(())
}

/// Empty modern recovery extensions can be removed to construct an exact35
/// catalog. This fixture does not rewrite any native or authenticated history.
fn install_v35_fixture(database: &std::path::Path) -> AnchoredTestResult {
    let db = Connection::open(database)?;
    require_alias_free_predecessor_fixture(&db)?;
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'deployment-history:*' OR record_key GLOB 'workflow-quota:*'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        0,
        "schema35 fixture cannot discard new protected history"
    );
    let tx = db.unchecked_transaction()?;
    remove_empty_captured_terminal_format(&tx)?;
    tx.execute_batch(
        "DROP TRIGGER admission_operation_recovery_history_insert;
         DROP TRIGGER admission_operation_recovery_history_immutable;
         DROP TRIGGER admission_operation_recovery_hold_immutable;
         DROP INDEX admission_operation_recovery_origin_presence;
         DROP INDEX admission_operation_recovery_command_alias;
         UPDATE chio_store_schema_versions SET version=35 WHERE store_key='admission_operation';",
    )?;
    tx.commit()?;
    Ok(())
}

/// Construct only the predecessor catalog. This is a modeled36 migration
/// fixture, separate from the preserved schema36 executable campaign.
fn install_v36_fixture(database: &std::path::Path) -> AnchoredTestResult {
    let db = Connection::open(database)?;
    require_alias_free_predecessor_fixture(&db)?;
    assert!(!db.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records
         WHERE record_key GLOB 'workflow-quota:*'
           AND json_type(payload,'$.native_hold') IS NOT NULL)",
        [],
        |row| row.get::<_, bool>(0),
    )?);
    let tx = db.unchecked_transaction()?;
    remove_empty_captured_terminal_format(&tx)?;
    tx.execute_batch(
        "DROP TRIGGER admission_operation_recovery_hold_immutable;
         DROP INDEX admission_operation_recovery_origin_presence;
         DROP INDEX admission_operation_recovery_command_alias;
         UPDATE chio_store_schema_versions SET version=36 WHERE store_key='admission_operation';",
    )?;
    tx.commit()?;
    Ok(())
}

#[test]
fn recovery_populated_v36_upgrade_preserves_native_operations_and_global_chain(
) -> AnchoredTestResult {
    let f = fixture();
    let operation = prepared_operation(
        &f.fence,
        AdmissionOperationKind::ToolDispatch,
        "retained-v36-operation",
        "retained-v36-capability",
    );
    f.store.begin(&operation, &f.fence, now_ms())?;
    let _lease = claim(&f, &operation, "retained-v36-owner", now_ms());
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
    install_v36_fixture(&database)?;
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
            "rewrote schema36: {table}"
        );
    }
    assert!(matches!(
        crate::check_schema_version(&db, "admission_operation", 36, &["admission_operations"]),
        Err(crate::SchemaVersionError::FutureSchema {
            found: crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
            supported: 36
        })
    ));
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM sqlite_schema
             WHERE name IN ('admission_operation_recovery_hold_immutable',
                 'admission_operation_recovery_origin_presence')",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        2
    );
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

#[test]
fn recovery_v36_catalog_and_native_integrity_refuse_before_upgrade() -> AnchoredTestResult {
    for catalog_fault in [true, false] {
        let f = fixture();
        let operation = prepared_operation(
            &f.fence,
            AdmissionOperationKind::ToolDispatch,
            "v36-integrity-operation",
            "v36-integrity-capability",
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
        install_v36_fixture(&database)?;
        let db = Connection::open(&database)?;
        db.execute_batch("DROP TRIGGER admission_operation_commits_immutable;")?;
        if !catalog_fault {
            db.execute(
                "UPDATE admission_operation_commits SET operation_digest=?1",
                ["0".repeat(64)],
            )?;
            db.execute_batch(super::super::super::ADMISSION_OPERATION_SCHEMA)?;
        }
        let before = [
            rows(&db, "admission_operations")?,
            rows(&db, "admission_operation_commits")?,
            rows(&db, "authority_global_commits")?,
        ];
        drop(db);
        assert!(
            SqliteAuthorityStore::provision(&database, &lock_root).is_err(),
            "malformed36 predecessor was upgraded"
        );
        let db = Connection::open(&database)?;
        assert_eq!(
            db.query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key='admission_operation'",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            36
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE name IN ('admission_operation_recovery_hold_immutable',
                     'admission_operation_recovery_origin_presence')",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            0
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
                "failed migration rewrote schema36: {table}"
            );
        }
    }
    Ok(())
}

#[test]
fn recovery_populated_v35_upgrade_preserves_native_operations_and_global_chain(
) -> AnchoredTestResult {
    let f = fixture();
    let operation = prepared_operation(
        &f.fence,
        AdmissionOperationKind::ToolDispatch,
        "retained-v35-operation",
        "retained-v35-capability",
    );
    f.store.begin(&operation, &f.fence, now_ms())?;
    let _lease = claim(&f, &operation, "retained-v35-owner", now_ms());
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
    install_v35_fixture(&database)?;
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
            "rewrote schema35: {table}"
        );
    }
    assert_eq!(
        db.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key='admission_operation'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        i64::from(crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
    );
    assert!(matches!(
        crate::check_schema_version(&db, "admission_operation", 35, &["admission_operations"]),
        Err(crate::SchemaVersionError::FutureSchema {
            found: crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
            supported: 35
        })
    ));
    assert_eq!(db.query_row("SELECT count(*) FROM sqlite_schema WHERE name IN ('admission_operation_recovery_history_insert','admission_operation_recovery_history_immutable')", [], |row| row.get::<_, i64>(0))?, 2);
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

#[test]
fn recovery_v35_catalog_and_native_integrity_refuse_before_upgrade() -> AnchoredTestResult {
    for catalog_fault in [true, false] {
        let f = fixture();
        let operation = prepared_operation(
            &f.fence,
            AdmissionOperationKind::ToolDispatch,
            "v35-integrity-operation",
            "v35-integrity-capability",
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
        install_v35_fixture(&database)?;
        let db = Connection::open(&database)?;
        db.execute_batch("DROP TRIGGER admission_operation_commits_immutable;")?;
        if !catalog_fault {
            db.execute(
                "UPDATE admission_operation_commits SET operation_digest=?1",
                ["0".repeat(64)],
            )?;
            db.execute_batch(super::super::super::ADMISSION_OPERATION_SCHEMA)?;
        }
        let before = [
            rows(&db, "admission_operations")?,
            rows(&db, "admission_operation_commits")?,
            rows(&db, "authority_global_commits")?,
        ];
        drop(db);
        assert!(
            SqliteAuthorityStore::provision(&database, &lock_root).is_err(),
            "malformed35 predecessor was upgraded"
        );
        let db = Connection::open(&database)?;
        assert_eq!(db.query_row("SELECT version FROM chio_store_schema_versions WHERE store_key='admission_operation'", [], |row| row.get::<_, i64>(0))?, 35);
        assert_eq!(db.query_row("SELECT count(*) FROM sqlite_schema WHERE name GLOB 'admission_operation_recovery_history_*'", [], |row| row.get::<_, i64>(0))?, 0);
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
                "failed migration rewrote predecessor: {table}"
            );
        }
    }
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
    let f = fixture();
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
    assert_eq!(std::fs::read(marker)?, b"verified-v35-before-commit");
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
fn recovery_schema37_fences_predecessor36_before_serving() -> AnchoredTestResult {
    let fixture = fixture();
    let db = Connection::open(&fixture.database)?;
    let version: i64 = db.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key='admission_operation'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        version,
        i64::from(crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION),
        "auxiliary control custody has no serving schema fence"
    );
    assert!(matches!(
        crate::check_schema_version(&db, "admission_operation", 36, &["admission_operations"]),
        Err(crate::SchemaVersionError::FutureSchema {
            found: crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
            supported: 36
        })
    ));
    Ok(())
}

fn require_alias_free_predecessor_fixture(connection: &Connection) -> AnchoredTestResult {
    let alias_custody: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records
            WHERE record_key GLOB 'command-alias:*')
         OR EXISTS(SELECT 1 FROM admission_operation_recovery_events
            WHERE record_key GLOB 'command-alias:*')
         OR EXISTS(SELECT 1 FROM authority_global_commits
            WHERE projection_kind='recovery' AND projection_key GLOB 'command-alias:*')",
        [],
        |row| row.get(0),
    )?;
    assert!(
        !alias_custody,
        "predecessor fixture cannot erase durable command alias custody"
    );
    Ok(())
}

/// This models an exact37 catalog on a disposable current native fixture.
/// Genuine predecessor executable refusal has separate same-path evidence.
fn install_v37_fixture(database: &std::path::Path) -> AnchoredTestResult {
    let db = Connection::open(database)?;
    require_alias_free_predecessor_fixture(&db)?;
    let tx = db.unchecked_transaction()?;
    remove_empty_captured_terminal_format(&tx)?;
    tx.execute_batch(
        "DROP INDEX admission_operation_recovery_command_alias;
         UPDATE chio_store_schema_versions SET version=37 WHERE store_key='admission_operation';",
    )?;
    tx.commit()?;
    Ok(())
}

#[test]
fn recovery_alias_catalog_upgrade_preserves_predecessor_native_custody() -> AnchoredTestResult {
    let f = fixture();
    let operation = prepared_operation(
        &f.fence,
        AdmissionOperationKind::ToolDispatch,
        "retained-alias-predecessor-operation",
        "retained-alias-predecessor-capability",
    );
    f.store.begin(&operation, &f.fence, now_ms())?;
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
    install_v37_fixture(&database)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let db = Connection::open(&database)?;
    assert_eq!(
        db.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key='admission_operation'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        i64::from(crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
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
            "rewrote schema37: {table}"
        );
    }
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='admission_operation_recovery_command_alias'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        1
    );
    assert!(matches!(
        crate::check_schema_version(&db, "admission_operation", 37, &["admission_operations"]),
        Err(crate::SchemaVersionError::FutureSchema {
            found: crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
            supported: 37,
        })
    ));
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

/// Construct the exact journal-only predecessor on a disposable current fixture.
/// Existing native operations and retained global references are untouched.
fn install_journal_only_predecessor_fixture(database: &std::path::Path) -> AnchoredTestResult {
    let db = Connection::open(database)?;
    crate::admission_operation_store::schema::require_predecessor_knowledge_encoding_absence(&db)?;
    let tx = db.unchecked_transaction()?;
    tx.execute_batch(
        "DROP TRIGGER admission_operation_recovery_codec_guard_insert;
         DROP TRIGGER admission_operation_recovery_codec_guard_update;
         DROP TRIGGER admission_operation_recovery_encoding_chunk_immutable;
         DROP INDEX idx_recovery_knowledge_journal_chunk_authority;
         DROP INDEX admission_operation_recovery_reference_capacity;",
    )?;
    tx.execute_batch(include_str!("../../recovery_knowledge_encoding.sql"))?;
    tx.execute(
        "UPDATE chio_store_schema_versions SET version=39 WHERE store_key='admission_operation'",
        [],
    )?;
    tx.commit()?;
    Ok(())
}

#[test]
fn recovery_lossless_label_catalog_upgrade_preserves_original_native_custody() -> AnchoredTestResult
{
    let f = fixture();
    let operation = prepared_operation(
        &f.fence,
        AdmissionOperationKind::ToolDispatch,
        "retained-journal-only-operation",
        "retained-journal-only-capability",
    );
    f.store.begin(&operation, &f.fence, now_ms())?;
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
    install_journal_only_predecessor_fixture(&database)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let db = Connection::open(&database)?;
    assert!(matches!(
        crate::check_schema_version(&db, "admission_operation", 39, &["admission_operations"]),
        Err(crate::SchemaVersionError::FutureSchema {
            found: 40,
            supported: 39
        })
    ));
    for (index, table) in [
        "admission_operations",
        "admission_operation_commits",
        "authority_global_commits",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            rows(&db, table)?,
            before[index],
            "rewrote predecessor native custody: {table}"
        );
    }
    assert!(!db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |row| row.get::<_, bool>(0)
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

#[test]
fn recovery_alias_catalog_refuses_a_lowered_predecessor_stamp() -> AnchoredTestResult {
    let f = fixture();
    let operation = prepared_operation(
        &f.fence,
        AdmissionOperationKind::ToolDispatch,
        "lowered-alias-schema-operation",
        "lowered-alias-schema-capability",
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
    db.execute(
        "UPDATE chio_store_schema_versions SET version=37 WHERE store_key='admission_operation'",
        [],
    )?;
    let before = [
        rows(&db, "admission_operations")?,
        rows(&db, "admission_operation_commits")?,
        rows(&db, "authority_global_commits")?,
    ];
    drop(db);
    let error = SqliteAuthorityStore::provision(&database, &lock_root)
        .err()
        .ok_or("lowered predecessor stamp accepted a future alias catalog")?;
    assert!(error.to_string().contains("canonical definition"));
    let db = Connection::open(&database)?;
    assert_eq!(
        db.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key='admission_operation'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        37
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
            "failed migration rewrote schema37: {table}"
        );
    }
    Ok(())
}
