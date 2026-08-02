use super::super::*;
use super::support::*;

fn stamped_receipt_schema_version(
    connection: &rusqlite::Connection,
) -> Result<i32, rusqlite::Error> {
    connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'receipt'",
        [],
        |row| row.get(0),
    )
}

fn replace_settlement_observer_outbox_with_v2(connection: &rusqlite::Connection) {
    connection
        .execute_batch(
            r#"
            DROP TRIGGER chio_settlement_observer_outbox_validate_update;
            DROP TRIGGER chio_settlement_observer_outbox_reject_unfinished_delete;
            DROP INDEX idx_chio_settlement_observer_outbox_pending;
            ALTER TABLE chio_settlement_observer_outbox
                RENAME TO chio_settlement_observer_outbox_v3_discard;
            "#,
        )
        .test_unwrap();
    connection
        .execute_batch(&format!(
            r#"
            {};
            CREATE INDEX idx_chio_settlement_observer_outbox_pending
                ON chio_settlement_observer_outbox(state, finalized_at, receipt_id);
            CREATE TRIGGER chio_settlement_observer_outbox_validate_update
            BEFORE UPDATE ON chio_settlement_observer_outbox
            WHEN NEW.receipt_id != OLD.receipt_id
              OR NEW.finalized_at != OLD.finalized_at
              OR OLD.state = 'completed'
              OR NEW.version != OLD.version + 1
              OR (OLD.state = 'pending' AND NEW.state != 'claimed')
              OR (OLD.state = 'claimed' AND NEW.state NOT IN ('pending', 'claimed', 'routing'))
              OR (OLD.state = 'routing' AND NEW.state NOT IN ('routing', 'completed'))
              OR (
                  OLD.state = 'routing'
                  AND NEW.state = 'routing'
                  AND NEW.staged_status_json IS NOT OLD.staged_status_json
              )
            BEGIN
                SELECT RAISE(ABORT, 'invalid settlement-observer outbox transition');
            END;
            CREATE TRIGGER chio_settlement_observer_outbox_reject_unfinished_delete
            BEFORE DELETE ON chio_settlement_observer_outbox
            WHEN OLD.state != 'completed'
            BEGIN
                SELECT RAISE(ABORT, 'unfinished settlement-observer outbox rows are durable');
            END;
            DROP TABLE chio_settlement_observer_outbox_v3_discard;
            "#,
            crate::receipt_store::bootstrap::open::SETTLEMENT_OBSERVER_OUTBOX_V2_TABLE_SQL,
        ))
        .test_unwrap();
    crate::stamp_schema_version(connection, "receipt", 2).test_unwrap();
}

fn settlement_observer_outbox_rows(
    connection: &rusqlite::Connection,
) -> Vec<(
    String,
    i64,
    String,
    Option<String>,
    Option<i64>,
    i64,
    Option<String>,
    Option<String>,
)> {
    connection
        .prepare(
            "SELECT receipt_id, finalized_at, state, claim_token, claim_deadline_unix_ms, version, staged_status_json, last_error FROM chio_settlement_observer_outbox ORDER BY finalized_at, receipt_id",
        )
        .test_unwrap()
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        })
        .test_unwrap()
        .collect::<Result<Vec<_>, _>>()
        .test_unwrap()
}

#[cfg(unix)]
fn create_private_empty_file(path: &std::path::Path) {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .test_unwrap();
}

#[cfg(unix)]
fn receipt_sidecar_path(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(suffix);
    std::path::PathBuf::from(sidecar)
}

#[cfg(unix)]
fn retained_receipt_identity(
    temporary: &tempfile::TempDir,
    name: &str,
) -> (std::path::PathBuf, ReceiptDatabaseIdentityFile) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).test_unwrap();
    let path = temporary.path().join(name);
    let identity = ReceiptDatabaseIdentityFile::open(&path, true).test_unwrap();
    (path, identity)
}

#[cfg(unix)]
fn direct_receipt_connection_manager(
    temporary: &tempfile::TempDir,
    name: &str,
) -> (std::path::PathBuf, ReceiptConnectionManager) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).test_unwrap();
    let path = temporary.path().join(name);
    let identity = ReceiptDatabaseIdentityFile::open(&path, true).test_unwrap();
    let manager = ReceiptConnectionManager::new(&path, std::sync::Arc::new(identity), None);
    (path, manager)
}

#[cfg(unix)]
#[test]
fn receipt_identity_requires_a_private_final_authority_directory() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().test_unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o750)).test_unwrap();
    let path = temporary.path().join("non-private-parent.sqlite3");
    let error = match ReceiptDatabaseIdentityFile::open(&path, true) {
        Ok(_) => panic!("accepted a non-private receipt authority directory"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("mode 0700"));
}

#[cfg(unix)]
#[test]
fn receipt_connection_manager_rejects_an_open_transaction() {
    let temporary = tempfile::tempdir().test_unwrap();
    let (_path, manager) =
        direct_receipt_connection_manager(&temporary, "transaction-hygiene.sqlite3");
    let mut connection = r2d2::ManageConnection::connect(&manager).test_unwrap();
    connection
        .execute_batch(
            "CREATE TABLE transaction_probe (value INTEGER NOT NULL); \
             BEGIN IMMEDIATE; \
             INSERT INTO transaction_probe (value) VALUES (1)",
        )
        .test_unwrap();

    assert!(r2d2::ManageConnection::is_valid(&manager, &mut connection).is_err());
    assert!(r2d2::ManageConnection::has_broken(
        &manager,
        &mut connection
    ));
    assert!(!connection.is_autocommit());
    connection.execute_batch("ROLLBACK").test_unwrap();
    r2d2::ManageConnection::is_valid(&manager, &mut connection).test_unwrap();
    assert!(!r2d2::ManageConnection::has_broken(
        &manager,
        &mut connection
    ));
}

#[cfg(unix)]
#[test]
fn receipt_connection_manager_rejects_an_unexpected_attachment() {
    let temporary = tempfile::tempdir().test_unwrap();
    let (_path, manager) =
        direct_receipt_connection_manager(&temporary, "attachment-hygiene.sqlite3");
    let attached = temporary.path().join("unexpected-attachment.sqlite3");
    create_private_empty_file(&attached);
    let escaped = attached.to_string_lossy().replace('\'', "''");
    let mut connection = r2d2::ManageConnection::connect(&manager).test_unwrap();
    connection
        .execute_batch(&format!(
            "ATTACH DATABASE '{escaped}' AS unexpected_authority"
        ))
        .test_unwrap();
    let attached_schema = crate::receipt_store::bootstrap::open::sqlite_database_list(&connection)
        .test_unwrap()
        .into_iter()
        .find(|(_, name, _)| name == "unexpected_authority")
        .map(|(_, name, _)| name)
        .test_unwrap();
    assert_eq!(attached_schema, "unexpected_authority");

    assert!(r2d2::ManageConnection::is_valid(&manager, &mut connection).is_err());
    assert!(r2d2::ManageConnection::has_broken(
        &manager,
        &mut connection
    ));
    connection
        .execute_batch("DETACH DATABASE unexpected_authority")
        .test_unwrap();
    connection
        .execute_batch("CREATE TEMP TABLE poisoned_temp_schema (value INTEGER)")
        .test_unwrap();
    assert!(r2d2::ManageConnection::is_valid(&manager, &mut connection).is_err());
    assert!(r2d2::ManageConnection::has_broken(
        &manager,
        &mut connection
    ));
    connection
        .execute_batch("DROP TABLE temp.poisoned_temp_schema")
        .test_unwrap();
    connection
        .execute_batch(
            "CREATE TABLE temp_trigger_target (value INTEGER NOT NULL); \
             CREATE TEMP TRIGGER poisoned_retention_trigger \
             AFTER DELETE ON main.temp_trigger_target \
             BEGIN \
                 INSERT INTO temp_trigger_target (value) VALUES (OLD.value); \
             END",
        )
        .test_unwrap();
    assert!(r2d2::ManageConnection::is_valid(&manager, &mut connection).is_err());
    assert!(r2d2::ManageConnection::has_broken(
        &manager,
        &mut connection
    ));
    connection
        .execute_batch("DROP TRIGGER temp.poisoned_retention_trigger")
        .test_unwrap();
    r2d2::ManageConnection::is_valid(&manager, &mut connection).test_unwrap();
    assert!(!r2d2::ManageConnection::has_broken(
        &manager,
        &mut connection
    ));
}

#[cfg(unix)]
#[test]
fn receipt_connection_catalog_pragma_cannot_be_shadowed() {
    let temporary = tempfile::tempdir().test_unwrap();
    let (path, manager) =
        direct_receipt_connection_manager(&temporary, "database-list-shadow.sqlite3");
    let mut connection = r2d2::ManageConnection::connect(&manager).test_unwrap();
    connection
        .execute_batch(
            "CREATE TABLE pragma_database_list (seq INTEGER, name TEXT, file TEXT); \
             INSERT INTO pragma_database_list (seq, name, file) \
             VALUES (0, 'forged', '/forged.sqlite3'); \
             CREATE TABLE pragma_foreign_key_list (id INTEGER NOT NULL); \
             INSERT INTO pragma_foreign_key_list (id) VALUES (1)",
        )
        .test_unwrap();

    let databases =
        crate::receipt_store::bootstrap::open::sqlite_database_list(&connection).test_unwrap();
    assert!(databases.iter().any(|(_, name, _)| name == "main"));
    assert!(!databases.iter().any(|(_, name, _)| name == "forged"));
    r2d2::ManageConnection::is_valid(&manager, &mut connection).test_unwrap();
    drop(connection);
    SqliteReceiptStore::open_existing_strict(&path).test_unwrap();
}

#[cfg(unix)]
#[test]
fn receipt_store_rejects_a_swap_during_initial_sqlite_open() {
    let directory =
        chio_test_support::private_fs::private_tempdir("receipt-initial-open-swap").test_unwrap();
    let directory = fs::canonicalize(directory.path()).test_unwrap();
    let path = directory.join("receipt-initial-open.sqlite3");
    let replacement = directory.join("receipt-initial-open-replacement.sqlite3");
    let displaced = directory.join("receipt-initial-open-displaced.sqlite3");
    create_private_empty_file(&replacement);

    crate::receipt_store::bootstrap::open::connection_open_test_hooks::install(
        path.clone(),
        replacement.clone(),
        displaced.clone(),
        crate::receipt_store::bootstrap::open::ReceiptConnectionOpenStage::Initial,
    )
    .test_unwrap();

    let error = SqliteReceiptStore::open(&path).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("live SQLite connection is not bound to the retained receipt database file"),
        "unexpected error: {error}"
    );
    assert!(
        error
            .to_string()
            .contains("SQLite main database handle is no longer bound to its opened path"),
        "the live SQLite handle must report the displaced file: {error}"
    );
    assert!(
        crate::receipt_store::bootstrap::open::connection_open_test_hooks::take_completed(&path)
            .test_unwrap(),
        "the initial-open swap hook must run to completion"
    );
    assert!(path.is_file());
    assert!(replacement.is_file());
    assert!(!displaced.exists());
}

#[cfg(unix)]
#[test]
fn receipt_store_rejects_a_swap_during_pool_sqlite_open() {
    let directory =
        chio_test_support::private_fs::private_tempdir("receipt-pool-open-swap").test_unwrap();
    let directory = fs::canonicalize(directory.path()).test_unwrap();
    let path = directory.join("receipt-pool-open.sqlite3");
    let replacement = directory.join("receipt-pool-open-replacement.sqlite3");
    let displaced = directory.join("receipt-pool-open-displaced.sqlite3");
    drop(SqliteReceiptStore::open(&path).test_unwrap());
    create_private_empty_file(&replacement);

    crate::receipt_store::bootstrap::open::connection_open_test_hooks::install(
        path.clone(),
        replacement.clone(),
        displaced.clone(),
        crate::receipt_store::bootstrap::open::ReceiptConnectionOpenStage::Pool,
    )
    .test_unwrap();

    let error = SqliteReceiptStore::open_existing(&path).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("live SQLite connection is not bound to the retained receipt database file"),
        "unexpected error: {error}"
    );
    assert!(
        error
            .to_string()
            .contains("SQLite main database handle is no longer bound to its opened path"),
        "the pooled SQLite handle must report the displaced file: {error}"
    );
    assert!(
        crate::receipt_store::bootstrap::open::connection_open_test_hooks::take_completed(&path)
            .test_unwrap(),
        "the pool-open swap hook must run to completion"
    );
    assert!(path.is_file());
    assert!(replacement.is_file());
    assert!(!displaced.exists());
}

#[cfg(unix)]
#[test]
fn receipt_store_detects_post_open_hardlinks_and_path_rebinding() {
    use std::os::unix::fs::OpenOptionsExt;

    let directory =
        chio_test_support::private_fs::private_tempdir("receipt-post-open-rebind").test_unwrap();
    let path = directory.path().join("receipt-identity.sqlite3");
    let hardlink = directory.path().join("receipt-identity-hardlink.sqlite3");
    let displaced = directory.path().join("receipt-identity-displaced.sqlite3");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    fs::hard_link(&path, &hardlink).test_unwrap();
    assert!(store.max_tool_receipt_seq().is_err());
    assert!(store.append_chio_receipt(&sample_receipt()).is_err());
    fs::remove_file(&hardlink).test_unwrap();
    assert!(store.max_tool_receipt_seq().is_ok());

    fs::rename(&path, &displaced).test_unwrap();
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .test_unwrap();
    assert!(store.max_tool_receipt_seq().is_err());
    assert!(store.append_chio_receipt(&sample_receipt()).is_err());
    assert!(
        store.open_bound_colocated_connection().is_err(),
        "a co-located connection must reject a post-open path replacement"
    );
}

#[cfg(unix)]
#[test]
fn receipt_identity_rejects_unsafe_sqlite_sidecars() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    for suffix in ["-wal", "-shm", "-journal"] {
        let temporary = tempfile::tempdir().test_unwrap();
        let (path, identity) = retained_receipt_identity(&temporary, "symlink.sqlite3");
        let target = temporary.path().join("symlink-target");
        create_private_empty_file(&target);
        symlink(&target, receipt_sidecar_path(&path, suffix)).test_unwrap();
        assert!(identity.validate().is_err(), "accepted {suffix} symlink");

        let temporary = tempfile::tempdir().test_unwrap();
        let (path, identity) = retained_receipt_identity(&temporary, "hardlink.sqlite3");
        let target = temporary.path().join("hardlink-target");
        create_private_empty_file(&target);
        fs::hard_link(&target, receipt_sidecar_path(&path, suffix)).test_unwrap();
        assert!(identity.validate().is_err(), "accepted {suffix} hardlink");

        let temporary = tempfile::tempdir().test_unwrap();
        let (path, identity) = retained_receipt_identity(&temporary, "mode.sqlite3");
        let sidecar = receipt_sidecar_path(&path, suffix);
        create_private_empty_file(&sidecar);
        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o640)).test_unwrap();
        assert!(
            identity.validate().is_err(),
            "accepted permissive {suffix} mode"
        );

        let temporary = tempfile::tempdir().test_unwrap();
        let (path, identity) = retained_receipt_identity(&temporary, "nonregular.sqlite3");
        fs::create_dir(receipt_sidecar_path(&path, suffix)).test_unwrap();
        assert!(
            identity.validate().is_err(),
            "accepted non-regular {suffix}"
        );
    }
}

#[cfg(unix)]
#[test]
fn receipt_store_revalidates_live_sqlite_sidecars_before_use() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().test_unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).test_unwrap();
    let path = temporary.path().join("live-sidecars.sqlite3");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let wal = receipt_sidecar_path(&path, "-wal");
    assert!(wal.is_file(), "receipt store did not materialize its WAL");
    fs::set_permissions(&wal, fs::Permissions::from_mode(0o640)).test_unwrap();

    assert!(
        store.max_tool_receipt_seq().is_err(),
        "receipt store accepted widened live WAL authority"
    );
}

#[cfg(unix)]
#[test]
fn receipt_store_pins_a_resolved_parent_alias() {
    use std::os::unix::fs::symlink;

    let alias_directory =
        chio_test_support::private_fs::private_tempdir("receipt-parent-alias").test_unwrap();
    let original_directory =
        chio_test_support::private_fs::private_tempdir("receipt-parent-original").test_unwrap();
    let replacement_directory =
        chio_test_support::private_fs::private_tempdir("receipt-parent-replacement").test_unwrap();
    let alias = alias_directory.path().join("database-parent");
    symlink(original_directory.path(), &alias).test_unwrap();
    let aliased_path = alias.join("receipts.sqlite3");

    let store = SqliteReceiptStore::open(&aliased_path).test_unwrap();
    fs::remove_file(&alias).test_unwrap();
    symlink(replacement_directory.path(), &alias).test_unwrap();

    store.append_chio_receipt(&sample_receipt()).test_unwrap();
    assert_eq!(store.tool_receipt_count().test_unwrap(), 1);
    assert!(original_directory.path().join("receipts.sqlite3").is_file());
    assert!(!replacement_directory
        .path()
        .join("receipts.sqlite3")
        .exists());
}

#[test]
fn sqlite_receipt_store_persists_across_reopen() {
    let path = unique_db_path("chio-receipts");
    {
        let store = SqliteReceiptStore::open(&path).test_unwrap();
        store.append_chio_receipt(&sample_receipt()).test_unwrap();
        store
            .append_child_receipt(&sample_child_receipt())
            .test_unwrap();
        assert_eq!(store.tool_receipt_count().test_unwrap(), 1);
        assert_eq!(store.child_receipt_count().test_unwrap(), 1);
    }

    let reopened = SqliteReceiptStore::open(&path).test_unwrap();
    assert_eq!(reopened.tool_receipt_count().test_unwrap(), 1);
    assert_eq!(reopened.child_receipt_count().test_unwrap(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn bounded_page_count_yields_full_error() {
    let path = unique_db_path("chio-receipts-bounded-pages");

    // Establish the schema and a baseline under the default (uncapped) config,
    // then measure the live page count so the cap sits just above it. The bound
    // must clear the schema yet leave only a little headroom, so a bounded append
    // loop provably reaches SQLITE_FULL rather than looping forever.
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    for i in 0..16u64 {
        let receipt = sample_receipt_with_id_and_timestamp(&format!("bounded-pre-{i}"), i + 1);
        store
            .append_chio_receipt_returning_seq(&receipt)
            .test_unwrap();
    }
    store.flush_receipt_writes().test_unwrap();
    let baseline_pages: i64 = store
        .connection()
        .test_unwrap()
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .test_unwrap();
    drop(store);

    let cap = u32::try_from(baseline_pages).test_unwrap() + 48;
    let store = SqliteReceiptStore::open_with_pool_config(
        &path,
        crate::SqlitePoolConfig {
            max_page_count: Some(cap),
            ..crate::SqlitePoolConfig::default()
        },
    )
    .test_unwrap();

    let mut full_error = None;
    for i in 0..50_000u64 {
        let receipt = sample_receipt_with_id_and_timestamp(&format!("bounded-fill-{i}"), 1_000 + i);
        match store.append_chio_receipt_returning_seq(&receipt) {
            Ok(_) => continue,
            Err(error) => {
                full_error = Some(error);
                break;
            }
        }
    }

    // The cap must actually have forced a rejection; a silent pass would prove
    // nothing about the bound.
    let error = match full_error {
        Some(error) => error,
        None => panic!("a bounded page count must eventually reject an append"),
    };
    match error {
        ReceiptStoreError::Sqlite(sqlite_error) => assert_eq!(
            sqlite_error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DiskFull),
            "a bounded page count must surface SQLITE_FULL as a typed Sqlite error"
        ),
        other => panic!("expected ReceiptStoreError::Sqlite(SQLITE_FULL), got {other:?}"),
    }

    let _ = fs::remove_file(path);
}

#[test]
fn bounded_page_count_rejects_zero_effective_mismatch() {
    let path = unique_db_path("chio-receipts-zero-page-cap");
    let error = match SqliteReceiptStore::open_with_pool_config(
        &path,
        crate::SqlitePoolConfig {
            max_page_count: Some(0),
            ..crate::SqlitePoolConfig::default()
        },
    ) {
        Ok(_) => panic!("a zero page cap must not open as SQLite's default maximum"),
        Err(error) => error,
    };
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "a silently ignored zero page cap must deny with Conflict, got {error:?}"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn bounded_page_count_rejects_cap_below_existing_database() {
    let path = unique_db_path("chio-receipts-below-existing-page-cap");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let current_pages: i64 = store
        .connection()
        .test_unwrap()
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .test_unwrap();
    drop(store);
    let requested = u32::try_from(current_pages.saturating_sub(1)).test_unwrap();

    let error = match SqliteReceiptStore::open_with_pool_config(
        &path,
        crate::SqlitePoolConfig {
            max_page_count: Some(requested),
            ..crate::SqlitePoolConfig::default()
        },
    ) {
        Ok(_) => panic!("a page cap below the existing database must not be raised silently"),
        Err(error) => error,
    };
    assert!(
        matches!(error, ReceiptStoreError::Conflict(_)),
        "an effective cap above the requested cap must deny with Conflict, got {error:?}"
    );
    let _ = fs::remove_file(path);
}

#[cfg(feature = "pq")]
#[test]
fn receipt_verify_accepts_hybrid_receipts_for_persistence() {
    let path = unique_db_path("chio-receipts-hybrid");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    let tool_seq = store
        .append_chio_receipt_returning_seq(&sample_hybrid_receipt())
        .test_unwrap();
    let child_seq = store
        .append_child_receipt_record(&sample_hybrid_child_receipt())
        .test_unwrap();

    assert_eq!(tool_seq, 1);
    assert_eq!(child_seq, 2);
    assert_eq!(store.tool_receipt_count().test_unwrap(), 1);
    assert_eq!(store.child_receipt_count().test_unwrap(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn request_lineage_record_persistence_rejects_unsupported_schema() {
    let path = unique_db_path("chio-request-lineage-schema");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let mut lineage_json = request_lineage_json("req-schema", "anchor-schema", None);
    lineage_json["schema"] = serde_json::Value::String("chio.request_lineage.v1".to_string());

    let result = store.record_request_lineage_record(
        "sess-schema",
        "req-schema",
        None,
        Some("anchor-schema"),
        1_710_000_000,
        Some("req-schema-fingerprint"),
        &lineage_json,
    );

    let error = match result {
        Ok(()) => panic!("unsupported request lineage schema should fail"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("unsupported request lineage record schema"));

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_receipt_store_configures_durable_pragmas() {
    let path = unique_db_path("chio-receipts-pragmas");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let connection = store.connection().test_unwrap();

    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .test_unwrap();
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .test_unwrap();
    let busy_timeout: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .test_unwrap();
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .test_unwrap();

    assert!(journal_mode.eq_ignore_ascii_case("wal"));
    assert_eq!(synchronous, 2);
    assert!(busy_timeout >= 5000);
    assert_eq!(foreign_keys, 1);

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_receipt_store_stamps_application_id_and_refuses_future_database() {
    let path = unique_db_path("chio-receipts-schema-stamp");

    // A fresh open stamps the Chio application_id and leaves the database-wide
    // user_version untouched: the schema revision lives in keyed metadata so
    // co-located stores can version independently.
    {
        let store = SqliteReceiptStore::open(&path).test_unwrap();
        let connection = store.connection().test_unwrap();
        let app_id: i32 = connection
            .query_row("PRAGMA application_id", [], |row| row.get(0))
            .test_unwrap();
        assert_eq!(app_id, crate::CHIO_SQLITE_APPLICATION_ID);
        let user_version: i32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .test_unwrap();
        assert_eq!(user_version, 0);
    }

    // Simulate a database written by a newer binary and confirm the older binary
    // refuses to open it rather than silently misreading a future schema. The
    // receipt store records its revision under its own key in the shared metadata
    // table, so the future revision is staged there.
    {
        let connection = rusqlite::Connection::open(&path).test_unwrap();
        crate::stamp_schema_version(&connection, "receipt", 99).test_unwrap();
    }
    assert!(
        SqliteReceiptStore::open_existing(&path).is_err(),
        "a future-version receipt database must be refused"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_schema_v4_upgrades_a_branch_v3_database_without_cost_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipts-v3-cost-upgrade");
    let receipt = sample_financial_receipt("v3-cost-upgrade", u64::MAX)?;
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.append_chio_receipt(&receipt)?;
    }
    {
        let connection = rusqlite::Connection::open(&path)?;
        crate::receipt_store::support::drop_transparency_projection_guards(&connection)?;
        connection.execute_batch(
            "DROP INDEX idx_chio_tool_receipts_cost; \
             DROP INDEX idx_chio_tool_receipts_cost_global; \
             ALTER TABLE chio_tool_receipts DROP COLUMN cost_charged_be; \
             ALTER TABLE chio_tool_receipts DROP COLUMN cost_currency;",
        )?;
        crate::stamp_schema_version(&connection, "receipt", 3)?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let connection = store.connection()?;
    let projection = connection.query_row(
        "SELECT cost_currency, cost_charged_be FROM chio_tool_receipts WHERE receipt_id = ?1",
        [receipt.id.as_str()],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )?;
    assert_eq!(
        projection,
        ("USD".to_string(), u64::MAX.to_be_bytes().to_vec())
    );
    let version = stamped_receipt_schema_version(&connection)?;
    assert_eq!(
        version,
        crate::receipt_store::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
    );
    drop(connection);
    drop(store);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn receipt_schema_v4_upgrades_a_main_v3_database_without_observer_outbox(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipts-main-v3-upgrade");
    drop(SqliteReceiptStore::open(&path)?);
    {
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(
            "DROP TRIGGER chio_settlement_observer_outbox_validate_update; \
             DROP TRIGGER chio_settlement_observer_outbox_reject_unfinished_delete; \
             DROP INDEX idx_chio_settlement_observer_outbox_pending; \
             DROP TABLE chio_settlement_observer_outbox;",
        )?;
        crate::stamp_schema_version(&connection, "receipt", 3)?;
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let connection = store.connection()?;
    crate::receipt_store::bootstrap::open::validate_settlement_observer_outbox_schema(
        &connection,
        false,
    )?;
    assert_eq!(
        stamped_receipt_schema_version(&connection)?,
        crate::receipt_store::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
    );
    drop(connection);
    drop(store);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn receipt_schema_v4_atomically_preserves_valid_v2_outbox_rows() {
    let path = unique_db_path("chio-receipts-v2-outbox-upgrade");
    drop(SqliteReceiptStore::open(&path).test_unwrap());
    let before = {
        let connection = rusqlite::Connection::open(&path).test_unwrap();
        replace_settlement_observer_outbox_with_v2(&connection);
        connection
            .execute_batch(
                r#"
                INSERT INTO chio_settlement_observer_outbox (
                    receipt_id, finalized_at, state, version, last_error
                ) VALUES ('pending', 1, 'pending', 0, 'prior pending error');
                INSERT INTO chio_settlement_observer_outbox (
                    receipt_id, finalized_at, state, claim_token,
                    claim_deadline_unix_ms, version
                ) VALUES ('claimed', 2, 'claimed', 'claim-token', 10, 2);
                INSERT INTO chio_settlement_observer_outbox (
                    receipt_id, finalized_at, state, claim_token,
                    claim_deadline_unix_ms, version, staged_status_json,
                    last_error
                ) VALUES (
                    'routing', 3, 'routing', 'routing-token', 20, 3,
                    '{"kind":"skipped","reason":"bounded"}',
                    'prior routing error'
                );
                INSERT INTO chio_settlement_observer_outbox (
                    receipt_id, finalized_at, state, version
                ) VALUES ('completed', 4, 'completed', 4);
                "#,
            )
            .test_unwrap();
        settlement_observer_outbox_rows(&connection)
    };

    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let connection = store.connection().test_unwrap();
    assert_eq!(settlement_observer_outbox_rows(&connection), before);
    let version: i32 = connection
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'receipt'",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    assert_eq!(
        version,
        crate::receipt_store::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
    );
    let staging_table_exists: i64 = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chio_settlement_observer_outbox_v2')",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    assert_eq!(staging_table_exists, 0);
    drop(connection);
    drop(store);

    let current_binary = rusqlite::Connection::open(&path).test_unwrap();
    assert!(current_binary
        .execute(
            "INSERT INTO chio_settlement_observer_outbox (receipt_id, finalized_at, state, claim_token, claim_deadline_unix_ms) VALUES ('negative', 5, 'claimed', 'token', -1)",
            [],
        )
        .is_err());
    drop(current_binary);

    let old_binary = rusqlite::Connection::open(&path).test_unwrap();
    let old_error = crate::check_schema_version(
        &old_binary,
        "receipt",
        2,
        &["chio_tool_receipts", "http_receipts", "tool_receipts"],
    )
    .test_unwrap_err();
    assert!(old_error.to_string().contains("schema version 4 is newer"));

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_schema_v4_rejects_invalid_v2_rows_without_partial_mutation() {
    let path = unique_db_path("chio-receipts-v2-outbox-invalid");
    drop(SqliteReceiptStore::open(&path).test_unwrap());
    let (before_table_sql, before_rows) = {
        let connection = rusqlite::Connection::open(&path).test_unwrap();
        replace_settlement_observer_outbox_with_v2(&connection);
        connection
            .execute(
                "INSERT INTO chio_settlement_observer_outbox (receipt_id, finalized_at, state, claim_token, claim_deadline_unix_ms, version) VALUES ('invalid-deadline', 1, 'claimed', 'token', -1, 0)",
                [],
            )
            .test_unwrap();
        let table_sql = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'chio_settlement_observer_outbox'",
                [],
                |row| row.get::<_, String>(0),
            )
            .test_unwrap();
        (table_sql, settlement_observer_outbox_rows(&connection))
    };

    let error = SqliteReceiptStore::open_existing(&path).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("outbox contains an invalid persisted row"),
        "unexpected migration error: {error}"
    );

    let connection = rusqlite::Connection::open(&path).test_unwrap();
    let version: i32 = connection
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'receipt'",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    assert_eq!(version, 2);
    let after_table_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'chio_settlement_observer_outbox'",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    assert_eq!(after_table_sql, before_table_sql);
    assert_eq!(settlement_observer_outbox_rows(&connection), before_rows);
    let staging_table_exists: i64 = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chio_settlement_observer_outbox_v2')",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    assert_eq!(staging_table_exists, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn open_refuses_foreign_database_without_switching_it_to_wal() {
    let path = unique_db_path("chio-receipts-foreign-no-wal");

    // A pre-existing, unrelated SQLite database on the target path, in the
    // default rollback-journal mode.
    {
        let foreign = rusqlite::Connection::open(&path).test_unwrap();
        foreign
            .execute_batch("CREATE TABLE someone_elses_table (id TEXT PRIMARY KEY);")
            .test_unwrap();
        let journal_mode: String = foreign
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .test_unwrap();
        assert!(
            !journal_mode.eq_ignore_ascii_case("wal"),
            "precondition: the foreign database is not in WAL mode"
        );
    }

    // Opening it as a receipt store must fail closed as foreign.
    let error = SqliteReceiptStore::open(&path).test_unwrap_err();
    assert!(
        error.to_string().contains("not a Chio store"),
        "unexpected error: {error}"
    );

    // The refused foreign database must be left untouched: the durability
    // pragmas must not have rewritten its header into WAL mode.
    let reopened = rusqlite::Connection::open(&path).test_unwrap();
    let journal_mode: String = reopened
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .test_unwrap();
    assert!(
        !journal_mode.eq_ignore_ascii_case("wal"),
        "a refused foreign database must not be switched to WAL, got {journal_mode}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn open_refuses_a_foreign_db_with_a_lookalike_legacy_receipt_table() {
    let path = unique_db_path("chio-receipts-foreign-lookalike");

    // An unrelated SQLite database that merely happens to carry a table named
    // `tool_receipts` with an unrelated shape (no receipt payload column).
    {
        let foreign = rusqlite::Connection::open(&path).test_unwrap();
        foreign
            .execute_batch("CREATE TABLE tool_receipts (id INTEGER PRIMARY KEY, note TEXT);")
            .test_unwrap();
    }

    let error = SqliteReceiptStore::open(&path).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("refusing to adopt a foreign database"),
        "unexpected error: {error}"
    );

    // The refused database must not be stamped as a Chio store.
    let reopened = rusqlite::Connection::open(&path).test_unwrap();
    let app_id: i32 = reopened
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .test_unwrap();
    assert_eq!(app_id, 0, "a refused foreign database must not be stamped");

    let _ = fs::remove_file(path);
}

#[test]
fn open_adopts_a_legacy_receipt_db_carrying_the_payload_column() {
    let path = unique_db_path("chio-receipts-legacy-adopt");

    // A pre-stamping receipt database: a legacy anchor table carrying the
    // receipt payload column, which the store must still adopt and upgrade.
    {
        let legacy = rusqlite::Connection::open(&path).test_unwrap();
        legacy
            .execute_batch(
                "CREATE TABLE tool_receipts (id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL);",
            )
            .test_unwrap();
    }

    let store = SqliteReceiptStore::open(&path).test_unwrap();
    drop(store);

    let reopened = rusqlite::Connection::open(&path).test_unwrap();
    let app_id: i32 = reopened
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .test_unwrap();
    assert_eq!(
        app_id,
        crate::CHIO_SQLITE_APPLICATION_ID,
        "a legacy receipt database with the payload column is adopted and stamped"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn flush_receipt_writes_reports_prior_committed_entries() {
    let path = unique_db_path("chio-receipts-flush");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    store
        .append_chio_receipt(&sample_receipt_with_id("rcpt-flush-1"))
        .test_unwrap();
    store
        .append_child_receipt(&sample_child_receipt_with_id_and_timestamp("flush-2", 2))
        .test_unwrap();

    let report = store.flush_receipt_writes().test_unwrap();

    assert!(report.writer.accepted_total >= 1);
    assert!(report.writer.committed_total >= 1);
    assert_eq!(report.latest_committed_entry_seq, 2);
    assert_eq!(report.latest_checkpointed_entry_seq, 0);
    assert_eq!(report.uncheckpointed_start_seq, Some(1));
    assert_eq!(report.uncheckpointed_end_seq, Some(2));
    assert!(report.wal_checkpoint.is_some());

    let _ = fs::remove_file(path);
}

/// The SIEM watchdog samples receipt health via a READ-ONLY open (no
/// create/WAL/writer-pool). Against a live store the sampler reads the same
/// committed/checkpointed progress as `receipt_store_health`. The writer is kept
/// alive (WAL/-shm in place), matching the production deployment where the
/// kernel owns the DB and the watchdog only reads.
#[test]
fn receipt_store_health_read_only_samples_a_live_store() {
    let path = unique_db_path("chio-receipts-health-ro");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    store
        .append_chio_receipt(&sample_receipt_with_id("rcpt-ro-1"))
        .test_unwrap();
    store
        .append_chio_receipt(&sample_receipt_with_id_and_timestamp("rcpt-ro-2", 2))
        .test_unwrap();

    let report = SqliteReceiptStore::receipt_store_health_read_only(&path).test_unwrap();
    assert!(report.healthy);
    assert_eq!(report.latest_committed_entry_seq, 2);
    assert_eq!(report.latest_checkpointed_entry_seq, 0);
    assert_eq!(report.uncheckpointed_start_seq, Some(1));
    assert_eq!(report.uncheckpointed_end_seq, Some(2));

    let _ = fs::remove_file(path);
}

/// A missing receipt DB must report NotFound and must NOT be created. `open`
/// creates a fresh empty DB on a mistyped path; the read-only sampler never
/// writes.
#[test]
fn receipt_store_health_read_only_missing_db_reports_not_found_without_creating() {
    let path = unique_db_path("chio-receipts-health-ro-missing");
    let _ = fs::remove_file(&path);
    assert!(!path.exists(), "precondition: the DB path must be absent");

    let error = SqliteReceiptStore::receipt_store_health_read_only(&path).test_unwrap_err();
    assert!(
        matches!(error, chio_kernel::ReceiptStoreError::NotFound(_)),
        "unexpected error: {error:?}"
    );
    assert!(
        !path.exists(),
        "the read-only sampler must not create the missing DB"
    );
}

#[test]
fn empty_store_reports_zero_committed_entry_for_operator_surfaces() {
    let path = unique_db_path("chio-receipts-empty-operator-surfaces");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    store
        .wait_for_writer_ready(Duration::from_secs(5))
        .test_unwrap();

    assert_eq!(store.latest_committed_entry_seq().test_unwrap(), 0);

    // Flush is an initialization barrier for the asynchronous receipt writer:
    // the actor cannot process it until verified-head seeding has completed.
    let flush = store.flush_receipt_writes().test_unwrap();
    assert_eq!(flush.latest_committed_entry_seq, 0);
    assert_eq!(flush.latest_checkpointed_entry_seq, 0);
    assert_eq!(flush.uncheckpointed_start_seq, None);
    assert_eq!(flush.uncheckpointed_end_seq, None);

    let health = store.receipt_store_health().test_unwrap();
    assert!(health.healthy);
    assert_eq!(health.latest_committed_entry_seq, 0);
    assert_eq!(health.latest_checkpointed_entry_seq, 0);
    assert_eq!(health.uncheckpointed_start_seq, None);
    assert_eq!(health.uncheckpointed_end_seq, None);

    let status = store.receipt_checkpoint_status(Some(10)).test_unwrap();
    assert!(status.healthy);
    assert_eq!(status.latest_committed_entry_seq, 0);
    assert_eq!(status.latest_checkpointed_entry_seq, 0);
    assert_eq!(status.next_range, None);

    let created = <SqliteReceiptStore as ReceiptStore>::create_next_receipt_checkpoint(
        &store,
        10,
        &receipt_test_keypair(),
    )
    .test_unwrap();
    assert!(!created.created);
    assert_eq!(created.latest_committed_entry_seq, 0);
    assert_eq!(created.latest_checkpointed_entry_seq, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn checkpoint_range_requires_contiguous_claim_log() {
    let path = unique_db_path("chio-receipts-checkpoint-gap");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    store
        .append_chio_receipt(&sample_receipt_with_id("rcpt-gap-1"))
        .test_unwrap();
    store
        .append_chio_receipt(&sample_receipt_with_id_and_timestamp("rcpt-gap-2", 2))
        .test_unwrap();
    store
        .append_chio_receipt(&sample_receipt_with_id_and_timestamp("rcpt-gap-3", 3))
        .test_unwrap();
    let connection = store.connection().test_unwrap();
    connection
        .execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete;")
        .test_unwrap();
    connection
        .execute(
            "DELETE FROM claim_receipt_log_entries WHERE entry_seq = 2",
            [],
        )
        .test_unwrap();

    let error = store.next_checkpoint_range(3).test_unwrap_err();

    assert!(error
        .to_string()
        .contains("claim receipt log has a gap in checkpoint range"));

    let _ = fs::remove_file(path);
}

#[test]
fn canonical_bytes_range_rejects_partial_checkpoint_range() {
    let path = unique_db_path("chio-receipts-partial-range");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    store
        .append_chio_receipt(&sample_receipt_with_id("rcpt-range-1"))
        .test_unwrap();
    store
        .append_chio_receipt(&sample_receipt_with_id_and_timestamp("rcpt-range-2", 2))
        .test_unwrap();
    let connection = store.connection().test_unwrap();
    connection
        .execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete;")
        .test_unwrap();
    connection
        .execute(
            "DELETE FROM claim_receipt_log_entries WHERE entry_seq = 2",
            [],
        )
        .test_unwrap();

    let error = store.receipts_canonical_bytes_range(1, 2).test_unwrap_err();

    assert!(error
        .to_string()
        .contains("claim receipt log has a gap in range 1..=2"));

    let _ = fs::remove_file(path);
}

#[test]
fn open_creates_kernel_checkpoints_table() {
    let path = unique_db_path("chio-receipts-cp-table");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    // Query the table to confirm it exists.
    let connection = store.connection().test_unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM kernel_checkpoints", [], |row| {
            row.get(0)
        })
        .test_unwrap();
    assert_eq!(count, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn open_creates_checkpoint_publication_metadata_table() {
    let path = unique_db_path("chio-receipts-cp-publication-table");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let connection = store.connection().test_unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM checkpoint_publication_metadata",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    assert_eq!(count, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn open_existing_missing_path_does_not_create_database_file() {
    let path = unique_db_path("chio-receipts-open-existing-missing");

    let error = SqliteReceiptStore::open_existing(&path).test_unwrap_err();
    assert!(matches!(
        error,
        chio_kernel::ReceiptStoreError::NotFound(message)
            if message.contains("does not exist")
    ));
    assert!(
        !path.exists(),
        "open_existing must not create {}",
        path.display()
    );
}

#[test]
fn open_existing_rejects_touched_empty_database_file() {
    let path = unique_db_path("chio-receipts-open-existing-empty");
    fs::write(&path, "").test_unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).test_unwrap();
    }

    let error = SqliteReceiptStore::open_existing(&path).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("not an initialized Chio receipt store"),
        "unexpected error: {error}"
    );
    assert!(
        path.exists(),
        "open_existing should refuse, not remove, an empty database file"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_pool_sizes_reject_zero_capacity() {
    let path = unique_db_path("chio-receipts-zero-pool");

    let reader_error = match SqliteReceiptStore::open_with_pool_sizes(&path, 0, 1) {
        Ok(_) => panic!("expected zero reader pool capacity to fail"),
        Err(error) => error,
    };
    assert!(matches!(
        reader_error,
        chio_kernel::ReceiptStoreError::Pool(message)
            if message.contains("reader receipt sqlite pool max_size")
    ));

    let writer_error = match SqliteReceiptStore::open_with_pool_sizes(&path, 1, 0) {
        Ok(_) => panic!("expected zero writer pool capacity to fail"),
        Err(error) => error,
    };
    assert!(matches!(
        writer_error,
        chio_kernel::ReceiptStoreError::Pool(message)
            if message.contains("writer receipt sqlite pool max_size")
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn open_existing_reinstalls_projection_guards() {
    // `SqliteReceiptStore::open_existing` runs
    // `ensure_transparency_projection_guards` against the connection it
    // opens, which must reinstall every immutability trigger that
    // protects the transparency projection rows. Drop a representative
    // subset before reopening and confirm the reopen restores the full
    // guard set.
    let path = unique_db_path("chio-receipts-open-existing-guards");

    let store = SqliteReceiptStore::open(&path).test_unwrap();
    store
        .append_chio_receipt(&sample_receipt_with_id("rcpt-open-existing-guards"))
        .test_unwrap();
    drop(store);

    let store = SqliteReceiptStore::open(&path).test_unwrap();
    for trigger in TRANSPARENCY_PROJECTION_GUARD_TRIGGER_NAMES {
        assert!(
            trigger_exists(&store, trigger),
            "trigger {trigger} should be present after initial open"
        );
    }

    let dropped_triggers: &[&str] = &[
        "chio_tool_receipts_reject_update",
        "chio_tool_receipts_reject_delete",
        "claim_receipt_log_entries_reject_update",
        "claim_receipt_log_entries_reject_delete",
    ];
    {
        let connection = store.connection().test_unwrap();
        for trigger in dropped_triggers {
            connection
                .execute_batch(&format!("DROP TRIGGER IF EXISTS {trigger};"))
                .test_unwrap();
        }
    }
    for trigger in dropped_triggers {
        assert!(
            !trigger_exists(&store, trigger),
            "trigger {trigger} should be absent after explicit drop"
        );
    }
    drop(store);

    let reopened = SqliteReceiptStore::open_existing(&path).test_unwrap();
    for trigger in TRANSPARENCY_PROJECTION_GUARD_TRIGGER_NAMES {
        assert!(
            trigger_exists(&reopened, trigger),
            "trigger {trigger} should be reinstalled by open_existing"
        );
    }

    let _ = fs::remove_file(path);
}
