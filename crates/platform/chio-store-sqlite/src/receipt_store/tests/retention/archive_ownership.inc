#[cfg(unix)]
#[test]
fn rotation_commit_guard_blocks_a_transient_hardlink_alias_writer(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::delete_archived_prefix_in_tx_with_precommit_boundary_for_test;

    let (directory, store, _path, archive, identity, content) =
        prepare_archive_commit_guard_fixture("rotation-transient-hardlink-writer")?;
    let archive_path = archive.to_str().ok_or("archive path invalid")?.to_string();
    let alias = directory.path().join("transient-archive-alias.sqlite3");

    store.writer_handle().run_write({
        let archive_path = archive_path.clone();
        move |connection| {
            let boundary_path = archive_path.clone();
            let boundary_alias = alias.clone();
            delete_archived_prefix_in_tx_with_precommit_boundary_for_test(
                connection,
                0,
                2,
                150,
                &archive_path,
                &identity,
                None,
                &content,
                move || {
                    std::fs::hard_link(&boundary_path, &boundary_alias)?;
                    let alias_write_succeeded = (|| -> rusqlite::Result<usize> {
                        let writer = rusqlite::Connection::open(&boundary_alias)?;
                        writer.busy_timeout(std::time::Duration::ZERO)?;
                        writer.execute(
                            "UPDATE chio_retention_archive_identity SET nonce = nonce \
                             WHERE identity_slot = 1",
                            [],
                        )
                    })()
                    .is_ok();
                    std::fs::remove_file(&boundary_alias)?;
                    if alias_write_succeeded {
                        return Err(ReceiptStoreError::Conflict(
                            "transient archive hardlink bypassed inode ownership".to_string(),
                        ));
                    }
                    Ok(())
                },
            )
        }
    })?;

    assert_eq!(store.tool_receipt_count()?, 0);
    let live = store.reader_connection_for_test()?;
    assert_eq!(
        crate::receipt_store::support::retention_watermark(&live)?,
        Some(2)
    );
    let archive_connection = rusqlite::Connection::open(&archive)?;
    let journal_mode: String =
        archive_connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    assert!(journal_mode.eq_ignore_ascii_case("delete"));
    Ok(())
}

#[test]
fn attached_archive_transaction_cleans_up_after_body_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::with_attached_retention_archive_transaction;

    let directory = tempfile::tempdir()?;
    let archive = directory.path().join("body-failure-archive.sqlite3");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let mut connection = rusqlite::Connection::open_in_memory()?;
    connection.execute_batch(
        "CREATE TABLE live_probe (value INTEGER NOT NULL); \
         INSERT INTO live_probe (value) VALUES (1)",
    )?;

    let failed: Result<(), ReceiptStoreError> = with_attached_retention_archive_transaction(
        &mut connection,
        archive_path,
        |connection| {
            connection.execute_batch(
                "CREATE TABLE archive.uncommitted_probe (value INTEGER NOT NULL); \
                 INSERT INTO archive.uncommitted_probe (value) VALUES (1)",
            )?;
            Err(ReceiptStoreError::Conflict(
                "injected archive body failure".to_string(),
            ))
        },
    );
    let error = match failed {
        Ok(()) => return Err("archive body failure unexpectedly succeeded".into()),
        Err(error) => error,
    };
    assert!(error.to_string().contains("injected archive body failure"));
    assert!(connection.is_autocommit());
    let archive_attached = crate::receipt_store::bootstrap::open::sqlite_database_list(&connection)?
        .into_iter()
        .any(|(_, name, _)| name == "archive");
    assert!(!archive_attached);

    connection.execute_batch(
        "BEGIN IMMEDIATE; \
         INSERT INTO live_probe (value) VALUES (2); \
         COMMIT",
    )?;
    assert_eq!(
        connection.query_row("SELECT SUM(value) FROM live_probe", [], |row| {
            row.get::<_, i64>(0)
        })?,
        3
    );
    let archive_connection = rusqlite::Connection::open(&archive)?;
    let uncommitted_table: i64 = archive_connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master \
         WHERE type = 'table' AND name = 'uncommitted_probe')",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(uncommitted_table, 0);
    Ok(())
}

#[test]
fn attached_archive_transaction_rejects_a_caller_transaction_without_mutating_it(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::with_attached_retention_archive_transaction;

    let directory = tempfile::tempdir()?;
    let archive = directory.path().join("caller-transaction-archive.sqlite3");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let mut connection = rusqlite::Connection::open_in_memory()?;
    connection.execute_batch(
        "CREATE TABLE live_probe (value INTEGER NOT NULL); \
         BEGIN IMMEDIATE; \
         INSERT INTO live_probe (value) VALUES (7)",
    )?;

    let refused: Result<(), ReceiptStoreError> = with_attached_retention_archive_transaction(
        &mut connection,
        archive_path,
        |_connection| Ok(()),
    );
    let error = match refused {
        Ok(()) => return Err("archive attachment accepted a caller transaction".into()),
        Err(error) => error,
    };
    assert!(error.to_string().contains("requires an autocommit connection"));
    assert!(!connection.is_autocommit());
    assert!(!archive.exists());
    let archive_attached = crate::receipt_store::bootstrap::open::sqlite_database_list(&connection)?
        .into_iter()
        .any(|(_, name, _)| name == "archive");
    assert!(!archive_attached);

    connection.execute_batch("COMMIT")?;
    assert_eq!(
        connection.query_row("SELECT value FROM live_probe", [], |row| {
            row.get::<_, i64>(0)
        })?,
        7
    );
    Ok(())
}
