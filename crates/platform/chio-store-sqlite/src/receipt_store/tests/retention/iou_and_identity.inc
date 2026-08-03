#[test]
fn co_archival_rejects_a_divergent_iou_copy() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::create_archive_schema;

    let path = unique_db_path("co-archival-iou-conflict");
    let archive = unique_db_path("co-archival-iou-conflict-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let kernel = super::support::receipt_test_keypair();
    let issuer = chio_core::crypto::Keypair::from_seed(&[93; 32]);

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&kernel, 2))?;
    let mut priced_body = super::support::sample_receipt_with_keypair_and_timestamp(
        "iou-conflict-priced",
        1,
        100,
        &kernel,
    )
    .body();
    priced_body.metadata = Some(serde_json::json!({
        "financial": priced_test_metadata(25)
    }));
    let priced = chio_core::receipt::body::ChioReceipt::sign(priced_body, &kernel)?;
    store.append_chio_receipt_returning_seq(&priced)?;
    let companion = super::support::sample_receipt_with_keypair_and_timestamp(
        "iou-conflict-companion",
        2,
        100,
        &kernel,
    );
    store.append_chio_receipt_returning_seq(&companion)?;
    store.flush_receipt_writes()?;

    let iou_store = SqliteIouEnvelopeStore::open_alongside(&store)?;
    let envelope = LocalCreditAccount::new_with_trusted_kernel_keys(
        chio_core::crypto::Ed25519Backend::new(issuer),
        [kernel.public_key()],
    )
    .evaluate(&priced)?
    .ok_or("priced receipt did not mint an IOU")?;
    assert!(iou_store.insert(&envelope)?);
    store.complete_settlement_reconciliation_exact(&priced.id, Some("transcript=iou"))?;

    let seeded = rusqlite::Connection::open_in_memory()?;
    let escaped_archive = archive_path.replace('\'', "''");
    seeded.execute_batch(&format!("ATTACH DATABASE '{escaped_archive}' AS archive"))?;
    create_archive_schema(&seeded)?;
    seeded.execute(
        "INSERT INTO archive.iou_envelope \
         (receipt_id, iou_id, receipt_timestamp, tenant_id, amount_units, currency, issuer_key, canonical_json) \
         VALUES (?1, 'divergent-iou', 100, NULL, 999, 'USD', 'divergent-key', '{}')",
        rusqlite::params![priced.id.as_str()],
    )?;
    drop(seeded);
    restrict_test_archive_file(&archive)?;

    let result = store.archive_receipts_before(150, archive_path);
    assert!(matches!(
        result,
        Err(ReceiptStoreError::RetentionArchiveIncomplete {
            table: "iou_envelope",
            ..
        })
    ));
    assert_eq!(store.tool_receipt_count()?, 2);
    assert_eq!(iou_store.get_by_receipt_id(&priced.id)?, Some(envelope));

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[cfg(unix)]
#[test]
fn first_rotation_reopens_all_evidence_from_the_recorded_path_before_delete(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, delete_archived_prefix_in_tx,
    };

    let path = unique_db_path("first-rotation-path-swap");
    let archive = unique_db_path("first-rotation-path-swap-archive");
    let displaced = unique_db_path("first-rotation-path-swap-displaced");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let displaced_path = displaced.to_str().ok_or("displaced path invalid")?;
    let kernel = super::support::receipt_test_keypair();
    let issuer = chio_core::crypto::Keypair::from_seed(&[94; 32]);

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&kernel, 2))?;
    let mut priced_body = super::support::sample_receipt_with_keypair_and_timestamp(
        "first-path-swap-priced",
        1,
        100,
        &kernel,
    )
    .body();
    priced_body.metadata = Some(serde_json::json!({
        "financial": priced_test_metadata(30)
    }));
    let priced = chio_core::receipt::body::ChioReceipt::sign(priced_body, &kernel)?;
    store.append_chio_receipt_returning_seq(&priced)?;
    let companion = super::support::sample_receipt_with_keypair_and_timestamp(
        "first-path-swap-companion",
        2,
        100,
        &kernel,
    );
    store.append_chio_receipt_returning_seq(&companion)?;
    store.flush_receipt_writes()?;
    let iou_store = SqliteIouEnvelopeStore::open_alongside(&store)?;
    let envelope = LocalCreditAccount::new_with_trusted_kernel_keys(
        chio_core::crypto::Ed25519Backend::new(issuer),
        [kernel.public_key()],
    )
    .evaluate(&priced)?
    .ok_or("priced receipt did not mint an IOU")?;
    assert!(iou_store.insert(&envelope)?);
    store.complete_settlement_reconciliation_exact(&priced.id, Some("transcript=path-swap"))?;
    provision_test_archive_file(&archive)?;

    let refused = store.writer_handle().run_write({
        let archive_path = archive_path.to_string();
        let displaced_path = displaced_path.to_string();
        let priced_id = priced.id.clone();
        move |connection| {
            let escaped = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            create_archive_schema(connection)?;
            let archive_identity =
                crate::receipt_store::support::ensure_attached_retention_archive_identity(
                    connection, None,
                )?;
            copy_archived_prefix(connection, 2)?;
            let archive_content_sha256 =
                crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
                    connection, "archive", 2,
                )?;
            connection.execute_batch("DETACH DATABASE archive")?;

            // Preserve the faithful archive under a displaced pathname. Put a
            // byte-for-byte copy back at the recorded path, then remove only
            // its IOU. Its signed claim-log roots remain valid, so a root-only
            // path check would pass while the complete evidence contract does not.
            std::fs::rename(&archive_path, &displaced_path)?;
            std::fs::copy(&displaced_path, &archive_path)?;
            let replacement = rusqlite::Connection::open(&archive_path)?;
            let removed = replacement.execute(
                "DELETE FROM iou_envelope WHERE receipt_id = ?1",
                rusqlite::params![priced_id],
            )?;
            if removed != 1 {
                return Err(ReceiptStoreError::Conflict(
                    "replacement archive did not contain the expected IOU".to_string(),
                ));
            }
            drop(replacement);
            restrict_test_archive_file(std::path::Path::new(&archive_path))?;

            let result = delete_archived_prefix_in_tx(
                connection,
                0,
                2,
                150,
                &archive_path,
                &archive_identity,
                None,
                &archive_content_sha256,
            );
            Ok(matches!(
                result,
                Err(ReceiptStoreError::Conflict(message))
                    if message.contains("canonical content digest")
            ))
        }
    })?;
    assert!(
        refused,
        "rotation must reject a pathname replacement before deleting live evidence"
    );
    assert_eq!(
        store.tool_receipt_count()?,
        2,
        "the first-rotation prefix must survive the replaced archive path"
    );
    assert_eq!(iou_store.get_by_receipt_id(&priced.id)?, Some(envelope));

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    let _ = std::fs::remove_file(&displaced);
    Ok(())
}

#[test]
fn later_rotation_rejects_a_divergent_recorded_archive_suffix(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, delete_archived_prefix_in_tx,
    };
    use crate::receipt_store::support::retention_watermark;

    let path = unique_db_path("later-rotation-divergent-suffix");
    let archive = unique_db_path("later-rotation-divergent-suffix-archive");
    let faithful = unique_db_path("later-rotation-divergent-suffix-faithful");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let faithful_path = faithful.to_str().ok_or("faithful path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;

    for index in 0..4_u64 {
        let timestamp = if index < 2 { 100 } else { 200 };
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("later-rotation-divergent-suffix-{index}"),
            index + 1,
            timestamp,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert_eq!(store.archive_receipts_before(150, archive_path)?, 2);

    let refused = store.writer_handle().run_write({
        let archive_path = archive_path.to_string();
        let faithful_path = faithful_path.to_string();
        move |connection| {
            let escaped_archive = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped_archive}' AS archive"))?;
            create_archive_schema(connection)?;
            let expected_identity =
                crate::receipt_store::support::latest_watermark_archive_sha256(connection)?;
            let previous_archive_content_sha256 =
                crate::receipt_store::support::latest_watermark_archive_content_sha256(connection)?;
            let archive_identity =
                crate::receipt_store::support::ensure_attached_retention_archive_identity(
                    connection,
                    expected_identity.as_deref(),
                )?;
            copy_archived_prefix(connection, 4)?;
            let archive_content_sha256 =
                crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
                    connection, "archive", 4,
                )?;
            connection.execute_batch("DETACH DATABASE archive")?;

            std::fs::copy(&archive_path, &faithful_path)?;
            let replacement = rusqlite::Connection::open(&archive_path)?;
            let changed = replacement.execute(
                "UPDATE chio_tool_receipts SET raw_json = '{\"divergent\":true}' WHERE seq = 3",
                [],
            )?;
            if changed != 1 {
                return Err(ReceiptStoreError::Conflict(
                    "recorded archive did not contain the expected suffix row".to_string(),
                ));
            }
            drop(replacement);
            restrict_test_archive_file(std::path::Path::new(&archive_path))?;

            let result = delete_archived_prefix_in_tx(
                connection,
                2,
                4,
                250,
                &archive_path,
                &archive_identity,
                previous_archive_content_sha256.as_deref(),
                &archive_content_sha256,
            );
            Ok(matches!(
                result,
                Err(ReceiptStoreError::Conflict(message))
                    if message.contains("canonical content digest")
            ))
        }
    })?;
    assert!(
        refused,
        "the final verifier must reject a divergent newly copied archive suffix"
    );

    let live = store.reader_connection_for_test()?;
    assert_eq!(retention_watermark(&live)?, Some(2));
    let surviving_suffix: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq > 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(surviving_suffix, 2);

    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    let _ = std::fs::remove_file(&faithful);
    Ok(())
}

/// The writer's original `archive` attachment remains bound to its opened inode
/// after the recorded pathname is replaced. The final verifier must open that
/// pathname itself with NOFOLLOW. Otherwise a symlink to the live database can
/// make a live-primary verifier attach and compare the live file against itself,
/// then delete evidence whose recorded archive path never held it.
#[cfg(unix)]
#[test]
fn first_rotation_rejects_archive_symlink_at_the_final_verifier_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, delete_archived_prefix_in_tx,
    };
    use crate::receipt_store::support::retention_watermark;

    let path = unique_db_path("first-rotation-final-symlink");
    let archive = unique_db_path("first-rotation-final-symlink-archive");
    let displaced = unique_db_path("first-rotation-final-symlink-displaced");
    let live_path = path.to_str().ok_or("live path invalid")?;
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let displaced_path = displaced.to_str().ok_or("displaced path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for index in 0..2_u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("first-final-symlink-{index}"),
            index + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    provision_test_archive_file(&archive)?;
    let refused = store.writer_handle().run_write({
        let live_path = live_path.to_string();
        let archive_path = archive_path.to_string();
        let displaced_path = displaced_path.to_string();
        move |connection| {
            let escaped_archive = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped_archive}' AS archive"))?;
            create_archive_schema(connection)?;
            let archive_identity =
                crate::receipt_store::support::ensure_attached_retention_archive_identity(
                    connection, None,
                )?;
            copy_archived_prefix(connection, 2)?;
            let archive_content_sha256 =
                crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
                    connection, "archive", 2,
                )?;
            connection.execute_batch("DETACH DATABASE archive")?;

            // Preserve the faithful inode under its displaced name, but replace
            // the pathname that would be recorded with a symlink to the live
            // database. The final locked alias check must refuse the link before
            // any live delete starts.
            std::fs::rename(&archive_path, &displaced_path)?;
            std::os::unix::fs::symlink(&live_path, &archive_path)?;
            let result = delete_archived_prefix_in_tx(
                connection,
                0,
                2,
                150,
                &archive_path,
                &archive_identity,
                None,
                &archive_content_sha256,
            );
            Ok(matches!(
                result,
                Err(ReceiptStoreError::Conflict(message))
                    if message.contains("without following links")
                        || message.contains("trusted durable database file")
            ))
        }
    })?;
    assert!(
        refused,
        "the final verifier must reject an archive symlink before deleting live evidence"
    );
    assert_eq!(
        store.tool_receipt_count()?,
        2,
        "the live receipt prefix must survive the rejected archive symlink"
    );
    let live = store.reader_connection_for_test()?;
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "the live claim-log prefix must survive the rejected archive symlink"
    );
    assert_eq!(
        retention_watermark(&live)?,
        None,
        "a rejected archive symlink must not record a retention watermark"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    let _ = std::fs::remove_file(&displaced);
    Ok(())
}

#[cfg(unix)]
#[test]
fn first_rotation_rejects_archive_hardlink_to_the_live_database_under_final_lock(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, delete_archived_prefix_in_tx,
    };
    use crate::receipt_store::support::retention_watermark;

    let path = unique_db_path("first-rotation-final-hardlink");
    let archive = unique_db_path("first-rotation-final-hardlink-archive");
    let displaced = unique_db_path("first-rotation-final-hardlink-displaced");
    let live_path = path.to_str().ok_or("live path invalid")?;
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let displaced_path = displaced.to_str().ok_or("displaced path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for index in 0..2_u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("first-final-hardlink-{index}"),
            index + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    provision_test_archive_file(&archive)?;
    let live_schema_before = {
        let live = store.reader_connection_for_test()?;
        let mut statement =
            live.prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;
        let mut schema = Vec::new();
        for row in rows {
            schema.push(row?);
        }
        schema
    };

    let refused = store.writer_handle().run_write({
        let live_path = live_path.to_string();
        let archive_path = archive_path.to_string();
        let displaced_path = displaced_path.to_string();
        move |connection| {
            let escaped_archive = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped_archive}' AS archive"))?;
            create_archive_schema(connection)?;
            let archive_identity =
                crate::receipt_store::support::ensure_attached_retention_archive_identity(
                    connection, None,
                )?;
            copy_archived_prefix(connection, 2)?;
            let archive_content_sha256 =
                crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
                    connection, "archive", 2,
                )?;
            connection.execute_batch("DETACH DATABASE archive")?;

            // Replace the recorded pathname with a hard link to the live
            // database after the earlier preflight. The final check must compare
            // device/inode under the live lock because WAL writer locks use
            // pathname-derived sidecars and do not reliably detect this alias.
            std::fs::rename(&archive_path, &displaced_path)?;
            std::fs::hard_link(&live_path, &archive_path)?;
            let result = delete_archived_prefix_in_tx(
                connection,
                0,
                2,
                150,
                &archive_path,
                &archive_identity,
                None,
                &archive_content_sha256,
            );
            // Restore the live database's single-link identity before the writer
            // actor resynchronizes its head after this deterministic boundary.
            std::fs::remove_file(&archive_path)?;
            Ok(matches!(
                result,
                Err(ReceiptStoreError::Conflict(message))
                    if message.contains("trusted durable database file")
            ))
        }
    })?;
    assert!(
        refused,
        "the final live lock must reject an archive pathname hard-linked to the live database"
    );
    assert_eq!(
        store.tool_receipt_count()?,
        2,
        "a rejected archive hardlink must leave live source receipts intact"
    );
    let live = store.reader_connection_for_test()?;
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "a rejected archive hardlink must leave the live claim log intact"
    );
    assert_eq!(
        retention_watermark(&live)?,
        None,
        "a rejected archive hardlink must not record a retention watermark"
    );
    let live_schema_after = {
        let mut statement =
            live.prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;
        let mut schema = Vec::new();
        for row in rows {
            schema.push(row?);
        }
        schema
    };
    assert_eq!(
        live_schema_after, live_schema_before,
        "a rejected archive hardlink must not write archive identity objects into live sqlite_master"
    );

    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    let _ = std::fs::remove_file(&displaced);
    Ok(())
}

/// The archive-path pin is checked before the delete transaction takes the write
/// lock, so two store handles rotating concurrently to DIFFERENT archives can
/// split the prefix: one commits `[1, W1]` to archive A after the outer check,
/// then the other copies only the surviving suffix to archive B and records a
/// higher watermark naming B, leaving the ledger pointing at a file that lacks
/// the earlier prefix. The delete must re-read and re-enforce the ledger archive
/// path AFTER acquiring the write lock and fail closed, so the split is caught
/// and the surviving suffix is preserved for a later rotation.
#[test]
fn delete_rechecks_archive_path_under_the_write_lock() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, delete_archived_prefix_in_tx,
    };
    let path = unique_db_path("toctou-path-split");
    let archive_a = unique_db_path("toctou-path-split-a");
    let archive_b = unique_db_path("toctou-path-split-b");
    let archive_a_path = archive_a.to_str().ok_or("archive path invalid")?;
    let archive_b_path = archive_b.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    // Two aged batches: [1,2] at timestamp 100, [3,4] at timestamp 200.
    for i in 0..2u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("a-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    for i in 2..4u64 {
        let r = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("b-{i}"),
            i + 1,
            200,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&r)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(2)?.is_some());

    // A concurrent rotation commits [1,2] to archive A: the ledger now pins the
    // archive path to A and the live prefix [1,2] is gone.
    let first = store.archive_receipts_before(150, archive_a_path)?;
    assert_eq!(first, 2, "the aged [1,2] batch archives to A");
    provision_test_archive_file(&archive_b)?;

    // This rotation, in flight against a DIFFERENT archive B, has already copied
    // the surviving suffix [3,4] into B and now reaches its locked delete for
    // W=4. Under the write lock the ledger names A, so the delete must refuse the
    // path split rather than strand [1,2] in A behind a ledger pointing at B.
    let refusal = store.writer_handle().run_write({
        let archive_b_path = archive_b_path.to_string();
        move |connection| {
            let escaped = archive_b_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            create_archive_schema(connection)?;
            let archive_identity =
                crate::receipt_store::support::ensure_attached_retention_archive_identity(
                    connection, None,
                )?;
            copy_archived_prefix(connection, 4)?;
            let archive_content_sha256 =
                crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
                    connection, "archive", 4,
                )?;
            let previous_archive_content_sha256 =
                crate::receipt_store::support::latest_watermark_archive_content_sha256(connection)?;
            connection.execute_batch("DETACH DATABASE archive")?;
            restrict_test_archive_file(std::path::Path::new(&archive_b_path))?;
            let result = delete_archived_prefix_in_tx(
                connection,
                2,
                4,
                250,
                &archive_b_path,
                &archive_identity,
                previous_archive_content_sha256.as_deref(),
                &archive_content_sha256,
            );
            Ok(result.err().map(|error| error.to_string()))
        }
    })?;
    let message = refusal
        .ok_or("the delete must fail closed when a concurrent rotation split the archive path")?;
    assert!(
        message.contains("differs from the archive"),
        "expected the archive-path pin to fire under the write lock, got: {message}"
    );

    // Fail-closed: the surviving [3,4] suffix is intact for a later rotation.
    let live = store.reader_connection_for_test()?;
    let live_log: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq > 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_log, 2,
        "no [3,4] rows may be deleted when the locked path re-check rejects the split"
    );

    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive_a);
    let _ = std::fs::remove_file(&archive_b);
    Ok(())
}

/// A governed receipt's lineage statement must travel into the archive with the
/// receipt. The delete leaves the live lineage row in place (like capability
/// lineage), so the archive becomes the standalone copy: opening it must still
/// surface the archived receipt's call-chain provenance.
#[test]
fn governed_receipt_lineage_is_co_archived() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("lineage-archived");
    let archive = unique_db_path("lineage-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("lineage-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // Persist a lineage statement for the first receipt, the shape a governed
    // call-chain receipt records on append. It sits in the archived range
    // because its receipt does.
    let receipt_id = super::support::first_tool_receipt_id(&store)?;
    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO receipt_lineage_statements \
                 (receipt_id, statement_id, request_id, session_id, session_anchor_id, chain_id, \
                  parent_request_id, parent_receipt_id, evidence_class, evidence_sources_json, \
                  verified_session_anchor, verified_parent_request, verified_parent_receipt, \
                  replay_protected, recorded_at, source_kind, json_sha256, raw_json) \
                 VALUES (?1, 'stmt-lineage-0', NULL, NULL, NULL, 'chain-lineage-0', NULL, \
                         'parent-receipt-lineage-0', 'delegated', NULL, 0, 0, 1, 0, 100, 'test', \
                         'sha-lineage-0', '{\"schema\":\"lineage\"}')",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;

    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 2);

    // The live lineage row survives (not cascaded away).
    let live = store.reader_connection_for_test()?;
    let live_lineage: i64 = live.query_row(
        "SELECT COUNT(*) FROM receipt_lineage_statements WHERE receipt_id = ?1",
        rusqlite::params![receipt_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        live_lineage, 1,
        "the live lineage row must survive rotation"
    );

    // The archive holds a faithful copy, so the archived receipt keeps its
    // provenance when the archive is opened standalone.
    let archive_store = SqliteReceiptStore::open_existing(&archive)?;
    let arch = archive_store.reader_connection_for_test()?;
    let (arch_lineage, arch_chain, arch_parent): (i64, Option<String>, Option<String>) = arch
        .query_row(
            "SELECT COUNT(*), MAX(chain_id), MAX(parent_receipt_id) \
             FROM receipt_lineage_statements WHERE receipt_id = ?1",
            rusqlite::params![receipt_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    assert_eq!(
        arch_lineage, 1,
        "the governed receipt's lineage statement must be co-archived"
    );
    assert_eq!(arch_chain.as_deref(), Some("chain-lineage-0"));
    assert_eq!(arch_parent.as_deref(), Some("parent-receipt-lineage-0"));

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}
