use std::time::{Duration, Instant};

use chio_credit::{CreditEvaluatorHook, IouEnvelopeStore, LocalCreditAccount};
use chio_kernel::{ReceiptStore, ReceiptStoreError, RetentionConfig};

use crate::{SqliteIouEnvelopeStore, SqliteReceiptStore};

const TEST_ARCHIVE_IDENTITY_SHA256: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TEST_ARCHIVE_CONTENT_SHA256: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    chio_test_support::private_fs::unique_sqlite_path(&format!("chio-{prefix}"))
}

fn install_test_archive_identity(
    connection: &rusqlite::Connection,
    schema: &str,
    nonce: &str,
) -> Result<String, ReceiptStoreError> {
    let schema = match schema {
        "archive" | "archive_a" | "archive_b" | "supplied" => schema,
        _ => {
            return Err(ReceiptStoreError::Conflict(format!(
                "invalid test archive schema {schema:?}"
            )))
        }
    };
    connection.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {schema}.chio_retention_archive_identity ( \
             identity_slot INTEGER PRIMARY KEY CHECK (identity_slot = 1), \
             nonce TEXT NOT NULL UNIQUE, commitment_sha256 TEXT NOT NULL UNIQUE)"
    ))?;
    let material = format!("chio.retention-archive.identity.v1\0{nonce}");
    let commitment = chio_core::sha256(material.as_bytes()).to_hex();
    connection.execute(
        &format!(
            "INSERT INTO {schema}.chio_retention_archive_identity \
                 (identity_slot, nonce, commitment_sha256) VALUES (1, ?1, ?2)"
        ),
        rusqlite::params![nonce, commitment.as_str()],
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let database_path = crate::receipt_store::bootstrap::open::sqlite_database_list(connection)?
            .into_iter()
            .find(|(_, name, _)| name == schema)
            .and_then(|(_, _, path)| path)
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(format!(
                    "test archive schema {schema:?} has no durable database path"
                ))
            })?;
        std::fs::set_permissions(database_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(commitment)
}

#[cfg(unix)]
fn restrict_test_archive_file(path: &std::path::Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_test_archive_file(_path: &std::path::Path) -> Result<(), std::io::Error> {
    Ok(())
}

fn provision_test_archive_file(
    path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = crate::durable_sqlite::TrustedSqliteDirectory::open_for_database(path)?;
    directory
        .open_database(path, true)?
        .sync_file_and_directory()?;
    Ok(())
}

fn prepare_archive_commit_guard_fixture(
    prefix: &str,
) -> Result<
    (
        tempfile::TempDir,
        SqliteReceiptStore,
        std::path::PathBuf,
        std::path::PathBuf,
        String,
        String,
    ),
    Box<dyn std::error::Error>,
> {
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, retention_archive_prefix_content_sha256,
    };

    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    // The live writer connection carries SQLITE_OPEN_NOFOLLOW, which rejects
    // any symlink path component on ATTACH (macOS `/var` -> `private/var`), so
    // the fixture paths must be canonical.
    let base = std::fs::canonicalize(directory.path())?;
    let path = base.join(format!("{prefix}-live.sqlite3"));
    let archive = base.join(format!("{prefix}-archive.sqlite3"));
    let archive_path = archive.to_str().ok_or("archive path invalid")?.to_string();
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for index in 0..2_u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("{prefix}-{index}"),
            index + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    provision_test_archive_file(&archive)?;
    let (identity, content) = store.writer_handle().run_write({
        let archive_path = archive_path.clone();
        move |connection| {
            let escaped = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            create_archive_schema(connection)?;
            let identity =
                crate::receipt_store::support::ensure_attached_retention_archive_identity(
                    connection, None,
                )?;
            copy_archived_prefix(connection, 2)?;
            let content = retention_archive_prefix_content_sha256(connection, "archive", 2)?;
            connection.execute_batch("DETACH DATABASE archive")?;
            Ok((identity, content))
        }
    })?;
    restrict_test_archive_file(&archive)?;
    Ok((directory, store, path, archive, identity, content))
}

fn install_fresh_test_archive_identity(
    connection: &rusqlite::Connection,
) -> Result<String, ReceiptStoreError> {
    let nonce = uuid::Uuid::now_v7().to_string();
    install_test_archive_identity(connection, "archive", &nonce)
}

fn priced_test_metadata(cost_charged: u64) -> super::support::FinancialReceiptMetadata {
    super::support::FinancialReceiptMetadata {
        grant_index: 0,
        cost_charged,
        currency: "USD".to_string(),
        budget_remaining: 1_000_u64.saturating_sub(cost_charged),
        budget_total: 1_000,
        delegation_depth: 0,
        root_budget_holder: "retention-test-budget-holder".to_string(),
        payment_reference: None,
        settlement_status: super::support::SettlementStatus::Pending,
        cost_breakdown: None,
        oracle_evidence: None,
        attempted_cost: None,
    }
}

#[test]
fn watermark_ledger_reports_max_and_rejects_regression() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::{insert_receipt_retention_watermark, retention_watermark};
    let path = unique_db_path("watermark-ledger");
    let store = SqliteReceiptStore::open(&path)?;
    // A pristine store has never archived.
    let connection = store.reader_connection_for_test()?;
    assert_eq!(retention_watermark(&connection)?, None);

    insert_receipt_retention_watermark(
        &connection,
        10,
        100,
        "archive.sqlite3",
        TEST_ARCHIVE_IDENTITY_SHA256,
        TEST_ARCHIVE_CONTENT_SHA256,
        1,
    )?;
    insert_receipt_retention_watermark(
        &connection,
        25,
        200,
        "archive.sqlite3",
        TEST_ARCHIVE_IDENTITY_SHA256,
        TEST_ARCHIVE_CONTENT_SHA256,
        2,
    )?;
    assert_eq!(retention_watermark(&connection)?, Some(25));

    // A rotation that would lower the watermark is rejected fail-closed.
    let regression = insert_receipt_retention_watermark(
        &connection,
        20,
        300,
        "archive.sqlite3",
        TEST_ARCHIVE_IDENTITY_SHA256,
        TEST_ARCHIVE_CONTENT_SHA256,
        3,
    );
    let message = regression
        .err()
        .ok_or("expected RetentionWatermarkRegression")?
        .to_string();
    assert!(
        message.contains("retention watermark regression"),
        "unexpected error: {message}"
    );
    // The rejected write left the ledger unchanged.
    assert_eq!(retention_watermark(&connection)?, Some(25));

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn watermark_schema_requires_archive_content_digest() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("watermark-content-digest-schema");
    let store = SqliteReceiptStore::open(&path)?;
    let connection = store.reader_connection_for_test()?;
    let (column_type, not_null): (String, i64) = connection.query_row(
        "SELECT type, \"notnull\" FROM pragma_table_info('receipt_retention_watermark') \
         WHERE name = 'archive_content_sha256'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(column_type, "TEXT");
    assert_eq!(not_null, 1, "archive content commitment must be mandatory");

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn backfill_refuses_regeneration_over_checkpointed_range() -> Result<(), Box<dyn std::error::Error>>
{
    use crate::receipt_store::support::validate_or_backfill_claim_receipt_log_entries;

    let path = unique_db_path("backfill-refuse");
    {
        let store = SqliteReceiptStore::open(&path)?;
        let keypair = super::support::receipt_test_keypair();
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        for i in 0..2u64 {
            let receipt =
                super::support::sample_receipt_with_keypair(&format!("bf-{i}"), i + 1, &keypair);
            store.append_chio_receipt_returning_seq(&receipt)?;
        }
        store.flush_receipt_writes()?;
        // A checkpoint now covers [1, 2].
        assert!(store.load_checkpoint_by_seq(1)?.is_some());
    }

    // Simulate a botched manual repair: empty the projection on a checkpointed
    // store by dropping the reject-delete guard and deleting the rows.
    let store = SqliteReceiptStore::open_existing(&path)?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete; \
             DELETE FROM claim_receipt_log_entries;",
        )?;
        Ok(())
    })?;

    let connection = store.reader_connection_for_test()?;
    let error = validate_or_backfill_claim_receipt_log_entries(&connection, true);
    let message = error
        .err()
        .ok_or("expected ArchivedRangeProjection, backfill regenerated instead")?
        .to_string();
    assert!(
        message.contains("checkpointed or archived range"),
        "unexpected error: {message}"
    );
    // `chio receipt retention repair` only removes claim-log rows whose source
    // rows are already gone; with an empty projection it removes nothing and
    // leaves the store bricked, so the guidance must not point there. It must
    // name an applicable recovery instead.
    assert!(
        !message.contains("retention repair"),
        "must not point at the no-op retention repair for a missing projection: {message}"
    );
    assert!(
        message.contains("restore") && message.contains("backup"),
        "must direct operators to an applicable recovery path: {message}"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Append two aged receipts (timestamp 100) checkpointed as [1,2] and four
/// fresh receipts (timestamp 500) checkpointed as [3,4] with 5..6 left
/// uncheckpointed, then genuinely archive the aged range so a real archive holds
/// the co-archived `[1, 2]` prefix and the live rows are deleted with the
/// watermark set to 2.
fn store_with_archived_first_checkpoint(
    path: &std::path::Path,
    archive_path: &str,
    keypair: &chio_core::crypto::Keypair,
) -> Result<SqliteReceiptStore, Box<dyn std::error::Error>> {
    let store = SqliteReceiptStore::open(path)?;
    store.enable_background_checkpoints(super::support::signer(keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("ce-aged-{i}"),
            i + 1,
            100,
            keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    for i in 2..6u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("ce-fresh-{i}"),
            i + 1,
            500,
            keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert!(store.load_checkpoint_by_seq(2)?.is_some());

    // Archive only the aged first checkpoint's range [1,2]: the rows move to a
    // real archive, the live prefix is deleted, and the ledger records W=2.
    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 2, "only the aged [1,2] batch archives");
    Ok(store)
}

#[test]
fn authoritative_point_load_resolves_archived_receipt_after_rotation_and_reopen(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("archived-point-load");
    let archive = unique_db_path("archived-point-load-archive");
    let archive_path = archive.to_str().ok_or("archive path is not valid utf-8")?;
    let keypair = super::support::receipt_test_keypair();
    let archived_receipt = super::support::sample_receipt_with_keypair_and_timestamp(
        "archived-point-load-receipt",
        1,
        100,
        &keypair,
    );

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 1))?;
        store.append_chio_receipt_returning_seq(&archived_receipt)?;
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(1)?.is_some());
        assert_eq!(store.archive_receipts_before(150, archive_path)?, 1);

        let connection = store.reader_connection_for_test()?;
        let live_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM chio_tool_receipts WHERE receipt_id = ?1",
            rusqlite::params![archived_receipt.id],
            |row| row.get(0),
        )?;
        assert_eq!(live_count, 0, "rotation must remove the live source row");
        drop(connection);

        let loaded = store
            .load_chio_receipt(&archived_receipt.id)?
            .ok_or("trusted archive lookup missed the archived receipt")?;
        assert_eq!(
            serde_json::to_value(&loaded)?,
            serde_json::to_value(&archived_receipt)?,
            "authoritative lookup must return the exact archived receipt"
        );
    }

    let reopened = SqliteReceiptStore::open(&path)?;
    let loaded = reopened
        .load_chio_receipt(&archived_receipt.id)?
        .ok_or("reopened trusted archive lookup missed the archived receipt")?;
    assert_eq!(
        serde_json::to_value(&loaded)?,
        serde_json::to_value(&archived_receipt)?,
        "exact archive fallback must survive a live-store restart"
    );
    assert!(
        reopened
            .load_chio_receipt("never-committed-receipt")?
            .is_none(),
        "a genuine miss must remain distinguishable from an archived id"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn positive_legacy_watermark_without_content_digest_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::{
        ensure_receipt_retention_watermark_table, load_trusted_archived_chio_receipt,
        trusted_retention_watermark, verify_checkpoint_chain_integrity,
    };

    let path = unique_db_path("legacy-watermark-missing-content");
    let archive = unique_db_path("legacy-watermark-missing-content-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
        "legacy-watermark-missing-content-receipt",
        1,
        100,
        &keypair,
    );
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 1))?;
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;
    assert_eq!(store.archive_receipts_before(150, archive_path)?, 1);

    // Simulate a positive legacy watermark with a nullable, absent content
    // commitment. The production schema cannot represent this state, so build
    // the weakened legacy table explicitly after the real rotation.
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER receipt_retention_watermark_reject_update; \
             DROP TRIGGER receipt_retention_watermark_reject_delete; \
             DROP TRIGGER receipt_retention_watermark_reject_regression; \
             ALTER TABLE receipt_retention_watermark RENAME TO retention_watermark_bound; \
             CREATE TABLE receipt_retention_watermark ( \
                 archived_through_entry_seq INTEGER NOT NULL, \
                 archived_through_timestamp INTEGER NOT NULL, \
                 archive_path TEXT NOT NULL, \
                 archive_sha256 TEXT NOT NULL, \
                 archive_content_sha256 TEXT, \
                 rotated_at INTEGER NOT NULL, \
                 CHECK (archived_through_entry_seq >= 0)); \
             INSERT INTO receipt_retention_watermark \
                 (archived_through_entry_seq, archived_through_timestamp, archive_path, \
                  archive_sha256, archive_content_sha256, rotated_at) \
             SELECT archived_through_entry_seq, archived_through_timestamp, archive_path, \
                    archive_sha256, NULL, rotated_at FROM retention_watermark_bound; \
             DROP TABLE retention_watermark_bound;",
        )?;
        Ok(())
    })?;

    let schema_rejected = store.writer_handle().run_write(|connection| {
        Ok(ensure_receipt_retention_watermark_table(connection).is_err())
    })?;
    assert!(
        schema_rejected,
        "writable schema validation must reject a nullable legacy content digest"
    );
    let live = store.reader_connection_for_test()?;
    assert!(
        trusted_retention_watermark(&live).is_err(),
        "a positive watermark without content binding must not produce a trusted floor"
    );
    assert!(
        verify_checkpoint_chain_integrity(&live).is_err(),
        "chain verification must reject a missing archive content commitment"
    );
    assert!(
        load_trusted_archived_chio_receipt(&live, &receipt.id).is_err(),
        "archived point lookup must reject a missing archive content commitment"
    );

    drop(live);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn auxiliary_archive_mutation_invalidates_health_lookup_and_repair(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::load_trusted_archived_chio_receipt;

    let path = unique_db_path("archive-content-auxiliary-mutation");
    let archive = unique_db_path("archive-content-auxiliary-mutation-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
        "archive-content-auxiliary-mutation-receipt",
        1,
        100,
        &keypair,
    );
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 1))?;
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;
    store.writer_handle().run_write({
        let receipt_id = receipt.id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO settlement_reconciliations \
                     (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'reconciled', 'committed-note', 1)",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;
    assert_eq!(store.archive_receipts_before(150, archive_path)?, 1);

    let archive_connection = rusqlite::Connection::open(&archive)?;
    let mutated = archive_connection.execute(
        "UPDATE settlement_reconciliations \
         SET note = 'hostile-post-commit-mutation' WHERE receipt_id = ?1",
        rusqlite::params![receipt.id],
    )?;
    assert_eq!(mutated, 1, "fixture must mutate the unsigned auxiliary row");
    drop(archive_connection);

    let report = store.receipt_store_health()?;
    assert!(
        !report.healthy,
        "canonical archive mutation must fail health"
    );
    assert!(
        report.checkpoint_error.is_some(),
        "health must surface the archive trust failure: {:?}",
        report.checkpoint_error
    );
    let live = store.reader_connection_for_test()?;
    let lookup_error = load_trusted_archived_chio_receipt(&live, &receipt.id)
        .err()
        .ok_or("mutated auxiliary archive authorized a trusted point lookup")?;
    assert!(
        lookup_error.to_string().contains("content digest"),
        "unexpected trusted lookup refusal: {lookup_error}"
    );
    drop(live);

    let raw_live = rusqlite::Connection::open(&path)?;
    let escaped = archive_path.replace('\'', "''");
    raw_live.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
    raw_live.execute(
        "INSERT INTO main.claim_receipt_log_entries \
             SELECT * FROM archive.claim_receipt_log_entries WHERE receipt_id = ?1",
        rusqlite::params![receipt.id],
    )?;
    raw_live.execute_batch("DETACH DATABASE archive")?;
    drop(raw_live);
    let repair_error = store
        .retention_repair(archive_path)
        .err()
        .ok_or("retention repair trusted a mutated auxiliary archive")?;
    assert!(
        repair_error.to_string().contains("content digest"),
        "unexpected repair refusal: {repair_error}"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn archive_prefix_digest_is_logical_and_vacuum_stable() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("archive-content-vacuum-stable");
    let archive = unique_db_path("archive-content-vacuum-stable-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 1))?;
    let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
        "archive-content-vacuum-stable-receipt",
        1,
        100,
        &keypair,
    );
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;
    assert_eq!(store.archive_receipts_before(150, archive_path)?, 1);

    let live = store.reader_connection_for_test()?;
    let committed = crate::receipt_store::support::latest_watermark_archive_content_sha256(&live)?
        .ok_or("rotation omitted the canonical archive content commitment")?;
    drop(live);
    let archive_connection = rusqlite::Connection::open(&archive)?;
    let before = crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
        &archive_connection,
        "main",
        1,
    )?;
    archive_connection.execute_batch("VACUUM")?;
    let after = crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
        &archive_connection,
        "main",
        1,
    )?;
    assert_eq!(before, committed, "watermark binds the logical archive");
    assert_eq!(after, committed, "VACUUM must not alter the logical digest");
    drop(archive_connection);
    assert!(store.receipt_store_health()?.healthy);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn opening_an_archive_as_a_live_store_invalidates_its_evidence_catalog(
) -> Result<(), Box<dyn std::error::Error>>
{
    use crate::receipt_store::support::load_trusted_archived_chio_receipt;

    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let path = directory.path().join("live.sqlite3");
    let archive = directory.path().join("archive.sqlite3");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    let mut receipt_ids = Vec::new();
    for index in 0..6_u64 {
        let timestamp = if index < 4 { 100 } else { 200 };
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("archive-open-fixed-point-{index}"),
            index + 1,
            timestamp,
            &keypair,
        );
        receipt_ids.push(receipt.id.clone());
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.writer_handle().run_write(|connection| {
        connection.execute(
            "INSERT INTO checkpoint_publication_trust_anchor_bindings \
                 (checkpoint_seq, binding_json) VALUES (2, '{\"schema\":\"test-binding\"}')",
            [],
        )?;
        Ok(())
    })?;

    assert_eq!(store.archive_receipts_before(150, archive_path)?, 4);
    let committed = {
        let live = store.reader_connection_for_test()?;
        crate::receipt_store::support::latest_watermark_archive_content_sha256(&live)?
            .ok_or("rotation omitted archive content digest")?
    };
    let before = {
        let archived = rusqlite::Connection::open(&archive)?;
        let counts: (i64, i64, i64, i64) = archived.query_row(
            "SELECT \
                 (SELECT COUNT(*) FROM checkpoint_tree_heads), \
                 (SELECT COUNT(*) FROM checkpoint_predecessor_witnesses), \
                 (SELECT COUNT(*) FROM checkpoint_publication_metadata), \
                 (SELECT COUNT(*) FROM checkpoint_publication_trust_anchor_bindings)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        assert_eq!(counts, (2, 1, 2, 1));
        crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
            &archived, "main", 4,
        )?
    };
    assert_eq!(before, committed);

    drop(SqliteReceiptStore::open(&archive)?);
    let catalog_error = {
        let archived = rusqlite::Connection::open(&archive)?;
        crate::receipt_store::evidence_retention::retention_archive_prefix_content_sha256(
            &archived, "main", 4,
        )
        .err()
        .ok_or("live-store open left a trusted archive evidence catalog")?
    };
    assert!(
        catalog_error.to_string().contains("archive table catalog"),
        "unexpected archive catalog refusal: {catalog_error}"
    );
    assert!(!store.receipt_store_health()?.healthy);
    let live = store.reader_connection_for_test()?;
    assert!(
        load_trusted_archived_chio_receipt(&live, &receipt_ids[0]).is_err(),
        "trusted lookup accepted an archive with live-store schema objects"
    );
    drop(live);

    assert!(
        store.archive_receipts_before(250, archive_path).is_err(),
        "rotation extended an archive with an active live-store catalog"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn authoritative_archived_point_load_refuses_a_symlinked_archive_path(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::load_trusted_archived_chio_receipt;

    let path = unique_db_path("archived-point-load-symlink");
    let archive = unique_db_path("archived-point-load-symlink-archive");
    let displaced = unique_db_path("archived-point-load-symlink-displaced");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
        "archived-point-load-symlink-receipt",
        1,
        100,
        &keypair,
    );
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 1))?;
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;
    assert_eq!(store.archive_receipts_before(150, archive_path)?, 1);

    std::fs::rename(&archive, &displaced)?;
    std::os::unix::fs::symlink(&displaced, &archive)?;
    let live = store.reader_connection_for_test()?;
    let error = load_trusted_archived_chio_receipt(&live, &receipt.id)
        .err()
        .ok_or("archived point load followed a symlinked archive path")?;
    assert!(
        error.to_string().contains("cannot open retention archive"),
        "unexpected symlink refusal: {error}"
    );

    drop(live);
    let _ = std::fs::remove_file(&archive);
    let _ = std::fs::remove_file(&displaced);
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn authoritative_archived_point_load_rejects_divergent_source_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("archived-point-load-divergent");
    let archive = unique_db_path("archived-point-load-divergent-archive");
    let archive_path = archive.to_str().ok_or("archive path is not valid utf-8")?;
    let keypair = super::support::receipt_test_keypair();
    let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
        "archived-point-load-divergent-receipt",
        1,
        100,
        &keypair,
    );
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 1))?;
    store.append_chio_receipt_returning_seq(&receipt)?;
    store.flush_receipt_writes()?;
    assert_eq!(store.archive_receipts_before(150, archive_path)?, 1);

    let archive_connection = rusqlite::Connection::open(&archive)?;
    archive_connection.execute(
        "UPDATE chio_tool_receipts SET raw_json = '{\"divergent\":true}' WHERE receipt_id = ?1",
        rusqlite::params![receipt.id],
    )?;
    drop(archive_connection);

    let error = store
        .load_chio_receipt(&receipt.id)
        .err()
        .ok_or("divergent archived source row must fail closed")?;
    assert!(
        error.to_string().contains("content digest"),
        "unexpected archived lookup error: {error}"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn checkpoint_chain_watermark_exemption() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::verify_checkpoint_chain_integrity;

    let path = unique_db_path("chain-exemption");
    let archive = unique_db_path("chain-exemption-archive");
    let archive_path = archive.to_str().ok_or("archive path is not valid utf-8")?;
    let keypair = super::support::receipt_test_keypair();
    let store = store_with_archived_first_checkpoint(&path, archive_path, &keypair)?;

    // With the exemption the chain still verifies: checkpoint 1 (batch_end_seq
    // <= W = 2) skips the live Merkle rebuild and trusts the co-archived range;
    // checkpoint 2 (batch_end_seq 4 > W) is rebuilt as before.
    let connection = store.reader_connection_for_test()?;
    verify_checkpoint_chain_integrity(&connection)?;

    // Tamper with a claim-log row ABOVE the watermark: the chain must still
    // fail (the exemption never weakens verification above W).
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update; \
             UPDATE claim_receipt_log_entries SET raw_json = '{\"tampered\":true}' WHERE entry_seq = 3;",
        )?;
        Ok(())
    })?;
    let connection = store.reader_connection_for_test()?;
    assert!(
        verify_checkpoint_chain_integrity(&connection).is_err(),
        "tamper above the watermark must still fail the chain"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// The watermark exemption must be backed by the archived evidence, not merely
/// by a matching checkpoint boundary and an absent live prefix. After a genuine
/// rotation the watermark is trusted, but once the archive that vouches for the
/// deleted prefix is gone the exemption is withdrawn fail-closed even though the
/// ledger and boundary are unchanged (the state an out-of-band prefix delete
/// plus a planted watermark would leave behind).
#[test]
fn watermark_trust_requires_backing_archive() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::trusted_retention_watermark;

    let path = unique_db_path("watermark-backing");
    let archive = unique_db_path("watermark-backing-archive");
    let archive_path = archive.to_str().ok_or("archive path is not valid utf-8")?;
    let keypair = super::support::receipt_test_keypair();
    let store = store_with_archived_first_checkpoint(&path, archive_path, &keypair)?;

    // Archive present and covering [1,2]: the watermark is trusted.
    let connection = store.reader_connection_for_test()?;
    assert_eq!(trusted_retention_watermark(&connection)?, 2);
    drop(connection);

    // Remove the archive that backs the deleted prefix. The ledger row, the
    // matching checkpoint boundary, and the absent live prefix are all still in
    // place, but there is no longer any archived evidence to trust.
    std::fs::remove_file(&archive)?;
    let connection = store.reader_connection_for_test()?;
    assert_eq!(
        trusted_retention_watermark(&connection)?,
        0,
        "a watermark with no backing archive must not be trusted"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Co-archive-and-delete removes the source tables and the claim-log projection
/// together, so append, health, checkpoint status, and a fresh open() all
/// succeed after archival. (Deleting source rows while leaving the projection
/// behind would leave set drift that bricks the store on the next rotation.)
#[test]
fn retention_then_append_and_reopen_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("retention-reopen");
    let keypair = super::support::receipt_test_keypair();
    let archive = unique_db_path("retention-reopen-archive");
    let archive_path = archive.to_str().ok_or("archive path is not valid utf-8")?;

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
        // 4 aged receipts (old timestamps) get two checkpoints [1,2],[3,4];
        // 2 fresh receipts stay uncheckpointed and unaged.
        for i in 0..4u64 {
            let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
                &format!("aged-{i}"),
                i + 1,
                100,
                &keypair,
            );
            store.append_chio_receipt_returning_seq(&receipt)?;
        }
        store.flush_receipt_writes()?;
        assert!(store.load_checkpoint_by_seq(2)?.is_some());

        // Archive everything older than timestamp 150 (all four aged rows).
        let archived = store.archive_receipts_before(150, archive_path)?;
        assert_eq!(archived, 4, "the two checkpointed aged batches archive");

        // The store is NOT bricked: append, health, and checkpoint status all
        // succeed AFTER archival.
        let fresh =
            super::support::sample_receipt_with_keypair_and_timestamp("fresh-0", 5, 500, &keypair);
        store.append_chio_receipt_returning_seq(&fresh)?;
        store.flush_receipt_writes()?;
        assert!(
            store.receipt_store_health()?.healthy,
            "store healthy post-archival"
        );
        assert!(store.receipt_checkpoint_status(Some(1))?.healthy);
    }

    // And a fresh open() succeeds (open-time seed runs the full verifier and
    // the watermark-aware chain walk against the co-archived range).
    let reopened = SqliteReceiptStore::open(&path)?;
    let more =
        super::support::sample_receipt_with_keypair_and_timestamp("fresh-1", 6, 600, &keypair);
    reopened.append_chio_receipt_returning_seq(&more)?;
    reopened.flush_receipt_writes()?;
    assert!(reopened.receipt_store_health()?.healthy);

    // The archived and live receipt-id sets partition the history with no
    // overlap: the four aged ids are gone from live, present in the archive.
    // The archive is a minimal evidence bundle (no live-only tables), so it is
    // consumed with open() (which rebuilds the checkpoint projections from the
    // co-archived kernel_checkpoints), not open_existing().
    let archive_store = SqliteReceiptStore::open(&archive)?;
    assert_eq!(archive_store.tool_receipt_count()?, 4);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// A rotation must dispatch to the writer actor, never begin a write
/// transaction on a reader-pool connection (mirrors single_writer.rs
/// `reader_pool_never_begins_a_write_transaction`).
#[test]
fn reader_pool_never_rotates() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("reader-never-rotates");
    let store = SqliteReceiptStore::open(&path)?;
    // A rotation over an empty store is a no-op but still routes through the
    // &self -> Rotate-command path to the single writer.
    let archived = store.rotate_if_needed(&RetentionConfig::default())?;
    assert_eq!(archived, 0);
    // Pin a reader-pool connection read-only: it can never open the IMMEDIATE
    // (write) transaction the co-archive-and-delete needs, so retention could
    // only have executed on the writer actor.
    let reader = store.reader_connection_for_test()?;
    reader.execute_batch("PRAGMA query_only = ON;")?;
    let write_attempt = reader.execute("CREATE TABLE reader_probe (x INTEGER)", []);
    assert!(
        write_attempt.is_err(),
        "reader-pool connections must be read-only (retention runs on the writer)"
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// The retention watermark ledger is security-load-bearing (chain verification
/// trusts W to skip claim-log validation), so its append-only, strictly
/// monotonic guarantee is enforced by DB triggers, not only by the insert
/// helper. A raw UPDATE, a raw DELETE, and a non-monotonic INSERT are all
/// rejected by the database.
#[test]
fn watermark_ledger_db_triggers_reject_tamper() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::insert_receipt_retention_watermark;
    let path = unique_db_path("watermark-triggers");
    let store = SqliteReceiptStore::open(&path)?;
    let connection = store.reader_connection_for_test()?;

    // Seed a legitimate mark through the helper (the trigger allows the first
    // strictly-increasing insert).
    insert_receipt_retention_watermark(
        &connection,
        10,
        100,
        "archive.sqlite3",
        TEST_ARCHIVE_IDENTITY_SHA256,
        TEST_ARCHIVE_CONTENT_SHA256,
        1,
    )?;

    // A raw UPDATE is rejected by receipt_retention_watermark_reject_update.
    let updated = connection.execute(
        "UPDATE receipt_retention_watermark SET archived_through_entry_seq = 999",
        [],
    );
    assert!(
        updated.is_err(),
        "raw UPDATE of the watermark must be rejected"
    );

    // A raw DELETE is rejected by receipt_retention_watermark_reject_delete.
    let deleted = connection.execute("DELETE FROM receipt_retention_watermark", []);
    assert!(
        deleted.is_err(),
        "raw DELETE of the watermark must be rejected"
    );

    // A non-monotonic raw INSERT (equal to the current MAX) is rejected by
    // receipt_retention_watermark_reject_regression, even though it bypasses the
    // insert helper's own regression check.
    let equal = connection.execute(
        "INSERT INTO receipt_retention_watermark \
         (archived_through_entry_seq, archived_through_timestamp, archive_path, archive_sha256, \
          archive_content_sha256, rotated_at) \
         VALUES (10, 200, 'archive.sqlite3', \
                 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
                 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 2)",
        [],
    );
    assert!(
        equal.is_err(),
        "a non-increasing raw INSERT must be rejected"
    );

    // A lower raw INSERT is likewise rejected.
    let lower = connection.execute(
        "INSERT INTO receipt_retention_watermark \
         (archived_through_entry_seq, archived_through_timestamp, archive_path, archive_sha256, \
          archive_content_sha256, rotated_at) \
         VALUES (5, 300, 'archive.sqlite3', \
                 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
                 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 3)",
        [],
    );
    assert!(lower.is_err(), "a regressing raw INSERT must be rejected");

    // The ledger is unchanged: still exactly the one legitimate mark of 10.
    let (count, max_seq): (i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(MAX(archived_through_entry_seq), 0) FROM receipt_retention_watermark",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(count, 1);
    assert_eq!(max_seq, 10);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn tenant_scoped_rotation_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("tenant-rejected");
    let store = SqliteReceiptStore::open(&path)?;
    let config = RetentionConfig {
        tenant_id: Some("tenant-a".to_string()),
        ..RetentionConfig::default()
    };
    let error = store.rotate_if_needed(&config);
    let message = error
        .err()
        .ok_or("expected RetentionTenantScopeUnsupported")?
        .to_string();
    assert!(
        message.contains("tenant-scoped retention"),
        "unexpected: {message}"
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn settlement_and_metered_rows_are_archived_not_cascaded() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("recon-archived");
    let archive = unique_db_path("recon-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();

    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for i in 0..2u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("recon-{i}"),
            i + 1,
            100,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    // Attach a settlement + metered reconciliation row, and an authorization
    // consumption row, to the first receipt. All three sit in the archived
    // range (entry_seq <= W) because the receipt itself does.
    let receipt_id = super::support::first_tool_receipt_id(&store)?;
    store.writer_handle().run_write({
        let receipt_id = receipt_id.clone();
        move |connection| {
            connection.execute(
                "INSERT INTO settlement_reconciliations (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'reconciled', NULL, 1)",
                rusqlite::params![receipt_id],
            )?;
            connection.execute(
                "INSERT INTO metered_billing_reconciliations \
                 (receipt_id, adapter_kind, evidence_id, observed_units, billed_cost_units, billed_cost_currency, evidence_sha256, recorded_at, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'test', 'ev-1', 1, 1, 'usd', NULL, 1, 'reconciled', NULL, 1)",
                rusqlite::params![receipt_id],
            )?;
            // chio_authorization_receipt_consumptions.authorization_receipt_id
            // is FK REFERENCES chio_tool_receipts(receipt_id), so it must name
            // an existing receipt; consumer_receipt_id/request_id/session_id/
            // tool_call_id/parameter_hash carry no FK, so arbitrary values
            // satisfy their NOT NULL constraints.
            connection.execute(
                "INSERT INTO chio_authorization_receipt_consumptions \
                 (authorization_receipt_id, consumer_receipt_id, request_id, session_id, tool_call_id, tenant_id, parameter_hash, consumed_at_unix_ms) \
                 VALUES (?1, 'consumer-recon-0', 'req-recon-0', 'sess-recon-0', 'tool-call-recon-0', NULL, 'hash-recon-0', 1000)",
                rusqlite::params![receipt_id],
            )?;
            Ok(())
        }
    })?;

    let archived = store.archive_receipts_before(150, archive_path)?;
    assert_eq!(archived, 2);

    // Gone from live, present in the archive (co-archived, not cascaded away).
    let live = store.reader_connection_for_test()?;
    let live_settlement: i64 = live.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_settlement, 0, "settlement row absent from live");
    let live_metered: i64 = live.query_row(
        "SELECT COUNT(*) FROM metered_billing_reconciliations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_metered, 0, "metered row absent from live");
    let live_consumptions: i64 = live.query_row(
        "SELECT COUNT(*) FROM chio_authorization_receipt_consumptions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(live_consumptions, 0, "consumption row absent from live");
    let archive_store = SqliteReceiptStore::open_existing(&archive)?;
    let arch = archive_store.reader_connection_for_test()?;
    let arch_settlement: i64 = arch.query_row(
        "SELECT COUNT(*) FROM settlement_reconciliations",
        [],
        |row| row.get(0),
    )?;
    let arch_metered: i64 = arch.query_row(
        "SELECT COUNT(*) FROM metered_billing_reconciliations",
        [],
        |row| row.get(0),
    )?;
    let arch_consumptions: i64 = arch.query_row(
        "SELECT COUNT(*) FROM chio_authorization_receipt_consumptions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(arch_settlement, 1, "settlement row co-archived");
    assert_eq!(arch_metered, 1, "metered row co-archived");
    assert_eq!(arch_consumptions, 1, "consumption row co-archived");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}
