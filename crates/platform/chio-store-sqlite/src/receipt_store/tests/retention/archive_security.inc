fn two_batch_retention_fixture(
    prefix: &str,
) -> Result<
    (
        SqliteReceiptStore,
        std::path::PathBuf,
        std::path::PathBuf,
        String,
    ),
    Box<dyn std::error::Error>,
> {
    let path = unique_db_path(&format!("{prefix}-live"));
    let archive = unique_db_path(&format!("{prefix}-archive"));
    let archive_path = archive.to_str().ok_or("archive path invalid")?.to_string();
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for index in 0..4_u64 {
        let timestamp = if index < 2 { 100 } else { 200 };
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("{prefix}-{index}"),
            index + 1,
            timestamp,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert_eq!(store.archive_receipts_before(150, &archive_path)?, 2);
    Ok((store, path, archive, archive_path))
}

#[test]
fn poisoned_pooled_connection_is_discarded_before_rotation(
) -> Result<(), Box<dyn std::error::Error>> {
    let (store, path, archive, archive_path) =
        two_batch_retention_fixture("temp-trigger-poison")?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "CREATE TEMP TRIGGER poison_retention_delete \
             AFTER DELETE ON main.chio_tool_receipts \
             BEGIN \
                 DELETE FROM chio_tool_receipts WHERE seq > OLD.seq; \
             END",
        )?;
        Ok(())
    })?;

    assert_eq!(
        store.archive_receipts_before(250, &archive_path)?,
        2,
        "the pool must discard the poisoned connection before rotation"
    );
    let live = store.reader_connection_for_test()?;
    assert_eq!(
        crate::receipt_store::support::retention_watermark(&live)?,
        Some(4)
    );
    drop(live);
    let archived = rusqlite::Connection::open(&archive)?;
    let archived_rows: i64 = archived.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 4",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(archived_rows, 4, "the evicted trigger cannot delete the suffix");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn destructive_retention_rejects_temp_trigger_on_its_active_connection(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::delete_archived_prefix_in_tx;

    let (store, path, archive, archive_path) =
        two_batch_retention_fixture("active-temp-trigger-poison")?;
    let refusal = store.writer_handle().run_write({
        let archive_path = archive_path.clone();
        move |connection| {
            connection.execute_batch(
                "CREATE TEMP TRIGGER poison_active_retention_delete \
                 AFTER DELETE ON main.chio_tool_receipts \
                 BEGIN \
                     DELETE FROM chio_tool_receipts WHERE seq > OLD.seq; \
                 END",
            )?;
            let error = delete_archived_prefix_in_tx(
                connection,
                2,
                4,
                250,
                &archive_path,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )
            .err()
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(
                    "destructive retention accepted a TEMP trigger".to_string(),
                )
            })?;
            connection.execute_batch("DROP TRIGGER temp.poison_active_retention_delete")?;
            Ok(error.to_string())
        }
    })?;
    assert!(
        refusal.contains("TEMP trigger"),
        "unexpected active TEMP trigger refusal: {refusal}"
    );

    let live = store.reader_connection_for_test()?;
    let suffix_rows: i64 = live.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq > 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(suffix_rows, 2, "TEMP refusal must precede destructive SQL");
    drop(live);
    assert_eq!(store.archive_receipts_before(250, &archive_path)?, 2);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn archived_capability_absence_rejects_public_late_snapshot_before_reuse(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("late-capability-snapshot");
    let archive = unique_db_path("late-capability-snapshot-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?.to_string();
    let issuer = super::support::receipt_test_keypair();
    let subject = super::support::Keypair::generate();
    let token = super::support::CapabilityToken::sign(
        super::support::CapabilityTokenBody {
            id: "cap-1".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: super::support::ChioScope {
                grants: vec![super::support::ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![super::support::Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..super::support::ChioScope::default()
            },
            issued_at: 1,
            expires_at: 10_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?;

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.enable_background_checkpoints(super::support::signer(&issuer, 2))?;
        for index in 0..2_u64 {
            let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
                "late-capability-first",
                index + 1,
                100,
                &issuer,
            );
            store.append_chio_receipt_returning_seq(&receipt)?;
        }
        store.flush_receipt_writes()?;
        assert_eq!(store.archive_receipts_before(150, &archive_path)?, 2);
    }

    let store = SqliteReceiptStore::open_existing(&path)?;
    let snapshot_error = store
        .record_capability_snapshot(&token, None)
        .err()
        .ok_or("archived capability accepted a late public snapshot")?;
    assert!(
        snapshot_error.to_string().contains("frozen after archival"),
        "unexpected late snapshot refusal: {snapshot_error}"
    );
    store.enable_background_checkpoints(super::support::signer(&issuer, 2))?;
    for index in 0..2_u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            "late-capability-reuse",
            index + 3,
            200,
            &issuer,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert_eq!(
        store.archive_receipts_before(250, &archive_path)?,
        2,
        "a rejected late snapshot must not wedge a later capability reuse rotation"
    );

    let archived = rusqlite::Connection::open(&archive)?;
    let archived_lineage: i64 = archived.query_row(
        "SELECT COUNT(*) FROM capability_lineage WHERE capability_id = 'cap-1'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        archived_lineage, 0,
        "the original archive absence remains authoritative after reuse"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn archived_capability_lineage_allows_exact_noops_but_rejects_mutation(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("frozen-capability-mutations");
    let archive = unique_db_path("frozen-capability-mutations-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?.to_string();
    let issuer = super::support::receipt_test_keypair();
    let subject = super::support::Keypair::generate();
    let token = super::support::CapabilityToken::sign(
        super::support::CapabilityTokenBody {
            id: "cap-1".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: super::support::ChioScope {
                grants: vec![super::support::ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![super::support::Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..super::support::ChioScope::default()
            },
            issued_at: 1,
            expires_at: 10_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?;

    let store = SqliteReceiptStore::open(&path)?;
    store.record_capability_snapshot(&token, None)?;
    store.enable_background_checkpoints(super::support::signer(&issuer, 2))?;
    for index in 0..2_u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            "frozen-capability-first",
            index + 1,
            100,
            &issuer,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert_eq!(store.archive_receipts_before(150, &archive_path)?, 2);

    store.record_capability_snapshot(&token, None)?;
    let (no_op_updated, divergent_update_rejected, delete_rejected) =
        store.writer_handle().run_write(|connection| {
            let no_op_updated = connection.execute(
                "UPDATE capability_lineage SET grants_json = grants_json \
                 WHERE capability_id = 'cap-1'",
                [],
            )?;
            let divergent_update_rejected = connection
                .execute(
                    "UPDATE capability_lineage SET grants_json = '{\"changed\":true}' \
                     WHERE capability_id = 'cap-1'",
                    [],
                )
                .is_err();
            let delete_rejected = connection
                .execute(
                    "DELETE FROM capability_lineage WHERE capability_id = 'cap-1'",
                    [],
                )
                .is_err();
            Ok((no_op_updated, divergent_update_rejected, delete_rejected))
        })?;
    assert_eq!(no_op_updated, 1, "an exact SQL no-op update remains idempotent");
    assert!(divergent_update_rejected, "frozen lineage update must fail");
    assert!(delete_rejected, "frozen lineage delete must fail");

    for index in 0..2_u64 {
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            "frozen-capability-reuse",
            index + 3,
            200,
            &issuer,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    assert_eq!(store.archive_receipts_before(250, &archive_path)?, 2);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn second_rotation_retries_after_copy_commits_but_live_delete_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::evidence_retention::{
        copy_archived_prefix, create_archive_schema, delete_archived_prefix_in_tx,
        retention_archive_prefix_content_sha256,
    };

    let (store, path, archive, archive_path) =
        two_batch_retention_fixture("retry-after-copy")?;
    let (previous_identity, previous_content) = {
        let live = store.reader_connection_for_test()?;
        (
            crate::receipt_store::support::latest_watermark_archive_sha256(&live)?
                .ok_or("first rotation omitted archive identity")?,
            crate::receipt_store::support::latest_watermark_archive_content_sha256(&live)?
                .ok_or("first rotation omitted archive content commitment")?,
        )
    };
    let suffix_receipt_id = {
        let live = store.reader_connection_for_test()?;
        live.query_row(
            "SELECT receipt_id FROM claim_receipt_log_entries WHERE entry_seq = 3",
            [],
            |row| row.get::<_, String>(0),
        )?
    };
    let late_binding_rejected = store.writer_handle().run_write(|connection| {
        Ok(connection
            .execute(
                "INSERT INTO checkpoint_publication_trust_anchor_bindings \
                 (checkpoint_seq, binding_json) \
                 SELECT checkpoint_seq, '{}' FROM kernel_checkpoints \
                 WHERE batch_end_seq <= 2 ORDER BY checkpoint_seq DESC LIMIT 1",
                [],
            )
            .is_err())
    })?;
    assert!(
        late_binding_rejected,
        "a committed archival prefix must reject late checkpoint bindings"
    );

    let failed = store.writer_handle().run_write({
        let archive_path = archive_path.clone();
        let previous_identity = previous_identity.clone();
        let previous_content = previous_content.clone();
        let suffix_receipt_id = suffix_receipt_id.clone();
        move |connection| {
            let escaped = archive_path.replace('\'', "''");
            connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
            create_archive_schema(connection)?;
            let identity =
                crate::receipt_store::support::ensure_attached_retention_archive_identity(
                    connection,
                    Some(&previous_identity),
                )?;
            copy_archived_prefix(connection, 4)?;
            let prospective_content =
                retention_archive_prefix_content_sha256(connection, "archive", 4)?;
            connection.execute(
                "INSERT INTO settlement_reconciliations \
                     (receipt_id, reconciliation_state, note, updated_at) \
                 VALUES (?1, 'pending', 'late barrier', 1)",
                rusqlite::params![suffix_receipt_id],
            )?;
            connection.execute_batch("DETACH DATABASE archive")?;
            restrict_test_archive_file(std::path::Path::new(&archive_path))?;
            Ok(delete_archived_prefix_in_tx(
                connection,
                2,
                4,
                250,
                &archive_path,
                &identity,
                Some(&previous_content),
                &prospective_content,
            )
            .is_err())
        }
    })?;
    assert!(failed, "late barrier must stop the live destructive commit");
    store.writer_handle().run_write(move |connection| {
        connection.execute(
            "DELETE FROM settlement_reconciliations WHERE receipt_id = ?1",
            rusqlite::params![suffix_receipt_id],
        )?;
        Ok(())
    })?;

    assert_eq!(
        store.archive_receipts_before(250, &archive_path)?,
        2,
        "a prospective suffix left by a failed delete must be safely retryable"
    );
    let live = store.reader_connection_for_test()?;
    assert_eq!(
        crate::receipt_store::support::retention_watermark(&live)?,
        Some(4)
    );
    drop(live);
    let archived = rusqlite::Connection::open(&archive)?;
    let archived_rows: i64 = archived.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE entry_seq <= 4",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(archived_rows, 4, "retry must preserve both committed batches");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn second_rotation_rolls_back_copy_that_changes_the_committed_prefix(
) -> Result<(), Box<dyn std::error::Error>> {
    let (store, path, archive, archive_path) =
        two_batch_retention_fixture("old-prefix-copy-rollback")?;
    let checkpoint_seq = {
        let live = store.reader_connection_for_test()?;
        live.query_row(
            "SELECT checkpoint_seq FROM kernel_checkpoints \
             WHERE batch_end_seq <= 2 ORDER BY checkpoint_seq DESC LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )?
    };
    store.writer_handle().run_write(move |connection| {
        connection.execute_batch(
            "DROP TRIGGER checkpoint_publication_trust_anchor_bindings_reject_archived_insert",
        )?;
        connection.execute(
            "INSERT INTO checkpoint_publication_trust_anchor_bindings \
             (checkpoint_seq, binding_json) VALUES (?1, '{}')",
            rusqlite::params![checkpoint_seq],
        )?;
        crate::receipt_store::support::ensure_transparency_projection_guards(connection)?;
        Ok(())
    })?;

    let error = store
        .archive_receipts_before(250, &archive_path)
        .err()
        .ok_or("rotation committed a copy that changed its prior prefix")?;
    assert!(
        error.to_string().contains("digest"),
        "unexpected old-prefix stability refusal: {error}"
    );
    let archived = rusqlite::Connection::open(&archive)?;
    let copied_binding: i64 = archived.query_row(
        "SELECT COUNT(*) FROM checkpoint_publication_trust_anchor_bindings \
         WHERE checkpoint_seq = ?1",
        rusqlite::params![checkpoint_seq],
        |row| row.get(0),
    )?;
    assert_eq!(
        copied_binding, 0,
        "a rejected copy must roll the archive transaction back"
    );
    drop(archived);

    store.writer_handle().run_write(move |connection| {
        connection.execute_batch(
            "DROP TRIGGER checkpoint_publication_trust_anchor_bindings_reject_delete",
        )?;
        connection.execute(
            "DELETE FROM checkpoint_publication_trust_anchor_bindings \
             WHERE checkpoint_seq = ?1",
            rusqlite::params![checkpoint_seq],
        )?;
        crate::receipt_store::support::ensure_transparency_projection_guards(connection)?;
        Ok(())
    })?;
    assert_eq!(store.archive_receipts_before(250, &archive_path)?, 2);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

fn assert_second_rotation_rejects_archive_catalog_mutation(
    prefix: &str,
    mutation: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (store, path, archive, archive_path) = two_batch_retention_fixture(prefix)?;
    let archive_connection = rusqlite::Connection::open(&archive)?;
    archive_connection.execute_batch(mutation)?;
    drop(archive_connection);
    restrict_test_archive_file(&archive)?;

    let error = store
        .archive_receipts_before(250, &archive_path)
        .err()
        .ok_or("rotation accepted mutation-capable archive schema")?;
    assert!(
        error.to_string().contains("archive") && error.to_string().contains("schema"),
        "unexpected archive catalog refusal: {error}"
    );
    let live = store.reader_connection_for_test()?;
    assert_eq!(
        crate::receipt_store::support::retention_watermark(&live)?,
        Some(2),
        "rejected schema must not advance the ledger"
    );
    assert_eq!(store.tool_receipt_count()?, 2, "live suffix must survive");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn second_rotation_rejects_archive_unique_expression_index(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_second_rotation_rejects_archive_catalog_mutation(
        "archive-unique-expression",
        "CREATE UNIQUE INDEX hostile_archive_reconciliation_collapse \
         ON settlement_reconciliations ((1))",
    )
}

#[test]
fn second_rotation_rejects_archive_trigger() -> Result<(), Box<dyn std::error::Error>> {
    assert_second_rotation_rejects_archive_catalog_mutation(
        "archive-trigger",
        "CREATE TRIGGER hostile_archive_receipt_delete \
         AFTER INSERT ON chio_tool_receipts \
         BEGIN DELETE FROM chio_tool_receipts WHERE seq < NEW.seq; END",
    )
}

#[test]
fn second_rotation_rejects_archive_table_with_sqlite_like_prefix(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_second_rotation_rejects_archive_catalog_mutation(
        "archive-sqlite-like-prefix",
        "CREATE TABLE sqliteevil (id INTEGER PRIMARY KEY)",
    )
}

#[test]
fn rotation_rejects_extra_live_trigger_before_dropping_delete_guards(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("live-retention-trigger");
    let archive = unique_db_path("live-retention-trigger-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for index in 0..4_u64 {
        let timestamp = if index < 2 { 100 } else { 200 };
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("live-retention-trigger-{index}"),
            index + 1,
            timestamp,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "CREATE TRIGGER hostile_watermark_suffix_delete \
             AFTER INSERT ON receipt_retention_watermark \
             BEGIN \
                 DELETE FROM chio_tool_receipts \
                 WHERE seq > NEW.archived_through_entry_seq; \
             END",
        )?;
        Ok(())
    })?;

    let error = store
        .archive_receipts_before(150, archive_path)
        .err()
        .ok_or("rotation executed an unexpected live watermark trigger")?;
    assert!(
        error.to_string().contains("trigger"),
        "unexpected live trigger refusal: {error}"
    );
    assert_eq!(store.tool_receipt_count()?, 4);
    let live = store.reader_connection_for_test()?;
    assert_eq!(
        crate::receipt_store::support::retention_watermark(&live)?,
        None,
        "rejected live trigger must not create a watermark"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn rotation_rejects_replaced_live_trigger_before_dropping_delete_guards(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("replaced-live-retention-trigger");
    let archive = unique_db_path("replaced-live-retention-trigger-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for index in 0..4_u64 {
        let timestamp = if index < 2 { 100 } else { 200 };
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("replaced-live-retention-trigger-{index}"),
            index + 1,
            timestamp,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "DROP TRIGGER chio_tool_receipts_project_claim_log_entry; \
             CREATE TRIGGER chio_tool_receipts_project_claim_log_entry \
             BEFORE DELETE ON chio_tool_receipts \
             BEGIN \
                 DELETE FROM chio_child_receipts; \
             END",
        )?;
        Ok(())
    })?;

    let error = store
        .archive_receipts_before(150, archive_path)
        .err()
        .ok_or("rotation executed a substituted live trigger")?;
    assert!(
        error.to_string().contains("trigger"),
        "unexpected substituted trigger refusal: {error}"
    );
    assert_eq!(store.tool_receipt_count()?, 4);
    let live = store.reader_connection_for_test()?;
    assert_eq!(
        crate::receipt_store::support::retention_watermark(&live)?,
        None,
        "rejected trigger substitution must not create a watermark"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

#[test]
fn rotation_rejects_unexpected_cascading_foreign_key_before_deleting_receipts(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("live-retention-cascade");
    let archive = unique_db_path("live-retention-cascade-archive");
    let archive_path = archive.to_str().ok_or("archive path invalid")?;
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;
    store.enable_background_checkpoints(super::support::signer(&keypair, 2))?;
    for index in 0..4_u64 {
        let timestamp = if index < 2 { 100 } else { 200 };
        let receipt = super::support::sample_receipt_with_keypair_and_timestamp(
            &format!("live-retention-cascade-{index}"),
            index + 1,
            timestamp,
            &keypair,
        );
        store.append_chio_receipt_returning_seq(&receipt)?;
    }
    store.flush_receipt_writes()?;
    store.writer_handle().run_write(|connection| {
        connection.execute_batch(
            "CREATE TABLE hostile_retention_cascade ( \
                 receipt_id TEXT PRIMARY KEY \
                     REFERENCES chio_tool_receipts(receipt_id) ON DELETE CASCADE \
             ); \
             CREATE TRIGGER hostile_retention_cascade_delete \
             AFTER DELETE ON hostile_retention_cascade \
             BEGIN \
                 DELETE FROM chio_tool_receipts WHERE seq > 2; \
             END; \
             INSERT INTO hostile_retention_cascade (receipt_id) \
             SELECT receipt_id FROM chio_tool_receipts ORDER BY seq LIMIT 1",
        )?;
        Ok(())
    })?;

    let error = store
        .archive_receipts_before(150, archive_path)
        .err()
        .ok_or("rotation followed an unexpected cascading foreign key")?;
    assert!(
        error.to_string().contains("foreign-key"),
        "unexpected cascading foreign-key refusal: {error}"
    );
    assert_eq!(store.tool_receipt_count()?, 4);
    let live = store.reader_connection_for_test()?;
    assert_eq!(
        crate::receipt_store::support::retention_watermark(&live)?,
        None,
        "rejected cascading foreign key must not create a watermark"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
    Ok(())
}
