use super::*;

pub(in crate::receipt_store::tests) fn canonical_receipt_bytes(
    store: &SqliteReceiptStore,
    start_seq: u64,
    end_seq: u64,
) -> Vec<Vec<u8>> {
    store
        .receipts_canonical_bytes_range(start_seq, end_seq)
        .test_unwrap()
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect()
}

pub(in crate::receipt_store::tests) fn insert_checkpoint_row(
    store: &SqliteReceiptStore,
    checkpoint: &chio_kernel::KernelCheckpoint,
    batch_end_seq: u64,
) {
    insert_checkpoint_row_with_statement_json(
        store,
        checkpoint,
        batch_end_seq,
        &serde_json::to_string(&checkpoint.body).test_unwrap(),
    );
}

pub(in crate::receipt_store::tests) fn insert_checkpoint_row_with_statement_json(
    store: &SqliteReceiptStore,
    checkpoint: &chio_kernel::KernelCheckpoint,
    batch_end_seq: u64,
    statement_json: &str,
) {
    store
        .connection()
        .test_unwrap()
        .execute(
            r#"
            INSERT INTO kernel_checkpoints (
                checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
                merkle_root, issued_at, statement_json, signature, kernel_key, previous_checkpoint_sha256
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            rusqlite::params![
                checkpoint.body.checkpoint_seq as i64,
                checkpoint.body.batch_start_seq as i64,
                batch_end_seq as i64,
                checkpoint.body.tree_size as i64,
                checkpoint.body.merkle_root.to_hex(),
                checkpoint.body.issued_at as i64,
                statement_json,
                checkpoint.signature.to_hex(),
                checkpoint.body.kernel_key.to_hex(),
                checkpoint.body.previous_checkpoint_sha256,
            ],
        )
        .test_unwrap();
}

pub(in crate::receipt_store::tests) fn load_claim_log_rows(
    store: &SqliteReceiptStore,
) -> Vec<(u64, String, String, u64, u64)> {
    let connection = store.connection().test_unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT entry_seq, receipt_id, receipt_kind, source_seq, timestamp
            FROM claim_receipt_log_entries
            ORDER BY entry_seq ASC
            "#,
        )
        .test_unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .test_unwrap();
    rows.map(|row| {
        let (entry_seq, receipt_id, receipt_kind, source_seq, timestamp) = row.test_unwrap();
        (
            entry_seq as u64,
            receipt_id,
            receipt_kind,
            source_seq as u64,
            timestamp as u64,
        )
    })
    .collect()
}

pub(in crate::receipt_store::tests) fn load_claim_log_identity(
    store: &SqliteReceiptStore,
    receipt_id: &str,
) -> (Option<String>, Option<String>) {
    let connection = store.connection().test_unwrap();
    connection
        .query_row(
            r#"
            SELECT subject_key, issuer_key
            FROM claim_receipt_log_entries
            WHERE receipt_id = ?1
            "#,
            rusqlite::params![receipt_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .test_unwrap()
}

pub(in crate::receipt_store::tests) fn tamper_persisted_tool_receipt(
    store: &SqliteReceiptStore,
    receipt_id: &str,
    mutate: impl FnOnce(&mut ChioReceipt),
) {
    let connection = store.connection().test_unwrap();
    connection
        .execute_batch("DROP TRIGGER IF EXISTS chio_tool_receipts_reject_update;")
        .test_unwrap();
    let raw_json = connection
        .query_row(
            "SELECT raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
            rusqlite::params![receipt_id],
            |row| row.get::<_, String>(0),
        )
        .test_unwrap();
    let mut receipt: ChioReceipt = serde_json::from_str(&raw_json).test_unwrap();
    mutate(&mut receipt);
    let tampered = serde_json::to_string(&receipt).test_unwrap();
    connection
        .execute(
            "UPDATE chio_tool_receipts SET raw_json = ?1 WHERE receipt_id = ?2",
            rusqlite::params![tampered, receipt_id],
        )
        .test_unwrap();
}

pub(in crate::receipt_store::tests) fn tamper_claim_log_tool_receipt(
    store: &SqliteReceiptStore,
    receipt_id: &str,
    mutate: impl FnOnce(&mut ChioReceipt),
) {
    let connection = store.connection().test_unwrap();
    connection
        .execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_update;")
        .test_unwrap();
    let raw_json = connection
        .query_row(
            "SELECT raw_json FROM claim_receipt_log_entries WHERE receipt_id = ?1 AND receipt_kind = 'tool_receipt'",
            rusqlite::params![receipt_id],
            |row| row.get::<_, String>(0),
        )
        .test_unwrap();
    let mut receipt: ChioReceipt = serde_json::from_str(&raw_json).test_unwrap();
    mutate(&mut receipt);
    let tampered = serde_json::to_string(&receipt).test_unwrap();
    connection
        .execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1 WHERE receipt_id = ?2 AND receipt_kind = 'tool_receipt'",
            rusqlite::params![tampered, receipt_id],
        )
        .test_unwrap();
}

pub(in crate::receipt_store::tests) fn load_checkpoint_tree_head_rows(
    store: &SqliteReceiptStore,
) -> Vec<(u64, u64, u64, Option<String>)> {
    let connection = store.connection().test_unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT checkpoint_seq, batch_start_seq, tree_size, previous_checkpoint_sha256
            FROM checkpoint_tree_heads
            ORDER BY checkpoint_seq ASC
            "#,
        )
        .test_unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .test_unwrap();
    rows.map(|row| {
        let (checkpoint_seq, batch_start_seq, tree_size, previous_checkpoint_sha256) =
            row.test_unwrap();
        (
            checkpoint_seq as u64,
            batch_start_seq as u64,
            tree_size as u64,
            previous_checkpoint_sha256,
        )
    })
    .collect()
}

pub(in crate::receipt_store::tests) fn load_checkpoint_predecessor_witness_rows(
    store: &SqliteReceiptStore,
) -> Vec<(u64, u64, String)> {
    let connection = store.connection().test_unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT predecessor_checkpoint_seq, witness_checkpoint_seq, previous_checkpoint_sha256
            FROM checkpoint_predecessor_witnesses
            ORDER BY witness_checkpoint_seq ASC
            "#,
        )
        .test_unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .test_unwrap();
    rows.map(|row| {
        let (predecessor_checkpoint_seq, witness_checkpoint_seq, previous_checkpoint_sha256) =
            row.test_unwrap();
        (
            predecessor_checkpoint_seq as u64,
            witness_checkpoint_seq as u64,
            previous_checkpoint_sha256,
        )
    })
    .collect()
}

type CheckpointPublicationMetadataRow = (
    u64,
    String,
    String,
    u64,
    String,
    u64,
    u64,
    u64,
    Option<String>,
);

pub(in crate::receipt_store::tests) fn load_checkpoint_publication_metadata_rows(
    store: &SqliteReceiptStore,
) -> Vec<CheckpointPublicationMetadataRow> {
    let connection = store.connection().test_unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT checkpoint_seq, publication_schema, merkle_root, published_at, kernel_key,
                   log_tree_size, entry_start_seq, entry_end_seq, previous_checkpoint_sha256
            FROM checkpoint_publication_metadata
            ORDER BY checkpoint_seq ASC
            "#,
        )
        .test_unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        })
        .test_unwrap();
    rows.map(|row| {
        let (
            checkpoint_seq,
            publication_schema,
            merkle_root,
            published_at,
            kernel_key,
            log_tree_size,
            entry_start_seq,
            entry_end_seq,
            previous_checkpoint_sha256,
        ) = row.test_unwrap();
        (
            checkpoint_seq as u64,
            publication_schema,
            merkle_root,
            published_at as u64,
            kernel_key,
            log_tree_size as u64,
            entry_start_seq as u64,
            entry_end_seq as u64,
            previous_checkpoint_sha256,
        )
    })
    .collect()
}

pub(in crate::receipt_store::tests) fn load_checkpoint_publication_trust_anchor_binding_rows(
    store: &SqliteReceiptStore,
) -> Vec<(
    u64,
    chio_core::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding,
)> {
    let connection = store.connection().test_unwrap();
    let mut statement = connection
        .prepare(
            r#"
            SELECT checkpoint_seq, binding_json
            FROM checkpoint_publication_trust_anchor_bindings
            ORDER BY checkpoint_seq ASC
            "#,
        )
        .test_unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .test_unwrap();
    rows.map(|row| {
        let (checkpoint_seq, binding_json) = row.test_unwrap();
        (
            checkpoint_seq as u64,
            serde_json::from_str::<
                chio_core::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding,
            >(&binding_json)
            .test_unwrap(),
        )
    })
    .collect()
}
