//! Checkpoint rows read from a retention archive.
use super::*;

/// Checkpoint rows of a retention archive stamped with the current receipt
/// schema. Any other archive is refused before a row is read.
pub(crate) struct ArchiveCheckpointReader<'a> {
    connection: &'a Connection,
}

impl<'a> ArchiveCheckpointReader<'a> {
    pub(crate) fn new(connection: &'a Connection) -> Result<Self, ReceiptStoreError> {
        let version = connection
            .query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key = ?1",
                [RECEIPT_STORE_SCHEMA_KEY],
                |row| row.get::<_, i32>(0),
            )
            .optional()
            .ok()
            .flatten();
        if version != Some(RECEIPT_STORE_SCHEMA_VERSION) {
            return Err(ReceiptStoreError::Conflict(
                "unsupported retained checkpoint schema".into(),
            ));
        }
        Ok(Self { connection })
    }

    pub(crate) fn load(
        &self,
        sequence: u64,
    ) -> Result<Option<PersistedCheckpointRow>, ReceiptStoreError> {
        load_persisted_checkpoint_row(self.connection, sequence)
    }
}

pub(crate) fn load_persisted_checkpoint_row(
    connection: &Connection,
    checkpoint_seq: u64,
) -> Result<Option<PersistedCheckpointRow>, ReceiptStoreError> {
    connection
        .query_row(
            r#"
            SELECT id, checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
                   merkle_root, issued_at, statement_json, signature, kernel_key,
                   previous_checkpoint_sha256
            FROM kernel_checkpoints
            WHERE checkpoint_seq = ?1
            "#,
            params![sqlite_i64(checkpoint_seq, "checkpoint_seq")?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            },
        )
        .optional()?
        .map(
            |(
                id,
                checkpoint_seq,
                batch_start_seq,
                batch_end_seq,
                tree_size,
                merkle_root_hex,
                issued_at,
                statement_json,
                signature_hex,
                kernel_key_hex,
                previous_checkpoint_sha256,
            )| {
                Ok(PersistedCheckpointRow {
                    id: sqlite_u64(id, "checkpoint id")?,
                    checkpoint_seq: sqlite_u64(checkpoint_seq, "checkpoint_seq")?,
                    batch_start_seq: sqlite_u64(batch_start_seq, "batch_start_seq")?,
                    batch_end_seq: sqlite_u64(batch_end_seq, "batch_end_seq")?,
                    tree_size: sqlite_u64(tree_size, "tree_size")?,
                    merkle_root_hex,
                    issued_at: sqlite_u64(issued_at, "issued_at")?,
                    statement_json,
                    signature_hex,
                    kernel_key_hex,
                    previous_checkpoint_sha256,
                })
            },
        )
        .transpose()
}
