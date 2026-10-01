//! Receipt archive compatibility without modifying operator-owned evidence.
use super::*;

pub(crate) struct ArchiveCheckpointReader<'a> {
    connection: &'a Connection,
    predecessor_in_body: bool,
}

impl<'a> ArchiveCheckpointReader<'a> {
    pub(crate) fn new(connection: &'a Connection) -> Result<Self, ReceiptStoreError> {
        let versioned: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chio_store_schema_versions')",
            [], |row| row.get(0),
        )?;
        let version = if versioned {
            // A declared catalog must contain the receipt owner. An absent row
            // is corruption, not evidence that this is an unversioned archive.
            Some(connection.query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key = 'receipt'",
                [],
                |row| row.get::<_, i32>(0),
            )?)
        } else {
            None
        };
        let column: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('kernel_checkpoints') WHERE name = 'previous_checkpoint_sha256')",
            [], |row| row.get(0),
        )?;
        // Only the known v6 layout lacks this mirror. A damaged current schema
        // or an unknown future schema must never acquire a compatibility path.
        let predecessor_in_body = match (version, column) {
            (Some(6), false) => true,
            (Some(6 | RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION), true) => false,
            // Older repair archives copied the full mirrored checkpoint table
            // without schema metadata. Only that complete layout is accepted;
            // load and caller validation still authenticate every retained row.
            (None, true) => false,
            _ => {
                return Err(ReceiptStoreError::Conflict(
                    "unsupported retained checkpoint schema".into(),
                ))
            }
        };
        Ok(Self {
            connection,
            predecessor_in_body,
        })
    }

    pub(crate) fn load(
        &self,
        sequence: u64,
    ) -> Result<Option<PersistedCheckpointRow>, ReceiptStoreError> {
        let column = if self.predecessor_in_body {
            "NULL"
        } else {
            "previous_checkpoint_sha256"
        };
        let Some(mut row) = load_row(self.connection, sequence, column)? else {
            return Ok(None);
        };
        if self.predecessor_in_body {
            // Authenticate the original signed body and every existing mirror
            // before projecting the v7 field. The caller also requires complete
            // equality with the live row and verifies the archived claim log.
            let checkpoint = parse_checkpoint_signed_columns(&row)?;
            row.previous_checkpoint_sha256 = checkpoint.body.previous_checkpoint_sha256;
        }
        Ok(Some(row))
    }
}

pub(crate) fn load_persisted_checkpoint_row(
    connection: &Connection,
    checkpoint_seq: u64,
) -> Result<Option<PersistedCheckpointRow>, ReceiptStoreError> {
    load_row(connection, checkpoint_seq, "previous_checkpoint_sha256")
}

fn load_row(
    connection: &Connection,
    checkpoint_seq: u64,
    predecessor_column: &'static str,
) -> Result<Option<PersistedCheckpointRow>, ReceiptStoreError> {
    connection
        .query_row(
            &format!(r#"
            SELECT id, checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
                   merkle_root, issued_at, statement_json, signature, kernel_key, {predecessor_column}
            FROM kernel_checkpoints
            WHERE checkpoint_seq = ?1
            "#),
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
