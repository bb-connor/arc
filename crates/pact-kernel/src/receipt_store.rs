use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use pact_core::canonical::canonical_json_bytes;
use pact_core::crypto::Signature;
use pact_core::receipt::{ChildRequestReceipt, Decision, PactReceipt};
use pact_core::session::OperationTerminalState;
use rusqlite::{params, Connection, OptionalExtension};

use crate::receipt_query::{ReceiptQuery, ReceiptQueryResult, MAX_QUERY_LIMIT};

use crate::checkpoint::{KernelCheckpoint, KernelCheckpointBody};

/// Configuration for receipt retention and archival.
///
/// When set on `KernelConfig`, the kernel can archive aged-out or oversized
/// receipt databases to a separate read-only SQLite file while keeping archived
/// receipts verifiable against their Merkle checkpoint roots.
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    /// Number of days to retain receipts in the live database. Default: 90.
    pub retention_days: u64,
    /// Maximum size in bytes before the live database is rotated. Default: 10 GB.
    pub max_size_bytes: u64,
    /// Path for the archive SQLite file. Must be writable on first rotation.
    pub archive_path: String,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            retention_days: 90,
            max_size_bytes: 10_737_418_240,
            archive_path: "receipts-archive.sqlite3".to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiptStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("failed to prepare receipt store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("crypto decode error: {0}")]
    CryptoDecode(String),

    #[error("canonical json error: {0}")]
    Canonical(String),

    #[error("invalid outcome filter: {0}")]
    InvalidOutcome(String),
}

pub trait ReceiptStore: Send {
    fn append_pact_receipt(&mut self, receipt: &PactReceipt) -> Result<(), ReceiptStoreError>;
    fn append_child_receipt(
        &mut self,
        receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError>;

    /// Return a mutable `Any` reference for downcasting to concrete types.
    ///
    /// This allows the kernel to downcast to `SqliteReceiptStore` when it
    /// needs access to seq-returning and checkpoint methods that are not
    /// part of the minimal trait.
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        None
    }
}

pub struct SqliteReceiptStore {
    pub(crate) connection: Connection,
}

#[derive(Debug, Clone)]
pub struct StoredToolReceipt {
    pub seq: u64,
    pub receipt: PactReceipt,
}

#[derive(Debug, Clone)]
pub struct StoredChildReceipt {
    pub seq: u64,
    pub receipt: ChildRequestReceipt,
}

impl SqliteReceiptStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReceiptStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let connection = Connection::open(path)?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS pact_tool_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision_kind TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_pact_tool_receipts_timestamp
                ON pact_tool_receipts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_pact_tool_receipts_capability
                ON pact_tool_receipts(capability_id);
            CREATE INDEX IF NOT EXISTS idx_pact_tool_receipts_tool
                ON pact_tool_receipts(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_pact_tool_receipts_decision
                ON pact_tool_receipts(decision_kind);

            CREATE TABLE IF NOT EXISTS pact_child_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                parent_request_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                operation_kind TEXT NOT NULL,
                terminal_state TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                outcome_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_pact_child_receipts_timestamp
                ON pact_child_receipts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_pact_child_receipts_session
                ON pact_child_receipts(session_id);
            CREATE INDEX IF NOT EXISTS idx_pact_child_receipts_parent
                ON pact_child_receipts(parent_request_id);
            CREATE INDEX IF NOT EXISTS idx_pact_child_receipts_request
                ON pact_child_receipts(request_id);

            CREATE TABLE IF NOT EXISTS kernel_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkpoint_seq INTEGER NOT NULL UNIQUE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                kernel_key TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_kernel_checkpoints_batch_end
                ON kernel_checkpoints(batch_end_seq);

            CREATE TABLE IF NOT EXISTS capability_lineage (
                capability_id        TEXT PRIMARY KEY,
                subject_key          TEXT NOT NULL,
                issuer_key           TEXT NOT NULL,
                issued_at            INTEGER NOT NULL,
                expires_at           INTEGER NOT NULL,
                grants_json          TEXT NOT NULL,
                delegation_depth     INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT REFERENCES capability_lineage(capability_id)
            );
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_subject
                ON capability_lineage(subject_key);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_issued_at
                ON capability_lineage(issued_at);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_parent
                ON capability_lineage(parent_capability_id);
            "#,
        )?;

        Ok(Self { connection })
    }

    pub fn tool_receipt_count(&self) -> Result<u64, ReceiptStoreError> {
        let count =
            self.connection
                .query_row("SELECT COUNT(*) FROM pact_tool_receipts", [], |row| {
                    row.get::<_, u64>(0)
                })?;
        Ok(count)
    }

    pub fn child_receipt_count(&self) -> Result<u64, ReceiptStoreError> {
        let count =
            self.connection
                .query_row("SELECT COUNT(*) FROM pact_child_receipts", [], |row| {
                    row.get::<_, u64>(0)
                })?;
        Ok(count)
    }

    pub fn list_tool_receipts(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        tool_server: Option<&str>,
        tool_name: Option<&str>,
        decision_kind: Option<&str>,
    ) -> Result<Vec<PactReceipt>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT raw_json
            FROM pact_tool_receipts
            WHERE (?1 IS NULL OR capability_id = ?1)
              AND (?2 IS NULL OR tool_server = ?2)
              AND (?3 IS NULL OR tool_name = ?3)
              AND (?4 IS NULL OR decision_kind = ?4)
            ORDER BY seq DESC
            LIMIT ?5
            "#,
        )?;
        let rows = statement.query_map(
            params![
                capability_id,
                tool_server,
                tool_name,
                decision_kind,
                limit as i64,
            ],
            |row| row.get::<_, String>(0),
        )?;

        rows.map(|row| {
            let raw_json = row?;
            Ok(serde_json::from_str(&raw_json)?)
        })
        .collect()
    }

    pub fn list_tool_receipts_after_seq(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredToolReceipt>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM pact_tool_receipts
            WHERE seq > ?1
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![after_seq as i64, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (seq, raw_json) = row?;
            Ok(StoredToolReceipt {
                seq: seq.max(0) as u64,
                receipt: serde_json::from_str(&raw_json)?,
            })
        })
        .collect()
    }

    pub fn list_child_receipts(
        &self,
        limit: usize,
        session_id: Option<&str>,
        parent_request_id: Option<&str>,
        request_id: Option<&str>,
        operation_kind: Option<&str>,
        terminal_state: Option<&str>,
    ) -> Result<Vec<ChildRequestReceipt>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT raw_json
            FROM pact_child_receipts
            WHERE (?1 IS NULL OR session_id = ?1)
              AND (?2 IS NULL OR parent_request_id = ?2)
              AND (?3 IS NULL OR request_id = ?3)
              AND (?4 IS NULL OR operation_kind = ?4)
              AND (?5 IS NULL OR terminal_state = ?5)
            ORDER BY seq DESC
            LIMIT ?6
            "#,
        )?;
        let rows = statement.query_map(
            params![
                session_id,
                parent_request_id,
                request_id,
                operation_kind,
                terminal_state,
                limit as i64,
            ],
            |row| row.get::<_, String>(0),
        )?;

        rows.map(|row| {
            let raw_json = row?;
            Ok(serde_json::from_str(&raw_json)?)
        })
        .collect()
    }

    pub fn list_child_receipts_after_seq(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredChildReceipt>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM pact_child_receipts
            WHERE seq > ?1
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![after_seq as i64, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (seq, raw_json) = row?;
            Ok(StoredChildReceipt {
                seq: seq.max(0) as u64,
                receipt: serde_json::from_str(&raw_json)?,
            })
        })
        .collect()
    }

    /// Append a PactReceipt and return the AUTOINCREMENT seq assigned.
    ///
    /// Returns 0 if the receipt was a duplicate (ON CONFLICT DO NOTHING).
    pub fn append_pact_receipt_returning_seq(
        &mut self,
        receipt: &PactReceipt,
    ) -> Result<u64, ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        self.connection.execute(
            r#"
            INSERT INTO pact_tool_receipts (
                receipt_id,
                timestamp,
                capability_id,
                tool_server,
                tool_name,
                decision_kind,
                policy_hash,
                content_hash,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt.id,
                receipt.timestamp,
                receipt.capability_id,
                receipt.tool_server,
                receipt.tool_name,
                decision_kind(&receipt.decision),
                receipt.policy_hash,
                receipt.content_hash,
                raw_json,
            ],
        )?;
        let seq = self.connection.last_insert_rowid().max(0) as u64;
        Ok(seq)
    }

    /// Store a signed KernelCheckpoint in the kernel_checkpoints table.
    pub fn store_checkpoint(
        &mut self,
        checkpoint: &KernelCheckpoint,
    ) -> Result<(), ReceiptStoreError> {
        let statement_json = serde_json::to_string(&checkpoint.body)?;
        self.connection.execute(
            r#"
            INSERT INTO kernel_checkpoints (
                checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
                merkle_root, issued_at, statement_json, signature, kernel_key
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                checkpoint.body.checkpoint_seq as i64,
                checkpoint.body.batch_start_seq as i64,
                checkpoint.body.batch_end_seq as i64,
                checkpoint.body.tree_size as i64,
                checkpoint.body.merkle_root.to_hex(),
                checkpoint.body.issued_at as i64,
                statement_json,
                checkpoint.signature.to_hex(),
                checkpoint.body.kernel_key.to_hex(),
            ],
        )?;
        Ok(())
    }

    /// Load a KernelCheckpoint by its checkpoint_seq.
    pub fn load_checkpoint_by_seq(
        &self,
        checkpoint_seq: u64,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        let row = self
            .connection
            .query_row(
                r#"
                SELECT statement_json, signature
                FROM kernel_checkpoints
                WHERE checkpoint_seq = ?1
                "#,
                params![checkpoint_seq as i64],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;

        match row {
            None => Ok(None),
            Some((statement_json, signature_hex)) => {
                let body: KernelCheckpointBody = serde_json::from_str(&statement_json)?;
                let signature = Signature::from_hex(&signature_hex)
                    .map_err(|e| ReceiptStoreError::CryptoDecode(e.to_string()))?;
                Ok(Some(KernelCheckpoint { body, signature }))
            }
        }
    }

    /// Return canonical JSON bytes for receipts with seq in [start_seq, end_seq], ordered by seq.
    ///
    /// Uses RFC 8785 canonical JSON for deterministic Merkle leaf hashing.
    pub fn receipts_canonical_bytes_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM pact_tool_receipts
            WHERE seq >= ?1 AND seq <= ?2
            ORDER BY seq ASC
            "#,
        )?;
        let rows = statement.query_map(params![start_seq as i64, end_seq as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (seq, raw_json) = row?;
            let receipt: PactReceipt = serde_json::from_str(&raw_json)?;
            let canonical = canonical_json_bytes(&receipt)
                .map_err(|e| ReceiptStoreError::Canonical(e.to_string()))?;
            result.push((seq.max(0) as u64, canonical));
        }
        Ok(result)
    }

    /// Return the current on-disk size of the database in bytes.
    ///
    /// Uses `PRAGMA page_count` and `PRAGMA page_size` to compute the size
    /// without requiring a filesystem stat, which is consistent in WAL mode.
    pub fn db_size_bytes(&self) -> Result<u64, ReceiptStoreError> {
        let page_count: i64 = self
            .connection
            .query_row("PRAGMA page_count", [], |row| row.get(0))?;
        let page_size: i64 = self
            .connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))?;
        Ok((page_count.max(0) as u64) * (page_size.max(0) as u64))
    }

    /// Return the Unix timestamp (seconds) of the oldest receipt in the live
    /// database, or `None` if there are no receipts.
    pub fn oldest_receipt_timestamp(&self) -> Result<Option<u64>, ReceiptStoreError> {
        let ts = self.connection.query_row(
            "SELECT MIN(timestamp) FROM pact_tool_receipts",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        Ok(ts.map(|t| t.max(0) as u64))
    }

    /// Archive all receipts with `timestamp < cutoff_unix_secs` to an external
    /// SQLite file, then delete them from the live database.
    ///
    /// Checkpoint rows whose entire batch (`batch_end_seq`) falls within the
    /// archived receipt range are also copied to the archive. Partial batches
    /// are never archived to avoid breaking inclusion proofs.
    ///
    /// Returns the number of receipt rows deleted from the live database.
    pub fn archive_receipts_before(
        &mut self,
        cutoff_unix_secs: u64,
        archive_path: &str,
    ) -> Result<u64, ReceiptStoreError> {
        // Escape single quotes in the path to safely embed it in an ATTACH statement.
        let escaped_path = archive_path.replace('\'', "''");

        // Attach the archive database.
        self.connection
            .execute_batch(&format!("ATTACH DATABASE '{escaped_path}' AS archive"))?;

        // Create archive tables with the same schema as the main database.
        self.connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS archive.pact_tool_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision_kind TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS archive.kernel_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkpoint_seq INTEGER NOT NULL UNIQUE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                kernel_key TEXT NOT NULL
            );
            "#,
        )?;

        let cutoff = cutoff_unix_secs as i64;

        // Copy qualifying receipts to the archive (ignore duplicates from prior runs).
        self.connection.execute(
            "INSERT OR IGNORE INTO archive.pact_tool_receipts \
             SELECT * FROM main.pact_tool_receipts WHERE timestamp < ?1",
            params![cutoff],
        )?;

        // Find the maximum seq among archived receipts (for checkpoint filtering).
        let max_archived_seq: Option<i64> = self.connection.query_row(
            "SELECT MAX(seq) FROM main.pact_tool_receipts WHERE timestamp < ?1",
            params![cutoff],
            |row| row.get(0),
        )?;

        if let Some(max_seq) = max_archived_seq {
            // Copy checkpoint rows whose full batch is covered by the archived receipts.
            // Never archive a checkpoint whose batch_end_seq exceeds the max archived seq
            // because that would leave a partial batch in the archive.
            self.connection.execute(
                "INSERT OR IGNORE INTO archive.kernel_checkpoints \
                 SELECT * FROM main.kernel_checkpoints WHERE batch_end_seq <= ?1",
                params![max_seq],
            )?;

            // Verify that every checkpoint covering the archived range is now present
            // in the archive. If any checkpoint failed to transfer, refuse to delete the
            // receipts from the live database to preserve inclusion-proof integrity.
            let live_count: i64 = self.connection.query_row(
                "SELECT COUNT(*) FROM main.kernel_checkpoints WHERE batch_end_seq <= ?1",
                params![max_seq],
                |row| row.get(0),
            )?;
            let archive_count: i64 = self.connection.query_row(
                "SELECT COUNT(*) FROM archive.kernel_checkpoints WHERE batch_end_seq <= ?1",
                params![max_seq],
                |row| row.get(0),
            )?;
            if archive_count < live_count {
                // Detach the archive before returning the error to avoid leaving
                // the database in an attached state.
                let _ = self.connection.execute_batch("DETACH DATABASE archive");
                return Err(ReceiptStoreError::Canonical(format!(
                    "checkpoint co-archival incomplete: {live_count} checkpoints in live, \
                     only {archive_count} transferred to archive; aborting receipt deletion \
                     to preserve inclusion-proof integrity"
                )));
            }
        }

        // Delete archived receipts from the live database.
        let deleted = self.connection.execute(
            "DELETE FROM main.pact_tool_receipts WHERE timestamp < ?1",
            params![cutoff],
        )? as u64;

        // Detach the archive and checkpoint WAL.
        self.connection.execute_batch("DETACH DATABASE archive")?;
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;

        Ok(deleted)
    }

    /// Check time and size thresholds and archive receipts if either is exceeded.
    ///
    /// - Time threshold: receipts older than `config.retention_days` days are archived.
    /// - Size threshold: if `db_size_bytes()` exceeds `config.max_size_bytes`, receipts
    ///   older than the median timestamp are archived (removes roughly half the receipts).
    ///
    /// Returns the number of receipt rows archived (0 if no threshold was exceeded).
    pub fn rotate_if_needed(&mut self, config: &RetentionConfig) -> Result<u64, ReceiptStoreError> {
        // Check time threshold.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let time_cutoff = now.saturating_sub(config.retention_days.saturating_mul(86_400));
        let oldest = self.oldest_receipt_timestamp()?;

        if let Some(oldest_ts) = oldest {
            if oldest_ts < time_cutoff {
                return self.archive_receipts_before(time_cutoff, &config.archive_path);
            }
        }

        // Check size threshold.
        let size = self.db_size_bytes()?;
        if size > config.max_size_bytes {
            // Use the median timestamp as the cutoff to archive roughly half the receipts.
            let median_cutoff: Option<i64> = self
                .connection
                .query_row(
                    r#"
                    SELECT timestamp FROM pact_tool_receipts
                    ORDER BY timestamp
                    LIMIT 1
                    OFFSET (SELECT COUNT(*) FROM pact_tool_receipts) / 2
                    "#,
                    [],
                    |row| row.get(0),
                )
                .optional()?;

            if let Some(cutoff) = median_cutoff {
                return self.archive_receipts_before(cutoff.max(0) as u64, &config.archive_path);
            }
        }

        Ok(0)
    }

    /// Internal implementation for `query_receipts` (called from `receipt_query` module).
    ///
    /// Requires access to the private `connection` field, so it lives here in `receipt_store`.
    pub(crate) fn query_receipts_impl(
        &self,
        query: &ReceiptQuery,
    ) -> Result<ReceiptQueryResult, ReceiptStoreError> {
        // Validate the `outcome` filter against the known decision_kind values.
        // Silently accepting unknown values would return zero results and could
        // mask caller bugs; fail explicitly instead.
        const VALID_OUTCOMES: &[&str] = &["allow", "deny", "cancelled", "incomplete"];
        if let Some(outcome) = query.outcome.as_deref() {
            if !VALID_OUTCOMES.contains(&outcome) {
                return Err(ReceiptStoreError::InvalidOutcome(format!(
                    "unknown outcome filter {:?}; valid values are: allow, deny, cancelled, incomplete",
                    outcome
                )));
            }
        }

        let limit = query.limit.clamp(1, MAX_QUERY_LIMIT);

        // Both queries share the same 9 filter parameters.
        // Parameters:
        //   ?1  capability_id
        //   ?2  tool_server
        //   ?3  tool_name
        //   ?4  outcome (decision_kind)
        //   ?5  since (timestamp >=, inclusive)
        //   ?6  until (timestamp <=, inclusive)
        //   ?7  min_cost (json_extract cost_charged >=)
        //   ?8  max_cost (json_extract cost_charged <=)
        //   ?9  agent_subject (capability_lineage.subject_key via LEFT JOIN)
        //
        // Data query also uses:
        //   ?10 cursor (seq >, exclusive)
        //   ?11 limit
        //
        // When agent_subject is None, the LEFT JOIN produces NULL for cl.subject_key,
        // and the (?9 IS NULL OR ...) guard passes -- no rows are filtered out.
        let data_sql = r#"
            SELECT r.seq, r.raw_json
            FROM pact_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.decision_kind = ?4)
              AND (?5 IS NULL OR r.timestamp >= ?5)
              AND (?6 IS NULL OR r.timestamp <= ?6)
              AND (?7 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) >= ?7)
              AND (?8 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) <= ?8)
              AND (?9 IS NULL OR cl.subject_key = ?9)
              AND (?10 IS NULL OR r.seq > ?10)
            ORDER BY r.seq ASC
            LIMIT ?11
        "#;

        // Count query uses identical WHERE clause but no cursor and no LIMIT.
        // total_count reflects the full filtered set regardless of pagination.
        let count_sql = r#"
            SELECT COUNT(*)
            FROM pact_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.decision_kind = ?4)
              AND (?5 IS NULL OR r.timestamp >= ?5)
              AND (?6 IS NULL OR r.timestamp <= ?6)
              AND (?7 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) >= ?7)
              AND (?8 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) <= ?8)
              AND (?9 IS NULL OR cl.subject_key = ?9)
        "#;

        let cap_id = query.capability_id.as_deref();
        let tool_srv = query.tool_server.as_deref();
        let tool_nm = query.tool_name.as_deref();
        let outcome = query.outcome.as_deref();
        let since = query.since.map(|v| v as i64);
        let until = query.until.map(|v| v as i64);
        let min_cost = query.min_cost.map(|v| v as i64);
        let max_cost = query.max_cost.map(|v| v as i64);
        let agent_sub = query.agent_subject.as_deref();
        // Convert cursor to signed i64 for SQLite. SQLite AUTOINCREMENT seq
        // values are bounded by i64::MAX; a cursor above that can never be
        // exceeded. Convert with a checked cast: on overflow return an empty
        // receipts page (the cursor excludes everything) while still reporting
        // the correct total_count for the uncursored filter set.
        let cursor_i64: Option<i64> = match query.cursor {
            None => None,
            Some(c) => match i64::try_from(c) {
                Ok(v) => Some(v),
                Err(_) => {
                    // cursor > i64::MAX: no AUTOINCREMENT seq can exceed it.
                    // Run only the count query (no cursor applied) and return empty.
                    let total_count: u64 = self
                        .connection
                        .query_row(
                            count_sql,
                            params![
                                cap_id, tool_srv, tool_nm, outcome, since, until, min_cost,
                                max_cost, agent_sub,
                            ],
                            |row| row.get::<_, i64>(0),
                        )
                        .map(|n| n.max(0) as u64)?;
                    return Ok(ReceiptQueryResult {
                        receipts: Vec::new(),
                        total_count,
                        next_cursor: None,
                    });
                }
            },
        };

        // Execute data query.
        let mut stmt = self.connection.prepare(data_sql)?;
        let rows = stmt.query_map(
            params![
                cap_id,
                tool_srv,
                tool_nm,
                outcome,
                since,
                until,
                min_cost,
                max_cost,
                agent_sub,
                cursor_i64,
                limit as i64,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;

        let mut receipts = Vec::new();
        for row in rows {
            let (seq, raw_json) = row?;
            let receipt: PactReceipt = serde_json::from_str(&raw_json)?;
            receipts.push(StoredToolReceipt {
                seq: seq.max(0) as u64,
                receipt,
            });
        }

        // Execute count query (same filters, no cursor, no limit).
        let total_count: u64 = self
            .connection
            .query_row(
                count_sql,
                params![
                    cap_id, tool_srv, tool_nm, outcome, since, until, min_cost, max_cost,
                    agent_sub,
                ],
                |row| row.get::<_, i64>(0),
            )
            .map(|n| n.max(0) as u64)?;

        // next_cursor is Some(last_seq) when the page is full (more results may exist).
        let next_cursor = if receipts.len() == limit {
            receipts.last().map(|r| r.seq)
        } else {
            None
        };

        Ok(ReceiptQueryResult {
            receipts,
            total_count,
            next_cursor,
        })
    }
}

impl ReceiptStore for SqliteReceiptStore {
    fn append_pact_receipt(&mut self, receipt: &PactReceipt) -> Result<(), ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        self.connection.execute(
            r#"
            INSERT INTO pact_tool_receipts (
                receipt_id,
                timestamp,
                capability_id,
                tool_server,
                tool_name,
                decision_kind,
                policy_hash,
                content_hash,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt.id,
                receipt.timestamp,
                receipt.capability_id,
                receipt.tool_server,
                receipt.tool_name,
                decision_kind(&receipt.decision),
                receipt.policy_hash,
                receipt.content_hash,
                raw_json,
            ],
        )?;
        Ok(())
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }

    fn append_child_receipt(
        &mut self,
        receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        self.connection.execute(
            r#"
            INSERT INTO pact_child_receipts (
                receipt_id,
                timestamp,
                session_id,
                parent_request_id,
                request_id,
                operation_kind,
                terminal_state,
                policy_hash,
                outcome_hash,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt.id,
                receipt.timestamp,
                receipt.session_id.as_str(),
                receipt.parent_request_id.as_str(),
                receipt.request_id.as_str(),
                receipt.operation_kind.as_str(),
                terminal_state_kind(&receipt.terminal_state),
                receipt.policy_hash,
                receipt.outcome_hash,
                raw_json,
            ],
        )?;
        Ok(())
    }
}

fn decision_kind(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny { .. } => "deny",
        Decision::Cancelled { .. } => "cancelled",
        Decision::Incomplete { .. } => "incomplete",
    }
}

fn terminal_state_kind(state: &OperationTerminalState) -> &'static str {
    match state {
        OperationTerminalState::Completed => "completed",
        OperationTerminalState::Cancelled { .. } => "cancelled",
        OperationTerminalState::Incomplete { .. } => "incomplete",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use pact_core::crypto::Keypair;
    use pact_core::receipt::{
        ChildRequestReceipt, ChildRequestReceiptBody, Decision, PactReceipt, PactReceiptBody,
        ToolCallAction,
    };
    use pact_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};

    use crate::checkpoint::build_checkpoint;

    use super::*;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn sample_receipt() -> PactReceipt {
        let keypair = Keypair::generate();
        PactReceipt::sign(
            PactReceiptBody {
                id: "rcpt-test-001".to_string(),
                timestamp: 1,
                capability_id: "cap-1".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: ToolCallAction {
                    parameters: serde_json::json!({}),
                    parameter_hash: "abc123".to_string(),
                },
                decision: Decision::Allow,
                content_hash: "content-1".to_string(),
                policy_hash: "policy-1".to_string(),
                evidence: Vec::new(),
                metadata: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .unwrap()
    }

    fn sample_child_receipt() -> ChildRequestReceipt {
        let keypair = Keypair::generate();
        ChildRequestReceipt::sign(
            ChildRequestReceiptBody {
                id: "child-rcpt-test-001".to_string(),
                timestamp: 2,
                session_id: SessionId::new("sess-1"),
                parent_request_id: RequestId::new("parent-1"),
                request_id: RequestId::new("child-1"),
                operation_kind: OperationKind::CreateMessage,
                terminal_state: OperationTerminalState::Completed,
                outcome_hash: "outcome-1".to_string(),
                policy_hash: "policy-1".to_string(),
                metadata: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .unwrap()
    }

    #[test]
    fn sqlite_receipt_store_persists_across_reopen() {
        let path = unique_db_path("pact-receipts");
        {
            let mut store = SqliteReceiptStore::open(&path).unwrap();
            store.append_pact_receipt(&sample_receipt()).unwrap();
            store.append_child_receipt(&sample_child_receipt()).unwrap();
            assert_eq!(store.tool_receipt_count().unwrap(), 1);
            assert_eq!(store.child_receipt_count().unwrap(), 1);
        }

        let reopened = SqliteReceiptStore::open(&path).unwrap();
        assert_eq!(reopened.tool_receipt_count().unwrap(), 1);
        assert_eq!(reopened.child_receipt_count().unwrap(), 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_receipt_store_lists_filtered_receipts() {
        let path = unique_db_path("pact-receipts-filtered");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        store.append_pact_receipt(&sample_receipt()).unwrap();
        store.append_child_receipt(&sample_child_receipt()).unwrap();

        let tool_receipts = store
            .list_tool_receipts(
                10,
                Some("cap-1"),
                Some("shell"),
                Some("bash"),
                Some("allow"),
            )
            .unwrap();
        assert_eq!(tool_receipts.len(), 1);
        assert_eq!(tool_receipts[0].capability_id, "cap-1");
        assert_eq!(tool_receipts[0].tool_name, "bash");

        let child_receipts = store
            .list_child_receipts(
                10,
                Some("sess-1"),
                Some("parent-1"),
                Some("child-1"),
                Some("create_message"),
                Some("completed"),
            )
            .unwrap();
        assert_eq!(child_receipts.len(), 1);
        assert_eq!(child_receipts[0].session_id.as_str(), "sess-1");
        assert_eq!(child_receipts[0].request_id.as_str(), "child-1");

        let _ = fs::remove_file(path);
    }

    fn sample_receipt_with_id(id: &str) -> PactReceipt {
        let keypair = Keypair::generate();
        PactReceipt::sign(
            PactReceiptBody {
                id: id.to_string(),
                timestamp: 1,
                capability_id: "cap-1".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: ToolCallAction {
                    parameters: serde_json::json!({}),
                    parameter_hash: "abc123".to_string(),
                },
                decision: Decision::Allow,
                content_hash: "content-1".to_string(),
                policy_hash: "policy-1".to_string(),
                evidence: Vec::new(),
                metadata: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .unwrap()
    }

    #[test]
    fn open_creates_kernel_checkpoints_table() {
        let path = unique_db_path("pact-receipts-cp-table");
        let store = SqliteReceiptStore::open(&path).unwrap();
        // Query the table to confirm it exists.
        let count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM kernel_checkpoints", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn append_pact_receipt_returning_seq_returns_seq() {
        let path = unique_db_path("pact-receipts-seq");
        let mut store = SqliteReceiptStore::open(&path).unwrap();
        let receipt = sample_receipt_with_id("rcpt-seq-001");
        let seq = store.append_pact_receipt_returning_seq(&receipt).unwrap();
        assert!(seq > 0, "seq should be non-zero for a new insert");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn append_100_receipts_seqs_span_1_to_100() {
        let path = unique_db_path("pact-receipts-100");
        let mut store = SqliteReceiptStore::open(&path).unwrap();
        let mut seqs = Vec::new();
        for i in 0..100usize {
            let receipt = sample_receipt_with_id(&format!("rcpt-{i:04}"));
            let seq = store.append_pact_receipt_returning_seq(&receipt).unwrap();
            seqs.push(seq);
        }
        assert_eq!(seqs[0], 1);
        assert_eq!(seqs[99], 100);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn store_and_load_checkpoint_by_seq() {
        let path = unique_db_path("pact-receipts-cp-store");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        // Append 5 receipts.
        let mut seqs = Vec::new();
        for i in 0..5usize {
            let receipt = sample_receipt_with_id(&format!("rcpt-store-{i}"));
            let seq = store.append_pact_receipt_returning_seq(&receipt).unwrap();
            seqs.push(seq);
        }

        // Build checkpoint.
        let kp = Keypair::generate();
        let bytes: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("receipt-bytes-{i}").into_bytes())
            .collect();
        let cp = build_checkpoint(1, seqs[0], seqs[4], &bytes, &kp).unwrap();

        // Store and retrieve.
        store.store_checkpoint(&cp).unwrap();
        let loaded = store.load_checkpoint_by_seq(1).unwrap();
        assert!(loaded.is_some(), "checkpoint should be loadable");
        let loaded = loaded.unwrap();
        assert_eq!(loaded.body.checkpoint_seq, 1);
        assert_eq!(loaded.body.tree_size, 5);
        assert_eq!(loaded.body.batch_start_seq, seqs[0]);
        assert_eq!(loaded.body.batch_end_seq, seqs[4]);
        assert_eq!(
            loaded.signature.to_hex(),
            cp.signature.to_hex(),
            "signature should round-trip"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_checkpoint_by_seq_returns_none_for_missing() {
        let path = unique_db_path("pact-receipts-cp-missing");
        let store = SqliteReceiptStore::open(&path).unwrap();
        let result = store.load_checkpoint_by_seq(999).unwrap();
        assert!(result.is_none());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn receipts_canonical_bytes_range_returns_correct_count() {
        let path = unique_db_path("pact-receipts-canon-range");
        let mut store = SqliteReceiptStore::open(&path).unwrap();

        for i in 0..10usize {
            let receipt = sample_receipt_with_id(&format!("rcpt-canon-{i}"));
            store.append_pact_receipt_returning_seq(&receipt).unwrap();
        }

        // Fetch seqs 3..=7 (5 receipts).
        let range = store.receipts_canonical_bytes_range(3, 7).unwrap();
        assert_eq!(range.len(), 5, "should return 5 receipts in range 3..=7");
        assert_eq!(range[0].0, 3);
        assert_eq!(range[4].0, 7);

        // Verify all bytes are non-empty canonical JSON.
        for (_, bytes) in &range {
            assert!(!bytes.is_empty());
            // Should be valid JSON.
            let _: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        }

        let _ = fs::remove_file(path);
    }
}
