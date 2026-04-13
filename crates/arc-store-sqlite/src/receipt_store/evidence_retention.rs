use super::*;

impl SqliteReceiptStore {
    pub fn append_arc_receipt_returning_seq(
        &mut self,
        receipt: &ArcReceipt,
    ) -> Result<u64, ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        let attribution = extract_receipt_attribution(receipt);
        let tx = self.connection.transaction()?;
        let inserted = tx.execute(
            r#"
            INSERT INTO arc_tool_receipts (
                receipt_id,
                timestamp,
                capability_id,
                subject_key,
                issuer_key,
                grant_index,
                tool_server,
                tool_name,
                decision_kind,
                policy_hash,
                content_hash,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt.id,
                receipt.timestamp,
                receipt.capability_id,
                attribution.subject_key,
                attribution.issuer_key,
                attribution.grant_index.map(i64::from),
                receipt.tool_server,
                receipt.tool_name,
                decision_kind(&receipt.decision),
                receipt.policy_hash,
                receipt.content_hash,
                raw_json,
            ],
        )?;
        if inserted == 0 {
            tx.commit()?;
            return Ok(0);
        }
        let seq = tx.last_insert_rowid().max(0) as u64;
        tx.commit()?;
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
            FROM arc_tool_receipts
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
            let receipt: ArcReceipt = serde_json::from_str(&raw_json)?;
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
            "SELECT MIN(timestamp) FROM arc_tool_receipts",
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
            CREATE TABLE IF NOT EXISTS archive.arc_tool_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                grant_index INTEGER,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision_kind TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS archive.arc_child_receipts (
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

            CREATE TABLE IF NOT EXISTS archive.capability_lineage (
                capability_id        TEXT PRIMARY KEY,
                subject_key          TEXT NOT NULL,
                issuer_key           TEXT NOT NULL,
                issued_at            INTEGER NOT NULL,
                expires_at           INTEGER NOT NULL,
                grants_json          TEXT NOT NULL,
                delegation_depth     INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT
            );
            "#,
        )?;

        let cutoff = cutoff_unix_secs as i64;

        // Copy qualifying receipts to the archive (ignore duplicates from prior runs).
        self.connection.execute(
            "INSERT OR IGNORE INTO archive.arc_tool_receipts \
             SELECT * FROM main.arc_tool_receipts WHERE timestamp < ?1",
            params![cutoff],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO archive.arc_child_receipts \
             SELECT * FROM main.arc_child_receipts WHERE timestamp < ?1",
            params![cutoff],
        )?;
        self.connection.execute(
            "INSERT OR IGNORE INTO archive.capability_lineage
             SELECT DISTINCT cl.*
             FROM main.capability_lineage cl
             INNER JOIN main.arc_tool_receipts r ON r.capability_id = cl.capability_id
             WHERE r.timestamp < ?1",
            params![cutoff],
        )?;

        // Find the maximum seq among archived receipts (for checkpoint filtering).
        let max_archived_seq: Option<i64> = self.connection.query_row(
            "SELECT MAX(seq) FROM main.arc_tool_receipts WHERE timestamp < ?1",
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
            "DELETE FROM main.arc_tool_receipts WHERE timestamp < ?1",
            params![cutoff],
        )? as u64;
        self.connection.execute(
            "DELETE FROM main.arc_child_receipts WHERE timestamp < ?1",
            params![cutoff],
        )?;

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
                    SELECT timestamp FROM arc_tool_receipts
                    ORDER BY timestamp
                    LIMIT 1
                    OFFSET (SELECT COUNT(*) FROM arc_tool_receipts) / 2
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
        //   ?9  agent_subject (receipt subject_key, falling back to capability_lineage)
        // Data query also uses:
        //   ?10 cursor (seq >, exclusive)
        //   ?11 limit
        //
        // When agent_subject is None, the LEFT JOIN produces NULL for cl.subject_key,
        // and the (?9 IS NULL OR ...) guard passes -- no rows are filtered out.
        let data_sql = r#"
            SELECT r.seq, r.raw_json
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.decision_kind = ?4)
              AND (?5 IS NULL OR r.timestamp >= ?5)
              AND (?6 IS NULL OR r.timestamp <= ?6)
              AND (?7 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) >= ?7)
              AND (?8 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) <= ?8)
              AND (?9 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?9)
              AND (?10 IS NULL OR r.seq > ?10)
            ORDER BY r.seq ASC
            LIMIT ?11
        "#;

        // Count query uses identical WHERE clause but no cursor and no LIMIT.
        // total_count reflects the full filtered set regardless of pagination.
        let count_sql = r#"
            SELECT COUNT(*)
            FROM arc_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.decision_kind = ?4)
              AND (?5 IS NULL OR r.timestamp >= ?5)
              AND (?6 IS NULL OR r.timestamp <= ?6)
              AND (?7 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) >= ?7)
              AND (?8 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) <= ?8)
              AND (?9 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?9)
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
            let receipt: ArcReceipt = serde_json::from_str(&raw_json)?;
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
