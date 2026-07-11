use super::support::{
    ensure_checkpoint_transparency_guards, ensure_transparency_projection_guards,
    insert_receipt_retention_watermark, load_claim_tree_canonical_bytes_range,
    load_persisted_checkpoint_row, parse_persisted_checkpoint_row, store_kernel_checkpoint_atomic,
};
use super::*;

impl SqliteReceiptStore {
    pub fn append_chio_receipt_returning_seq(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<u64, ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        self.append_verified_chio_receipt_record(receipt, &raw_json, false)
    }

    /// Store a signed KernelCheckpoint in the kernel_checkpoints table.
    pub fn store_checkpoint(&self, checkpoint: &KernelCheckpoint) -> Result<(), ReceiptStoreError> {
        let checkpoint = checkpoint.clone();
        self.writer_handle()
            .run_write(move |connection| store_kernel_checkpoint_atomic(connection, &checkpoint))
    }

    /// Load a KernelCheckpoint by its checkpoint_seq.
    pub fn load_checkpoint_by_seq(
        &self,
        checkpoint_seq: u64,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        let connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;
        load_persisted_checkpoint_row(&connection, checkpoint_seq)?
            .map(parse_persisted_checkpoint_row)
            .transpose()
    }

    /// Return canonical JSON bytes for receipts with seq in [start_seq, end_seq], ordered by seq.
    ///
    /// Uses RFC 8785 canonical JSON for deterministic Merkle leaf hashing.
    pub fn receipts_canonical_bytes_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        let connection = self.connection()?;
        load_claim_tree_canonical_bytes_range(&connection, start_seq, end_seq)
    }

    /// Return the current on-disk size of the database in bytes.
    ///
    /// Uses `PRAGMA page_count` and `PRAGMA page_size` to compute the size
    /// without requiring a filesystem stat, which is consistent in WAL mode.
    pub fn db_size_bytes(&self) -> Result<u64, ReceiptStoreError> {
        let page_count: i64 = self
            .connection()?
            .query_row("PRAGMA page_count", [], |row| row.get(0))?;
        let page_size: i64 = self
            .connection()?
            .query_row("PRAGMA page_size", [], |row| row.get(0))?;
        Ok((page_count.max(0) as u64) * (page_size.max(0) as u64))
    }

    /// Live logical size in bytes: `(page_count - freelist_count) * page_size`.
    /// Unlike `db_size_bytes` (on-disk, freelist included), this drops after an
    /// archival delete plus incremental_vacuum, so a size-driven rotation
    /// trigger converges instead of re-firing on freed-but-not-reclaimed pages.
    pub fn live_db_size_bytes(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        live_db_size_bytes_on_connection(&connection)
    }

    /// Return the Unix timestamp (seconds) of the oldest receipt in the live
    /// database, or `None` if there are no receipts.
    pub fn oldest_receipt_timestamp(&self) -> Result<Option<u64>, ReceiptStoreError> {
        let ts = self.connection()?.query_row(
            "SELECT MIN(timestamp) FROM chio_tool_receipts",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        Ok(ts.map(|t| t.max(0) as u64))
    }

    /// Return the oldest live receipt timestamp for a tenant.
    pub fn oldest_receipt_timestamp_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        let ts = self.connection()?.query_row(
            "SELECT MIN(timestamp) FROM chio_tool_receipts WHERE tenant_id = ?1",
            params![tenant_id],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        Ok(ts.map(|t| t.max(0) as u64))
    }

    /// Archive all receipts whose entire checkpointed prefix has aged past
    /// `cutoff_unix_secs`, co-archiving the claim-log projection and
    /// reconciliation evidence, then deleting the archived range from the live
    /// store, all on the single writer connection. Returns the number of
    /// tool-receipt rows archived.
    pub fn archive_receipts_before(
        &self,
        cutoff_unix_secs: u64,
        archive_path: &str,
    ) -> Result<u64, ReceiptStoreError> {
        let config = RetentionConfig {
            retention_days: 0,
            max_size_bytes: u64::MAX,
            archive_path: archive_path.to_string(),
            tenant_id: None,
            explicit_cutoff_unix_secs: Some(cutoff_unix_secs),
            ..RetentionConfig::default()
        };
        // archive_receipts_before is the explicit-cutoff entry point, so bypass
        // rotate_if_needed's day/size threshold math and dispatch the cutoff
        // directly to the writer actor.
        self.dispatch_rotate(Box::new(config), Some(cutoff_unix_secs))
    }

    /// Check the time and size thresholds and, if either is exceeded, run a
    /// checkpoint-aligned rotation on the writer connection.
    ///
    /// - Time threshold: receipts older than `config.retention_days` days age
    ///   out of the checkpointed prefix.
    /// - Size threshold: if the live database size exceeds `max_size_bytes`,
    ///   the median-timestamp cutoff archives roughly the checkpointed half.
    ///
    /// Returns the number of tool-receipt rows archived (0 when no whole
    /// checkpointed batch has fully aged, i.e. a no-op rotation).
    pub fn rotate_if_needed(&self, config: &RetentionConfig) -> Result<u64, ReceiptStoreError> {
        self.dispatch_rotate(Box::new(config.clone()), None)
    }

    fn dispatch_rotate(
        &self,
        config: Box<RetentionConfig>,
        explicit_cutoff: Option<u64>,
    ) -> Result<u64, ReceiptStoreError> {
        if config.tenant_id.is_some() {
            // Tenant-scoped archival is not expressible as a prefix watermark,
            // so reject here before any partial work runs.
            return Err(ReceiptStoreError::RetentionTenantScopeUnsupported);
        }
        let config = match explicit_cutoff {
            Some(cutoff) => {
                let mut config = config;
                config.retention_days = 0;
                config.explicit_cutoff_unix_secs = Some(cutoff);
                config
            }
            None => config,
        };
        let (response, result) = std::sync::mpsc::sync_channel(1);
        // A rotation is an in-flight writer just like an append or a Write job:
        // increment BEFORE handing the command to the actor so a concurrent
        // `receipt_store_health` cannot observe a dequeued-but-uncounted
        // rotation, mirroring `ReceiptCommitActor::append` and
        // `WriterHandle::run_write_kind`. The Rotate actor arm decrements
        // unconditionally on dequeue; any send or recv failure here undoes the
        // speculative increment so a rejected rotation never leaks inflight.
        let health = &self.receipt_commit_actor.health;
        health
            .inflight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Err(error) = self
            .receipt_commit_actor
            .sender
            .try_send(ReceiptCommitCommand::Rotate { config, response })
        {
            atomic_saturating_sub(&health.inflight, 1);
            return Err(match error {
                std::sync::mpsc::TrySendError::Full(_) => receipt_actor_saturated_error(),
                std::sync::mpsc::TrySendError::Disconnected(_) => receipt_actor_unavailable_error(),
            });
        }
        match result.recv() {
            Ok(outcome) => outcome,
            Err(_) => {
                atomic_saturating_sub(&health.inflight, 1);
                Err(receipt_actor_unavailable_error())
            }
        }
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

        // Receipt read isolation: admin contexts can read all rows, tenant
        // contexts see exact tenant rows by default, and local compatibility
        // mode may include NULL-tenant (pre-multitenant) rows.
        let read_scope = query
            .effective_read_scope()
            .map_err(ReceiptStoreError::ReadBoundary)?;
        let tenant_fragment = match (
            read_scope.tenant.as_deref(),
            read_scope.include_null_tenant && !self.strict_tenant_isolation_enabled(),
        ) {
            (None, _) => "(?12 IS NULL)",
            (Some(_), true) => "(r.tenant_id = ?12 OR r.tenant_id IS NULL)",
            (Some(_), false) => "(r.tenant_id = ?12)",
        };

        // Both queries share the same filter parameters.
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
        //   ?12 tenant_filter (tenant_id exact match or NULL fallback)
        // Data query also uses:
        //   ?10 cursor (seq >, exclusive)
        //   ?11 limit
        //
        // When agent_subject is None, the LEFT JOIN produces NULL for cl.subject_key,
        // and the (?9 IS NULL OR ...) guard passes -- no rows are filtered out.
        let data_sql = format!(
            r#"
            SELECT r.seq, r.raw_json
            FROM chio_tool_receipts r
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
              AND {tenant_fragment}
              AND (?10 IS NULL OR r.seq > ?10)
            ORDER BY r.seq ASC
            LIMIT ?11
        "#
        );

        // Count query uses identical WHERE clause but no cursor and no LIMIT.
        // total_count reflects the full filtered set regardless of pagination.
        let count_sql = format!(
            r#"
            SELECT COUNT(*)
            FROM chio_tool_receipts r
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
              AND {tenant_fragment}
        "#
        );

        let cap_id = query.capability_id.as_deref();
        let tool_srv = query.tool_server.as_deref();
        let tool_nm = query.tool_name.as_deref();
        let outcome = query.outcome.as_deref();
        let since = query.since.map(|v| v as i64);
        let until = query.until.map(|v| v as i64);
        let min_cost = query.min_cost.map(|v| v as i64);
        let max_cost = query.max_cost.map(|v| v as i64);
        let agent_sub = query.agent_subject.as_deref();
        let tenant = read_scope.tenant.as_deref();
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
                    // ?10 and ?11 (cursor/limit) are not used in the count query
                    // but must still bind placeholders if we reuse `params!`;
                    // the count SQL uses only ?1..=?9 and ?12, so we need to
                    // bind ?10 and ?11 as NULL / 0 to keep indexes stable.
                    let total_count: u64 = self
                        .connection()?
                        .query_row(
                            &count_sql,
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
                                // ?10, ?11 unused in count_sql but bound so ?12
                                // resolves to the tenant filter.
                                None::<i64>,
                                0i64,
                                tenant,
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
        let connection = self.connection()?;
        let mut stmt = connection.prepare(&data_sql)?;
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
                tenant,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;

        let mut receipts = Vec::new();
        for row in rows {
            let (seq, raw_json) = row?;
            let seq = seq.max(0) as u64;
            let receipt =
                decode_verified_chio_receipt(&raw_json, "persisted tool receipt", Some(seq))?;
            receipts.push(StoredToolReceipt { seq, receipt });
        }

        // Execute count query (same filters, no cursor, no limit).
        let total_count: u64 = self
            .connection()?
            .query_row(
                &count_sql,
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
                    // ?10, ?11 unused in count_sql; bound to keep ?12 stable.
                    None::<i64>,
                    0i64,
                    tenant,
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

/// Largest checkpoint `batch_end_seq` whose entire covered prefix (in the
/// entry_seq domain) has aged past `cutoff`. 0 when no whole checkpointed batch
/// has fully aged (a no-op rotation).
fn compute_archival_watermark(
    connection: &rusqlite::Connection,
    cutoff_unix_secs: u64,
) -> Result<u64, ReceiptStoreError> {
    let cutoff = sqlite_i64(cutoff_unix_secs, "retention cutoff")?;
    let watermark: i64 = connection.query_row(
        r#"
        SELECT COALESCE(MAX(kc.batch_end_seq), 0)
        FROM kernel_checkpoints kc
        WHERE NOT EXISTS (
            SELECT 1 FROM claim_receipt_log_entries e
            WHERE e.entry_seq <= kc.batch_end_seq
              AND e.timestamp >= ?1
        )
        "#,
        params![cutoff],
        |row| row.get(0),
    )?;
    sqlite_u64(watermark, "retention watermark")
}

/// Resolve the effective cutoff for a rotation config (explicit cutoff wins;
/// else the day/size thresholds from `rotate_if_needed`'s contract).
fn resolve_rotation_cutoff(
    connection: &rusqlite::Connection,
    config: &RetentionConfig,
) -> Result<Option<u64>, ReceiptStoreError> {
    if let Some(cutoff) = config.explicit_cutoff_unix_secs {
        return Ok(Some(cutoff));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let time_cutoff = now.saturating_sub(config.retention_days.saturating_mul(86_400));
    let oldest: Option<i64> =
        connection.query_row("SELECT MIN(timestamp) FROM chio_tool_receipts", [], |row| {
            row.get::<_, Option<i64>>(0)
        })?;
    if let Some(oldest_ts) = oldest {
        if (oldest_ts.max(0) as u64) < time_cutoff {
            return Ok(Some(time_cutoff));
        }
    }
    // Size trigger: measured against live_db_size_bytes (freelist-adjusted),
    // not the raw on-disk db_size_bytes, so the trigger converges.
    let size = live_db_size_bytes_on_connection(connection)?;
    if size > config.max_size_bytes {
        let median: Option<i64> = connection
            .query_row(
                "SELECT timestamp FROM chio_tool_receipts ORDER BY timestamp \
                 LIMIT 1 OFFSET (SELECT COUNT(*) FROM chio_tool_receipts) / 2",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(cutoff) = median {
            return Ok(Some(cutoff.max(0) as u64));
        }
    }
    Ok(None)
}

/// Live logical size backing `SqliteReceiptStore::live_db_size_bytes`:
/// `(page_count - freelist_count) * page_size`. Freelist pages are excluded
/// so an archival delete plus `incremental_vacuum` strictly reduces this
/// value and the size rotation trigger in `resolve_rotation_cutoff` converges
/// instead of re-firing on freed-but-not-reclaimed pages.
fn live_db_size_bytes_on_connection(
    connection: &rusqlite::Connection,
) -> Result<u64, ReceiptStoreError> {
    let page_count: i64 = connection.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    let freelist_count: i64 =
        connection.query_row("PRAGMA freelist_count", [], |row| row.get(0))?;
    let page_size: i64 = connection.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    let live_pages = (page_count - freelist_count).max(0);
    Ok((live_pages as u64) * (page_size.max(0) as u64))
}

/// Entry point run on the single writer connection by the `Rotate` command.
pub(super) fn rotate_on_writer_connection(
    connection: &mut rusqlite::Connection,
    config: &RetentionConfig,
) -> Result<u64, ReceiptStoreError> {
    if config.tenant_id.is_some() {
        return Err(ReceiptStoreError::RetentionTenantScopeUnsupported);
    }
    // One-time migration: enable incremental auto-vacuum on a legacy store
    // that predates this pragma so the first rotation on the drained writer
    // starts reclaiming freed pages. A no-op once migrated.
    super::support::migrate_auto_vacuum_incremental_if_needed(connection)?;
    let Some(cutoff) = resolve_rotation_cutoff(connection, config)? else {
        return Ok(0);
    };
    archive_range(connection, cutoff, &config.archive_path)
}

/// Co-archive-and-delete the checkpoint-aligned prefix [1, W]. All deletes plus
/// the trigger drop/recreate plus the watermark insert run in ONE BEGIN
/// IMMEDIATE transaction on the writer connection; the
/// copy is idempotent and completes first, so a crash between copy and delete
/// leaves the live store intact and the rotation re-runnable.
fn archive_range(
    connection: &mut rusqlite::Connection,
    cutoff_unix_secs: u64,
    archive_path: &str,
) -> Result<u64, ReceiptStoreError> {
    let watermark = compute_archival_watermark(connection, cutoff_unix_secs)?;
    if watermark == 0 {
        return Ok(0); // fail-safe: nothing checkpointed has fully aged.
    }
    // Idempotency / monotonicity: a rotation only ever advances the prefix.
    // When the recomputed watermark does not exceed what is already archived
    // (a re-run at the same or an earlier cutoff), there is nothing new to
    // archive. Returning early keeps the DB-level monotonic watermark trigger
    // (strictly-increasing) from rejecting a redundant re-insert and makes a
    // repeated rotation a clean no-op rather than an error.
    if let Some(current) = super::support::retention_watermark(connection)? {
        if watermark <= current {
            return Ok(0);
        }
    }
    let w = sqlite_i64(watermark, "archival watermark")?;

    let escaped_path = archive_path.replace('\'', "''");
    connection.execute_batch(&format!("ATTACH DATABASE '{escaped_path}' AS archive"))?;

    let result = (|| -> Result<u64, ReceiptStoreError> {
        create_archive_schema(connection)?;
        let archived = copy_archived_prefix(connection, w)?;
        verify_co_archival_complete(connection, w)?; // RetentionArchiveIncomplete on any shortfall
        delete_archived_prefix_in_tx(connection, w, cutoff_unix_secs, archive_path)?;
        Ok(archived)
    })();

    let detach = connection.execute_batch("DETACH DATABASE archive");
    let archived = match (result, detach) {
        (Ok(archived), Ok(())) => archived,
        (Err(error), _) => return Err(error),
        (Ok(_), Err(error)) => return Err(error.into()),
    };

    // Reclaim freelist pages produced by the delete and shrink the WAL.
    connection.execute_batch("PRAGMA incremental_vacuum")?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(archived)
}

/// Create the archive schema. The archive gains the receipt tables, the
/// checkpoint rows, capability lineage, the claim-log projection (with
/// `entry_seq` preserved: `INTEGER PRIMARY KEY`, no `AUTOINCREMENT`, so copied
/// values insert verbatim), settlement/metered reconciliations and
/// authorization consumptions. The archive `chio_tool_receipts` mirrors the
/// live column layout exactly, including the `tenant_id` column added to the
/// live table by the attribution migration (`ensure_tool_receipt_attribution_columns`),
/// so a global rotation over a mixed-tenant store preserves tenant attribution
/// in the archive. Every copy names its columns explicitly (except the tables
/// copied with `SELECT *`, whose column order is asserted to match the live
/// DDL) so a future column added to one side cannot silently produce a
/// positional or column-count mismatch at runtime.
///
/// The checkpoint-projection tables (`checkpoint_tree_heads`,
/// `checkpoint_predecessor_witnesses`, `checkpoint_publication_metadata`,
/// `checkpoint_publication_trust_anchor_bindings`) exist here schema-only
/// (unpopulated): `SqliteReceiptStore::open()` on the archive rebuilds them
/// from the co-archived `kernel_checkpoints` rows (the archive is a minimal
/// evidence bundle, see the retention test suite), but
/// `require_existing_receipt_schema` requires all seven core tables to be
/// present for `open_existing()`, and `ensure_transparency_projection_guards`
/// creates its reject-update/reject-delete triggers on all of them
/// unconditionally. Without these table shells, `open_existing()` against a
/// freshly rotated archive fails closed with a missing-table error before a
/// caller can even read the co-archived reconciliation rows. Unlike the live
/// schema, the archive versions carry no `REFERENCES` clauses: the archive is
/// a write-once evidence copy, not a live database enforcing FK-cascade
/// invariants.
fn create_archive_schema(connection: &rusqlite::Connection) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS archive.chio_tool_receipts (
            seq INTEGER PRIMARY KEY,
            receipt_id TEXT NOT NULL UNIQUE, timestamp INTEGER NOT NULL,
            capability_id TEXT NOT NULL, subject_key TEXT, issuer_key TEXT,
            grant_index INTEGER, tool_server TEXT NOT NULL, tool_name TEXT NOT NULL,
            decision_kind TEXT NOT NULL, policy_hash TEXT NOT NULL,
            content_hash TEXT NOT NULL, raw_json TEXT NOT NULL, tenant_id TEXT
        );
        CREATE TABLE IF NOT EXISTS archive.chio_child_receipts (
            seq INTEGER PRIMARY KEY,
            receipt_id TEXT NOT NULL UNIQUE, timestamp INTEGER NOT NULL,
            session_id TEXT NOT NULL, parent_request_id TEXT NOT NULL,
            request_id TEXT NOT NULL, operation_kind TEXT NOT NULL,
            terminal_state TEXT NOT NULL, policy_hash TEXT NOT NULL,
            outcome_hash TEXT NOT NULL, raw_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.kernel_checkpoints (
            id INTEGER PRIMARY KEY, checkpoint_seq INTEGER NOT NULL UNIQUE,
            batch_start_seq INTEGER NOT NULL, batch_end_seq INTEGER NOT NULL,
            tree_size INTEGER NOT NULL, merkle_root TEXT NOT NULL,
            issued_at INTEGER NOT NULL, statement_json TEXT NOT NULL,
            signature TEXT NOT NULL, kernel_key TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.capability_lineage (
            capability_id TEXT PRIMARY KEY, subject_key TEXT NOT NULL,
            issuer_key TEXT NOT NULL, issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL, grants_json TEXT NOT NULL,
            delegation_depth INTEGER NOT NULL DEFAULT 0, parent_capability_id TEXT
        );
        CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries (
            entry_seq INTEGER PRIMARY KEY,
            receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL,
            source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL,
            capability_id TEXT, session_id TEXT, parent_request_id TEXT,
            request_id TEXT, subject_key TEXT, issuer_key TEXT,
            tool_server TEXT, tool_name TEXT, raw_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.settlement_reconciliations (
            receipt_id TEXT PRIMARY KEY, reconciliation_state TEXT NOT NULL,
            note TEXT, updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.metered_billing_reconciliations (
            receipt_id TEXT PRIMARY KEY, adapter_kind TEXT NOT NULL,
            evidence_id TEXT NOT NULL, observed_units INTEGER NOT NULL,
            billed_cost_units INTEGER NOT NULL, billed_cost_currency TEXT NOT NULL,
            evidence_sha256 TEXT, recorded_at INTEGER NOT NULL,
            reconciliation_state TEXT NOT NULL, note TEXT, updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.chio_authorization_receipt_consumptions (
            authorization_receipt_id TEXT PRIMARY KEY, consumer_receipt_id TEXT NOT NULL,
            request_id TEXT NOT NULL, session_id TEXT NOT NULL, tool_call_id TEXT NOT NULL,
            tenant_id TEXT, parameter_hash TEXT NOT NULL, consumed_at_unix_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.checkpoint_tree_heads (
            checkpoint_seq INTEGER PRIMARY KEY, batch_start_seq INTEGER NOT NULL,
            batch_end_seq INTEGER NOT NULL, tree_size INTEGER NOT NULL,
            merkle_root TEXT NOT NULL, issued_at INTEGER NOT NULL, kernel_key TEXT NOT NULL,
            previous_checkpoint_sha256 TEXT, statement_json TEXT NOT NULL, signature TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.checkpoint_predecessor_witnesses (
            predecessor_checkpoint_seq INTEGER NOT NULL, witness_checkpoint_seq INTEGER PRIMARY KEY,
            previous_checkpoint_sha256 TEXT NOT NULL, witnessed_at INTEGER NOT NULL,
            witness_statement_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.checkpoint_publication_metadata (
            checkpoint_seq INTEGER PRIMARY KEY, publication_schema TEXT NOT NULL,
            merkle_root TEXT NOT NULL, published_at INTEGER NOT NULL, kernel_key TEXT NOT NULL,
            log_tree_size INTEGER NOT NULL, entry_start_seq INTEGER NOT NULL,
            entry_end_seq INTEGER NOT NULL, previous_checkpoint_sha256 TEXT
        );
        CREATE TABLE IF NOT EXISTS archive.checkpoint_publication_trust_anchor_bindings (
            checkpoint_seq INTEGER PRIMARY KEY, binding_json TEXT NOT NULL
        );
        "#,
    )?;
    Ok(())
}

/// Idempotent copy of the [1, W] prefix into the archive (INSERT OR IGNORE).
/// Returns the number of newly archived tool-receipt rows.
fn copy_archived_prefix(
    connection: &rusqlite::Connection,
    w: i64,
) -> Result<u64, ReceiptStoreError> {
    let before: i64 = connection.query_row(
        "SELECT COUNT(*) FROM archive.chio_tool_receipts",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch(&format!(
        r#"
        INSERT OR IGNORE INTO archive.claim_receipt_log_entries
            SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= {w};
        INSERT OR IGNORE INTO archive.chio_tool_receipts
            (seq, receipt_id, timestamp, capability_id, subject_key, issuer_key,
             grant_index, tool_server, tool_name, decision_kind, policy_hash,
             content_hash, raw_json, tenant_id)
            SELECT seq, receipt_id, timestamp, capability_id, subject_key, issuer_key,
                   grant_index, tool_server, tool_name, decision_kind, policy_hash,
                   content_hash, raw_json, tenant_id
            FROM main.chio_tool_receipts WHERE seq IN (
                SELECT source_seq FROM main.claim_receipt_log_entries
                WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        INSERT OR IGNORE INTO archive.chio_child_receipts
            (seq, receipt_id, timestamp, session_id, parent_request_id, request_id,
             operation_kind, terminal_state, policy_hash, outcome_hash, raw_json)
            SELECT seq, receipt_id, timestamp, session_id, parent_request_id, request_id,
                   operation_kind, terminal_state, policy_hash, outcome_hash, raw_json
            FROM main.chio_child_receipts WHERE seq IN (
                SELECT source_seq FROM main.claim_receipt_log_entries
                WHERE entry_seq <= {w} AND receipt_kind = 'child_receipt');
        INSERT OR IGNORE INTO archive.kernel_checkpoints
            SELECT * FROM main.kernel_checkpoints WHERE batch_end_seq <= {w};
        INSERT OR IGNORE INTO archive.capability_lineage
            SELECT DISTINCT cl.* FROM main.capability_lineage cl
            INNER JOIN main.chio_tool_receipts r ON r.capability_id = cl.capability_id
            WHERE r.seq IN (
                SELECT source_seq FROM main.claim_receipt_log_entries
                WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        INSERT OR IGNORE INTO archive.settlement_reconciliations
            SELECT * FROM main.settlement_reconciliations WHERE receipt_id IN (
                SELECT receipt_id FROM main.claim_receipt_log_entries
                WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        INSERT OR IGNORE INTO archive.metered_billing_reconciliations
            SELECT * FROM main.metered_billing_reconciliations WHERE receipt_id IN (
                SELECT receipt_id FROM main.claim_receipt_log_entries
                WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        INSERT OR IGNORE INTO archive.chio_authorization_receipt_consumptions
            SELECT * FROM main.chio_authorization_receipt_consumptions WHERE authorization_receipt_id IN (
                SELECT receipt_id FROM main.claim_receipt_log_entries
                WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        "#
    ))?;
    let after: i64 = connection.query_row(
        "SELECT COUNT(*) FROM archive.chio_tool_receipts",
        [],
        |row| row.get(0),
    )?;
    sqlite_u64((after - before).max(0), "archived tool receipt delta")
}

/// Every row the delete will remove must already be in the archive, and it must
/// be IDENTICAL to the live row, not merely present. Presence alone is not
/// enough: the copy uses `INSERT OR IGNORE`, so a pre-existing archive row with
/// the same primary key but different bytes (a conflicting or partially-written
/// prior archive, or a reused archive file) is silently kept and the live row
/// is dropped by the IGNORE. A count-only check would pass while the archive
/// held stale bytes, and the delete would then leave the store with no faithful
/// archived copy. Every archived table the delete touches is therefore verified
/// by identity: the receipt tables (`chio_tool_receipts`, `chio_child_receipts`)
/// on `seq` (the primary key the claim-log projection's `source_seq` points at,
/// so a same-`receipt_id` archive row copied under a different `seq` cannot pass)
/// and `raw_json`, and the claim-log projection, checkpoint rows, and
/// settlement/metered/consumption reconciliations by a NULL-safe (`IS`)
/// full-column compare of the live prefix rows against their archive
/// counterparts (keyed on each table's primary key). The compare is bounded to
/// the archived prefix (`O(archived rows)`, a primary-key lookup per row, never
/// `O(full history)`). Any shortfall aborts before any delete (fail-closed,
/// `RetentionArchiveIncomplete`).
fn verify_co_archival_complete(
    connection: &rusqlite::Connection,
    w: i64,
) -> Result<(), ReceiptStoreError> {
    let checks: [(&'static str, String, String); 7] = [
        (
            // Present AND byte-identical: `archive_sql` counts only live prefix
            // rows that have an archive row with the same `receipt_id` and
            // identical `raw_json`, so a missing OR divergent archive row makes
            // archived < live and aborts before the delete.
            "chio_tool_receipts",
            format!(
                "SELECT COUNT(*) FROM main.chio_tool_receipts WHERE seq IN \
                 (SELECT source_seq FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt')"
            ),
            format!(
                "SELECT COUNT(*) FROM main.chio_tool_receipts m WHERE m.seq IN \
                 (SELECT source_seq FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt') \
                 AND EXISTS (SELECT 1 FROM archive.chio_tool_receipts a WHERE a.seq = m.seq AND a.receipt_id = m.receipt_id AND a.raw_json = m.raw_json)"
            ),
        ),
        (
            "chio_child_receipts",
            format!(
                "SELECT COUNT(*) FROM main.chio_child_receipts WHERE seq IN \
                 (SELECT source_seq FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'child_receipt')"
            ),
            format!(
                "SELECT COUNT(*) FROM main.chio_child_receipts m WHERE m.seq IN \
                 (SELECT source_seq FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'child_receipt') \
                 AND EXISTS (SELECT 1 FROM archive.chio_child_receipts a WHERE a.seq = m.seq AND a.receipt_id = m.receipt_id AND a.raw_json = m.raw_json)"
            ),
        ),
        (
            // Identity on the full row (entry_seq is the PK, copied verbatim):
            // a divergent archived projection row makes archived < live.
            "claim_receipt_log_entries",
            format!("SELECT COUNT(*) FROM main.claim_receipt_log_entries WHERE entry_seq <= {w}"),
            format!(
                "SELECT COUNT(*) FROM main.claim_receipt_log_entries m WHERE m.entry_seq <= {w} \
                 AND EXISTS (SELECT 1 FROM archive.claim_receipt_log_entries a WHERE a.entry_seq = m.entry_seq \
                 AND a.receipt_id IS m.receipt_id AND a.receipt_kind IS m.receipt_kind \
                 AND a.source_seq IS m.source_seq AND a.timestamp IS m.timestamp \
                 AND a.capability_id IS m.capability_id AND a.session_id IS m.session_id \
                 AND a.parent_request_id IS m.parent_request_id AND a.request_id IS m.request_id \
                 AND a.subject_key IS m.subject_key AND a.issuer_key IS m.issuer_key \
                 AND a.tool_server IS m.tool_server AND a.tool_name IS m.tool_name \
                 AND a.raw_json IS m.raw_json)"
            ),
        ),
        (
            // Identity keyed on checkpoint_seq (UNIQUE): every content column,
            // including the signed statement and signature, must match.
            "kernel_checkpoints",
            format!("SELECT COUNT(*) FROM main.kernel_checkpoints WHERE batch_end_seq <= {w}"),
            format!(
                "SELECT COUNT(*) FROM main.kernel_checkpoints m WHERE m.batch_end_seq <= {w} \
                 AND EXISTS (SELECT 1 FROM archive.kernel_checkpoints a WHERE a.checkpoint_seq = m.checkpoint_seq \
                 AND a.id IS m.id AND a.batch_start_seq IS m.batch_start_seq \
                 AND a.batch_end_seq IS m.batch_end_seq AND a.tree_size IS m.tree_size \
                 AND a.merkle_root IS m.merkle_root AND a.issued_at IS m.issued_at \
                 AND a.statement_json IS m.statement_json AND a.signature IS m.signature \
                 AND a.kernel_key IS m.kernel_key)"
            ),
        ),
        (
            // Identity keyed on receipt_id (PK): state, note, and timestamp
            // must match the live reconciliation row being archived.
            "settlement_reconciliations",
            format!(
                "SELECT COUNT(*) FROM main.settlement_reconciliations WHERE receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt')"
            ),
            format!(
                "SELECT COUNT(*) FROM main.settlement_reconciliations m WHERE m.receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt') \
                 AND EXISTS (SELECT 1 FROM archive.settlement_reconciliations a WHERE a.receipt_id = m.receipt_id \
                 AND a.reconciliation_state IS m.reconciliation_state AND a.note IS m.note \
                 AND a.updated_at IS m.updated_at)"
            ),
        ),
        (
            // Identity keyed on receipt_id (PK): all metered evidence columns
            // (units, cost, currency, evidence hash, state, note) must match.
            "metered_billing_reconciliations",
            format!(
                "SELECT COUNT(*) FROM main.metered_billing_reconciliations WHERE receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt')"
            ),
            format!(
                "SELECT COUNT(*) FROM main.metered_billing_reconciliations m WHERE m.receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt') \
                 AND EXISTS (SELECT 1 FROM archive.metered_billing_reconciliations a WHERE a.receipt_id = m.receipt_id \
                 AND a.adapter_kind IS m.adapter_kind AND a.evidence_id IS m.evidence_id \
                 AND a.observed_units IS m.observed_units AND a.billed_cost_units IS m.billed_cost_units \
                 AND a.billed_cost_currency IS m.billed_cost_currency AND a.evidence_sha256 IS m.evidence_sha256 \
                 AND a.recorded_at IS m.recorded_at AND a.reconciliation_state IS m.reconciliation_state \
                 AND a.note IS m.note AND a.updated_at IS m.updated_at)"
            ),
        ),
        (
            // Identity keyed on authorization_receipt_id (PK): the consuming
            // receipt, request/session/tool-call identifiers, tenant, parameter
            // hash, and consumption timestamp must all match.
            "chio_authorization_receipt_consumptions",
            format!(
                "SELECT COUNT(*) FROM main.chio_authorization_receipt_consumptions WHERE authorization_receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt')"
            ),
            format!(
                "SELECT COUNT(*) FROM main.chio_authorization_receipt_consumptions m WHERE m.authorization_receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt') \
                 AND EXISTS (SELECT 1 FROM archive.chio_authorization_receipt_consumptions a \
                 WHERE a.authorization_receipt_id = m.authorization_receipt_id \
                 AND a.consumer_receipt_id IS m.consumer_receipt_id AND a.request_id IS m.request_id \
                 AND a.session_id IS m.session_id AND a.tool_call_id IS m.tool_call_id \
                 AND a.tenant_id IS m.tenant_id AND a.parameter_hash IS m.parameter_hash \
                 AND a.consumed_at_unix_ms IS m.consumed_at_unix_ms)"
            ),
        ),
    ];
    for (table, live_sql, archive_sql) in checks {
        let live: i64 = connection.query_row(&live_sql, [], |row| row.get(0))?;
        let archived: i64 = connection.query_row(&archive_sql, [], |row| row.get(0))?;
        if archived < live {
            return Err(ReceiptStoreError::RetentionArchiveIncomplete {
                table,
                live: sqlite_u64(live, "live co-archival count")?,
                archived: sqlite_u64(archived, "archive co-archival count")?,
            });
        }
    }
    Ok(())
}

/// Delete the [1, W] prefix from the live store in ONE BEGIN IMMEDIATE
/// transaction (FK-safe order: the reconciliation/consumption children first,
/// then the receipts, then the claim-log last so its rows drive the receipt
/// deletes), record the watermark, and restore the immutability guards. A
/// rollback restores rows AND triggers together, so a failed delete cannot
/// leave the store with its append-only guards dropped.
///
/// The claim-log and source-receipt tables must lose EXACTLY the same
/// receipt_id set together and atomically: deleting source rows while leaving
/// the claim-log projection intact would make the next projection validation
/// see set drift (the expected set shrank, the projection did not) and brick
/// the store on the following rotation.
fn delete_archived_prefix_in_tx(
    connection: &mut rusqlite::Connection,
    w: i64,
    cutoff_unix_secs: u64,
    archive_path: &str,
) -> Result<(), ReceiptStoreError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute_batch(&format!(
        r#"
        DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete;
        DROP TRIGGER IF EXISTS chio_child_receipts_reject_delete;
        DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete;

        DELETE FROM settlement_reconciliations WHERE receipt_id IN (
            SELECT receipt_id FROM claim_receipt_log_entries
            WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        DELETE FROM metered_billing_reconciliations WHERE receipt_id IN (
            SELECT receipt_id FROM claim_receipt_log_entries
            WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        DELETE FROM chio_authorization_receipt_consumptions WHERE authorization_receipt_id IN (
            SELECT receipt_id FROM claim_receipt_log_entries
            WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        DELETE FROM chio_tool_receipts WHERE seq IN (
            SELECT source_seq FROM claim_receipt_log_entries
            WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        DELETE FROM chio_child_receipts WHERE seq IN (
            SELECT source_seq FROM claim_receipt_log_entries
            WHERE entry_seq <= {w} AND receipt_kind = 'child_receipt');
        DELETE FROM claim_receipt_log_entries WHERE entry_seq <= {w};
        "#
    ))?;
    insert_receipt_retention_watermark(
        &tx,
        sqlite_u64(w, "watermark entry_seq")?,
        cutoff_unix_secs,
        archive_path,
        None,
        now,
    )?;
    ensure_transparency_projection_guards(&tx)?; // recreate all reject-delete/update guards
    tx.commit()?;
    Ok(())
}

/// Recover a store whose claim-log projection rows survived a source-row
/// delete: the source rows were deleted but the projection rows remained,
/// producing set drift that fails the projection guard on open. Fail-closed:
/// only the `extra` claim-log rows -- present in the projection but absent from
/// BOTH source tables -- are candidates, and each
/// candidate must (a) already be present in the named archive and (b) fall at
/// or below the smallest checkpoint `batch_end_seq` that covers it, so the
/// uncheckpointed suffix is never touched. Entry point for
/// `SqliteReceiptStore::retention_repair`, run on the single writer
/// connection.
pub(super) fn retention_repair_on_writer(
    connection: &mut rusqlite::Connection,
    archive_path: &str,
) -> Result<u64, ReceiptStoreError> {
    // 1. extra = claim-log receipt_ids absent from BOTH source tables.
    let extras: Vec<(i64, String)> = {
        let mut stmt = connection.prepare(
            "SELECT e.entry_seq, e.receipt_id FROM claim_receipt_log_entries e \
             WHERE NOT EXISTS (SELECT 1 FROM chio_tool_receipts t WHERE t.receipt_id = e.receipt_id) \
               AND NOT EXISTS (SELECT 1 FROM chio_child_receipts c WHERE c.receipt_id = e.receipt_id) \
             ORDER BY e.entry_seq",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        out
    };
    if extras.is_empty() {
        return Ok(0);
    }
    let max_extra_entry_seq = extras.iter().map(|(seq, _)| *seq).max().unwrap_or(0);

    // 2. Assert every extra id is present in the archive, and its range is
    //    checkpoint-covered. Refuse otherwise (never delete a non-archived row,
    //    never touch the uncheckpointed suffix).
    let escaped = archive_path.replace('\'', "''");
    connection.execute_batch(&format!("ATTACH DATABASE '{escaped}' AS archive"))?;
    let assert_result = (|| -> Result<u64, ReceiptStoreError> {
        for (entry_seq, _) in &extras {
            // Identity, not mere presence: the orphaned live claim-log row is the
            // last faithful evidence for its receipt, and deleting it is only safe
            // if the archive holds a BYTE-IDENTICAL copy. A reused or wrong archive
            // that merely reuses the `receipt_id` under a divergent `entry_seq`,
            // `source_seq`, `receipt_kind`, or `raw_json` would pass a count-only
            // probe yet leave no faithful archived copy behind the delete, so
            // compare the whole row (keyed on the verbatim-copied `entry_seq`).
            let faithful: i64 = connection.query_row(
                "SELECT COUNT(*) FROM main.claim_receipt_log_entries m \
                 WHERE m.entry_seq = ?1 \
                   AND EXISTS (SELECT 1 FROM archive.claim_receipt_log_entries a \
                     WHERE a.entry_seq = m.entry_seq \
                       AND a.receipt_id IS m.receipt_id AND a.receipt_kind IS m.receipt_kind \
                       AND a.source_seq IS m.source_seq AND a.timestamp IS m.timestamp \
                       AND a.capability_id IS m.capability_id AND a.session_id IS m.session_id \
                       AND a.parent_request_id IS m.parent_request_id AND a.request_id IS m.request_id \
                       AND a.subject_key IS m.subject_key AND a.issuer_key IS m.issuer_key \
                       AND a.tool_server IS m.tool_server AND a.tool_name IS m.tool_name \
                       AND a.raw_json IS m.raw_json)",
                params![entry_seq],
                |row| row.get(0),
            )?;
            if faithful == 0 {
                return Err(ReceiptStoreError::RetentionArchiveIncomplete {
                    table: "claim_receipt_log_entries",
                    live: 1,
                    archived: 0,
                });
            }
        }
        // Checkpoint-aligned rounding: smallest batch_end_seq >= max(extra).
        let rounded: Option<i64> = connection.query_row(
            "SELECT MIN(batch_end_seq) FROM kernel_checkpoints WHERE batch_end_seq >= ?1",
            params![max_extra_entry_seq],
            |row| row.get(0),
        )?;
        let rounded = rounded.ok_or_else(|| {
            ReceiptStoreError::Conflict(
                "retention repair: extra claim-log rows are not covered by any checkpoint; \
                 refusing to touch the uncheckpointed suffix"
                    .to_string(),
            )
        })?;
        // The rounded watermark is a checkpoint boundary at or above the largest
        // orphan. If the orphans cover only PART of that batch, rows between the
        // largest orphan and the boundary may still have LIVE source receipts;
        // stamping the watermark there would mark them archived and permanently
        // skip their Merkle rebuild. Refuse a partial batch: every claim-log row
        // up to the boundary must itself be an orphan (absent from both source
        // tables), so after the delete the whole covered prefix is genuinely
        // gone and the watermark never covers a live row.
        let live_in_prefix: i64 = connection.query_row(
            "SELECT COUNT(*) FROM claim_receipt_log_entries e \
             WHERE e.entry_seq <= ?1 \
               AND (EXISTS (SELECT 1 FROM chio_tool_receipts t WHERE t.receipt_id = e.receipt_id) \
                    OR EXISTS (SELECT 1 FROM chio_child_receipts c WHERE c.receipt_id = e.receipt_id))",
            params![rounded],
            |row| row.get(0),
        )?;
        if live_in_prefix > 0 {
            return Err(ReceiptStoreError::Conflict(
                "retention repair: the checkpoint batch covering the orphaned rows still has \
                 live source receipts; refusing to watermark a partially archived batch"
                    .to_string(),
            ));
        }
        sqlite_u64(rounded, "repair rounded watermark")
    })();
    let detach = connection.execute_batch("DETACH DATABASE archive");
    let rounded_watermark = match (assert_result, detach) {
        (Ok(w), Ok(())) => w,
        (Err(error), _) => return Err(error),
        (Ok(_), Err(error)) => return Err(error.into()),
    };

    // 3. One BEGIN IMMEDIATE tx: drop guard, delete extras, insert watermark,
    //    recreate guard, commit.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let removed = extras.len() as u64;
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete;")?;
    for (entry_seq, _) in &extras {
        tx.execute(
            "DELETE FROM claim_receipt_log_entries WHERE entry_seq = ?1",
            params![entry_seq],
        )?;
    }
    insert_receipt_retention_watermark(&tx, rounded_watermark, now, archive_path, None, now)?;
    ensure_transparency_projection_guards(&tx)?;
    tx.commit()?;

    connection.execute_batch("PRAGMA incremental_vacuum")?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(removed)
}
