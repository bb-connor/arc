use super::support::{
    ensure_checkpoint_transparency_guards, ensure_transparency_projection_guards,
    insert_receipt_retention_watermark, load_claim_tree_canonical_bytes_range,
    load_persisted_checkpoint_row, parse_persisted_checkpoint_row, store_kernel_checkpoint_atomic,
    validate_transparency_projection_guards,
};
use super::*;
use sha2::{Digest as Sha2Digest, Sha256};

pub(crate) fn receipt_query_sql(
    query: &ReceiptQuery,
    tenant_fragment: &str,
) -> Result<(String, String), ReceiptStoreError> {
    let currency = query
        .validated_cost_currency()
        .map_err(ReceiptStoreError::ReadBoundary)?;
    let cost_fragment = match (
        query.min_cost.is_some(),
        query.max_cost.is_some(),
        currency.is_some(),
    ) {
        (false, false, false) => "AND ?13 IS NULL",
        (false, false, true) => "AND r.cost_currency = ?13",
        (true, false, true) => "AND r.cost_currency = ?13 AND r.cost_charged_be >= ?7",
        (false, true, true) => "AND r.cost_currency = ?13 AND r.cost_charged_be <= ?8",
        (true, true, true) => {
            "AND r.cost_currency = ?13 AND r.cost_charged_be >= ?7 AND r.cost_charged_be <= ?8"
        }
        _ => {
            return Err(ReceiptStoreError::ReadBoundary(
                "receipt query cost bounds require a currency".to_string(),
            ))
        }
    };
    let from_where = format!(
        r#"
        FROM chio_tool_receipts r
        LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
        WHERE (?1 IS NULL OR r.capability_id = ?1)
          AND (?2 IS NULL OR r.tool_server = ?2)
          AND (?3 IS NULL OR r.tool_name = ?3)
          AND (?4 IS NULL OR r.decision_kind = ?4)
          AND (?5 IS NULL OR r.timestamp >= ?5)
          AND (?6 IS NULL OR r.timestamp <= ?6)
          {cost_fragment}
          AND (?9 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?9)
          AND {tenant_fragment}
    "#
    );
    let data_sql = format!(
        r#"
        SELECT r.seq, r.raw_json
        {from_where}
          AND (?10 IS NULL OR r.seq > ?10)
        ORDER BY r.seq ASC
        LIMIT ?11
    "#
    );
    let count_sql = format!("SELECT COUNT(*) {from_where}");
    Ok((data_sql, count_sql))
}

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
        self.database_identity_file.validate()?;
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
        // `WriterHandle::run_write_kind`. The Rotate actor arm adopts the
        // increment until the rotation has finished; a send failure here undoes
        // it before returning.
        let health = &self.receipt_commit_actor.health;
        let (inflight, inflight_release, _previous_inflight) = WriterInflightLease::acquire(health);
        health.note_channel_send();
        if let Err(error) =
            self.receipt_commit_actor
                .sender
                .try_send(ReceiptCommitCommand::Rotate {
                    config,
                    response,
                    inflight,
                })
        {
            inflight_release.release();
            health.note_channel_send_rejected();
            return Err(match error {
                std::sync::mpsc::TrySendError::Full(_) => {
                    health
                        .saturated_total
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    receipt_actor_saturated_error()
                }
                std::sync::mpsc::TrySendError::Disconnected(_) => {
                    health.note_writer_unavailable();
                    receipt_actor_unavailable_error()
                }
            });
        }
        match result.recv() {
            Ok(outcome) => outcome,
            Err(_) => {
                inflight_release.release();
                health.note_writer_unavailable();
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

        let (data_sql, count_sql) = receipt_query_sql(query, tenant_fragment)?;

        let cap_id = query.capability_id.as_deref();
        let tool_srv = query.tool_server.as_deref();
        let tool_nm = query.tool_name.as_deref();
        let outcome = query.outcome.as_deref();
        let since = query
            .since
            .map(i64::try_from)
            .transpose()
            .map_err(|_| {
                ReceiptStoreError::InvalidQuery(
                    "since exceeds SQLite's signed timestamp range".to_string(),
                )
            })?;
        let until = query
            .until
            .map(i64::try_from)
            .transpose()
            .map_err(|_| {
                ReceiptStoreError::InvalidQuery(
                    "until exceeds SQLite's signed timestamp range".to_string(),
                )
            })?;
        let min_cost = query.min_cost.map(|value| value.to_be_bytes().to_vec());
        let max_cost = query.max_cost.map(|value| value.to_be_bytes().to_vec());
        let agent_sub = query.agent_subject.as_deref();
        let tenant = read_scope.tenant.as_deref();
        let cost_currency = query.cost_currency.as_deref();
        let mut connection = self.connection()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
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
                    // but must still bind values if we reuse `params!`;
                    // the count SQL uses only ?1..=?9 and ?12, so we need to
                    // bind ?10 and ?11 as NULL / 0 to keep indexes stable.
                    let total_count: u64 = transaction
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
                                cost_currency,
                            ],
                            |row| row.get::<_, i64>(0),
                        )
                        .map(|n| n.max(0) as u64)?;
                    transaction.commit()?;
                    return Ok(ReceiptQueryResult {
                        receipts: Vec::new(),
                        total_count,
                        next_cursor: None,
                    });
                }
            },
        };

        let receipts = {
            let mut stmt = transaction.prepare(&data_sql)?;
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
                    cost_currency,
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
            receipts
        };

        // Execute count query (same filters, no cursor, no limit).
        let total_count: u64 = transaction
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
                    cost_currency,
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
        transaction.commit()?;

        Ok(ReceiptQueryResult {
            receipts,
            total_count,
            next_cursor,
        })
    }
}

/// Largest checkpoint `batch_end_seq` whose entire covered prefix (in the
/// entry_seq domain) has aged past `cutoff`, never splits a live
/// authorization-consumption pair, never strands a live receipt from its
/// lineage parent, and never archives a receipt whose reconciliation is still
/// nonterminal. Unfinished settlement-observer delivery and durable retry rows
/// are live reconciliation state too, so their receipts remain live until the
/// outbox completes and the retry row is terminally cleared. 0 when no whole
/// checkpointed batch qualifies (a no-op
/// rotation).
///
/// An authorization receipt and the consumer receipt that consumed it are bound
/// by a `chio_authorization_receipt_consumptions` row keyed on the authorization
/// (a RESTRICT foreign key). Archiving-and-deleting the authorization while its
/// consumer is still live would either strand that row (dropping the live
/// consumer's replay/audit binding) or fail closed on the RESTRICT delete. The
/// watermark therefore never advances past an authorization whose bound consumer
/// still sits above the boundary: the whole pair archives together on a later
/// rotation once the consumer has also aged out.
///
/// Governed receipts carry the same hazard through receipt lineage. A surviving
/// child receipt records its parent in `receipt_lineage_statements.parent_receipt_id`,
/// and `receipt_lineage_verification` / `ReceiptStore::load_chio_receipt` resolve
/// that parent only in the LIVE receipt tables. Deleting a parent whose live
/// child still sits above the boundary would leave the child unable to resolve
/// its verified parent, breaking governed call-chain validation and explain.
/// The watermark therefore also never advances past a lineage parent whose child
/// is still live; the parent is preserved until the child ages out and the whole
/// lineage archives together on a later rotation.
///
/// Reconciliation rows carry the hazard in the receipt itself. A receipt's
/// settlement or metered-billing reconciliation lives in
/// `settlement_reconciliations` / `metered_billing_reconciliations`, keyed on the
/// receipt, and both upsert paths require that receipt to still exist in
/// `chio_tool_receipts` before they can record progress. While a reconciliation
/// is nonterminal (`open` or `retry_scheduled`) it is an actionable item that
/// live operator reports display and a later reconciliation attempt must be able
/// to update. Archiving-and-deleting the receipt drops the only live row those
/// paths can find, so the actionable item disappears and the next reconciliation
/// returns NotFound. The watermark therefore never advances past a receipt with a
/// nonterminal reconciliation row; that receipt and its reconciliation archive
/// together on a later rotation once the reconciliation reaches a terminal state
/// (`reconciled` or `ignored`).
fn compute_archival_watermark(
    connection: &rusqlite::Connection,
    cutoff_unix_secs: u64,
) -> Result<u64, ReceiptStoreError> {
    let cutoff = sqlite_i64(cutoff_unix_secs, "retention cutoff")?;
    let settle_attempts_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master \
         WHERE type = 'table' AND name = 'settle_attempts')",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0;
    let retry_guard = if settle_attempts_exists {
        r#"
        AND NOT EXISTS (
            SELECT 1 FROM settle_attempts sa
            JOIN claim_receipt_log_entries e ON e.receipt_id = sa.receipt_id
            WHERE e.entry_seq <= kc.batch_end_seq
        )
        "#
    } else {
        ""
    };
    let iou_envelope_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master \
         WHERE type = 'table' AND name = 'iou_envelope')",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0;
    let pending_iou_guard = if iou_envelope_exists {
        r#"
        AND NOT EXISTS (
            SELECT 1 FROM iou_envelope iou
            JOIN claim_receipt_log_entries e ON e.receipt_id = iou.receipt_id
            LEFT JOIN settlement_reconciliations sr ON sr.receipt_id = iou.receipt_id
            WHERE e.entry_seq <= kc.batch_end_seq
              AND sr.receipt_id IS NULL
        )
        "#
    } else {
        ""
    };
    let watermark_sql = format!(
        r#"
        SELECT COALESCE(MAX(kc.batch_end_seq), 0)
        FROM kernel_checkpoints kc
        WHERE NOT EXISTS (
            SELECT 1 FROM claim_receipt_log_entries e
            WHERE e.entry_seq <= kc.batch_end_seq
              AND e.timestamp >= ?1
        )
        AND NOT EXISTS (
            SELECT 1 FROM chio_authorization_receipt_consumptions ac
            JOIN claim_receipt_log_entries ae ON ae.receipt_id = ac.authorization_receipt_id
            JOIN claim_receipt_log_entries ce ON ce.receipt_id = ac.consumer_receipt_id
            WHERE ae.entry_seq <= kc.batch_end_seq
              AND ce.entry_seq > kc.batch_end_seq
        )
        AND NOT EXISTS (
            SELECT 1 FROM receipt_lineage_statements ls
            JOIN claim_receipt_log_entries pe ON pe.receipt_id = ls.parent_receipt_id
            JOIN claim_receipt_log_entries ce ON ce.receipt_id = ls.receipt_id
            WHERE pe.entry_seq <= kc.batch_end_seq
              AND ce.entry_seq > kc.batch_end_seq
        )
        AND NOT EXISTS (
            SELECT 1 FROM settlement_reconciliations sr
            JOIN claim_receipt_log_entries e ON e.receipt_id = sr.receipt_id
            WHERE e.entry_seq <= kc.batch_end_seq
              AND sr.reconciliation_state NOT IN ('reconciled', 'ignored')
        )
        AND NOT EXISTS (
            SELECT 1 FROM metered_billing_reconciliations mbr
            JOIN claim_receipt_log_entries e ON e.receipt_id = mbr.receipt_id
            WHERE e.entry_seq <= kc.batch_end_seq
              AND mbr.reconciliation_state NOT IN ('reconciled', 'ignored')
        )
        AND NOT EXISTS (
            SELECT 1 FROM chio_settlement_observer_outbox observer
            JOIN claim_receipt_log_entries e ON e.receipt_id = observer.receipt_id
            WHERE e.entry_seq <= kc.batch_end_seq
              AND observer.state != 'completed'
        )
        {retry_guard}
        {pending_iou_guard}
        "#
    );
    let watermark: i64 = connection.query_row(&watermark_sql, params![cutoff], |row| row.get(0))?;
    sqlite_u64(watermark, "retention watermark")
}

fn ensure_no_late_settlement_barrier(
    connection: &rusqlite::Connection,
    watermark: i64,
) -> Result<(), ReceiptStoreError> {
    let unfinished_observer_exists = connection.query_row(
        "SELECT EXISTS( \
             SELECT 1 FROM chio_settlement_observer_outbox observer \
             JOIN claim_receipt_log_entries e ON e.receipt_id = observer.receipt_id \
             WHERE e.entry_seq <= ?1 AND observer.state != 'completed' \
         )",
        params![watermark],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if unfinished_observer_exists {
        return Err(ReceiptStoreError::Conflict(
            "unfinished settlement observer delivery entered the archival prefix".to_string(),
        ));
    }

    let settle_attempts_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master \
         WHERE type = 'table' AND name = 'settle_attempts')",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if settle_attempts_exists {
        let retry_exists = connection.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM settle_attempts retry \
                 JOIN claim_receipt_log_entries e ON e.receipt_id = retry.receipt_id \
                 WHERE e.entry_seq <= ?1 \
             )",
            params![watermark],
            |row| row.get::<_, i64>(0),
        )? != 0;
        if retry_exists {
            return Err(ReceiptStoreError::Conflict(
                "settlement retry entered the archival prefix".to_string(),
            ));
        }
    }

    let iou_envelope_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master \
         WHERE type = 'table' AND name = 'iou_envelope')",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if iou_envelope_exists {
        let pending_iou_exists = connection.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM iou_envelope iou \
                 JOIN claim_receipt_log_entries e ON e.receipt_id = iou.receipt_id \
                 LEFT JOIN settlement_reconciliations sr ON sr.receipt_id = iou.receipt_id \
                 WHERE e.entry_seq <= ?1 AND sr.receipt_id IS NULL \
             )",
            params![watermark],
            |row| row.get::<_, i64>(0),
        )? != 0;
        if pending_iou_exists {
            return Err(ReceiptStoreError::Conflict(
                "pending settlement IOU entered the archival prefix".to_string(),
            ));
        }
    }

    Ok(())
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
    // Trigger thresholds are measured over the claim receipt log, which projects
    // BOTH tool and child receipts. Reading only chio_tool_receipts would leave a
    // store whose aged (or oldest-checkpointed) evidence is child-only stuck below
    // every trigger, even though the rotation/delete path co-archives child rows
    // once a cutoff is chosen.
    let oldest: Option<i64> = connection.query_row(
        "SELECT MIN(timestamp) FROM claim_receipt_log_entries",
        [],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    // Both triggers are evaluated and the rotation uses whichever cutoff frees
    // more (the max). The time cutoff alone can archive nothing, for example when
    // a still-fresh receipt sits early in the checkpointed prefix, because
    // `compute_archival_watermark` requires a checkpoint's ENTIRE covered prefix
    // to be older than the cutoff. Returning that cutoff before the size check
    // would let an oversized store stay oversized indefinitely even while the
    // size trigger is exceeded, since the maintenance worker would keep applying
    // a no-op time cutoff. Taking the max lets the size-relief cutoff apply
    // whenever the store is over its limit, independent of the time trigger.
    let mut cutoff: Option<u64> = None;
    if let Some(oldest_ts) = oldest {
        if (oldest_ts.max(0) as u64) < time_cutoff {
            cutoff = Some(time_cutoff);
        }
    }
    // Size trigger: measured against live_db_size_bytes (freelist-adjusted),
    // not the raw on-disk db_size_bytes, so the trigger converges.
    let size = live_db_size_bytes_on_connection(connection)?;
    if size > config.max_size_bytes {
        let median: Option<i64> = connection
            .query_row(
                "SELECT timestamp FROM claim_receipt_log_entries ORDER BY timestamp \
                 LIMIT 1 OFFSET (SELECT COUNT(*) FROM claim_receipt_log_entries) / 2",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(median_ts) = median {
            // `compute_archival_watermark` archives a checkpoint only when its
            // entire prefix is strictly older than the cutoff (a row with
            // `timestamp >= cutoff` blocks its batch). When many receipts share
            // the median timestamp (second-resolution or bursty traffic), a
            // cutoff equal to that timestamp blocks every batch containing one,
            // so size rotation would archive nothing and never converge below
            // `max_size_bytes`. Advance the cutoff one second past the median so
            // receipts at the median become eligible and a checkpointed prefix
            // can actually age out.
            let size_cutoff = (median_ts.max(0) as u64).saturating_add(1);
            cutoff = Some(cutoff.map_or(size_cutoff, |current| current.max(size_cutoff)));
        }
    }
    Ok(cutoff)
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

/// Materialize the sibling archive database file before a rotation `ATTACH`es
/// it.
///
/// The live store's writer connection is opened READ_WRITE without
/// `SQLITE_OPEN_CREATE` so that opening a store whose main database is missing
/// fails closed instead of silently creating an empty one. `ATTACH DATABASE`
/// inherits the main connection's open flags, so the first rotation against such
/// a store would be unable to create a not-yet-existing archive and would fail.
/// Opening the archive path once with `SQLITE_OPEN_CREATE` creates an empty
/// database file (a zero-length file is a valid empty SQLite database) that the
/// subsequent no-CREATE `ATTACH` can open, without loosening the main store's
/// flags. An already-present archive is opened and closed unchanged, so this is
/// a no-op on every rotation after the first and never rewrites a prior archive;
/// the co-archival identity verification still fails closed on a foreign or
/// divergent archive.
fn ensure_archive_file_exists(archive_path: &str) -> Result<(), ReceiptStoreError> {
    let path = std::path::Path::new(archive_path);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let directory = crate::durable_sqlite::TrustedSqliteDirectory::open_for_database(&absolute)
        .map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "retention archive parent is not a trusted durable directory: {error}"
            ))
        })?;
    directory
        .open_database(&absolute, true)
        .map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "retention archive could not be provisioned as a durable file: {error}"
            ))
        })?
        .sync_file_and_directory()
        .map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "retention archive provisioning could not be persisted: {error}"
            ))
        })?;
    Ok(())
}

fn open_durable_retention_archive_file(
    archive_path: &str,
) -> Result<std::sync::Arc<crate::durable_sqlite::DurableSqliteFile>, ReceiptStoreError> {
    let path = std::path::Path::new(archive_path);
    let directory = crate::durable_sqlite::TrustedSqliteDirectory::open_for_database(path)
        .map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "retention archive parent is not a trusted durable directory: {error}"
            ))
        })?;
    directory.open_database(path, false).map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "retention archive is not a trusted durable database file: {error}"
        ))
    })
}

/// Resolve `archive_path` to an absolute, symlink-free location so the watermark
/// ledger records a path that is stable across process working directories and
/// restarts.
///
/// The recorded archive path is read back by the watermark-trust check
/// (`archived_prefix_is_backed`), which opens it to confirm the deleted prefix
/// still survives in the archive. A relative path stored verbatim (including the
/// default `receipts-archive.sqlite3`) resolves against whatever working
/// directory the reader happens to run in, so a restart or a CLI health check
/// launched from a different directory would find no archive, withdraw the
/// exemption, and then fail full verification because the live prefix was
/// intentionally deleted. Canonicalizing before the insert ties the recorded
/// location to the real file. Fail-closed: the archive is expected to exist by
/// this point (it was just materialized and co-archived into), so a path that
/// cannot be resolved aborts the rotation rather than sealing an unstable
/// relative path behind a trusted watermark.
fn absolute_archive_path(archive_path: &str) -> Result<String, ReceiptStoreError> {
    let canonical = std::fs::canonicalize(std::path::Path::new(archive_path)).map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "retention archive path {archive_path:?} could not be resolved to an absolute path: \
             {error}"
        ))
    })?;
    canonical.to_str().map(str::to_owned).ok_or_else(|| {
        ReceiptStoreError::Conflict(format!(
            "retention archive path {archive_path:?} is not valid UTF-8 after canonicalization"
        ))
    })
}

/// Reject an archive target that could destroy the only copy of the evidence a
/// rotation is about to delete.
///
/// `ATTACH DATABASE` accepts non-durable and aliasing targets that silently
/// break the co-archive-then-delete contract:
///
/// - An in-memory or temporary target (`:memory:`, an empty path, or a
///   `mode=memory` URI) is destroyed on `DETACH`, so co-archiving into it and
///   then deleting the live prefix leaves no copy of the archived rows behind a
///   recorded watermark.
/// - A target that aliases the live database (the same path, or a hard link to
///   it) makes SQLite attach the live file itself as `archive`, so the
///   co-archival identity checks compare the table to itself and pass trivially,
///   then the delete removes the only copy while still recording a watermark.
///
/// Fail closed on both before the ATTACH so a rotation never records a watermark
/// it cannot back with durable, independent evidence.
fn ensure_durable_distinct_archive_path(
    connection: &rusqlite::Connection,
    archive_path: &str,
) -> Result<(), ReceiptStoreError> {
    let trimmed = archive_path.trim();
    let lowered = trimmed.to_ascii_lowercase();
    if trimmed.is_empty() || lowered == ":memory:" || lowered.contains("mode=memory") {
        return Err(ReceiptStoreError::Conflict(format!(
            "retention archive path {archive_path:?} is not a durable database file; refusing to \
             co-archive evidence into a target destroyed on detach"
        )));
    }
    // The live main database's backing file. Empty for an in-memory/temporary
    // main store, which cannot alias a file archive, so the alias check is
    // skipped in that case (the durable-target check above still applies).
    let main_file = super::bootstrap::open::sqlite_database_list(connection)?
        .into_iter()
        .find_map(|(_, schema, file)| (schema == "main").then_some(file).flatten())
        .unwrap_or_default();
    if !main_file.is_empty() && archive_path_aliases_live(&main_file, trimmed) {
        return Err(ReceiptStoreError::Conflict(format!(
            "retention archive path {archive_path:?} aliases the live database; refusing to archive \
             a store into itself"
        )));
    }
    Ok(())
}

/// Reject a rotation whose archive target differs from the one an earlier
/// rotation already committed to.
///
/// Retention archives a contiguous `[1, W]` prefix and then deletes those live
/// rows. Once deleted they can never be re-copied, so a second rotation pointed
/// at a NEW target writes only the newer suffix `(W1, W2]` there: the co-archival
/// check still passes (it only inspects the still-live rows, all now above `W1`)
/// and the ledger advances to `W2` naming the new target, but that target holds
/// only `(W1, W2]` while `[1, W1]` remains stranded in the original archive. The
/// watermark-trust reader then asks the new target for the whole `[1, W2]`
/// prefix, finds it short, and withdraws the exemption, leaving a store whose
/// evidence is real but split across two files that neither alone can satisfy.
/// Pinning the archive path (compared canonical-to-canonical, see
/// `absolute_archive_path`) keeps the archived prefix whole. Fail-closed: a
/// mismatch aborts before any copy or delete.
fn ensure_archive_path_matches_ledger(
    connection: &rusqlite::Connection,
    archive_path: &str,
) -> Result<(), ReceiptStoreError> {
    if let Some(recorded) = super::support::latest_watermark_archive_path(connection)? {
        if recorded != archive_path {
            return Err(ReceiptStoreError::Conflict(format!(
                "retention archive path {archive_path:?} differs from the archive {recorded:?} an \
                 earlier rotation committed to; the archived prefix would be split across two \
                 files. Keep the same archive path or start a fresh store"
            )));
        }
    }
    Ok(())
}

/// Confirm the archive the ledger already committed to still re-derives the
/// signed checkpoint roots for the committed prefix `[1, current]`.
///
/// A subsequent rotation only ever appends the newer suffix to that same
/// archive; the earlier `[1, current]` prefix was deleted from the live store
/// and survives nowhere else. If that archive was deleted, replaced, or emptied
/// since, extending it would advance the watermark while the earlier prefix is
/// backed by no archive at all, splitting one logical archive across a live
/// store that no longer holds the prefix and a file that never did. Fail closed
/// so the deleted prefix can never be stranded. A never-archived store (no
/// watermark, or a zero watermark) is vacuously backed.
fn ensure_committed_prefix_still_backed(
    connection: &rusqlite::Connection,
) -> Result<bool, ReceiptStoreError> {
    let Some(current) = super::support::retention_watermark(connection)? else {
        return Ok(false);
    };
    if current == 0 {
        return Ok(false);
    }
    let backing_uses_legacy_content_digest = match super::support::latest_watermark_archive_path(connection)? {
        Some(ledger_path) => {
            let Some(archive_identity) =
                super::support::latest_watermark_archive_sha256(connection)?
            else {
                return Err(ReceiptStoreError::Conflict(
                    "retention archive watermark lacks a committed archive identity".to_string(),
                ));
            };
            let archive_content_sha256 =
                super::support::latest_watermark_archive_content_sha256(connection)?.ok_or_else(
                    || {
                        ReceiptStoreError::Conflict(
                            "retention archive watermark lacks a committed canonical content \
                             digest"
                                .to_string(),
                        )
                    },
                )?;
            let current_result = super::support::archive_path_backs_prefix(
                connection,
                &ledger_path,
                current,
                &archive_identity,
                &archive_content_sha256,
            );
            if matches!(current_result, Ok(true)) {
                false
            } else if legacy_archive_path_backs_prefix(
                connection,
                &ledger_path,
                current,
                &archive_identity,
                &archive_content_sha256,
            )? {
                true
            } else {
                if let Err(error) = current_result {
                    return Err(error);
                }
                return Err(ReceiptStoreError::Conflict(format!(
                    "retention archive no longer backs the committed watermark {current}; the prior \
                     archive is missing, unreadable, or does not re-derive the signed checkpoint roots. \
                     Refusing to rotate and strand the deleted prefix; restore the archive before \
                     rotating again"
                )));
            }
        }
        None => {
            return Err(ReceiptStoreError::Conflict(format!(
                "retention archive no longer backs the committed watermark {current}; the prior \
                 archive is missing, unreadable, or does not re-derive the signed checkpoint roots. \
                 Refusing to rotate and strand the deleted prefix; restore the archive before \
                 rotating again"
            )));
        }
    };
    Ok(backing_uses_legacy_content_digest)
}

/// Durable ownership of the archive across a destructive live commit.
///
/// Acquisition checkpoints and truncates any archive WAL, switches the archive
/// to rollback-journal mode, persists the main file and parent entry, then takes
/// an archive `BEGIN EXCLUSIVE` before the caller takes the live `BEGIN
/// IMMEDIATE`. Rollback-journal locks bind to the database inode, so a transient
/// hardlink alias cannot create an independent WAL namespace and write around
/// ownership. The retained descriptor, trusted parent descriptor, single-link
/// invariant, SQLite main-file handle, identity, and watermark-scoped canonical
/// content are all validated while that archive lock is held. Rotation and
/// repair perform one final descriptor/path validation after staging their live
/// changes and immediately before committing them. Any failed check therefore
/// rolls the live transaction back while the verified archive remains owned and
/// unchanged.
struct RetentionArchiveCommitGuard {
    file: std::sync::Arc<crate::durable_sqlite::DurableSqliteFile>,
    connection: rusqlite::Connection,
}

impl RetentionArchiveCommitGuard {
    fn acquire(
        archive_path: &str,
        archive_identity_commitment: &str,
        archive_content_sha256: &str,
        watermark: i64,
    ) -> Result<Self, ReceiptStoreError> {
        let flags =
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = rusqlite::Connection::open_with_flags(archive_path, flags).map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "retention archive path {archive_path:?} could not be opened without following links: {error}"
            ))
        })?;
        let file = open_durable_retention_archive_file(archive_path)?;
        file.validate_live_connection(&connection).map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "retention archive connection could not be bound to its retained descriptor: {error}"
            ))
        })?;
        connection.busy_timeout(std::time::Duration::ZERO)?;
        require_complete_wal_checkpoint(&connection, "retention archive")?;
        let requested_journal_mode: String = connection
            .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
            .map_err(|error| {
                ReceiptStoreError::Conflict(format!(
                    "retention archive could not switch to rollback-journal ownership: {error}"
                ))
            })?;
        if !requested_journal_mode.eq_ignore_ascii_case("delete") {
            return Err(ReceiptStoreError::Conflict(format!(
                "retention archive refused rollback-journal ownership and remained in \
                 {requested_journal_mode:?} mode"
            )));
        }
        let verified_journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(|error| {
                ReceiptStoreError::Conflict(format!(
                    "retention archive journal mode could not be verified: {error}"
                ))
            })?;
        if !verified_journal_mode.eq_ignore_ascii_case("delete") {
            return Err(ReceiptStoreError::Conflict(format!(
                "retention archive journal mode changed to {verified_journal_mode:?} before \
                 ownership"
            )));
        }
        file.sync_file_and_directory().map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "retention archive checkpoint could not be durably persisted: {error}"
            ))
        })?;
        connection
            .execute_batch("BEGIN EXCLUSIVE")
            .map_err(|error| {
                ReceiptStoreError::Conflict(format!(
                    "retention archive writer ownership could not be acquired: {error}"
                ))
            })?;
        connection
            .query_row("SELECT COUNT(*) FROM main.sqlite_master", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|error| {
                ReceiptStoreError::Conflict(format!(
                    "retention archive path {archive_path:?} could not materialize its owned snapshot: {error}"
                ))
            })?;
        file.validate_live_connection(&connection)
            .map_err(|error| {
                ReceiptStoreError::Conflict(format!(
                "retention archive descriptor/path binding failed after writer ownership: {error}"
            ))
            })?;
        validate_archive_schema_contract_in_schema(&connection, "main")?;
        super::support::validate_retention_archive_identity(
            &connection,
            archive_identity_commitment,
        )?;
        validate_retention_archive_prefix_content_sha256(
            &connection,
            "main",
            watermark,
            archive_content_sha256,
        )?;
        Ok(Self { file, connection })
    }

    fn connection(&self) -> &rusqlite::Connection {
        &self.connection
    }

    fn validate_binding(&self) -> Result<(), ReceiptStoreError> {
        self.file
            .validate_live_connection(&self.connection)
            .map_err(|error| {
                ReceiptStoreError::Conflict(format!(
                    "retention archive ownership changed before the live commit: {error}"
                ))
            })
    }
}

fn require_complete_wal_checkpoint(
    connection: &rusqlite::Connection,
    authority: &str,
) -> Result<(), ReceiptStoreError> {
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "{authority} WAL could not be checkpointed: {error}"
            ))
        })?;
    if busy != 0 || (log_frames >= 0 && checkpointed_frames != log_frames) {
        return Err(ReceiptStoreError::Conflict(format!(
            "{authority} WAL checkpoint remained busy or incomplete \
             (busy={busy}, log_frames={log_frames}, \
             checkpointed_frames={checkpointed_frames})"
        )));
    }
    Ok(())
}

fn open_verified_recorded_archive(
    archive_path: &str,
    archive_identity_commitment: &str,
    archive_content_sha256: &str,
    watermark: i64,
) -> Result<RetentionArchiveCommitGuard, ReceiptStoreError> {
    RetentionArchiveCommitGuard::acquire(
        archive_path,
        archive_identity_commitment,
        archive_content_sha256,
        watermark,
    )
}

/// True when `archive_path` names the same on-disk file as the live database:
/// an identical path string, the same file after resolving symlinks and
/// `.`/`..`, or (on Unix) the same device+inode as a hard link.
fn archive_path_aliases_live(main_file: &str, archive_path: &str) -> bool {
    if main_file == archive_path {
        return true;
    }
    let resolved = |path: &str| std::fs::canonicalize(std::path::Path::new(path)).ok();
    if let (Some(main), Some(archive)) = (resolved(main_file), resolved(archive_path)) {
        if main == archive {
            return true;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(main), Ok(archive)) = (
            std::fs::metadata(main_file),
            std::fs::metadata(archive_path),
        ) {
            if main.dev() == archive.dev() && main.ino() == archive.ino() {
                return true;
            }
        }
    }
    false
}

/// Entry point run on the single writer connection by the `Rotate` command.
///
/// `verified_checkpoint_ceiling` caps the archival watermark at the newest
/// checkpoint boundary the writer actor has verified. In incremental mode the
/// caller skips the O(N) chain rebuild before rotating and trusts the
/// per-append verified head instead, but that head can be stale relative to
/// `kernel_checkpoints` when a second store instance or an operator import has
/// appended checkpoint rows since the head was seeded. Computing the watermark
/// from every persisted checkpoint would then archive and delete up to an
/// unaudited boundary. Capping at the verified boundary keeps pruning behind the
/// chain the actor has actually validated; the unaudited suffix is archived only
/// after a later append catches the head up and verifies it. `None` imposes no
/// cap (the caller already ran full checkpoint verification).
pub(super) fn rotate_on_writer_connection(
    connection: &mut rusqlite::Connection,
    config: &RetentionConfig,
    verified_checkpoint_ceiling: Option<u64>,
) -> Result<u64, ReceiptStoreError> {
    if config.tenant_id.is_some() {
        return Err(ReceiptStoreError::RetentionTenantScopeUnsupported);
    }
    // One-time migration: enable incremental auto-vacuum on a legacy store
    // that predates this pragma so the first rotation on the drained writer
    // starts reclaiming freed pages. A no-op once migrated.
    super::support::migrate_auto_vacuum_incremental_if_needed(connection)?;
    // The delete transaction writes archived ids into the tombstone table; make
    // sure it and its reuse-reject triggers exist even on a store opened before
    // this migration.
    super::support::ensure_receipt_retention_tombstones(connection)?;
    // Existing-store open repairs or validates this security metadata before it
    // starts the writer actor. Repeat the exact contract check at rotation entry
    // so a direct writer caller or interleaved schema tamper cannot reach the
    // archive copy with a missing or weakened watermark ledger.
    super::support::ensure_receipt_retention_watermark_table(connection)?;
    let Some(cutoff) = resolve_rotation_cutoff(connection, config)? else {
        return Ok(0);
    };
    archive_range(
        connection,
        cutoff,
        &config.archive_path,
        verified_checkpoint_ceiling,
    )
}

/// Install and validate the receipt-backed IOU ownership contract when the
/// co-located table exists, and reject any row without its exact live receipt.
fn ensure_retention_iou_ownership_schema(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    let iou_envelope_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master \
         WHERE type = 'table' AND name = 'iou_envelope')",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if !iou_envelope_exists {
        return Ok(());
    }
    crate::iou_store::ensure_alongside_receipt_ownership_schema(connection).map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "retention IOU ownership validation failed: {error}"
        ))
    })
}

fn preflight_retention_iou_ownership(
    connection: &mut rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    ensure_retention_iou_ownership_schema(&tx)?;
    tx.commit()?;
    Ok(())
}
