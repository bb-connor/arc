//! Parameterized receipt filters shared by live and retained snapshots.
use crate::receipt_store::{decode_verified_chio_receipt, SqliteReceiptStore};
use chio_kernel::receipt_query::{ReceiptQuery, ReceiptQueryResult, MAX_QUERY_LIMIT};
use chio_kernel::{ReceiptStoreError, StoredToolReceipt};
use rusqlite::{params, Connection};

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
    /// Internal implementation for `query_receipts` (called from `receipt_query` module).
    ///
    /// Requires access to the private `connection` field, so it lives here in `receipt_store`.
    pub(crate) fn query_receipts_impl(
        &self,
        query: &ReceiptQuery,
    ) -> Result<ReceiptQueryResult, ReceiptStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let result = query_receipts_on_connection(&transaction, query, None)?;
        transaction.commit()?;
        Ok(result)
    }
}

pub(crate) fn query_receipts_on_connection(
    connection: &Connection,
    query: &ReceiptQuery,
    archived_through: Option<u64>,
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

    // Tenant reads always exclude rows without that exact signed tenant.
    let read_scope = query
        .effective_read_scope()
        .map_err(ReceiptStoreError::from)?;
    let tenant_fragment = match read_scope.tenant.as_deref() {
        None => "(?12 IS NULL)",
        Some(_) => "(r.tenant_id = ?12)",
    };

    // `archived_through` is an authenticated integer from the live ledger,
    // never a caller-supplied SQL fragment. Copied but uncommitted tails
    // in an archive must not participate in filters, counts or pages.
    let prefix_fragment = archived_through.map(|watermark| format!(
            "{tenant_fragment} AND EXISTS (SELECT 1 FROM claim_receipt_log_entries e WHERE e.receipt_kind = 'tool_receipt' AND e.source_seq = r.seq AND e.receipt_id = r.receipt_id AND e.entry_seq <= {watermark})"
        ));
    let (data_sql, count_sql) =
        receipt_query_sql(query, prefix_fragment.as_deref().unwrap_or(tenant_fragment))?;

    let cap_id = query.capability_id.as_deref();
    let tool_srv = query.tool_server.as_deref();
    let tool_nm = query.tool_name.as_deref();
    let outcome = query.outcome.as_deref();
    let since = query
        .since
        .map(crate::integer::checked::<_, i64>)
        .transpose()?;
    let until = query
        .until
        .map(crate::integer::checked::<_, i64>)
        .transpose()?;
    let min_cost = query.min_cost.map(|value| value.to_be_bytes().to_vec());
    let max_cost = query.max_cost.map(|value| value.to_be_bytes().to_vec());
    let agent_sub = query.agent_subject.as_deref();
    let tenant = read_scope.tenant.as_deref();
    let cost_currency = query.cost_currency.as_deref();
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
                let total_count: u64 = connection
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
                    .map(|n| u64::try_from(n.max(0)).unwrap_or_default())?;
                return Ok(ReceiptQueryResult {
                    receipts: Vec::new(),
                    total_count,
                    next_cursor: None,
                });
            }
        },
    };

    let receipts = {
        let mut statement = connection.prepare(&data_sql)?;
        let rows = statement.query_map(
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
                crate::integer::checked::<_, i64>(limit)?,
                tenant,
                cost_currency,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;

        let mut receipts = Vec::new();
        for row in rows {
            let (seq, raw_json) = row?;
            let seq = u64::try_from(seq.max(0)).unwrap_or_default();
            let receipt =
                decode_verified_chio_receipt(&raw_json, "persisted tool receipt", Some(seq))?;
            if tenant.is_some_and(|tenant| receipt.tenant_id.as_deref() != Some(tenant)) {
                return Err(
                    chio_kernel::receipt_query::ReceiptReadError::TenantProjectionMismatch.into(),
                );
            }
            receipts.push(StoredToolReceipt { seq, receipt });
        }
        receipts
    };

    let total_count: u64 = connection
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
        .map(|n| u64::try_from(n.max(0)).unwrap_or_default())?;

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
