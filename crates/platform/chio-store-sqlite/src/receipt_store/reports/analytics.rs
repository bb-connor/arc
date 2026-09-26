// Receipt analytics report query.

use super::*;

use rusqlite::functions::{Aggregate, Context, FunctionFlags};
use rusqlite::types::ValueRef;

/// SQL name of the aggregate that totals the charged-cost projection.
const TOTAL_COST_CHARGED: &str = "chio_total_cost_charged";

/// Width of the `cost_charged_be` projection the receipt append path writes.
const COST_CHARGED_BYTES: usize = 8;

/// Width the charged-cost aggregate returns its running total in.
const COST_TOTAL_BYTES: usize = 16;

/// Refusal when the charges in scope total more than the report's metrics carry.
const COST_TOTAL_UNREPORTABLE: &str =
    "receipt analytics charged-cost total exceeds the reportable range";

/// Totals the eight-byte big-endian charged-cost projection.
///
/// SQLite arithmetic is signed 64-bit and degrades silently to floating point on
/// overflow, so no SQL expression can sum the unsigned charge domain exactly.
/// The running total is a `u128` here and comes back as a big-endian blob the
/// report decodes. A NULL projection is a receipt with no financial block and
/// contributes nothing; any other width violates the column's `CHECK` constraint
/// and refuses rather than contributing a wrong number to a financial report.
struct TotalCostCharged;

impl Aggregate<u128, Vec<u8>> for TotalCostCharged {
    fn init(&self, _context: &mut Context<'_>) -> rusqlite::Result<u128> {
        Ok(0)
    }

    fn step(&self, context: &mut Context<'_>, total: &mut u128) -> rusqlite::Result<()> {
        let charged = match context.get_raw(0) {
            ValueRef::Null => 0,
            ValueRef::Blob(projection) => decode_cost_charged(projection)?,
            other => {
                return Err(rusqlite::Error::UserFunctionError(
                    format!(
                        "charged-cost projection is {:?}, not a blob",
                        other.data_type()
                    )
                    .into(),
                ))
            }
        };
        *total = total
            .checked_add(charged)
            .ok_or_else(|| rusqlite::Error::UserFunctionError(COST_TOTAL_UNREPORTABLE.into()))?;
        Ok(())
    }

    fn finalize(
        &self,
        _context: &mut Context<'_>,
        total: Option<u128>,
    ) -> rusqlite::Result<Vec<u8>> {
        Ok(total.unwrap_or(0).to_be_bytes().to_vec())
    }
}

fn decode_cost_charged(projection: &[u8]) -> rusqlite::Result<u128> {
    let charged: [u8; COST_CHARGED_BYTES] = projection.try_into().map_err(|_| {
        rusqlite::Error::UserFunctionError(
            format!(
                "charged-cost projection is {} bytes, not {COST_CHARGED_BYTES}",
                projection.len()
            )
            .into(),
        )
    })?;
    Ok(u128::from(u64::from_be_bytes(charged)))
}

/// The charged-cost total, refused rather than truncated when the receipts in
/// scope total more than the report's `u64` metric holds.
fn decoded_cost_total(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let total = u128::from_be_bytes(row.get::<_, [u8; COST_TOTAL_BYTES]>(index)?);
    u64::try_from(total).map_err(|_| {
        rusqlite::Error::UserFunctionError(format!("{COST_TOTAL_UNREPORTABLE}: {total}").into())
    })
}

/// Registered on the connection the report runs on, which keeps a SQL function
/// that only this report uses out of the shared connection setup.
fn register_total_cost_charged(connection: &Connection) -> Result<(), ReceiptStoreError> {
    connection.create_aggregate_function(
        TOTAL_COST_CHARGED,
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        TotalCostCharged,
    )?;
    Ok(())
}

/// The metric columns every dimension selects, in the order
/// `ReceiptAnalyticsMetrics::from_raw` consumes them.
fn metric_columns() -> String {
    format!(
        "COUNT(*) AS total_receipts, \
         COALESCE(SUM(CASE WHEN r.decision_kind = 'allow' THEN 1 ELSE 0 END), 0) AS allow_count, \
         COALESCE(SUM(CASE WHEN r.decision_kind = 'deny' THEN 1 ELSE 0 END), 0) AS deny_count, \
         COALESCE(SUM(CASE WHEN r.decision_kind = 'cancelled' THEN 1 ELSE 0 END), 0) \
         AS cancelled_count, \
         COALESCE(SUM(CASE WHEN r.decision_kind = 'incomplete' THEN 1 ELSE 0 END), 0) \
         AS incomplete_count, \
         {TOTAL_COST_CHARGED}(r.cost_charged_be) AS total_cost_charged, \
         COALESCE(SUM(CAST(COALESCE(json_extract(r.raw_json, \
         '$.metadata.financial.attempted_cost'), 0) AS INTEGER)), 0) AS total_attempted_cost"
    )
}

fn metrics_from_row(
    row: &rusqlite::Row<'_>,
    first: usize,
) -> rusqlite::Result<ReceiptAnalyticsMetrics> {
    Ok(ReceiptAnalyticsMetrics::from_raw(
        row.get::<_, i64>(first)?.max(0) as u64,
        row.get::<_, i64>(first + 1)?.max(0) as u64,
        row.get::<_, i64>(first + 2)?.max(0) as u64,
        row.get::<_, i64>(first + 3)?.max(0) as u64,
        row.get::<_, i64>(first + 4)?.max(0) as u64,
        decoded_cost_total(row, first + 5)?,
        row.get::<_, i64>(first + 6)?.max(0) as u64,
    ))
}

/// One read snapshot for every dimension of a report.
///
/// In WAL mode each statement outside a transaction reads its own snapshot, so
/// four statements on one connection can still straddle a concurrent append and
/// return totals that disagree with each other. A deferred transaction pins the
/// snapshot at the first read and rolls back when it drops. It holds back WAL
/// checkpoint truncation while it is open, which the report's own bounds limit.
fn report_snapshot(
    connection: &Connection,
) -> Result<rusqlite::Transaction<'_>, ReceiptStoreError> {
    Ok(rusqlite::Transaction::new_unchecked(
        connection,
        rusqlite::TransactionBehavior::Deferred,
    )?)
}

const ANALYTICS_FROM_WHERE: &str = "FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)";

impl SqliteReceiptStore {
    /// Receipt activity and financial totals over the receipts a report's
    /// filters select.
    ///
    /// `total_cost_charged` is decoded from the typed `cost_charged_be`
    /// projection, which holds the eight big-endian bytes of the `u64` the
    /// receipt's financial metadata carried. A receipt with no financial block
    /// leaves that projection NULL: it contributes nothing to the total and
    /// still counts toward `total_receipts`. A projection of any other width
    /// violates the column's `CHECK` constraint and refuses the report. Charges
    /// totalling beyond `u64` refuse for the same reason rather than reporting a
    /// truncated figure.
    ///
    /// The projection holds minor units and the currency lives in a sibling
    /// column this report neither filters on nor returns, so a corpus spanning
    /// more than one currency totals unlike units. Read the total as money only
    /// where one currency is in use.
    ///
    /// `total_attempted_cost` has no typed projection and is still summed out of
    /// the signed receipt body, which is exact below `2^63` and clamps above it.
    pub fn query_receipt_analytics(
        &self,
        query: &ReceiptAnalyticsQuery,
    ) -> Result<ReceiptAnalyticsResponse, ReceiptStoreError> {
        require_admin_receipt_read_context(
            query.read_context.as_ref(),
            "receipt analytics report",
        )?;
        let group_limit = query
            .group_limit
            .unwrap_or(50)
            .clamp(1, MAX_ANALYTICS_GROUP_LIMIT) as i64;
        let time_bucket = query.time_bucket.unwrap_or(AnalyticsTimeBucket::Day);
        let bucket_width = time_bucket.width_secs() as i64;

        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let agent_subject = query.agent_subject.as_deref();

        let connection = self.connection()?;
        register_total_cost_charged(&connection)?;
        let snapshot = report_snapshot(&connection)?;

        let summary_sql = format!("SELECT {} {ANALYTICS_FROM_WHERE}", metric_columns());
        let summary = snapshot.query_row(
            &summary_sql,
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| metrics_from_row(row, 0),
        )?;

        let by_agent_sql = format!(
            "SELECT COALESCE(r.subject_key, cl.subject_key) AS subject_key, {} \
             {ANALYTICS_FROM_WHERE}
              AND COALESCE(r.subject_key, cl.subject_key) IS NOT NULL
            GROUP BY COALESCE(r.subject_key, cl.subject_key)
            ORDER BY total_receipts DESC, subject_key ASC
            LIMIT ?7",
            metric_columns()
        );
        let by_agent = snapshot
            .prepare(&by_agent_sql)?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject,
                    group_limit
                ],
                |row| {
                    Ok(AgentAnalyticsRow {
                        subject_key: row.get(0)?,
                        metrics: metrics_from_row(row, 1)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let by_tool_sql = format!(
            "SELECT r.tool_server, r.tool_name, {} {ANALYTICS_FROM_WHERE}
            GROUP BY r.tool_server, r.tool_name
            ORDER BY total_receipts DESC, r.tool_server ASC, r.tool_name ASC
            LIMIT ?7",
            metric_columns()
        );
        let by_tool = snapshot
            .prepare(&by_tool_sql)?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject,
                    group_limit
                ],
                |row| {
                    Ok(ToolAnalyticsRow {
                        tool_server: row.get(0)?,
                        tool_name: row.get(1)?,
                        metrics: metrics_from_row(row, 2)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        let by_time_sql = format!(
            "SELECT CAST((r.timestamp / ?7) * ?7 AS INTEGER) AS bucket_start, {} \
             {ANALYTICS_FROM_WHERE}
            GROUP BY bucket_start
            ORDER BY bucket_start ASC
            LIMIT ?8",
            metric_columns()
        );
        let by_time = snapshot
            .prepare(&by_time_sql)?
            .query_map(
                params![
                    capability_id,
                    tool_server,
                    tool_name,
                    since,
                    until,
                    agent_subject,
                    bucket_width,
                    group_limit
                ],
                |row| {
                    let bucket_start = row.get::<_, i64>(0)?.max(0) as u64;
                    Ok(TimeAnalyticsRow {
                        bucket_start,
                        bucket_end: bucket_start
                            .saturating_add(bucket_width.max(1) as u64)
                            .saturating_sub(1),
                        metrics: metrics_from_row(row, 1)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ReceiptAnalyticsResponse {
            summary,
            by_agent,
            by_tool,
            by_time,
        })
    }
}

#[cfg(test)]
#[path = "analytics_tests.rs"]
mod analytics_tests;
