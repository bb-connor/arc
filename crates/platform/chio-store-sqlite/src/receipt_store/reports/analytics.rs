// Receipt analytics report query.

use super::*;

use rusqlite::functions::{Aggregate, Context, FunctionFlags};
use rusqlite::types::ValueRef;
use rusqlite::ToSql;

/// SQL name of the aggregate that totals the charged-cost projection.
const TOTAL_COST_CHARGED: &str = "chio_total_cost_charged";

/// Width of the `cost_charged_be` projection the receipt append path writes.
const COST_CHARGED_BYTES: usize = 8;

/// Width the charged-cost aggregate returns its running total in.
const COST_TOTAL_BYTES: usize = 16;

/// Refusal when the charges in scope total more than the report's metrics carry.
const COST_TOTAL_UNREPORTABLE: &str =
    "receipt analytics charged-cost total exceeds the reportable range";

/// Receipts one analytics report may aggregate.
///
/// No rollup table stands behind this report, so each of its four dimensions
/// visits every matching receipt and parses its JSON once for the attempted
/// cost. At the cost this lane measured, around 22 microseconds of report time
/// per receipt across the four dimensions, this ceiling puts the slowest
/// accepted report in the seconds and makes a whole-table request an error that
/// names the filters that bound it.
const MAX_ANALYTICS_RECEIPT_SCAN: i64 = 250_000;

/// Totals the eight-byte big-endian charged-cost projection.
///
/// SQLite arithmetic is signed 64-bit and degrades silently to floating point on
/// overflow, so no SQL expression can sum the unsigned charge domain exactly.
/// The running total is a `u128` here and comes back as a big-endian blob the
/// report decodes. A NULL projection is a receipt with no financial block and
/// contributes nothing; any other width violates the column's `CHECK`
/// constraint and refuses rather than contributing a wrong number to a financial
/// report.
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

/// The filters a report was asked for, owned so the bound parameters can borrow
/// from one place for every dimension.
struct AnalyticsScope {
    capability_id: Option<String>,
    tool_server: Option<String>,
    tool_name: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
    agent_subject: Option<String>,
}

/// Whether a dimension resolves each receipt's subject through capability
/// lineage.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SubjectDimension {
    /// The dimension neither filters nor groups by subject.
    Absent,
    /// The dimension groups by the resolved subject and drops receipts whose
    /// subject resolves to nothing.
    Grouped,
}

/// The `FROM` and `WHERE` text for one dimension with the values its positional
/// parameters bind to. Values are bound, never interpolated.
struct AnalyticsScan<'bind> {
    from_where: String,
    bound: Vec<&'bind dyn ToSql>,
}

impl<'bind> AnalyticsScan<'bind> {
    /// Bind one more value and return the positional index that names it.
    fn bind(&mut self, value: &'bind dyn ToSql) -> usize {
        self.bound.push(value);
        self.bound.len()
    }

    fn params(&self) -> &[&'bind dyn ToSql] {
        &self.bound
    }
}

impl AnalyticsScope {
    fn from_query(query: &ReceiptAnalyticsQuery) -> Self {
        Self {
            capability_id: query.capability_id.clone(),
            tool_server: query.tool_server.clone(),
            tool_name: query.tool_name.clone(),
            since: query.since.map(|value| value as i64),
            until: query.until.map(|value| value as i64),
            agent_subject: query.agent_subject.clone(),
        }
    }

    /// Build the scan for one dimension.
    ///
    /// Only the filters the caller supplied become predicates. Under the
    /// `(?N IS NULL OR col = ?N)` form the planner has no usable index on any of
    /// the six indexed columns, so a report was a full table scan whatever it
    /// filtered on.
    fn scan(&self, subject: SubjectDimension) -> AnalyticsScan<'_> {
        let mut bound: Vec<&dyn ToSql> = Vec::new();
        let mut predicates: Vec<String> = Vec::new();

        if self.capability_id.is_some() {
            bound.push(&self.capability_id);
            predicates.push(format!("r.capability_id = ?{}", bound.len()));
        }
        if self.tool_server.is_some() {
            bound.push(&self.tool_server);
            predicates.push(format!("r.tool_server = ?{}", bound.len()));
        }
        if self.tool_name.is_some() {
            bound.push(&self.tool_name);
            predicates.push(format!("r.tool_name = ?{}", bound.len()));
        }
        if self.since.is_some() {
            bound.push(&self.since);
            predicates.push(format!("r.timestamp >= ?{}", bound.len()));
        }
        if self.until.is_some() {
            bound.push(&self.until);
            predicates.push(format!("r.timestamp <= ?{}", bound.len()));
        }
        if self.agent_subject.is_some() {
            bound.push(&self.agent_subject);
            let subject_param = bound.len();
            // Written as a disjunction rather than over COALESCE so the subject
            // index stays usable: a receipt carries its own subject whenever its
            // metadata named one, and capability lineage is the fallback for the
            // rest.
            predicates.push(format!(
                "(r.subject_key = ?{subject_param} \
                 OR (r.subject_key IS NULL AND cl.subject_key = ?{subject_param}))"
            ));
        }
        if subject == SubjectDimension::Grouped {
            predicates.push("COALESCE(r.subject_key, cl.subject_key) IS NOT NULL".to_string());
        }

        // `capability_lineage.capability_id` is that table's primary key, so the
        // left join can neither add nor drop a receipt row, and it is left out
        // where no predicate or grouping reads the lineage subject.
        let resolves_subject = self.agent_subject.is_some() || subject == SubjectDimension::Grouped;
        let mut from_where = String::from("FROM chio_tool_receipts r");
        if resolves_subject {
            from_where.push_str(
                "\n            LEFT JOIN capability_lineage cl \
                 ON r.capability_id = cl.capability_id",
            );
        }
        if !predicates.is_empty() {
            from_where.push_str("\n            WHERE ");
            from_where.push_str(&predicates.join("\n              AND "));
        }

        AnalyticsScan { from_where, bound }
    }
}

fn receipt_ceiling_query<'bind>(
    scope: &'bind AnalyticsScope,
    ceiling: &'bind i64,
) -> (String, AnalyticsScan<'bind>) {
    let mut scan = scope.scan(SubjectDimension::Absent);
    let limit = scan.bind(ceiling);
    // The subquery's LIMIT stops the walk one row past the ceiling, so the check
    // costs a bounded scan rather than a count of the whole match.
    let sql = format!(
        "SELECT COUNT(*) FROM (SELECT 1 {} LIMIT ?{limit})",
        scan.from_where
    );
    (sql, scan)
}

fn summary_query(scope: &AnalyticsScope) -> (String, AnalyticsScan<'_>) {
    let scan = scope.scan(SubjectDimension::Absent);
    let sql = format!("SELECT {} {}", metric_columns(), scan.from_where);
    (sql, scan)
}

fn agent_query<'bind>(
    scope: &'bind AnalyticsScope,
    group_limit: &'bind i64,
) -> (String, AnalyticsScan<'bind>) {
    let mut scan = scope.scan(SubjectDimension::Grouped);
    let limit = scan.bind(group_limit);
    let sql = format!(
        "SELECT COALESCE(r.subject_key, cl.subject_key) AS subject_key, {} {}
            GROUP BY COALESCE(r.subject_key, cl.subject_key)
            ORDER BY total_receipts DESC, subject_key ASC
            LIMIT ?{limit}",
        metric_columns(),
        scan.from_where
    );
    (sql, scan)
}

fn tool_query<'bind>(
    scope: &'bind AnalyticsScope,
    group_limit: &'bind i64,
) -> (String, AnalyticsScan<'bind>) {
    let mut scan = scope.scan(SubjectDimension::Absent);
    let limit = scan.bind(group_limit);
    let sql = format!(
        "SELECT r.tool_server, r.tool_name, {} {}
            GROUP BY r.tool_server, r.tool_name
            ORDER BY total_receipts DESC, r.tool_server ASC, r.tool_name ASC
            LIMIT ?{limit}",
        metric_columns(),
        scan.from_where
    );
    (sql, scan)
}

fn time_query<'bind>(
    scope: &'bind AnalyticsScope,
    bucket_width: &'bind i64,
    group_limit: &'bind i64,
) -> (String, AnalyticsScan<'bind>) {
    let mut scan = scope.scan(SubjectDimension::Absent);
    let width = scan.bind(bucket_width);
    let limit = scan.bind(group_limit);
    let sql = format!(
        "SELECT CAST((r.timestamp / ?{width}) * ?{width} AS INTEGER) AS bucket_start, {} {}
            GROUP BY bucket_start
            ORDER BY bucket_start ASC
            LIMIT ?{limit}",
        metric_columns(),
        scan.from_where
    );
    (sql, scan)
}

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
    ///
    /// A report matching more receipts than `MAX_ANALYTICS_RECEIPT_SCAN` is
    /// refused. `since` and `until` bound it.
    pub fn query_receipt_analytics(
        &self,
        query: &ReceiptAnalyticsQuery,
    ) -> Result<ReceiptAnalyticsResponse, ReceiptStoreError> {
        self.receipt_analytics_within(query, MAX_ANALYTICS_RECEIPT_SCAN)
    }

    fn receipt_analytics_within(
        &self,
        query: &ReceiptAnalyticsQuery,
        receipt_ceiling: i64,
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
        let scope = AnalyticsScope::from_query(query);

        let connection = self.connection()?;
        register_total_cost_charged(&connection)?;
        let snapshot = report_snapshot(&connection)?;

        let ceiling = receipt_ceiling.saturating_add(1);
        let (ceiling_sql, ceiling_scan) = receipt_ceiling_query(&scope, &ceiling);
        let matched: i64 =
            snapshot.query_row(&ceiling_sql, ceiling_scan.params(), |row| row.get(0))?;
        if matched > receipt_ceiling {
            return Err(ReceiptStoreError::ReadBoundary(format!(
                "receipt analytics report covers more than {receipt_ceiling} receipts; \
                 bound it with `since` and `until`"
            )));
        }

        let (summary_sql, summary_scan) = summary_query(&scope);
        let summary = snapshot.query_row(&summary_sql, summary_scan.params(), |row| {
            metrics_from_row(row, 0)
        })?;

        let (agent_sql, agent_scan) = agent_query(&scope, &group_limit);
        let by_agent = snapshot
            .prepare(&agent_sql)?
            .query_map(agent_scan.params(), |row| {
                Ok(AgentAnalyticsRow {
                    subject_key: row.get(0)?,
                    metrics: metrics_from_row(row, 1)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let (tool_sql, tool_scan) = tool_query(&scope, &group_limit);
        let by_tool = snapshot
            .prepare(&tool_sql)?
            .query_map(tool_scan.params(), |row| {
                Ok(ToolAnalyticsRow {
                    tool_server: row.get(0)?,
                    tool_name: row.get(1)?,
                    metrics: metrics_from_row(row, 2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let (time_sql, time_scan) = time_query(&scope, &bucket_width, &group_limit);
        let by_time = snapshot
            .prepare(&time_sql)?
            .query_map(time_scan.params(), |row| {
                let bucket_start = row.get::<_, i64>(0)?.max(0) as u64;
                Ok(TimeAnalyticsRow {
                    bucket_start,
                    bucket_end: bucket_start
                        .saturating_add(bucket_width.max(1) as u64)
                        .saturating_sub(1),
                    metrics: metrics_from_row(row, 1)?,
                })
            })?
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
