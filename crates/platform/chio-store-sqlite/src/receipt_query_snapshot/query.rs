//! Fixed query plans over the owned snapshot. Every plan walks one index in
//! cursor order, so no plan needs a sorter or a temporary b-tree, and every
//! selection runs under one SQL work budget.
use chio_kernel::receipt_query::{ReceiptQuery, MAX_QUERY_LIMIT};
use chio_kernel::{ReceiptQuerySnapshotError, ReceiptStoreError};
use rusqlite::types::Value;
use rusqlite::{params_from_iter, ErrorCode, OptionalExtension};

use super::db::{
    blob32, tool_key, SnapshotDb, SnapshotDbError, COUNT_HOUR, COUNT_TOTAL, DIM_CAPABILITY,
    DIM_CURRENCY, DIM_DECISION, DIM_SUBJECT, DIM_TENANT, DIM_TOOL, DIM_TOOL_NAME, DIM_TOOL_SERVER,
    SCOPE_ALL,
};
use crate::receipt_store::support::SqlWorkBudget;

const SECONDS_PER_HOUR: i64 = 3_600;

/// One selected snapshot row, before its payload is fetched and authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SelectedRow {
    pub(super) seq: u64,
    pub(super) entry_seq: i64,
    pub(super) leaf_hash: [u8; 32],
}

#[derive(Debug, Default)]
pub(super) struct Selection {
    pub(super) rows: Vec<SelectedRow>,
    pub(super) total_count: u64,
    pub(super) limit: usize,
    /// Signed tenant every returned receipt must carry, if the read is scoped.
    pub(super) tenant: Option<String>,
}

/// Point lookup by receipt id within an optional tenant scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LocatedReceipt {
    pub(super) row: SelectedRow,
    pub(super) receipt_id: String,
}

/// Equality filter served by `(tenant, column, seq)` and `(column, seq)`.
#[derive(Debug, Clone, Copy)]
struct Equality {
    dim: i64,
    column: &'static str,
    value: i64,
}

fn column(dim: i64) -> &'static str {
    match dim {
        DIM_CAPABILITY => "capability",
        DIM_TOOL_SERVER => "tool_server",
        DIM_TOOL_NAME => "tool_name",
        DIM_TOOL => "tool",
        DIM_DECISION => "decision",
        DIM_SUBJECT => "subject",
        _ => "cost_currency",
    }
}

pub(super) fn snapshot_error(error: SnapshotDbError) -> ReceiptStoreError {
    match error {
        SnapshotDbError::Store(error) => error,
        // Storage I/O and resource failures say nothing about the snapshot's
        // contents; a read refuses as unavailable and may be retried.
        SnapshotDbError::Sqlite(error) if storage_unavailable(&error) => {
            ReceiptQuerySnapshotError::Unavailable(format!(
                "receipt query snapshot storage failed: {error}"
            ))
            .into()
        }
        SnapshotDbError::Sqlite(error) => ReceiptStoreError::Sqlite(error),
        other => ReceiptStoreError::Conflict(other.to_string()),
    }
}

/// Whether a snapshot storage error is an I/O or resource failure rather
/// than a statement about the stored rows.
pub(super) fn storage_unavailable(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(
            ErrorCode::SystemIoFailure
                | ErrorCode::CannotOpen
                | ErrorCode::OutOfMemory
                | ErrorCode::ReadOnly
                | ErrorCode::PermissionDenied
                | ErrorCode::DiskFull
                | ErrorCode::DatabaseBusy
                | ErrorCode::DatabaseLocked
        )
    )
}

/// Select one page and its exact total from one snapshot version.
///
/// Validation matches the per-call path exactly, so an invalid query fails
/// with the same error whichever path serves it.
pub(super) fn select(
    db: &SnapshotDb,
    query: &ReceiptQuery,
    sql_steps: u64,
) -> Result<Selection, ReceiptStoreError> {
    // Even a cached empty answer requires intact custody for this hold.
    db.connection()?;
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
    let scope = query
        .effective_read_scope()
        .map_err(ReceiptStoreError::from)?;
    let currency = query
        .validated_cost_currency()
        .map_err(ReceiptStoreError::ReadBoundary)?;
    if (query.min_cost.is_some() || query.max_cost.is_some()) && currency.is_none() {
        return Err(ReceiptStoreError::ReadBoundary(
            "receipt query cost bounds require a currency".to_string(),
        ));
    }
    let since = query
        .since
        .map(crate::integer::checked::<_, i64>)
        .transpose()?;
    let until = query
        .until
        .map(crate::integer::checked::<_, i64>)
        .transpose()?;
    // A cursor beyond every representable seq excludes every row while the
    // total still reports the uncursored filter set.
    let cursor = match query.cursor {
        None => Some(0),
        Some(cursor) => i64::try_from(cursor).ok(),
    };
    let mut selection = Selection {
        limit,
        tenant: scope.tenant.clone(),
        ..Selection::default()
    };

    let tenant = match scope.tenant.as_deref() {
        None => None,
        Some(tenant) => match db.dim_id(DIM_TENANT, tenant) {
            Some(id) => Some(id),
            None => return Ok(selection),
        },
    };
    let mut equalities = Vec::new();
    let mut wanted = Vec::new();
    if let Some(capability) = query.capability_id.as_deref() {
        wanted.push((DIM_CAPABILITY, capability.to_string()));
    }
    match (query.tool_server.as_deref(), query.tool_name.as_deref()) {
        (Some(server), Some(name)) => wanted.push((DIM_TOOL, tool_key(server, name))),
        (Some(server), None) => wanted.push((DIM_TOOL_SERVER, server.to_string())),
        (None, Some(name)) => wanted.push((DIM_TOOL_NAME, name.to_string())),
        (None, None) => {}
    }
    if let Some(outcome) = query.outcome.as_deref() {
        wanted.push((DIM_DECISION, outcome.to_string()));
    }
    if let Some(subject) = query.agent_subject.as_deref() {
        wanted.push((DIM_SUBJECT, subject.to_string()));
    }
    if let Some(currency) = currency {
        wanted.push((DIM_CURRENCY, currency.to_string()));
    }
    let count_scope = tenant.unwrap_or(SCOPE_ALL);
    let mut smallest: Option<(u64, usize)> = None;
    for (dim, value) in wanted {
        // An unknown value matches nothing, and dimensions commit with the rows
        // that use them, so this empty answer is exact for the version.
        let Some(id) = db.dim_id(dim, &value) else {
            return Ok(selection);
        };
        let Some((n, _, _)) = db.count(count_scope, dim, id).map_err(snapshot_error)? else {
            return Ok(selection);
        };
        if smallest.is_none_or(|(best, _)| n < best) {
            smallest = Some((n, equalities.len()));
        }
        equalities.push(Equality {
            dim,
            column: column(dim),
            value: id,
        });
    }

    let budget = SqlWorkBudget::new_for(db.connection()?, sql_steps, "receipt query")?;
    let result = run_plan(
        db,
        tenant,
        &equalities,
        smallest.map(|(_, index)| index),
        RangeFilters {
            since,
            until,
            min_cost: query.min_cost.map(|value| value.to_be_bytes().to_vec()),
            max_cost: query.max_cost.map(|value| value.to_be_bytes().to_vec()),
        },
        cursor,
        limit,
    );
    let exhausted = budget.exhausted();
    drop(budget);
    if exhausted {
        return Err(ReceiptQuerySnapshotError::WorkBudgetExhausted("receipt query".into()).into());
    }
    let (rows, total_count) = result?;
    selection.rows = rows;
    selection.total_count = total_count;
    Ok(selection)
}

struct RangeFilters {
    since: Option<i64>,
    until: Option<i64>,
    min_cost: Option<Vec<u8>>,
    max_cost: Option<Vec<u8>>,
}

impl RangeFilters {
    fn has_time(&self) -> bool {
        self.since.is_some() || self.until.is_some()
    }

    fn has_cost(&self) -> bool {
        self.min_cost.is_some() || self.max_cost.is_some()
    }
}

fn run_plan(
    db: &SnapshotDb,
    tenant: Option<i64>,
    equalities: &[Equality],
    driver: Option<usize>,
    ranges: RangeFilters,
    cursor: Option<i64>,
    limit: usize,
) -> Result<(Vec<SelectedRow>, u64), ReceiptStoreError> {
    let count_scope = tenant.unwrap_or(SCOPE_ALL);
    let window = if ranges.has_time() {
        match time_window(db, tenant, ranges.since, ranges.until)? {
            Some(window) => Some(window),
            None => return Ok((Vec::new(), 0)),
        }
    } else {
        None
    };

    // Unfiltered, single-equality and time-window shapes answer the total
    // from maintained cardinalities.
    let maintained = match (equalities, window, ranges.has_cost()) {
        ([], None, false) => Some(
            db.count(count_scope, COUNT_TOTAL, 0)
                .map_err(snapshot_error)?
                .map_or(0, |(n, _, _)| n),
        ),
        ([only], None, false) => Some(
            db.count(count_scope, only.dim, only.value)
                .map_err(snapshot_error)?
                .map_or(0, |(n, _, _)| n),
        ),
        ([], Some(window), false) => Some(window.count),
        _ => None,
    };

    let index = match driver.and_then(|index| equalities.get(index)) {
        Some(equality) => Some(match tenant {
            Some(_) => format!("sq_t_{}", equality.column),
            None => format!("sq_{}", equality.column),
        }),
        None => tenant.map(|_| "sq_t".to_string()),
    };
    let mut predicates = Vec::new();
    let mut values: Vec<Value> = Vec::new();
    if let Some(tenant) = tenant {
        predicates.push("tenant = ?".to_string());
        values.push(Value::Integer(tenant));
    }
    for equality in equalities {
        predicates.push(format!("{} = ?", equality.column));
        values.push(Value::Integer(equality.value));
    }
    if let Some(since) = ranges.since {
        predicates.push("ts >= ?".to_string());
        values.push(Value::Integer(since));
    }
    if let Some(until) = ranges.until {
        predicates.push("ts <= ?".to_string());
        values.push(Value::Integer(until));
    }
    if let Some(min_cost) = ranges.min_cost {
        predicates.push("cost_charged >= ?".to_string());
        values.push(Value::Blob(min_cost));
    }
    if let Some(max_cost) = ranges.max_cost {
        predicates.push("cost_charged <= ?".to_string());
        values.push(Value::Blob(max_cost));
    }
    if let Some(window) = window {
        predicates.push("seq >= ? AND seq <= ?".to_string());
        values.push(Value::Integer(window.min_seq));
        values.push(Value::Integer(window.max_seq));
    }
    let index_clause = index.map_or_else(
        || "NOT INDEXED".to_string(),
        |index| format!("INDEXED BY {index}"),
    );
    let filter = if predicates.is_empty() {
        "1".to_string()
    } else {
        predicates.join(" AND ")
    };

    let total_count = match maintained {
        Some(total) => total,
        None => {
            let sql =
                format!("SELECT COUNT(*) FROM snapshot_tool_receipt {index_clause} WHERE {filter}");
            let count: i64 = db
                .connection()?
                .prepare(&sql)?
                .query_row(params_from_iter(values.iter()), |row| row.get(0))?;
            u64::try_from(count).unwrap_or(0)
        }
    };
    let Some(cursor) = cursor else {
        return Ok((Vec::new(), total_count));
    };
    let sql = format!(
        "SELECT seq, entry_seq, leaf_hash FROM snapshot_tool_receipt {index_clause}
         WHERE {filter} AND seq > ? ORDER BY seq LIMIT ?"
    );
    values.push(Value::Integer(cursor));
    values.push(Value::Integer(crate::integer::checked::<_, i64>(limit)?));
    let mut statement = db.connection()?.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(values.iter()), |row| {
        Ok(SelectedRow {
            seq: u64::try_from(row.get::<_, i64>(0)?).unwrap_or(0),
            entry_seq: row.get(1)?,
            leaf_hash: blob32(row.get::<_, Vec<u8>>(2)?)?,
        })
    })?;
    let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok((rows, total_count))
}

/// Exact seq window and count of the rows whose timestamp lies in
/// `[since, until]`, from whole-hour cardinalities plus the boundary hours.
#[derive(Debug, Clone, Copy)]
struct TimeWindow {
    count: u64,
    min_seq: i64,
    max_seq: i64,
}

fn time_window(
    db: &SnapshotDb,
    tenant: Option<i64>,
    since: Option<i64>,
    until: Option<i64>,
) -> Result<Option<TimeWindow>, ReceiptStoreError> {
    if let (Some(since), Some(until)) = (since, until) {
        if since > until {
            return Ok(None);
        }
    }
    let scope = tenant.unwrap_or(SCOPE_ALL);
    let low_hour = since.map(|since| since.div_euclid(SECONDS_PER_HOUR));
    let high_hour = until.map(|until| until.div_euclid(SECONDS_PER_HOUR));
    let mut count = 0_u64;
    let mut min_seq = i64::MAX;
    let mut max_seq = i64::MIN;
    let mut absorb = |n: u64, low: Option<i64>, high: Option<i64>| {
        count = count.saturating_add(n);
        if let Some(low) = low {
            min_seq = min_seq.min(low);
        }
        if let Some(high) = high {
            max_seq = max_seq.max(high);
        }
    };

    // Whole hours strictly inside the window.
    let interior_low = low_hour.map_or(i64::MIN, |hour| hour.saturating_add(1));
    let interior_high = high_hour.map_or(i64::MAX, |hour| hour.saturating_sub(1));
    if interior_low <= interior_high {
        let (n, low, high): (i64, Option<i64>, Option<i64>) = db
            .connection()?
            .prepare_cached(
                "SELECT COALESCE(SUM(n), 0), MIN(min_seq), MAX(max_seq) FROM snapshot_count
                 WHERE scope = ?1 AND dim = ?2 AND value >= ?3 AND value <= ?4",
            )?
            .query_row(
                rusqlite::params![scope, COUNT_HOUR, interior_low, interior_high],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        absorb(u64::try_from(n).unwrap_or(0), low, high);
    }

    // Boundary hours are counted exactly from the timestamp index.
    let mut boundaries = Vec::new();
    match (since, until, low_hour, high_hour) {
        (Some(since), Some(until), Some(low), Some(high)) if low == high => {
            boundaries.push((since, until));
        }
        _ => {
            if let (Some(since), Some(low)) = (since, low_hour) {
                let hour_end = low
                    .saturating_add(1)
                    .saturating_mul(SECONDS_PER_HOUR)
                    .saturating_sub(1);
                boundaries.push((since, until.map_or(hour_end, |until| until.min(hour_end))));
            }
            if let (Some(until), Some(high)) = (until, high_hour) {
                boundaries.push((high.saturating_mul(SECONDS_PER_HOUR), until));
            }
        }
    }
    for (start, end) in boundaries {
        let (n, low, high): (i64, Option<i64>, Option<i64>) = match tenant {
            Some(tenant) => db
                .connection()?
                .prepare_cached(
                    "SELECT COUNT(*), MIN(seq), MAX(seq) FROM snapshot_tool_receipt INDEXED BY sq_t_ts
                     WHERE tenant = ?1 AND ts >= ?2 AND ts <= ?3",
                )?
                .query_row(rusqlite::params![tenant, start, end], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?,
            None => db
                .connection()?
                .prepare_cached(
                    "SELECT COUNT(*), MIN(seq), MAX(seq) FROM snapshot_tool_receipt INDEXED BY sq_ts
                     WHERE ts >= ?1 AND ts <= ?2",
                )?
                .query_row(rusqlite::params![start, end], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?,
        };
        absorb(u64::try_from(n).unwrap_or(0), low, high);
    }
    if count == 0 {
        return Ok(None);
    }
    Ok(Some(TimeWindow {
        count,
        min_seq,
        max_seq,
    }))
}

/// Locate one receipt by id. Rows outside the read scope are absent, as on
/// the per-call path.
pub(super) fn locate(
    db: &SnapshotDb,
    receipt_id: &str,
    tenant: Option<&str>,
) -> Result<Option<LocatedReceipt>, ReceiptStoreError> {
    db.connection()?;
    let tenant_id = match tenant {
        None => None,
        Some(tenant) => match db.dim_id(DIM_TENANT, tenant) {
            Some(id) => Some(id),
            None => return Ok(None),
        },
    };
    let row = db
        .connection()?
        .prepare_cached(
            "SELECT seq, entry_seq, leaf_hash, tenant FROM snapshot_tool_receipt INDEXED BY sq_receipt_id
             WHERE receipt_id = ?1",
        )?
        .query_row([receipt_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                blob32(row.get::<_, Vec<u8>>(2)?)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .optional()?;
    Ok(row.and_then(|(seq, entry_seq, leaf_hash, row_tenant)| {
        if tenant_id.is_some_and(|tenant| tenant != row_tenant) {
            return None;
        }
        Some(LocatedReceipt {
            row: SelectedRow {
                seq: u64::try_from(seq).unwrap_or(0),
                entry_seq,
                leaf_hash,
            },
            receipt_id: receipt_id.to_string(),
        })
    }))
}
