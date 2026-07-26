//! `chio settle status` CLI surface.
//!
//! Surfaces the local settlement lifecycle for operator review. The
//! command opens an existing chio-store-sqlite database read-only and
//! reports:
//!
//! - `pending`: IOU envelopes that have no `settlement_reconciliations`
//!   row yet.
//! - `retrying`: durable `settle_attempts` rows awaiting a drive pass.
//! - `settled`: rows in `settlement_reconciliations` whose
//!   `reconciliation_state` is `reconciled`.
//! - `dead_lettered`: rows in `settle_dead_letters`.
//!
//! The status report is deterministic: lists are sorted by
//! `(finalized_at, receipt_id)` to match the settlement-ordering
//! invariant documented on `chio-settle::SettlementHook`.
//!
//! Output formats:
//!
//! - default (TTY): a small human table per state.
//! - `--json`: a stable JSON report suitable for tooling. The schema
//!   tag is `chio.settle.status-report.v2`.

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

/// Schema string emitted on the wire for status reports.
pub const SETTLE_STATUS_REPORT_SCHEMA: &str = "chio.settle.status-report.v2";
#[cfg(test)]
pub const DEFAULT_SETTLE_STATUS_LIMIT: usize = 256;
pub const MAX_SETTLE_STATUS_LIMIT: usize = 4_096;
const MAX_STATUS_CANONICAL_BYTES: i64 = 65_536;
const MAX_STATUS_RECEIPT_BYTES: i64 = 1_048_576;
const MAX_STATUS_RETRY_ATTEMPTS: u32 = 32;

/// Errors surfaced by the `chio settle status` command.
#[derive(Debug, thiserror::Error)]
pub enum SettleStatusError {
    #[error("settle status backend error: {0}")]
    Backend(String),
    #[error("settle status store path does not exist: {0}")]
    NotFound(PathBuf),
    #[error("settle drive integrity error: {0}")]
    Integrity(String),
}

/// One pending IOU envelope row surfaced by the status report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingRow {
    pub receipt_id: String,
    pub finalized_at: i64,
    pub amount_units: i64,
    pub currency: String,
}

/// One settled receipt row surfaced by the status report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettledRow {
    pub receipt_id: String,
    pub reconciliation_state: String,
    pub updated_at: i64,
}

/// One dead-lettered row surfaced by the status report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeadLetteredRow {
    pub receipt_id: String,
    pub finalized_at: i64,
    pub attempts: i64,
    pub reason: String,
}

/// One durable retry row surfaced by the status report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetryingRow {
    pub receipt_id: String,
    pub finalized_at: i64,
    pub attempts: i64,
    pub next_visible_at: i64,
    pub state: String,
    pub claim_deadline_unix_secs: Option<i64>,
    pub last_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusSectionCount {
    pub total: u64,
    pub returned: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettleStatusCounts {
    pub pending: StatusSectionCount,
    pub retrying: StatusSectionCount,
    pub settled: StatusSectionCount,
    pub dead_lettered: StatusSectionCount,
}

/// Aggregate status report. The `schema` tag pins the wire format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettleStatusReport {
    pub schema: String,
    pub limit: usize,
    pub truncated: bool,
    pub counts: SettleStatusCounts,
    pub pending: Vec<PendingRow>,
    pub retrying: Vec<RetryingRow>,
    pub settled: Vec<SettledRow>,
    pub dead_lettered: Vec<DeadLetteredRow>,
}

impl SettleStatusReport {
    /// Build a status report from a chio-store-sqlite database file.
    /// The connection is opened read-only; tables that are absent
    /// (because the relevant migration has not run yet) yield empty
    /// vectors rather than errors.
    #[cfg(test)]
    pub fn load(path: &Path) -> Result<Self, SettleStatusError> {
        Self::load_bounded(path, DEFAULT_SETTLE_STATUS_LIMIT)
    }

    pub fn load_bounded(path: &Path, limit: usize) -> Result<Self, SettleStatusError> {
        if !path.exists() {
            return Err(SettleStatusError::NotFound(path.to_path_buf()));
        }
        if limit == 0 || limit > MAX_SETTLE_STATUS_LIMIT {
            return Err(SettleStatusError::Integrity(format!(
                "settle status limit must be in 1..={MAX_SETTLE_STATUS_LIMIT}"
            )));
        }
        // Force a read-only connection so the CLI never mutates state.
        let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
        let conn: &Connection = &transaction;

        let pending_total = if table_exists(conn, "iou_envelope")? {
            count_pending(conn)?
        } else {
            0
        };
        let pending = if pending_total > 0 {
            list_pending(conn, limit)?
        } else {
            Vec::new()
        };
        let retrying_total = if table_exists(conn, "settle_attempts")? {
            count_rows(conn, "settle_attempts", None)?
        } else {
            0
        };
        let retrying = if retrying_total > 0 {
            list_retrying(conn, limit)?
        } else {
            Vec::new()
        };
        let settled_total = if table_exists(conn, "settlement_reconciliations")? {
            count_rows(
                conn,
                "settlement_reconciliations",
                Some("reconciliation_state = 'reconciled'"),
            )?
        } else {
            0
        };
        let settled = if settled_total > 0 {
            list_settled(conn, limit)?
        } else {
            Vec::new()
        };
        let dead_lettered_total = if table_exists(conn, "settle_dead_letters")? {
            count_rows(conn, "settle_dead_letters", None)?
        } else {
            0
        };
        let dead_lettered = if dead_lettered_total > 0 {
            list_dead_lettered(conn, limit)?
        } else {
            Vec::new()
        };

        let counts = SettleStatusCounts {
            pending: section_count(pending_total, pending.len())?,
            retrying: section_count(retrying_total, retrying.len())?,
            settled: section_count(settled_total, settled.len())?,
            dead_lettered: section_count(dead_lettered_total, dead_lettered.len())?,
        };
        let truncated = counts.pending.truncated
            || counts.retrying.truncated
            || counts.settled.truncated
            || counts.dead_lettered.truncated;
        transaction
            .commit()
            .map_err(|err| SettleStatusError::Backend(err.to_string()))?;

        Ok(Self {
            schema: SETTLE_STATUS_REPORT_SCHEMA.to_string(),
            limit,
            truncated,
            counts,
            pending,
            retrying,
            settled,
            dead_lettered,
        })
    }

    /// Render the report as a human-readable text summary.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "settle status: pending={}/{} retrying={}/{} settled={}/{} dead_lettered={}/{} truncated={}\n",
            self.counts.pending.returned,
            self.counts.pending.total,
            self.counts.retrying.returned,
            self.counts.retrying.total,
            self.counts.settled.returned,
            self.counts.settled.total,
            self.counts.dead_lettered.returned,
            self.counts.dead_lettered.total,
            self.truncated,
        ));
        if !self.pending.is_empty() {
            out.push_str("\npending:\n");
            for row in &self.pending {
                out.push_str(&format!(
                    "  {receipt_id} ts={finalized_at} {amount_units} {currency}\n",
                    receipt_id = display_field(&row.receipt_id),
                    finalized_at = row.finalized_at,
                    amount_units = row.amount_units,
                    currency = display_field(&row.currency),
                ));
            }
        }
        if !self.retrying.is_empty() {
            out.push_str("\nretrying:\n");
            for row in &self.retrying {
                out.push_str(&format!(
                    "  {receipt_id} ts={finalized_at} attempts={attempts} next_visible_at={next_visible_at} state={state}\n",
                    receipt_id = display_field(&row.receipt_id),
                    finalized_at = row.finalized_at,
                    attempts = row.attempts,
                    next_visible_at = row.next_visible_at,
                    state = display_field(&row.state),
                ));
            }
        }
        if !self.settled.is_empty() {
            out.push_str("\nsettled:\n");
            for row in &self.settled {
                out.push_str(&format!(
                    "  {receipt_id} state={state} updated_at={updated_at}\n",
                    receipt_id = display_field(&row.receipt_id),
                    state = display_field(&row.reconciliation_state),
                    updated_at = row.updated_at,
                ));
            }
        }
        if !self.dead_lettered.is_empty() {
            out.push_str("\ndead_lettered:\n");
            for row in &self.dead_lettered {
                out.push_str(&format!(
                    "  {receipt_id} ts={finalized_at} attempts={attempts} reason={reason}\n",
                    receipt_id = display_field(&row.receipt_id),
                    finalized_at = row.finalized_at,
                    attempts = row.attempts,
                    reason = display_field(&row.reason),
                ));
            }
        }
        out
    }

    /// Render the report as structured JSON.
    pub fn render_json(&self) -> Result<String, SettleStatusError> {
        serde_json::to_string_pretty(self)
            .map_err(|err| SettleStatusError::Backend(err.to_string()))
    }
}

fn display_field(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

fn checked_u64(value: i64, field: &str) -> Result<u64, SettleStatusError> {
    u64::try_from(value).map_err(|_| {
        SettleStatusError::Integrity(format!("{field} is outside the supported u64 range"))
    })
}

fn section_count(total: u64, returned: usize) -> Result<StatusSectionCount, SettleStatusError> {
    let returned = u64::try_from(returned).map_err(|_| {
        SettleStatusError::Integrity("settle status returned row count exceeds u64".to_string())
    })?;
    Ok(StatusSectionCount {
        total,
        returned,
        truncated: total > returned,
    })
}

fn count_rows(
    conn: &Connection,
    table: &str,
    predicate: Option<&str>,
) -> Result<u64, SettleStatusError> {
    let sql = predicate.map_or_else(
        || format!("SELECT COUNT(*) FROM {table}"),
        |predicate| format!("SELECT COUNT(*) FROM {table} WHERE {predicate}"),
    );
    let count = conn
        .query_row(&sql, [], |row| row.get::<_, i64>(0))
        .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
    checked_u64(count, "settle status row count")
}

fn count_pending(conn: &Connection) -> Result<u64, SettleStatusError> {
    let sql = if table_exists(conn, "settlement_reconciliations")? {
        "SELECT COUNT(*) FROM iou_envelope AS iou \
         LEFT JOIN settlement_reconciliations AS rec ON rec.receipt_id = iou.receipt_id \
         WHERE rec.receipt_id IS NULL"
    } else {
        "SELECT COUNT(*) FROM iou_envelope"
    };
    let count = conn
        .query_row(sql, [], |row| row.get::<_, i64>(0))
        .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
    checked_u64(count, "pending IOU count")
}

fn require_receipt_table(conn: &Connection) -> Result<(), SettleStatusError> {
    if !table_exists(conn, "chio_tool_receipts")? {
        return Err(SettleStatusError::Integrity(
            "settlement rows exist without the authoritative receipt table".to_string(),
        ));
    }
    Ok(())
}

fn preflight_blob_size(
    conn: &Connection,
    table: &str,
    column: &str,
    maximum: i64,
) -> Result<(), SettleStatusError> {
    let sql = format!("SELECT COALESCE(MAX(length(CAST({column} AS BLOB))), 0) FROM {table}");
    let size = conn
        .query_row(&sql, [], |row| row.get::<_, i64>(0))
        .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
    if size < 0 || size > maximum {
        return Err(SettleStatusError::Integrity(format!(
            "{table}.{column} exceeds the bounded status read limit"
        )));
    }
    Ok(())
}

fn validate_status_receipt(
    raw_json: &str,
    expected_receipt_id: &str,
    expected_timestamp: Option<i64>,
) -> Result<chio_core::receipt::body::ChioReceipt, SettleStatusError> {
    let receipt: chio_core::receipt::body::ChioReceipt = serde_json::from_str(raw_json)
        .map_err(|error| SettleStatusError::Integrity(format!(
            "authoritative receipt {expected_receipt_id} is invalid JSON: {error}"
        )))?;
    if receipt.id != expected_receipt_id {
        return Err(SettleStatusError::Integrity(
            "settlement row is owned by a different authoritative receipt".to_string(),
        ));
    }
    if let Some(expected_timestamp) = expected_timestamp {
        let receipt_timestamp = i64::try_from(receipt.timestamp).map_err(|_| {
            SettleStatusError::Integrity(format!(
                "receipt {} timestamp exceeds SQLite INTEGER range",
                receipt.id
            ))
        })?;
        if receipt_timestamp != expected_timestamp {
            return Err(SettleStatusError::Integrity(format!(
                "settlement row timestamp does not match receipt {}",
                receipt.id
            )));
        }
    }
    let content_derived_id =
        chio_core::receipt::body::chio_receipt_id(&receipt.body()).map_err(|error| {
            SettleStatusError::Integrity(format!(
                "receipt {} content-derived id could not be computed: {error}",
                receipt.id
            ))
        })?;
    if content_derived_id != receipt.id {
        return Err(SettleStatusError::Integrity(format!(
            "receipt {} does not match its content-derived id {content_derived_id}",
            receipt.id
        )));
    }
    if !receipt.verify_signature().map_err(|error| {
        SettleStatusError::Integrity(format!(
            "receipt {} signature verification failed: {error}",
            receipt.id
        ))
    })? {
        return Err(SettleStatusError::Integrity(format!(
            "receipt {} has an invalid signature",
            receipt.id
        )));
    }
    if !receipt.action.verify_hash().map_err(|error| {
        SettleStatusError::Integrity(format!(
            "receipt {} action validation failed: {error}",
            receipt.id
        ))
    })? {
        return Err(SettleStatusError::Integrity(format!(
            "receipt {} has an invalid action hash",
            receipt.id
        )));
    }
    Ok(receipt)
}

struct StatusIouRow {
    receipt_id: String,
    iou_id: String,
    receipt_timestamp: i64,
    tenant_id: Option<String>,
    amount_units: i64,
    currency: String,
    issuer_key: String,
    canonical_json: String,
}

fn validate_status_iou(
    row: &StatusIouRow,
    receipt: &chio_core::receipt::body::ChioReceipt,
    lifecycle: &str,
) -> Result<(), SettleStatusError> {
    if row.receipt_id.trim().is_empty()
        || row.receipt_id.len() > 512
        || row.iou_id.trim().is_empty()
        || row.iou_id.len() > 512
        || row.receipt_timestamp < 0
        || row.amount_units <= 0
        || row.currency.trim().is_empty()
        || row.currency.len() > 512
    {
        return Err(SettleStatusError::Integrity(format!(
            "{lifecycle} IOU contains an invalid bounded projection"
        )));
    }
    let financial = receipt.financial_metadata().ok_or_else(|| {
        SettleStatusError::Integrity(format!(
            "{lifecycle} IOU {} has no authoritative financial metadata",
            row.receipt_id
        ))
    })?;
    let envelope: chio_core::credit::IouEnvelope = serde_json::from_str(&row.canonical_json)
        .map_err(|error| {
            SettleStatusError::Integrity(format!(
                "{lifecycle} IOU {} is invalid JSON: {error}",
                row.receipt_id
            ))
        })?;
    if chio_core::canonical::canonical_json_bytes(&envelope)
        .map_err(|error| SettleStatusError::Integrity(error.to_string()))?
        != row.canonical_json.as_bytes()
    {
        return Err(SettleStatusError::Integrity(format!(
            "{lifecycle} IOU {} is not canonical JSON",
            row.receipt_id
        )));
    }
    if row.receipt_id != receipt.id
        || envelope.body.schema != chio_core::credit::IOU_ENVELOPE_SCHEMA
        || envelope.body.receipt_id != row.receipt_id
        || envelope.body.iou_id != row.iou_id
        || envelope.body.iou_id
            != chio_core::credit::local_account::derive_iou_id(&receipt.id)
        || i64::try_from(envelope.body.receipt_timestamp).ok() != Some(row.receipt_timestamp)
        || envelope.body.tenant_id != row.tenant_id
        || i64::try_from(envelope.body.amount_units).ok() != Some(row.amount_units)
        || envelope.body.currency != row.currency
        || serde_json::to_string(&envelope.body.issuer_key)
            .map_err(|error| SettleStatusError::Integrity(error.to_string()))?
            != row.issuer_key
        || envelope.body.tool_server != receipt.tool_server
        || envelope.body.tool_name != receipt.tool_name
        || envelope.body.capability_id != receipt.capability_id
        || envelope.body.tenant_id != receipt.tenant_id
        || envelope.body.amount_units != financial.cost_charged
        || envelope.body.currency != financial.currency
    {
        return Err(SettleStatusError::Integrity(format!(
            "{lifecycle} IOU {} projections or receipt ownership are invalid",
            row.receipt_id
        )));
    }
    if !envelope.verify_signature().map_err(|error| {
        SettleStatusError::Integrity(format!(
            "{lifecycle} IOU {} signature verification failed: {error}",
            row.receipt_id
        ))
    })? {
        return Err(SettleStatusError::Integrity(format!(
            "{lifecycle} IOU {} has an invalid signature",
            row.receipt_id
        )));
    }
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool, SettleStatusError> {
    let row: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    Ok(row.is_some())
}

fn list_pending(conn: &Connection, limit: usize) -> Result<Vec<PendingRow>, SettleStatusError> {
    require_receipt_table(conn)?;
    preflight_blob_size(
        conn,
        "iou_envelope",
        "canonical_json",
        MAX_STATUS_CANONICAL_BYTES,
    )?;
    preflight_blob_size(
        conn,
        "chio_tool_receipts",
        "raw_json",
        MAX_STATUS_RECEIPT_BYTES,
    )?;
    let reconciliations_present = table_exists(conn, "settlement_reconciliations")?;
    let sql = if reconciliations_present {
        "SELECT iou.receipt_id, iou.iou_id, iou.receipt_timestamp, iou.tenant_id, \
                iou.amount_units, iou.currency, iou.issuer_key, iou.canonical_json, r.raw_json \
         FROM iou_envelope AS iou \
         LEFT JOIN settlement_reconciliations AS rec \
           ON rec.receipt_id = iou.receipt_id \
         LEFT JOIN chio_tool_receipts AS r ON r.receipt_id = iou.receipt_id \
         WHERE rec.receipt_id IS NULL \
         ORDER BY iou.receipt_timestamp ASC, iou.receipt_id ASC LIMIT ?1"
    } else {
        "SELECT iou.receipt_id, iou.iou_id, iou.receipt_timestamp, iou.tenant_id, \
                iou.amount_units, iou.currency, iou.issuer_key, iou.canonical_json, r.raw_json \
         FROM iou_envelope AS iou \
         LEFT JOIN chio_tool_receipts AS r ON r.receipt_id = iou.receipt_id \
         ORDER BY iou.receipt_timestamp ASC, iou.receipt_id ASC LIMIT ?1"
    };
    let limit = i64::try_from(limit).map_err(|_| {
        SettleStatusError::Integrity("settle status limit exceeds SQLite INTEGER".to_string())
    })?;
    let mut stmt = conn
        .prepare(sql)
        .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    let rows = stmt
        .query_map([limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        })
        .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        let (
            receipt_id,
            iou_id,
            receipt_timestamp,
            tenant_id,
            amount_units,
            currency,
            issuer_key,
            canonical_json,
            raw_receipt,
        ) = row.map_err(|err| SettleStatusError::Backend(err.to_string()))?;
        let iou = StatusIouRow {
            receipt_id,
            iou_id,
            receipt_timestamp,
            tenant_id,
            amount_units,
            currency,
            issuer_key,
            canonical_json,
        };
        let raw_receipt = raw_receipt.ok_or_else(|| {
            SettleStatusError::Integrity(format!(
                "pending IOU {} has no authoritative live receipt",
                iou.receipt_id
            ))
        })?;
        let receipt = validate_status_receipt(
            &raw_receipt,
            &iou.receipt_id,
            Some(iou.receipt_timestamp),
        )?;
        validate_status_iou(&iou, &receipt, "pending")?;
        out.push(PendingRow {
            receipt_id: iou.receipt_id,
            finalized_at: iou.receipt_timestamp,
            amount_units: iou.amount_units,
            currency: iou.currency,
        });
    }
    Ok(out)
}

fn list_settled(conn: &Connection, limit: usize) -> Result<Vec<SettledRow>, SettleStatusError> {
    require_receipt_table(conn)?;
    preflight_blob_size(
        conn,
        "chio_tool_receipts",
        "raw_json",
        MAX_STATUS_RECEIPT_BYTES,
    )?;
    let iou_table_present = table_exists(conn, "iou_envelope")?;
    if iou_table_present {
        preflight_blob_size(
            conn,
            "iou_envelope",
            "canonical_json",
            MAX_STATUS_CANONICAL_BYTES,
        )?;
    }
    let sql = if iou_table_present {
        "SELECT sr.receipt_id, sr.reconciliation_state, sr.updated_at, \
                r.timestamp, r.raw_json, iou.receipt_id, iou.iou_id, \
                iou.receipt_timestamp, iou.tenant_id, iou.amount_units, \
                iou.currency, iou.issuer_key, iou.canonical_json \
         FROM settlement_reconciliations AS sr \
         LEFT JOIN chio_tool_receipts AS r ON r.receipt_id = sr.receipt_id \
         LEFT JOIN iou_envelope AS iou ON iou.receipt_id = sr.receipt_id \
         WHERE sr.reconciliation_state = 'reconciled' \
         ORDER BY r.timestamp ASC, sr.receipt_id ASC LIMIT ?1"
    } else {
        "SELECT sr.receipt_id, sr.reconciliation_state, sr.updated_at, \
                r.timestamp, r.raw_json, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL \
         FROM settlement_reconciliations AS sr \
         LEFT JOIN chio_tool_receipts AS r ON r.receipt_id = sr.receipt_id \
         WHERE sr.reconciliation_state = 'reconciled' \
         ORDER BY r.timestamp ASC, sr.receipt_id ASC LIMIT ?1"
    };
    let limit = i64::try_from(limit).map_err(|_| {
        SettleStatusError::Integrity("settle status limit exceeds SQLite INTEGER".to_string())
    })?;
    let mut stmt = conn
        .prepare(sql)
        .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    let rows = stmt
        .query_map([limit], |row| {
            let iou_receipt_id = row.get::<_, Option<String>>(5)?;
            let iou = if let Some(receipt_id) = iou_receipt_id {
                Some(StatusIouRow {
                    receipt_id,
                    iou_id: row.get(6)?,
                    receipt_timestamp: row.get(7)?,
                    tenant_id: row.get(8)?,
                    amount_units: row.get(9)?,
                    currency: row.get(10)?,
                    issuer_key: row.get(11)?,
                    canonical_json: row.get(12)?,
                })
            } else {
                None
            };
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<String>>(4)?,
                iou,
            ))
        })
        .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        let (receipt_id, reconciliation_state, updated_at, timestamp, raw_json, iou) =
            row.map_err(|err| SettleStatusError::Backend(err.to_string()))?;
        if receipt_id.trim().is_empty()
            || receipt_id.len() > 512
            || reconciliation_state != "reconciled"
            || updated_at < 0
        {
            return Err(SettleStatusError::Integrity(
                "settled reconciliation contains invalid projections".to_string(),
            ));
        }
        let timestamp = timestamp.ok_or_else(|| {
            SettleStatusError::Integrity(format!(
                "settled reconciliation {receipt_id} has no authoritative receipt"
            ))
        })?;
        let raw_json = raw_json.ok_or_else(|| {
            SettleStatusError::Integrity(format!(
                "settled reconciliation {receipt_id} has no authoritative receipt bytes"
            ))
        })?;
        let receipt = validate_status_receipt(&raw_json, &receipt_id, Some(timestamp))?;
        if let Some(iou) = iou {
            validate_status_iou(&iou, &receipt, "settled")?;
        }
        out.push(SettledRow {
            receipt_id,
            reconciliation_state,
            updated_at,
        });
    }
    Ok(out)
}

fn list_retrying(conn: &Connection, limit: usize) -> Result<Vec<RetryingRow>, SettleStatusError> {
    require_receipt_table(conn)?;
    preflight_blob_size(
        conn,
        "chio_tool_receipts",
        "raw_json",
        MAX_STATUS_RECEIPT_BYTES,
    )?;
    let limit = i64::try_from(limit).map_err(|_| {
        SettleStatusError::Integrity("settle status limit exceeds SQLite INTEGER".to_string())
    })?;
    let mut statement = conn
        .prepare(
            "SELECT a.receipt_id, a.finalized_at, a.attempts, a.next_visible_at, \
                    a.last_reason, a.state, a.claim_token, a.claim_deadline_unix_secs, \
                    a.version, a.updated_at, r.raw_json \
             FROM settle_attempts AS a \
             LEFT JOIN chio_tool_receipts AS r ON r.receipt_id = a.receipt_id \
             ORDER BY a.finalized_at ASC, a.receipt_id ASC LIMIT ?1",
        )
        .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
    let rows = statement
        .query_map([limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, Option<String>>(10)?,
            ))
        })
        .map_err(|error| SettleStatusError::Backend(error.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        let (
            receipt_id,
            finalized_at,
            attempts,
            next_visible_at,
            last_reason,
            state,
            claim_token,
            claim_deadline_unix_secs,
            version,
            updated_at,
            raw_json,
        ) = row.map_err(|error| SettleStatusError::Backend(error.to_string()))?;
        let claim_shape_valid = match state.as_str() {
            "pending" => claim_token.is_none() && claim_deadline_unix_secs.is_none(),
            "claimed" => {
                claim_token
                    .as_ref()
                    .is_some_and(|token| !token.trim().is_empty() && token.len() <= 512)
                    && claim_deadline_unix_secs.is_some_and(|deadline| deadline >= 0)
            }
            _ => false,
        };
        if receipt_id.trim().is_empty()
            || receipt_id.len() > 512
            || finalized_at < 0
            || attempts <= 0
            || attempts > i64::from(MAX_STATUS_RETRY_ATTEMPTS)
            || next_visible_at < 0
            || version < 0
            || updated_at < 0
            || last_reason
                .as_ref()
                .is_some_and(|reason| reason.trim().is_empty() || reason.len() > 2_048)
            || !claim_shape_valid
        {
            return Err(SettleStatusError::Integrity(format!(
                "settlement retry {receipt_id} has invalid projections"
            )));
        }
        let raw_json = raw_json.ok_or_else(|| {
            SettleStatusError::Integrity(format!(
                "settlement retry {receipt_id} has no authoritative live receipt"
            ))
        })?;
        let _ = validate_status_receipt(&raw_json, &receipt_id, Some(finalized_at))?;
        out.push(RetryingRow {
            receipt_id,
            finalized_at,
            attempts,
            next_visible_at,
            state,
            claim_deadline_unix_secs,
            last_reason,
        });
    }
    Ok(out)
}

fn list_dead_lettered(
    conn: &Connection,
    limit: usize,
) -> Result<Vec<DeadLetteredRow>, SettleStatusError> {
    preflight_blob_size(
        conn,
        "settle_dead_letters",
        "canonical_json",
        MAX_STATUS_CANONICAL_BYTES,
    )?;
    let limit = i64::try_from(limit).map_err(|_| {
        SettleStatusError::Integrity("settle status limit exceeds SQLite INTEGER".to_string())
    })?;
    let mut stmt = conn
        .prepare(
            "SELECT receipt_id, finalized_at, attempts, reason, pipeline_error, canonical_json, recorded_at \
             FROM settle_dead_letters \
             ORDER BY finalized_at ASC, receipt_id ASC LIMIT ?1",
        )
        .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    let rows = stmt
        .query_map([limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        let (
            receipt_id,
            finalized_at,
            attempts,
            reason,
            pipeline_error,
            canonical_json,
            recorded_at,
        ) =
            row.map_err(|err| SettleStatusError::Backend(err.to_string()))?;
        if recorded_at < 0 {
            return Err(SettleStatusError::Integrity(format!(
                "dead-letter {receipt_id} has an invalid recorded_at projection"
            )));
        }
        let record: chio_settle::DeadLetterRecord = serde_json::from_str(&canonical_json)
            .map_err(|error| SettleStatusError::Integrity(format!(
                "dead-letter {receipt_id} is invalid JSON: {error}"
            )))?;
        if chio_core::canonical::canonical_json_bytes(&record)
            .map_err(|error| SettleStatusError::Integrity(error.to_string()))?
            != canonical_json.as_bytes()
        {
            return Err(SettleStatusError::Integrity(format!(
                "dead-letter {receipt_id} is not canonical JSON"
            )));
        }
        if !record.has_supported_schema()
            || record.receipt_id.trim().is_empty()
            || record.attempts == 0
            || record.attempts > MAX_STATUS_RETRY_ATTEMPTS.saturating_add(1)
        {
            return Err(SettleStatusError::Integrity(format!(
                "dead-letter {receipt_id} is invalid"
            )));
        }
        let reason_projection =
            chio_core::canonical::canonical_json_bytes(&record.reason).map_err(|error| {
                SettleStatusError::Integrity(format!(
                    "dead-letter {receipt_id} reason is invalid: {error}"
                ))
            })?;
        let reason_projection = format!(
            "settlement_failure:sha256:{}",
            chio_core::sha256_hex(&reason_projection)
        );
        if record.receipt_id != receipt_id
            || i64::try_from(record.finalized_at).ok() != Some(finalized_at)
            || i64::from(record.attempts) != attempts
            || reason_projection != reason
            || pipeline_error.is_some()
        {
            return Err(SettleStatusError::Integrity(format!(
                "dead-letter {receipt_id} projections do not match canonical bytes"
            )));
        }
        out.push(DeadLetteredRow {
            receipt_id,
            finalized_at,
            attempts,
            reason,
        });
    }
    Ok(out)
}

/// Run `chio settle status`. Wires the report into the CLI dispatch
/// surface; callers control output format via `json`.
pub fn cmd_settle_status(
    store_path: &Path,
    limit: usize,
    json: bool,
) -> Result<i32, SettleStatusError> {
    // Defensive: verify the file is at least readable before opening.
    let _meta =
        fs::metadata(store_path).map_err(|err| SettleStatusError::Backend(err.to_string()))?;
    let report = SettleStatusReport::load_bounded(store_path, limit)?;
    if json {
        println!("{}", report.render_json()?);
    } else {
        print!("{}", report.render_text());
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use chio_core::credit::{CreditEvaluatorHook, IouEnvelopeStore};
    use chio_kernel::settlement_retry::SettlementRetryStore;
    use chio_kernel::ReceiptStore;
    use tempfile::TempDir;

    fn status_receipt(
        keypair: &chio_core::Keypair,
        receipt_id: &str,
        timestamp: u64,
    ) -> chio_core::receipt::body::ChioReceipt {
        let action = chio_core::receipt::decision::ToolCallAction::from_parameters(
            serde_json::json!({"receipt": receipt_id}),
        )
        .expect("hash action");
        chio_core::receipt::body::ChioReceipt::sign(
            chio_core::receipt::body::ChioReceiptBody {
                id: receipt_id.to_string(),
                timestamp,
                capability_id: format!("cap-{receipt_id}"),
                tool_server: "srv".to_string(),
                tool_name: "tool".to_string(),
                action,
                decision: Some(chio_core::receipt::decision::Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: format!("content-{receipt_id}"),
                policy_hash: "policy".to_string(),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({
                    "financial": {"cost_charged": 250, "currency": "USD"}
                })),
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            keypair,
        )
        .expect("sign receipt")
    }

    fn status_envelope(
        issuer: &chio_core::Keypair,
        kernel: &chio_core::Keypair,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> chio_core::credit::IouEnvelope {
        chio_core::credit::LocalCreditAccount::new_with_trusted_kernel_keys(
            chio_core::crypto::Ed25519Backend::new(issuer.clone()),
            [kernel.public_key()],
        )
        .evaluate(receipt)
        .expect("evaluate receipt")
        .expect("priced receipt")
    }

    struct StatusFixture {
        path: PathBuf,
        pending_receipt_id: String,
        settled_receipt_id: String,
    }

    fn write_db(dir: &TempDir) -> StatusFixture {
        let path = dir.path().join("settle.sqlite");
        let kernel = chio_core::Keypair::from_seed(&[71; 32]);
        let issuer = chio_core::Keypair::from_seed(&[72; 32]);
        let receipts = chio_store_sqlite::SqliteReceiptStore::open(&path).expect("open db");
        let pending = status_receipt(&kernel, "rcpt-1", 100);
        let settled = status_receipt(&kernel, "rcpt-2", 200);
        receipts.append_chio_receipt(&pending).expect("append pending");
        receipts.append_chio_receipt(&settled).expect("append settled");
        let ious = chio_store_sqlite::SqliteIouEnvelopeStore::open_alongside(&receipts)
            .expect("open IOU store");
        ious.insert(&status_envelope(&issuer, &kernel, &pending))
            .expect("insert pending IOU");
        ious.insert(&status_envelope(&issuer, &kernel, &settled))
            .expect("insert settled IOU");
        receipts
            .complete_settlement_reconciliation_exact(&settled.id, Some("transcript=test"))
            .expect("settle receipt");
        let retries = chio_store_sqlite::SqliteSettlementRetryStore::open_alongside(&receipts)
            .expect("open retry store");
        retries
            .insert_dead_letter(&chio_settle::DeadLetterRecord::new(
                "rcpt-3", 300, 5, "rpc lag",
            ))
            .expect("insert dead letter");
        StatusFixture {
            path,
            pending_receipt_id: pending.id,
            settled_receipt_id: settled.id,
        }
    }

    fn tamper_iou_amount(path: &Path, receipt_id: &str) -> usize {
        let connection = Connection::open(path).expect("open tamper connection");
        let immutable_trigger_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master \
                 WHERE type = 'trigger' AND name = 'iou_envelope_reject_update'",
                [],
                |row| row.get(0),
            )
            .expect("load IOU immutable-row guard");
        connection
            .execute_batch("DROP TRIGGER iou_envelope_reject_update;")
            .expect("disable IOU immutable-row test guard");
        let changed = connection
            .execute(
                "UPDATE iou_envelope SET amount_units = amount_units + 1 WHERE receipt_id = ?1",
                [receipt_id],
            )
            .expect("tamper IOU projection");
        connection
            .execute_batch(&immutable_trigger_sql)
            .expect("restore IOU immutable-row test guard");
        changed
    }

    #[test]
    fn load_classifies_pending_settled_dead_lettered() {
        let dir = TempDir::new().expect("tempdir");
        let fixture = write_db(&dir);
        let report = SettleStatusReport::load(&fixture.path).expect("load ok");
        assert_eq!(report.pending.len(), 1);
        assert_eq!(report.pending[0].receipt_id, fixture.pending_receipt_id);
        assert_eq!(report.settled.len(), 1);
        assert_eq!(report.settled[0].receipt_id, fixture.settled_receipt_id);
        assert_eq!(report.dead_lettered.len(), 1);
        assert_eq!(report.dead_lettered[0].receipt_id, "rcpt-3");
        assert_eq!(report.schema, SETTLE_STATUS_REPORT_SCHEMA);
    }

    #[test]
    fn render_text_summary_lists_counts_and_rows() {
        let dir = TempDir::new().expect("tempdir");
        let fixture = write_db(&dir);
        let report = SettleStatusReport::load(&fixture.path).expect("load ok");
        let text = report.render_text();
        assert!(text.contains("pending=1"));
        assert!(text.contains("settled=1"));
        assert!(text.contains("dead_lettered=1"));
        assert!(text.contains(&fixture.pending_receipt_id));
        assert!(text.contains("rcpt-3"));
    }

    #[test]
    fn render_json_carries_schema_tag() {
        let dir = TempDir::new().expect("tempdir");
        let fixture = write_db(&dir);
        let report = SettleStatusReport::load(&fixture.path).expect("load ok");
        let json = report.render_json().expect("render json");
        assert!(json.contains("\"schema\": \"chio.settle.status-report.v2\""));
        assert!(json.contains("\"retrying\""));
        assert!(json.contains("\"pending\""));
        assert!(json.contains("\"settled\""));
        assert!(json.contains("\"dead_lettered\""));
    }

    #[test]
    fn bounded_status_reports_explicit_truncation_and_retry_rows() {
        let dir = TempDir::new().expect("tempdir");
        let fixture = write_db(&dir);
        let receipts = chio_store_sqlite::SqliteReceiptStore::open_existing(&fixture.path)
            .expect("open receipts");
        let retries = chio_store_sqlite::SqliteSettlementRetryStore::open_alongside(&receipts)
            .expect("open retries");
        retries
            .insert_dead_letter(&chio_settle::DeadLetterRecord::new(
                "rcpt-4", 400, 3, "terminal",
            ))
            .expect("insert second dead letter");
        let pending_receipt = status_receipt(
            &chio_core::Keypair::from_seed(&[71; 32]),
            "rcpt-retry",
            500,
        );
        receipts
            .append_chio_receipt(&pending_receipt)
            .expect("append retry receipt");
        retries
            .upsert_attempt(&chio_kernel::settlement_retry::SettleAttemptRecord {
                receipt_id: pending_receipt.id.clone(),
                finalized_at: pending_receipt.timestamp,
                attempts: 1,
                next_visible_at: 600,
                last_reason: Some("retryable".to_string()),
            })
            .expect("insert retry");
        drop(retries);
        drop(receipts);

        let report =
            SettleStatusReport::load_bounded(&fixture.path, 1).expect("load bounded status");
        assert_eq!(report.retrying.len(), 1);
        assert_eq!(report.counts.retrying.total, 1);
        assert_eq!(report.counts.dead_lettered.total, 2);
        assert_eq!(report.counts.dead_lettered.returned, 1);
        assert!(report.counts.dead_lettered.truncated);
        assert!(report.truncated);
    }

    #[test]
    fn status_rejects_tampered_iou_projection() {
        let dir = TempDir::new().expect("tempdir");
        let fixture = write_db(&dir);
        let changed = tamper_iou_amount(&fixture.path, &fixture.pending_receipt_id);
        assert_eq!(changed, 1, "pending IOU fixture must be tampered");
        assert!(matches!(
            SettleStatusReport::load(&fixture.path),
            Err(SettleStatusError::Integrity(_))
        ));
    }

    #[test]
    fn status_rejects_tampered_settled_iou_projection() {
        let dir = TempDir::new().expect("tempdir");
        let fixture = write_db(&dir);
        let changed = tamper_iou_amount(&fixture.path, &fixture.settled_receipt_id);
        assert_eq!(changed, 1, "settled IOU fixture must be tampered");
        assert!(matches!(
            SettleStatusReport::load(&fixture.path),
            Err(SettleStatusError::Integrity(_))
        ));
    }

    #[test]
    fn status_allows_manual_reconciliation_without_iou() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("manual-reconciliation.sqlite");
        let kernel = chio_core::Keypair::from_seed(&[74; 32]);
        let receipts = chio_store_sqlite::SqliteReceiptStore::open(&path).expect("open db");
        let receipt = status_receipt(&kernel, "rcpt-manual", 300);
        receipts
            .append_chio_receipt(&receipt)
            .expect("append receipt");
        receipts
            .complete_settlement_reconciliation_exact(
                &receipt.id,
                Some("transcript=manual"),
            )
            .expect("reconcile without IOU");
        drop(receipts);

        let report = SettleStatusReport::load(&path).expect("load manual reconciliation");
        assert_eq!(report.settled.len(), 1);
        assert_eq!(report.settled[0].receipt_id, receipt.id);
    }

    #[test]
    fn status_rejects_raw_legacy_retry_above_bounded_envelope_without_mutation() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("legacy-retry.sqlite");
        let kernel = chio_core::Keypair::from_seed(&[75; 32]);
        let receipts = chio_store_sqlite::SqliteReceiptStore::open(&path).expect("open db");
        let receipt = status_receipt(&kernel, "rcpt-legacy-retry", 400);
        receipts
            .append_chio_receipt(&receipt)
            .expect("append receipt");
        drop(receipts);

        let connection = Connection::open(&path).expect("open raw legacy writer");
        connection
            .execute_batch(
                "DROP TABLE IF EXISTS settle_attempts; \
                 CREATE TABLE settle_attempts ( \
                     receipt_id TEXT PRIMARY KEY NOT NULL, \
                     finalized_at INTEGER NOT NULL, \
                     attempts INTEGER NOT NULL, \
                     next_visible_at INTEGER NOT NULL, \
                     last_reason TEXT, \
                     updated_at INTEGER NOT NULL, \
                     state TEXT NOT NULL, \
                     claim_token TEXT, \
                     claim_deadline_unix_secs INTEGER, \
                     version INTEGER NOT NULL \
                 );",
            )
            .expect("install permissive legacy retry table");
        connection
            .execute(
                "INSERT INTO settle_attempts ( \
                     receipt_id, finalized_at, attempts, next_visible_at, last_reason, \
                     updated_at, state, claim_token, claim_deadline_unix_secs, version \
                 ) VALUES (?1, ?2, 33, 0, 'legacy retry', 0, 'pending', NULL, NULL, 0)",
                rusqlite::params![
                    receipt.id,
                    i64::try_from(receipt.timestamp).expect("timestamp fits SQLite")
                ],
            )
            .expect("insert out-of-envelope legacy retry");
        drop(connection);

        assert!(matches!(
            SettleStatusReport::load(&path),
            Err(SettleStatusError::Integrity(_))
        ));
        let attempts = Connection::open(&path)
            .expect("reopen raw legacy database")
            .query_row(
                "SELECT attempts FROM settle_attempts WHERE receipt_id = ?1",
                [&receipt.id],
                |row| row.get::<_, i64>(0),
            )
            .expect("read unchanged legacy retry");
        assert_eq!(attempts, 33);
    }

    #[test]
    fn missing_db_returns_not_found() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("absent.sqlite");
        match SettleStatusReport::load(&path) {
            Err(SettleStatusError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn missing_tables_return_empty_vectors() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("empty.sqlite");
        let conn = Connection::open(&path).expect("open empty");
        // No tables created at all.
        drop(conn);
        let report = SettleStatusReport::load(&path).expect("load ok");
        assert!(report.pending.is_empty());
        assert!(report.settled.is_empty());
        assert!(report.dead_lettered.is_empty());
    }

    #[test]
    fn settled_orders_by_receipt_finalized_at_when_receipts_table_present() {
        // When `chio_tool_receipts` is present, list_settled must
        // order by the receipt's finalized timestamp (`r.timestamp`),
        // not by `settlement_reconciliations.updated_at`. This test
        // creates two settled rows whose `updated_at` ordering is the
        // OPPOSITE of their receipt-finalized ordering, then confirms
        // the report follows the receipts ordering.
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("ordered.sqlite");
        let kernel = chio_core::Keypair::from_seed(&[73; 32]);
        let receipts = chio_store_sqlite::SqliteReceiptStore::open(&path).expect("open db");
        let first = status_receipt(&kernel, "rcpt-A", 100);
        let second = status_receipt(&kernel, "rcpt-B", 200);
        receipts.append_chio_receipt(&first).expect("append first");
        receipts.append_chio_receipt(&second).expect("append second");
        receipts
            .complete_settlement_reconciliation_exact(&second.id, Some("transcript=second"))
            .expect("settle second");
        receipts
            .complete_settlement_reconciliation_exact(&first.id, Some("transcript=first"))
            .expect("settle first");
        drop(receipts);

        let connection = Connection::open(&path).expect("open ordering fixture writer");
        assert_eq!(
            connection
                .execute(
                    "UPDATE settlement_reconciliations SET updated_at = ?1 WHERE receipt_id = ?2",
                    rusqlite::params![2_000_i64, first.id.as_str()],
                )
                .expect("set later update time on earlier receipt"),
            1
        );
        assert_eq!(
            connection
                .execute(
                    "UPDATE settlement_reconciliations SET updated_at = ?1 WHERE receipt_id = ?2",
                    rusqlite::params![1_000_i64, second.id.as_str()],
                )
                .expect("set earlier update time on later receipt"),
            1
        );
        let first_updated_at: i64 = connection
            .query_row(
                "SELECT updated_at FROM settlement_reconciliations WHERE receipt_id = ?1",
                [first.id.as_str()],
                |row| row.get(0),
            )
            .expect("load earlier receipt update time");
        let second_updated_at: i64 = connection
            .query_row(
                "SELECT updated_at FROM settlement_reconciliations WHERE receipt_id = ?1",
                [second.id.as_str()],
                |row| row.get(0),
            )
            .expect("load later receipt update time");
        assert!(
            first_updated_at > second_updated_at,
            "fixture must invert receipt and reconciliation ordering"
        );
        drop(connection);

        let report = SettleStatusReport::load(&path).expect("load ok");
        assert_eq!(report.settled.len(), 2);
        assert_eq!(report.settled[0].receipt_id, first.id);
        assert_eq!(report.settled[1].receipt_id, second.id);
    }
}

/// Schema string emitted on the wire for drive reports.
pub const SETTLE_DRIVE_REPORT_SCHEMA: &str = "chio.settle.drive-report.v1";

/// Summary of one settlement drive pass over due `settle_attempts` rows.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettleDriveReport {
    /// Attempts that settled: an exact IOU and reconciliation were persisted,
    /// then the claimed attempt was completed.
    pub settled: u64,
    /// Attempts re-armed with a later visibility.
    pub retried: u64,
    /// Attempts that landed a dead-letter row.
    pub dead_lettered: u64,
    /// Attempts cleared without a settled record (skipped outcomes and
    /// receipts outside the marketplace surface).
    pub skipped: u64,
}

/// Drive due settlement attempts through the reference hook: for each due
/// `settle_attempts` row, claim the strict head of line, load and verify the
/// finalized receipt through the authoritative store, mint its deterministic
/// IOU, and apply the driver step. An accepted step persists the IOU before
/// completing the typed reconciliation, then completes the fenced claim.
/// Recoverable failures re-arm and end the pass so later attempts cannot
/// leapfrog the unresolved head of line. Terminal failures dead-letter.
/// Bounded by `batch`.
#[cfg(test)]
pub fn run_settlement_drive(
    store_path: &Path,
    batch: usize,
    iou_issuer: &chio_core::Keypair,
    trusted_kernel_keys: &[chio_core::PublicKey],
) -> Result<SettleDriveReport, SettleStatusError> {
    let trusted_iou_issuers = [iou_issuer.public_key()];
    run_settlement_drive_with_iou_trust(
        store_path,
        batch,
        iou_issuer,
        &trusted_iou_issuers,
        trusted_kernel_keys,
    )
}

pub fn run_settlement_drive_with_iou_trust(
    store_path: &Path,
    batch: usize,
    iou_issuer: &chio_core::Keypair,
    trusted_iou_issuer_keys: &[chio_core::PublicKey],
    trusted_kernel_keys: &[chio_core::PublicKey],
) -> Result<SettleDriveReport, SettleStatusError> {
    use chio_core::credit::CreditEvaluatorHook;
    use chio_kernel::settlement_retry::{SettleAttemptRecord, SettlementRetryStore};
    use chio_kernel::ReceiptStore;

    const MAX_DRIVE_BATCH: usize = 4_096;
    const MAX_TRUST_ROOTS: usize = 256;
    if batch == 0 || batch > MAX_DRIVE_BATCH {
        return Err(SettleStatusError::Integrity(format!(
            "settlement drive batch must be in 1..={MAX_DRIVE_BATCH}"
        )));
    }
    if trusted_kernel_keys.is_empty() {
        return Err(SettleStatusError::Integrity(
            "at least one trusted kernel public key is required".to_string(),
        ));
    }
    if trusted_iou_issuer_keys.is_empty() {
        return Err(SettleStatusError::Integrity(
            "at least one trusted IOU issuer public key is required".to_string(),
        ));
    }
    if trusted_kernel_keys.len() > MAX_TRUST_ROOTS
        || trusted_iou_issuer_keys.len() > MAX_TRUST_ROOTS
    {
        return Err(SettleStatusError::Integrity(format!(
            "settlement trust domains are limited to {MAX_TRUST_ROOTS} keys each"
        )));
    }
    let distinct_trust_roots = trusted_kernel_keys
        .iter()
        .map(|key| key.to_hex())
        .collect::<std::collections::BTreeSet<_>>();
    if distinct_trust_roots.len() != trusted_kernel_keys.len() {
        return Err(SettleStatusError::Integrity(
            "duplicate trusted kernel public keys are not allowed".to_string(),
        ));
    }
    let distinct_iou_issuers = trusted_iou_issuer_keys
        .iter()
        .map(|key| key.to_hex())
        .collect::<std::collections::BTreeSet<_>>();
    if distinct_iou_issuers.len() != trusted_iou_issuer_keys.len() {
        return Err(SettleStatusError::Integrity(
            "duplicate trusted IOU issuer public keys are not allowed".to_string(),
        ));
    }
    if !trusted_iou_issuer_keys.contains(&iou_issuer.public_key()) {
        return Err(SettleStatusError::Integrity(
            "current IOU issuer is absent from the IOU issuer trust set".to_string(),
        ));
    }
    if trusted_iou_issuer_keys
        .iter()
        .any(|issuer| trusted_kernel_keys.contains(issuer))
    {
        return Err(SettleStatusError::Integrity(
            "IOU issuer and kernel receipt signer trust domains must be disjoint".to_string(),
        ));
    }

    let receipts = chio_store_sqlite::SqliteReceiptStore::open_existing(store_path)
        .map_err(map_receipt_store_error)?;
    let retry_store = chio_store_sqlite::SqliteSettlementRetryStore::open_alongside(&receipts)
        .map_err(map_settlement_retry_error)?;
    let credit_account = chio_core::credit::LocalCreditAccount::new_with_trusted_kernel_keys(
        chio_core::crypto::Ed25519Backend::new(iou_issuer.clone()),
        trusted_kernel_keys.iter().cloned(),
    );
    let runtime = chio_settle::SettlementRuntime::new(
        chio_settle::OpsSettlementHook::new(),
        chio_settle::RetryPolicy::default(),
    );

    let mut report = SettleDriveReport::default();
    for _ in 0..batch {
        let now_unix_secs = settlement_now_unix_secs()?;
        let claim_deadline_unix_secs = now_unix_secs
            .checked_add(SETTLEMENT_DRIVE_CLAIM_TTL_SECS)
            .ok_or_else(|| {
                SettleStatusError::Integrity(
                    "settlement claim deadline overflowed unix seconds".to_string(),
                )
            })?;
        let claim_token = uuid::Uuid::new_v4().simple().to_string();
        let claimed = retry_store
            .claim_due_attempts(
                now_unix_secs,
                claim_deadline_unix_secs,
                &claim_token,
                1,
            )
            .map_err(map_settlement_retry_error)?;
        if claimed.len() > 1 {
            return Err(SettleStatusError::Integrity(
                "settlement retry store returned more than one strict-order claim".to_string(),
            ));
        }
        let Some(lease) = claimed.into_iter().next() else {
            break;
        };
        let attempt = &lease.record;

        let receipt = receipts
            .load_chio_receipt(&attempt.receipt_id)
            .map_err(map_receipt_store_error)?;
        let Some(receipt) = receipt else {
            // A genuinely absent authoritative receipt cannot ever settle.
            dead_letter_attempt(
                &retry_store,
                &lease,
                chio_settle::SettlementFailureReason::from_detail(
                    chio_settle::SettlementFailureCode::InvalidObservation,
                    "finalized receipt absent from authoritative storage",
                ),
            )?;
            report.dead_lettered += 1;
            continue;
        };

        // The authoritative lookup is archive-aware, but settlement evidence
        // is owned by the live receipt row. Retention treats the claimed retry
        // as a barrier, so this preflight remains stable for the rest of the
        // attempt. Legacy archive-only attempts remain recoverable and mint no
        // IOU or terminal evidence.
        if !receipts
            .contains_live_chio_receipt(&attempt.receipt_id)
            .map_err(map_receipt_store_error)?
        {
            return Err(SettleStatusError::Integrity(format!(
                "authoritative receipt {} is archive-only; settlement attempt remains claimed for recovery",
                attempt.receipt_id
            )));
        }

        validate_authoritative_receipt(&receipt, attempt)?;
        if !trusted_kernel_keys
            .iter()
            .any(|trusted| trusted == &receipt.kernel_key)
        {
            dead_letter_attempt(
                &retry_store,
                &lease,
                chio_settle::SettlementFailureReason::from_detail(
                    chio_settle::SettlementFailureCode::UntrustedReceiptSigner,
                    "receipt signer is outside the configured kernel trust set",
                ),
            )?;
            report.dead_lettered += 1;
            continue;
        }

        let envelope = credit_account.evaluate(&receipt).map_err(|error| {
            SettleStatusError::Integrity(format!(
                "receipt {} failed deterministic IOU evaluation: {error}",
                receipt.id
            ))
        })?;
        let Some(envelope) = envelope else {
            complete_claimed_attempt(&retry_store, &lease, "skipping a receipt with no IOU")?;
            report.skipped += 1;
            continue;
        };

        let observation = chio_kernel::settlement_observer::build_observation(
            &receipt,
            trusted_kernel_keys,
        );
        let observation = match observation {
            chio_kernel::settlement_observer::SettlementObservationBuild::Observation(
                observation,
            ) => observation,
            chio_kernel::settlement_observer::SettlementObservationBuild::Skipped(reason) => {
                return Err(SettleStatusError::Integrity(format!(
                    "receipt {} minted an IOU but settlement skipped it as {reason:?}",
                    receipt.id
                )));
            }
            chio_kernel::settlement_observer::SettlementObservationBuild::Permanent(reason) => {
                return Err(SettleStatusError::Integrity(format!(
                    "receipt {} minted an IOU but settlement rejected it as {}",
                    receipt.id,
                    reason.code().as_str()
                )));
            }
        };
        match runtime.drive(&observation, attempt.attempts) {
            chio_settle::SettlementDriveStep::Settle { transcript_id } => {
                let note = format!("transcript={transcript_id}");
                let committed = retry_store
                    .commit_claimed_settlement_exact(
                        &lease,
                        &envelope,
                        trusted_iou_issuer_keys,
                        trusted_kernel_keys,
                        Some(&note),
                    )
                    .map_err(map_settlement_retry_error)?;
                if !committed {
                    return Err(SettleStatusError::Integrity(format!(
                        "settlement claim for {} was lost before evidence commit",
                        receipt.id
                    )));
                }
                report.settled += 1;
            }
            chio_settle::SettlementDriveStep::Retry {
                attempts,
                backoff,
                reason,
            } => {
                let next = SettleAttemptRecord {
                    receipt_id: attempt.receipt_id.clone(),
                    finalized_at: attempt.finalized_at,
                    attempts,
                    next_visible_at: now_unix_secs
                        .saturating_add(backoff.as_secs().max(1)),
                    last_reason: Some(reason.code().as_str().to_string()),
                };
                let rescheduled = retry_store
                    .reschedule_claimed_attempt(&lease, &next)
                    .map_err(map_settlement_retry_error)?;
                if !rescheduled {
                    return Err(lost_lease_error(
                        &attempt.receipt_id,
                        "rescheduling a recoverable settlement",
                    ));
                }
                report.retried += 1;
                break;
            }
            chio_settle::SettlementDriveStep::DeadLetter { reason } => {
                dead_letter_attempt(&retry_store, &lease, reason)?;
                report.dead_lettered += 1;
            }
            chio_settle::SettlementDriveStep::Skip { .. } => {
                complete_claimed_attempt(&retry_store, &lease, "skipping a settlement outcome")?;
                report.skipped += 1;
            }
        }
    }
    Ok(report)
}

const SETTLEMENT_DRIVE_CLAIM_TTL_SECS: u64 = 60;

fn settlement_now_unix_secs() -> Result<u64, SettleStatusError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|error| {
            SettleStatusError::Integrity(format!(
                "system clock is before the unix epoch: {error}"
            ))
        })
}

fn map_receipt_store_error(error: chio_kernel::ReceiptStoreError) -> SettleStatusError {
    let message = error.to_string();
    match error {
        chio_kernel::ReceiptStoreError::Sqlite(_)
        | chio_kernel::ReceiptStoreError::Pool(_)
        | chio_kernel::ReceiptStoreError::Timeout { .. }
        | chio_kernel::ReceiptStoreError::Io(_)
        | chio_kernel::ReceiptStoreError::WriterDead { .. } => {
            SettleStatusError::Backend(message)
        }
        _ => SettleStatusError::Integrity(message),
    }
}

fn map_settlement_retry_error(
    error: chio_kernel::settlement_retry::SettlementRetryError,
) -> SettleStatusError {
    match error {
        chio_kernel::settlement_retry::SettlementRetryError::Backend(message) => {
            SettleStatusError::Backend(message)
        }
        chio_kernel::settlement_retry::SettlementRetryError::Conflict(message) => {
            SettleStatusError::Integrity(message)
        }
    }
}

fn validate_authoritative_receipt(
    receipt: &chio_core::receipt::body::ChioReceipt,
    attempt: &chio_kernel::settlement_retry::SettleAttemptRecord,
) -> Result<(), SettleStatusError> {
    if receipt.id != attempt.receipt_id {
        return Err(SettleStatusError::Integrity(format!(
            "authoritative receipt lookup for {} returned mismatched id {}",
            attempt.receipt_id, receipt.id
        )));
    }
    if receipt.timestamp != attempt.finalized_at {
        return Err(SettleStatusError::Integrity(format!(
            "receipt {} finalized timestamp {} does not match settlement attempt {}",
            receipt.id, receipt.timestamp, attempt.finalized_at
        )));
    }
    let expected_id = chio_core::receipt::body::chio_receipt_id(&receipt.body()).map_err(|error| {
        SettleStatusError::Integrity(format!(
            "receipt {} content-derived id could not be computed: {error}",
            receipt.id
        ))
    })?;
    if expected_id != receipt.id {
        return Err(SettleStatusError::Integrity(format!(
            "receipt {} does not match its content-derived id {}",
            receipt.id, expected_id
        )));
    }
    let signature_valid = receipt.verify_signature().map_err(|error| {
        SettleStatusError::Integrity(format!(
            "receipt {} signature verification failed: {error}",
            receipt.id
        ))
    })?;
    if !signature_valid {
        return Err(SettleStatusError::Integrity(format!(
            "receipt {} has an invalid kernel signature",
            receipt.id
        )));
    }
    let action_valid = receipt.action.verify_hash().map_err(|error| {
        SettleStatusError::Integrity(format!(
            "receipt {} action hash verification failed: {error}",
            receipt.id
        ))
    })?;
    if !action_valid {
        return Err(SettleStatusError::Integrity(format!(
            "receipt {} has an invalid action hash",
            receipt.id
        )));
    }
    Ok(())
}

fn complete_claimed_attempt(
    retry_store: &chio_store_sqlite::SqliteSettlementRetryStore,
    lease: &chio_kernel::settlement_retry::SettleAttemptLease,
    operation: &str,
) -> Result<(), SettleStatusError> {
    use chio_kernel::settlement_retry::SettlementRetryStore;

    let completed = retry_store
        .complete_claimed_attempt(lease)
        .map_err(map_settlement_retry_error)?;
    if !completed {
        return Err(lost_lease_error(&lease.record.receipt_id, operation));
    }
    Ok(())
}

fn lost_lease_error(receipt_id: &str, operation: &str) -> SettleStatusError {
    SettleStatusError::Integrity(format!(
        "settlement attempt {receipt_id} lost its fenced lease while {operation}"
    ))
}

fn dead_letter_attempt(
    retry_store: &chio_store_sqlite::SqliteSettlementRetryStore,
    lease: &chio_kernel::settlement_retry::SettleAttemptLease,
    reason: chio_settle::SettlementFailureReason,
) -> Result<(), SettleStatusError> {
    use chio_kernel::settlement_retry::SettlementRetryStore;
    let attempt = &lease.record;
    let attempts = attempt.attempts.checked_add(1).ok_or_else(|| {
        SettleStatusError::Integrity(format!(
            "settlement attempt {} exhausted the u32 attempt counter",
            attempt.receipt_id
        ))
    })?;
    let record = chio_settle::DeadLetterRecord::new(
        attempt.receipt_id.clone(),
        attempt.finalized_at,
        attempts,
        reason,
    );
    let completed = retry_store
        .dead_letter_claimed_attempt(lease, &record)
        .map_err(map_settlement_retry_error)?;
    if !completed {
        return Err(lost_lease_error(
            &attempt.receipt_id,
            "persisting a terminal dead letter",
        ));
    }
    Ok(())
}

/// `chio settle drive` entry point: run one drive pass and report.
pub fn cmd_settle_drive(
    store_path: &Path,
    batch: usize,
    json: bool,
    iou_issuer: &chio_core::Keypair,
    trusted_iou_issuer_keys: &[chio_core::PublicKey],
    trusted_kernel_keys: &[chio_core::PublicKey],
) -> Result<i32, SettleStatusError> {
    let report = run_settlement_drive_with_iou_trust(
        store_path,
        batch,
        iou_issuer,
        trusted_iou_issuer_keys,
        trusted_kernel_keys,
    )?;
    if json {
        let value = serde_json::json!({
            "schema": SETTLE_DRIVE_REPORT_SCHEMA,
            "settled": report.settled,
            "retried": report.retried,
            "deadLettered": report.dead_lettered,
            "skipped": report.skipped,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value)
                .map_err(|error| SettleStatusError::Backend(error.to_string()))?
        );
    } else {
        println!(
            "settled {}  retried {}  dead-lettered {}  skipped {}",
            report.settled, report.retried, report.dead_lettered, report.skipped
        );
    }
    Ok(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod drive_tests {
    include!("settle/drive_tests.inc");
}
