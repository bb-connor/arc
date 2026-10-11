//! Work limits for selected-row diagnostics, not authenticated history selection.
use super::*;
use rusqlite::types::ValueRef;

#[path = "read_boundary/lineage.rs"]
mod lineage;
#[path = "read_boundary/projection.rs"]
mod projection;
#[path = "read_boundary/text.rs"]
mod text;
#[path = "analytics/work_budget.rs"]
mod work_budget;

pub(crate) use text::decoded_json_text_bytes;
pub(crate) use work_budget::SqlWorkBudget;

#[derive(Clone, Copy)]
pub(super) struct ReportReadLimits {
    pub rows: u64,
    pub row_bytes: u64,
    pub raw_bytes: u64,
    pub decoded_bytes: u64,
    pub groups: u64,
    pub lineage_lookups: u64,
    pub sql_steps: u64,
}

impl Default for ReportReadLimits {
    fn default() -> Self {
        Self {
            rows: 250_000,
            row_bytes: 8 * 1024 * 1024,
            raw_bytes: 64 * 1024 * 1024,
            decoded_bytes: 32 * 1024 * 1024,
            groups: 10_000,
            lineage_lookups: 250_000,
            sql_steps: 100_000_000,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum ReportReadExhaustion {
    #[error("selected receipt row limit")]
    Rows,
    #[error("raw record byte limit")]
    RowBytes,
    #[error("aggregate raw source byte limit")]
    RawBytes,
    #[error("aggregate decoded JSON text byte limit")]
    DecodedBytes,
    #[error("distinct group limit")]
    Groups,
    #[error("lineage lookup limit")]
    Lineage,
}

pub(super) struct ReportReadBudget {
    pub limits: ReportReadLimits,
    surface: &'static str,
    rows: u64,
    raw_bytes: u64,
    decoded_bytes: u64,
    lineage_lookups: u64,
}

impl ReportReadBudget {
    fn new(surface: &'static str, limits: ReportReadLimits) -> Self {
        Self {
            limits,
            surface,
            rows: 0,
            raw_bytes: 0,
            decoded_bytes: 0,
            lineage_lookups: 0,
        }
    }

    fn refusal(&self, reason: ReportReadExhaustion) -> ReceiptStoreError {
        ReceiptStoreError::ReadBoundary(format!("{} exhausted its {reason}", self.surface))
    }

    fn add(current: &mut u64, amount: u64, limit: u64) -> bool {
        match current.checked_add(amount) {
            Some(next) if next <= limit => {
                *current = next;
                true
            }
            _ => false,
        }
    }

    pub fn receipt_row(&mut self) -> Result<(), ReceiptStoreError> {
        if !Self::add(&mut self.rows, 1, self.limits.rows) {
            return Err(self.refusal(ReportReadExhaustion::Rows));
        }
        Ok(())
    }

    pub fn source_bytes(&mut self, bytes: u64) -> Result<(), ReceiptStoreError> {
        if bytes > self.limits.row_bytes {
            return Err(self.refusal(ReportReadExhaustion::RowBytes));
        }
        if !Self::add(&mut self.raw_bytes, bytes, self.limits.raw_bytes) {
            return Err(self.refusal(ReportReadExhaustion::RawBytes));
        }
        Ok(())
    }

    pub fn decoded_text(&mut self, raw: &str) -> Result<(), ReceiptStoreError> {
        let bytes = decoded_json_text_bytes(raw)?;
        if !Self::add(&mut self.decoded_bytes, bytes, self.limits.decoded_bytes) {
            return Err(self.refusal(ReportReadExhaustion::DecodedBytes));
        }
        Ok(())
    }

    pub fn groups(&self, groups: usize) -> Result<(), ReceiptStoreError> {
        if crate::integer::count(groups) > self.limits.groups {
            return Err(self.refusal(ReportReadExhaustion::Groups));
        }
        Ok(())
    }

    fn lineage_lookup(&mut self) -> Result<(), ReceiptStoreError> {
        if !Self::add(&mut self.lineage_lookups, 1, self.limits.lineage_lookups) {
            return Err(self.refusal(ReportReadExhaustion::Lineage));
        }
        Ok(())
    }

    pub fn receipt(
        &mut self,
        connection: &Connection,
        row: &rusqlite::Row<'_>,
    ) -> Result<(u64, ChioReceipt), ReceiptStoreError> {
        self.receipt_row()?;
        let seq = sqlite_positive_u64(row.get(0)?, "report receipt sequence")?;
        if sqlite_u64(row.get(1)?, "report encoded receipt bytes")? > self.metadata_byte_limit()? {
            return Err(self.refusal(ReportReadExhaustion::RowBytes));
        }
        // SQLite may store TEXT as UTF-16. Measure the actual borrowed UTF-8
        // representation of the whole tuple before JSON or owned text copies.
        let mut actual = 0_u64;
        for column in [2, 3, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17] {
            let size = match row.get_ref(column)? {
                ValueRef::Text(bytes) | ValueRef::Blob(bytes) => crate::integer::count(bytes.len()),
                ValueRef::Null => 0,
                _ => {
                    return Err(ReceiptStoreError::Conflict(
                        "report source tuple has invalid storage types".into(),
                    ))
                }
            };
            actual = actual
                .checked_add(size)
                .filter(|size| *size <= self.limits.row_bytes)
                .ok_or_else(|| self.refusal(ReportReadExhaustion::RowBytes))?;
        }
        self.source_bytes(actual)?;
        let raw = match row.get_ref(2)? {
            ValueRef::Text(bytes) => std::str::from_utf8(bytes).map_err(|_| {
                ReceiptStoreError::Conflict("report receipt text is not UTF-8".into())
            })?,
            _ => {
                return Err(ReceiptStoreError::Conflict(
                    "report receipt payload is not text".into(),
                ))
            }
        };
        self.decoded_text(raw)?;
        let receipt = decode_verified_chio_receipt(raw, self.surface, Some(seq))?;
        projection::verify(connection, row, &receipt, self)?;
        Ok((seq, receipt))
    }

    pub fn metadata_byte_limit(&self) -> Result<u64, ReceiptStoreError> {
        self.limits
            .row_bytes
            .checked_mul(2)
            .ok_or_else(|| self.refusal(ReportReadExhaustion::RowBytes))
    }

    pub fn delegation_chain(
        &mut self,
        connection: &Connection,
        capability_id: &str,
    ) -> Result<Vec<CapabilitySnapshot>, ReceiptStoreError> {
        lineage::chain(connection, capability_id, self)
    }
}

/// Metadata CASE bounds encoded payload loading. The read owner then checks
/// actual borrowed UTF-8 before constructing owned text/JSON, including UTF-16.
/// Column order is consumed by `ReportReadBudget::receipt` and `projection`.
pub(super) fn receipt_columns(row_byte_bound: usize) -> String {
    let text_columns = [
        "raw_json",
        "receipt_id",
        "capability_id",
        "tool_server",
        "tool_name",
        "decision_kind",
        "tenant_id",
        "subject_key",
        "issuer_key",
        "policy_hash",
        "content_hash",
        "cost_currency",
        "cost_charged_be",
        "attempted_cost_be",
    ];
    // Direct octet_length(column) uses SQLite's metadata-only column opcode.
    // A CAST argument would force loading the complete value before its bound.
    let bytes = text_columns
        .iter()
        .map(|column| format!("COALESCE(octet_length(r.{column}), 0)"))
        .collect::<Vec<_>>()
        .join(" + ");
    let bounded =
        |column: &str| format!("CASE WHEN ({bytes}) <= ?{row_byte_bound} THEN r.{column} END");
    format!("r.seq, {bytes}, {}, {}, r.timestamp, {}, {}, {}, {}, {}, {}, {}, r.grant_index, {}, {}, {}, {}, {}",
        bounded("raw_json"), bounded("receipt_id"), bounded("capability_id"), bounded("tool_server"), bounded("tool_name"),
        bounded("decision_kind"), bounded("tenant_id"), bounded("subject_key"), bounded("issuer_key"),
        bounded("policy_hash"), bounded("content_hash"), bounded("cost_currency"), bounded("cost_charged_be"), bounded("attempted_cost_be"))
}

/// Progress is cleared before the read transaction rolls back or its connection
/// is returned to the pool. The first read pins receipt and lineage visibility.
pub(super) struct ReportSnapshot<'connection> {
    progress: SqlWorkBudget<'connection>,
    transaction: rusqlite::Transaction<'connection>,
    accounting: ReportReadBudget,
}

impl<'connection> ReportSnapshot<'connection> {
    pub fn new(
        connection: &'connection Connection,
        surface: &'static str,
        limits: ReportReadLimits,
    ) -> Result<Self, ReceiptStoreError> {
        let transaction = rusqlite::Transaction::new_unchecked(
            connection,
            rusqlite::TransactionBehavior::Deferred,
        )?;
        let progress = SqlWorkBudget::new_for(connection, limits.sql_steps, surface)?;
        transaction.query_row(
            "SELECT COUNT(*) FROM (SELECT 1 FROM chio_tool_receipts LIMIT 1)",
            [],
            |_row| Ok(()),
        )?;
        Ok(Self {
            progress,
            transaction,
            accounting: ReportReadBudget::new(surface, limits),
        })
    }

    pub fn split(&mut self) -> (&Connection, &mut ReportReadBudget) {
        (&self.transaction, &mut self.accounting)
    }

    pub fn finish<T>(self, result: Result<T, ReceiptStoreError>) -> Result<T, ReceiptStoreError> {
        self.progress.finish(result)
    }
}
