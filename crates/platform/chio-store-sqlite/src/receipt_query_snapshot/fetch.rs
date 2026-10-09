//! Leaf-bound payload fetch. Selected rows name their claim entry and the
//! leaf the snapshot authenticated; the receipt bytes are re-read from the
//! mutable store and accepted only when their signature verifies and their
//! canonical leaf equals the owned leaf.
use chio_core::receipt::body::ChioReceipt;
use chio_kernel::receipt_query::ReceiptReadError;
use chio_kernel::{ReceiptStoreError, StoredToolReceipt};
use rusqlite::{Connection, OptionalExtension};

use super::query::SelectedRow;
use crate::receipt_store::support::{
    latest_watermark_archive_path, retention_watermark, SqlWorkBudget,
};
use crate::receipt_store::{decode_verified_chio_receipt, SqliteReceiptStore};

/// Per-request fetch limits.
#[derive(Debug, Clone, Copy)]
pub(super) struct FetchLimits {
    pub(super) page_bytes: u64,
    pub(super) max_receipt_bytes: u64,
    pub(super) sql_steps: u64,
}

/// Why a fetch produced no page.
#[derive(Debug)]
pub(super) enum FetchError {
    /// The stored bytes no longer match what the snapshot authenticated.
    Mismatch(String),
    /// The fetch exhausted its SQL budget: a resource outcome.
    Budget,
    /// Any other store error, returned to the caller unchanged.
    Store(ReceiptStoreError),
}

/// A fetched page. `short` is true when the byte limit ended it early.
pub(super) struct FetchedPage {
    pub(super) receipts: Vec<StoredToolReceipt>,
    pub(super) short: bool,
}

enum Copied {
    Rows(Vec<(SelectedRow, String)>, bool),
    Missing(i64),
}

pub(super) fn fetch(
    store: &SqliteReceiptStore,
    rows: &[SelectedRow],
    tenant: Option<&str>,
    limits: FetchLimits,
) -> Result<FetchedPage, FetchError> {
    if rows.is_empty() {
        return Ok(FetchedPage {
            receipts: Vec::new(),
            short: false,
        });
    }
    // A row absent from both stores may have moved between them during a
    // rotation; one fresh attempt distinguishes that from loss.
    let copied = match copy(store, rows, limits)? {
        Copied::Missing(_) => copy(store, rows, limits)?,
        copied => copied,
    };
    let (copied, short) = match copied {
        Copied::Rows(copied, short) => (copied, short),
        Copied::Missing(entry_seq) => {
            return Err(FetchError::Mismatch(format!(
                "authenticated claim entry {entry_seq} is missing from the receipt store"
            )))
        }
    };
    let mut receipts = Vec::with_capacity(copied.len());
    for (row, raw_json) in copied {
        let receipt: ChioReceipt =
            decode_verified_chio_receipt(&raw_json, "snapshot receipt fetch", Some(row.seq))
                .map_err(|error| FetchError::Mismatch(error.to_string()))?;
        let bytes = chio_core::canonical::canonical_json_bytes(&receipt)
            .map_err(|error| FetchError::Mismatch(error.to_string()))?;
        if *chio_core::merkle::leaf_hash(&bytes).as_bytes() != row.leaf_hash {
            return Err(FetchError::Mismatch(format!(
                "claim entry {} no longer holds the receipt the snapshot authenticated",
                row.entry_seq
            )));
        }
        if tenant.is_some_and(|tenant| receipt.tenant_id.as_deref() != Some(tenant)) {
            return Err(FetchError::Store(
                ReceiptReadError::TenantProjectionMismatch.into(),
            ));
        }
        receipts.push(StoredToolReceipt {
            seq: row.seq,
            receipt,
        });
    }
    Ok(FetchedPage { receipts, short })
}

fn copy(
    store: &SqliteReceiptStore,
    rows: &[SelectedRow],
    limits: FetchLimits,
) -> Result<Copied, FetchError> {
    let mut live = store.connection().map_err(FetchError::Store)?;
    let live_tx = live
        .transaction()
        .map_err(|error| FetchError::Store(error.into()))?;
    let budget = SqlWorkBudget::new_for(&live_tx, limits.sql_steps, "receipt query fetch")
        .map_err(FetchError::Store)?;
    let result = copy_in(&live_tx, rows, limits);
    let exhausted = budget.exhausted();
    drop(budget);
    let _ = live_tx.commit();
    if exhausted {
        return Err(FetchError::Budget);
    }
    result
}

fn copy_in(
    live: &Connection,
    rows: &[SelectedRow],
    limits: FetchLimits,
) -> Result<Copied, FetchError> {
    let store_error = |error: ReceiptStoreError| FetchError::Store(error);
    let watermark = retention_watermark(live).map_err(store_error)?.unwrap_or(0);
    let watermark = i64::try_from(watermark).unwrap_or(i64::MAX);
    let archive = if rows.iter().any(|row| row.entry_seq <= watermark) {
        let path = latest_watermark_archive_path(live)
            .map_err(store_error)?
            .ok_or_else(|| {
                FetchError::Mismatch("retention watermark names no archive".to_string())
            })?;
        let archive = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| FetchError::Store(error.into()))?;
        let _ = archive.busy_timeout(std::time::Duration::from_millis(5_000));
        archive
            .execute_batch("BEGIN DEFERRED")
            .map_err(|error| FetchError::Store(error.into()))?;
        Some(archive)
    } else {
        None
    };
    let archive_budget = archive
        .as_ref()
        .map(|archive| SqlWorkBudget::new_for(archive, limits.sql_steps, "receipt query fetch"))
        .transpose()
        .map_err(FetchError::Store)?;
    let copied = copy_rows(live, archive.as_ref(), watermark, rows, limits);
    let exhausted = archive_budget
        .as_ref()
        .is_some_and(|budget| budget.exhausted());
    drop(archive_budget);
    if let Some(archive) = archive.as_ref() {
        let _ = archive.execute_batch("COMMIT");
    }
    if exhausted {
        return Err(FetchError::Budget);
    }
    copied
}

fn copy_rows(
    live: &Connection,
    archive: Option<&Connection>,
    watermark: i64,
    rows: &[SelectedRow],
    limits: FetchLimits,
) -> Result<Copied, FetchError> {
    let mut copied = Vec::with_capacity(rows.len());
    let mut bytes = 0_u64;
    let mut short = false;
    for row in rows {
        let source = match (row.entry_seq <= watermark, archive) {
            (true, Some(archive)) => archive,
            _ => live,
        };
        let found: Option<(String, i64)> = source
            .prepare_cached(
                "SELECT receipt_kind, length(CAST(raw_json AS BLOB)) FROM claim_receipt_log_entries
                 WHERE entry_seq = ?1",
            )
            .and_then(|mut statement| {
                statement
                    .query_row([row.entry_seq], |r| Ok((r.get(0)?, r.get(1)?)))
                    .optional()
            })
            .map_err(|error| FetchError::Store(error.into()))?;
        let Some((kind, length)) = found else {
            return Ok(Copied::Missing(row.entry_seq));
        };
        let length = u64::try_from(length).unwrap_or(u64::MAX);
        if kind != "tool_receipt" || length > limits.max_receipt_bytes {
            return Err(FetchError::Mismatch(format!(
                "claim entry {} no longer holds the receipt the snapshot authenticated",
                row.entry_seq
            )));
        }
        if !copied.is_empty() && bytes.saturating_add(length) > limits.page_bytes {
            short = true;
            break;
        }
        let raw_json: String = source
            .prepare_cached("SELECT raw_json FROM claim_receipt_log_entries WHERE entry_seq = ?1")
            .and_then(|mut statement| statement.query_row([row.entry_seq], |r| r.get(0)))
            .map_err(|error| FetchError::Store(error.into()))?;
        bytes = bytes.saturating_add(length);
        copied.push((row.clone(), raw_json));
    }
    Ok(Copied::Rows(copied, short))
}
