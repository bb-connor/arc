//! Authentication walker.
//!
//! Every step copies a bounded claim or checkpoint range in short read
//! transactions, authenticates it with no transaction or lock held, checks the
//! stored source rows in a second short transaction, and only then touches the
//! owned snapshot. No step relies on a mutable SQLite handle for authority.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::lineage::ChildRequestReceipt;
use chio_kernel::checkpoint::{CheckpointChainFrontier, KernelCheckpoint};
use chio_kernel::receipt_query::ReceiptQuerySnapshotError;
use chio_kernel::ReceiptStoreError;
use rusqlite::{params, Connection, ErrorCode, OptionalExtension};

use super::db::{
    ChildCursor, OwnedCheckpoint, PendingLeaf, ProjectedToolRow, SnapshotBatch, SnapshotDb,
    SnapshotDbError, KIND_CHILD, KIND_TOOL,
};
use super::project::{
    child_source_matches, SignedToolProjection, CHILD_SOURCE_PROJECTION_SQL,
    TOOL_SOURCE_PROJECTION_SQL,
};
use crate::capability_lineage::snapshot_from_row;
use crate::receipt_store::support::{
    checkpoint_error_to_receipt_store, latest_watermark_archive_path,
    parse_persisted_checkpoint_row, retention_watermark, validate_checkpoint_base,
    validate_checkpoint_projection_rows, ArchiveCheckpointReader, PersistedCheckpointRow,
};
use crate::receipt_store::SqliteReceiptStore;
use crate::receipt_store::{decode_verified_child_receipt, decode_verified_chio_receipt};

/// Enforced per-step limits. None of them is a timing promise.
#[derive(Debug, Clone, Copy)]
pub(super) struct WalkLimits {
    pub(super) step_rows: u64,
    pub(super) step_bytes: u64,
    pub(super) max_receipt_bytes: u64,
    pub(super) sql_steps: u64,
    pub(super) insert_rows: usize,
    pub(super) checkpoint_page: u64,
    /// SQLite busy timeout of walker connections.
    pub(super) busy_timeout: std::time::Duration,
}

/// Outcome classes of a walker step. Only `Integrity` and `Regressed` are
/// evidence about the stored history; the others are resource or scheduling
/// outcomes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(super) enum WalkError {
    #[error("{0}")]
    Integrity(String),
    #[error("receipt log regressed: {0}")]
    Regressed(String),
    #[error("receipt query snapshot storage is full: backing storage or configured quota may be exhausted ({quota_bytes} byte quota, {used_bytes} bytes used)")]
    Capacity { quota_bytes: u64, used_bytes: u64 },
    #[error("{what} holds {bytes} bytes, above the per-row limit")]
    RowCap { what: String, bytes: u64 },
    #[error("walker step exhausted its SQL work budget")]
    WalkerBudget,
    #[error("walker step was refused by a busy store: {0}")]
    Busy(String),
    #[error("walker was cancelled")]
    Cancelled,
    #[error("receipt query snapshot lineage was superseded")]
    Superseded,
    #[error("receipt query snapshot is unavailable: {0}")]
    Unavailable(String),
}

impl From<SnapshotDbError> for WalkError {
    fn from(error: SnapshotDbError) -> Self {
        match error {
            SnapshotDbError::Capacity {
                quota_bytes,
                used_bytes,
            } => Self::Capacity {
                quota_bytes,
                used_bytes,
            },
            SnapshotDbError::Duplicate(message) => Self::Integrity(message),
            SnapshotDbError::Store(error) => classify(error, None),
            SnapshotDbError::Sqlite(error) => classify(ReceiptStoreError::Sqlite(error), None),
        }
    }
}

/// Shared walker inputs.
pub(super) struct WalkContext<'a> {
    pub(super) store: &'a SqliteReceiptStore,
    pub(super) limits: WalkLimits,
    pub(super) cancel: &'a Arc<AtomicBool>,
    /// Full passes read through a fresh connection, whose page cache cannot
    /// hold bytes that an in-place edit has since replaced on disk.
    pub(super) fresh_reads: bool,
}

/// Live store connection for one walker transaction.
enum LiveConnection {
    Pooled(crate::receipt_store::SqliteStoreConnection),
    Fresh(Connection),
}

impl std::ops::Deref for LiveConnection {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        match self {
            Self::Pooled(connection) => connection,
            Self::Fresh(connection) => connection,
        }
    }
}

impl std::ops::DerefMut for LiveConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        match self {
            Self::Pooled(connection) => connection,
            Self::Fresh(connection) => connection,
        }
    }
}

fn live_connection(ctx: &WalkContext<'_>) -> Result<LiveConnection, WalkError> {
    let pooled = ctx
        .store
        .connection()
        .map_err(|error| classify(error, None))?;
    let path = pooled
        .path()
        .filter(|path| !path.is_empty())
        .map(str::to_owned);
    let (true, Some(path)) = (ctx.fresh_reads, path) else {
        return Ok(LiveConnection::Pooled(pooled));
    };
    drop(pooled);
    let fresh = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| classify(sql(error), None))?;
    fresh
        .busy_timeout(ctx.limits.busy_timeout)
        .map_err(|error| classify(sql(error), None))?;
    Ok(LiveConnection::Fresh(fresh))
}

impl WalkContext<'_> {
    pub(super) fn check_cancel(&self) -> Result<(), WalkError> {
        if self.cancel.load(Ordering::SeqCst) {
            Err(WalkError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// Progress handler for walker SQL: interrupts on cancellation or when the
/// step's VM budget is spent, and records which one fired.
struct StepGuard<'c> {
    connection: &'c Connection,
    exhausted: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
}

impl<'c> StepGuard<'c> {
    fn install(
        connection: &'c Connection,
        steps: u64,
        cancel: &Arc<AtomicBool>,
    ) -> Result<Self, WalkError> {
        const INTERVAL: i32 = 1_000;
        let exhausted = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&exhausted);
        let stop = Arc::clone(cancel);
        let mut remaining = steps;
        connection
            .progress_handler(
                INTERVAL,
                Some(move || {
                    if stop.load(Ordering::SeqCst) {
                        return true;
                    }
                    remaining = remaining.saturating_sub(1_000);
                    if remaining == 0 {
                        signal.store(true, Ordering::SeqCst);
                        return true;
                    }
                    false
                }),
            )
            .map_err(|error| classify(sql(error), None))?;
        Ok(Self {
            connection,
            exhausted,
            cancel: Arc::clone(cancel),
        })
    }

    fn classify(&self, error: ReceiptStoreError) -> WalkError {
        classify(error, Some(self))
    }
}

impl Drop for StepGuard<'_> {
    fn drop(&mut self) {
        let _ = self.connection.progress_handler(0, None::<fn() -> bool>);
    }
}

/// SQLite failures of storage or its environment: I/O, opening, memory,
/// permissions and space. They say nothing about the stored rows.
fn sqlite_resource_failure(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(
            ErrorCode::SystemIoFailure
                | ErrorCode::CannotOpen
                | ErrorCode::OutOfMemory
                | ErrorCode::ReadOnly
                | ErrorCode::PermissionDenied
                | ErrorCode::DiskFull
                | ErrorCode::NoLargeFileSupport
                | ErrorCode::FileLockingProtocolFailed
        )
    )
}

/// The availability reason of a store error that wraps a SQLite resource
/// failure, shared by the walker and the read path. Interruption, contention
/// and every other error are left to their own class.
pub(super) fn resource_unavailable(error: &ReceiptStoreError) -> Option<String> {
    match error {
        ReceiptStoreError::Sqlite(sqlite) if sqlite_resource_failure(sqlite) => {
            Some(format!("receipt query snapshot storage failed: {sqlite}"))
        }
        _ => None,
    }
}

/// Map a store error to its walker outcome, in order of precedence. A typed
/// snapshot outcome keeps its class: only `Invalid` is an integrity failure.
/// Interruption means cancellation or budget exhaustion; busy and pool errors
/// are contention; a SQLite resource failure is unavailability.
fn classify(error: ReceiptStoreError, guard: Option<&StepGuard<'_>>) -> WalkError {
    if let ReceiptStoreError::QuerySnapshot(snapshot) = &error {
        return match snapshot {
            ReceiptQuerySnapshotError::Invalid(reason) => WalkError::Integrity(reason.clone()),
            ReceiptQuerySnapshotError::Unavailable(reason)
            | ReceiptQuerySnapshotError::ExportRefused(reason) => {
                WalkError::Unavailable(reason.clone())
            }
            ReceiptQuerySnapshotError::WorkBudgetExhausted(_) => WalkError::WalkerBudget,
            ReceiptQuerySnapshotError::Building { .. }
            | ReceiptQuerySnapshotError::Stale
            | ReceiptQuerySnapshotError::Busy => WalkError::Busy(snapshot.to_string()),
        };
    }
    if let ReceiptStoreError::Sqlite(sqlite) = &error {
        match sqlite.sqlite_error_code() {
            Some(ErrorCode::OperationInterrupted) => {
                return match guard {
                    Some(guard) if guard.cancel.load(Ordering::SeqCst) => WalkError::Cancelled,
                    Some(guard) if guard.exhausted.load(Ordering::SeqCst) => {
                        WalkError::WalkerBudget
                    }
                    _ => WalkError::Busy(error.to_string()),
                };
            }
            Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => {
                return WalkError::Busy(error.to_string());
            }
            _ => {}
        }
    }
    if let Some(reason) = resource_unavailable(&error) {
        return WalkError::Unavailable(reason);
    }
    match error {
        ReceiptStoreError::Pool(_)
        | ReceiptStoreError::Timeout { .. }
        | ReceiptStoreError::Io(_)
        | ReceiptStoreError::Clock(_) => WalkError::Busy(error.to_string()),
        other => WalkError::Integrity(other.to_string()),
    }
}

fn sql(error: rusqlite::Error) -> ReceiptStoreError {
    ReceiptStoreError::Sqlite(error)
}

/// A copied claim-log row, not yet authenticated.
#[derive(Debug, Clone)]
pub(super) struct ClaimRow {
    pub(super) entry_seq: i64,
    pub(super) kind: String,
    pub(super) source_seq: i64,
    pub(super) receipt_id: String,
    pub(super) raw_json: String,
}

/// A claim whose signature verified and whose leaf is computed.
pub(super) enum Authenticated {
    Tool(Box<ChioReceipt>),
    Child(Box<ChildRequestReceipt>),
}

pub(super) struct AuthenticatedEntry {
    pub(super) row: ClaimRow,
    pub(super) receipt: Authenticated,
    pub(super) leaf_hash: [u8; 32],
    pub(super) signer: String,
}

/// Read-only connection to the archive named by the live watermark ledger.
fn open_archive(
    live: &Connection,
    busy_timeout: std::time::Duration,
) -> Result<Connection, ReceiptStoreError> {
    let path = latest_watermark_archive_path(live)?.ok_or_else(|| {
        ReceiptStoreError::Conflict(
            "retention watermark does not name an authenticated archive".to_owned(),
        )
    })?;
    let archive = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    archive.busy_timeout(busy_timeout)?;
    Ok(archive)
}

fn watermark_i64(connection: &Connection) -> Result<i64, ReceiptStoreError> {
    let watermark = retention_watermark(connection)?.unwrap_or(0);
    Ok(crate::integer::checked::<_, i64>(watermark)?)
}

/// Copy claim rows from `start` up to at most `end` in one short read
/// transaction. Returns at least one row. Rows at or below the live watermark
/// are read from the archive; a range never crosses the watermark.
pub(super) fn copy_claims(
    ctx: &WalkContext<'_>,
    start: i64,
    end: i64,
) -> Result<Vec<ClaimRow>, WalkError> {
    ctx.check_cancel()?;
    let mut live = live_connection(ctx)?;
    let live_tx = live
        .transaction()
        .map_err(|error| classify(sql(error), None))?;
    let guard = StepGuard::install(&live_tx, ctx.limits.sql_steps, ctx.cancel)?;
    let watermark = watermark_i64(&live_tx).map_err(|error| guard.classify(error))?;
    let rows = if start <= watermark {
        let archive = open_archive(&live_tx, ctx.limits.busy_timeout)
            .map_err(|error| guard.classify(error))?;
        let archive_guard = StepGuard::install(&archive, ctx.limits.sql_steps, ctx.cancel)?;
        archive
            .execute_batch("BEGIN DEFERRED")
            .map_err(|error| archive_guard.classify(sql(error)))?;
        let rows =
            read_claim_range(&archive, start, end.min(watermark), &ctx.limits).map_err(|error| {
                match error {
                    CopyError::Store(error) => archive_guard.classify(error),
                    CopyError::Walk(error) => error,
                }
            });
        let _ = archive.execute_batch("COMMIT");
        rows?
    } else {
        read_claim_range(&live_tx, start, end, &ctx.limits).map_err(|error| match error {
            CopyError::Store(error) => guard.classify(error),
            CopyError::Walk(error) => error,
        })?
    };
    drop(guard);
    let _ = live_tx.commit();
    Ok(rows)
}

enum CopyError {
    Store(ReceiptStoreError),
    Walk(WalkError),
}

impl From<rusqlite::Error> for CopyError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(sql(error))
    }
}

fn read_claim_range(
    connection: &Connection,
    start: i64,
    end: i64,
    limits: &WalkLimits,
) -> Result<Vec<ClaimRow>, CopyError> {
    let step_rows = i64::try_from(limits.step_rows.max(1)).unwrap_or(i64::MAX);
    let mut sizes = connection.prepare_cached(
        "SELECT entry_seq, length(CAST(raw_json AS BLOB)) + length(CAST(receipt_id AS BLOB))
                + length(CAST(receipt_kind AS BLOB))
         FROM claim_receipt_log_entries
         WHERE entry_seq >= ?1 AND entry_seq <= ?2 ORDER BY entry_seq LIMIT ?3",
    )?;
    let mut last = None;
    let mut bytes = 0_u64;
    let mut expected = start;
    let rows = sizes.query_map(params![start, end, step_rows], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (entry_seq, length) = row?;
        if entry_seq != expected {
            return Err(CopyError::Walk(WalkError::Integrity(format!(
                "claim receipt log has a gap at entry_seq {expected}"
            ))));
        }
        let length = u64::try_from(length).unwrap_or(0);
        if length > limits.max_receipt_bytes {
            return Err(CopyError::Walk(WalkError::RowCap {
                what: format!("claim receipt log entry {entry_seq}"),
                bytes: length,
            }));
        }
        if last.is_some() && bytes.saturating_add(length) > limits.step_bytes {
            break;
        }
        bytes = bytes.saturating_add(length);
        last = Some(entry_seq);
        expected = entry_seq.saturating_add(1);
    }
    let Some(last) = last else {
        return Err(CopyError::Walk(WalkError::Integrity(format!(
            "claim receipt log has a gap at entry_seq {start}"
        ))));
    };
    let mut statement = connection.prepare_cached(
        "SELECT entry_seq, receipt_kind, source_seq, receipt_id, raw_json
         FROM claim_receipt_log_entries WHERE entry_seq >= ?1 AND entry_seq <= ?2
         ORDER BY entry_seq",
    )?;
    let copied = statement
        .query_map(params![start, last], |row| {
            Ok(ClaimRow {
                entry_seq: row.get(0)?,
                kind: row.get(1)?,
                source_seq: row.get(2)?,
                receipt_id: row.get(3)?,
                raw_json: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let contiguous = copied
        .iter()
        .zip(start..=last)
        .all(|(row, expected)| row.entry_seq == expected);
    if !contiguous || copied.len() != usize::try_from(last - start + 1).unwrap_or(0) {
        return Err(CopyError::Walk(WalkError::Integrity(format!(
            "claim receipt log range {start}..={last} changed while it was copied"
        ))));
    }
    Ok(copied)
}

/// Verify signatures and compute leaves with no transaction or lock held.
/// When `checkpoint_key` is set, every entry must be signed by that key, the
/// same signer binding the per-call path enforces.
pub(super) fn authenticate(
    ctx: &WalkContext<'_>,
    rows: Vec<ClaimRow>,
    checkpoint: Option<&OwnedCheckpoint>,
) -> Result<Vec<AuthenticatedEntry>, WalkError> {
    let mut entries = Vec::with_capacity(rows.len());
    for (index, row) in rows.into_iter().enumerate() {
        if index % 64 == 0 {
            ctx.check_cancel()?;
        }
        let entry_seq = u64::try_from(row.entry_seq).unwrap_or(0);
        let (receipt, bytes, signer, id) = match row.kind.as_str() {
            "tool_receipt" => {
                let receipt = decode_verified_chio_receipt(
                    &row.raw_json,
                    "claim-log tool receipt",
                    Some(entry_seq),
                )
                .map_err(|error| WalkError::Integrity(error.to_string()))?;
                let bytes = chio_core::canonical::canonical_json_bytes(&receipt)
                    .map_err(|error| WalkError::Integrity(error.to_string()))?;
                let signer = receipt.kernel_key.clone();
                let id = receipt.id.clone();
                (Authenticated::Tool(Box::new(receipt)), bytes, signer, id)
            }
            "child_receipt" => {
                let receipt = decode_verified_child_receipt(
                    &row.raw_json,
                    "claim-log child receipt",
                    Some(entry_seq),
                )
                .map_err(|error| WalkError::Integrity(error.to_string()))?;
                let bytes = chio_core::canonical::canonical_json_bytes(&receipt)
                    .map_err(|error| WalkError::Integrity(error.to_string()))?;
                let signer = receipt.kernel_key.clone();
                let id = receipt.id.clone();
                (Authenticated::Child(Box::new(receipt)), bytes, signer, id)
            }
            other => {
                return Err(WalkError::Integrity(format!(
                    "unsupported claim receipt kind `{other}` at entry_seq {entry_seq}"
                )))
            }
        };
        if id != row.receipt_id {
            return Err(WalkError::Integrity(format!(
                "claim receipt log entry {entry_seq} names `{}` but carries receipt `{id}`",
                row.receipt_id
            )));
        }
        if let Some(checkpoint) = checkpoint {
            if signer.to_hex() != checkpoint.kernel_key {
                return Err(WalkError::Integrity(format!(
                    "checkpoint {} kernel key {} does not match receipt signer key {} at entry_seq {entry_seq}",
                    checkpoint.seq,
                    checkpoint.kernel_key,
                    signer.to_hex(),
                )));
            }
        }
        entries.push(AuthenticatedEntry {
            leaf_hash: *chio_core::merkle::leaf_hash(&bytes).as_bytes(),
            signer: signer.to_hex(),
            receipt,
            row,
        });
    }
    Ok(entries)
}

/// Check each entry's stored source row against its signed projection, in one
/// short read transaction on the live store and, for archived entries, the
/// archive. Lineage fallback always reads the live store.
///
/// Returns the projections of a prefix of `entries`, one per checked entry:
/// the step stops early when the bytes it would retain exceed `step_bytes`,
/// and always checks its first entry.
pub(super) fn check_sources(
    ctx: &WalkContext<'_>,
    entries: &[AuthenticatedEntry],
) -> Result<(Vec<ProjectedToolRow>, Vec<ChildCursor>), WalkError> {
    ctx.check_cancel()?;
    let mut live = live_connection(ctx)?;
    let live_tx = live
        .transaction()
        .map_err(|error| classify(sql(error), None))?;
    let guard = StepGuard::install(&live_tx, ctx.limits.sql_steps, ctx.cancel)?;
    let result = check_sources_in(ctx, &live_tx, entries).map_err(|error| match error {
        CopyError::Store(error) => guard.classify(error),
        CopyError::Walk(error) => error,
    });
    drop(guard);
    let _ = live_tx.commit();
    result
}

fn check_sources_in(
    ctx: &WalkContext<'_>,
    live: &Connection,
    entries: &[AuthenticatedEntry],
) -> Result<(Vec<ProjectedToolRow>, Vec<ChildCursor>), CopyError> {
    let watermark = watermark_i64(live).map_err(CopyError::Store)?;
    let archive = if entries.iter().any(|entry| entry.row.entry_seq <= watermark) {
        let archive = open_archive(live, ctx.limits.busy_timeout).map_err(CopyError::Store)?;
        archive.execute_batch("BEGIN DEFERRED")?;
        Some(archive)
    } else {
        None
    };
    let _archive_guard = archive
        .as_ref()
        .map(|archive| StepGuard::install(archive, ctx.limits.sql_steps, ctx.cancel))
        .transpose()
        .map_err(CopyError::Walk)?;
    let (tool_ceiling, child_ceiling): (i64, i64) = live.query_row(
        "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'chio_tool_receipts'), 0),
                COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'chio_child_receipts'), 0)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut live_tools = live.prepare_cached(TOOL_SOURCE_PROJECTION_SQL)?;
    let mut live_children = live.prepare_cached(CHILD_SOURCE_PROJECTION_SQL)?;
    let mut live_tool_exists =
        live.prepare_cached("SELECT EXISTS(SELECT 1 FROM chio_tool_receipts WHERE seq = ?1)")?;
    let mut live_child_exists =
        live.prepare_cached("SELECT EXISTS(SELECT 1 FROM chio_child_receipts WHERE seq = ?1)")?;
    let mut archive_statements = match archive.as_ref() {
        Some(archive) => Some((
            archive.prepare(TOOL_SOURCE_PROJECTION_SQL)?,
            archive.prepare(CHILD_SOURCE_PROJECTION_SQL)?,
        )),
        None => None,
    };
    let drift = |entry_seq: i64| {
        CopyError::Walk(WalkError::Integrity(format!(
            "receipt source row diverges from its authenticated claim log entry {entry_seq}"
        )))
    };
    let mut tools = Vec::new();
    let mut children = Vec::new();
    // Bytes this step retains: the copied claim rows plus every lineage
    // subject a projection keeps. A step that would exceed its budget ends
    // early; the caller resumes after the last checked entry.
    let mut retained = 0_u64;
    for (index, entry) in entries.iter().enumerate() {
        if index % 64 == 0 && ctx.cancel.load(Ordering::SeqCst) {
            return Err(CopyError::Walk(WalkError::Cancelled));
        }
        let row = &entry.row;
        let mut charge = crate::integer::count(row.raw_json.len())
            .saturating_add(crate::integer::count(row.receipt_id.len()))
            .saturating_add(crate::integer::count(row.kind.len()));
        if row.source_seq <= 0 {
            return Err(drift(row.entry_seq));
        }
        let archived = row.entry_seq <= watermark;
        match &entry.receipt {
            Authenticated::Tool(receipt) => {
                if archived
                    && (row.source_seq > tool_ceiling
                        || live_tool_exists.query_row([row.source_seq], |r| r.get::<_, bool>(0))?)
                {
                    return Err(drift(row.entry_seq));
                }
                let attribution =
                    crate::receipt_store::support::extract_receipt_attribution(receipt);
                if attribution.subject_key.is_none() || attribution.issuer_key.is_none() {
                    let measured = lineage_row_bytes(live, &receipt.capability_id)
                        .map_err(CopyError::Store)?;
                    if let Some((bytes, subject)) = measured {
                        if bytes > ctx.limits.max_receipt_bytes {
                            return Err(CopyError::Walk(WalkError::RowCap {
                                what: format!("capability lineage {}", receipt.capability_id),
                                bytes,
                            }));
                        }
                        charge = charge.saturating_add(subject);
                    }
                }
                if index > 0 && retained.saturating_add(charge) > ctx.limits.step_bytes {
                    break;
                }
                retained = retained.saturating_add(charge);
                let projection =
                    SignedToolProjection::derive(receipt, live).map_err(CopyError::Store)?;
                let statement = match (archived, archive_statements.as_mut()) {
                    (true, Some((tools, _))) => tools,
                    (true, None) => return Err(drift(row.entry_seq)),
                    (false, _) => &mut live_tools,
                };
                if !projection
                    .source_matches(statement, row.source_seq, &row.raw_json, archived)
                    .map_err(CopyError::Store)?
                {
                    return Err(drift(row.entry_seq));
                }
                tools.push(ProjectedToolRow {
                    seq: row.source_seq,
                    entry_seq: row.entry_seq,
                    leaf_hash: entry.leaf_hash,
                    signer: entry.signer.clone(),
                    receipt_id: projection.receipt_id,
                    ts: projection.timestamp,
                    tenant: projection.tenant,
                    capability: projection.capability_id,
                    tool_server: projection.tool_server,
                    tool_name: projection.tool_name,
                    decision: projection.decision.to_string(),
                    subject: projection.subject,
                    subject_signed: projection.subject_signed,
                    cost_currency: projection.cost_currency,
                    cost_charged: projection.cost_charged,
                });
            }
            Authenticated::Child(receipt) => {
                if index > 0 && retained.saturating_add(charge) > ctx.limits.step_bytes {
                    break;
                }
                retained = retained.saturating_add(charge);
                if archived
                    && (row.source_seq > child_ceiling
                        || live_child_exists
                            .query_row([row.source_seq], |r| r.get::<_, bool>(0))?)
                {
                    return Err(drift(row.entry_seq));
                }
                let statement = match (archived, archive_statements.as_mut()) {
                    (true, Some((_, children))) => children,
                    (true, None) => return Err(drift(row.entry_seq)),
                    (false, _) => &mut live_children,
                };
                if !child_source_matches(statement, row.source_seq, &row.raw_json, receipt)
                    .map_err(CopyError::Store)?
                {
                    return Err(drift(row.entry_seq));
                }
                children.push(ChildCursor {
                    source_seq: row.source_seq,
                    entry_seq: row.entry_seq,
                    signer: entry.signer.clone(),
                    leaf_hash: entry.leaf_hash,
                    ts: crate::receipt_store::support::sqlite_i64(
                        receipt.timestamp,
                        "child timestamp",
                    )
                    .map_err(CopyError::Store)?,
                });
            }
        }
    }
    drop(archive_statements);
    if let Some(archive) = archive.as_ref() {
        let _ = archive.execute_batch("COMMIT");
    }
    Ok((tools, children))
}

/// Copy up to `checkpoint_page` persisted checkpoint rows starting at `start`
/// and ending at most at `end`, with the archive rows of those at or below the
/// watermark, in one short read transaction. Every row's variable-length
/// fields are measured before any is allocated: a row over the per-row limit
/// is a typed resource outcome, and the page stops before its byte budget is
/// exceeded (it always carries its first row).
pub(super) fn copy_checkpoints(
    ctx: &WalkContext<'_>,
    start: i64,
    end: i64,
) -> Result<Vec<(PersistedCheckpointRow, Option<PersistedCheckpointRow>)>, WalkError> {
    ctx.check_cancel()?;
    let page_end =
        end.min(start.saturating_add(
            i64::try_from(ctx.limits.checkpoint_page.max(1)).unwrap_or(i64::MAX) - 1,
        ));
    let mut live = live_connection(ctx)?;
    let live_tx = live
        .transaction()
        .map_err(|error| classify(sql(error), None))?;
    let guard = StepGuard::install(&live_tx, ctx.limits.sql_steps, ctx.cancel)?;
    let watermark = watermark_i64(&live_tx).map_err(|error| guard.classify(error))?;
    let sizes = checkpoint_row_sizes(&live_tx, start, page_end, false)
        .map_err(|error| guard.classify(error))?;
    let needs_archive = sizes
        .iter()
        .any(|(_, batch_end, _)| *batch_end <= watermark);
    let archive = if needs_archive {
        let archive = open_archive(&live_tx, ctx.limits.busy_timeout)
            .map_err(|error| guard.classify(error))?;
        archive
            .execute_batch("BEGIN DEFERRED")
            .map_err(|error| guard.classify(sql(error)))?;
        Some(archive)
    } else {
        None
    };
    let _archive_guard = archive
        .as_ref()
        .map(|archive| StepGuard::install(archive, ctx.limits.sql_steps, ctx.cancel))
        .transpose()?;
    let mut last = None;
    let mut bytes = 0_u64;
    for (expected, (seq, batch_end, length)) in (start..).zip(sizes.iter().copied()) {
        if seq != expected {
            return Err(WalkError::Integrity(format!(
                "checkpoint chain has a gap: expected seq {expected}, found {seq}"
            )));
        }
        let mut row_bytes = length;
        if length > ctx.limits.max_receipt_bytes {
            return Err(WalkError::RowCap {
                what: format!("checkpoint {seq}"),
                bytes: length,
            });
        }
        if let (Some(archive), true) = (archive.as_ref(), batch_end <= watermark) {
            let archived = checkpoint_row_sizes(archive, seq, seq, true)
                .map_err(|error| classify(error, None))?
                .first()
                .map_or(0, |(_, _, length)| *length);
            if archived > ctx.limits.max_receipt_bytes {
                return Err(WalkError::RowCap {
                    what: format!("archived checkpoint {seq}"),
                    bytes: archived,
                });
            }
            row_bytes = row_bytes.saturating_add(archived);
        }
        if last.is_some() && bytes.saturating_add(row_bytes) > ctx.limits.step_bytes {
            break;
        }
        bytes = bytes.saturating_add(row_bytes);
        last = Some(seq);
    }
    let Some(last) = last else {
        return Err(WalkError::Integrity(format!(
            "checkpoint chain has a gap: expected seq {start}"
        )));
    };
    let rows =
        load_checkpoint_rows(&live_tx, start, last).map_err(|error| guard.classify(error))?;
    let reader = match archive.as_ref() {
        Some(archive) => Some(
            ArchiveCheckpointReader::new(archive)
                .map_err(|error| WalkError::Integrity(error.to_string()))?,
        ),
        None => None,
    };
    let mut copied = Vec::with_capacity(rows.len());
    for (expected, row) in (start..=last).zip(rows) {
        if i64::try_from(row.checkpoint_seq).unwrap_or(-1) != expected {
            return Err(WalkError::Integrity(format!(
                "checkpoint chain has a gap: expected seq {expected}, found {}",
                row.checkpoint_seq
            )));
        }
        let archived = match reader.as_ref() {
            Some(reader) if i64::try_from(row.batch_end_seq).unwrap_or(i64::MAX) <= watermark => {
                Some(
                    reader
                        .load(row.checkpoint_seq)
                        .map_err(|error| WalkError::Integrity(error.to_string()))?
                        .ok_or_else(|| {
                            WalkError::Integrity(format!(
                                "archived checkpoint {} is missing",
                                row.checkpoint_seq
                            ))
                        })?,
                )
            }
            _ => None,
        };
        copied.push((row, archived));
    }
    drop(_archive_guard);
    if let Some(archive) = archive.as_ref() {
        let _ = archive.execute_batch("COMMIT");
    }
    drop(guard);
    let _ = live_tx.commit();
    let expected_len = usize::try_from(last - start + 1).unwrap_or(0);
    if copied.len() != expected_len {
        return Err(WalkError::Integrity(format!(
            "checkpoint chain has a gap: expected seq {}",
            start + i64::try_from(copied.len()).unwrap_or(0)
        )));
    }
    Ok(copied)
}

/// `(checkpoint_seq, batch_end_seq, bytes of every variable-length column)`
/// for a checkpoint range, read without allocating any of those columns.
fn checkpoint_row_sizes(
    connection: &Connection,
    start: i64,
    end: i64,
    tolerate_legacy_layout: bool,
) -> Result<Vec<(i64, i64, u64)>, ReceiptStoreError> {
    let has_predecessor: bool = if tolerate_legacy_layout {
        connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('kernel_checkpoints') WHERE name = 'previous_checkpoint_sha256')",
            [],
            |row| row.get(0),
        )?
    } else {
        true
    };
    let predecessor = if has_predecessor {
        "COALESCE(length(CAST(previous_checkpoint_sha256 AS BLOB)), 0)"
    } else {
        "0"
    };
    let mut statement = connection.prepare(&format!(
        "SELECT checkpoint_seq, batch_end_seq,
                length(CAST(merkle_root AS BLOB)) + length(CAST(statement_json AS BLOB))
                + length(CAST(signature AS BLOB)) + length(CAST(kernel_key AS BLOB)) + {predecessor}
         FROM kernel_checkpoints WHERE checkpoint_seq >= ?1 AND checkpoint_seq <= ?2
         ORDER BY checkpoint_seq ASC"
    ))?;
    let rows = statement.query_map(params![start, end], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            u64::try_from(row.get::<_, i64>(2)?).unwrap_or(u64::MAX),
        ))
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn load_checkpoint_rows(
    connection: &Connection,
    start: i64,
    end: i64,
) -> Result<Vec<PersistedCheckpointRow>, ReceiptStoreError> {
    let mut statement = connection.prepare_cached(
        "SELECT id, checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
                merkle_root, issued_at, statement_json, signature, kernel_key, previous_checkpoint_sha256
         FROM kernel_checkpoints WHERE checkpoint_seq >= ?1 AND checkpoint_seq <= ?2
         ORDER BY checkpoint_seq ASC",
    )?;
    let rows = statement.query_map(params![start, end], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, String>(9)?,
            row.get::<_, Option<String>>(10)?,
        ))
    })?;
    rows.map(|row| {
        let (id, seq, start, end, size, root, issued, statement, signature, key, previous) =
            row.map_err(ReceiptStoreError::from)?;
        let unsigned = |value: i64, field: &str| crate::receipt_store::sqlite_u64(value, field);
        Ok(PersistedCheckpointRow {
            id: unsigned(id, "checkpoint id")?,
            checkpoint_seq: unsigned(seq, "checkpoint_seq")?,
            batch_start_seq: unsigned(start, "batch_start_seq")?,
            batch_end_seq: unsigned(end, "batch_end_seq")?,
            tree_size: unsigned(size, "tree_size")?,
            merkle_root_hex: root,
            issued_at: unsigned(issued, "issued_at")?,
            statement_json: statement,
            signature_hex: signature,
            kernel_key_hex: key,
            previous_checkpoint_sha256: previous,
        })
    })
    .collect()
}

/// Authenticate copied checkpoint rows as members of the chain extending
/// `previous` and `chain`, outside any transaction, then validate their
/// projection rows in one short read transaction.
pub(super) fn authenticate_checkpoints(
    ctx: &WalkContext<'_>,
    rows: Vec<(PersistedCheckpointRow, Option<PersistedCheckpointRow>)>,
    previous: &mut Option<KernelCheckpoint>,
    chain: &mut CheckpointChainFrontier,
) -> Result<Vec<(KernelCheckpoint, PersistedCheckpointRow)>, WalkError> {
    let mut verified = Vec::with_capacity(rows.len());
    let integrity = |error: ReceiptStoreError| WalkError::Integrity(error.to_string());
    let mut next_previous = previous.clone();
    let mut next_chain = chain.clone();
    for (row, archived) in rows {
        ctx.check_cancel()?;
        if let Some(archived) = archived {
            if archived != row {
                return Err(WalkError::Integrity(format!(
                    "archived checkpoint {} differs from the live checkpoint row",
                    row.checkpoint_seq
                )));
            }
        }
        let checkpoint = parse_persisted_checkpoint_row(row.clone()).map_err(integrity)?;
        match next_previous.as_ref() {
            Some(predecessor) => {
                chio_kernel::checkpoint::validate_checkpoint_predecessor(predecessor, &checkpoint)
                    .map_err(|error| integrity(checkpoint_error_to_receipt_store(error)))?
            }
            None => validate_checkpoint_base(&checkpoint).map_err(integrity)?,
        }
        next_chain.append(
            chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&checkpoint.body)
                .map_err(|error| integrity(checkpoint_error_to_receipt_store(error)))?,
        );
        if let Some(chain_root) = checkpoint.body.chain_root {
            if next_chain.root() != Some(chain_root) {
                return Err(WalkError::Integrity(format!(
                    "checkpoint {} chain_root does not match the persisted chain",
                    checkpoint.body.checkpoint_seq
                )));
            }
        }
        next_previous = Some(checkpoint.clone());
        verified.push((checkpoint, row));
    }
    let mut live = live_connection(ctx)?;
    let live_tx = live
        .transaction()
        .map_err(|error| classify(sql(error), None))?;
    let guard = StepGuard::install(&live_tx, ctx.limits.sql_steps, ctx.cancel)?;
    for (checkpoint, row) in &verified {
        validate_checkpoint_projection_rows(&live_tx, row, checkpoint)
            .map_err(|error| guard.classify(error))?;
    }
    drop(guard);
    let _ = live_tx.commit();
    *previous = next_previous;
    *chain = next_chain;
    Ok(verified)
}

pub(super) fn owned_checkpoint(
    checkpoint: &KernelCheckpoint,
) -> Result<OwnedCheckpoint, WalkError> {
    let field = |value: u64| {
        i64::try_from(value)
            .map_err(|_| WalkError::Integrity("checkpoint field exceeds SQLite range".into()))
    };
    Ok(OwnedCheckpoint {
        seq: field(checkpoint.body.checkpoint_seq)?,
        batch_start: field(checkpoint.body.batch_start_seq)?,
        batch_end: field(checkpoint.body.batch_end_seq)?,
        tree_size: field(crate::integer::count(checkpoint.body.tree_size))?,
        merkle_root: *checkpoint.body.merkle_root.as_bytes(),
        kernel_key: checkpoint.body.kernel_key.to_hex(),
        canonical_sha256: super::export::checkpoint_digest(checkpoint)
            .map_err(|error| WalkError::Integrity(error.to_string()))?,
    })
}

/// Commit rows and cursors in holds of at most `insert_rows` entries.
pub(super) fn commit_in_holds<S: OwnedSink>(
    owned: &mut S,
    limits: &WalkLimits,
    tools: Vec<ProjectedToolRow>,
    children: Vec<ChildCursor>,
    pending: Vec<PendingLeaf>,
) -> Result<(), WalkError> {
    let mut batch = SnapshotBatch::default();
    let mut tools = tools.into_iter().peekable();
    let mut children = children.into_iter().peekable();
    let mut pending = pending.into_iter().peekable();
    let hold = limits.insert_rows.max(1);
    loop {
        // Interleave by entry order so each hold publishes a contiguous prefix.
        let next_tool = tools.peek().map(|row| row.entry_seq);
        let next_child = children.peek().map(|cursor| cursor.entry_seq);
        let take_tool = match (next_tool, next_child) {
            (None, None) => break,
            (Some(tool), Some(child)) => tool < child,
            (Some(_), None) => true,
            (None, Some(_)) => false,
        };
        let entry_seq = if take_tool {
            let row = tools.next();
            let entry_seq = row.as_ref().map_or(0, |row| row.entry_seq);
            batch.tools.extend(row);
            entry_seq
        } else {
            let cursor = children.next();
            let entry_seq = cursor.as_ref().map_or(0, |cursor| cursor.entry_seq);
            batch.children.extend(cursor);
            entry_seq
        };
        while pending
            .peek()
            .is_some_and(|leaf| leaf.entry_seq <= entry_seq)
        {
            batch.pending.extend(pending.next());
        }
        if batch.tools.len() + batch.children.len() >= hold {
            owned.commit(&std::mem::take(&mut batch), entry_seq)?;
        }
    }
    batch.pending.extend(pending);
    let last = batch
        .tools
        .iter()
        .map(|row| row.entry_seq)
        .chain(batch.children.iter().map(|cursor| cursor.entry_seq))
        .chain(batch.pending.iter().map(|leaf| leaf.entry_seq))
        .max();
    if let Some(last) = last {
        owned.commit(&batch, last)?;
    }
    Ok(())
}

/// Destination of authenticated changes. Each call is one bounded hold of the
/// snapshot connection. `through_entry_seq` is the last claim entry a batch
/// completes.
pub(super) trait OwnedSink {
    fn commit(&mut self, batch: &SnapshotBatch, through_entry_seq: i64) -> Result<(), WalkError>;
    fn read<T, F>(&mut self, read: F) -> Result<T, WalkError>
    where
        F: FnOnce(&SnapshotDb) -> Result<T, SnapshotDbError>;
}

/// Unpublished snapshot owned by the build: no reader can observe it.
impl OwnedSink for SnapshotDb {
    fn commit(&mut self, batch: &SnapshotBatch, _through_entry_seq: i64) -> Result<(), WalkError> {
        Ok(SnapshotDb::commit(self, batch)?)
    }

    fn read<T, F>(&mut self, read: F) -> Result<T, WalkError>
    where
        F: FnOnce(&SnapshotDb) -> Result<T, SnapshotDbError>,
    {
        Ok(read(self)?)
    }
}

/// The claim-log head and watermark observed in one read transaction, with the
/// sequence of the newest checkpoint row. That checkpoint is not yet
/// validated: its signed coverage is authenticated, and checked against
/// `head`, before any range is classified by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Observation {
    pub(super) head: i64,
    pub(super) watermark: i64,
    pub(super) checkpoint: i64,
    pub(super) lineage_rowid: i64,
    /// Largest live tool and child source sequences in the same read. Every
    /// source row at or below them existed when `head` was observed, so it
    /// must be logged at or below `head`; later appends lie above them.
    pub(super) max_source_seqs: (i64, i64),
}

pub(super) fn observe(ctx: &WalkContext<'_>) -> Result<Observation, WalkError> {
    let mut live = live_connection(ctx)?;
    let live_tx = live
        .transaction()
        .map_err(|error| classify(sql(error), None))?;
    let guard = StepGuard::install(&live_tx, ctx.limits.sql_steps, ctx.cancel)?;
    let result = (|| -> Result<Observation, ReceiptStoreError> {
        let watermark = watermark_i64(&live_tx)?;
        let max_entry: i64 = live_tx.query_row(
            "SELECT COALESCE(MAX(entry_seq), 0) FROM claim_receipt_log_entries",
            [],
            |row| row.get(0),
        )?;
        let head = max_entry.max(watermark);
        // The newest checkpoint, whatever its unsigned coverage columns say:
        // its signed body is authenticated before its range is classified,
        // and must end at or below `head` (see `within_target`).
        let checkpoint: i64 = live_tx.query_row(
            "SELECT COALESCE(MAX(checkpoint_seq), 0) FROM kernel_checkpoints",
            [],
            |row| row.get(0),
        )?;
        let lineage_rowid: i64 = live_tx
            .query_row(
                "SELECT COALESCE(MAX(rowid), 0) FROM capability_lineage",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let max_source_seqs: (i64, i64) = live_tx.query_row(
            "SELECT COALESCE((SELECT MAX(seq) FROM chio_tool_receipts), 0),
                    COALESCE((SELECT MAX(seq) FROM chio_child_receipts), 0)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(Observation {
            head,
            watermark,
            checkpoint,
            lineage_rowid,
            max_source_seqs,
        })
    })()
    .map_err(|error| guard.classify(error));
    drop(guard);
    let _ = live_tx.commit();
    result
}

/// A target's checkpoints cover only claim entries the target observed. The
/// observation takes its newest checkpoint without trusting any unsigned
/// coverage column, so this signed bound is what keeps a covered range from
/// being treated as uncheckpointed tail.
pub(super) fn within_target(checkpoint: &OwnedCheckpoint, head: i64) -> Result<(), WalkError> {
    if checkpoint.batch_end > head {
        return Err(WalkError::Integrity(format!(
            "checkpoint {} covers claim entries through {}, beyond the observed claim log head {head}",
            checkpoint.seq, checkpoint.batch_end
        )));
    }
    Ok(())
}

/// Live source counts and checkpoint projection id statistics read in one
/// transaction: `(count, max id, ids beyond the newest checkpoint)` per table.
struct LiveCounts {
    watermark: i64,
    tools: u64,
    children: u64,
    projections: [(i64, i64, i64); 3],
}

/// Live source rows must be exactly the owned rows located above the
/// watermark. `max_seqs` are the live source maxima pinned in the pass's
/// starting observation: every row at or below them existed at that moment,
/// including any unlogged row past the last logged one, while legitimate
/// appends after the observation lie above them. Owned counts are supplied by
/// the caller from bounded holds.
pub(super) fn verify_source_bijection(
    ctx: &WalkContext<'_>,
    max_seqs: (i64, i64),
    owned_counts_above: &mut dyn FnMut(i64) -> Result<(u64, u64), WalkError>,
    checkpoint_bound: i64,
    expected_witnesses: u64,
) -> Result<(), WalkError> {
    let mut live = live_connection(ctx)?;
    let live_tx = live
        .transaction()
        .map_err(|error| classify(sql(error), None))?;
    let guard = StepGuard::install(&live_tx, ctx.limits.sql_steps, ctx.cancel)?;
    let counted = (|| -> Result<LiveCounts, ReceiptStoreError> {
        let watermark = watermark_i64(&live_tx)?;
        let tools: i64 = live_tx.query_row(
            "SELECT COUNT(*) FROM chio_tool_receipts WHERE seq <= ?1",
            [max_seqs.0],
            |row| row.get(0),
        )?;
        let children: i64 = live_tx.query_row(
            "SELECT COUNT(*) FROM chio_child_receipts WHERE seq <= ?1",
            [max_seqs.1],
            |row| row.get(0),
        )?;
        let mut projections = [(0, 0, 0); 3];
        for (slot, (table, column)) in projections.iter_mut().zip([
            ("checkpoint_tree_heads", "checkpoint_seq"),
            ("checkpoint_predecessor_witnesses", "witness_checkpoint_seq"),
            ("checkpoint_publication_metadata", "checkpoint_seq"),
        ]) {
            *slot = live_tx.query_row(
                &format!(
                    "SELECT (SELECT COUNT(*) FROM {table} WHERE {column} <= ?1),
                            (SELECT COALESCE(MAX({column}), 0) FROM {table} WHERE {column} <= ?1),
                            (SELECT COUNT(*) FROM {table} WHERE {column} > (SELECT COALESCE(MAX(checkpoint_seq), 0) FROM kernel_checkpoints))"
                ),
                [checkpoint_bound],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        }
        Ok(LiveCounts {
            watermark,
            tools: u64::try_from(tools).unwrap_or(0),
            children: u64::try_from(children).unwrap_or(0),
            projections,
        })
    })()
    .map_err(|error| guard.classify(error));
    drop(guard);
    let _ = live_tx.commit();
    let LiveCounts {
        watermark,
        tools: live_tools,
        children: live_children,
        projections,
    } = counted?;
    let (owned_tools, owned_children) = owned_counts_above(watermark)?;
    if (live_tools, live_children) != (owned_tools, owned_children) {
        return Err(WalkError::Integrity(format!(
            "live receipt source rows are not a bijection with the authenticated claim log: {live_tools} tool and {live_children} child rows, {owned_tools} and {owned_children} logged"
        )));
    }
    let bound = checkpoint_bound;
    let expected = [
        (u64::try_from(bound).unwrap_or(0), bound),
        (expected_witnesses, bound),
        (u64::try_from(bound).unwrap_or(0), bound),
    ];
    for ((count, max, beyond), (expected_count, expected_max)) in
        projections.into_iter().zip(expected)
    {
        let max_ok = if expected_count == 0 {
            max == 0
        } else {
            max <= expected_max
        };
        if u64::try_from(count).unwrap_or(u64::MAX) != expected_count || !max_ok || beyond != 0 {
            return Err(WalkError::Integrity(
                "checkpoint projection id sets drift from the persisted checkpoint chain".into(),
            ));
        }
    }
    Ok(())
}

/// One capability lineage row read for subject refresh.
#[derive(Debug)]
pub(super) struct LineageRow {
    pub(super) rowid: i64,
    pub(super) capability_id: String,
    /// The subject the canonical local reader accepts from this row, or why
    /// it refuses the row.
    pub(super) subject: Result<String, String>,
}

/// Read capability lineage rows above `after` for subject refresh through
/// the canonical local decoder and validator, measuring every
/// variable-length column of each row before allocating it.
pub(super) fn copy_lineage(
    ctx: &WalkContext<'_>,
    after: i64,
    through: i64,
    limit: i64,
) -> Result<Vec<LineageRow>, WalkError> {
    let mut connection = live_connection(ctx)?;
    let transaction = connection
        .transaction()
        .map_err(|error| classify(sql(error), None))?;
    let guard = StepGuard::install(&transaction, ctx.limits.sql_steps, ctx.cancel)?;
    let sizes = (|| -> Result<Vec<(i64, u64)>, ReceiptStoreError> {
        let mut statement = transaction.prepare_cached(
            "SELECT rowid,
                    length(CAST(capability_id AS BLOB)) + length(CAST(subject_key AS BLOB))
                    + length(CAST(issuer_key AS BLOB)) + length(CAST(grants_json AS BLOB))
                    + COALESCE(length(CAST(parent_capability_id AS BLOB)), 0)
                    + COALESCE(length(CAST(federated_parent_capability_id AS BLOB)), 0)
                    + COALESCE(length(CAST(provenance AS BLOB)), 0)
                    + COALESCE(length(CAST(signed_capability_json AS BLOB)), 0)
             FROM capability_lineage WHERE rowid > ?1 AND rowid <= ?2 ORDER BY rowid LIMIT ?3",
        )?;
        let rows = statement.query_map(params![after, through, limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                u64::try_from(row.get::<_, i64>(1)?).unwrap_or(u64::MAX),
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })()
    .map_err(|error| guard.classify(error))?;
    let mut last = None;
    let mut bytes = 0_u64;
    for (rowid, length) in sizes {
        if length > ctx.limits.max_receipt_bytes {
            return Err(WalkError::RowCap {
                what: format!("capability lineage rowid {rowid}"),
                bytes: length,
            });
        }
        if last.is_some() && bytes.saturating_add(length) > ctx.limits.step_bytes {
            break;
        }
        bytes = bytes.saturating_add(length);
        last = Some(rowid);
    }
    let Some(last) = last else {
        return Ok(Vec::new());
    };
    let rows = (|| -> Result<Vec<LineageRow>, ReceiptStoreError> {
        // The column order is the canonical reader's, with rowid appended.
        let mut statement = transaction.prepare_cached(
            "SELECT capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json,
                    delegation_depth, parent_capability_id, federated_parent_capability_id,
                    provenance, signed_capability_json, rowid
             FROM capability_lineage WHERE rowid > ?1 AND rowid <= ?2 ORDER BY rowid",
        )?;
        let rows = statement.query_map(params![after, last], |row| {
            Ok(LineageRow {
                rowid: row.get(11)?,
                capability_id: row.get(0)?,
                subject: snapshot_from_row(row)
                    .map(|snapshot| snapshot.subject_key)
                    .map_err(|error| error.to_string()),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })()
    .map_err(|error| guard.classify(error));
    drop(guard);
    let _ = transaction.commit();
    rows
}

/// Bytes of every variable-length column of the lineage row a missing-
/// attribution projection would load, measured without allocating them.
fn lineage_row_bytes(
    connection: &Connection,
    capability_id: &str,
) -> Result<Option<(u64, u64)>, ReceiptStoreError> {
    let bytes: Option<(i64, i64)> = connection
        .prepare_cached(
            "SELECT length(CAST(capability_id AS BLOB)) + length(CAST(subject_key AS BLOB))
                    + length(CAST(issuer_key AS BLOB)) + length(CAST(grants_json AS BLOB))
                    + COALESCE(length(CAST(parent_capability_id AS BLOB)), 0)
                    + COALESCE(length(CAST(federated_parent_capability_id AS BLOB)), 0)
                    + COALESCE(length(CAST(provenance AS BLOB)), 0)
                    + COALESCE(length(CAST(signed_capability_json AS BLOB)), 0),
                    length(CAST(subject_key AS BLOB))
             FROM capability_lineage WHERE capability_id = ?1",
        )?
        .query_row([capability_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?;
    Ok(bytes.map(|(row, subject)| {
        (
            u64::try_from(row).unwrap_or(u64::MAX),
            u64::try_from(subject).unwrap_or(u64::MAX),
        )
    }))
}

/// The entries `check_sources` checked: a prefix of `checked` entries.
pub(super) fn checked_prefix(
    entries: &[AuthenticatedEntry],
    checked: usize,
) -> &[AuthenticatedEntry] {
    entries.get(..checked).unwrap_or(entries)
}

/// Fold copied entries into tool rows, cursors and pending leaves.
pub(super) fn pending_leaves(entries: &[AuthenticatedEntry]) -> Vec<PendingLeaf> {
    entries
        .iter()
        .map(|entry| PendingLeaf {
            entry_seq: entry.row.entry_seq,
            kind: match entry.receipt {
                Authenticated::Tool(_) => KIND_TOOL,
                Authenticated::Child(_) => KIND_CHILD,
            },
            leaf_hash: entry.leaf_hash,
            signer: entry.signer.clone(),
        })
        .collect()
}
