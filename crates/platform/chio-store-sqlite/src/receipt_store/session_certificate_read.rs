//! Complete, independently pinned retained-session tool receipts for certificates.
//!
//! Coverage ends at an authenticated checkpoint in one live/archive snapshot.
//! It says nothing about a session's eventual closure or later appends.

use super::retained_read::{with_retained_connection_snapshot, RetainedSnapshot};
use super::*;
use chio_core::crypto::PublicKey;
use rusqlite::types::ValueRef;

const MAX_SESSION_RECEIPTS: usize = 100_000;
const MAX_SESSION_BYTES: usize = 128 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 1024 * 1024;
const MAX_MEMBERSHIP_BYTES: usize = 16 * 1024 * 1024;
const MAX_MEMBERSHIP_NODES: usize = 1_048_576;
const MAX_AUTHENTICATION_ROWS: usize = 1_000_000;
const MAX_AUTHENTICATION_BYTES: usize = 512 * 1024 * 1024;
const MAX_PROJECTION_BYTES: usize = 64 * 1024;
const MAX_SQL_STEPS: u64 = 100_000_000;
const SQL_PROGRESS_INTERVAL: i32 = 1_000;

/// A stored tool receipt with both original global sequence identities.
#[derive(Debug, Clone)]
pub struct RetainedSessionReceipt {
    /// Sequence in the tool receipt source table, including other sessions.
    pub seq: u64,
    /// Sequence in the claim log, including tool and child receipts.
    pub entry_seq: u64,
    pub receipt: ChioReceipt,
}

/// Complete retained tool history through a pinned, authenticated snapshot boundary.
///
/// This is an observed retained-history boundary, not an authenticated session
/// closure. A later append requires collecting and certifying a fresh snapshot.
/// Child receipts authenticate the claim corpus but are not exported here.
/// Deserializing or constructing this description does not authenticate a
/// collection. Consume the immutable reader-produced `RetainedSessionReceipts`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetainedSessionSnapshotCoverage {
    pub session_id: String,
    /// Authenticated read narrowing. `None` means an explicit admin read.
    pub tenant_id: Option<String>,
    pub snapshot_end_entry_seq: u64,
    pub archived_through_entry_seq: u64,
    /// The authenticated checkpoint whose end equals the snapshot boundary.
    pub checkpoint: KernelCheckpoint,
}

/// Immutable authenticated collector output. Its selected set cannot be
/// changed while preserving the same producer-origin coverage.
///
/// ```compile_fail
/// use chio_store_sqlite::RetainedSessionReceipts;
/// fn remove_row(history: &mut RetainedSessionReceipts) {
///     history.receipts.remove(0);
/// }
/// ```
///
/// ```compile_fail
/// use chio_store_sqlite::RetainedSessionReceipts;
/// fn reorder_rows(history: &RetainedSessionReceipts) {
///     history.receipts().reverse();
/// }
/// ```
///
/// ```compile_fail
/// use chio_store_sqlite::{RetainedSessionReceipts, RetainedSessionSnapshotCoverage};
/// fn forge(coverage: RetainedSessionSnapshotCoverage) -> RetainedSessionReceipts {
///     RetainedSessionReceipts { receipts: Vec::new(), coverage }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RetainedSessionReceipts {
    receipts: Vec<RetainedSessionReceipt>,
    coverage: RetainedSessionSnapshotCoverage,
}

impl RetainedSessionReceipts {
    /// The exact complete selected set produced by the authenticated reader.
    #[must_use]
    pub fn receipts(&self) -> &[RetainedSessionReceipt] {
        &self.receipts
    }

    /// The descriptive boundary of this exact immutable collected set.
    #[must_use]
    pub fn coverage(&self) -> &RetainedSessionSnapshotCoverage {
        &self.coverage
    }
}

#[derive(Clone, Copy)]
struct SessionReadLimits {
    receipts: usize,
    bytes: usize,
    receipt_bytes: usize,
    authentication_rows: usize,
    authentication_bytes: usize,
    sql_steps: u64,
}

impl Default for SessionReadLimits {
    fn default() -> Self {
        Self {
            receipts: MAX_SESSION_RECEIPTS,
            bytes: MAX_SESSION_BYTES,
            receipt_bytes: MAX_RECEIPT_BYTES,
            authentication_rows: MAX_AUTHENTICATION_ROWS,
            authentication_bytes: MAX_AUTHENTICATION_BYTES,
            sql_steps: MAX_SQL_STEPS,
        }
    }
}

struct SessionBudget {
    limits: SessionReadLimits,
    receipts: usize,
    bytes: usize,
}

impl SessionBudget {
    fn new(limits: SessionReadLimits) -> Self {
        Self {
            limits,
            receipts: limits.receipts,
            bytes: limits.bytes,
        }
    }

    fn charge(&mut self, bytes: usize) -> Result<(), ReceiptStoreError> {
        if bytes > self.limits.receipt_bytes {
            return Err(boundary("selected receipt byte limit exceeded"));
        }
        let receipts = self
            .receipts
            .checked_sub(1)
            .ok_or_else(|| boundary("session receipt limit exceeded"))?;
        let bytes = self
            .bytes
            .checked_sub(bytes)
            .ok_or_else(|| boundary("session byte limit exceeded"))?;
        self.receipts = receipts;
        self.bytes = bytes;
        Ok(())
    }
}

/// Collect without opening a serving writer, changing schema or claiming its
/// authority. Selection uses duplicate-aware signed membership, never an
/// unsigned capability/session/tenant index. The entire retained corpus must
/// authenticate against checkpoints signed by the independently supplied key.
///
/// At most 100,000 selected receipts and 128 MiB of their original stored text
/// are returned, with a 1 MiB per-selected-receipt ceiling. Authentication work
/// separately refuses more than 1,000,000 inspected rows, 512 MiB of original
/// text/blob projections, 16 MiB per membership document, 64 KiB per auxiliary
/// projection or 100,000,000 counted SQLite VM steps (1,000-step progress
/// intervals). Exhaustion never returns a prefix.
pub fn collect_retained_session_receipts_read_only(
    path: &Path,
    session_id: &str,
    read_context: &ReceiptReadContext,
    trusted_key: &PublicKey,
) -> Result<RetainedSessionReceipts, ReceiptStoreError> {
    collect_with_limits(
        path,
        session_id,
        read_context,
        trusted_key,
        SessionReadLimits::default(),
        |_| Ok(()),
    )
}

fn collect_with_limits(
    path: &Path,
    session_id: &str,
    read_context: &ReceiptReadContext,
    trusted_key: &PublicKey,
    limits: SessionReadLimits,
    after_authentication: impl FnOnce(&RetainedSnapshot<'_>) -> Result<(), ReceiptStoreError>,
) -> Result<RetainedSessionReceipts, ReceiptStoreError> {
    if session_id.is_empty() || session_id.len() > 1024 || session_id.trim() != session_id {
        return Err(boundary("session identifier is invalid"));
    }
    let scope = ReceiptQuery::default()
        .with_read_context(read_context.clone())
        .effective_read_scope()?;
    let mut connection = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.execute_batch("PRAGMA query_only = ON; PRAGMA busy_timeout = 5000;")?;
    let work = SessionSqlWork::new(limits.sql_steps);
    let mut preflight = SessionPreflight {
        rows: limits.authentication_rows,
        bytes: limits.authentication_bytes,
        session: SessionBudget::new(limits),
        session_id,
        tenant: scope.tenant.as_deref(),
    };
    let result = with_retained_connection_snapshot(
        &mut connection,
        |connection, upper| {
            work.install(connection)?;
            preflight.inspect(connection, upper)
        },
        |snapshot| {
            snapshot.reject_legacy_receipt_omission()?;
            after_authentication(snapshot)?;
            collect_authenticated_snapshot(
                snapshot,
                session_id,
                scope.tenant.as_deref(),
                trusted_key,
                limits,
            )
        },
    );
    if work.exhausted.load(Ordering::Relaxed) {
        Err(boundary(
            "session certificate exhausted its SQL work budget",
        ))
    } else {
        result
    }
}

fn collect_authenticated_snapshot(
    snapshot: &RetainedSnapshot<'_>,
    session_id: &str,
    tenant: Option<&str>,
    trusted_key: &PublicKey,
    limits: SessionReadLimits,
) -> Result<RetainedSessionReceipts, ReceiptStoreError> {
    let checkpoints = load_all_persisted_checkpoint_rows(snapshot.live)?;
    let mut latest = None;
    for row in checkpoints {
        let checkpoint = parse_persisted_checkpoint_row(row)?;
        if &checkpoint.body.kernel_key != trusted_key {
            return Err(boundary(
                "retained checkpoint signer is not the trusted kernel",
            ));
        }
        latest = Some(checkpoint);
    }
    let checkpoint =
        latest.ok_or_else(|| boundary("retained history has no authenticated checkpoint"))?;
    let end = latest_claim_log_entry_seq(snapshot.live)?.max(snapshot.watermark);
    if checkpoint.body.batch_end_seq != end {
        return Err(boundary(
            "retained snapshot has an uncheckpointed live tail",
        ));
    }
    reject_uncommitted_live_sources(snapshot.live)?;

    let mut receipts = Vec::new();
    let mut budget = SessionBudget::new(limits);
    let mut receipt_ids = BTreeSet::new();
    let mut source_sequences = BTreeSet::new();
    for (connection, lower, upper) in [
        (snapshot.archive, 1, snapshot.watermark),
        (
            Some(snapshot.live),
            snapshot.watermark.saturating_add(1),
            end,
        ),
    ] {
        let Some(connection) = connection.filter(|_| lower <= upper) else {
            continue;
        };
        // Start at the checkpoint-authenticated claim corpus. A source-table
        // join alone could silently omit a deleted or changed source row.
        let mut statement = connection.prepare(
            "SELECT entry_seq, source_seq, receipt_id, raw_json
             FROM claim_receipt_log_entries
             WHERE receipt_kind = 'tool_receipt' AND entry_seq >= ?1 AND entry_seq <= ?2
             ORDER BY entry_seq",
        )?;
        let mut rows = statement.query(params![
            sqlite_i64(lower, "session claim lower bound")?,
            sqlite_i64(upper, "session claim upper bound")?
        ])?;
        while let Some(row) = rows.next()? {
            let entry_seq = sqlite_positive_u64(row.get(0)?, "session claim sequence")?;
            let seq = sqlite_positive_u64(row.get(1)?, "session source sequence")?;
            let raw = bounded_text(row.get_ref(3)?, MAX_MEMBERSHIP_BYTES)?;
            let receipt = decode_verified_chio_receipt(raw, "session receipt", Some(entry_seq))?;
            let id = bounded_text(row.get_ref(2)?, MAX_PROJECTION_BYTES)?;
            if receipt.id != id
                || &receipt.kernel_key != trusted_key
                || !receipt_ids.insert(receipt.id.clone())
                || !source_sequences.insert(seq)
            {
                return Err(boundary(
                    "retained receipt identity or signer is inconsistent",
                ));
            }
            validate_source_binding(connection, seq, id, raw, &receipt)?;
            if signed_membership(receipt.metadata.as_ref())? == Some(session_id)
                && tenant.is_none_or(|tenant| receipt.tenant_id.as_deref() == Some(tenant))
            {
                budget.charge(raw.len())?;
                receipts.push(RetainedSessionReceipt {
                    seq,
                    entry_seq,
                    receipt,
                });
            }
        }
    }
    if receipts.is_empty() {
        return Err(boundary(
            "retained session has no receipts in the authorized snapshot",
        ));
    }
    Ok(RetainedSessionReceipts {
        receipts,
        coverage: RetainedSessionSnapshotCoverage {
            session_id: session_id.to_owned(),
            tenant_id: tenant.map(str::to_owned),
            snapshot_end_entry_seq: end,
            archived_through_entry_seq: snapshot.watermark,
            checkpoint,
        },
    })
}

fn validate_source_binding(
    connection: &Connection,
    seq: u64,
    id: &str,
    raw: &str,
    receipt: &ChioReceipt,
) -> Result<(), ReceiptStoreError> {
    let matches: bool = connection.query_row(
        "SELECT COUNT(*) = 1 AND COALESCE(MIN(receipt_id = ?2 AND raw_json = ?3
         AND tenant_id IS ?4), 0) FROM chio_tool_receipts WHERE seq = ?1",
        params![
            sqlite_i64(seq, "session source sequence")?,
            id,
            raw,
            receipt.tenant_id
        ],
        |row| row.get(0),
    )?;
    if matches {
        Ok(())
    } else {
        Err(boundary(
            "retained receipt source differs from its authenticated claim",
        ))
    }
}

fn reject_uncommitted_live_sources(connection: &Connection) -> Result<(), ReceiptStoreError> {
    for (table, kind) in [
        ("chio_tool_receipts", "tool_receipt"),
        ("chio_child_receipts", "child_receipt"),
    ] {
        let orphan: bool = connection.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table} r WHERE NOT EXISTS
            (SELECT 1 FROM claim_receipt_log_entries e WHERE e.receipt_kind = ?1
             AND e.source_seq = r.seq AND e.receipt_id = r.receipt_id AND e.raw_json = r.raw_json))"),
            [kind],
            |row| row.get(0),
        )?;
        if orphan {
            return Err(boundary(
                "live receipt source is absent from the authenticated claim corpus",
            ));
        }
    }
    Ok(())
}

fn signed_membership(
    metadata: Option<&serde_json::Value>,
) -> Result<Option<&str>, ReceiptStoreError> {
    let Some(metadata) = metadata.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let metadata = metadata
        .as_object()
        .ok_or_else(|| boundary("session metadata must be an object"))?;
    let member = |container, field| {
        metadata
            .get(container)
            .map(|value| {
                value
                    .as_object()
                    .ok_or_else(|| boundary("session membership container must be an object"))?
                    .get(field)
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| boundary("session membership must be text"))
                    })
                    .transpose()
            })
            .transpose()
            .map(Option::flatten)
    };
    let acp = member("acp", "sessionId")?;
    let context = member("receipt_context", "session_id")?;
    let refusal = member("protocol_refusal", "session_id")?;
    if metadata.get("protocol_refusal").is_some_and(|value| {
        value.get("schema").and_then(serde_json::Value::as_str)
            != Some("chio.session.protocol-refusal.v1")
    }) {
        return Err(boundary("signed protocol refusal schema is invalid"));
    }
    let mut membership = None;
    for value in [acp, context, refusal].into_iter().flatten() {
        if membership.is_some_and(|expected| expected != value) {
            return Err(boundary("signed session membership fields conflict"));
        }
        membership = Some(value);
    }
    Ok(membership)
}

fn bounded_text(value: ValueRef<'_>, maximum: usize) -> Result<&str, ReceiptStoreError> {
    match value {
        ValueRef::Text(bytes) if bytes.len() <= maximum => std::str::from_utf8(bytes)
            .map_err(|source| chio_core::canonical::UntrustedJsonError::NotUtf8(source).into()),
        _ => Err(boundary("retained source is not bounded text")),
    }
}

fn boundary(message: &str) -> ReceiptStoreError {
    ReceiptStoreError::ReadBoundary(message.to_owned())
}

#[path = "session_certificate_read/preflight.rs"]
mod preflight;
use preflight::{SessionPreflight, SessionSqlWork};

#[cfg(test)]
#[path = "session_certificate_read/tests.rs"]
mod tests;
