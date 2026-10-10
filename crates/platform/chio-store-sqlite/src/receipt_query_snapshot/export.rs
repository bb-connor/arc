//! Bounded HTTP export from one authenticated snapshot generation. Local
//! operator exports retain the deliberate full-corpus implementation.
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use chio_core::canonical::canonical_json_bytes;
use chio_kernel::checkpoint::{CheckpointTransparencySummary, KernelCheckpoint};
use chio_kernel::evidence_export::{
    EvidenceExportBundle, EvidenceExportError, EvidenceExportQuery, EvidenceRetentionMetadata,
    EvidenceToolReceiptRecord,
};
use chio_kernel::{ReceiptQuerySnapshotError, ReceiptSnapshotWatermark, ReceiptStoreError};
use sha2::{Digest, Sha256};

use super::db::SnapshotDb;
use super::fetch::{fetch, FetchError, FetchLimits};
use super::query::{read_outcome, select_for_export, SelectedRow, Selection};
use super::service::{Meta, Published, ReceiptQuerySnapshots};
use crate::evidence_export::http_budget::{refuse, ByteBudget, HTTP_EVIDENCE_EXPORT_MAX_BYTES};
use crate::receipt_store::support::SqlWorkBudget;

#[path = "export/metadata.rs"]
mod metadata;
#[path = "export/proofs.rs"]
mod proofs;
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Test fixtures deliberately fail on violated setup invariants."
)]
#[path = "export/tests.rs"]
mod tests;

#[derive(Clone, Copy)]
struct Limits {
    receipts: u64,
    bytes: u64,
    checkpoints: i64,
    proof_leaves: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            receipts: 4_096,
            bytes: HTTP_EVIDENCE_EXPORT_MAX_BYTES,
            checkpoints: 4_096,
            proof_leaves: 131_072,
        }
    }
}

pub(super) fn checkpoint_digest(
    checkpoint: &KernelCheckpoint,
) -> Result<[u8; 32], ReceiptStoreError> {
    let bytes = canonical_json_bytes(checkpoint)
        .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(b"chio.receipt-query-snapshot.checkpoint.v1\0");
    digest.update(bytes);
    Ok(digest.finalize().into())
}

struct Lease<'a> {
    snapshots: &'a ReceiptQuerySnapshots,
    published: Arc<Published>,
    meta: Meta,
    epoch: u64,
    watermark: ReceiptSnapshotWatermark,
    unsigned_subjects: BTreeMap<i64, i64>,
}

impl Lease<'_> {
    fn check(&self) -> Result<(), ReceiptStoreError> {
        self.snapshots.inner.recheck_lease(self.epoch)?;
        self.read(|_| Ok(()))
    }

    /// One bounded read of the owned projection. No source transaction spans
    /// it. Selection was captured in one generation; later reads use only
    /// immutable rows and the serving lineage fences every step and return.
    fn read<T>(
        &self,
        work: impl FnOnce(&SnapshotDb) -> Result<T, ReceiptStoreError>,
    ) -> Result<T, ReceiptStoreError> {
        self.snapshots.inner.recheck_lease(self.epoch)?;
        self.snapshots.inner.waiting.fetch_add(1, Ordering::SeqCst);
        let owned = self.published.owned.lock();
        self.snapshots.inner.waiting.fetch_sub(1, Ordering::SeqCst);
        let result = (|| {
            let owned = owned.map_err(|_| invalid("receipt query snapshot lock poisoned"))?;
            let budget = SqlWorkBudget::new_for(
                owned.db.connection()?,
                self.snapshots.inner.config.query_sql_steps,
                "HTTP evidence export projection",
            )?;
            let result = work(&owned.db);
            let exhausted = budget.exhausted();
            drop(budget);
            if exhausted {
                return Err(refuse("HTTP evidence export projection"));
            }
            result
        })();
        self.snapshots
            .inner
            .owned_read(&self.published, result.map_err(read_outcome))
    }

    fn invalid<T>(&self, reason: impl Into<String>) -> Result<T, ReceiptStoreError> {
        self.snapshots
            .inner
            .owned_read(&self.published, Err(invalid(reason)))
    }
}

fn invalid(reason: impl Into<String>) -> ReceiptStoreError {
    ReceiptQuerySnapshotError::Invalid(reason.into()).into()
}

impl ReceiptQuerySnapshots {
    /// Build an HTTP-sized evidence bundle from one authenticated generation.
    /// Selection and proofs never reauthenticate the retained corpus. Receipt
    /// payloads still verify against owned leaves, including after rotation.
    ///
    /// Live retention diagnostics are unavailable for this snapshot operation
    /// and are returned as `None`; local full exports retain those diagnostics.
    /// A required genesis checkpoint prefix beyond 4096 records cannot be
    /// reduced by narrowing a recent query; use local operator export until an
    /// anchored or paginated evidence format is available.
    pub fn build_evidence_export_bundle_with_transparency(
        &self,
        query: &EvidenceExportQuery,
    ) -> Result<
        (
            EvidenceExportBundle,
            CheckpointTransparencySummary,
            ReceiptSnapshotWatermark,
        ),
        EvidenceExportError,
    > {
        self.build_export(query, Limits::default())
    }

    fn build_export(
        &self,
        query: &EvidenceExportQuery,
        limits: Limits,
    ) -> Result<
        (
            EvidenceExportBundle,
            CheckpointTransparencySummary,
            ReceiptSnapshotWatermark,
        ),
        EvidenceExportError,
    > {
        query.validate_read_boundary()?;
        let query = query.normalized_for_read_boundary();
        let _permit = self.inner.admit()?;
        let (published, epoch) = self.inner.ready()?;
        self.inner.await_head(&published, false)?;
        let capture = (|| {
            let owned = published
                .owned
                .lock()
                .map_err(|_| invalid("receipt query snapshot lock poisoned"))?;
            let selection = select_for_export(
                &owned.db,
                &query.as_receipt_query(None),
                self.inner.config.query_sql_steps,
                limits.receipts,
            )?;
            let budget = SqlWorkBudget::new_for(
                owned.db.connection()?,
                self.inner.config.query_sql_steps,
                "HTTP evidence export capture",
            )?;
            let capture = (|| {
                let children = metadata::select_children(
                    &owned.db,
                    &query,
                    query.child_receipt_scope(),
                    limits.receipts - selection.total_count,
                )?;
                let mut subjects = BTreeMap::new();
                let mut statement = owned.db.connection()?.prepare_cached("SELECT subject FROM snapshot_tool_receipt WHERE entry_seq = ?1 AND subject_signed = 0")?;
                for row in &selection.rows {
                    use rusqlite::OptionalExtension;
                    if let Some(subject) = statement
                        .query_row([row.entry_seq], |row| row.get::<_, i64>(0))
                        .optional()?
                    {
                        subjects.insert(row.entry_seq, subject);
                    }
                }
                Ok::<_, ReceiptStoreError>((children, subjects))
            })();
            let exhausted = budget.exhausted();
            drop(budget);
            if exhausted {
                return Err(refuse("HTTP evidence export capture"));
            }
            let (children, subjects) = capture?;
            Ok::<_, ReceiptStoreError>((
                owned.meta,
                published.watermark_of(&owned.meta),
                selection,
                children,
                subjects,
            ))
        })();
        let (meta, watermark, selection, children, unsigned_subjects) =
            self.inner.owned_read(&published, capture)?;
        let lease = Lease {
            snapshots: self,
            published,
            meta,
            epoch,
            watermark,
            unsigned_subjects,
        };
        #[cfg(test)]
        tests::after_selection(lease.watermark.through_entry_seq);
        let mut bytes = ByteBudget::new(limits.bytes);
        bytes.charge(&query)?;
        metadata::reject_legacy(&lease)?;
        let tools = collect_tools(&lease, selection, &mut bytes)?;
        let child_scope = query.child_receipt_scope();
        let children = metadata::children(&lease, &children, &mut bytes)?;
        let (checkpoints, transparency) =
            metadata::checkpoints(&lease, &tools, limits.checkpoints, &mut bytes)?;
        let lineage = metadata::lineage(&lease, &tools, &mut bytes)?;
        let (inclusion_proofs, uncheckpointed_receipts) = proofs::collect(
            &lease,
            &tools,
            &checkpoints,
            limits.proof_leaves,
            &mut bytes,
        )?;
        let bundle = EvidenceExportBundle {
            query,
            tool_receipts: tools,
            child_receipts: children,
            child_receipt_scope: child_scope,
            checkpoints,
            capability_lineage: lineage,
            inclusion_proofs,
            uncheckpointed_receipts,
            retention: EvidenceRetentionMetadata {
                live_db_size_bytes: None,
                oldest_live_receipt_timestamp: None,
            },
        };
        // Record accounting prevents unbounded retained materialization; this
        // last check includes container overhead and derived transparency.
        let mut total = ByteBudget::new(limits.bytes);
        total.charge(&(&bundle, &transparency, &lease.watermark))?;
        lease.check()?;
        Ok((bundle, transparency, lease.watermark))
    }
}

fn collect_tools(
    lease: &Lease<'_>,
    selection: Selection,
    bytes: &mut ByteBudget,
) -> Result<Vec<EvidenceToolReceiptRecord>, ReceiptStoreError> {
    let mut records = Vec::new();
    let config = &lease.snapshots.inner.config;
    for rows in selection.rows.chunks(chio_kernel::MAX_QUERY_LIMIT) {
        let mut pending: &[SelectedRow] = rows;
        while !pending.is_empty() {
            lease.check()?;
            let page = match fetch(&lease.snapshots.inner.store, pending, selection.tenant.as_deref(), FetchLimits {
                page_bytes: config.page_bytes.min(bytes.remaining()),
                max_receipt_bytes: config.max_receipt_bytes.min(bytes.remaining()),
                sql_steps: config.fetch_sql_steps,
            }) {
                Ok(page) => page,
                Err(FetchError::Mismatch(reason)) => return lease.invalid(reason),
                Err(FetchError::RowCap { entry_seq, bytes: length }) if length > config.max_receipt_bytes => return lease.invalid(format!("authenticated claim entry {entry_seq} exceeds its source row limit")),
                Err(FetchError::RowCap { .. }) => return Err(refuse("HTTP evidence export byte allowance; narrow the selected receipts or use local operator export")),
                Err(FetchError::Budget) => return Err(refuse("HTTP evidence export payload fetch")),
                Err(FetchError::Store(error)) => return Err(read_outcome(error)),
            };
            let fetched = page.receipts.len();
            if fetched == 0 {
                return lease.invalid("authenticated evidence fetch omitted its selected rows");
            }
            for (stored, selected) in page.receipts.into_iter().zip(pending) {
                let record = EvidenceToolReceiptRecord {
                    seq: crate::receipt_store::sqlite_u64(
                        selected.entry_seq,
                        "export claim entry sequence",
                    )?,
                    receipt: stored.receipt,
                };
                bytes.charge(&record)?;
                records.push(record);
            }
            pending = match pending.get(fetched..) {
                Some(remaining) => remaining,
                None => {
                    return lease.invalid("authenticated evidence fetch exceeded its selected rows")
                }
            };
        }
    }
    if crate::integer::count(records.len()) != selection.total_count {
        return lease.invalid("authenticated evidence selection did not reproduce its count");
    }
    Ok(records)
}
