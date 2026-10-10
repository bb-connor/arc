//! Short, budgeted metadata/payload reads. Mutable checkpoint bytes must
//! reproduce the owned checkpoint digest; current capability lineage uses its
//! canonical validated reader and must preserve owned unsigned attribution.
use std::collections::{BTreeMap, BTreeSet};

use chio_core::receipt::lineage::ChildRequestReceipt;
use chio_kernel::capability_lineage::CapabilitySnapshot;
use chio_kernel::checkpoint::{
    validate_checkpoint_transparency, CheckpointTransparencySummary, KernelCheckpoint,
};
use chio_kernel::evidence_export::{
    EvidenceChildReceiptRecord, EvidenceChildReceiptScope, EvidenceExportQuery,
    EvidenceToolReceiptRecord,
};
use chio_kernel::{ReceiptQuerySnapshotError, ReceiptStoreError};
use rusqlite::{params, Connection, OptionalExtension};

use super::{checkpoint_digest, invalid, Lease};
use crate::evidence_export::http_budget::{refuse, ByteBudget};
use crate::receipt_query_snapshot::db::{blob32, ABSENT, DIM_CAPABILITY};
use crate::receipt_query_snapshot::query::{read_outcome, snapshot_error};
use crate::receipt_store::support::{
    latest_watermark_archive_path, retention_watermark, SqlWorkBudget,
};
use crate::receipt_store::SqliteReceiptStore;

const CHUNK: i64 = 128;

/// Mutable export metadata may be unusable without contradicting anything the
/// owned snapshot authenticated. Refuse this request without dropping serving
/// custody for other tenants, as the local full export reader does.
fn metadata_refusal(reason: impl Into<String>) -> ReceiptStoreError {
    ReceiptQuerySnapshotError::ExportRefused(reason.into()).into()
}

fn live_read<T>(
    lease: &Lease<'_>,
    read: impl FnOnce(&Connection) -> Result<T, ReceiptStoreError>,
) -> Result<T, ReceiptStoreError> {
    lease.check()?;
    let result = (|| {
        let mut live = lease.snapshots.inner.store.connection()?;
        let tx = live.transaction()?;
        let budget = SqlWorkBudget::new_for(
            &tx,
            lease.snapshots.inner.config.fetch_sql_steps,
            "HTTP evidence export metadata",
        )?;
        let result = read(&tx);
        let exhausted = budget.exhausted();
        drop(budget);
        let _ = tx.commit();
        if exhausted {
            return Err(refuse("HTTP evidence export metadata"));
        }
        result.map_err(read_outcome)
    })();
    lease.snapshots.inner.owned_read(&lease.published, result)
}

pub(super) fn reject_legacy(lease: &Lease<'_>) -> Result<(), ReceiptStoreError> {
    live_read(lease, |live| {
        for table in ["http_receipts", "tool_receipts", "chio_receipts"] {
            let present: bool = live.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )?;
            if present
                && live.query_row(
                    &format!("SELECT EXISTS(SELECT 1 FROM {table})"),
                    [],
                    |row| row.get::<_, bool>(0),
                )?
            {
                return Err(metadata_refusal("legacy mutable receipt history cannot be exported as authenticated evidence; preserve the original database and use a new evidence database"));
            }
        }
        Ok(())
    })
}

#[derive(Clone)]
pub(super) struct SelectedChild {
    source_seq: i64,
    entry_seq: i64,
    leaf_hash: [u8; 32],
    ts: i64,
}

pub(super) fn select_children(
    db: &crate::receipt_query_snapshot::db::SnapshotDb,
    query: &EvidenceExportQuery,
    scope: EvidenceChildReceiptScope,
    remaining: u64,
) -> Result<Vec<SelectedChild>, ReceiptStoreError> {
    if scope == EvidenceChildReceiptScope::OmittedNoJoinPath {
        return Ok(Vec::new());
    }
    let since = query
        .since
        .map(crate::integer::checked::<_, i64>)
        .transpose()?
        .unwrap_or(0);
    let until = query
        .until
        .map(crate::integer::checked::<_, i64>)
        .transpose()?
        .unwrap_or(i64::MAX);
    let count = db.connection()?.query_row("SELECT COUNT(*) FROM (SELECT 1 FROM snapshot_child_cursor INDEXED BY sq_child_ts WHERE ts >= ?1 AND ts <= ?2 LIMIT ?3)", params![since, until, crate::integer::checked::<_, i64>(remaining + 1)?], |row| row.get::<_, i64>(0))?;
    if crate::receipt_store::sqlite_u64(count, "export child count")? > remaining {
        return Err(refuse("HTTP evidence export receipt allowance; narrow the selected receipts or use local operator export"));
    }
    let mut statement = db.connection()?.prepare_cached("SELECT source_seq, entry_seq, leaf_hash, ts FROM snapshot_child_cursor INDEXED BY sq_child_ts WHERE ts >= ?1 AND ts <= ?2 ORDER BY source_seq")?;
    let rows = statement.query_map(params![since, until], |row| {
        Ok(SelectedChild {
            source_seq: row.get(0)?,
            entry_seq: row.get(1)?,
            leaf_hash: blob32(row.get::<_, Vec<u8>>(2)?)?,
            ts: row.get(3)?,
        })
    })?;
    let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    if crate::integer::count(rows.len()) != crate::receipt_store::sqlite_u64(count, "child count")?
    {
        return Err(invalid(
            "authenticated evidence child selection did not reproduce its count",
        ));
    }
    Ok(rows)
}

pub(super) fn children(
    lease: &Lease<'_>,
    selected: &[SelectedChild],
    bytes: &mut ByteBudget,
) -> Result<Vec<EvidenceChildReceiptRecord>, ReceiptStoreError> {
    let mut records = Vec::new();
    for rows in selected.chunks(crate::integer::checked::<_, usize>(CHUNK)?) {
        let mut pending = rows;
        while !pending.is_empty() {
            let copied = copy_children(lease, pending, bytes.remaining())?;
            let fetched = copied.len();
            if fetched == 0 {
                return lease
                    .invalid("authenticated child evidence fetch omitted its selected rows");
            }
            for (row, raw) in copied {
                let decoded = (|| {
                    let receipt: ChildRequestReceipt =
                        crate::receipt_store::decode_verified_child_receipt(
                            &raw,
                            "snapshot evidence child receipt",
                            Some(crate::receipt_store::sqlite_u64(
                                row.source_seq,
                                "child source sequence",
                            )?),
                        )
                        .map_err(|error| invalid(error.to_string()))?;
                    let canonical = chio_core::canonical::canonical_json_bytes(&receipt)
                        .map_err(|error| invalid(error.to_string()))?;
                    if *chio_core::merkle::leaf_hash(&canonical).as_bytes() != row.leaf_hash
                        || receipt.timestamp
                            != crate::receipt_store::sqlite_u64(row.ts, "child timestamp")?
                    {
                        return Err(invalid(format!("claim entry {} no longer holds the child receipt the snapshot authenticated", row.entry_seq)));
                    }
                    Ok(receipt)
                })();
                let receipt = lease
                    .snapshots
                    .inner
                    .owned_read(&lease.published, decoded)?;
                let record = EvidenceChildReceiptRecord {
                    seq: crate::receipt_store::sqlite_u64(row.source_seq, "child source sequence")?,
                    receipt,
                };
                bytes.charge(&record)?;
                records.push(record);
            }
            pending = match pending.get(fetched..) {
                Some(remaining) => remaining,
                None => {
                    return lease
                        .invalid("authenticated child evidence fetch exceeded its selected rows")
                }
            };
            lease.check()?;
        }
    }
    Ok(records)
}

fn copy_children(
    lease: &Lease<'_>,
    rows: &[SelectedChild],
    remaining: u64,
) -> Result<Vec<(SelectedChild, String)>, ReceiptStoreError> {
    live_read(lease, |live| {
        let watermark = retention_watermark(live)?.unwrap_or(0);
        let archive = if rows
            .iter()
            .any(|row| row.entry_seq.unsigned_abs() <= watermark)
        {
            let path = latest_watermark_archive_path(live)?
                .ok_or_else(|| invalid("retention watermark names no archive"))?;
            let archive = Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            archive.busy_timeout(lease.snapshots.inner.config.walker_busy_timeout)?;
            archive.execute_batch("BEGIN DEFERRED")?;
            Some(archive)
        } else {
            None
        };
        let budget = archive
            .as_ref()
            .map(|archive| {
                SqlWorkBudget::new_for(
                    archive,
                    lease.snapshots.inner.config.fetch_sql_steps,
                    "HTTP evidence export archived children",
                )
            })
            .transpose()?;
        let result = (|| {
            let mut copied = Vec::new();
            let mut used = 0_u64;
            for row in rows {
                let source = match (row.entry_seq.unsigned_abs() <= watermark, archive.as_ref()) {
                    (true, Some(archive)) => archive,
                    _ => live,
                };
                let found: Option<(bool, i64)> = source.query_row("SELECT receipt_kind = 'child_receipt', length(CAST(raw_json AS BLOB)) FROM claim_receipt_log_entries WHERE entry_seq = ?1", [row.entry_seq], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
                let Some((true, length)) = found else {
                    return Err(invalid(format!(
                        "authenticated child claim entry {} is missing or changed",
                        row.entry_seq
                    )));
                };
                let length = crate::receipt_store::sqlite_u64(length, "child payload bytes")?;
                if length > lease.snapshots.inner.config.max_receipt_bytes {
                    return Err(invalid(
                        "authenticated child payload exceeds its source row limit",
                    ));
                }
                if length > remaining.saturating_sub(used) {
                    return Err(refuse("HTTP evidence export byte allowance; narrow the selected receipts or use local operator export"));
                }
                if !copied.is_empty()
                    && used.saturating_add(length) > lease.snapshots.inner.config.page_bytes
                {
                    break;
                }
                let raw = source.query_row(
                    "SELECT raw_json FROM claim_receipt_log_entries WHERE entry_seq = ?1",
                    [row.entry_seq],
                    |r| r.get::<_, String>(0),
                )?;
                used += length;
                copied.push((row.clone(), raw));
            }
            Ok(copied)
        })();
        let exhausted = budget.as_ref().is_some_and(|budget| budget.exhausted());
        drop(budget);
        if let Some(archive) = &archive {
            let _ = archive.execute_batch("COMMIT");
        }
        if exhausted {
            return Err(refuse("HTTP evidence export archived children"));
        }
        result
    })
}

pub(super) fn checkpoints(
    lease: &Lease<'_>,
    tools: &[EvidenceToolReceiptRecord],
    limit: i64,
    bytes: &mut ByteBudget,
) -> Result<(Vec<KernelCheckpoint>, CheckpointTransparencySummary), ReceiptStoreError> {
    let (Some(first), Some(last)) = (tools.first(), tools.last()) else {
        return Ok((Vec::new(), CheckpointTransparencySummary::default()));
    };
    let high = lease.read(|db| {
        let candidate: Option<(i64, i64)> = db.connection()?.query_row("SELECT seq, batch_end FROM snapshot_checkpoint INDEXED BY sq_checkpoint_start WHERE batch_start <= ?1 AND seq <= ?2 ORDER BY batch_start DESC LIMIT 1", params![crate::integer::checked::<_, i64>(last.seq)?, lease.meta.checkpoint_seq], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
        Ok(candidate.filter(|(_, end)| *end >= i64::try_from(first.seq).unwrap_or(i64::MAX)).map(|(seq, _)| seq).unwrap_or(0))
    })?;
    if high > limit {
        return Err(refuse(format!("HTTP evidence export requires a genesis checkpoint prefix exceeding {limit} records; narrowing a recent query cannot reduce this prefix; use local operator export until anchored or paginated exports are available")));
    }
    let mut checkpoints = Vec::new();
    for seq in 1..=high {
        let authenticated = match lease
            .read(|db| db.load_checkpoint(seq).map_err(snapshot_error))?
        {
            Some(checkpoint) => checkpoint,
            None => {
                return lease.invalid(format!("authenticated checkpoint prefix is missing {seq}"))
            }
        };
        let checkpoint = live_read(lease, |live| {
            let length: Option<i64> = live.query_row("SELECT length(CAST(merkle_root AS BLOB)) + length(CAST(statement_json AS BLOB)) + length(CAST(signature AS BLOB)) + length(CAST(kernel_key AS BLOB)) + COALESCE(length(CAST(previous_checkpoint_sha256 AS BLOB)), 0) FROM kernel_checkpoints WHERE checkpoint_seq = ?1", [seq], |row| row.get(0)).optional()?;
            let length = length
                .ok_or_else(|| invalid(format!("authenticated checkpoint {seq} is missing")))?;
            bytes.preflight(crate::receipt_store::sqlite_u64(
                length,
                "checkpoint bytes",
            )?)?;
            let row = crate::receipt_store::support::load_persisted_checkpoint_row(
                live,
                crate::receipt_store::sqlite_u64(seq, "checkpoint sequence")?,
            )?
            .ok_or_else(|| invalid(format!("authenticated checkpoint {seq} is missing")))?;
            let checkpoint = crate::receipt_store::support::parse_persisted_checkpoint_row(row)
                .map_err(|error| invalid(error.to_string()))?;
            if checkpoint_digest(&checkpoint)? != authenticated.canonical_sha256 {
                return Err(invalid(format!("checkpoint {seq} no longer holds the signed checkpoint the snapshot authenticated")));
            }
            Ok(checkpoint)
        })?;
        bytes.charge(&checkpoint)?;
        checkpoints.push(checkpoint);
    }
    let mut summary = validate_checkpoint_transparency(&checkpoints)
        .map_err(|error| metadata_refusal(error.to_string()))?;
    for publication in &mut summary.publications {
        let partial = CheckpointTransparencySummary {
            publications: vec![publication.clone()],
            ..CheckpointTransparencySummary::default()
        };
        let enriched = live_read(lease, |live| {
            let core_bytes: Option<i64> = live.query_row("SELECT length(CAST(publication_schema AS BLOB)) + length(CAST(merkle_root AS BLOB)) + length(CAST(kernel_key AS BLOB)) + COALESCE(length(CAST(previous_checkpoint_sha256 AS BLOB)), 0) FROM checkpoint_publication_metadata WHERE checkpoint_seq = ?1", [crate::integer::checked::<_, i64>(publication.checkpoint_seq)?], |row| row.get(0)).optional()?;
            let core_bytes = core_bytes
                .map(|n| crate::receipt_store::sqlite_u64(n, "publication metadata bytes"))
                .transpose()?
                .unwrap_or(0);
            let binding_bytes: Option<i64> = live.query_row("SELECT length(CAST(binding_json AS BLOB)) FROM checkpoint_publication_trust_anchor_bindings WHERE checkpoint_seq = ?1", [crate::integer::checked::<_, i64>(publication.checkpoint_seq)?], |row| row.get(0)).optional()?;
            let binding_bytes = binding_bytes
                .map(|n| crate::receipt_store::sqlite_u64(n, "publication binding bytes"))
                .transpose()?
                .unwrap_or(0);
            bytes.preflight(core_bytes.saturating_add(binding_bytes))?;
            SqliteReceiptStore::enrich_transparency_on_connection(live, partial).map_err(|error| {
                match error {
                    chio_kernel::evidence_export::EvidenceExportError::ReceiptStore(
                        ReceiptStoreError::Conflict(reason),
                    ) => metadata_refusal(reason),
                    chio_kernel::evidence_export::EvidenceExportError::ReceiptStore(error) => error,
                    error => metadata_refusal(error.to_string()),
                }
            })
        })?;
        *publication = enriched.publications.into_iter().next().ok_or_else(|| {
            metadata_refusal("checkpoint publication enrichment omitted its record")
        })?;
        bytes.charge(publication)?;
    }
    Ok((checkpoints, summary))
}

const LINEAGE_COLUMNS: &str = "capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth, parent_capability_id, federated_parent_capability_id, provenance, signed_capability_json";
const LINEAGE_BYTES: &str = "length(CAST(capability_id AS BLOB)) + length(CAST(subject_key AS BLOB)) + length(CAST(issuer_key AS BLOB)) + length(CAST(grants_json AS BLOB)) + COALESCE(length(CAST(parent_capability_id AS BLOB)), 0) + COALESCE(length(CAST(federated_parent_capability_id AS BLOB)), 0) + COALESCE(length(CAST(provenance AS BLOB)), 0) + COALESCE(length(CAST(signed_capability_json AS BLOB)), 0)";

pub(super) fn lineage(
    lease: &Lease<'_>,
    tools: &[EvidenceToolReceiptRecord],
    bytes: &mut ByteBudget,
) -> Result<Vec<CapabilitySnapshot>, ReceiptStoreError> {
    let mut records = BTreeMap::<String, CapabilitySnapshot>::new();
    for tool in tools {
        let mut current = Some(tool.receipt.capability_id.clone());
        let mut chain = BTreeSet::new();
        while let Some(capability) = current.take() {
            if !chain.insert(capability.clone()) || chain.len() > 32 {
                return Err(metadata_refusal(
                    "export capability lineage contains a cycle or exceeds 32 records",
                ));
            }
            if let Some(cached) = records.get(&capability) {
                current = cached
                    .parent_capability_id
                    .clone()
                    .or_else(|| cached.federated_parent_capability_id.clone());
                continue;
            }
            let snapshot = live_read(lease, |live| {
                let mut table = "capability_lineage";
                let mut key = None;
                let local_bytes: Option<i64> = live.query_row(&format!("SELECT {LINEAGE_BYTES} FROM capability_lineage WHERE capability_id = ?1"), [&capability], |row| row.get(0)).optional()?;
                let length = match local_bytes {
                    Some(length) => length,
                    None => {
                        // Preserve the canonical latest-share choice without
                        // reading the unrelated share's receipt/lineage counts.
                        let row: Option<(i64, i64)> = live.query_row(&format!("SELECT l.rowid, length(CAST(l.share_id AS BLOB)) + {qualified} FROM federated_share_capability_lineage l JOIN federated_evidence_shares s ON s.share_id = l.share_id WHERE l.capability_id = ?1 ORDER BY s.imported_at DESC, s.share_id DESC LIMIT 1", qualified = LINEAGE_BYTES.replace("CAST(", "CAST(l.")), [&capability], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
                        let Some((share, length)) = row else {
                            return Ok(None);
                        };
                        table = "federated_share_capability_lineage";
                        key = Some(share);
                        length
                    }
                };
                bytes.preflight(crate::receipt_store::sqlite_u64(
                    length,
                    "capability lineage bytes",
                )?)?;
                let sql = format!(
                    "SELECT {LINEAGE_COLUMNS} FROM {table} WHERE capability_id = ?1{}",
                    if key.is_some() { " AND rowid = ?2" } else { "" }
                );
                let snapshot = if let Some(share) = key {
                    live.query_row(
                        &sql,
                        params![capability, share],
                        crate::capability_lineage::snapshot_from_row,
                    )?
                } else {
                    live.query_row(
                        &sql,
                        [&capability],
                        crate::capability_lineage::snapshot_from_row,
                    )?
                };
                snapshot
                    .validate_for_transport()
                    .map_err(|error| match error {
                        ReceiptStoreError::Conflict(reason) => metadata_refusal(reason),
                        other => other,
                    })?;
                Ok(Some(snapshot))
            })?;
            let Some(snapshot) = snapshot else {
                if chain.len() > 1 {
                    return Err(metadata_refusal(
                        "export capability lineage references a missing parent",
                    ));
                }
                // A missing first capability preserves the old empty-lineage
                // semantics only when selection knew no unsigned subject. A
                // captured attribution cannot silently lose its current proof.
                for tool in tools
                    .iter()
                    .filter(|tool| tool.receipt.capability_id == capability)
                {
                    let entry = crate::integer::checked::<_, i64>(tool.seq)?;
                    if lease
                        .unsigned_subjects
                        .get(&entry)
                        .is_some_and(|subject| *subject != ABSENT)
                    {
                        return lease.invalid(
                            "export capability lineage is missing required unsigned attribution",
                        );
                    }
                }
                break;
            };
            let subject_matches = lease.read(|db| {
                let Some(_) = db.dim_id(DIM_CAPABILITY, &capability) else {
                    return Ok(true);
                };
                for tool in tools
                    .iter()
                    .filter(|tool| tool.receipt.capability_id == capability)
                {
                    let entry = crate::integer::checked::<_, i64>(tool.seq)?;
                    if let Some(subject) = lease.unsigned_subjects.get(&entry) {
                        if db
                            .dim_value(*subject)
                            .map_err(snapshot_error)?
                            .is_some_and(|subject| subject != snapshot.subject_key)
                        {
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            })?;
            if !subject_matches {
                return lease.invalid("current unsigned capability attribution differs from the authenticated snapshot");
            }
            current = snapshot
                .parent_capability_id
                .clone()
                .or_else(|| snapshot.federated_parent_capability_id.clone());
            bytes.charge(&snapshot)?;
            records.insert(snapshot.capability_id.clone(), snapshot);
        }
    }
    Ok(records.into_values().collect())
}
