//! Pinned, authenticated live/archive evidence reads.
#[path = "retained_projection.rs"]
mod projection;
use super::support::{
    load_claim_tree_canonical_bytes_range, retention_watermark,
    trusted_retention_archive_for_connection_with_preflight,
    verify_latest_checkpoint_integrity_with_trusted_watermark,
};
use super::*;

/// Capabilities bound per query when a subject filter attributes archived
/// rows that recorded no attribution through current lineage.
const UNRECORDED_CAPABILITY_CHUNK: usize = 256;

#[cfg(test)]
thread_local! {
    /// Current lineage rows the unrecorded-attribution fallback read on this
    /// thread.
    static UNRECORDED_LINEAGE_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn unrecorded_lineage_reads_for_test() -> u64 {
    UNRECORDED_LINEAGE_READS.with(std::cell::Cell::get)
}

pub(crate) struct RetainedSnapshot<'a> {
    pub(crate) live: &'a Connection,
    pub(crate) archive: Option<&'a Connection>,
    pub(crate) watermark: u64,
}

impl SqliteReceiptStore {
    /// Revocations retained from the original API sidecar schema. These only
    /// restrict authority; legacy mutable receipt rows are never adopted.
    pub fn legacy_revoked_capability_ids(&self) -> Result<Vec<String>, ReceiptStoreError> {
        let connection = self.connection()?;
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'revoked_capabilities')",
            [], |row| row.get(0),
        )?;
        if !present {
            return Ok(Vec::new());
        }
        let mut statement = connection.prepare("SELECT CASE WHEN length(CAST(capability_id AS BLOB)) <= 1024 THEN capability_id END FROM revoked_capabilities")?;
        let ids = statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    pub(crate) fn with_retained_snapshot<T, E>(
        &self,
        read: impl FnOnce(&RetainedSnapshot<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<ReceiptStoreError> + From<rusqlite::Error>,
    {
        let mut connection = self.connection()?;
        with_retained_connection_snapshot(&mut connection, |_, _| Ok(()), read)
    }
}

/// Authenticate and read one live/archive snapshot without constructing a
/// serving store. A caller-supplied preflight may bound original bytes before
/// authentication decoders allocate. Its predicates grant no inclusion or
/// read authority.
pub(crate) fn with_retained_connection_snapshot<T, E>(
    connection: &mut Connection,
    mut preflight: impl FnMut(&Connection, u64) -> Result<(), ReceiptStoreError>,
    read: impl FnOnce(&RetainedSnapshot<'_>) -> Result<T, E>,
) -> Result<T, E>
where
    E: From<ReceiptStoreError> + From<rusqlite::Error>,
{
    let transaction = connection.transaction()?;
    preflight(&transaction, i64::MAX.unsigned_abs())?;
    let watermark = retention_watermark(&transaction)?.unwrap_or(0);
    let archive =
        trusted_retention_archive_for_connection_with_preflight(&transaction, &mut preflight)?;
    verify_latest_checkpoint_integrity_with_trusted_watermark(&transaction, watermark)?;
    if let Some(archive) = &archive {
        projection::validate(&transaction, archive, watermark)?;
    }
    let result = read(&RetainedSnapshot {
        live: &transaction,
        archive: archive.as_ref(),
        watermark,
    })?;
    transaction.commit()?;
    // Dropping the already authenticated archive releases its exact snapshot.
    Ok(result)
}

impl RetainedSnapshot<'_> {
    pub(crate) fn receipt(
        &self,
        receipt_id: &str,
        tenant: Option<&str>,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        for (connection, upper) in [
            (Some(self.live), i64::MAX.unsigned_abs()),
            (self.archive, self.watermark),
        ] {
            let Some(connection) = connection else {
                continue;
            };
            let row = connection
                .query_row(
                    "SELECT r.seq, r.raw_json FROM chio_tool_receipts r
                 JOIN claim_receipt_log_entries e ON e.receipt_kind = 'tool_receipt'
                   AND e.source_seq = r.seq AND e.receipt_id = r.receipt_id
                 WHERE r.receipt_id = ?1 AND (?2 IS NULL OR r.tenant_id = ?2)
                   AND e.entry_seq <= ?3",
                    params![
                        receipt_id,
                        tenant,
                        crate::integer::checked::<_, i64>(upper)?
                    ],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            if let Some((seq, raw_json)) = row {
                let receipt = decode_verified_chio_receipt(
                    &raw_json,
                    "retained receipt lookup",
                    Some(sqlite_u64(seq, "receipt seq")?),
                )?;
                if receipt.id != receipt_id {
                    return Err(ReceiptStoreError::Conflict(
                        "retained receipt identity differs from the requested ID".into(),
                    ));
                }
                if tenant.is_some_and(|tenant| receipt.tenant_id.as_deref() != Some(tenant)) {
                    return Err(
                        chio_kernel::receipt_query::ReceiptReadError::TenantProjectionMismatch
                            .into(),
                    );
                }
                return Ok(Some(receipt));
            }
        }
        Ok(None)
    }

    pub(crate) fn query_receipts(
        &self,
        query: &ReceiptQuery,
    ) -> Result<ReceiptQueryResult, ReceiptStoreError> {
        let mut page = crate::receipt_query::query_receipts_on_connection(self.live, query, None)?;
        if let Some(archive) = self.archive {
            let archived = crate::receipt_query::query_receipts_on_connection(
                archive,
                query,
                Some(self.watermark),
            )?;
            page.total_count = page
                .total_count
                .checked_add(archived.total_count)
                .ok_or_else(|| {
                    ReceiptStoreError::Conflict("retained receipt count overflow".into())
                })?;
            page.receipts.extend(archived.receipts);
            if let Some(subject) = query.agent_subject.as_deref() {
                self.add_unrecorded_attribution(archive, query, subject, &mut page)?;
            }
            page.receipts.sort_by_key(|row| row.seq);
        }
        let limit = query.limit.clamp(1, MAX_QUERY_LIMIT);
        page.receipts.truncate(limit);
        page.next_cursor = if page.receipts.len() == limit {
            page.receipts.last().map(|row| row.seq)
        } else {
            None
        };
        Ok(page)
    }

    /// Add the archived rows that recorded no attribution and whose
    /// capability's current lineage carries `subject`. Only capabilities of
    /// such committed archived rows are considered, streamed from the pinned
    /// archive, and each one's lineage is read from the pinned live snapshot
    /// through the canonical local reader, the row authenticating those
    /// archived receipts already read. Matching capabilities are bound in
    /// bounded chunks, each chunk's count is added, at most one page of
    /// candidates is kept between chunks, and only candidates that reach the
    /// page are verified.
    fn add_unrecorded_attribution(
        &self,
        archive: &Connection,
        query: &ReceiptQuery,
        subject: &str,
        page: &mut ReceiptQueryResult,
    ) -> Result<(), ReceiptStoreError> {
        let limit = query.limit.clamp(1, MAX_QUERY_LIMIT);
        let mut unrecorded = archive.prepare(
            "SELECT DISTINCT r.capability_id FROM chio_tool_receipts r
             LEFT JOIN capability_lineage cl ON cl.capability_id = r.capability_id
             WHERE r.subject_key IS NULL AND cl.capability_id IS NULL
               AND EXISTS (SELECT 1 FROM claim_receipt_log_entries e
                   WHERE e.receipt_kind = 'tool_receipt' AND e.source_seq = r.seq
                     AND e.receipt_id = r.receipt_id AND e.entry_seq <= ?1)",
        )?;
        let mut capabilities =
            unrecorded.query([sqlite_i64(self.watermark, "retained watermark")?])?;
        let mut chunk: Vec<String> = Vec::new();
        let mut candidates: Vec<(u64, String)> = Vec::new();
        let mut exhausted = false;
        while !exhausted {
            match capabilities.next()? {
                Some(row) => {
                    let capability: String = row.get(0)?;
                    #[cfg(test)]
                    UNRECORDED_LINEAGE_READS.with(|reads| reads.set(reads.get() + 1));
                    let lineage =
                        SqliteReceiptStore::get_lineage_on_connection(self.live, &capability)
                            .map_err(
                                crate::receipt_store::support::capability_lineage_store_error,
                            )?;
                    if lineage.is_some_and(|lineage| lineage.subject_key == subject) {
                        chunk.push(capability);
                    }
                }
                None => exhausted = true,
            }
            let full = chunk.len() == UNRECORDED_CAPABILITY_CHUNK;
            if !full && (chunk.is_empty() || !exhausted) {
                continue;
            }
            let bound = serde_json::to_string(&chunk)?;
            chunk.clear();
            let (rows, count) = crate::receipt_query::unrecorded_attribution_rows(
                archive,
                query,
                self.watermark,
                &bound,
            )?;
            page.total_count = page.total_count.checked_add(count).ok_or_else(|| {
                ReceiptStoreError::Conflict("retained receipt count overflow".into())
            })?;
            candidates.extend(rows);
            candidates.sort_by_key(|(seq, _)| *seq);
            candidates.truncate(limit);
        }
        let mut seqs: Vec<u64> = page.receipts.iter().map(|row| row.seq).collect();
        seqs.extend(candidates.iter().map(|(seq, _)| *seq));
        seqs.sort_unstable();
        let last_kept = seqs.get(limit - 1).copied().unwrap_or(u64::MAX);
        let tenant = query.effective_read_scope()?.tenant;
        for (seq, raw_json) in candidates {
            if seq > last_kept {
                continue;
            }
            let receipt =
                decode_verified_chio_receipt(&raw_json, "persisted tool receipt", Some(seq))?;
            if tenant
                .as_deref()
                .is_some_and(|tenant| receipt.tenant_id.as_deref() != Some(tenant))
            {
                return Err(
                    chio_kernel::receipt_query::ReceiptReadError::TenantProjectionMismatch.into(),
                );
            }
            page.receipts.push(StoredToolReceipt { seq, receipt });
        }
        Ok(())
    }

    pub(crate) fn claim_seq(&self, receipt_id: &str) -> Result<u64, ReceiptStoreError> {
        for (connection, upper) in [
            (Some(self.live), i64::MAX.unsigned_abs()),
            (self.archive, self.watermark),
        ] {
            if let Some(connection) = connection {
                let seq: Option<i64> = connection.query_row(
                    "SELECT entry_seq FROM claim_receipt_log_entries WHERE receipt_id = ?1 AND entry_seq <= ?2",
                    params![receipt_id, crate::integer::checked::<_, i64>(upper)?],
                    |row| row.get(0),
                ).optional()?;
                if let Some(seq) = seq {
                    return sqlite_u64(seq, "claim receipt log entry_seq");
                }
            }
        }
        Err(ReceiptStoreError::Conflict(format!(
            "receipt {receipt_id} is missing from the retained claim log"
        )))
    }

    pub(crate) fn canonical_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        let mut rows = Vec::new();
        if start <= self.watermark {
            let archive = self.archive.ok_or_else(|| {
                ReceiptStoreError::ReadBoundary(
                    "retained prefix has no authenticated archive".into(),
                )
            })?;
            rows.extend(load_claim_tree_canonical_bytes_range(
                archive,
                start,
                end.min(self.watermark),
            )?);
        }
        if end > self.watermark {
            rows.extend(load_claim_tree_canonical_bytes_range(
                self.live,
                start.max(self.watermark.saturating_add(1)),
                end,
            )?);
        }
        Ok(rows)
    }

    pub(crate) fn reject_legacy_receipt_omission(&self) -> Result<(), ReceiptStoreError> {
        for name in ["http_receipts", "tool_receipts", "chio_receipts"] {
            let present: bool = self.live.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                [name],
                |r| r.get(0),
            )?;
            if present
                && self.live.query_row(
                    &format!("SELECT EXISTS(SELECT 1 FROM {name})"),
                    [],
                    |r| r.get::<_, bool>(0),
                )?
            {
                return Err(ReceiptStoreError::ReadBoundary("legacy mutable receipt history cannot be exported as authenticated evidence; preserve the original database and use a new evidence database".into()));
            }
        }
        Ok(())
    }
}
