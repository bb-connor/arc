//! Process-owned snapshot storage with a page quota and checked platform custody.
use std::collections::HashMap;

#[path = "db/storage.rs"]
mod storage;
use storage::Storage;

use chio_kernel::{ReceiptQuerySnapshotError, ReceiptStoreError};
use rusqlite::{params, Connection, ErrorCode, OptionalExtension};

use crate::receipt_store::SqliteReceiptStore;

/// Interned dimension kinds. Count rows reuse them as their `dim` column.
pub(super) const DIM_TENANT: i64 = 1;
pub(super) const DIM_CAPABILITY: i64 = 2;
pub(super) const DIM_TOOL_SERVER: i64 = 3;
pub(super) const DIM_TOOL_NAME: i64 = 4;
pub(super) const DIM_TOOL: i64 = 5;
pub(super) const DIM_DECISION: i64 = 6;
pub(super) const DIM_SUBJECT: i64 = 7;
pub(super) const DIM_CURRENCY: i64 = 8;
/// Count-only dimensions.
pub(super) const COUNT_TOTAL: i64 = 0;
pub(super) const COUNT_HOUR: i64 = 100;
/// Count scope covering every tenant.
pub(super) const SCOPE_ALL: i64 = -1;
/// Dimension id meaning "absent" (no tenant, no subject, no cost).
pub(super) const ABSENT: i64 = 0;

pub(super) const KIND_TOOL: i64 = 1;
pub(super) const KIND_CHILD: i64 = 2;

const SCHEMA: &str = r#"
CREATE TABLE snapshot_dim (
    id INTEGER PRIMARY KEY,
    kind INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (kind, value)
);
CREATE TABLE snapshot_signer (id INTEGER PRIMARY KEY, kernel_key TEXT NOT NULL UNIQUE);
CREATE TABLE snapshot_tool_receipt (
    seq INTEGER PRIMARY KEY,
    entry_seq INTEGER NOT NULL,
    leaf_hash BLOB NOT NULL,
    signer INTEGER NOT NULL,
    receipt_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    tenant INTEGER NOT NULL,
    capability INTEGER NOT NULL,
    tool_server INTEGER NOT NULL,
    tool_name INTEGER NOT NULL,
    tool INTEGER NOT NULL,
    decision INTEGER NOT NULL,
    subject INTEGER NOT NULL,
    subject_signed INTEGER NOT NULL,
    cost_currency INTEGER NOT NULL,
    cost_charged BLOB
);
CREATE UNIQUE INDEX sq_entry ON snapshot_tool_receipt (entry_seq);
CREATE UNIQUE INDEX sq_receipt_id ON snapshot_tool_receipt (receipt_id);
CREATE INDEX sq_t ON snapshot_tool_receipt (tenant, seq);
CREATE INDEX sq_t_ts ON snapshot_tool_receipt (tenant, ts, seq);
CREATE INDEX sq_ts ON snapshot_tool_receipt (ts, seq);
CREATE INDEX sq_t_capability ON snapshot_tool_receipt (tenant, capability, seq);
CREATE INDEX sq_capability ON snapshot_tool_receipt (capability, seq);
CREATE INDEX sq_t_tool_server ON snapshot_tool_receipt (tenant, tool_server, seq);
CREATE INDEX sq_tool_server ON snapshot_tool_receipt (tool_server, seq);
CREATE INDEX sq_t_tool_name ON snapshot_tool_receipt (tenant, tool_name, seq);
CREATE INDEX sq_tool_name ON snapshot_tool_receipt (tool_name, seq);
CREATE INDEX sq_t_tool ON snapshot_tool_receipt (tenant, tool, seq);
CREATE INDEX sq_tool ON snapshot_tool_receipt (tool, seq);
CREATE INDEX sq_t_decision ON snapshot_tool_receipt (tenant, decision, seq);
CREATE INDEX sq_decision ON snapshot_tool_receipt (decision, seq);
CREATE INDEX sq_t_subject ON snapshot_tool_receipt (tenant, subject, seq);
CREATE INDEX sq_subject ON snapshot_tool_receipt (subject, seq);
CREATE INDEX sq_t_cost_currency ON snapshot_tool_receipt (tenant, cost_currency, seq);
CREATE INDEX sq_cost_currency ON snapshot_tool_receipt (cost_currency, seq);
CREATE TABLE snapshot_count (
    scope INTEGER NOT NULL,
    dim INTEGER NOT NULL,
    value INTEGER NOT NULL,
    n INTEGER NOT NULL,
    min_seq INTEGER NOT NULL,
    max_seq INTEGER NOT NULL,
    PRIMARY KEY (scope, dim, value)
) WITHOUT ROWID;
CREATE TABLE snapshot_checkpoint (
    seq INTEGER PRIMARY KEY,
    batch_start INTEGER NOT NULL,
    batch_end INTEGER NOT NULL,
    tree_size INTEGER NOT NULL,
    merkle_root BLOB NOT NULL,
    kernel_key TEXT NOT NULL,
    canonical_sha256 BLOB NOT NULL
);
CREATE INDEX sq_checkpoint_start ON snapshot_checkpoint (batch_start);
CREATE TABLE snapshot_pending_leaf (
    entry_seq INTEGER PRIMARY KEY,
    kind INTEGER NOT NULL,
    leaf_hash BLOB NOT NULL,
    signer INTEGER NOT NULL
);
CREATE TABLE snapshot_child_cursor (
    source_seq INTEGER PRIMARY KEY,
    entry_seq INTEGER NOT NULL UNIQUE,
    signer INTEGER NOT NULL,
    leaf_hash BLOB NOT NULL,
    ts INTEGER NOT NULL
);
CREATE INDEX sq_child_ts ON snapshot_child_cursor (ts, source_seq);
"#;

/// One authenticated tool receipt, projected for filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProjectedToolRow {
    pub(super) seq: i64,
    pub(super) entry_seq: i64,
    pub(super) leaf_hash: [u8; 32],
    pub(super) signer: String,
    pub(super) receipt_id: String,
    pub(super) ts: i64,
    pub(super) tenant: Option<String>,
    pub(super) capability: String,
    pub(super) tool_server: String,
    pub(super) tool_name: String,
    pub(super) decision: String,
    pub(super) subject: Option<String>,
    pub(super) subject_signed: bool,
    pub(super) cost_currency: Option<String>,
    pub(super) cost_charged: Option<Vec<u8>>,
}

/// One authenticated child receipt cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ChildCursor {
    pub(super) source_seq: i64,
    pub(super) entry_seq: i64,
    pub(super) signer: String,
    pub(super) leaf_hash: [u8; 32],
    pub(super) ts: i64,
}

/// Leaf of an entry above the newest verified checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingLeaf {
    pub(super) entry_seq: i64,
    pub(super) kind: i64,
    pub(super) leaf_hash: [u8; 32],
    pub(super) signer: String,
}

/// Verified checkpoint retained by the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OwnedCheckpoint {
    pub(super) seq: i64,
    pub(super) batch_start: i64,
    pub(super) batch_end: i64,
    pub(super) tree_size: i64,
    pub(super) merkle_root: [u8; 32],
    pub(super) kernel_key: String,
    /// Domain-separated SHA-256 of the canonical signed checkpoint, including
    /// its signature, publication fields and predecessor commitment.
    pub(super) canonical_sha256: [u8; 32],
}

/// One batch of authenticated changes committed as one snapshot transaction.
#[derive(Debug, Default)]
pub(super) struct SnapshotBatch {
    pub(super) tools: Vec<ProjectedToolRow>,
    pub(super) children: Vec<ChildCursor>,
    pub(super) pending: Vec<PendingLeaf>,
    pub(super) checkpoints: Vec<OwnedCheckpoint>,
}

/// Failures of the owned store. Capacity is a resource limit; a uniqueness
/// violation means the source offered the same cursor or receipt twice.
#[derive(Debug, thiserror::Error)]
pub(super) enum SnapshotDbError {
    #[error("receipt query snapshot storage is full: backing storage or configured quota may be exhausted ({quota_bytes} byte quota, {used_bytes} bytes used)")]
    Capacity { quota_bytes: u64, used_bytes: u64 },
    #[error("authenticated receipt history repeats a receipt or cursor: {0}")]
    Duplicate(String),
    #[error(transparent)]
    Store(#[from] ReceiptStoreError),
    #[error("receipt query snapshot storage failed: {0}")]
    Sqlite(rusqlite::Error),
}

impl From<rusqlite::Error> for SnapshotDbError {
    fn from(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(ErrorCode::ConstraintViolation) => Self::Duplicate(error.to_string()),
            _ => Self::Sqlite(error),
        }
    }
}

pub(super) struct SnapshotDb {
    storage: Storage,
    quota_bytes: u64,
    page_size: u64,
    dims: HashMap<(i64, String), i64>,
    signers: HashMap<String, i64>,
    /// Bytes of every interned dimension value, maintained as values commit.
    dim_bytes: u64,
    /// Byte length of each interned dimension value, by id, so owned rows
    /// can be measured without reading their values.
    dim_len: HashMap<i64, u64>,
    /// Largest number of pending leaves one snapshot transaction removed.
    #[cfg(test)]
    pub(super) max_settled_per_hold: std::cell::Cell<u64>,
    /// Largest number of variable-length bytes one owned-range read
    /// materialized.
    #[cfg(test)]
    pub(super) max_owned_range_bytes: std::cell::Cell<u64>,
}

impl SnapshotDb {
    /// Linux uses a process-private file in `store`'s data directory. Other
    /// platforms use private memory.
    pub(super) fn open_private(
        store: &SqliteReceiptStore,
        quota_bytes: u64,
    ) -> Result<Self, SnapshotDbError> {
        Self::from_storage(Storage::create(store)?, quota_bytes)
    }

    /// Reclaim snapshot files abandoned at `store`'s snapshot location by
    /// owners that died, without provisioning one. Bounded and best effort.
    pub(super) fn reclaim_abandoned(store: &SqliteReceiptStore) {
        storage::reclaim_abandoned(store);
    }

    #[cfg(test)]
    pub(super) fn open_memory(quota_bytes: u64) -> Result<Self, SnapshotDbError> {
        Self::from_storage(Storage::memory()?, quota_bytes)
    }

    fn from_storage(storage: Storage, quota_bytes: u64) -> Result<Self, SnapshotDbError> {
        let connection = storage.connection()?;
        connection.execute_batch("PRAGMA journal_mode = MEMORY; PRAGMA temp_store = MEMORY;")?;
        let page_size: i64 = connection.query_row("PRAGMA page_size", [], |row| row.get(0))?;
        let page_size = u64::try_from(page_size)
            .ok()
            .filter(|size| *size > 0)
            .ok_or_else(|| SnapshotDbError::Sqlite(rusqlite::Error::InvalidQuery))?;
        let pages = (quota_bytes / page_size).max(1);
        let pages = i64::try_from(pages).unwrap_or(i64::MAX);
        let applied: i64 =
            connection.query_row(&format!("PRAGMA max_page_count = {pages}"), [], |row| {
                row.get(0)
            })?;
        // SQLite clamps the page limit to its own maximum; report the quota
        // actually enforced rather than the one requested.
        let quota_bytes = u64::try_from(applied)
            .unwrap_or(0)
            .min(u64::try_from(pages).unwrap_or(u64::MAX))
            .saturating_mul(page_size);
        let db = Self {
            storage,
            quota_bytes,
            page_size,
            dims: HashMap::new(),
            signers: HashMap::new(),
            dim_bytes: 0,
            dim_len: HashMap::new(),
            #[cfg(test)]
            max_settled_per_hold: std::cell::Cell::new(0),
            #[cfg(test)]
            max_owned_range_bytes: std::cell::Cell::new(0),
        };
        with_quota(db.connection()?, quota_bytes, page_size, |connection| {
            connection.execute_batch(SCHEMA)
        })?;
        Ok(db)
    }

    pub(super) fn connection(&self) -> Result<&Connection, ReceiptStoreError> {
        self.storage.connection()
    }

    /// SQLite VM steps `work` spends on this connection.
    #[cfg(test)]
    pub(super) fn count_steps_for_test<T>(
        &self,
        work: impl FnOnce(&Self) -> T,
    ) -> Result<(T, u64), ReceiptStoreError> {
        let steps = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counter = std::sync::Arc::clone(&steps);
        self.connection()?.progress_handler(
            1,
            Some(move || {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                false
            }),
        )?;
        let value = work(self);
        self.connection()?
            .progress_handler(0, None::<fn() -> bool>)?;
        Ok((value, steps.load(std::sync::atomic::Ordering::Relaxed)))
    }

    #[cfg(test)]
    pub(super) fn trace_for_test(
        &mut self,
        trace: Option<fn(rusqlite::trace::TraceEvent<'_>)>,
    ) -> Result<(), ReceiptStoreError> {
        self.storage
            .connection_mut()?
            .trace_v2(rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT, trace);
        Ok(())
    }

    pub(super) fn quota_bytes(&self) -> u64 {
        self.quota_bytes
    }

    /// Apply only an explicit owner-requested increase; no write retries grow
    /// the budget themselves. SQLite may clamp it to its maximum page count.
    pub(super) fn increase_quota(&mut self, requested: u64) -> Result<(), SnapshotDbError> {
        if requested <= self.quota_bytes {
            return Ok(());
        }
        let pages = i64::try_from(requested / self.page_size).unwrap_or(i64::MAX);
        let applied: i64 = self.connection()?.query_row(
            &format!("PRAGMA max_page_count = {pages}"),
            [],
            |row| row.get(0),
        )?;
        self.quota_bytes = u64::try_from(applied)
            .unwrap_or(0)
            .saturating_mul(self.page_size);
        Ok(())
    }

    pub(super) fn used_bytes(&self) -> Result<u64, SnapshotDbError> {
        let pages: i64 = self
            .connection()?
            .query_row("PRAGMA page_count", [], |row| row.get(0))?;
        Ok(u64::try_from(pages)
            .unwrap_or(0)
            .saturating_mul(self.page_size))
    }

    /// Existing dimension id, or `None` when no row carries this value.
    pub(super) fn dim_id(&self, kind: i64, value: &str) -> Option<i64> {
        self.dims.get(&(kind, value.to_string())).copied()
    }

    pub(super) fn dim_value(&self, id: i64) -> Result<Option<String>, SnapshotDbError> {
        if id == ABSENT {
            return Ok(None);
        }
        Ok(self
            .connection()?
            .query_row(
                "SELECT value FROM snapshot_dim WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Commit one batch atomically: rows, cursors, leaves, checkpoints and the
    /// counts that summarize them. A failed batch leaves the snapshot unchanged.
    pub(super) fn commit(&mut self, batch: &SnapshotBatch) -> Result<(), SnapshotDbError> {
        let mut dims = Interned::new(&self.dims);
        let mut signers = Interned::new(&self.signers);
        let result = with_quota(
            self.connection()?,
            self.quota_bytes,
            self.page_size,
            |connection| {
                let transaction = connection.unchecked_transaction()?;
                for row in &batch.tools {
                    insert_tool_row(&transaction, &mut dims, &mut signers, row)?;
                }
                for cursor in &batch.children {
                    let signer = intern_signer(&transaction, &mut signers, &cursor.signer)?;
                    transaction
                    .prepare_cached(
                        "INSERT INTO snapshot_child_cursor (source_seq, entry_seq, signer, leaf_hash, ts) VALUES (?1, ?2, ?3, ?4, ?5)",
                    )?
                    .execute(params![cursor.source_seq, cursor.entry_seq, signer, &cursor.leaf_hash[..], cursor.ts])?;
                }
                for leaf in &batch.pending {
                    let signer = intern_signer(&transaction, &mut signers, &leaf.signer)?;
                    transaction
                    .prepare_cached(
                        "INSERT INTO snapshot_pending_leaf (entry_seq, kind, leaf_hash, signer) VALUES (?1, ?2, ?3, ?4)",
                    )?
                    .execute(params![leaf.entry_seq, leaf.kind, &leaf.leaf_hash[..], signer])?;
                }
                for checkpoint in &batch.checkpoints {
                    transaction
                    .prepare_cached(
                        "INSERT INTO snapshot_checkpoint (seq, batch_start, batch_end, tree_size, merkle_root, kernel_key, canonical_sha256) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    )?
                    .execute(params![
                        checkpoint.seq,
                        checkpoint.batch_start,
                        checkpoint.batch_end,
                        checkpoint.tree_size,
                        &checkpoint.merkle_root[..],
                        checkpoint.kernel_key,
                        &checkpoint.canonical_sha256[..]
                    ])?;
                }

                transaction.commit()
            },
        );
        if result.is_ok() {
            let (dims, signers) = (dims.added, signers.added);
            self.intern_committed(dims);
            self.signers.extend(signers);
        }
        result
    }

    /// Fill an absent unsigned subject from capability lineage. Returns the
    /// rows changed. A row whose present unsigned subject differs is drift and
    /// is reported through `Ok(Err(seq))`.
    pub(super) fn refresh_subject(
        &mut self,
        capability: &str,
        subject: &str,
        after_seq: i64,
        limit: i64,
    ) -> Result<Result<Vec<i64>, i64>, SnapshotDbError> {
        let Some(capability_id) = self.dim_id(DIM_CAPABILITY, capability) else {
            return Ok(Ok(Vec::new()));
        };
        let mut dims = Interned::new(&self.dims);
        let result = with_quota(
            self.connection()?,
            self.quota_bytes,
            self.page_size,
            |connection| {
                let transaction = connection.unchecked_transaction()?;
                let subject_id = intern_dim(&transaction, &mut dims, DIM_SUBJECT, subject)?;
                let rows = {
                    let mut statement = transaction.prepare_cached(
                    "SELECT seq, tenant, subject FROM snapshot_tool_receipt INDEXED BY sq_capability
                     WHERE capability = ?1 AND seq > ?2 AND subject_signed = 0
                     ORDER BY seq LIMIT ?3",
                )?;
                    let mapped =
                        statement.query_map(params![capability_id, after_seq, limit], |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, i64>(2)?,
                            ))
                        })?;
                    mapped.collect::<rusqlite::Result<Vec<_>>>()?
                };
                let mut changed = Vec::new();
                for (seq, tenant, existing) in rows {
                    if existing == subject_id {
                        changed.push(seq);
                        continue;
                    }
                    if existing != ABSENT {
                        return Ok(Err(seq));
                    }
                    transaction
                        .prepare_cached(
                            "UPDATE snapshot_tool_receipt SET subject = ?1 WHERE seq = ?2",
                        )?
                        .execute(params![subject_id, seq])?;
                    bump_count(&transaction, SCOPE_ALL, DIM_SUBJECT, subject_id, seq)?;
                    if tenant != ABSENT {
                        bump_count(&transaction, tenant, DIM_SUBJECT, subject_id, seq)?;
                    }
                    changed.push(seq);
                }
                transaction.commit()?;
                Ok(Ok(changed))
            },
        );
        if matches!(result, Ok(Ok(_))) {
            self.intern_committed(dims.added);
        }
        result
    }

    /// Record dimension values a committed transaction interned.
    fn intern_committed(&mut self, added: HashMap<(i64, String), i64>) {
        for ((_, value), id) in &added {
            let bytes = crate::integer::count(value.len());
            self.dim_bytes = self.dim_bytes.saturating_add(bytes);
            self.dim_len.insert(*id, bytes);
        }
        self.dims.extend(added);
    }

    /// Remove at most `limit` settled pending leaves in `[start, end]`.
    pub(super) fn delete_pending_chunk(
        &mut self,
        start: i64,
        end: i64,
        limit: i64,
    ) -> Result<u64, SnapshotDbError> {
        let removed = self
            .connection()?
            .prepare_cached(
                "DELETE FROM snapshot_pending_leaf WHERE entry_seq IN (
                     SELECT entry_seq FROM snapshot_pending_leaf
                     WHERE entry_seq >= ?1 AND entry_seq <= ?2 ORDER BY entry_seq LIMIT ?3)",
            )?
            .execute(params![start, end, limit])?;
        let removed = u64::try_from(removed).unwrap_or(u64::MAX);
        #[cfg(test)]
        self.max_settled_per_hold
            .set(self.max_settled_per_hold.get().max(removed));
        Ok(removed)
    }

    /// Maintained count for one key: `(n, min_seq, max_seq)`.
    pub(super) fn count(
        &self,
        scope: i64,
        dim: i64,
        value: i64,
    ) -> Result<Option<(u64, i64, i64)>, SnapshotDbError> {
        Ok(self
            .connection()?
            .prepare_cached(
                "SELECT n, min_seq, max_seq FROM snapshot_count WHERE scope = ?1 AND dim = ?2 AND value = ?3",
            )?
            .query_row(params![scope, dim, value], |row| {
                Ok((
                    u64::try_from(row.get::<_, i64>(0)?).unwrap_or(0),
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .optional()?)
    }

    pub(super) fn load_checkpoint(
        &self,
        seq: i64,
    ) -> Result<Option<OwnedCheckpoint>, SnapshotDbError> {
        Ok(self
            .connection()?
            .prepare_cached(
                "SELECT seq, batch_start, batch_end, tree_size, merkle_root, kernel_key, canonical_sha256 FROM snapshot_checkpoint WHERE seq = ?1",
            )?
            .query_row([seq], |row| {
                Ok(OwnedCheckpoint {
                    seq: row.get(0)?,
                    batch_start: row.get(1)?,
                    batch_end: row.get(2)?,
                    tree_size: row.get(3)?,
                    merkle_root: blob32(row.get::<_, Vec<u8>>(4)?)?,
                    kernel_key: row.get(5)?,
                    canonical_sha256: blob32(row.get::<_, Vec<u8>>(6)?)?,
                })
            })
            .optional()?)
    }

    /// Pending leaves in `[start, end]`, in entry order.
    pub(super) fn pending_leaves(
        &self,
        start: i64,
        end: i64,
    ) -> Result<Vec<PendingLeaf>, SnapshotDbError> {
        let mut statement = self.connection()?.prepare_cached(
            "SELECT p.entry_seq, p.kind, p.leaf_hash, s.kernel_key FROM snapshot_pending_leaf p
             JOIN snapshot_signer s ON s.id = p.signer
             WHERE p.entry_seq >= ?1 AND p.entry_seq <= ?2 ORDER BY p.entry_seq",
        )?;
        let rows = statement.query_map(params![start, end], |row| {
            Ok(PendingLeaf {
                entry_seq: row.get(0)?,
                kind: row.get(1)?,
                leaf_hash: blob32(row.get::<_, Vec<u8>>(2)?)?,
                signer: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Owned tool rows and child cursors for an entry range, used by
    /// recertification to compare against freshly authenticated history.
    pub(super) fn owned_range(
        &self,
        start: i64,
        end: i64,
    ) -> Result<(Vec<ProjectedToolRow>, Vec<ChildCursor>), SnapshotDbError> {
        let mut tools = Vec::new();
        {
            let mut statement = self.connection()?.prepare_cached(
                "SELECT r.seq, r.entry_seq, r.leaf_hash, s.kernel_key, r.receipt_id, r.ts,
                        r.tenant, r.capability, r.tool_server, r.tool_name, r.decision,
                        r.subject, r.subject_signed, r.cost_currency, r.cost_charged
                 FROM snapshot_tool_receipt r INDEXED BY sq_entry
                 JOIN snapshot_signer s ON s.id = r.signer
                 WHERE r.entry_seq >= ?1 AND r.entry_seq <= ?2 ORDER BY r.entry_seq",
            )?;
            let rows = statement.query_map(params![start, end], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    [
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, i64>(10)?,
                        row.get::<_, i64>(11)?,
                        row.get::<_, i64>(13)?,
                    ],
                    row.get::<_, bool>(12)?,
                    row.get::<_, Option<Vec<u8>>>(14)?,
                ))
            })?;
            for row in rows {
                let (seq, entry_seq, leaf, signer, receipt_id, ts, ids, subject_signed, charged) =
                    row?;
                let [tenant, capability, tool_server, tool_name, decision, subject, currency] = ids;
                tools.push(ProjectedToolRow {
                    seq,
                    entry_seq,
                    leaf_hash: blob32(leaf)?,
                    signer,
                    receipt_id,
                    ts,
                    tenant: self.dim_value(tenant)?,
                    capability: self.dim_value(capability)?.unwrap_or_default(),
                    tool_server: self.dim_value(tool_server)?.unwrap_or_default(),
                    tool_name: self.dim_value(tool_name)?.unwrap_or_default(),
                    decision: self.dim_value(decision)?.unwrap_or_default(),
                    subject: self.dim_value(subject)?,
                    subject_signed,
                    cost_currency: self.dim_value(currency)?,
                    cost_charged: charged,
                });
            }
        }
        let mut children = Vec::new();
        {
            let mut statement = self.connection()?.prepare_cached(
                "SELECT c.source_seq, c.entry_seq, s.kernel_key, c.leaf_hash, c.ts FROM snapshot_child_cursor c
                 JOIN snapshot_signer s ON s.id = c.signer
                 WHERE c.entry_seq >= ?1 AND c.entry_seq <= ?2 ORDER BY c.entry_seq",
            )?;
            let rows = statement.query_map(params![start, end], |row| {
                Ok(ChildCursor {
                    source_seq: row.get(0)?,
                    entry_seq: row.get(1)?,
                    signer: row.get(2)?,
                    leaf_hash: blob32(row.get::<_, Vec<u8>>(3)?)?,
                    ts: row.get(4)?,
                })
            })?;
            for row in rows {
                children.push(row?);
            }
        }
        #[cfg(test)]
        {
            let text = |value: &Option<String>| value.as_ref().map_or(0, String::len);
            let bytes: usize = tools
                .iter()
                .map(|row| {
                    row.signer.len()
                        + row.receipt_id.len()
                        + text(&row.tenant)
                        + row.capability.len()
                        + row.tool_server.len()
                        + row.tool_name.len()
                        + row.decision.len()
                        + text(&row.subject)
                        + text(&row.cost_currency)
                        + row.cost_charged.as_ref().map_or(0, Vec::len)
                })
                .chain(children.iter().map(|child| child.signer.len()))
                .sum();
            let bytes = crate::integer::count(bytes);
            self.max_owned_range_bytes
                .set(self.max_owned_range_bytes.get().max(bytes));
        }
        Ok((tools, children))
    }

    /// The last entry of `[start, end]` through which the owned rows fit in
    /// `budget` bytes, measured from interned value lengths without reading
    /// any value. The first owned entry is always included: one row may
    /// exceed a step's budget, bounded by the per-row limit it was built
    /// under.
    pub(super) fn owned_prefix_end(
        &self,
        start: i64,
        end: i64,
        budget: u64,
    ) -> Result<i64, SnapshotDbError> {
        let interned = |id: i64| -> Result<u64, SnapshotDbError> {
            if id == ABSENT {
                return Ok(0);
            }
            self.dim_len.get(&id).copied().ok_or_else(|| {
                SnapshotDbError::Store(
                    ReceiptQuerySnapshotError::Invalid(format!(
                        "snapshot row references dimension {id}, which was never interned"
                    ))
                    .into(),
                )
            })
        };
        let mut sizes: Vec<(i64, u64)> = Vec::new();
        {
            let mut statement = self.connection()?.prepare_cached(
                "SELECT r.entry_seq,
                        length(CAST(r.receipt_id AS BLOB)) + COALESCE(length(r.cost_charged), 0)
                            + length(CAST(s.kernel_key AS BLOB)),
                        r.tenant, r.capability, r.tool_server, r.tool_name, r.decision,
                        r.subject, r.cost_currency
                 FROM snapshot_tool_receipt r INDEXED BY sq_entry
                 JOIN snapshot_signer s ON s.id = r.signer
                 WHERE r.entry_seq >= ?1 AND r.entry_seq <= ?2 ORDER BY r.entry_seq",
            )?;
            let rows = statement.query_map(params![start, end], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    [
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                    ],
                ))
            })?;
            for row in rows {
                let (entry_seq, inline, ids) = row?;
                let mut bytes = u64::try_from(inline).unwrap_or(u64::MAX);
                for id in ids {
                    bytes = bytes.saturating_add(interned(id)?);
                }
                sizes.push((entry_seq, bytes));
            }
        }
        {
            let mut statement = self.connection()?.prepare_cached(
                "SELECT c.entry_seq, length(CAST(s.kernel_key AS BLOB)) FROM snapshot_child_cursor c
                 JOIN snapshot_signer s ON s.id = c.signer
                 WHERE c.entry_seq >= ?1 AND c.entry_seq <= ?2 ORDER BY c.entry_seq",
            )?;
            let rows = statement.query_map(params![start, end], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (entry_seq, bytes) = row?;
                sizes.push((entry_seq, u64::try_from(bytes).unwrap_or(u64::MAX)));
            }
        }
        sizes.sort_unstable_by_key(|(entry_seq, _)| *entry_seq);
        let mut total = 0_u64;
        let mut through: Option<i64> = None;
        for (entry_seq, bytes) in sizes {
            total = total.saturating_add(bytes);
            if let Some(through) = through.filter(|_| total > budget) {
                return Ok(through);
            }
            through = Some(entry_seq);
        }
        Ok(end)
    }

    /// Owned tool rows and child cursors with `entry_seq` in `(low, high]`.
    pub(super) fn owned_counts_between(
        &self,
        low: i64,
        high: i64,
    ) -> Result<(u64, u64), SnapshotDbError> {
        let tools: i64 = self.connection()?.prepare_cached(
            "SELECT COUNT(*) FROM snapshot_tool_receipt INDEXED BY sq_entry WHERE entry_seq > ?1 AND entry_seq <= ?2",
        )?.query_row(params![low, high], |row| row.get(0))?;
        let children: i64 = self.connection()?.prepare_cached(
            "SELECT COUNT(*) FROM snapshot_child_cursor WHERE entry_seq > ?1 AND entry_seq <= ?2",
        )?.query_row(params![low, high], |row| row.get(0))?;
        Ok((
            u64::try_from(tools).unwrap_or(0),
            u64::try_from(children).unwrap_or(0),
        ))
    }

    pub(super) fn tool_row_count(&self) -> Result<u64, SnapshotDbError> {
        Ok(self
            .count(SCOPE_ALL, COUNT_TOTAL, 0)?
            .map_or(0, |(n, _, _)| n))
    }

    /// Distinct dimension values and their bytes, maintained as values
    /// commit, so reading them costs no SQL work.
    pub(super) fn dim_stats(&self) -> Result<(u64, u64), SnapshotDbError> {
        Ok((crate::integer::count(self.dims.len()), self.dim_bytes))
    }
}

/// Run a snapshot write and retain the capacity context for `SQLITE_FULL`.
/// SQLite uses that code for both `max_page_count` and a full backing medium.
/// Rollback may leave usage below the quota in either case, so usage cannot
/// distinguish the causes. Neither is an integrity failure or a permanent latch.
fn with_quota<T>(
    connection: &Connection,
    quota_bytes: u64,
    page_size: u64,
    write: impl FnOnce(&Connection) -> rusqlite::Result<T>,
) -> Result<T, SnapshotDbError> {
    match write(connection) {
        Ok(value) => Ok(value),
        Err(error) if error.sqlite_error_code() == Some(ErrorCode::DiskFull) => {
            let pages: i64 = connection.query_row("PRAGMA page_count", [], |row| row.get(0))?;
            Err(SnapshotDbError::Capacity {
                quota_bytes,
                used_bytes: u64::try_from(pages).unwrap_or(0).saturating_mul(page_size),
            })
        }
        Err(error) => Err(error.into()),
    }
}

/// Values interned by an uncommitted batch, merged only after it commits.
struct Interned<'a, K> {
    committed: &'a HashMap<K, i64>,
    added: HashMap<K, i64>,
}

impl<'a, K: std::hash::Hash + Eq> Interned<'a, K> {
    fn new(committed: &'a HashMap<K, i64>) -> Self {
        Self {
            committed,
            added: HashMap::new(),
        }
    }

    fn get(&self, key: &K) -> Option<i64> {
        self.committed
            .get(key)
            .or_else(|| self.added.get(key))
            .copied()
    }
}

pub(super) fn blob32(bytes: Vec<u8>) -> rusqlite::Result<[u8; 32]> {
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::other("snapshot hash is not 32 bytes")),
        )
    })
}

fn intern_dim(
    connection: &Connection,
    dims: &mut Interned<'_, (i64, String)>,
    kind: i64,
    value: &str,
) -> rusqlite::Result<i64> {
    let key = (kind, value.to_string());
    if let Some(id) = dims.get(&key) {
        return Ok(id);
    }
    connection
        .prepare_cached("INSERT INTO snapshot_dim (kind, value) VALUES (?1, ?2)")?
        .execute(params![kind, value])?;
    let id = connection.last_insert_rowid();
    dims.added.insert(key, id);
    Ok(id)
}

fn intern_optional(
    connection: &Connection,
    dims: &mut Interned<'_, (i64, String)>,
    kind: i64,
    value: Option<&str>,
) -> rusqlite::Result<i64> {
    value.map_or(Ok(ABSENT), |value| {
        intern_dim(connection, dims, kind, value)
    })
}

fn intern_signer(
    connection: &Connection,
    signers: &mut Interned<'_, String>,
    kernel_key: &str,
) -> rusqlite::Result<i64> {
    let key = kernel_key.to_string();
    if let Some(id) = signers.get(&key) {
        return Ok(id);
    }
    connection
        .prepare_cached("INSERT INTO snapshot_signer (kernel_key) VALUES (?1)")?
        .execute([kernel_key])?;
    let id = connection.last_insert_rowid();
    signers.added.insert(key, id);
    Ok(id)
}

fn bump_count(
    connection: &Connection,
    scope: i64,
    dim: i64,
    value: i64,
    seq: i64,
) -> rusqlite::Result<()> {
    connection
        .prepare_cached(
            "INSERT INTO snapshot_count (scope, dim, value, n, min_seq, max_seq) VALUES (?1, ?2, ?3, 1, ?4, ?4)
             ON CONFLICT (scope, dim, value) DO UPDATE SET n = n + 1,
                 min_seq = min(min_seq, excluded.min_seq), max_seq = max(max_seq, excluded.max_seq)",
        )?
        .execute(params![scope, dim, value, seq])?;
    Ok(())
}

fn insert_tool_row(
    connection: &Connection,
    dims: &mut Interned<'_, (i64, String)>,
    signers: &mut Interned<'_, String>,
    row: &ProjectedToolRow,
) -> rusqlite::Result<()> {
    let tenant = intern_optional(connection, dims, DIM_TENANT, row.tenant.as_deref())?;
    let capability = intern_dim(connection, dims, DIM_CAPABILITY, &row.capability)?;
    let tool_server = intern_dim(connection, dims, DIM_TOOL_SERVER, &row.tool_server)?;
    let tool_name = intern_dim(connection, dims, DIM_TOOL_NAME, &row.tool_name)?;
    let tool = intern_dim(
        connection,
        dims,
        DIM_TOOL,
        &tool_key(&row.tool_server, &row.tool_name),
    )?;
    let decision = intern_dim(connection, dims, DIM_DECISION, &row.decision)?;
    let subject = intern_optional(connection, dims, DIM_SUBJECT, row.subject.as_deref())?;
    let currency = intern_optional(connection, dims, DIM_CURRENCY, row.cost_currency.as_deref())?;
    let signer = intern_signer(connection, signers, &row.signer)?;
    connection
        .prepare_cached(
            "INSERT INTO snapshot_tool_receipt (seq, entry_seq, leaf_hash, signer, receipt_id, ts,
                tenant, capability, tool_server, tool_name, tool, decision, subject, subject_signed,
                cost_currency, cost_charged)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        )?
        .execute(params![
            row.seq,
            row.entry_seq,
            &row.leaf_hash[..],
            signer,
            row.receipt_id,
            row.ts,
            tenant,
            capability,
            tool_server,
            tool_name,
            tool,
            decision,
            subject,
            row.subject_signed,
            currency,
            row.cost_charged
        ])?;
    let hour = row.ts.div_euclid(3600);
    let mut keys = vec![
        (COUNT_TOTAL, 0),
        (DIM_CAPABILITY, capability),
        (DIM_TOOL_SERVER, tool_server),
        (DIM_TOOL_NAME, tool_name),
        (DIM_TOOL, tool),
        (DIM_DECISION, decision),
        (COUNT_HOUR, hour),
    ];
    if subject != ABSENT {
        keys.push((DIM_SUBJECT, subject));
    }
    if currency != ABSENT {
        keys.push((DIM_CURRENCY, currency));
    }
    for (dim, value) in keys {
        bump_count(connection, SCOPE_ALL, dim, value, row.seq)?;
        if tenant != ABSENT {
            bump_count(connection, tenant, dim, value, row.seq)?;
        }
    }
    Ok(())
}

/// Interned key of a tool server and tool name pair. A JSON array encoding is
/// unambiguous, so distinct pairs never share a key.
pub(super) fn tool_key(tool_server: &str, tool_name: &str) -> String {
    serde_json::Value::Array(vec![
        serde_json::Value::String(tool_server.to_string()),
        serde_json::Value::String(tool_name.to_string()),
    ])
    .to_string()
}
