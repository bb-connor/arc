use std::fs;
use std::path::Path;
use std::sync::Arc;

use chio_core::root_authority::{
    RevocationEntry, RevocationEntryId, RevocationReason, RevocationTarget, RevocationTargetKind,
};
use chio_kernel::budget_store::{
    BudgetEventAuthority, BudgetGuaranteeLevel, RevocationCommitMetadata,
};
use chio_kernel::{RevocationObservation, RevocationRecord, RevocationStore, RevocationStoreError};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use crate::store_connection::{StoreConnection, StoreGuard};

mod targets;
pub use targets::TargetRevocation;

#[derive(Clone)]
pub struct SqliteRevocationStore {
    clock: crate::store_clock::StoreClock,
    connection: Arc<StoreConnection>,
    serving_owner: Option<Arc<crate::serving_owner::SqliteServingOwner>>,
    /// Whether the backing database lives only in process memory and so loses
    /// every revocation on restart. Computed from the open path, not assumed
    /// durable: an in-memory SQLite database must not satisfy the durability
    /// gate the way a real filesystem path does.
    ephemeral: bool,
}

#[derive(Debug, Clone)]
pub struct StoredRevocation {
    pub seq: u64,
    pub record: RevocationRecord,
}

/// Whether a SQLite path opens a database that lives only in memory for the life
/// of the process. rusqlite enables URI filenames, so the bare `:memory:`
/// sentinel, `file::memory:`, and any `file:...?mode=memory` URI all open a
/// non-durable database that loses every revocation on restart.
fn path_opens_in_memory(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    if value.eq_ignore_ascii_case(":memory:") {
        return true;
    }
    let Some(rest) = value.strip_prefix("file:") else {
        return false;
    };
    let (name, query) = match rest.split_once('?') {
        Some((name, query)) => (name, Some(query)),
        None => (rest, None),
    };
    if name.eq_ignore_ascii_case(":memory:") {
        return true;
    }
    query.is_some_and(|query| {
        query
            .split('&')
            .any(|param| param.eq_ignore_ascii_case("mode=memory"))
    })
}

/// Stable key under which this store records its schema revision in the shared
/// keyed metadata table, distinct from any co-located store's key.
const REVOCATION_STORE_SCHEMA_KEY: &str = "revocation";

impl SqliteRevocationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RevocationStoreError> {
        Self::open_with_clock(path, Arc::new(chio_security_types::clock::SystemClock))
    }

    /// Open a store that will advertise its delta stream to replication peers.
    ///
    /// Every serving activation rotates the stream identity before the caller
    /// can advertise a cursor. A database restored to an earlier dense-log head
    /// therefore cannot reuse sequence numbers under an identity cached by a
    /// follower. Ordinary non-serving opens retain the stored identity.
    pub fn open_replication_source(path: impl AsRef<Path>) -> Result<Self, RevocationStoreError> {
        Self::open_replication_source_with_clock(
            path,
            Arc::new(chio_security_types::clock::SystemClock),
        )
    }

    pub fn open_with_clock(
        path: impl AsRef<Path>,
        clock: Arc<dyn chio_security_types::clock::Clock>,
    ) -> Result<Self, RevocationStoreError> {
        Self::open_with_replication_epoch(path, false, clock)
    }

    pub fn open_replication_source_with_clock(
        path: impl AsRef<Path>,
        clock: Arc<dyn chio_security_types::clock::Clock>,
    ) -> Result<Self, RevocationStoreError> {
        Self::open_with_replication_epoch(path, true, clock)
    }

    fn open_with_replication_epoch(
        path: impl AsRef<Path>,
        rotate_replication_epoch: bool,
        clock: Arc<dyn chio_security_types::clock::Clock>,
    ) -> Result<Self, RevocationStoreError> {
        let path = path.as_ref();
        let ephemeral = path_opens_in_memory(path);
        if !ephemeral {
            // Derive the directory from the resolved filesystem path: a `file:`
            // URI sibling (`file:/var/lib/chio/receipts.db.revocations?mode=rwc`)
            // has a query and scheme that a raw `parent()` would fold into a
            // bogus directory, leaving the real one uncreated.
            if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
                fs::create_dir_all(&parent)?;
            }
        }

        let mut connection = Connection::open(path)?;
        if let Some(epoch) = crate::serving_owner::provisioned_owner_epoch(&connection)
            .map_err(|error| RevocationStoreError::Sync(error.to_string()))?
        {
            return Err(RevocationStoreError::Sync(format!(
                "provisioned sqlite authority store requires joint serving owner at epoch {epoch}"
            )));
        }
        connection.pragma_update(None, "foreign_keys", true)?;
        let creation = crate::schema_version::SchemaTransaction::begin(
            &mut connection,
            &[REVOCATION_STORE_SCHEMA_KEY],
        )
        .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;
        initialize_revocation_schema(&creation, false)?;
        creation
            .validate_catalog(&format!(
                "{REVOCATION_SCHEMA}\n{REVOCATION_STANDALONE_SCHEMA}"
            ))
            .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;
        creation
            .commit()
            .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;",
        )?;
        verify_revocation_foreign_keys(&connection)?;
        let clock = crate::store_clock::StoreClock::new(clock);
        if rotate_replication_epoch {
            clock.unix_millis()?;
            rotate_revocation_stream_identity(&mut connection)?;
        }

        // Opened by path there is no serving owner and no anchor: a revocation
        // and its delta-log entry land in one RAII transaction and nothing
        // outside the database records them.
        Ok(Self {
            clock,
            connection: Arc::new(StoreConnection::transaction_only("revocation", connection)),
            serving_owner: None,
            ephemeral,
        })
    }

    pub(crate) fn open_alongside(
        connection: Arc<StoreConnection>,
        serving_owner: Arc<crate::serving_owner::SqliteServingOwner>,
    ) -> Self {
        Self {
            clock: crate::store_clock::StoreClock::with_fence(
                serving_owner.clock.clone(),
                serving_owner.clock_fence.clone(),
            ),
            connection,
            serving_owner: Some(serving_owner),
            ephemeral: false,
        }
    }

    fn connection(&self) -> Result<StoreGuard<'_>, RevocationStoreError> {
        self.connection
            .lock()
            .map_err(|fenced| RevocationStoreError::Sync(fenced.to_string()))
    }

    fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, RevocationStoreError> {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::serving_owner::verify_revocation_fence(&transaction, self.serving_owner.as_deref())?;
        if let Some(owner) = self.serving_owner.as_ref() {
            owner
                .verify_authority_anchor(&transaction)
                .map_err(map_serving_owner_error)?;
            crate::admission_operation_store::observe_authority_time(&transaction, owner)
                .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;
        } else {
            self.clock.unix_millis()?;
        }
        Ok(transaction)
    }

    /// Record `capability_id` as revoked inside `transaction`: the row, its
    /// delta-log entry and, under a serving owner, the commit-chain entries the
    /// rollback anchor tracks. Returns false when it was already revoked.
    fn record_revocation(
        &self,
        transaction: &Transaction<'_>,
        capability_id: &str,
        revoked_at: i64,
    ) -> Result<bool, RevocationStoreError> {
        let exists = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
            params![capability_id],
            |row| row.get::<_, bool>(0),
        )?;
        if exists {
            return Ok(false);
        }
        let entry_id = self.record_capability_entry(transaction, capability_id, revoked_at)?;
        self.mark_revoked(transaction, capability_id, revoked_at, &entry_id)
    }

    /// Mark `capability_id` revoked by `entry_id` inside `transaction`: the
    /// projection row, its delta-log entry and, under a serving owner, the
    /// commit-chain entries. Returns false when it was already revoked.
    fn mark_revoked(
        &self,
        transaction: &Transaction<'_>,
        capability_id: &str,
        revoked_at: i64,
        entry_id: &RevocationEntryId,
    ) -> Result<bool, RevocationStoreError> {
        let exists = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
            params![capability_id],
            |row| row.get::<_, bool>(0),
        )?;
        if exists {
            return Ok(false);
        }
        let joint = self.serving_owner.is_some();
        let revocation_index = allocate_revocation_index(transaction, joint)?;
        let index_column = if joint {
            "admission_authority_commit_index"
        } else {
            "revocation_index"
        };
        let inserted = transaction
            .query_row(
                &format!(
                    r#"
            INSERT INTO revoked_capabilities (
                capability_id, revoked_at, {index_column}, revocation_entry_id
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(capability_id) DO NOTHING RETURNING 1
            "#
                ),
                params![
                    capability_id,
                    revoked_at,
                    revocation_index,
                    entry_id.as_str()
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if inserted.is_none() {
            return Ok(false);
        }
        append_revocation_delta(
            transaction,
            &RevocationRecord {
                capability_id: capability_id.to_string(),
                revoked_at,
            },
        )?;
        if joint {
            append_admission_revocation_commit(transaction, revocation_index, capability_id)?;
            self.serving_owner
                .as_ref()
                .ok_or_else(|| {
                    RevocationStoreError::Sync(
                        "joint revocation mutation lost its serving owner".to_string(),
                    )
                })?
                .append_global_commit(
                    transaction,
                    "revocation_revoke",
                    "revocation",
                    capability_id,
                    stored_index(revocation_index)?,
                )
                .map_err(map_serving_owner_error)?;
        }
        Ok(true)
    }

    /// Record the `capability_id` entry for `capability_id`, or keep the
    /// stored one. A replicated revocation carries no reason, so a new
    /// entry records `operator_request`.
    fn record_capability_entry(
        &self,
        transaction: &Transaction<'_>,
        capability_id: &str,
        revoked_at: i64,
    ) -> Result<RevocationEntryId, RevocationStoreError> {
        let target = RevocationTarget::capability(capability_id).map_err(|error| {
            RevocationStoreError::Sync(format!("invalid revocation target: {error}"))
        })?;
        self.record_revocation_entry(
            transaction,
            &target,
            revoked_at,
            RevocationReason::OperatorRequest,
        )
        .map(|(entry_id, _)| entry_id)
    }

    /// Record `target` inside `transaction`, or keep the stored entry: the
    /// first write's `revoked_at` and `reason` stand. Under a serving owner a
    /// new entry advances the global commit chain whether or not it matches
    /// any capability. Returns the entry id and whether this call created it.
    pub(crate) fn record_revocation_entry(
        &self,
        transaction: &Transaction<'_>,
        target: &RevocationTarget,
        revoked_at: i64,
        reason: RevocationReason,
    ) -> Result<(RevocationEntryId, bool), RevocationStoreError> {
        let entry_id = target.id();
        let inserted = transaction
            .query_row(
                r#"
                INSERT INTO revocation_entries (
                    entry_id, target_kind, target_value, revoked_at, reason
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT DO NOTHING RETURNING entry_seq
                "#,
                params![
                    entry_id.as_str(),
                    target.kind().as_str(),
                    target.value(),
                    revoked_at,
                    reason.as_str()
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(entry_seq) = inserted else {
            let stored = transaction.query_row(
                r#"
                SELECT entry_id FROM revocation_entries
                WHERE target_kind = ?1 AND target_value = ?2
                "#,
                params![target.kind().as_str(), target.value()],
                |row| row.get::<_, String>(0),
            )?;
            if stored != entry_id.as_str() {
                return Err(RevocationStoreError::Sync(
                    "stored revocation entry id does not match its target".to_string(),
                ));
            }
            return Ok((entry_id, false));
        };
        if let Some(owner) = self.serving_owner.as_ref() {
            owner
                .append_global_commit(
                    transaction,
                    "revocation_entry_record",
                    "revocation_entry",
                    entry_id.as_str(),
                    stored_index(entry_seq)?,
                )
                .map_err(map_serving_owner_error)?;
        }
        Ok((entry_id, true))
    }

    fn read<T>(
        &self,
        query: impl FnOnce(&Transaction<'_>) -> Result<T, RevocationStoreError>,
    ) -> Result<T, RevocationStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        crate::serving_owner::verify_revocation_fence(&transaction, self.serving_owner.as_deref())?;
        if let Some(owner) = self.serving_owner.as_ref() {
            owner
                .verify_authority_anchor(&transaction)
                .map_err(map_serving_owner_error)?;
        }
        let value = query(&transaction)?;
        transaction.rollback()?;
        Ok(value)
    }

    /// The entry that revoked `capability_id`, if any: the first entry that
    /// reached it.
    pub fn revocation_entry(
        &self,
        capability_id: &str,
    ) -> Result<Option<RevocationEntryId>, RevocationStoreError> {
        let stored = self.read(|transaction| {
            transaction
                .query_row(
                    "SELECT revocation_entry_id FROM revoked_capabilities WHERE capability_id = ?1",
                    params![capability_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(Into::into)
        })?;
        stored
            .map(|entry_id| {
                RevocationEntryId::parse(&entry_id).map_err(|error| {
                    RevocationStoreError::Sync(format!("stored revocation entry id: {error}"))
                })
            })
            .transpose()
    }

    /// One page of entries with `entry_seq` above `after_seq`, in sequence
    /// order, and the highest stored `entry_seq`, read from one snapshot.
    pub fn list_revocation_entries_after(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<(Vec<RevocationEntry>, u64), RevocationStoreError> {
        let after_seq = i64::try_from(after_seq).map_err(|_| {
            RevocationStoreError::Sync("revocation entry cursor exceeds SQLite range".to_string())
        })?;
        self.read(|transaction| {
            let rows = {
                let mut statement = transaction.prepare(
                    r#"
                    SELECT entry_id, target_kind, target_value, revoked_at, reason
                    FROM revocation_entries
                    WHERE entry_seq > ?1
                    ORDER BY entry_seq ASC
                    LIMIT ?2
                    "#,
                )?;
                let rows = statement
                    .query_map(
                        params![after_seq, crate::integer::checked::<_, i64>(limit)?],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, i64>(3)?,
                                row.get::<_, String>(4)?,
                            ))
                        },
                    )?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            };
            let entries = rows
                .into_iter()
                .map(|(entry_id, kind, value, revoked_at, reason)| {
                    stored_entry(&entry_id, &kind, &value, revoked_at, &reason)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let head = transaction.query_row(
                "SELECT COALESCE(MAX(entry_seq), 0) FROM revocation_entries",
                [],
                |row| row.get::<_, i64>(0),
            )?;
            Ok((entries, stored_index(head)?))
        })
    }

    pub fn latest_revocation_index(&self) -> Result<u64, RevocationStoreError> {
        let sql = if self.serving_owner.is_some() {
            "SELECT head_index FROM admission_authority_meta WHERE singleton = 1"
        } else {
            "SELECT next_index FROM revocation_replication_meta WHERE singleton = 1"
        };
        let value = self.read(|transaction| {
            transaction
                .query_row(sql, [], |row| row.get::<_, i64>(0))
                .map_err(Into::into)
        })?;
        u64::try_from(value)
            .map_err(|_| RevocationStoreError::Sync("negative revocation index".to_string()))
    }

    pub fn list_revocations(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<RevocationRecord>, RevocationStoreError> {
        self.read(|transaction| {
            let mut statement = transaction.prepare(
                r#"
                SELECT capability_id, revoked_at
                FROM revoked_capabilities
                WHERE (?1 IS NULL OR capability_id = ?1)
                ORDER BY revoked_at DESC, capability_id ASC
                LIMIT ?2
                "#,
            )?;
            let rows = statement.query_map(
                params![capability_id, crate::integer::checked::<_, i64>(limit)?],
                |row| {
                    Ok(RevocationRecord {
                        capability_id: row.get(0)?,
                        revoked_at: row.get(1)?,
                    })
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        })
    }

    pub fn list_revocations_after(
        &self,
        limit: usize,
        after_revoked_at: Option<i64>,
        after_capability_id: Option<&str>,
    ) -> Result<Vec<RevocationRecord>, RevocationStoreError> {
        self.read(|transaction| {
            let mut statement = transaction.prepare(
                r#"
                SELECT capability_id, revoked_at
                FROM revoked_capabilities
                WHERE (
                    ?1 IS NULL
                    OR revoked_at > ?1
                    OR (revoked_at = ?1 AND ?2 IS NOT NULL AND capability_id > ?2)
                )
                ORDER BY revoked_at ASC, capability_id ASC
                LIMIT ?3
                "#,
            )?;
            let rows = statement.query_map(
                params![
                    after_revoked_at,
                    after_capability_id,
                    crate::integer::checked::<_, i64>(limit)?
                ],
                |row| {
                    Ok(RevocationRecord {
                        capability_id: row.get(0)?,
                        revoked_at: row.get(1)?,
                    })
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        })
    }

    pub fn list_revocations_after_seq(
        &self,
        limit: usize,
        after_seq: u64,
    ) -> Result<Vec<StoredRevocation>, RevocationStoreError> {
        self.list_revocations_after_seq_with_head(limit, after_seq)
            .map(|(records, _)| records)
    }

    /// Read one delta page and the stream head from the same SQLite snapshot.
    /// This prevents an append between two separate reads from making an honest
    /// empty page appear to end below a later head.
    pub fn list_revocations_after_seq_with_head(
        &self,
        limit: usize,
        after_seq: u64,
    ) -> Result<(Vec<StoredRevocation>, u64), RevocationStoreError> {
        let after_seq = i64::try_from(after_seq).map_err(|_| {
            RevocationStoreError::Sync("revocation cursor exceeds SQLite range".to_string())
        })?;
        self.read(|transaction| {
            let records = {
                let mut statement = transaction.prepare(
                    r#"
                    SELECT seq, capability_id, revoked_at
                    FROM revocation_delta_log
                    WHERE seq > ?1
                    ORDER BY seq ASC
                    LIMIT ?2
                    "#,
                )?;
                let rows = statement.query_map(
                    params![after_seq, crate::integer::checked::<_, i64>(limit)?],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )?;
                rows.map(|row| {
                    let (seq, capability_id, revoked_at) = row?;
                    Ok(StoredRevocation {
                        seq: stored_index(seq)?,
                        record: RevocationRecord {
                            capability_id,
                            revoked_at,
                        },
                    })
                })
                .collect::<Result<Vec<_>, RevocationStoreError>>()?
            };
            let head = transaction.query_row(
                "SELECT next_seq FROM revocation_delta_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )?;
            Ok((records, stored_index(head)?))
        })
    }

    pub fn upsert_revocation(&self, record: &RevocationRecord) -> Result<(), RevocationStoreError> {
        self.upsert_revocation_if_newer(record).map(|_| ())
    }

    /// Apply a revocation only when it advances the stored projection.
    ///
    /// The returned flag is true exactly when this call commits a projection and
    /// append-log mutation. Replication callers use it to distinguish a fresh
    /// delta from an idempotent projection replay.
    pub fn upsert_revocation_if_newer(
        &self,
        record: &RevocationRecord,
    ) -> Result<bool, RevocationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let existing = transaction
            .query_row(
                "SELECT revoked_at FROM revoked_capabilities WHERE capability_id = ?1",
                params![&record.capability_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if existing.is_some_and(|revoked_at| revoked_at >= record.revoked_at) {
            transaction.rollback()?;
            return Ok(false);
        }
        let entry_id =
            self.record_capability_entry(&transaction, &record.capability_id, record.revoked_at)?;
        let joint = self.serving_owner.is_some();
        let revocation_index = allocate_revocation_index(&transaction, joint)?;
        if joint {
            transaction.execute(
                r#"
                INSERT INTO revoked_capabilities (
                    capability_id, revoked_at,
                    admission_authority_commit_index, revocation_entry_id
                ) VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(capability_id) DO UPDATE SET
                    revoked_at = excluded.revoked_at,
                    admission_authority_commit_index =
                        excluded.admission_authority_commit_index
                "#,
                params![
                    record.capability_id,
                    record.revoked_at,
                    revocation_index,
                    entry_id.as_str()
                ],
            )?;
            append_admission_revocation_commit(
                &transaction,
                revocation_index,
                &record.capability_id,
            )?;
            self.serving_owner
                .as_ref()
                .ok_or_else(|| {
                    RevocationStoreError::Sync(
                        "joint revocation mutation lost its serving owner".to_string(),
                    )
                })?
                .append_global_commit(
                    &transaction,
                    "revocation_upsert",
                    "revocation",
                    &record.capability_id,
                    stored_index(revocation_index)?,
                )
                .map_err(map_serving_owner_error)?;
        } else {
            transaction.execute(
                r#"
                INSERT INTO revoked_capabilities (
                    capability_id, revoked_at, revocation_index, revocation_entry_id
                ) VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(capability_id) DO UPDATE SET
                    revoked_at = excluded.revoked_at,
                    revocation_index = excluded.revocation_index
                "#,
                params![
                    record.capability_id,
                    record.revoked_at,
                    revocation_index,
                    entry_id.as_str()
                ],
            )?;
        }
        append_revocation_delta(&transaction, record)?;
        commit_mutation(self, transaction)?;
        if let Some(owner) = self.serving_owner.as_ref() {
            owner
                .sync_authority_anchor(&connection)
                .map_err(map_serving_owner_error)?;
        }
        Ok(true)
    }

    pub fn latest_revocation_stream_head(
        &self,
    ) -> Result<Option<StoredRevocation>, RevocationStoreError> {
        self.read(|transaction| {
            transaction
                .query_row(
                    "SELECT seq, capability_id, revoked_at \
                     FROM revocation_delta_log \
                     ORDER BY seq DESC LIMIT 1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?
                .map(|(seq, capability_id, revoked_at)| {
                    Ok(StoredRevocation {
                        seq: stored_index(seq)?,
                        record: RevocationRecord {
                            capability_id,
                            revoked_at,
                        },
                    })
                })
                .transpose()
        })
    }

    /// Identity of this append-only revocation serving epoch.
    ///
    /// Ordinary non-serving opens preserve the stored value. A trust-control
    /// replication source rotates it at activation, before advertising status,
    /// so a database rollback cannot reuse sequence numbers under an identity
    /// cached during an earlier serving epoch. A replication cursor is valid
    /// only for the identity that issued it.
    pub fn revocation_stream_id(&self) -> Result<String, RevocationStoreError> {
        self.read(|transaction| {
            transaction
                .query_row(
                    "SELECT stream_id FROM revocation_stream_meta WHERE singleton = 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .map_err(Into::into)
        })
    }

    /// Export the current revoked-capability projection and the append-only
    /// stream head from one SQLite read snapshot.
    ///
    /// Cluster snapshots transfer current state, not mutation history. Reading
    /// both values in one transaction ensures the advertised stream head never
    /// advances past a revocation omitted from the exported projection.
    pub fn export_revocation_snapshot(
        &self,
    ) -> Result<(String, Vec<RevocationRecord>, Option<StoredRevocation>), RevocationStoreError>
    {
        self.read(|transaction| {
            let stream_id = transaction.query_row(
                "SELECT stream_id FROM revocation_stream_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )?;
            let records = {
                let mut statement = transaction.prepare(
                    "SELECT capability_id, revoked_at FROM revoked_capabilities \
                     ORDER BY revoked_at ASC, capability_id ASC",
                )?;
                let records = statement
                    .query_map([], |row| {
                        Ok(RevocationRecord {
                            capability_id: row.get(0)?,
                            revoked_at: row.get(1)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                records
            };
            let head = transaction
                .query_row(
                    "SELECT seq, capability_id, revoked_at \
                     FROM revocation_delta_log ORDER BY seq DESC LIMIT 1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?
                .map(|(seq, capability_id, revoked_at)| {
                    Ok::<StoredRevocation, RevocationStoreError>(StoredRevocation {
                        seq: stored_index(seq)?,
                        record: RevocationRecord {
                            capability_id,
                            revoked_at,
                        },
                    })
                })
                .transpose()?;
            Ok((stream_id, records, head))
        })
    }
}

impl RevocationStore for SqliteRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        let exists = self.read(|transaction| {
            transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
                    params![capability_id],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(Into::into)
        })?;
        Ok(exists != 0)
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let revoked_at = self.clock.now_secs()?;
        if !self.record_revocation(&transaction, capability_id, revoked_at)? {
            transaction.rollback()?;
            return Ok(false);
        }
        commit_mutation(self, transaction)?;
        if let Some(owner) = self.serving_owner.as_ref() {
            owner
                .sync_authority_anchor(&connection)
                .map_err(map_serving_owner_error)?;
        }
        Ok(true)
    }

    fn observe_revocation(
        &self,
        capability_id: &str,
    ) -> Result<RevocationObservation, RevocationStoreError> {
        let sql = if self.serving_owner.is_some() {
            r#"
            SELECT EXISTS(
                       SELECT 1 FROM revoked_capabilities
                       WHERE capability_id = ?1
                   ),
                   head_index
            FROM admission_authority_meta WHERE singleton = 1
            "#
        } else {
            r#"
            SELECT EXISTS(
                       SELECT 1 FROM revoked_capabilities
                       WHERE capability_id = ?1
                   ),
                   next_index
            FROM revocation_replication_meta WHERE singleton = 1
            "#
        };
        let (revoked, commit_index) = self.read(|transaction| {
            transaction
                .query_row(sql, params![capability_id], |row| {
                    Ok((row.get::<_, bool>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(Into::into)
        })?;
        Ok(RevocationObservation {
            revoked,
            commit: self
                .serving_owner
                .as_ref()
                .map(|owner| {
                    Ok::<_, RevocationStoreError>(RevocationCommitMetadata {
                        authority: BudgetEventAuthority {
                            authority_id: owner.fence.store_uuid.clone(),
                            lease_id: owner.fence.lease_id.clone(),
                            lease_epoch: owner.fence.owner_epoch,
                        },
                        guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
                        commit_index: u64::try_from(commit_index).map_err(|_| {
                            RevocationStoreError::Sync(
                                "negative revocation commit index".to_string(),
                            )
                        })?,
                    })
                })
                .transpose()?,
        })
    }

    fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }
}

const REVOCATION_SCHEMA: &str = r#"

        CREATE TABLE IF NOT EXISTS revocation_entries (
            entry_seq INTEGER PRIMARY KEY CHECK (entry_seq > 0),
            entry_id TEXT NOT NULL UNIQUE CHECK (
                length(entry_id) = 68 AND substr(entry_id, 1, 4) = 'rev_'
                AND substr(entry_id, 5) NOT GLOB '*[^0-9a-f]*'
            ),
            target_kind TEXT NOT NULL CHECK (target_kind IN (
                'capability_id', 'root_policy_rule', 'anchor_subject', 'tenant_tag', 'replay_key'
            )),
            target_value TEXT NOT NULL CHECK (
                length(target_value) BETWEEN 1 AND 512 AND instr(target_value, char(0)) = 0
            ),
            revoked_at INTEGER NOT NULL CHECK (revoked_at > 0),
            reason TEXT NOT NULL CHECK (reason IN (
                'operator_request', 'credential_compromise', 'principal_offboarded',
                'tenant_offboarded', 'policy_withdrawn', 'incident_response'
            )),
            UNIQUE (target_kind, target_value),
            CHECK (
                target_kind IN ('capability_id', 'root_policy_rule')
                OR (length(target_value) = 64 AND target_value NOT GLOB '*[^0-9a-f]*')
            )
        ) STRICT;

        CREATE TABLE IF NOT EXISTS revocation_entry_tags (
            entry_id TEXT NOT NULL REFERENCES revocation_entries(entry_id),
            tag_key_id TEXT NOT NULL CHECK (
                length(tag_key_id) = 64 AND tag_key_id NOT GLOB '*[^0-9a-f]*'
            ),
            tag TEXT NOT NULL CHECK (length(tag) = 64 AND tag NOT GLOB '*[^0-9a-f]*'),
            PRIMARY KEY (entry_id, tag_key_id)
        ) STRICT, WITHOUT ROWID;

        CREATE INDEX IF NOT EXISTS idx_revocation_entry_tags_tag
            ON revocation_entry_tags(tag_key_id, tag);

        CREATE TABLE IF NOT EXISTS revoked_capabilities (
            capability_id TEXT PRIMARY KEY,
            revoked_at INTEGER NOT NULL,
            revocation_index INTEGER UNIQUE,
            admission_authority_commit_index INTEGER UNIQUE,
            revocation_entry_id TEXT NOT NULL REFERENCES revocation_entries(entry_id)
        );

        CREATE INDEX IF NOT EXISTS idx_revoked_capabilities_revoked_at
            ON revoked_capabilities(revoked_at);

        CREATE INDEX IF NOT EXISTS idx_revoked_capabilities_entry
            ON revoked_capabilities(revocation_entry_id);

        CREATE TABLE IF NOT EXISTS revocation_delta_log (
            seq INTEGER PRIMARY KEY CHECK (seq > 0),
            capability_id TEXT NOT NULL,
            revoked_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_revocation_delta_log_projection
            ON revocation_delta_log(capability_id, revoked_at);

        CREATE TABLE IF NOT EXISTS revocation_delta_meta (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            next_seq INTEGER NOT NULL CHECK (next_seq >= 0)
        );

        CREATE TABLE IF NOT EXISTS revocation_stream_meta (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            stream_id TEXT NOT NULL CHECK (stream_id <> '')
        );

        "#;
const REVOCATION_STANDALONE_SCHEMA: &str = r#"
            CREATE TABLE IF NOT EXISTS revocation_replication_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                next_index INTEGER NOT NULL CHECK (next_index >= 0)
            );
            "#;
const REVOCATION_AUTHORITY_SCHEMA: &str = r#"
            CREATE TABLE IF NOT EXISTS admission_authority_meta (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                head_index INTEGER NOT NULL CHECK (head_index > 0)
            );

            CREATE TABLE IF NOT EXISTS admission_authority_commits (
                commit_index INTEGER PRIMARY KEY CHECK (commit_index > 0),
                kind TEXT NOT NULL CHECK (kind IN ('genesis', 'revocation')),
                capability_id TEXT,
                CHECK (
                    (kind = 'genesis' AND capability_id IS NULL)
                    OR
                    (kind = 'revocation' AND capability_id IS NOT NULL)
                ),
                FOREIGN KEY (capability_id)
                    REFERENCES revoked_capabilities(capability_id)
            );

            "#;

pub(crate) fn initialize_revocation_schema(
    creation: &crate::schema_version::SchemaTransaction<'_>,
    shared_authority_sequence: bool,
) -> Result<(), RevocationStoreError> {
    let transaction = creation.connection();
    if creation.is_fresh() {
        transaction.execute_batch(REVOCATION_SCHEMA)?;
        transaction.execute_batch(if shared_authority_sequence {
            REVOCATION_AUTHORITY_SCHEMA
        } else {
            REVOCATION_STANDALONE_SCHEMA
        })?;
        transaction.execute(
            "INSERT INTO revocation_stream_meta (singleton, stream_id) VALUES (1, ?1)",
            [uuid::Uuid::now_v7().to_string()],
        )?;
        transaction.execute(
            "INSERT INTO revocation_delta_meta (singleton, next_seq) VALUES (1, 0)",
            [],
        )?;
        if shared_authority_sequence {
            transaction.execute(
                "INSERT INTO admission_authority_meta (singleton, head_index) VALUES (1, 1)",
                [],
            )?;
            transaction.execute("INSERT INTO admission_authority_commits (commit_index, kind, capability_id) VALUES (1, 'genesis', NULL)", [])?;
        } else {
            transaction.execute(
                "INSERT INTO revocation_replication_meta (singleton, next_index) VALUES (1, 0)",
                [],
            )?;
        }
        creation
            .stamp(REVOCATION_STORE_SCHEMA_KEY)
            .map_err(|error| RevocationStoreError::Sync(error.to_string()))?;
    }
    verify_revocation_delta_invariants(transaction)?;
    targets::verify_entry_tags(transaction)?;
    if shared_authority_sequence {
        verify_admission_authority_invariants(transaction)?;
    } else {
        let next: i64 = transaction.query_row(
            "SELECT next_index FROM revocation_replication_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let maximum: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(revocation_index), 0) FROM revoked_capabilities",
            [],
            |row| row.get(0),
        )?;
        let missing: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE revocation_index IS NULL)",
            [],
            |row| row.get(0),
        )?;
        if next < maximum || missing {
            return Err(RevocationStoreError::Sync(
                "revocation replication index is inconsistent".into(),
            ));
        }
    }
    Ok(())
}

fn rotate_revocation_stream_identity(
    connection: &mut Connection,
) -> Result<(), RevocationStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let updated = transaction.execute(
        "UPDATE revocation_stream_meta SET stream_id = ?1 WHERE singleton = 1",
        [uuid::Uuid::now_v7().to_string()],
    )?;
    if updated != 1 {
        return Err(RevocationStoreError::Sync(
            "revocation stream identity row is missing".to_string(),
        ));
    }
    transaction.commit()?;
    Ok(())
}

fn allocate_revocation_index(
    transaction: &Transaction<'_>,
    shared_authority_sequence: bool,
) -> Result<i64, RevocationStoreError> {
    let (table, column) = if shared_authority_sequence {
        ("admission_authority_meta", "head_index")
    } else {
        ("revocation_replication_meta", "next_index")
    };
    let current = transaction.query_row(
        &format!("SELECT {column} FROM {table} WHERE singleton = 1"),
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let next = current
        .checked_add(1)
        .ok_or_else(|| RevocationStoreError::Sync("revocation index overflowed i64".to_string()))?;
    transaction.execute(
        &format!("UPDATE {table} SET {column} = ?1 WHERE singleton = 1"),
        params![next],
    )?;
    Ok(next)
}

/// Allocate and append one row to the dense, append-only revocation delta log.
///
/// The mutable `revoked_capabilities` projection cannot itself be a sound delta
/// stream: updating one capability replaces its older projection row, and the
/// joint authority commit index is not the delta log's cursor contract. This
/// independent sequence advances exactly once for every accepted revocation
/// mutation and is written in the same transaction as the projection update.
fn append_revocation_delta(
    transaction: &Transaction<'_>,
    record: &RevocationRecord,
) -> Result<(), RevocationStoreError> {
    let current = transaction.query_row(
        "SELECT next_seq FROM revocation_delta_meta WHERE singleton = 1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let next = current.checked_add(1).ok_or_else(|| {
        RevocationStoreError::Sync("revocation delta sequence overflowed i64".to_string())
    })?;
    transaction.execute(
        "INSERT INTO revocation_delta_log (seq, capability_id, revoked_at) \
         VALUES (?1, ?2, ?3)",
        params![next, record.capability_id, record.revoked_at],
    )?;
    transaction.execute(
        "UPDATE revocation_delta_meta SET next_seq = ?1 WHERE singleton = 1",
        params![next],
    )?;
    Ok(())
}

fn verify_revocation_delta_invariants(connection: &Connection) -> Result<(), RevocationStoreError> {
    let projection_index_columns = {
        let mut statement =
            connection.prepare("PRAGMA index_info('idx_revocation_delta_log_projection')")?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(2))?
            .collect::<Result<Vec<_>, _>>()?;
        columns
    };
    if projection_index_columns != ["capability_id", "revoked_at"] {
        return Err(RevocationStoreError::Sync(
            "revocation projection-history index has an invalid shape".to_string(),
        ));
    }
    let (next_seq, row_count, min_seq, max_seq, projection_unlogged) = connection.query_row(
        r#"
        SELECT
            (SELECT next_seq FROM revocation_delta_meta WHERE singleton = 1),
            (SELECT COUNT(*) FROM revocation_delta_log),
            (SELECT COALESCE(MIN(seq), 0) FROM revocation_delta_log),
            (SELECT COALESCE(MAX(seq), 0) FROM revocation_delta_log),
            EXISTS(
                SELECT 1 FROM revoked_capabilities AS revoked
                WHERE NOT EXISTS (
                    SELECT 1 FROM revocation_delta_log AS delta
                    WHERE delta.capability_id = revoked.capability_id
                      AND delta.revoked_at = revoked.revoked_at
                )
            )
        "#,
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, bool>(4)?,
            ))
        },
    )?;
    let dense = if row_count == 0 {
        next_seq == 0 && min_seq == 0 && max_seq == 0
    } else {
        min_seq == 1 && row_count == max_seq && next_seq == max_seq
    };
    if !dense || projection_unlogged {
        return Err(RevocationStoreError::Sync(
            "revocation delta log is not a dense complete projection history".to_string(),
        ));
    }
    let stream_id = connection.query_row(
        "SELECT stream_id FROM revocation_stream_meta WHERE singleton = 1",
        [],
        |row| row.get::<_, String>(0),
    )?;
    let parsed = uuid::Uuid::parse_str(&stream_id).map_err(|_| {
        RevocationStoreError::Sync("revocation stream identity is not a valid UUID".to_string())
    })?;
    if parsed.get_version_num() != 7 {
        return Err(RevocationStoreError::Sync(
            "revocation stream identity is not a UUIDv7".to_string(),
        ));
    }
    Ok(())
}

fn append_admission_revocation_commit(
    transaction: &Transaction<'_>,
    commit_index: i64,
    capability_id: &str,
) -> Result<(), RevocationStoreError> {
    transaction.execute(
        r#"
        INSERT INTO admission_authority_commits (
            commit_index, kind, capability_id
        ) VALUES (?1, 'revocation', ?2)
        "#,
        params![commit_index, capability_id],
    )?;
    Ok(())
}

/// Rebuild a stored entry and refuse one whose id is not its target's.
fn stored_entry(
    entry_id: &str,
    kind: &str,
    value: &str,
    revoked_at: i64,
    reason: &str,
) -> Result<RevocationEntry, RevocationStoreError> {
    let invalid = |error: chio_core::root_authority::RootAuthorityShapeError| {
        RevocationStoreError::Sync(format!("stored revocation entry is invalid: {error}"))
    };
    let target =
        RevocationTarget::from_parts(RevocationTargetKind::parse(kind).map_err(invalid)?, value)
            .map_err(invalid)?;
    let revoked_at = u64::try_from(revoked_at).map_err(|_| {
        RevocationStoreError::Sync("stored revocation entry time is negative".to_string())
    })?;
    let entry = RevocationEntry::new(
        &target,
        revoked_at,
        RevocationReason::parse(reason).map_err(invalid)?,
    )
    .map_err(invalid)?;
    if entry.entry_id.as_str() != entry_id {
        return Err(RevocationStoreError::Sync(
            "stored revocation entry id does not match its target".to_string(),
        ));
    }
    Ok(entry)
}

fn stored_index(value: i64) -> Result<u64, RevocationStoreError> {
    u64::try_from(value)
        .map_err(|_| RevocationStoreError::Sync("negative revocation index".to_string()))
}

fn map_serving_owner_error(
    error: crate::serving_owner::SqliteServingOwnerError,
) -> RevocationStoreError {
    match error {
        crate::serving_owner::SqliteServingOwnerError::OutcomeUnknown(detail) => {
            RevocationStoreError::OutcomeUnknown(detail)
        }
        error => RevocationStoreError::Sync(error.to_string()),
    }
}

fn commit_mutation(
    store: &SqliteRevocationStore,
    transaction: Transaction<'_>,
) -> Result<(), RevocationStoreError> {
    transaction.commit().map_err(|error| {
        let detail = format!("sqlite revocation commit outcome is unknown: {error}");
        match store.serving_owner.as_ref() {
            Some(owner) => map_serving_owner_error(owner.outcome_unknown(detail)),
            None => RevocationStoreError::OutcomeUnknown(detail),
        }
    })
}

pub(crate) fn verify_admission_authority_invariants(
    connection: &Connection,
) -> Result<(), RevocationStoreError> {
    let (head, commit_count, max_commit, genesis_count) = connection.query_row(
        r#"
            SELECT
                (SELECT head_index FROM admission_authority_meta
                 WHERE singleton = 1),
                (SELECT COUNT(*) FROM admission_authority_commits),
                (SELECT COALESCE(MAX(commit_index), 0)
                 FROM admission_authority_commits),
                (SELECT COUNT(*) FROM admission_authority_commits
                 WHERE commit_index = 1 AND kind = 'genesis'
                   AND capability_id IS NULL)
            "#,
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )?;
    let invalid_projection = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM revoked_capabilities AS revoked
            WHERE admission_authority_commit_index IS NULL
               OR NOT EXISTS (
                   SELECT 1 FROM admission_authority_commits AS committed
                   WHERE committed.commit_index =
                             revoked.admission_authority_commit_index
                     AND committed.kind = 'revocation'
                     AND committed.capability_id = revoked.capability_id
               )
        )
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if head <= 0
        || commit_count != head
        || max_commit != head
        || genesis_count != 1
        || invalid_projection
    {
        return Err(RevocationStoreError::Sync(
            "admission authority commit log is not a dense valid projection".to_string(),
        ));
    }
    Ok(())
}

fn verify_revocation_foreign_keys(connection: &Connection) -> Result<(), RevocationStoreError> {
    let violation = connection
        .query_row("PRAGMA foreign_key_check", [], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .optional()?;
    if let Some((table, rowid)) = violation {
        return Err(RevocationStoreError::Sync(format!(
            "sqlite foreign key violation in `{table}` row {rowid}"
        )));
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
mod connection_recovery;
#[cfg(all(test, unix))]
pub(crate) use connection_recovery::write_probe_revocation;
#[cfg(all(test, unix))]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
mod entry_tests;

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
mod tests {

    use super::*;

    use chio_test_support::temp_sqlite_path;

    #[test]
    fn sqlite_revocation_store_persists_across_reopen() {
        let (_path_dir, path) = temp_sqlite_path("chio-revocations");
        {
            let store = SqliteRevocationStore::open(&path).unwrap();
            assert!(!store.is_revoked("cap-1").unwrap());
            assert!(store.revoke("cap-1").unwrap());
            assert!(store.is_revoked("cap-1").unwrap());
            assert!(!store.revoke("cap-1").unwrap());
        }

        let reopened = SqliteRevocationStore::open(&path).unwrap();
        assert!(reopened.is_revoked("cap-1").unwrap());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn revocation_stream_identity_is_durable_and_store_unique(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_first_path_dir, first_path) = temp_sqlite_path("chio-rev-stream-first");
        let (_second_path_dir, second_path) = temp_sqlite_path("chio-rev-stream-second");
        let first_id = SqliteRevocationStore::open(&first_path)?.revocation_stream_id()?;
        let reopened_id = SqliteRevocationStore::open(&first_path)?.revocation_stream_id()?;
        let second_id = SqliteRevocationStore::open(&second_path)?.revocation_stream_id()?;

        assert_eq!(first_id, reopened_id, "an ordinary reopen keeps the epoch");
        assert_ne!(
            first_id, second_id,
            "independent stores need distinct epochs"
        );
        assert_eq!(uuid::Uuid::parse_str(&first_id)?.get_version_num(), 7);

        let _ = fs::remove_file(first_path);
        let _ = fs::remove_file(second_path);
        Ok(())
    }

    #[test]
    fn replication_source_epoch_rotates_after_restored_sequence_reuse(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_path_dir, path) = temp_sqlite_path("chio-rev-stream-restore");
        let (_restored_snapshot_dir, restored_snapshot) =
            temp_sqlite_path("chio-rev-stream-snapshot");
        let store = SqliteRevocationStore::open(&path)?;
        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-first".to_string(),
            revoked_at: 10,
        })?;
        drop(store);
        fs::copy(&path, &restored_snapshot)?;

        let live = SqliteRevocationStore::open_replication_source(&path)?;
        let live_stream_id = live.revocation_stream_id()?;
        live.upsert_revocation(&RevocationRecord {
            capability_id: "cap-live-second".to_string(),
            revoked_at: 20,
        })?;
        assert_eq!(
            live.latest_revocation_stream_head()?.map(|row| row.seq),
            Some(2)
        );
        drop(live);

        fs::copy(&restored_snapshot, &path)?;
        let restored = SqliteRevocationStore::open_replication_source(&path)?;
        let restored_stream_id = restored.revocation_stream_id()?;
        restored.upsert_revocation(&RevocationRecord {
            capability_id: "cap-restored-second".to_string(),
            revoked_at: 20,
        })?;
        assert_eq!(
            restored.latest_revocation_stream_head()?.map(|row| row.seq),
            Some(2)
        );
        assert_ne!(
            live_stream_id, restored_stream_id,
            "equal restored heads must belong to distinct serving epochs"
        );

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(restored_snapshot);
        Ok(())
    }

    #[test]
    fn revocation_sequence_does_not_skip_same_second_backfill(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_path_dir, path) = temp_sqlite_path("chio-rev-sequence");
        let store = SqliteRevocationStore::open(&path)?;
        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-revoke-leader".to_string(),
            revoked_at: 100,
        })?;
        let first = store.list_revocations_after_seq(10, 0)?;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].seq, 1);

        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-revoke-leader".to_string(),
            revoked_at: 101,
        })?;
        store.upsert_revocation(&RevocationRecord {
            capability_id: "cap-revoke-follower".to_string(),
            revoked_at: 100,
        })?;
        let after = store.list_revocations_after_seq(10, first[0].seq)?;
        assert_eq!(after.len(), 2);
        assert_eq!(after[0].seq, 2);
        assert_eq!(after[0].record.capability_id, "cap-revoke-leader");
        assert_eq!(after[1].seq, 3);
        assert_eq!(after[1].record.capability_id, "cap-revoke-follower");
        assert_eq!(
            store
                .latest_revocation_stream_head()?
                .map(|stored| stored.seq),
            Some(3)
        );

        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn revocation_schema_other_than_current_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let (_path_dir, path) = temp_sqlite_path("chio-rev-stale-schema");
        drop(SqliteRevocationStore::open(&path)?);
        let connection = Connection::open(&path)?;
        crate::test_schema::write_version(&connection, REVOCATION_STORE_SCHEMA_KEY, 4)?;
        drop(connection);

        let error = SqliteRevocationStore::open(&path)
            .err()
            .ok_or("stale schema opened")?;
        assert_eq!(
            error.to_string(),
            "revocation store synchronization error: database schema version 4 is not the current schema version 1; refusing to open"
        );
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn unstamped_provisioned_revocation_database_is_refused(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_path_dir, path) = temp_sqlite_path("chio-rev-unstamped");
        drop(SqliteRevocationStore::open(&path)?);
        let connection = Connection::open(&path)?;
        connection.execute(
            "DELETE FROM chio_store_schema_versions WHERE store_key = ?1",
            [REVOCATION_STORE_SCHEMA_KEY],
        )?;
        drop(connection);

        let error = SqliteRevocationStore::open(&path)
            .err()
            .ok_or("unstamped store opened")?;
        assert_eq!(
            error.to_string(),
            "revocation store synchronization error: schema namespace revocation is missing"
        );
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn file_backed_revocation_store_reports_durable() {
        let (_path_dir, path) = temp_sqlite_path("chio-rev-durable");
        let store = SqliteRevocationStore::open(&path).unwrap();
        assert!(
            !store.is_ephemeral(),
            "a filesystem-backed revocation store is durable"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn in_memory_revocation_store_reports_ephemeral() {
        for path in [":memory:", "file::memory:", "file:rev?mode=memory"] {
            let store = SqliteRevocationStore::open(path).unwrap();
            assert!(
                store.is_ephemeral(),
                "in-memory revocation store {path} must report ephemeral so the durability gate refuses it"
            );
        }
    }

    #[test]
    fn open_creates_parent_dirs_for_a_file_uri_with_query() {
        let (_base_dir, base) = chio_test_support::temp_sqlite_path("chio-rev-uri");
        let db = base.join("nested").join("receipts.db.revocations");
        let parent = db.parent().expect("db path has a parent");
        assert!(
            !parent.exists(),
            "precondition: the parent dir must not exist yet"
        );

        // A `file:` URI sibling path carrying a query. A raw `parent()` would
        // resolve to `file:.../nested`, create a bogus relative directory, and
        // leave the real parent uncreated, so SQLite would fail to open it.
        let uri = format!("file:{}?mode=rwc", db.display());
        let store = SqliteRevocationStore::open(uri.as_str()).unwrap();

        assert!(
            !store.is_ephemeral(),
            "a file: URI to a real filesystem path is durable"
        );
        assert!(
            parent.exists(),
            "the real parent directory must be created before SQLite opens the URI"
        );
    }

    #[test]
    fn sqlite_revocation_store_lists_filtered_entries() {
        let (_path_dir, path) = temp_sqlite_path("chio-revocations-filtered");
        let store = SqliteRevocationStore::open(&path).unwrap();
        assert!(store.revoke("cap-1").unwrap());
        assert!(store.revoke("cap-2").unwrap());

        let all = store.list_revocations(10, None).unwrap();
        assert_eq!(all.len(), 2);

        let filtered = store.list_revocations(10, Some("cap-1")).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].capability_id, "cap-1");

        let _ = fs::remove_file(path);
    }
}
