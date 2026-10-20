//! Qualified S1 graph issuer under the serving authority.
//!
//! The issuer head advances only by an expected-head compare-and-swap that
//! verifies the strict additive extension, archives the predecessor by its
//! task-graph digest and retains the issuance by candidate digest, so an
//! acknowledged-lost advance resolves to its original success after later
//! heads. Runtime graph copies are evidence lookups, never issuers.

use std::sync::Arc;

use chio_core::crypto::PublicKey;
use chio_core::{sha256_hex, StoreMutationFence};
use chio_swarm_authority::{
    verify_swarm_authority_extension, verify_swarm_authority_for_admission, SwarmAuthorityBundle,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;

use crate::admission_operation_store::{verify_active_owner, verify_trusted_time};
use crate::serving_owner::{SqliteServingOwner, SqliteServingOwnerError};
use crate::store_connection::{StoreConnection, StoreGuard};

const SCHEMA_KEY: &str = "work_graph";
const SCHEMA: &str = include_str!("work_graph_store.sql");
const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

pub(crate) const PROJECTION: &str = "work_graph";
const PROJECTION_KEY: &str = "issuer";

type SchemaCatalogEntry = (String, String, String, Option<String>);

#[derive(Debug, thiserror::Error)]
pub enum SqliteWorkGraphStoreError {
    #[error("graph authority rejected: {0}")]
    Rejected(String),
    #[error("graph head is not the expected parent")]
    StaleHead,
    #[error("graph is not provisioned")]
    NotProvisioned,
    #[error("graph root conflicts with its retained root")]
    RootConflict,
    #[error("graph store is unavailable: {0}")]
    Unavailable(String),
    #[error("graph store invariant failed: {0}")]
    Invalid(String),
}

type Result<T> = std::result::Result<T, SqliteWorkGraphStoreError>;

/// A committed issuance, readable by its candidate digest after later heads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkGraphIssuance {
    pub graph_id: String,
    pub bundle_sha256: String,
    pub parent_bundle_sha256: Option<String>,
    pub revision: u64,
}

/// Serving-bound S1 graph issuer. Construct it with
/// [`crate::SqliteAuthorityStore::work_graph_store`].
pub struct SqliteWorkGraphStore {
    connection: Arc<StoreConnection>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteWorkGraphStore {
    pub(crate) fn open_alongside(
        connection: Arc<StoreConnection>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    pub fn mutation_fence(&self) -> StoreMutationFence {
        self.serving_owner.fence.clone()
    }

    /// Trusted owner configuration installing the first issued version.
    pub fn provision_root(
        &self,
        bundle: SwarmAuthorityBundle,
        trusted_keys: &[PublicKey],
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<WorkGraphIssuance> {
        self.mutate(fence, trusted_now_unix_ms, |tx, now| {
            let mut checked = bundle.clone();
            checked.now_unix_ms = now;
            verify_swarm_authority_for_admission(&checked, trusted_keys)
                .map_err(|error| SqliteWorkGraphStoreError::Rejected(error.runtime_detail()))?;
            let graph_id = bundle.task_graph.graph_id.clone();
            let digest = canonical_sha256(&bundle)?;
            if let Some(head) = head_row(tx, &graph_id)? {
                let root = issuance_row(tx, &head.root_sha256(tx)?)?;
                return match root {
                    Some(issuance) if issuance.bundle_sha256 == digest => Ok((issuance, false)),
                    _ => Err(SqliteWorkGraphStoreError::RootConflict),
                };
            }
            tx.execute(
                "INSERT INTO work_graph_heads (graph_id, bundle_sha256, bundle, revision)
                 VALUES (?1, ?2, ?3, 1)",
                params![graph_id, digest, encode(&bundle)?],
            )
            .map_err(sqlite_error)?;
            let issuance = WorkGraphIssuance {
                graph_id,
                bundle_sha256: digest,
                parent_bundle_sha256: None,
                revision: 1,
            };
            insert_issuance(tx, &issuance)?;
            Ok((issuance, true))
        })
    }

    /// Advance the issuer head from `expected_bundle_sha256` to `candidate`.
    /// Replaying an already committed candidate returns its original issuance
    /// even after later heads, and changes nothing.
    pub fn advance(
        &self,
        expected_bundle_sha256: &str,
        candidate: SwarmAuthorityBundle,
        trusted_keys: &[PublicKey],
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<WorkGraphIssuance> {
        self.mutate(fence, trusted_now_unix_ms, |tx, now| {
            let digest = canonical_sha256(&candidate)?;
            if let Some(issuance) = issuance_row(tx, &digest)? {
                if issuance.parent_bundle_sha256.as_deref() != Some(expected_bundle_sha256) {
                    return Err(SqliteWorkGraphStoreError::StaleHead);
                }
                return Ok((issuance, false));
            }
            let graph_id = candidate.task_graph.graph_id.clone();
            let head = head_row(tx, &graph_id)?.ok_or(SqliteWorkGraphStoreError::NotProvisioned)?;
            if head.bundle_sha256 != expected_bundle_sha256 {
                return Err(SqliteWorkGraphStoreError::StaleHead);
            }
            let parent = head.decode()?;
            verify_swarm_authority_extension(&parent, &candidate, trusted_keys, now)
                .map_err(|error| SqliteWorkGraphStoreError::Rejected(error.runtime_detail()))?;
            tx.execute(
                "INSERT INTO work_graph_versions
                     (graph_id, graph_sha256, bundle_sha256, bundle, successor_bundle_sha256)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    graph_id,
                    canonical_sha256(&parent.task_graph)?,
                    head.bundle_sha256,
                    head.bundle,
                    digest
                ],
            )
            .map_err(sqlite_error)?;
            let revision = head
                .revision
                .checked_add(1)
                .ok_or_else(|| invalid("graph revision overflow"))?;
            tx.execute(
                "UPDATE work_graph_heads SET bundle_sha256 = ?1, bundle = ?2, revision = ?3
                 WHERE graph_id = ?4",
                params![digest, encode(&candidate)?, sql_u64(revision)?, graph_id],
            )
            .map_err(sqlite_error)?;
            let issuance = WorkGraphIssuance {
                graph_id,
                bundle_sha256: digest,
                parent_bundle_sha256: Some(head.bundle_sha256),
                revision,
            };
            insert_issuance(tx, &issuance)?;
            Ok((issuance, true))
        })
    }

    /// The current issued head and its digest.
    pub fn head(&self, graph_id: &str) -> Result<Option<(SwarmAuthorityBundle, String)>> {
        self.read_only(|tx| {
            head_row(tx, graph_id)?
                .map(|head| Ok((head.decode()?, head.bundle_sha256)))
                .transpose()
        })
    }

    /// The issued version whose task graph has `graph_sha256`.
    pub fn version(
        &self,
        graph_id: &str,
        graph_sha256: &str,
    ) -> Result<Option<SwarmAuthorityBundle>> {
        self.read_only(|tx| {
            if let Some(head) = head_row(tx, graph_id)? {
                let bundle = head.decode()?;
                if canonical_sha256(&bundle.task_graph)? == graph_sha256 {
                    return Ok(Some(bundle));
                }
            }
            let row: Option<(String, String)> = tx
                .query_row(
                    "SELECT bundle_sha256, bundle FROM work_graph_versions
                     WHERE graph_id = ?1 AND graph_sha256 = ?2",
                    params![graph_id, graph_sha256],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(sqlite_error)?;
            row.map(|(digest, text)| decode_bundle(graph_id, &digest, &text))
                .transpose()
        })
    }

    /// Original issuance readback by candidate digest.
    pub fn issuance(&self, bundle_sha256: &str) -> Result<Option<WorkGraphIssuance>> {
        self.read_only(|tx| issuance_row(tx, bundle_sha256))
    }

    fn connection(&self) -> Result<StoreGuard<'_>> {
        self.connection
            .lock()
            .map_err(|error| SqliteWorkGraphStoreError::Unavailable(error.to_string()))
    }

    fn read_only<T>(&self, read: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&tx, &self.serving_owner, None).map_err(unavailable)?;
        self.serving_owner
            .verify_authority_anchor(&tx)
            .map_err(unavailable)?;
        read(&tx)
    }

    /// Run one fenced mutation. The closure returns the issuance and whether
    /// it was newly committed; a new issuance is one event and one global
    /// authority commit.
    fn mutate(
        &self,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
        apply: impl FnOnce(&Transaction<'_>, u64) -> Result<(WorkGraphIssuance, bool)>,
    ) -> Result<WorkGraphIssuance> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence)).map_err(unavailable)?;
        self.serving_owner
            .verify_authority_anchor(&tx)
            .map_err(unavailable)?;
        verify_trusted_time(&tx, trusted_now_unix_ms, &self.serving_owner).map_err(unavailable)?;
        let (issuance, fresh) = apply(&tx, trusted_now_unix_ms)?;
        if !fresh {
            return Ok(issuance);
        }
        let previous: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(sequence), 0) FROM work_graph_events",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let sequence = u64::try_from(previous)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| invalid("graph event sequence overflow"))?;
        tx.execute(
            "INSERT INTO work_graph_events (sequence, bundle_sha256) VALUES (?1, ?2)",
            params![sql_u64(sequence)?, issuance.bundle_sha256],
        )
        .map_err(sqlite_error)?;
        self.serving_owner
            .append_global_commit(
                &tx,
                if issuance.parent_bundle_sha256.is_some() {
                    "work_graph_advance"
                } else {
                    "work_graph_provision_root"
                },
                PROJECTION,
                PROJECTION_KEY,
                sequence,
            )
            .map_err(unavailable)?;
        tx.commit().map_err(|error| {
            SqliteWorkGraphStoreError::Unavailable(
                self.serving_owner
                    .outcome_unknown(format!("sqlite graph issuer commit is unknown: {error}"))
                    .to_string(),
            )
        })?;
        self.serving_owner
            .sync_authority_anchor(&connection)
            .map_err(unavailable)?;
        Ok(issuance)
    }
}

struct HeadRow {
    graph_id: String,
    bundle_sha256: String,
    bundle: String,
    revision: u64,
}

impl HeadRow {
    fn decode(&self) -> Result<SwarmAuthorityBundle> {
        decode_bundle(&self.graph_id, &self.bundle_sha256, &self.bundle)
    }

    fn root_sha256(&self, connection: &Connection) -> Result<String> {
        connection
            .query_row(
                "SELECT bundle_sha256 FROM work_graph_issuances WHERE graph_id = ?1 AND revision = 1",
                [&self.graph_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error)
    }
}

fn head_row(connection: &Connection, graph_id: &str) -> Result<Option<HeadRow>> {
    connection
        .query_row(
            "SELECT bundle_sha256, bundle, revision FROM work_graph_heads WHERE graph_id = ?1",
            [graph_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .map(|(bundle_sha256, bundle, revision)| {
            Ok(HeadRow {
                graph_id: graph_id.to_owned(),
                bundle_sha256,
                bundle,
                revision: u64::try_from(revision).map_err(|_| invalid("stored graph revision"))?,
            })
        })
        .transpose()
}

fn issuance_row(connection: &Connection, bundle_sha256: &str) -> Result<Option<WorkGraphIssuance>> {
    connection
        .query_row(
            "SELECT graph_id, parent_bundle_sha256, revision FROM work_graph_issuances
             WHERE bundle_sha256 = ?1",
            [bundle_sha256],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .map(|(graph_id, parent_bundle_sha256, revision)| {
            Ok(WorkGraphIssuance {
                graph_id,
                bundle_sha256: bundle_sha256.to_owned(),
                parent_bundle_sha256,
                revision: u64::try_from(revision).map_err(|_| invalid("stored graph revision"))?,
            })
        })
        .transpose()
}

fn insert_issuance(tx: &Transaction<'_>, issuance: &WorkGraphIssuance) -> Result<()> {
    tx.execute(
        "INSERT INTO work_graph_issuances (bundle_sha256, graph_id, parent_bundle_sha256, revision)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            issuance.bundle_sha256,
            issuance.graph_id,
            issuance.parent_bundle_sha256,
            sql_u64(issuance.revision)?
        ],
    )
    .map_err(sqlite_error)?;
    Ok(())
}

fn decode_bundle(graph_id: &str, digest: &str, text: &str) -> Result<SwarmAuthorityBundle> {
    let bundle: SwarmAuthorityBundle =
        chio_core::canonical::UntrustedJsonText::from_wire(text.as_bytes(), MAX_BUNDLE_BYTES)
            .and_then(|text| text.decode_signed())
            .map_err(|error| invalid(error.to_string()))?;
    if bundle.task_graph.graph_id != graph_id || canonical_sha256(&bundle)? != digest {
        return Err(invalid(
            "stored graph bundle does not match its index and digest",
        ));
    }
    Ok(bundle)
}

fn canonical_sha256(value: &impl Serialize) -> Result<String> {
    chio_core::canonical::canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| invalid(error.to_string()))
}

fn encode(value: &impl Serialize) -> Result<String> {
    let bytes = chio_core::canonical::canonical_json_bytes(value)
        .map_err(|error| invalid(error.to_string()))?;
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(invalid("graph bundle byte limit"));
    }
    String::from_utf8(bytes).map_err(|error| invalid(error.to_string()))
}

fn sql_u64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| invalid("integer exceeds SQLite range"))
}

fn sqlite_error(error: rusqlite::Error) -> SqliteWorkGraphStoreError {
    SqliteWorkGraphStoreError::Unavailable(error.to_string())
}

fn unavailable(error: impl std::fmt::Display) -> SqliteWorkGraphStoreError {
    SqliteWorkGraphStoreError::Unavailable(error.to_string())
}

fn invalid(detail: impl Into<String>) -> SqliteWorkGraphStoreError {
    SqliteWorkGraphStoreError::Invalid(detail.into())
}

fn owner_invalid(detail: impl Into<String>) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(detail.into())
}

pub(crate) fn initialize_work_graph_schema(
    schema: &crate::schema_version::SchemaTransaction<'_>,
) -> std::result::Result<(), SqliteServingOwnerError> {
    let transaction = schema.connection();

    if schema.is_fresh() {
        transaction.execute_batch(SCHEMA)?;

        schema
            .stamp(SCHEMA_KEY)
            .map_err(|error| owner_invalid(error.to_string()))?;
    }
    verify_work_graph_invariants(transaction)
}

/// The schema matches its canonical definition, every head is the latest
/// issuance of its graph and decodes to its digest, and every issuance has
/// exactly one event.
pub(crate) fn verify_work_graph_invariants(
    connection: &Connection,
) -> std::result::Result<(), SqliteServingOwnerError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SCHEMA)?;
    if schema_catalog(connection)? != schema_catalog(&expected)? {
        return Err(owner_invalid(
            "graph issuer schema differs from the canonical definition",
        ));
    }
    let mismatched: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM work_graph_heads h
            WHERE h.bundle_sha256 <> (
                SELECT i.bundle_sha256 FROM work_graph_issuances i
                WHERE i.graph_id = h.graph_id ORDER BY i.revision DESC LIMIT 1)
               OR h.revision <> (
                SELECT MAX(i.revision) FROM work_graph_issuances i WHERE i.graph_id = h.graph_id))
         OR EXISTS(
            SELECT 1 FROM work_graph_issuances i
            WHERE (SELECT COUNT(*) FROM work_graph_events e
                   WHERE e.bundle_sha256 = i.bundle_sha256) <> 1)",
        [],
        |row| row.get(0),
    )?;
    if mismatched {
        return Err(owner_invalid(
            "graph issuer heads, issuances and events do not correspond",
        ));
    }
    let mut statement =
        connection.prepare("SELECT graph_id, bundle_sha256, bundle FROM work_graph_heads")?;
    let heads = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (graph_id, digest, text) in heads {
        decode_bundle(&graph_id, &digest, &text)
            .map_err(|error| owner_invalid(error.to_string()))?;
    }
    Ok(())
}

/// The digest the global commit chain references for one graph event.
pub(crate) fn projection_reference(
    connection: &Connection,
    key: &str,
    sequence: u64,
) -> std::result::Result<String, SqliteServingOwnerError> {
    if key != PROJECTION_KEY {
        return Err(owner_invalid("graph issuer projection key is invalid"));
    }
    let sequence = i64::try_from(sequence)
        .map_err(|_| owner_invalid("graph issuer projection sequence is out of range"))?;
    let row: Option<(String, String, Option<String>, i64)> = connection
        .query_row(
            "SELECT e.bundle_sha256, i.graph_id, i.parent_bundle_sha256, i.revision
             FROM work_graph_events e JOIN work_graph_issuances i
               ON i.bundle_sha256 = e.bundle_sha256
             WHERE e.sequence = ?1",
            [sequence],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let (bundle_sha256, graph_id, parent, revision) =
        row.ok_or_else(|| owner_invalid("graph issuer projection reference is absent"))?;
    let bytes = chio_core::canonical::canonical_json_bytes(&(
        "chio.work-graph-event.v1",
        sequence,
        bundle_sha256,
        graph_id,
        parent,
        revision,
    ))
    .map_err(|error| owner_invalid(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Every graph event has exactly one global reference, and every global
/// reference names a graph event.
pub(crate) fn verify_projection_coverage(
    connection: &Connection,
) -> std::result::Result<(), SqliteServingOwnerError> {
    let events: i64 =
        connection.query_row("SELECT COUNT(*) FROM work_graph_events", [], |row| {
            row.get(0)
        })?;
    let global: i64 = connection.query_row(
        "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1",
        [PROJECTION],
        |row| row.get(0),
    )?;
    let matched: i64 = connection.query_row(
        "SELECT COUNT(*) FROM work_graph_events e
         JOIN authority_global_commits g
           ON g.projection_kind = ?1 AND g.projection_key = ?2
          AND g.projection_sequence = e.sequence",
        params![PROJECTION, PROJECTION_KEY],
        |row| row.get(0),
    )?;
    if events != global || events != matched {
        return Err(owner_invalid(
            "graph issuer events and global commits do not correspond",
        ));
    }
    Ok(())
}

fn schema_catalog(
    connection: &Connection,
) -> std::result::Result<Vec<SchemaCatalogEntry>, SqliteServingOwnerError> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE name GLOB 'work_graph_*' OR tbl_name GLOB 'work_graph_*'
         ORDER BY type, name, tbl_name",
    )?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(entries)
}
