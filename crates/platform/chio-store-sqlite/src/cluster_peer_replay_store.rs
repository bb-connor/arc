//! Durable per-peer `issued_at` high-water marks for trust-control cluster
//! peer authentication.
//!
//! The receiver stores one row per cluster peer: the highest `issued_at` it
//! has accepted from that peer. A restarted receiver loads every row and
//! refuses each request issued at or below its peer's mark, so replay closure
//! across a restart does not depend on the receiver clock.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::store_connection::StoreConnection;
use crate::{SchemaTransaction, SchemaVersionError};

const SCHEMA_KEY: &str = "cluster_peer_replay";

const SCHEMA: &str = "CREATE TABLE cluster_peer_replay_high_water (
    node_id TEXT NOT NULL PRIMARY KEY CHECK (octet_length(node_id) BETWEEN 1 AND 2048),
    issued_at INTEGER NOT NULL CHECK (issued_at >= 0)
) STRICT";

/// Most peer rows one store holds. A request from a peer without a row is
/// refused once the store is full.
pub const CLUSTER_PEER_REPLAY_MAX_PEERS: usize = 4096;

const MAX_NODE_ID_BYTES: usize = 2048;

#[derive(Debug, thiserror::Error)]
pub enum ClusterPeerReplayStoreError {
    #[error("cluster peer replay store requires a durable file path")]
    InvalidPath,
    #[error("cluster peer replay store schema refused: {0}")]
    Schema(#[from] SchemaVersionError),
    #[error("cluster peer replay store sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("cluster peer replay store filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("cluster peer replay store is unavailable: {0}")]
    Unavailable(String),
    #[error("cluster peer replay store holds an invalid high-water row")]
    InvalidRow,
    #[error("cluster peer replay store already holds {CLUSTER_PEER_REPLAY_MAX_PEERS} peers")]
    CapacityExhausted,
    #[error("cluster peer replay high-water is already at or above the request issue time")]
    NotAdvanced,
}

/// One SQLite file holding the high-water mark of every cluster peer.
pub struct SqliteClusterPeerReplayStore {
    connection: StoreConnection,
}

impl std::fmt::Debug for SqliteClusterPeerReplayStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteClusterPeerReplayStore")
            .finish_non_exhaustive()
    }
}

impl SqliteClusterPeerReplayStore {
    /// Open or create the store at `path`. An in-memory database, a foreign
    /// database, a database of another schema or an invalid row refuses.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ClusterPeerReplayStoreError> {
        let path = path.as_ref();
        let text = path.to_string_lossy();
        if text.is_empty() || text.eq_ignore_ascii_case(":memory:") || text.starts_with("file:") {
            return Err(ClusterPeerReplayStoreError::InvalidPath);
        }
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            std::fs::create_dir_all(parent)?;
        }
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let schema = SchemaTransaction::begin(&mut connection, &[SCHEMA_KEY])?;
        if schema.is_fresh() {
            schema.connection().execute_batch(SCHEMA)?;
            schema.stamp(SCHEMA_KEY)?;
        }
        schema.validate_catalog(SCHEMA)?;
        read_high_waters(schema.connection())?;
        schema.commit()?;
        connection.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
        Ok(Self {
            connection: StoreConnection::transaction_only("cluster_peer_replay", connection),
        })
    }

    /// Every stored peer high-water mark, by node id.
    pub fn high_waters(&self) -> Result<BTreeMap<String, i64>, ClusterPeerReplayStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|fenced| ClusterPeerReplayStoreError::Unavailable(fenced.to_string()))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let high_waters = read_high_waters(&transaction)?;
        transaction.commit()?;
        Ok(high_waters)
    }

    /// Raise `node_id`'s high-water mark to `issued_at`. Refuses with
    /// `NotAdvanced` unless `issued_at` is strictly greater than the stored
    /// mark, and with `CapacityExhausted` when a new peer row would exceed
    /// [`CLUSTER_PEER_REPLAY_MAX_PEERS`].
    pub fn advance(
        &self,
        node_id: &str,
        issued_at: i64,
    ) -> Result<(), ClusterPeerReplayStoreError> {
        if !valid_node_id(node_id) || issued_at < 0 {
            return Err(ClusterPeerReplayStoreError::InvalidRow);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|fenced| ClusterPeerReplayStoreError::Unavailable(fenced.to_string()))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<i64> = transaction
            .query_row(
                "SELECT issued_at FROM cluster_peer_replay_high_water WHERE node_id = ?1",
                [node_id],
                |row| row.get(0),
            )
            .optional()?;
        match stored {
            Some(stored) if stored >= issued_at => {
                return Err(ClusterPeerReplayStoreError::NotAdvanced);
            }
            Some(_) => {
                transaction.execute(
                    "UPDATE cluster_peer_replay_high_water SET issued_at = ?2 WHERE node_id = ?1 AND issued_at < ?2",
                    params![node_id, issued_at],
                )?;
            }
            None => {
                let rows: i64 = transaction.query_row(
                    "SELECT count(*) FROM cluster_peer_replay_high_water",
                    [],
                    |row| row.get(0),
                )?;
                if usize::try_from(rows).map_err(|_| ClusterPeerReplayStoreError::InvalidRow)?
                    >= CLUSTER_PEER_REPLAY_MAX_PEERS
                {
                    return Err(ClusterPeerReplayStoreError::CapacityExhausted);
                }
                transaction.execute(
                    "INSERT INTO cluster_peer_replay_high_water (node_id, issued_at) VALUES (?1, ?2)",
                    params![node_id, issued_at],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }
}

fn valid_node_id(node_id: &str) -> bool {
    !node_id.is_empty() && node_id.len() <= MAX_NODE_ID_BYTES
}

/// Read every stored mark. The row count and each column's type and size are
/// bounded in SQL, so a corrupt row is refused before any of it is copied out.
fn read_high_waters(
    connection: &Connection,
) -> Result<BTreeMap<String, i64>, ClusterPeerReplayStoreError> {
    let rows: i64 = connection.query_row(
        "SELECT count(*) FROM cluster_peer_replay_high_water",
        [],
        |row| row.get(0),
    )?;
    if !usize::try_from(rows).is_ok_and(|rows| rows <= CLUSTER_PEER_REPLAY_MAX_PEERS) {
        return Err(ClusterPeerReplayStoreError::InvalidRow);
    }
    let mut statement = connection.prepare(&format!(
        "SELECT CASE WHEN typeof(node_id) = 'text' AND octet_length(node_id) BETWEEN 1 AND {MAX_NODE_ID_BYTES} THEN node_id END, \
                CASE WHEN typeof(issued_at) = 'integer' AND issued_at >= 0 THEN issued_at END \
         FROM cluster_peer_replay_high_water"
    ))?;
    let mut rows = statement.query([])?;
    let mut high_waters = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let node_id = match row.get_ref(0)? {
            ValueRef::Text(bytes) => std::str::from_utf8(bytes)
                .map_err(|_| ClusterPeerReplayStoreError::InvalidRow)?
                .to_owned(),
            _ => return Err(ClusterPeerReplayStoreError::InvalidRow),
        };
        let ValueRef::Integer(issued_at) = row.get_ref(1)? else {
            return Err(ClusterPeerReplayStoreError::InvalidRow);
        };
        if high_waters.insert(node_id, issued_at).is_some() {
            return Err(ClusterPeerReplayStoreError::InvalidRow);
        }
    }
    Ok(high_waters)
}

#[cfg(test)]
#[path = "cluster_peer_replay_store_tests.rs"]
mod tests;
