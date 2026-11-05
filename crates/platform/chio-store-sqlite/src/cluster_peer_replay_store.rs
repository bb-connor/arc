//! SQLite cluster peer replay high-water store: one row per cluster peer.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use chio_security_types::ports::{
    ClusterPeerNodeId, PeerIssuedAtSecs, PeerReplayHighWaterStore, PeerReplayStoreError,
    CLUSTER_PEER_NODE_ID_MAX_BYTES, CLUSTER_PEER_REPLAY_MAX_PEERS,
};
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, ErrorCode, OptionalExtension, TransactionBehavior};

use crate::store_connection::StoreConnection;
use crate::{SchemaTransaction, SchemaVersionError};

const SCHEMA_KEY: &str = "cluster_peer_replay";

const SCHEMA: &str = "CREATE TABLE cluster_peer_replay_high_water (
    node_id TEXT NOT NULL PRIMARY KEY CHECK (octet_length(node_id) BETWEEN 1 AND 2048),
    issued_at INTEGER NOT NULL CHECK (issued_at >= 0)
) STRICT";

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
    #[error("cluster peer replay store holds an invalid high-water row")]
    InvalidRow,
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
}

impl PeerReplayHighWaterStore for SqliteClusterPeerReplayStore {
    fn high_waters(
        &self,
    ) -> Result<BTreeMap<ClusterPeerNodeId, PeerIssuedAtSecs>, PeerReplayStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| PeerReplayStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_fault)?;
        let high_waters = read_high_waters(&transaction).map_err(|error| match error {
            ClusterPeerReplayStoreError::Sqlite(error) => sqlite_fault(error),
            _ => PeerReplayStoreError::IntegrityFailure,
        })?;
        transaction.commit().map_err(sqlite_fault)?;
        Ok(high_waters)
    }

    fn advance(
        &self,
        node_id: &ClusterPeerNodeId,
        issued_at: PeerIssuedAtSecs,
    ) -> Result<(), PeerReplayStoreError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| PeerReplayStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_fault)?;
        let stored: Option<i64> = transaction
            .query_row(
                "SELECT issued_at FROM cluster_peer_replay_high_water WHERE node_id = ?1",
                [node_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_fault)?;
        match stored {
            Some(stored) if stored >= issued_at.get() => {
                return Err(PeerReplayStoreError::NotAdvanced);
            }
            Some(_) => {
                transaction
                    .execute(
                        "UPDATE cluster_peer_replay_high_water SET issued_at = ?2 WHERE node_id = ?1 AND issued_at < ?2",
                        params![node_id.as_str(), issued_at.get()],
                    )
                    .map_err(sqlite_fault)?;
            }
            None => {
                let rows: i64 = transaction
                    .query_row(
                        "SELECT count(*) FROM cluster_peer_replay_high_water",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(sqlite_fault)?;
                if usize::try_from(rows).map_err(|_| PeerReplayStoreError::IntegrityFailure)?
                    >= CLUSTER_PEER_REPLAY_MAX_PEERS
                {
                    return Err(PeerReplayStoreError::CapacityExhausted);
                }
                transaction
                    .execute(
                        "INSERT INTO cluster_peer_replay_high_water (node_id, issued_at) VALUES (?1, ?2)",
                        params![node_id.as_str(), issued_at.get()],
                    )
                    .map_err(sqlite_fault)?;
            }
        }
        transaction.commit().map_err(sqlite_fault)
    }
}

fn sqlite_fault(error: rusqlite::Error) -> PeerReplayStoreError {
    match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => {
            PeerReplayStoreError::IntegrityFailure
        }
        _ => PeerReplayStoreError::Unavailable,
    }
}

/// Read every stored mark. The row count and each column's type and stored
/// size are bounded in SQL, so a corrupt row is refused before any of it is
/// copied out. The decoded UTF-8 node id is bounded again before it is owned:
/// a UTF-16 database stores up to 2048 octets that decode to more UTF-8 bytes.
fn read_high_waters(
    connection: &Connection,
) -> Result<BTreeMap<ClusterPeerNodeId, PeerIssuedAtSecs>, ClusterPeerReplayStoreError> {
    let rows: i64 = connection.query_row(
        "SELECT count(*) FROM cluster_peer_replay_high_water",
        [],
        |row| row.get(0),
    )?;
    if !usize::try_from(rows).is_ok_and(|rows| rows <= CLUSTER_PEER_REPLAY_MAX_PEERS) {
        return Err(ClusterPeerReplayStoreError::InvalidRow);
    }
    let mut statement = connection.prepare(&format!(
        "SELECT CASE WHEN typeof(node_id) = 'text' AND octet_length(node_id) BETWEEN 1 AND {CLUSTER_PEER_NODE_ID_MAX_BYTES} THEN node_id END, \
                CASE WHEN typeof(issued_at) = 'integer' AND issued_at >= 0 THEN issued_at END \
         FROM cluster_peer_replay_high_water"
    ))?;
    let mut rows = statement.query([])?;
    let mut high_waters = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let node_id = match row.get_ref(0)? {
            ValueRef::Text(bytes) if bytes.len() <= CLUSTER_PEER_NODE_ID_MAX_BYTES => {
                std::str::from_utf8(bytes)
                    .ok()
                    .and_then(ClusterPeerNodeId::new)
                    .ok_or(ClusterPeerReplayStoreError::InvalidRow)?
            }
            _ => return Err(ClusterPeerReplayStoreError::InvalidRow),
        };
        let ValueRef::Integer(issued_at) = row.get_ref(1)? else {
            return Err(ClusterPeerReplayStoreError::InvalidRow);
        };
        let issued_at =
            PeerIssuedAtSecs::new(issued_at).ok_or(ClusterPeerReplayStoreError::InvalidRow)?;
        if high_waters.insert(node_id, issued_at).is_some() {
            return Err(ClusterPeerReplayStoreError::InvalidRow);
        }
    }
    Ok(high_waters)
}

#[cfg(test)]
#[path = "cluster_peer_replay_store_tests.rs"]
mod tests;
