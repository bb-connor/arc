//! Durable sparse-Merkle revocation oracle backed by SQLite.
//!
//! The sparse-Merkle oracle is a pure function of the ordered sequence of
//! inserted leaves, so the database stores that sequence (subject, epoch
//! nonce and insertion time, numbered densely from one) and every handle
//! rebuilds the same tree by replay. The sequence number of the newest leaf
//! equals the leaf count, and a stored sequence with a gap is corrupt. A
//! handle consults the database before each read and each write, so
//! revocations committed through another handle or process on the same file
//! are observed without a restart.
//!
//! Writes run inside one `BEGIN IMMEDIATE` transaction: the handle replays any
//! leaves committed by peers, stages the new leaves against a copy of the
//! tree, persists them, commits, and only then publishes the staged tree. A
//! failure rolls back and leaves both the database and the handle unchanged.
//!
//! The schema is versioned. A database without this oracle's stamp, with any
//! other version, or whose oracle tables and indexes differ from the catalog
//! this version creates, is refused without repair.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};

use crate::api::{
    EpochNonce, EpochRoot, InclusionProof, NonInclusionProof, RevocationKey, RevocationOracle,
    RevocationOracleError, SubjectId,
};
use crate::sparse_merkle::InMemoryRevocationOracle;

pub mod partner_mirror;

/// Schema version written by and accepted by this oracle.
pub const SQLITE_REVOCATION_ORACLE_SCHEMA_VERSION: i64 = 1;

/// Largest accepted subject, in UTF-8 bytes.
pub const MAX_REVOCATION_SUBJECT_BYTES: usize = 4096;

const SCHEMA: &str = "
CREATE TABLE chio_revocation_oracle_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1)
) STRICT;
CREATE TABLE chio_revocation_oracle_leaves (
    seq INTEGER PRIMARY KEY CHECK (seq >= 1),
    subject TEXT NOT NULL CHECK (
        typeof(subject) = 'text'
        AND length(subject) BETWEEN 1 AND 4096
        AND octet_length(subject) <= 16384
        AND instr(subject, char(0)) = 0
    ),
    epoch_nonce BLOB NOT NULL
        CHECK (typeof(epoch_nonce) = 'blob' AND length(epoch_nonce) = 8),
    inserted_at_unix_ms BLOB NOT NULL
        CHECK (typeof(inserted_at_unix_ms) = 'blob' AND length(inserted_at_unix_ms) = 8),
    UNIQUE (subject, epoch_nonce)
) STRICT;
";

/// Failures of the durable oracle. Every error leaves the database and the
/// handle's published tree unchanged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SqliteRevocationOracleError {
    #[error("revocation oracle database is not stamped by this oracle")]
    UnstampedDatabase,
    #[error("unsupported revocation oracle schema version {0}")]
    UnsupportedSchema(i64),
    #[error("revocation oracle catalog does not match schema version {SQLITE_REVOCATION_ORACLE_SCHEMA_VERSION}")]
    CatalogMismatch,
    #[error("revocation oracle record is corrupt: {0}")]
    CorruptRecord(String),
    #[error("revocation subject exceeds {MAX_REVOCATION_SUBJECT_BYTES} bytes")]
    SubjectTooLong,
    #[error("revocation leaf cursor {0} is outside the stored sequence range")]
    CursorOutOfRange(u64),
    #[error("revocation oracle state lock is poisoned")]
    Poisoned,
    #[error(transparent)]
    Oracle(#[from] RevocationOracleError),
    #[error("revocation oracle storage failed: {0}")]
    Storage(String),
}

impl From<rusqlite::Error> for SqliteRevocationOracleError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

type Result<T> = core::result::Result<T, SqliteRevocationOracleError>;

/// One committed leaf. `seq` numbers the leaves densely from one in
/// insertion order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationLeaf {
    pub seq: u64,
    pub key: RevocationKey,
    pub inserted_at_unix_ms: u64,
}

/// The replayed tree and the sequence number of the last leaf it includes,
/// which is also its leaf count.
#[derive(Clone)]
struct Replayed {
    oracle: InMemoryRevocationOracle,
    seq: u64,
}

/// Durable sparse-Merkle revocation oracle.
pub struct SqliteRevocationOracle {
    connection: Mutex<Connection>,
    replayed: Mutex<Replayed>,
}

impl SqliteRevocationOracle {
    /// Opens (creating if absent) the oracle database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        Self::with_connection(Connection::open_with_flags(path, flags)?)
    }

    /// Opens a private in-memory oracle database.
    pub fn open_in_memory() -> Result<Self> {
        Self::with_connection(Connection::open_in_memory()?)
    }

    fn with_connection(mut connection: Connection) -> Result<Self> {
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        initialize(&transaction)?;
        transaction.commit()?;
        let replayed = Replayed {
            oracle: InMemoryRevocationOracle::new(),
            seq: 0,
        };
        let replayed = catch_up(&connection, replayed)?;
        Ok(Self {
            connection: Mutex::new(connection),
            replayed: Mutex::new(replayed),
        })
    }

    #[cfg(test)]
    pub(crate) fn set_busy_timeout(&self, timeout: std::time::Duration) -> Result<()> {
        Ok(self.lock_connection()?.busy_timeout(timeout)?)
    }

    fn lock_connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| SqliteRevocationOracleError::Poisoned)
    }

    fn lock_replayed(&self) -> Result<MutexGuard<'_, Replayed>> {
        self.replayed
            .lock()
            .map_err(|_| SqliteRevocationOracleError::Poisoned)
    }

    /// The tree including every leaf committed to the database so far.
    fn current(&self) -> Result<InMemoryRevocationOracle> {
        let connection = self.lock_connection()?;
        let mut replayed = self.lock_replayed()?;
        let caught_up = catch_up(&connection, replayed.clone())?;
        *replayed = caught_up;
        Ok(replayed.oracle.clone())
    }

    /// Runs `body` inside one immediate transaction over the current tree.
    /// Keys the body revokes are persisted and published only if the body
    /// and the commit succeed.
    pub fn transact<T>(
        &self,
        now_unix_ms: u64,
        body: impl FnOnce(&mut RevocationTransaction<'_>) -> Result<T>,
    ) -> Result<(T, EpochRoot)> {
        self.write(now_unix_ms, body)
    }

    /// [`Self::transact`] for a body that refuses with its own error type.
    /// The transaction also carries state an owner in this crate keeps beside
    /// the oracle in the same database.
    pub(crate) fn write<T, E: From<SqliteRevocationOracleError>>(
        &self,
        now_unix_ms: u64,
        body: impl FnOnce(&mut RevocationTransaction<'_>) -> core::result::Result<T, E>,
    ) -> core::result::Result<(T, EpochRoot), E> {
        let mut connection = self.lock_connection()?;
        let mut replayed = self.lock_replayed()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(SqliteRevocationOracleError::from)?;
        let base = catch_up(&transaction, replayed.clone())?;
        let mut staged = RevocationTransaction {
            connection: &transaction,
            oracle: base.oracle.clone(),
            seq: base.seq,
            now_unix_ms,
        };
        let value = body(&mut staged)?;
        let published = Replayed {
            oracle: staged.oracle,
            seq: staged.seq,
        };
        transaction
            .commit()
            .map_err(SqliteRevocationOracleError::from)?;
        let root = published.oracle.epoch_root();
        *replayed = published;
        Ok((value, root))
    }

    /// Runs `body` against the connection, for owner state kept in the same
    /// database. Writes belong in [`Self::transact`].
    pub fn read<T>(&self, body: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let connection = self.lock_connection()?;
        body(&connection)
    }

    /// Runs `body` against the connection and the tree inside one read
    /// transaction, so owner state the body reads and the tree describe one
    /// committed state.
    pub(crate) fn read_with_tree<T>(
        &self,
        body: impl FnOnce(&Connection, &InMemoryRevocationOracle) -> Result<T>,
    ) -> Result<T> {
        let mut connection = self.lock_connection()?;
        let mut replayed = self.lock_replayed()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let caught_up = catch_up(&transaction, replayed.clone())?;
        let value = body(&transaction, &caught_up.oracle)?;
        transaction.commit()?;
        *replayed = caught_up;
        Ok(value)
    }

    /// Revokes `key`, or returns [`RevocationOracleError::AlreadyRevoked`].
    pub fn revoke(&self, key: RevocationKey, now_unix_ms: u64) -> Result<EpochRoot> {
        let (inserted, root) = self.transact(now_unix_ms, |txn| txn.revoke(&key))?;
        if inserted {
            Ok(root)
        } else {
            Err(RevocationOracleError::AlreadyRevoked.into())
        }
    }

    pub fn is_revoked(&self, key: &RevocationKey) -> Result<bool> {
        Ok(self.current()?.contains(key))
    }

    /// Up to `limit` committed leaves with a sequence number above `after`,
    /// in sequence order.
    pub fn leaves_after(&self, after: u64, limit: usize) -> Result<Vec<RevocationLeaf>> {
        let cursor = i64::try_from(after)
            .map_err(|_| SqliteRevocationOracleError::CursorOutOfRange(after))?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let connection = self.lock_connection()?;
        let mut statement = connection.prepare_cached(
            "SELECT seq, subject, epoch_nonce, inserted_at_unix_ms
             FROM chio_revocation_oracle_leaves WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2",
        )?;
        let mut rows = statement.query(params![cursor, limit])?;
        let mut leaves = Vec::new();
        let mut expected = after;
        while let Some(row) = rows.next()? {
            let leaf = decode_leaf(row)?;
            expected = next_seq(expected)?;
            if leaf.seq != expected {
                return Err(corrupt_leaf(leaf.seq));
            }
            leaves.push(leaf);
        }
        Ok(leaves)
    }

    /// The committed tree at one instant. Its root and its membership answer
    /// from that one state, so a check of its members binds the root it yields.
    pub fn snapshot(&self) -> Result<InMemoryRevocationOracle> {
        self.current()
    }

    pub fn current_epoch_root(&self) -> Result<EpochRoot> {
        Ok(self.current()?.epoch_root())
    }

    pub fn prove_inclusion(&self, key: &RevocationKey) -> Result<InclusionProof> {
        Ok(self.current()?.inclusion_proof(key)?)
    }

    pub fn prove_non_inclusion(
        &self,
        key: RevocationKey,
        now_unix_ms: u64,
    ) -> Result<NonInclusionProof> {
        Ok(self.current()?.non_inclusion_proof(key, now_unix_ms)?)
    }
}

/// The trait surface. `contains` reports a key as revoked whenever the
/// database cannot be read, so a storage fault never admits a revoked key.
impl RevocationOracle for SqliteRevocationOracle {
    fn insert(&mut self, key: RevocationKey, now_unix_ms: u64) -> crate::api::Result<EpochRoot> {
        self.revoke(key, now_unix_ms).map_err(to_oracle_error)
    }

    fn contains(&self, key: &RevocationKey) -> bool {
        self.is_revoked(key).unwrap_or(true)
    }

    fn epoch_root(&self) -> EpochRoot {
        match self.current() {
            Ok(oracle) => oracle.epoch_root(),
            Err(_) => match self.lock_replayed() {
                Ok(replayed) => replayed.oracle.epoch_root(),
                Err(_) => InMemoryRevocationOracle::new().epoch_root(),
            },
        }
    }

    fn inclusion_proof(&self, key: &RevocationKey) -> crate::api::Result<InclusionProof> {
        self.prove_inclusion(key).map_err(to_oracle_error)
    }

    fn non_inclusion_proof(
        &self,
        key: RevocationKey,
        now_unix_ms: u64,
    ) -> crate::api::Result<NonInclusionProof> {
        self.prove_non_inclusion(key, now_unix_ms)
            .map_err(to_oracle_error)
    }
}

fn to_oracle_error(error: SqliteRevocationOracleError) -> RevocationOracleError {
    match error {
        SqliteRevocationOracleError::Oracle(inner) => inner,
        other => RevocationOracleError::Serialization(other.to_string()),
    }
}

/// One write transaction over the oracle.
pub struct RevocationTransaction<'t> {
    connection: &'t Connection,
    oracle: InMemoryRevocationOracle,
    seq: u64,
    now_unix_ms: u64,
}

impl RevocationTransaction<'_> {
    /// The open transaction, for owner state kept in the same database.
    #[must_use]
    pub fn connection(&self) -> &Connection {
        self.connection
    }

    pub fn is_revoked(&self, key: &RevocationKey) -> bool {
        self.oracle.contains(key)
    }

    /// The root of the staged tree, including keys revoked so far in this
    /// transaction.
    #[must_use]
    pub fn epoch_root(&self) -> EpochRoot {
        self.oracle.epoch_root()
    }

    /// Revokes `key` within the transaction. Returns `false` when the key is
    /// already revoked.
    pub fn revoke(&mut self, key: &RevocationKey) -> Result<bool> {
        if self.oracle.contains(key) {
            return Ok(false);
        }
        if key.subject_id.as_str().len() > MAX_REVOCATION_SUBJECT_BYTES {
            return Err(SqliteRevocationOracleError::SubjectTooLong);
        }
        let seq = next_seq(self.seq)?;
        let stored_seq = i64::try_from(seq).map_err(|_| corrupt_leaf(seq))?;
        self.oracle.insert(key.clone(), self.now_unix_ms)?;
        self.connection.execute(
            "INSERT INTO chio_revocation_oracle_leaves
                (seq, subject, epoch_nonce, inserted_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                stored_seq,
                key.subject_id.as_str(),
                key.epoch_nonce.get().to_be_bytes().as_slice(),
                self.now_unix_ms.to_be_bytes().as_slice()
            ],
        )?;
        self.seq = seq;
        Ok(true)
    }
}

fn initialize(transaction: &Transaction<'_>) -> Result<()> {
    let stamped = transaction.query_row(
        "SELECT count(*) FROM sqlite_schema
             WHERE type = 'table' AND name = 'chio_revocation_oracle_meta'",
        [],
        |row| row.get::<_, i64>(0),
    )? == 1;
    if stamped {
        let version = transaction
            .query_row(
                "SELECT schema_version FROM chio_revocation_oracle_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or(SqliteRevocationOracleError::UnstampedDatabase)?;
        if version != SQLITE_REVOCATION_ORACLE_SCHEMA_VERSION {
            return Err(SqliteRevocationOracleError::UnsupportedSchema(version));
        }
        if oracle_catalog(transaction)? != canonical_catalog()? {
            return Err(SqliteRevocationOracleError::CatalogMismatch);
        }
        return Ok(());
    }
    let tables = transaction.query_row(
        "SELECT count(*) FROM sqlite_schema
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    if tables != 0 {
        return Err(SqliteRevocationOracleError::UnstampedDatabase);
    }
    transaction.execute_batch(SCHEMA)?;
    transaction.execute(
        "INSERT INTO chio_revocation_oracle_meta (singleton, schema_version) VALUES (1, ?1)",
        params![SQLITE_REVOCATION_ORACLE_SCHEMA_VERSION],
    )?;
    Ok(())
}

type Catalog = Vec<(String, String, String, Option<String>)>;

/// The catalog entries of the oracle's own tables and their indexes.
fn oracle_catalog(connection: &Connection) -> Result<Catalog> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE tbl_name IN ('chio_revocation_oracle_meta', 'chio_revocation_oracle_leaves')
            OR name IN ('chio_revocation_oracle_meta', 'chio_revocation_oracle_leaves')
         ORDER BY type, name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    Ok(rows.collect::<rusqlite::Result<Catalog>>()?)
}

/// The catalog [`SCHEMA`] creates in an empty database.
fn canonical_catalog() -> Result<Catalog> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(SCHEMA)?;
    oracle_catalog(&connection)
}

/// Replays every leaf committed after `replayed.seq`, in sequence order.
fn catch_up(connection: &Connection, mut replayed: Replayed) -> Result<Replayed> {
    let cursor = i64::try_from(replayed.seq).map_err(|_| corrupt_leaf(replayed.seq))?;
    let mut statement = connection.prepare_cached(
        "SELECT seq, subject, epoch_nonce, inserted_at_unix_ms
         FROM chio_revocation_oracle_leaves WHERE seq > ?1 ORDER BY seq ASC",
    )?;
    let mut rows = statement.query(params![cursor])?;
    while let Some(row) = rows.next()? {
        let leaf = decode_leaf(row)?;
        if leaf.seq != next_seq(replayed.seq)? {
            return Err(corrupt_leaf(leaf.seq));
        }
        replayed
            .oracle
            .insert(leaf.key, leaf.inserted_at_unix_ms)
            .map_err(|_| corrupt_leaf(leaf.seq))?;
        replayed.seq = leaf.seq;
    }
    Ok(replayed)
}

fn next_seq(seq: u64) -> Result<u64> {
    seq.checked_add(1)
        .filter(|next| i64::try_from(*next).is_ok())
        .ok_or_else(|| corrupt_leaf(seq))
}

fn decode_leaf(row: &rusqlite::Row<'_>) -> Result<RevocationLeaf> {
    let stored_seq: i64 = row.get(0)?;
    let seq = u64::try_from(stored_seq)
        .map_err(|_| SqliteRevocationOracleError::CorruptRecord(format!("leaf {stored_seq}")))?;
    let subject: String = row.get(1)?;
    let nonce: Vec<u8> = row.get(2)?;
    let inserted_at: Vec<u8> = row.get(3)?;
    let nonce: [u8; 8] = nonce.try_into().map_err(|_| corrupt_leaf(seq))?;
    let inserted_at: [u8; 8] = inserted_at.try_into().map_err(|_| corrupt_leaf(seq))?;
    Ok(RevocationLeaf {
        seq,
        key: RevocationKey::new(
            SubjectId::new(subject),
            EpochNonce::new(u64::from_be_bytes(nonce)),
        ),
        inserted_at_unix_ms: u64::from_be_bytes(inserted_at),
    })
}

fn corrupt_leaf(seq: u64) -> SqliteRevocationOracleError {
    SqliteRevocationOracleError::CorruptRecord(format!("leaf {seq}"))
}
