//! Explicit retirement of legacy flow and declassification writers. A source
//! fingerprint is not an admission owner, transferred inventory or activation.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use chio_security_types::ports::{PortError, PortResult};
use chio_sqlite_file_identity::{main_database_file_identity, SqliteFileIdentity};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};

mod evidence;
mod inventory;
mod row_codec;
mod schema;
pub use evidence::{SecurityParticipantSourceBinding, SecurityParticipantSourceSnapshot};
pub(crate) use inventory::TableHasher;
pub(crate) use row_codec::{
    decode_retained_security_row, encode_retained_security_values, retained_security_columns,
};
#[cfg(all(test, unix))]
pub(crate) use tests::{
    declassification_consumption_fixture, declassification_outcome_fixture, seeded_security_history,
};

/// Actual rows read from a live, verified sealed source, not a deserializable
/// substitute for source verification. Destination persistence verifies them
/// again against the independently pinned fingerprint.
pub(crate) struct RetainedSecuritySourceRows {
    pub(crate) tables: Vec<(&'static str, Vec<Vec<u8>>)>,
}

/// Bounded diagnostics deliberately exclude retained flow and receipt contents.
#[derive(Debug, thiserror::Error)]
pub enum SecurityParticipantSourceError {
    #[error("security participant source: {0}")]
    Invalid(&'static str),
    #[error("security participant source SQLite operation failed: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("security participant source file operation failed: {0}")]
    Io(#[from] std::io::Error),
}

type Error = SecurityParticipantSourceError;
type Result<T> = std::result::Result<T, Error>;

/// An observed, fully verified physical seal. It cannot be deserialized into
/// authority. Importers must reverify the live source against their pinned data.
pub struct SecurityParticipantSourceSeal(SecurityParticipantSourceSnapshot);

impl SecurityParticipantSourceSeal {
    #[must_use]
    pub const fn snapshot(&self) -> &SecurityParticipantSourceSnapshot {
        &self.0
    }
}

impl std::fmt::Debug for SecurityParticipantSourceSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecurityParticipantSourceSeal")
            .field(&self.0)
            .finish()
    }
}

/// Migration-only I/O for an existing source. No legacy writer or underlying
/// connection is exposed. Opening never migrates, prunes, stamps or creates it.
///
/// This is not a serving store. Retirement requires operator quiescence and a
/// separately retained expectation; it is irreversible through this API. The
/// critical inventory covers flow, declassification and shared transition
/// history, not unrelated active-defense tables in the same file. It does not
/// qualify destination import, a live admission owner or filesystem rollback
/// resistance. SQLite main-file identity must be supported by the native VFS.
pub struct SqliteSecurityParticipantSource {
    connection: Mutex<Connection>,
    path: PathBuf,
    identity: SqliteFileIdentity,
}

pub(super) fn ensure_legacy_writable(connection: &Connection) -> PortResult<()> {
    if schema::has_evidence(connection).map_err(|_| PortError::integrity_failure())? {
        return Err(PortError::conflict());
    }
    Ok(())
}

impl SqliteSecurityParticipantSource {
    pub(crate) fn read_sealed_rows(
        &self,
        expected: &SecurityParticipantSourceSnapshot,
    ) -> Result<RetainedSecuritySourceRows> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| Error::Invalid("source lock poisoned"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let seal = load_seal(&tx, &self.path, self.identity)?
            .ok_or(Error::Invalid("source is not sealed"))?;
        require_same(seal.snapshot(), expected)?;
        let mut tables = schema::TABLES
            .iter()
            .map(|table| (*table, Vec::new()))
            .collect::<Vec<_>>();
        let observed = inventory::visit(&tx, |table, row| {
            let (_, rows) = tables
                .iter_mut()
                .find(|(name, _)| *name == table)
                .ok_or(Error::Invalid("source row has an unknown table"))?;
            rows.push(row.to_vec());
            Ok(())
        })?;
        if observed != expected.tables() || file_identity(&tx, &self.path)? != self.identity {
            return Err(Error::Invalid(
                "sealed row readback differs from expectation",
            ));
        }
        tx.commit()?;
        Ok(RetainedSecuritySourceRows { tables })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = path.as_os_str().to_string_lossy();
        if text.is_empty()
            || text == ":memory:"
            || text.to_ascii_lowercase().starts_with("file:")
            || text.contains('?')
            || text.contains('#')
        {
            return Err(Error::Invalid("source must be an ordinary existing file"));
        }
        if !std::fs::symlink_metadata(path)?.file_type().is_file() {
            return Err(Error::Invalid("source must be a regular file"));
        }
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        require_durability(&connection)?;
        let path = std::path::absolute(path)?;
        let identity = file_identity(&connection, &path)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let sealed = schema::has_evidence(&tx)?;
        schema::verify(&tx, sealed)?;
        inventory::read(&tx)?;
        inventory::validate_domain(&tx)?;
        if sealed {
            load_seal(&tx, &path, identity)?
                .ok_or(Error::Invalid("seal evidence is incomplete"))?;
        }
        if file_identity(&tx, &path)? != identity {
            return Err(Error::Invalid("source file changed during opening"));
        }
        tx.commit()?;
        Ok(Self {
            connection: Mutex::new(connection),
            path,
            identity,
        })
    }

    /// Observe the complete bounded critical-table inventory without mutation.
    /// The returned data must be independently pinned before retirement.
    pub fn preview(
        &self,
        binding: &SecurityParticipantSourceBinding,
    ) -> Result<SecurityParticipantSourceSnapshot> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| Error::Invalid("source lock poisoned"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        if schema::has_evidence(&tx)? {
            return Err(Error::Invalid("preview requires an unretired source"));
        }
        let candidate = snapshot(&tx, &self.path, self.identity, binding)?;
        tx.commit()?;
        Ok(candidate)
    }

    /// Permanently retire exactly the expected source. Operators must quiesce
    /// every legacy consumer first. This cannot retract already admitted work,
    /// transfer ownership, or qualify an independent destination automatically.
    /// Resolve uncertain commits by load/verify, never by resuming old writers.
    pub fn seal_exact(
        &self,
        expected: &SecurityParticipantSourceSnapshot,
    ) -> Result<SecurityParticipantSourceSeal> {
        expected.validate()?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| Error::Invalid("source lock poisoned"))?;
        require_durability(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(seal) = load_seal(&tx, &self.path, self.identity)? {
            require_same(&seal.0, expected)?;
            tx.commit()?;
            return Ok(seal);
        }
        let actual = snapshot(&tx, &self.path, self.identity, expected.binding())?;
        require_same(&actual, expected)?;
        tx.execute_batch(schema::SEAL_SCHEMA)?;
        cutpoint(1)?;
        tx.execute(
            "INSERT INTO chio_security_participant_source_seal (singleton, canonical_bytes)
            VALUES (1, ?1)",
            params![actual.canonical_bytes()?],
        )?;
        cutpoint(2)?;
        tx.execute_batch(&schema::barrier_sql())?;
        cutpoint(3)?;
        let sealed =
            load_seal(&tx, &self.path, self.identity)?.ok_or(Error::Invalid("new seal missing"))?;
        require_same(&sealed.0, expected)?;
        cutpoint(4)?;
        tx.commit()?;
        cutpoint(5)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let readback = load_seal(&tx, &self.path, self.identity)?
            .ok_or(Error::Invalid("committed seal missing"))?;
        require_same(&readback.0, expected)?;
        tx.commit()?;
        Ok(readback)
    }

    pub fn load_seal(&self) -> Result<Option<SecurityParticipantSourceSeal>> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| Error::Invalid("source lock poisoned"))?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let seal = load_seal(&tx, &self.path, self.identity)?;
        tx.commit()?;
        Ok(seal)
    }

    pub fn verify_seal(&self, expected: &SecurityParticipantSourceSnapshot) -> Result<()> {
        let seal = self
            .load_seal()?
            .ok_or(Error::Invalid("expected seal missing"))?;
        require_same(&seal.0, expected)
    }
}

fn require_same(
    actual: &SecurityParticipantSourceSnapshot,
    expected: &SecurityParticipantSourceSnapshot,
) -> Result<()> {
    if actual != expected {
        return Err(Error::Invalid("source differs from pinned expectation"));
    }
    Ok(())
}

fn require_durability(connection: &Connection) -> Result<()> {
    let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let sync: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal") || sync != 2 {
        return Err(Error::Invalid("source requires WAL and synchronous FULL"));
    }
    Ok(())
}

fn file_identity(connection: &Connection, path: &Path) -> Result<SqliteFileIdentity> {
    let identity = main_database_file_identity(connection)
        .map_err(|_| Error::Invalid("source lacks qualified SQLite file identity"))?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || identity.link_count != 1 {
        return Err(Error::Invalid("source must be regular and single-link"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.dev() != identity.device
            || metadata.ino() != identity.inode
            || metadata.nlink() != 1
        {
            return Err(Error::Invalid(
                "source path no longer names its SQLite descriptor",
            ));
        }
    }
    Ok(identity)
}

fn snapshot(
    connection: &Connection,
    path: &Path,
    identity: SqliteFileIdentity,
    binding: &SecurityParticipantSourceBinding,
) -> Result<SecurityParticipantSourceSnapshot> {
    require_durability(connection)?;
    let sealed = schema::has_evidence(connection)?;
    schema::verify(connection, sealed)?;
    if file_identity(connection, path)? != identity {
        return Err(Error::Invalid("source file identity changed"));
    }
    let inventory = inventory::read(connection)?;
    inventory::validate_domain(connection)?;
    let snapshot = SecurityParticipantSourceSnapshot::new(
        binding.clone(),
        identity,
        schema::digest()?,
        inventory,
    )?;
    if file_identity(connection, path)? != identity {
        return Err(Error::Invalid("source file changed during inventory"));
    }
    Ok(snapshot)
}

fn load_seal(
    connection: &Connection,
    path: &Path,
    identity: SqliteFileIdentity,
) -> Result<Option<SecurityParticipantSourceSeal>> {
    require_durability(connection)?;
    if !schema::has_evidence(connection)? {
        schema::verify(connection, false)?;
        if file_identity(connection, path)? != identity {
            return Err(Error::Invalid("source file identity changed"));
        }
        return Ok(None);
    }
    schema::verify(connection, true)?;
    let (count, valid): (i64, bool) = connection.query_row(
        "SELECT COUNT(*), COALESCE(MIN(singleton = 1 AND typeof(canonical_bytes) = 'blob'
        AND length(canonical_bytes) BETWEEN 1 AND 65536), 0)
        FROM chio_security_participant_source_seal",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if count != 1 || !valid {
        return Err(Error::Invalid("seal row has invalid cardinality or bounds"));
    }
    let bytes: Vec<u8> = connection.query_row(
        "SELECT canonical_bytes FROM chio_security_participant_source_seal",
        [],
        |row| row.get(0),
    )?;
    let expected = SecurityParticipantSourceSnapshot::from_canonical_bytes(&bytes)?;
    let actual = snapshot(connection, path, identity, expected.binding())?;
    require_same(&actual, &expected)?;
    Ok(Some(SecurityParticipantSourceSeal(actual)))
}

fn cutpoint(_stage: u8) -> Result<()> {
    #[cfg(all(test, unix))]
    tests::cutpoint(_stage)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
