//! Explicit retirement of the legacy approval replay namespace. A source seal
//! is migration evidence, not operation ownership or antirollback protection.

use chio_kernel::admission_operation::{
    governed_approval_replay::{
        GovernedApprovalReplaySourceFileIdentity, GovernedApprovalReplaySourcePort,
    },
    AdmissionOperationStoreError,
};
use chio_sqlite_file_identity::{main_database_file_identity, SqliteFileIdentity};
use rusqlite::{params, Connection, TransactionBehavior};

use super::{SqliteGovernedApprovalReplayStore, SqliteGovernedApprovalReplayStoreError as Error};

mod evidence;
mod inventory;
mod opening;
mod schema;
pub use evidence::{
    GovernedApprovalReplaySourceBinding, GovernedApprovalReplaySourceSeal,
    GovernedApprovalReplaySourceSnapshot,
};
pub use opening::SqliteGovernedApprovalReplaySource;

fn invalid(message: impl Into<String>) -> Error {
    Error::storage(format!(
        "governed approval replay source: {}",
        message.into()
    ))
}

pub(super) fn ensure_writable(connection: &Connection) -> Result<(), Error> {
    if schema::has_evidence(connection)? {
        return Err(invalid("sealed or contains incomplete seal evidence"));
    }
    Ok(())
}

impl SqliteGovernedApprovalReplayStore {
    /// Observe one bounded inventory snapshot without changing it. This is data
    /// for independently pinning a migration expectation, not a seal claim.
    pub fn preview_legacy_replay_source(
        &self,
        binding: &GovernedApprovalReplaySourceBinding,
    ) -> Result<GovernedApprovalReplaySourceSnapshot, Error> {
        let mut connection = self.pool.get()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let snapshot = match self.load_replay_source_seal_tx(&tx)? {
            Some(seal) => {
                require_binding(seal.binding(), binding)?;
                seal.0
            }
            None => {
                schema::verify(&tx, false)?;
                self.replay_source_snapshot(&tx, binding)?
            }
        };
        tx.commit()?;
        Ok(snapshot)
    }

    /// Permanently freeze exactly the expected source. Operators must quiesce
    /// all legacy consumers first: sealing cannot revoke already admitted work.
    /// The complete retained inventory, clock, capacity and SQL write barriers
    /// commit together. A commit error is ambiguous; resolve it with load/verify,
    /// never by resuming legacy writes or activating an unverified destination.
    pub fn seal_expected_legacy_replay_source(
        &self,
        expected: &GovernedApprovalReplaySourceSnapshot,
    ) -> Result<GovernedApprovalReplaySourceSeal, Error> {
        let mut connection = self.pool.get()?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        require_durability(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(seal) = self.load_replay_source_seal_tx(&tx)? {
            require_same(&seal.0, expected)?;
            tx.commit()?;
            return Ok(seal);
        }
        schema::verify(&tx, false)?;
        let candidate = self.replay_source_snapshot(&tx, expected.binding())?;
        require_same(&candidate, expected)?;
        // Compare before the first write, under the same serialized snapshot.
        tx.execute_batch(schema::SEAL_SCHEMA)?;
        #[cfg(all(test, unix))]
        tests::seal_cutpoint(1)?;
        tx.execute(
            "INSERT INTO chio_governed_approval_replay_source_seal
            (singleton, canonical_bytes) VALUES (1, ?1)",
            params![candidate.canonical_bytes()?],
        )?;
        #[cfg(all(test, unix))]
        tests::seal_cutpoint(2)?;
        tx.execute_batch(&schema::barrier_sql())?;
        #[cfg(all(test, unix))]
        tests::seal_cutpoint(3)?;
        let seal = self
            .load_replay_source_seal_tx(&tx)?
            .ok_or_else(|| invalid("new seal missing"))?;
        require_same(&seal.0, expected)?;
        #[cfg(all(test, unix))]
        tests::seal_cutpoint(4)?;
        tx.commit()?;
        #[cfg(all(test, unix))]
        tests::seal_cutpoint(5)?;
        // Read through SQLite's WAL snapshot, not a copy of the main .db file.
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let persisted = self
            .load_replay_source_seal_tx(&tx)?
            .ok_or_else(|| invalid("committed seal missing"))?;
        require_same(&persisted.0, expected)?;
        tx.commit()?;
        Ok(persisted)
    }

    /// Validate the complete persisted seal, including its current physical
    /// file and SQL barriers. Partial evidence is an error, never `None`.
    pub fn load_legacy_replay_source_seal(
        &self,
        binding: &GovernedApprovalReplaySourceBinding,
    ) -> Result<Option<GovernedApprovalReplaySourceSeal>, Error> {
        let mut connection = self.pool.get()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let seal = self.load_replay_source_seal_tx(&tx)?;
        if let Some(seal) = &seal {
            require_binding(seal.binding(), binding)?;
        }
        tx.commit()?;
        Ok(seal)
    }

    /// A previous observation or a copied artifact is insufficient. Reconstruct
    /// the live source and compare it to an independently pinned expectation.
    pub fn verify_legacy_replay_source_seal(
        &self,
        expected: &GovernedApprovalReplaySourceSnapshot,
    ) -> Result<(), Error> {
        let actual = self
            .load_legacy_replay_source_seal(expected.binding())?
            .ok_or_else(|| invalid("expected seal missing"))?;
        require_same(&actual.0, expected)
    }

    pub(super) fn load_replay_source_seal_tx(
        &self,
        connection: &Connection,
    ) -> Result<Option<GovernedApprovalReplaySourceSeal>, Error> {
        if !schema::has_evidence(connection)? {
            return Ok(None);
        }
        require_durability(connection)?;
        schema::verify(connection, true)?;
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM chio_governed_approval_replay_source_seal",
            [],
            |row| row.get(0),
        )?;
        if count != 1 {
            return Err(invalid("seal must contain exactly one row"));
        }
        let (singleton, kind, bytes): (i64, String, i64) = connection.query_row(
            "SELECT singleton, typeof(canonical_bytes), length(canonical_bytes)
             FROM chio_governed_approval_replay_source_seal",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if singleton != 1
            || kind != "blob"
            || bytes <= 0
            || usize::try_from(bytes).map_err(|_| invalid("invalid seal size"))?
                > evidence::MAX_BYTES
        {
            return Err(invalid("seal has invalid type or size"));
        }
        let bytes: Vec<u8> = connection.query_row(
            "SELECT canonical_bytes FROM chio_governed_approval_replay_source_seal WHERE singleton = 1",
            [], |row| row.get(0))?;
        let expected = GovernedApprovalReplaySourceSnapshot::from_canonical_bytes(&bytes)?;
        let reconstructed = self.replay_source_snapshot(connection, expected.binding())?;
        require_same(&reconstructed, &expected)?;
        Ok(Some(GovernedApprovalReplaySourceSeal(reconstructed)))
    }

    fn replay_source_snapshot(
        &self,
        connection: &Connection,
        binding: &GovernedApprovalReplaySourceBinding,
    ) -> Result<GovernedApprovalReplaySourceSnapshot, Error> {
        schema::verify_metadata(connection)?;
        let identity = self.replay_source_file_identity(connection)?;
        Ok(GovernedApprovalReplaySourceSnapshot::from_inventory(
            binding.clone(),
            GovernedApprovalReplaySourceFileIdentity {
                device: identity.device,
                inode: identity.inode,
                link_count: identity.link_count,
            },
            schema::digest()?,
            inventory::read(connection)?,
        )?)
    }

    fn replay_source_file_identity(
        &self,
        connection: &Connection,
    ) -> Result<SqliteFileIdentity, Error> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| invalid("source must be file-backed"))?;
        let identity = main_database_file_identity(connection).map_err(invalid)?;
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() || identity.link_count != 1 {
            return Err(invalid("source must be a regular single-link file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != identity.device
                || metadata.ino() != identity.inode
                || metadata.nlink() != identity.link_count
            {
                return Err(invalid(
                    "source path no longer identifies its open database",
                ));
            }
        }
        Ok(identity)
    }
}

impl GovernedApprovalReplaySourcePort for SqliteGovernedApprovalReplaySource {
    fn preview_unsealed(
        &self,
        binding: &GovernedApprovalReplaySourceBinding,
    ) -> Result<GovernedApprovalReplaySourceSnapshot, AdmissionOperationStoreError> {
        let preview = || -> Result<_, Error> {
            let mut connection = self.store.pool.get()?;
            let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            ensure_writable(&tx)?;
            schema::verify(&tx, false)?;
            let snapshot = self.store.replay_source_snapshot(&tx, binding)?;
            tx.commit()?;
            Ok(snapshot)
        };
        preview().map_err(source_port_error)
    }

    fn seal_exact(
        &self,
        expected: &GovernedApprovalReplaySourceSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.store
            .seal_expected_legacy_replay_source(expected)
            .map(|_| ())
            .map_err(source_port_error)
    }

    fn verify_exact(
        &self,
        expected: &GovernedApprovalReplaySourceSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.store
            .verify_legacy_replay_source_seal(expected)
            .map_err(source_port_error)
    }
}

fn source_port_error(error: Error) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(error.to_string())
}

fn require_durability(connection: &Connection) -> Result<(), Error> {
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if synchronous != 2 || !journal.eq_ignore_ascii_case("wal") {
        return Err(invalid("sealing requires WAL and synchronous FULL"));
    }
    Ok(())
}

fn require_binding(
    actual: &GovernedApprovalReplaySourceBinding,
    expected: &GovernedApprovalReplaySourceBinding,
) -> Result<(), Error> {
    if actual != expected {
        return Err(invalid("source or authority binding mismatch"));
    }
    Ok(())
}

fn require_same(
    actual: &GovernedApprovalReplaySourceSnapshot,
    expected: &GovernedApprovalReplaySourceSnapshot,
) -> Result<(), Error> {
    if actual != expected {
        return Err(invalid(
            "source does not match the exact expected inventory",
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
