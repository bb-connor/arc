//! Permanent retirement of the legacy SQLite replay namespace.
//!
//! A seal preserves blocking markers and excludes legacy SQL mutations. It
//! grants no operation ownership and does not provide independent antirollback
//! protection or revoke work that was already admitted before sealing.

use std::fs;

use chio_sqlite_file_identity::{main_database_file_identity, SqliteFileIdentity};
use rusqlite::{params, Connection, TransactionBehavior};

use crate::replay_source::{
    RuntimeReplaySourceBinding, RuntimeReplaySourceSeal, MAX_RUNTIME_REPLAY_SOURCE_BYTES,
};
use crate::ChioRuntimeError;

use super::{sqlite_error, SqliteRuntimeOrchestrationStore};

mod expectation;
mod inventory;
mod schema;

fn invalid(detail: impl Into<String>) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "runtime_replay_source_invalid",
        detail: detail.into(),
    }
}

/// New callers reject even a no-op release. Persistent triggers separately
/// prevent actual mutations by connections opened before this implementation.
pub(super) fn ensure_legacy_replay_writable(
    connection: &Connection,
) -> Result<(), ChioRuntimeError> {
    if schema::has_seal_evidence(connection)? {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_replay_source_sealed",
            detail: "legacy replay source is sealed or contains incomplete seal evidence"
                .to_string(),
        });
    }
    Ok(())
}

impl SqliteRuntimeOrchestrationStore {
    /// Permanently freeze the legacy replay markers for an explicitly bound
    /// source and destination. This is inventory evidence, not replay authority.
    ///
    /// The transaction installs persistent SQL barriers and a complete bounded
    /// inventory together. A commit error can mean that sealing committed; use
    /// the load/verify methods to resolve that uncertainty, never legacy writes.
    pub fn seal_legacy_replay_source(
        &self,
        binding: &RuntimeReplaySourceBinding,
    ) -> Result<RuntimeReplaySourceSeal, ChioRuntimeError> {
        self.seal_replay_source(binding, None)
    }

    fn seal_replay_source(
        &self,
        binding: &RuntimeReplaySourceBinding,
        expected_bytes: Option<&[u8]>,
    ) -> Result<RuntimeReplaySourceSeal, ChioRuntimeError> {
        let mut connection = self.lock_connection()?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(sqlite_error)?;
        let synchronous: i64 = connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .map_err(sqlite_error)?;
        let journal: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(sqlite_error)?;
        if synchronous != 2 || !journal.eq_ignore_ascii_case("wal") {
            return Err(invalid(
                "replay source sealing requires WAL and synchronous FULL",
            ));
        }
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(seal) = self.load_replay_source_seal_tx(&tx)? {
            require_binding(&seal, binding)?;
            require_expected_bytes(&seal, expected_bytes)?;
            tx.commit().map_err(sqlite_error)?;
            return Ok(seal);
        }
        let seal = self.candidate_replay_source_seal(&tx, binding)?;
        // This check shares the write snapshot that installs the barriers. A
        // changed source must remain unsealed, not acquire a different seal
        // that a caller could subsequently mistake for its pinned expectation.
        require_expected_bytes(&seal, expected_bytes)?;
        let bytes = seal.canonical_bytes()?;
        tx.execute_batch(schema::SEAL_TABLE_SCHEMA)
            .map_err(sqlite_error)?;
        tx.execute(
            "INSERT INTO runtime_replay_source_seal (singleton, canonical_bytes) VALUES (1, ?1)",
            params![bytes],
        )
        .map_err(sqlite_error)?;
        tx.execute_batch(&schema::barrier_sql())
            .map_err(sqlite_error)?;
        let verified = self
            .load_replay_source_seal_tx(&tx)?
            .ok_or_else(|| invalid("new replay source seal is missing"))?;
        require_same_seal(&verified, &seal)?;
        tx.commit().map_err(sqlite_error)?;

        // FULL syncs the WAL commit, not necessarily the main file. Verify via
        // SQLite, without requiring a checkpoint or reading only the .db file.
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let persisted = self
            .load_replay_source_seal_tx(&tx)?
            .ok_or_else(|| invalid("committed replay source seal is missing"))?;
        require_same_seal(&persisted, &seal)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(persisted)
    }

    /// Build candidate bytes from one snapshot. This does not assert that any
    /// barriers exist; callers must not expose the internal candidate as a seal.
    fn candidate_replay_source_seal(
        &self,
        connection: &Connection,
        binding: &RuntimeReplaySourceBinding,
    ) -> Result<RuntimeReplaySourceSeal, ChioRuntimeError> {
        schema::verify_schema(connection, false)?;
        RuntimeReplaySourceSeal::from_inventory(
            binding.clone(),
            self.replay_source_file_identity(connection)?,
            schema::barrier_sha256()?,
            inventory::read_inventory(connection)?,
        )
    }

    /// Load and validate an existing seal against the caller's expected source
    /// binding. Missing or damaged pieces of a seal are errors, not `None`.
    pub fn load_legacy_replay_source_seal(
        &self,
        binding: &RuntimeReplaySourceBinding,
    ) -> Result<Option<RuntimeReplaySourceSeal>, ChioRuntimeError> {
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let seal = self.load_replay_source_seal_tx(&tx)?;
        if let Some(seal) = &seal {
            require_binding(seal, binding)?;
        }
        tx.commit().map_err(sqlite_error)?;
        Ok(seal)
    }

    /// Verify persisted barriers, inventory, binding and actual file identity.
    /// A copied artifact by itself is never sufficient evidence of sealing.
    pub fn verify_legacy_replay_source_seal(
        &self,
        expected: &RuntimeReplaySourceSeal,
    ) -> Result<(), ChioRuntimeError> {
        let actual = self
            .load_legacy_replay_source_seal(expected.binding())?
            .ok_or_else(|| invalid("expected replay source seal is missing"))?;
        require_same_seal(&actual, expected)
    }

    pub(super) fn verify_replay_source_before_init(&self) -> Result<(), ChioRuntimeError> {
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        self.load_replay_source_seal_tx(&tx)?;
        tx.commit().map_err(sqlite_error)
    }

    fn load_replay_source_seal_tx(
        &self,
        connection: &Connection,
    ) -> Result<Option<RuntimeReplaySourceSeal>, ChioRuntimeError> {
        if !schema::has_seal_evidence(connection)? {
            return Ok(None);
        }
        schema::verify_schema(connection, true)?;
        let row_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM runtime_replay_source_seal",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if row_count != 1 {
            return Err(invalid(
                "replay source seal must contain exactly one record",
            ));
        }
        let (singleton, storage_type, byte_count): (i64, String, i64) = connection
            .query_row(
                "SELECT singleton, typeof(canonical_bytes), length(canonical_bytes)
                 FROM runtime_replay_source_seal",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(sqlite_error)?;
        let byte_count = usize::try_from(byte_count)
            .map_err(|_| invalid("replay source seal record has invalid size"))?;
        if singleton != 1
            || storage_type != "blob"
            || byte_count == 0
            || byte_count > MAX_RUNTIME_REPLAY_SOURCE_BYTES
        {
            return Err(invalid(
                "replay source seal record has invalid type or size",
            ));
        }
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT canonical_bytes FROM runtime_replay_source_seal WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let seal = RuntimeReplaySourceSeal::from_canonical_bytes(&bytes)?;
        let identity = self.replay_source_file_identity(connection)?;
        if seal.file_identity() != &identity {
            return Err(invalid(
                "replay source seal belongs to a different physical file",
            ));
        }
        let reconstructed = RuntimeReplaySourceSeal::from_inventory(
            seal.binding().clone(),
            identity,
            schema::barrier_sha256()?,
            inventory::read_inventory(connection)?,
        )?;
        require_same_seal(&reconstructed, &seal)?;
        Ok(Some(seal))
    }

    fn replay_source_file_identity(
        &self,
        connection: &Connection,
    ) -> Result<SqliteFileIdentity, ChioRuntimeError> {
        let identity = main_database_file_identity(connection)
            .map_err(|error| invalid(format!("replay source file identity: {error}")))?;
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| invalid(format!("replay source path identity: {error}")))?;
        if !metadata.file_type().is_file() || identity.link_count != 1 {
            return Err(invalid(
                "replay source requires a regular single-link database file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != identity.device
                || metadata.ino() != identity.inode
                || metadata.nlink() != identity.link_count
            {
                return Err(invalid(
                    "replay source path no longer identifies its open database",
                ));
            }
        }
        Ok(identity)
    }
}

fn require_binding(
    seal: &RuntimeReplaySourceSeal,
    binding: &RuntimeReplaySourceBinding,
) -> Result<(), ChioRuntimeError> {
    if seal.binding() != binding {
        return Err(invalid(
            "replay source seal has a different source or authority binding",
        ));
    }
    Ok(())
}

fn require_same_seal(
    actual: &RuntimeReplaySourceSeal,
    expected: &RuntimeReplaySourceSeal,
) -> Result<(), ChioRuntimeError> {
    if actual.canonical_bytes()? != expected.canonical_bytes()? {
        return Err(invalid(
            "replay source seal does not match its frozen inventory",
        ));
    }
    Ok(())
}

fn require_expected_bytes(
    actual: &RuntimeReplaySourceSeal,
    expected_bytes: Option<&[u8]>,
) -> Result<(), ChioRuntimeError> {
    if let Some(expected) = expected_bytes {
        if actual.canonical_bytes()?.as_slice() != expected {
            return Err(invalid(
                "replay source does not match the exact expected snapshot",
            ));
        }
    }
    Ok(())
}
