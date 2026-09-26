//! Exact source pinning and complete inactive row import under the destination
//! serving fence and global rollback anchor. No activation or invocation grant.

use chio_sqlite_file_identity::main_database_file_identity;

use crate::security_state::{
    SecurityParticipantSourceBinding, SecurityParticipantSourceSnapshot,
    SqliteSecurityParticipantSource,
};

use super::*;

mod integrity;
mod records;
mod storage;

pub(crate) use integrity::{
    security_participant_projection_reference, verify_security_participant_migration_coverage,
    verify_security_participant_migration_pristine,
};
pub(super) use records::verify_all;

const PROJECTION_KIND: &str = "security_participant_migration";
const MAX_MIGRATIONS: u64 = 16;
const MAX_TOTAL_ROWS: u64 = 65_536;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityParticipantMigrationPhase {
    Expected,
    ImportedInactive,
}

/// Fenced migration history. Its rows are retained source evidence, not the
/// active mutable flow projection, a prepared caller or a recovered live owner.
#[derive(Clone, Eq, PartialEq)]
pub struct SecurityParticipantMigrationRecord {
    snapshot: SecurityParticipantSourceSnapshot,
    expectation_id: AdmissionIdentifier,
    fingerprint_digest: String,
    events: Vec<records::MigrationEvent>,
}

impl SecurityParticipantMigrationRecord {
    pub fn snapshot(&self) -> &SecurityParticipantSourceSnapshot {
        &self.snapshot
    }
    pub fn expectation_id(&self) -> &AdmissionIdentifier {
        &self.expectation_id
    }
    pub fn phase(&self) -> SecurityParticipantMigrationPhase {
        if self.events.len() == 2 {
            SecurityParticipantMigrationPhase::ImportedInactive
        } else {
            SecurityParticipantMigrationPhase::Expected
        }
    }
    fn authority(&self) -> &str {
        self.snapshot.binding().security_authority_id().as_str()
    }
}

impl std::fmt::Debug for SecurityParticipantMigrationRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityParticipantMigrationRecord")
            .field("phase", &self.phase())
            .finish_non_exhaustive()
    }
}

impl SqliteAdmissionOperationStore {
    /// Retain the exact complete source fingerprint before retiring any writer.
    /// The destination UUID is obtained from the independently verified fence.
    pub fn expect_security_participant_source(
        &self,
        source_id: &AdmissionIdentifier,
        security_authority_id: &AdmissionIdentifier,
        source: &SqliteSecurityParticipantSource,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<SecurityParticipantMigrationRecord, AdmissionOperationStoreError> {
        if let Some(record) = self.load_security_participant_migration(
            security_authority_id,
            fence,
            trusted_now_unix_ms,
        )? {
            require_binding(&record.snapshot, source_id, security_authority_id, fence)?;
            return Ok(record);
        }
        let binding = SecurityParticipantSourceBinding::new(
            source_id.as_str(),
            security_authority_id.as_str(),
            &fence.store_uuid,
        )
        .map_err(invalid)?;
        // Source I/O is outside the destination mutex and transaction.
        let candidate = records::new_expectation(source.preview(&binding).map_err(invalid)?)?;
        {
            let mut connection = self.connection()?;
            let tx = self.begin_write(&mut connection, Some(fence))?;
            let observed = migration_time(&tx, trusted_now_unix_ms)?;
            require_distinct_source(&tx, &candidate.snapshot)?;
            records::verify_all(&tx)?;
            if let Some(current) = records::load(&tx, security_authority_id.as_str())? {
                require_same(&current, &candidate)?;
                return Ok(current);
            }
            records::insert_expectation(&tx, &candidate)?;
            cutpoint(1)?;
            records::insert_event(&tx, &candidate, 1, observed, fence)?;
            records::verify_all(&tx)?;
            append_commit(&self.serving_owner, &tx, security_authority_id.as_str(), 1)?;
            cutpoint(2)?;
            self.commit_write(tx)?;
            crash_after_commit(9);
            self.sync_after_write(&connection)?;
        }
        cutpoint(3)?;
        let readback = self
            .load_security_participant_migration(security_authority_id, fence, trusted_now_unix_ms)?
            .ok_or_else(|| invalid("source expectation readback missing"))?;
        require_same(&readback, &candidate)?;
        Ok(readback)
    }

    /// Copy every retained source row into immutable destination history. This
    /// does not hydrate active flow state or enable any legacy/operation writer.
    pub fn import_security_participant_source(
        &self,
        security_authority_id: &AdmissionIdentifier,
        expectation_id: &AdmissionIdentifier,
        source: &SqliteSecurityParticipantSource,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<SecurityParticipantMigrationRecord, AdmissionOperationStoreError> {
        let _migration = self
            .serving_owner
            .begin_replay_source_migration()
            .map_err(map_owner_error)?;
        let expected = self
            .load_security_participant_migration(security_authority_id, fence, trusted_now_unix_ms)?
            .ok_or_else(|| invalid("source expectation is absent"))?;
        if expected.expectation_id() != expectation_id {
            return Err(invalid("source generation mismatch"));
        }
        if expected.phase() == SecurityParticipantMigrationPhase::Expected {
            source.seal_exact(&expected.snapshot).map_err(invalid)?;
        }
        cutpoint(4)?;
        let retained = source
            .read_sealed_rows(&expected.snapshot)
            .map_err(invalid)?;
        cutpoint(5)?;
        {
            let mut connection = self.connection()?;
            let tx = self.begin_write(&mut connection, Some(fence))?;
            let observed = migration_time(&tx, trusted_now_unix_ms)?;
            records::verify_all(&tx)?;
            let current = records::load(&tx, security_authority_id.as_str())?
                .ok_or_else(|| invalid("source expectation disappeared"))?;
            require_same(&current, &expected)?;
            if current.phase() == SecurityParticipantMigrationPhase::ImportedInactive {
                return Ok(current);
            }
            storage::insert_rows(&tx, &current, retained)?;
            cutpoint(6)?;
            records::insert_event(&tx, &current, 2, observed, fence)?;
            records::verify_all(&tx)?;
            append_commit(&self.serving_owner, &tx, security_authority_id.as_str(), 2)?;
            cutpoint(7)?;
            self.commit_write(tx)?;
            crash_after_commit(10);
            self.sync_after_write(&connection)?;
        }
        cutpoint(8)?;
        let imported = self
            .load_security_participant_migration(security_authority_id, fence, trusted_now_unix_ms)?
            .ok_or_else(|| invalid("inactive import readback missing"))?;
        require_same(&imported, &expected)?;
        if imported.phase() != SecurityParticipantMigrationPhase::ImportedInactive {
            return Err(invalid("inactive import phase mismatch"));
        }
        Ok(imported)
    }

    pub fn load_security_participant_migration(
        &self,
        security_authority_id: &AdmissionIdentifier,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<SecurityParticipantMigrationRecord>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        migration_time(&tx, trusted_now_unix_ms)?;
        verify_security_participant_migration_coverage(&tx).map_err(map_owner_error)?;
        let record = records::load(&tx, security_authority_id.as_str())?;
        if record.as_ref().is_some_and(|record| {
            record.snapshot.binding().destination_store_uuid().as_str() != fence.store_uuid
        }) {
            return Err(invalid("migration destination mismatch"));
        }
        Ok(record)
    }
}

fn require_binding(
    snapshot: &SecurityParticipantSourceSnapshot,
    source: &AdmissionIdentifier,
    authority: &AdmissionIdentifier,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let binding = snapshot.binding();
    if binding.source_id().as_str() != source.as_str()
        || binding.security_authority_id().as_str() != authority.as_str()
        || binding.destination_store_uuid().as_str() != fence.store_uuid
    {
        return Err(invalid("source binding mismatch"));
    }
    Ok(())
}

pub(super) fn load_imported_source(
    connection: &Connection,
    authority: &str,
) -> Result<SecurityParticipantMigrationRecord, AdmissionOperationStoreError> {
    let record = records::load(connection, authority)?
        .ok_or_else(|| invalid("security source expectation is absent"))?;
    if record.phase() != SecurityParticipantMigrationPhase::ImportedInactive {
        return Err(invalid("security source is not completely imported"));
    }
    Ok(record)
}

fn require_same(
    actual: &SecurityParticipantMigrationRecord,
    expected: &SecurityParticipantMigrationRecord,
) -> Result<(), AdmissionOperationStoreError> {
    if actual.snapshot != expected.snapshot
        || actual.expectation_id != expected.expectation_id
        || actual.fingerprint_digest != expected.fingerprint_digest
    {
        return Err(invalid("source expectation conflict"));
    }
    Ok(())
}

pub(super) fn require_distinct_source(
    connection: &Connection,
    source: &SecurityParticipantSourceSnapshot,
) -> Result<(), AdmissionOperationStoreError> {
    let identity = main_database_file_identity(connection).map_err(invalid)?;
    let source_identity = source.file_identity().map_err(invalid)?;
    if identity.device == source_identity.device && identity.inode == source_identity.inode {
        return Err(invalid("destination cannot be its own security source"));
    }
    Ok(())
}

fn mutation(sequence: u64) -> Result<&'static str, AdmissionOperationStoreError> {
    match sequence {
        1 => Ok("expect_security_participant_source"),
        2 => Ok("import_security_participant_source"),
        _ => Err(invalid("unsupported migration sequence")),
    }
}

fn append_commit(
    owner: &SqliteServingOwner,
    tx: &Transaction<'_>,
    authority: &str,
    sequence: u64,
) -> Result<(), AdmissionOperationStoreError> {
    owner
        .append_global_commit(
            tx,
            mutation(sequence)?,
            PROJECTION_KIND,
            authority,
            sequence,
        )
        .map_err(map_owner_error)
}

fn migration_time(tx: &Transaction<'_>, now: u64) -> Result<u64, AdmissionOperationStoreError> {
    schema::authority_validation_time(tx, now)?;
    // Caller skew validation must not let an ahead caller timestamp conceal an
    // independently observed authority-clock rollback or advance this ledger.
    let observed = schema::observe_authority_time(tx)?;
    let high_water: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(observed_at_unix_ms), 0)
        FROM security_participant_migration_events",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if observed < u64::try_from(high_water).map_err(invalid)? {
        return Err(invalid("migration clock regressed"));
    }
    Ok(observed)
}

fn invalid(detail: impl std::fmt::Display) -> AdmissionOperationStoreError {
    invariant(format!("security participant migration: {detail}"))
}

fn cutpoint(_stage: u8) -> Result<(), AdmissionOperationStoreError> {
    #[cfg(test)]
    super::tests::security_participant_migration::cutpoint(_stage)?;
    Ok(())
}

fn crash_after_commit(_stage: u8) {
    #[cfg(test)]
    super::tests::security_participant_migration::crash_cutpoint(_stage);
}
