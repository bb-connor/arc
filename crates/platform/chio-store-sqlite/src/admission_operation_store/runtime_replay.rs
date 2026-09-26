//! Anchored replay migration and activation. Activation qualifies a replay
//! backend, not a request, prepared plan or dispatch authorization.

use chio_kernel::admission_operation::{RuntimeReplaySourcePort, RuntimeReplaySourceSnapshotV1};

use super::*;

mod activation;
mod integrity;
mod records;

pub(crate) use integrity::{
    runtime_replay_projection_reference, verify_runtime_replay_pristine,
    verify_runtime_replay_projection_coverage,
};
pub(super) use records::verify_all_records;
use records::{load_record, MigrationEvent};

pub(super) fn require_imported_source(
    connection: &Connection,
    authority: &AdmissionIdentifier,
    expectation: &AdmissionIdentifier,
) -> Result<RuntimeReplayMigrationRecordV1, AdmissionOperationStoreError> {
    let record = load_record(connection, authority.as_str())
        .map_err(integrity_error)?
        .ok_or_else(|| invariant("runtime participant source expectation is absent"))?;
    if !record.is_imported() || record.expectation_id() != expectation {
        return Err(invariant(
            "runtime participant source is not the exact imported generation",
        ));
    }
    Ok(record)
}

const EXPECT_MUTATION: &str = "expect_runtime_replay_source";
const IMPORT_MUTATION: &str = "import_runtime_replay_source";
const ACTIVATE_MUTATION: &str = "activate_runtime_replay_source";
const PROJECTION_KIND: &str = "runtime_replay_migration";
const MAX_MIGRATIONS: usize = 128;
const MAX_TOTAL_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_TOTAL_MARKERS: usize = 65_536;

/// Fenced source-generation history, not participant ownership or dispatch authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeReplayMigrationRecordV1 {
    snapshot: RuntimeReplaySourceSnapshotV1,
    expectation_id: AdmissionIdentifier,
    expectation_digest: String,
    events: Vec<MigrationEvent>,
}

impl RuntimeReplayMigrationRecordV1 {
    pub fn snapshot(&self) -> &RuntimeReplaySourceSnapshotV1 {
        &self.snapshot
    }

    pub fn expectation_id(&self) -> &AdmissionIdentifier {
        &self.expectation_id
    }

    pub fn expectation_digest(&self) -> &str {
        &self.expectation_digest
    }

    pub fn imported_inactive(&self) -> bool {
        self.events.len() == 2
    }

    pub fn is_imported(&self) -> bool {
        self.events.len() >= 2
    }
    pub fn is_active(&self) -> bool {
        self.events.len() == 3
    }

    pub fn event_sequence(&self) -> u64 {
        self.events.len() as u64
    }
}

impl SqliteAdmissionOperationStore {
    /// Pin one immutable source generation under an independently configured
    /// runtime authority. The actual destination UUID comes from this store.
    ///
    /// Source I/O is trusted operator configuration, not an agent-selectable
    /// plugin. No source callback runs while the destination mutex is held.
    pub fn expect_runtime_replay_source(
        &self,
        source_id: &AdmissionIdentifier,
        runtime_authority_id: &AdmissionIdentifier,
        source: &dyn RuntimeReplaySourcePort,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<RuntimeReplayMigrationRecordV1, AdmissionOperationStoreError> {
        // Validate authority before even read-only source callbacks. Exact pin
        // retry returns existing history without rediscovering a sealed source.
        if let Some(existing) =
            self.load_runtime_replay_migration(runtime_authority_id, fence, trusted_now_unix_ms)?
        {
            require_source_binding(&existing.snapshot, source_id, runtime_authority_id, fence)?;
            return Ok(existing);
        }
        let destination =
            AdmissionIdentifier::try_new("destination_store_uuid", &fence.store_uuid)?;
        let snapshot = source.preview(source_id, runtime_authority_id, &destination)?;
        require_source_binding(&snapshot, source_id, runtime_authority_id, fence)?;
        let candidate = records::new_expectation(snapshot)?;

        {
            let mut connection = self.connection()?;
            let transaction = self.begin_write(&mut connection, Some(fence))?;
            let observed = migration_time(&transaction, trusted_now_unix_ms)?;
            verify_all_records(&transaction).map_err(integrity_error)?;
            if let Some(existing) =
                load_record(&transaction, runtime_authority_id.as_str()).map_err(integrity_error)?
            {
                require_same_expectation(&existing, &candidate)?;
                return Ok(existing);
            }
            let source_exists: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM runtime_replay_migration_expectations WHERE source_id = ?1)",
                    [source_id.as_str()],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if source_exists {
                return Err(invariant("runtime replay migration expectation conflict"));
            }
            records::insert_expectation(&transaction, &candidate)?;
            records::insert_event(&transaction, &candidate, 1, observed, fence)?;
            verify_all_records(&transaction).map_err(integrity_error)?;
            append_migration_commit(
                &self.serving_owner,
                &transaction,
                runtime_authority_id.as_str(),
                1,
            )?;
            self.commit_write(transaction)?;
            self.sync_after_write(&connection)?;
        }
        // Read back through the same fenced/anchored port. A failed readback
        // never authorizes sealing an unconfirmed destination expectation.
        self.load_runtime_replay_migration(runtime_authority_id, fence, trusted_now_unix_ms)?
            .filter(|record| record.expectation_id == candidate.expectation_id)
            .ok_or_else(|| invariant("runtime replay migration expectation readback mismatch"))
    }

    /// Seal the exact pinned source, then atomically retain every historical
    /// marker as unresolved blocking evidence. This never activates a profile.
    ///
    /// Concurrent or reentrant imports through this serving owner reject
    /// without waiting. A blocked trusted source callback retains that import
    /// guard, but does not hold the destination database mutex or transaction.
    pub fn import_runtime_replay_source(
        &self,
        runtime_authority_id: &AdmissionIdentifier,
        expectation_id: &AdmissionIdentifier,
        source: &dyn RuntimeReplaySourcePort,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<RuntimeReplayMigrationRecordV1, AdmissionOperationStoreError> {
        // Share this guard across every adapter belonging to the owner. A
        // concurrent stale pending plan must not reseal a source after another
        // import has already made its barriers permanent historical evidence.
        let _migration = self
            .serving_owner
            .begin_replay_source_migration()
            .map_err(map_owner_error)?;
        let expected = self
            .load_runtime_replay_migration(runtime_authority_id, fence, trusted_now_unix_ms)?
            .ok_or_else(|| invariant("runtime replay migration expectation not found"))?;
        if expected.expectation_id() != expectation_id {
            return Err(invariant(
                "runtime replay migration source generation mismatch",
            ));
        }
        // These callbacks can block, fail, or lose their acknowledgements. They
        // run outside the destination database mutex/transaction. No import is recorded
        // unless live exact verification succeeds.
        // Once import is durably recorded, missing source barriers are damage,
        // not an interrupted first seal. Never reconstruct them on replay.
        if !expected.is_imported() {
            source.seal_exact(expected.snapshot())?;
        }
        source.verify_exact(expected.snapshot())?;

        {
            let mut connection = self.connection()?;
            let transaction = self.begin_write(&mut connection, Some(fence))?;
            let observed = migration_time(&transaction, trusted_now_unix_ms)?;
            verify_all_records(&transaction).map_err(integrity_error)?;
            let current = load_record(&transaction, runtime_authority_id.as_str())
                .map_err(integrity_error)?
                .ok_or_else(|| invariant("runtime replay migration expectation not found"))?;
            require_same_expectation(&current, &expected)?;
            if current.is_imported() {
                return Ok(current);
            }
            records::insert_tombstones(&transaction, &current)?;
            records::insert_event(&transaction, &current, 2, observed, fence)?;
            verify_all_records(&transaction).map_err(integrity_error)?;
            append_migration_commit(
                &self.serving_owner,
                &transaction,
                runtime_authority_id.as_str(),
                2,
            )?;
            self.commit_write(transaction)?;
            self.sync_after_write(&connection)?;
        }
        let imported = self
            .load_runtime_replay_migration(runtime_authority_id, fence, trusted_now_unix_ms)?
            .ok_or_else(|| invariant("runtime replay migration import readback missing"))?;
        require_same_expectation(&imported, &expected)?;
        if !imported.is_imported() {
            return Err(invariant(
                "runtime replay migration import readback mismatch",
            ));
        }
        Ok(imported)
    }

    /// Fenced, anchored history lookup. Missing or altered physical records are
    /// corruption, never permission to reconstruct or replace a generation.
    pub fn load_runtime_replay_migration(
        &self,
        runtime_authority_id: &AdmissionIdentifier,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<RuntimeReplayMigrationRecordV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(fence))?;
        migration_time(&transaction, trusted_now_unix_ms)?;
        verify_runtime_replay_projection_coverage(&transaction).map_err(map_owner_error)?;
        let record =
            load_record(&transaction, runtime_authority_id.as_str()).map_err(integrity_error)?;
        if record.as_ref().is_some_and(|record| {
            record.snapshot.destination_authority_id() != self.serving_owner.fence.store_uuid
        }) {
            return Err(invariant(
                "runtime replay migration destination binding mismatch",
            ));
        }
        Ok(record)
    }
}

fn require_source_binding(
    snapshot: &RuntimeReplaySourceSnapshotV1,
    source_id: &AdmissionIdentifier,
    runtime_authority_id: &AdmissionIdentifier,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    if snapshot.source_id() != source_id.as_str()
        || snapshot.runtime_authority_id() != runtime_authority_id.as_str()
        || snapshot.destination_authority_id() != fence.store_uuid
    {
        return Err(invariant(
            "runtime replay migration source binding mismatch",
        ));
    }
    Ok(())
}

fn require_same_expectation(
    actual: &RuntimeReplayMigrationRecordV1,
    expected: &RuntimeReplayMigrationRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if actual.expectation_id != expected.expectation_id
        || actual.expectation_digest != expected.expectation_digest
        || actual.snapshot != expected.snapshot
    {
        return Err(invariant("runtime replay migration expectation conflict"));
    }
    Ok(())
}

fn append_migration_commit(
    owner: &SqliteServingOwner,
    transaction: &Transaction<'_>,
    runtime_authority_id: &str,
    sequence: u64,
) -> Result<(), AdmissionOperationStoreError> {
    owner
        .append_global_commit(
            transaction,
            migration_mutation(sequence)?,
            PROJECTION_KIND,
            runtime_authority_id,
            sequence,
        )
        .map_err(map_owner_error)
}

fn migration_mutation(sequence: u64) -> Result<&'static str, AdmissionOperationStoreError> {
    match sequence {
        1 => Ok(EXPECT_MUTATION),
        2 => Ok(IMPORT_MUTATION),
        3 => Ok(ACTIVATE_MUTATION),
        _ => Err(invariant("invalid runtime migration sequence")),
    }
}

fn integrity_error(detail: impl std::fmt::Display) -> AdmissionOperationStoreError {
    invariant(format!("runtime replay migration integrity: {detail}"))
}

fn migration_time(
    transaction: &Transaction<'_>,
    trusted_now_unix_ms: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    let observed = schema::authority_validation_time(transaction, trusted_now_unix_ms)?;
    let high_water: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(observed_at_unix_ms), 0) FROM runtime_replay_migration_events",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let high_water = u64::try_from(high_water)
        .map_err(|_| integrity_error("migration authority clock is negative"))?;
    if observed < high_water {
        return Err(invariant(
            "runtime replay migration authority time regressed",
        ));
    }
    // This projection has its own history. Advancing the admission-operation
    // counter here would invent a corresponding invocation commit.
    Ok(observed)
}
