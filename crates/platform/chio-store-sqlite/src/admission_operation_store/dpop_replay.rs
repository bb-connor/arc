//! Anchored DPoP source expectation and conservative import.
//! Process-relative deadlines are preserved as data, not portable expiry.
//! Imported history is inactive until explicit domain-separated activation.
//! Neither state alone grants an operation claim or dispatch permission.

use chio_kernel::dpop::replay_source::{
    DpopReplaySourceBinding, DpopReplaySourcePort, DpopReplaySourceSnapshot,
};

use super::*;
use chio_kernel::dpop::authority::DpopReplayAuthorityV1;

mod activation;
mod bounds;
mod custody;
mod integrity;
mod records;
pub(super) use custody::{dpop_clock_tx, require_active_authority, verify_source_clock_floor};

pub(crate) use integrity::{
    dpop_replay_projection_reference, verify_dpop_replay_pristine,
    verify_dpop_replay_projection_coverage,
};
pub(super) use records::verify_all_records;
use records::{load_record, MigrationEvent};

const EXPECT_MUTATION: &str = "expect_dpop_replay_source";
const IMPORT_MUTATION: &str = "import_dpop_replay_source";
const ACTIVATE_MUTATION: &str = "activate_dpop_replay_source";
const PROJECTION_KIND: &str = "dpop_replay_migration";
const MAX_MIGRATIONS: usize = 128;
const MAX_TOTAL_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_TOTAL_MARKERS: usize = 65_536;

/// Fenced source-generation history, not participant ownership or dispatch authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DpopReplayMigrationRecordV1 {
    snapshot: DpopReplaySourceSnapshot,
    expectation_id: AdmissionIdentifier,
    expectation_digest: String,
    events: Vec<MigrationEvent>,
    authority: Option<DpopReplayAuthorityV1>,
}

impl DpopReplayMigrationRecordV1 {
    pub fn snapshot(&self) -> &DpopReplaySourceSnapshot {
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
        self.events.len() == 3 && self.authority.is_some()
    }

    pub fn authority(&self) -> Option<&DpopReplayAuthorityV1> {
        self.authority.as_ref()
    }

    pub fn event_sequence(&self) -> u64 {
        self.events.len() as u64
    }
}

impl SqliteAdmissionOperationStore {
    /// Pin one immutable source generation under an independently configured
    /// DPoP authority. The actual destination UUID comes from this store.
    ///
    /// Source I/O is trusted operator configuration, not an agent-selectable
    /// plugin. No source callback runs while the destination mutex is held.
    pub fn expect_dpop_replay_source(
        &self,
        source_instance_id: &AdmissionIdentifier,
        dpop_authority_id: &AdmissionIdentifier,
        source: &dyn DpopReplaySourcePort,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<DpopReplayMigrationRecordV1, AdmissionOperationStoreError> {
        // Validate authority before even read-only source callbacks. Exact pin
        // retry returns existing history without rediscovering a sealed source.
        if let Some(existing) =
            self.load_dpop_replay_migration(dpop_authority_id, fence, trusted_now_unix_ms)?
        {
            require_source_binding(
                &existing.snapshot,
                source_instance_id,
                dpop_authority_id,
                fence,
            )?;
            return Ok(existing);
        }
        let destination =
            AdmissionIdentifier::try_new("destination_store_uuid", &fence.store_uuid)?;
        let snapshot = source_io(|| {
            source.preview_unsealed(&DpopReplaySourceBinding {
                dpop_authority_id: dpop_authority_id.clone(),
                destination_authority_id: destination,
            })
        })?;
        require_source_binding(&snapshot, source_instance_id, dpop_authority_id, fence)?;
        let candidate = records::new_expectation(snapshot)?;

        {
            let mut connection = self.connection()?;
            let transaction = self.begin_write(&mut connection, Some(fence))?;
            let observed = migration_time(&transaction, trusted_now_unix_ms)?;
            verify_all_records(&transaction).map_err(integrity_error)?;
            if let Some(existing) =
                load_record(&transaction, dpop_authority_id.as_str()).map_err(integrity_error)?
            {
                require_same_expectation(&existing, &candidate)?;
                return Ok(existing);
            }
            let source_exists: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM dpop_replay_migration_expectations WHERE source_instance_id = ?1)",
                    [source_instance_id.as_str()],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if source_exists {
                return Err(invariant("DPoP replay migration expectation conflict"));
            }
            records::insert_expectation(&transaction, &candidate)?;
            records::insert_event(&transaction, &candidate, 1, observed, fence)?;
            verify_all_records(&transaction).map_err(integrity_error)?;
            append_migration_commit(
                &self.serving_owner,
                &transaction,
                dpop_authority_id.as_str(),
                1,
            )?;
            self.commit_write(transaction)?;
            self.sync_after_write(&connection)?;
        }
        // Read back through the same fenced/anchored port. A failed readback
        // never authorizes sealing an unconfirmed destination expectation.
        let persisted = self
            .load_dpop_replay_migration(dpop_authority_id, fence, trusted_now_unix_ms)?
            .ok_or_else(|| invariant("DPoP replay migration expectation readback mismatch"))?;
        require_same_expectation(&persisted, &candidate)?;
        Ok(persisted)
    }

    /// Seal the exact pinned source, then atomically retain every historical
    /// marker as unresolved blocking evidence. This never activates a profile.
    ///
    /// Concurrent or reentrant imports through this serving owner reject
    /// without waiting. A blocked trusted source callback retains that import
    /// guard, but does not hold the destination database mutex or transaction.
    pub fn import_dpop_replay_source(
        &self,
        dpop_authority_id: &AdmissionIdentifier,
        expectation_id: &AdmissionIdentifier,
        source: &dyn DpopReplaySourcePort,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<DpopReplayMigrationRecordV1, AdmissionOperationStoreError> {
        // Share this guard across every adapter belonging to the owner. A
        // concurrent stale pending plan must not reseal a source after another
        // import has already made its barriers permanent historical evidence.
        let _migration = self
            .serving_owner
            .begin_replay_source_migration()
            .map_err(map_owner_error)?;
        let expected = self
            .load_dpop_replay_migration(dpop_authority_id, fence, trusted_now_unix_ms)?
            .ok_or_else(|| invariant("DPoP replay migration expectation not found"))?;
        if expected.expectation_id() != expectation_id {
            return Err(invariant(
                "DPoP replay migration source generation mismatch",
            ));
        }
        // These callbacks can block, fail, or lose their acknowledgements. They
        // run outside the destination database mutex/transaction. No import is recorded
        // unless live exact verification succeeds.
        // Once import is durably recorded, missing source barriers are damage,
        // not an interrupted first seal. Never reconstruct them on replay.
        if !expected.is_imported() {
            source_io(|| source.seal_exact(expected.snapshot()))?;
        }
        source_io(|| source.verify_exact(expected.snapshot()))?;

        {
            let mut connection = self.connection()?;
            let transaction = self.begin_write(&mut connection, Some(fence))?;
            let observed = migration_time(&transaction, trusted_now_unix_ms)?;
            verify_all_records(&transaction).map_err(integrity_error)?;
            let current = load_record(&transaction, dpop_authority_id.as_str())
                .map_err(integrity_error)?
                .ok_or_else(|| invariant("DPoP replay migration expectation not found"))?;
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
                dpop_authority_id.as_str(),
                2,
            )?;
            self.commit_write(transaction)?;
            self.sync_after_write(&connection)?;
        }
        let imported = self
            .load_dpop_replay_migration(dpop_authority_id, fence, trusted_now_unix_ms)?
            .ok_or_else(|| invariant("DPoP replay migration import readback missing"))?;
        require_same_expectation(&imported, &expected)?;
        if !imported.is_imported() {
            return Err(invariant("DPoP replay migration import readback mismatch"));
        }
        Ok(imported)
    }

    /// Fenced, anchored history lookup. Missing or altered physical records are
    /// corruption, never permission to reconstruct or replace a generation.
    pub fn load_dpop_replay_migration(
        &self,
        dpop_authority_id: &AdmissionIdentifier,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<DpopReplayMigrationRecordV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(fence))?;
        migration_time(&transaction, trusted_now_unix_ms)?;
        verify_dpop_replay_projection_coverage(&transaction).map_err(map_owner_error)?;
        let record =
            load_record(&transaction, dpop_authority_id.as_str()).map_err(integrity_error)?;
        if record.as_ref().is_some_and(|record| {
            record.snapshot.destination_authority_id() != self.serving_owner.fence.store_uuid
        }) {
            return Err(invariant(
                "DPoP replay migration destination binding mismatch",
            ));
        }
        Ok(record)
    }
}

fn require_source_binding(
    snapshot: &DpopReplaySourceSnapshot,
    source_instance_id: &AdmissionIdentifier,
    dpop_authority_id: &AdmissionIdentifier,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    if snapshot.instance_id() != source_instance_id.as_str()
        || snapshot.dpop_authority_id() != dpop_authority_id.as_str()
        || snapshot.destination_authority_id() != fence.store_uuid
    {
        return Err(invariant("DPoP replay migration source binding mismatch"));
    }
    Ok(())
}

fn require_same_expectation(
    actual: &DpopReplayMigrationRecordV1,
    expected: &DpopReplayMigrationRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if actual.expectation_id != expected.expectation_id
        || actual.expectation_digest != expected.expectation_digest
        || actual.snapshot != expected.snapshot
    {
        return Err(invariant("DPoP replay migration expectation conflict"));
    }
    Ok(())
}

fn append_migration_commit(
    owner: &SqliteServingOwner,
    transaction: &Transaction<'_>,
    dpop_authority_id: &str,
    sequence: u64,
) -> Result<(), AdmissionOperationStoreError> {
    owner
        .append_global_commit(
            transaction,
            migration_mutation(sequence)?,
            PROJECTION_KIND,
            dpop_authority_id,
            sequence,
        )
        .map_err(map_owner_error)
}

fn migration_mutation(sequence: u64) -> Result<&'static str, AdmissionOperationStoreError> {
    match sequence {
        1 => Ok(EXPECT_MUTATION),
        2 => Ok(IMPORT_MUTATION),
        3 => Ok(ACTIVATE_MUTATION),
        _ => Err(invariant("invalid DPoP migration sequence")),
    }
}

fn integrity_error(detail: impl std::fmt::Display) -> AdmissionOperationStoreError {
    invariant(format!("DPoP replay migration integrity: {detail}"))
}

fn migration_time(
    transaction: &Transaction<'_>,
    trusted_now_unix_ms: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    let observed = schema::authority_validation_time(transaction, trusted_now_unix_ms)?;
    let high_water: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(observed_at_unix_ms), 0) FROM dpop_replay_migration_events",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let high_water = u64::try_from(high_water)
        .map_err(|_| integrity_error("migration authority clock is negative"))?;
    if observed < high_water {
        return Err(invariant("DPoP replay migration authority time regressed"));
    }
    // This projection has its own history. Advancing the admission-operation
    // counter here would invent a corresponding invocation commit.
    Ok(observed)
}

fn source_io<T>(
    operation: impl FnOnce() -> Result<T, chio_kernel::KernelError>,
) -> Result<T, AdmissionOperationStoreError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
        .map_err(|_| invariant("configured DPoP replay source panicked"))?
        .map_err(|_| invariant("configured DPoP replay source failed"))
}
