//! Activate only an imported exact source whose physical legacy barriers still
//! verify. Quiescing previously admitted legacy invocations is an operator gate.

use super::*;
use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;

impl SqliteAdmissionOperationStore {
    /// Record irreversible activation for one pinned source generation. This
    /// verifies existing barriers without repairing or resealing them. Operators
    /// must quiesce legacy invocations before activation; a source seal cannot
    /// retract an effect that a legacy consumer already admitted.
    pub fn activate_runtime_replay_source(
        &self,
        binding: &RuntimeParticipantAuthorityBindingV1,
        source: &dyn RuntimeReplaySourcePort,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<RuntimeReplayMigrationRecordV1, AdmissionOperationStoreError> {
        let _migration = self
            .serving_owner
            .begin_replay_source_migration()
            .map_err(map_owner_error)?;
        let expected = self
            .load_runtime_replay_migration(
                binding.runtime_authority_id(),
                fence,
                trusted_now_unix_ms,
            )?
            .ok_or_else(|| invariant("runtime activation requires an imported source"))?;
        if !expected.is_imported() || expected.expectation_id() != binding.expectation_id() {
            return Err(invariant(
                "runtime activation requires the exact imported generation",
            ));
        }
        // External source I/O never runs under the destination connection lock.
        // Even an already-active retry verifies the sealed source, never repairs it.
        source.verify_exact(expected.snapshot())?;
        {
            let mut connection = self.connection()?;
            let transaction = self.begin_write(&mut connection, Some(fence))?;
            let observed = migration_time(&transaction, trusted_now_unix_ms)?;
            verify_all_records(&transaction).map_err(integrity_error)?;
            let current = load_record(&transaction, binding.runtime_authority_id().as_str())
                .map_err(integrity_error)?
                .ok_or_else(|| invariant("runtime activation expectation disappeared"))?;
            require_same_expectation(&current, &expected)?;
            if current.is_active() {
                return Ok(current);
            }
            if !current.imported_inactive() {
                return Err(invariant(
                    "runtime activation predecessor is not imported-inactive",
                ));
            }
            records::insert_event(&transaction, &current, 3, observed, fence)?;
            verify_all_records(&transaction).map_err(integrity_error)?;
            append_migration_commit(
                &self.serving_owner,
                &transaction,
                binding.runtime_authority_id().as_str(),
                3,
            )?;
            self.commit_write(transaction)?;
            self.sync_after_write(&connection)?;
        }
        let active = self
            .load_runtime_replay_migration(
                binding.runtime_authority_id(),
                fence,
                trusted_now_unix_ms,
            )?
            .ok_or_else(|| invariant("runtime activation readback is missing"))?;
        require_same_expectation(&active, &expected)?;
        if !active.is_active() {
            return Err(invariant("runtime activation readback is not active"));
        }
        Ok(active)
    }

    pub(in crate::admission_operation_store) fn load_activated_runtime_source(
        &self,
        binding: &RuntimeParticipantAuthorityBindingV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<RuntimeReplaySourceSnapshotV1, AdmissionOperationStoreError> {
        let record = self
            .load_runtime_replay_migration(
                binding.runtime_authority_id(),
                fence,
                trusted_now_unix_ms,
            )?
            .ok_or_else(|| invariant("runtime profile has no activation record"))?;
        if !record.is_active() || record.expectation_id() != binding.expectation_id() {
            return Err(invariant(
                "runtime profile source is not the exact activated generation",
            ));
        }
        Ok(record.snapshot)
    }
}
