//! Irreversible approval authority handoff. Activation cannot reset the legacy
//! clock or infer fresh authority from already pruned replay history.
use super::*;
use chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalAuthorityBindingV1;

impl SqliteAdmissionOperationStore {
    pub fn activate_governed_approval_replay_source(
        &self,
        binding: &GovernedApprovalAuthorityBindingV1,
        source: &dyn GovernedApprovalReplaySourcePort,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<GovernedApprovalReplayMigrationRecordV1, AdmissionOperationStoreError> {
        let _migration = self
            .serving_owner
            .begin_replay_source_migration()
            .map_err(map_owner_error)?;
        let expected = self
            .load_governed_approval_replay_migration(
                binding.approval_authority_id(),
                fence,
                trusted_now_unix_ms,
            )?
            .ok_or_else(|| invariant("approval activation requires imported history"))?;
        if !expected.is_imported() || expected.expectation_id() != binding.expectation_id() {
            return Err(invariant(
                "approval activation requires the exact imported generation",
            ));
        }
        source_io(|| source.verify_exact(expected.snapshot()))?;
        {
            let mut connection = self.connection()?;
            let tx = self.begin_write(&mut connection, Some(fence))?;
            let observed = approval_clock_tx(&tx, expected.snapshot(), trusted_now_unix_ms)?;
            verify_all_records(&tx).map_err(integrity_error)?;
            let current = load_record(&tx, binding.approval_authority_id().as_str())
                .map_err(integrity_error)?
                .ok_or_else(|| invariant("approval activation history disappeared"))?;
            require_same_expectation(&current, &expected)?;
            if current.is_active() {
                return Ok(current);
            }
            if !current.imported_inactive() {
                return Err(invariant(
                    "approval activation predecessor is not imported-inactive",
                ));
            }
            records::insert_event(&tx, &current, 3, observed, fence)?;
            verify_all_records(&tx).map_err(integrity_error)?;
            append_migration_commit(
                &self.serving_owner,
                &tx,
                binding.approval_authority_id().as_str(),
                3,
            )?;
            self.commit_write(tx)?;
            self.sync_after_write(&connection)?;
        }
        let active = self
            .load_governed_approval_replay_migration(
                binding.approval_authority_id(),
                fence,
                trusted_now_unix_ms,
            )?
            .ok_or_else(|| invariant("approval activation readback missing"))?;
        require_same_expectation(&active, &expected)?;
        if !active.is_active() {
            return Err(invariant("approval activation readback is inactive"));
        }
        Ok(active)
    }
}

pub(in crate::admission_operation_store) fn require_active_source(
    connection: &Connection,
    authority: &AdmissionIdentifier,
    expectation: &AdmissionIdentifier,
) -> Result<GovernedApprovalReplaySourceSnapshot, AdmissionOperationStoreError> {
    let record = load_record(connection, authority.as_str())
        .map_err(integrity_error)?
        .ok_or_else(|| invariant("approval profile has no source history"))?;
    if !record.is_active() || record.expectation_id() != expectation {
        return Err(invariant(
            "approval profile is not the exact active generation",
        ));
    }
    Ok(record.snapshot)
}

pub(in crate::admission_operation_store) fn approval_clock_tx(
    tx: &Transaction<'_>,
    source: &GovernedApprovalReplaySourceSnapshot,
    decision_time: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    // Require the authority's actual observation, not merely a caller timestamp
    // ahead within tolerated skew, to have reached the imported high-water.
    let observed = schema::observe_authority_time(tx)?;
    verify_source_clock_floor(source, observed)?;
    let effective = migration_time(tx, decision_time)?;
    verify_source_clock_floor(source, effective)?;
    Ok(effective)
}

pub(in crate::admission_operation_store) fn verify_source_clock_floor(
    source: &GovernedApprovalReplaySourceSnapshot,
    observed_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let high_water: u64 = source
        .inventory()
        .wall_clock_high_water
        .parse()
        .map_err(|_| invariant("invalid imported approval clock"))?;
    if observed_unix_ms / 1000 < high_water {
        return Err(invariant(
            "approval authority clock precedes imported high-water and prune horizon",
        ));
    }
    Ok(())
}
