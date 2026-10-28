use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;
use chio_kernel::admission_operation::{RuntimeSourcePort, RuntimeSourceQualificationV1};

use super::*;

mod integrity;
mod records;
mod requalification;
mod supersession;

pub use requalification::RuntimeSourceRequalificationInput;

pub(crate) use integrity::{
    runtime_source_projection_reference, verify_runtime_source_pristine,
    verify_runtime_source_projection_coverage,
};
pub(super) use records::verify_all_records;

const PROJECTION_KIND: &str = "runtime_source_qualification";
const INSTALL_MUTATION: &str = "install_runtime_source";
const MAX_SOURCES: usize = 128;
const MAX_SUPERSEDED: usize = 1024;
const MAX_QUALIFICATION_HISTORY: usize = MAX_SOURCES + MAX_SUPERSEDED;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSourceRecordV1 {
    qualification: RuntimeSourceQualificationV1,
    qualification_id: AdmissionIdentifier,
    observed_at_unix_ms: u64,
    fence: StoreMutationFence,
    record_digest: String,
}

impl RuntimeSourceRecordV1 {
    pub fn qualification(&self) -> &RuntimeSourceQualificationV1 {
        &self.qualification
    }
    pub fn qualification_id(&self) -> &AdmissionIdentifier {
        &self.qualification_id
    }
}

impl SqliteAdmissionOperationStore {
    pub fn install_runtime_source(
        &self,
        source_id: &AdmissionIdentifier,
        runtime_authority_id: &AdmissionIdentifier,
        source: &dyn RuntimeSourcePort,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<RuntimeSourceRecordV1, AdmissionOperationStoreError> {
        let _installation = self
            .serving_owner
            .begin_replay_source_migration()
            .map_err(map_owner_error)?;
        if let Some(existing) =
            self.load_runtime_source(runtime_authority_id, fence, trusted_now_unix_ms)?
        {
            require_binding(
                &existing.qualification,
                source_id,
                runtime_authority_id,
                fence,
            )?;
            source.verify_exact(&existing.qualification)?;
            return self
                .load_runtime_source(runtime_authority_id, fence, trusted_now_unix_ms)?
                .filter(|current| current == &existing)
                .ok_or_else(|| invariant("runtime source changed during verification"));
        }
        let destination =
            AdmissionIdentifier::try_new("destination_store_uuid", &fence.store_uuid)?;
        let qualification = source.qualify(source_id, runtime_authority_id, &destination)?;
        require_binding(&qualification, source_id, runtime_authority_id, fence)?;
        source.verify_exact(&qualification)?;
        let candidate;
        {
            let mut connection = self.connection()?;
            let transaction = self.begin_write(&mut connection, Some(fence))?;
            let observed = source_time(&transaction, trusted_now_unix_ms, &self.serving_owner)?;
            let current = verify_all_records(&transaction).map_err(integrity_error)?;
            if let Some(existing) = current.iter().find(|record| {
                record.qualification.runtime_authority_id() == runtime_authority_id.as_str()
            }) {
                if existing.qualification != qualification {
                    return Err(invariant("runtime source qualification conflict"));
                }
                return Ok(existing.clone());
            }
            if supersession::active_count(&transaction, &current).map_err(integrity_error)?
                >= MAX_SOURCES
                || current
                    .iter()
                    .any(|record| record.qualification.source_id() == source_id.as_str())
            {
                return Err(invariant(
                    "runtime source capacity or source identity conflict",
                ));
            }
            candidate = records::new_record(qualification, observed, fence.clone())?;
            records::insert(&transaction, &candidate)?;
            verify_all_records(&transaction).map_err(integrity_error)?;
            self.serving_owner
                .append_global_commit(
                    &transaction,
                    INSTALL_MUTATION,
                    PROJECTION_KIND,
                    runtime_authority_id.as_str(),
                    1,
                )
                .map_err(map_owner_error)?;
            self.commit_write(transaction)?;
            self.sync_after_write(&connection)?;
        }
        self.load_runtime_source(runtime_authority_id, fence, trusted_now_unix_ms)?
            .filter(|current| current == &candidate)
            .ok_or_else(|| invariant("runtime source installation readback mismatch"))
    }

    pub fn load_runtime_source(
        &self,
        runtime_authority_id: &AdmissionIdentifier,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<RuntimeSourceRecordV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(fence))?;
        source_time(&transaction, trusted_now_unix_ms, &self.serving_owner)?;
        verify_runtime_source_projection_coverage(&transaction).map_err(map_owner_error)?;
        supersession::require_active(&transaction, runtime_authority_id.as_str())?;
        let record = records::load_record(&transaction, runtime_authority_id.as_str())
            .map_err(integrity_error)?;
        if record.as_ref().is_some_and(|record| {
            record.qualification.destination_authority_id() != fence.store_uuid
        }) {
            return Err(invariant("runtime source destination binding mismatch"));
        }
        Ok(record)
    }

    pub(in crate::admission_operation_store) fn load_qualified_runtime_source(
        &self,
        binding: &RuntimeParticipantAuthorityBindingV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<RuntimeSourceQualificationV1, AdmissionOperationStoreError> {
        let record = self
            .load_runtime_source(binding.runtime_authority_id(), fence, trusted_now_unix_ms)?
            .ok_or_else(|| invariant("runtime profile has no source qualification"))?;
        if record.qualification_id() != binding.qualification_id() {
            return Err(invariant("runtime profile source qualification mismatch"));
        }
        Ok(record.qualification)
    }
}

pub(super) fn require_active_source(
    connection: &Connection,
    runtime: &AdmissionIdentifier,
) -> Result<(), AdmissionOperationStoreError> {
    verify_runtime_source_projection_coverage(connection).map_err(map_owner_error)?;
    supersession::require_active(connection, runtime.as_str())
}

pub(super) fn require_qualified_source(
    connection: &Connection,
    authority: &AdmissionIdentifier,
    qualification: &AdmissionIdentifier,
) -> Result<RuntimeSourceRecordV1, AdmissionOperationStoreError> {
    let record = records::load_record(connection, authority.as_str())
        .map_err(integrity_error)?
        .ok_or_else(|| invariant("runtime participant source qualification is absent"))?;
    if record.qualification_id() != qualification {
        return Err(invariant(
            "runtime participant source qualification mismatch",
        ));
    }
    Ok(record)
}

fn require_binding(
    qualification: &RuntimeSourceQualificationV1,
    source: &AdmissionIdentifier,
    runtime: &AdmissionIdentifier,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    if qualification.source_id() != source.as_str()
        || qualification.runtime_authority_id() != runtime.as_str()
        || qualification.destination_authority_id() != fence.store_uuid
    {
        return Err(invariant("runtime source qualification binding mismatch"));
    }
    Ok(())
}

fn integrity_error(detail: impl std::fmt::Display) -> AdmissionOperationStoreError {
    invariant(format!("runtime source qualification integrity: {detail}"))
}

fn source_time(
    transaction: &Transaction<'_>,
    trusted_now_unix_ms: u64,
    owner: &SqliteServingOwner,
) -> Result<u64, AdmissionOperationStoreError> {
    let observed = schema::authority_validation_time(transaction, trusted_now_unix_ms, owner)?;
    let high_water: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(observed_at_unix_ms), 0) FROM runtime_source_qualifications",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let high_water = u64::try_from(high_water).map_err(integrity_error)?;
    if observed < high_water {
        return Err(invariant("runtime source authority time regressed"));
    }
    Ok(observed)
}
