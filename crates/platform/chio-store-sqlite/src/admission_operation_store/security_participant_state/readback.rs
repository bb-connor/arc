//! Lost-acknowledgement readback never reacquires mutation or dispatch authority.
use super::*;
use chio_security_types::ports::FlowStateSnapshot;

/// Anchored historical result. Not a fresh flow observation or execution permit.
#[derive(Clone, Eq, PartialEq)]
pub struct SecurityParticipantFlowJoinHistory {
    authority: AdmissionIdentifier,
    operation: AdmissionOperationId,
    initialization: String,
    digest: String,
    snapshot: FlowStateSnapshot,
}

impl SecurityParticipantFlowJoinHistory {
    pub fn security_authority_id(&self) -> &AdmissionIdentifier {
        &self.authority
    }
    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation
    }
    pub fn initialization_digest(&self) -> &str {
        &self.initialization
    }
    pub fn mutation_digest(&self) -> &str {
        &self.digest
    }
    /// The snapshot at the recorded join, which may have since been invalidated.
    pub fn historical_snapshot(&self) -> &FlowStateSnapshot {
        &self.snapshot
    }
}

impl std::fmt::Debug for SecurityParticipantFlowJoinHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityParticipantFlowJoinHistory")
            .field("state", &"recorded_monotone_join")
            .finish_non_exhaustive()
    }
}

impl SqliteAdmissionOperationStore {
    /// Read the operation and complete join evidence together. The portable
    /// record is data for the kernel coordinator, not a replacement write owner.
    pub(in crate::admission_operation_store) fn load_native_flow_join_record(
        &self,
        operation: &AdmissionOperationId,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            Option<chio_kernel::admission_operation::NativeSecurityFlowJoinRecordV1>,
        )>,
        AdmissionOperationStoreError,
    > {
        self.load_native_join_record(
            operation,
            fence,
            trusted_now_unix_ms,
            |record, initialized| record.join_record(initialized),
        )
    }

    pub(in crate::admission_operation_store) fn load_native_input_join_record(
        &self,
        operation: &AdmissionOperationId,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            Option<chio_kernel::admission_operation::NativeSecurityInputJoinRecordV1>,
        )>,
        AdmissionOperationStoreError,
    > {
        self.load_native_join_record(
            operation,
            fence,
            trusted_now_unix_ms,
            |record, initialized| record.input_record(initialized),
        )
    }

    fn load_native_join_record<T>(
        &self,
        operation: &AdmissionOperationId,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
        decode: impl FnOnce(
            &history::Record,
            &SecurityParticipantStateInitialization,
        ) -> Result<T, AdmissionOperationStoreError>,
    ) -> Result<Option<(AdmissionOperationV1, Option<T>)>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        observed_time(&tx, trusted_now_unix_ms)?;
        verify_coverage(&tx).map_err(map_owner_error)?;
        let Some(stored) = load_by_operation_id_tx(&tx, operation)? else {
            return Ok(None);
        };
        stored.verify_decision_time(trusted_now_unix_ms)?;
        let history = history::load_for_operation(&tx, operation)?
            .map(|record| {
                let initialized = records::load_metadata(&tx, record.authority.as_str())?
                    .ok_or_else(|| invalid("native join initialization is absent"))?;
                decode(&record, &initialized)
            })
            .transpose()?;
        Ok(Some((stored.operation, history)))
    }

    /// Inspect committed history under the current serving fence. No recovery
    /// lease, unexpired old credential, source device or active operation phase
    /// is required. This returns data only and cannot restart an old command.
    pub fn load_security_participant_flow_join(
        &self,
        operation: &AdmissionOperationId,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<SecurityParticipantFlowJoinHistory>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        observed_time(&tx, trusted_now_unix_ms)?;
        verify_coverage(&tx).map_err(map_owner_error)?;
        let Some(record) = history::load_for_operation(&tx, operation)? else {
            return Ok(None);
        };
        let result = SecurityParticipantFlowJoinHistory {
            authority: record.authority.clone(),
            operation: operation.clone(),
            initialization: record.initialization.clone(),
            digest: record.digest()?,
            snapshot: record.result,
        };
        Ok(Some(result))
    }
}
