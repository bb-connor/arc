//! Historical operation-owned egress, never fresh execution or row authority.
use super::*;
use chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1;

mod portable;
pub(in crate::admission_operation_store::security_participant_state) use portable::load_history;

pub struct SecurityParticipantEgressHistory {
    binding: NativeSecurityAuthorityBindingV1,
    operation: AdmissionOperationId,
    digest: AdmissionDigest,
    live_request_hash: AdmissionDigest,
    fence: EgressFence,
    committed: Option<CommittedEgressFence>,
}

impl SecurityParticipantEgressHistory {
    pub fn binding(&self) -> &NativeSecurityAuthorityBindingV1 {
        &self.binding
    }
    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation
    }
    pub fn event_digest(&self) -> &AdmissionDigest {
        &self.digest
    }
    pub fn live_request_hash(&self) -> &AdmissionDigest {
        &self.live_request_hash
    }
    pub fn historical_fence(&self) -> &EgressFence {
        &self.fence
    }
    pub fn historical_commitment(&self) -> Option<&CommittedEgressFence> {
        self.committed.as_ref()
    }
}

impl std::fmt::Debug for SecurityParticipantEgressHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityParticipantEgressHistory")
            .finish_non_exhaustive()
    }
}

impl SqliteAdmissionOperationStore {
    /// Read historical custody under the current serving fence, without
    /// reacquiring a lease, renewing a fence or authorizing another dispatch.
    pub fn load_security_participant_egress(
        &self,
        operation: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<SecurityParticipantEgressHistory>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        super::super::observed_time(&tx, now)?;
        super::super::verify_coverage(&tx).map_err(map_owner_error)?;
        let record = match load_operation(&tx, operation, "committed")? {
            Some(record) => Some(record),
            None => load_operation(&tx, operation, "acquired")?,
        };
        let Some(record) = record else {
            return Ok(None);
        };
        let initialized = super::super::records::load_metadata(&tx, record.authority.as_str())?
            .ok_or_else(|| invalid("native egress initialization is absent"))?;
        let digest = AdmissionDigest::try_new("native_egress_event", record.digest()?)?;
        let historical_fence = record.command.fence().map_err(invalid)?;
        let committed = match record.result {
            NativeEgressResult::Acquired(_) => None,
            NativeEgressResult::Committed(value) => Some(value),
        };
        Ok(Some(SecurityParticipantEgressHistory {
            binding: initialized.admission_binding()?,
            operation: operation.clone(),
            digest,
            live_request_hash: record.live_request_hash,
            fence: historical_fence,
            committed,
        }))
    }
}
