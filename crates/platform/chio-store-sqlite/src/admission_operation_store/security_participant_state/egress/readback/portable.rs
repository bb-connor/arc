//! Read the current operation and both immutable egress phases in one snapshot.
use super::*;
use chio_kernel::admission_operation::{
    NativeSecurityEgressAcquisitionV1, NativeSecurityEgressCommitmentV1,
    NativeSecurityEgressHistoryV1,
};

impl SqliteAdmissionOperationStore {
    pub(in crate::admission_operation_store) fn load_native_egress_history(
        &self,
        operation: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<
        Option<(AdmissionOperationV1, Option<NativeSecurityEgressHistoryV1>)>,
        AdmissionOperationStoreError,
    > {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        super::super::super::observed_time(&tx, now)?;
        super::super::super::verify_coverage(&tx).map_err(map_owner_error)?;
        let Some(stored) = load_by_operation_id_tx(&tx, operation)? else {
            return Ok(None);
        };
        stored.verify_decision_time(now)?;
        let history = load_history(&tx, operation)?;
        Ok(Some((stored.operation, history)))
    }
}

pub(in crate::admission_operation_store::security_participant_state) fn load_history(
    tx: &Connection,
    operation: &AdmissionOperationId,
) -> Result<Option<NativeSecurityEgressHistoryV1>, AdmissionOperationStoreError> {
    let acquired = load_operation(tx, operation, "acquired")?;
    let committed = load_operation(tx, operation, "committed")?;
    let Some(acquired) = acquired else {
        if committed.is_some() {
            return Err(invalid("native egress commitment has no acquisition"));
        }
        return Ok(None);
    };
    let initialized = super::super::super::records::load_metadata(tx, acquired.authority.as_str())?
        .ok_or_else(|| invalid("native egress initialization is absent"))?;
    let acquisition_digest = AdmissionDigest::try_new("native_egress_event", acquired.digest()?)?;
    let fence = match acquired.result {
        NativeEgressResult::Acquired(fence) => fence,
        NativeEgressResult::Committed(_) => {
            return Err(invalid("native egress acquisition result differs"));
        }
    };
    let commitment = committed
        .map(|record| {
            let event_digest = AdmissionDigest::try_new("native_egress_event", record.digest()?)?;
            let predecessor = record
                .acquisition_digest
                .ok_or_else(|| invalid("native egress acquisition predecessor is absent"))?;
            if predecessor != acquisition_digest {
                return Err(invalid("native egress acquisition predecessor differs"));
            }
            let commitment = match record.result {
                NativeEgressResult::Committed(commitment) => commitment,
                NativeEgressResult::Acquired(_) => {
                    return Err(invalid("native egress commitment result differs"));
                }
            };
            Ok::<_, AdmissionOperationStoreError>(NativeSecurityEgressCommitmentV1 {
                commitment,
                event_digest,
                acquisition_digest: predecessor,
                declassification: match record.command {
                    NativeEgressCommand::CommitDeclassified { consumption, .. } => {
                        Some(*consumption)
                    }
                    NativeEgressCommand::Acquire(_) | NativeEgressCommand::Commit(_) => None,
                },
            })
        })
        .transpose()?;
    Ok(Some(NativeSecurityEgressHistoryV1 {
        binding: initialized.admission_binding()?,
        operation_id: operation.clone(),
        live_request_hash: acquired.live_request_hash,
        acquisition: NativeSecurityEgressAcquisitionV1 {
            fence,
            event_digest: acquisition_digest,
        },
        commitment,
    }))
}
