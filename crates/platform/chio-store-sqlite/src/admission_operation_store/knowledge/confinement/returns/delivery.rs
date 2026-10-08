//! Fresh byte dispatch is distinct from actor-free owed outcome reconciliation.
use super::*;

impl SqliteAdmissionOperationStore {
    pub fn verify_confined_return_delivery(
        &self,
        input: chio_kernel::admission_operation::ConfinedReturnDeliveryInput<'_>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<IsolationBoundaryV1, AdmissionOperationStoreError> {
        let chio_kernel::admission_operation::ConfinedReturnDeliveryInput {
            actor,
            request,
            seal,
            admission,
        } = input;
        if actor.permission() != RecoveryPermission::ConfinedReturn {
            return Err(refused("return delivery authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, now| {
            let parent_source = require_parent_source_audience(&tx, actor, profile)?;
            let record = record(&tx, actor.scope(), request)?;
            let input = require_input_source_audience(
                &tx,
                actor,
                parent_source,
                &record.reservation.boundary,
            )?;
            require_child_source_audience(&tx, actor, profile, &record, input)?;
            validate_current(&tx, &record, profile, now)?;
            original_admission::verify_actor_and_admission(&tx, &record, actor, admission)?;
            if record.return_seal.as_ref() != Some(seal)
                || !matches!(
                    record.reservation.state,
                    IsolationStateV1::ReturnAdmitted | IsolationStateV1::Closed
                )
                || record
                    .return_admission
                    .as_ref()
                    .is_none_or(|value| value.admitted.state == ArtifactDeliveryStateV1::Admitted)
            {
                return Err(refused("return delivery binding"));
            }
            Ok((tx, record.reservation.boundary))
        })
    }
}
