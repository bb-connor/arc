//! Fenced, unadmitted legacy history for forward-upgrade refusal tests.
use super::*;

/// Retain an originless historical workflow without fabricating native effects.
/// The template must be a genuine freshly created, wholly unadmitted record;
/// the alternate seed must have a real closed native original operation.
pub fn retain_unadmitted_legacy_recovery_fixture(
    store: &SqliteAdmissionOperationStore,
    actor: &AuthenticatedRecoveryActor,
    template: &WorkflowId,
    seed: &ToolCallRequest,
    fence: &StoreMutationFence,
    now: u64,
) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
    if actor.permission() != RecoveryPermission::Create {
        return Err(invariant("legacy recovery fixture actor refused"));
    }
    store.recovery_mutation(actor, fence, now, |tx, profile, now| {
        let mut record = workflow_tx(tx, actor.scope(), template)?;
        if record.origin.is_none()
            || record.action.is_some()
            || record.admission.is_some()
            || record.process_reservation.is_some()
            || record.captured
            || record.control != WorkflowControlV1::Active
            || record.effect != EffectObservationV1::NeverAdmitted
            || record.release != ReleaseDispositionV1::NotAvailable
        {
            return Err(invariant("legacy recovery fixture must be unadmitted"));
        }
        validate_seed(seed, profile)?;
        origins::resolve(tx, seed, profile, now).map_err(|error| match error {
            RecoveryCommandPortError::Store(error) => error,
            RecoveryCommandPortError::OriginRefused | RecoveryCommandPortError::Conflict => {
                invariant("legacy fixture original custody refused")
            }
            RecoveryCommandPortError::Busy => AdmissionOperationStoreError::Unavailable(
                "legacy fixture original process journal is busy".into(),
            ),
        })?;
        let suffix = sha256_hex(&encode(&(actor.scope(), &seed.request_id))?);
        record.workflow_id = WorkflowId::new(&format!("legacy-workflow:{suffix}"))
            .map_err(|_| invariant("legacy fixture identity refused"))?;
        record.step_id = StepId::new(&format!("legacy-step:{suffix}"))
            .map_err(|_| invariant("legacy fixture identity refused"))?;
        record.continuation_id = ContinuationId::new(&format!("legacy-continuation:{suffix}"))
            .map_err(|_| invariant("legacy fixture identity refused"))?;
        record.origin = None;
        record.seed = seed.clone();
        record.creation_seed = ProtectedText::new(
            std::str::from_utf8(&encode(seed)?).map_err(|_| invariant("legacy seed refused"))?,
        )
        .map_err(|_| invariant("legacy seed refused"))?;
        if raw(tx, &workflow_key(actor.scope(), &record.workflow_id)?)?.is_some() {
            return Err(invariant("legacy fixture identity already retained"));
        }
        save_workflow(
            tx,
            &store.serving_owner,
            &mut record,
            WorkflowWriteClass::Planning,
        )?;
        Ok(record)
    })
}
