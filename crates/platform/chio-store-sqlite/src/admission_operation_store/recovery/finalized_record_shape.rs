//! Bound future terminal fields without changing frozen publication bindings.
use super::*;

const TERMINAL_RECORD_SPARE_BYTES: usize = 32768;
const MAX_PROVIDER_FINALITY_BYTES: usize = 16384;

fn finalized_shape(
    record: &RecoveryWorkflowRecordV1,
) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
    // Exhaustive destructuring makes additions to this vocabulary require an
    // explicit accounting decision. The twenty frozen fields remain exact.
    let RecoveryWorkflowRecordV1 {
        scope,
        origin,
        workflow_id,
        step_id,
        continuation_id,
        revision: _,
        control: _,
        seed,
        creation_seed,
        deployment_digest,
        created_by,
        effect_cardinality,
        action,
        process_reservation,
        selected,
        review,
        approval,
        issuance,
        signed_grant,
        envelope,
        admission,
        admission_closed: _,
        native_link: _,
        captured: _,
        captured_deployment: _,
        historical_hold: _,
        effect: _,
        release: _,
        original_flow,
        reported_decision: _,
        provider_finality: _,
        provider_lookups: _,
    } = record.clone();
    let admission = admission.ok_or_else(|| invariant("recovery finalized intent is absent"))?;
    if envelope.is_none() {
        return Err(invariant("recovery finalized envelope is absent"));
    }
    let effect = EffectObservationV1::AdmissionUnresolved {
        admission_intent: admission.intent.clone(),
    };
    Ok(RecoveryWorkflowRecordV1 {
        scope,
        origin,
        workflow_id,
        step_id,
        continuation_id,
        revision: SafeInteger::ZERO,
        control: WorkflowControlV1::Active,
        seed,
        creation_seed,
        deployment_digest,
        created_by,
        effect_cardinality,
        action,
        process_reservation,
        selected,
        review,
        approval,
        issuance,
        signed_grant,
        envelope,
        admission: Some(admission),
        admission_closed: false,
        native_link: None,
        captured: false,
        captured_deployment: None,
        historical_hold: None,
        effect,
        release: ReleaseDispositionV1::NotAvailable,
        original_flow,
        reported_decision: None,
        provider_finality: None,
        provider_lookups: SafeInteger::ZERO,
    })
}

pub(super) fn finalized_shape_bytes(
    record: &RecoveryWorkflowRecordV1,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    canonical_json_bytes(&finalized_shape(record)?)
        .map_err(|_| invariant("recovery finalized shape encoding refused"))
}

/// The same frozen shape is checked after envelope/admission staging and before
/// capture. Adding native_link or revision progress cannot move this boundary.
pub(in crate::admission_operation_store) fn require_finalized_workflow_headroom(
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if finalized_shape_bytes(record)?.len()
        > MAX_RECOVERY_RECORD_BYTES - TERMINAL_RECORD_SPARE_BYTES
    {
        return Err(invariant("recovery terminal record headroom exhausted"));
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn require_provider_finality_headroom(
    finality: &chio_core_types::recovery::SignedRecoveryProviderFinalityV1,
) -> Result<(), AdmissionOperationStoreError> {
    let bytes = canonical_json_bytes(finality)
        .map_err(|_| invariant("recovery finality encoding refused"))?;
    if bytes.len() > MAX_PROVIDER_FINALITY_BYTES {
        return Err(invariant("recovery terminal finality headroom exhausted"));
    }
    Ok(())
}

#[cfg(feature = "admission-test-support")]
pub(in crate::admission_operation_store) fn fixture_finalized_shape(
    record: &RecoveryWorkflowRecordV1,
) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
    finalized_shape(record)
}
