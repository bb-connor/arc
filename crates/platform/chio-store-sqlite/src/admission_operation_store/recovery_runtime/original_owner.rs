//! A workflow's original claim is permanent. Its owner stays current while the
//! retained claim names it and its creation preimage is unchanged.
use super::*;

pub(in crate::admission_operation_store) fn original_owner_is_current(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let Some(origin) = record.origin.as_ref() else {
        return Ok(false);
    };
    let (claim, _) = origins::load_immutable_claim(tx, origin)?;
    verify_creation_preimage(tx, record)?;
    Ok(claim.scope == record.scope
        && claim.workflow_id == record.workflow_id
        && claim.continuation_id == record.continuation_id
        && claim.origin == *origin)
}

pub(in crate::admission_operation_store) fn require_current_original_owner(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if !original_owner_is_current(tx, record)? {
        return Err(invariant("recovery original owner is closed or superseded"));
    }
    Ok(())
}

fn verify_creation_preimage(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    let key = workflow_key(&record.scope, &record.workflow_id)?;
    let current =
        raw_checked(tx, &key)?.ok_or_else(|| invariant("original owner workflow disappeared"))?;
    source_reference(tx, &key)?;
    if current.kind != "workflow"
        || current.scope != scope_key(&record.scope)?
        || current.version != record.revision.get()
        || current.payload != encode(record)?
    {
        return Err(invariant("original owner requires its physical workflow"));
    }
    let (digest, _) = historical_record_reference(tx, &key, 1)?;
    let mut initial = record.clone();
    initial.seed =
        chio_core_types::recovery::decode_contract(record.creation_seed.as_str().as_bytes())
            .map_err(|_| invariant("original owner lost its pristine creation seed"))?;
    initial.revision =
        SafeInteger::new(1).map_err(|_| invariant("original owner ordinal exhausted"))?;
    initial.control = WorkflowControlV1::Active;
    initial.action = None;
    initial.process_reservation = None;
    initial.selected = false;
    initial.review = None;
    initial.approval = None;
    initial.issuance = None;
    initial.signed_grant = None;
    initial.envelope = None;
    initial.admission = None;
    initial.admission_closed = false;
    initial.native_link = None;
    initial.captured = false;
    initial.captured_deployment = None;
    initial.historical_hold = None;
    initial.effect = EffectObservationV1::NeverAdmitted;
    initial.release = ReleaseDispositionV1::NotAvailable;
    initial.original_flow = None;
    initial.reported_decision = None;
    initial.provider_finality = None;
    initial.provider_lookups = SafeInteger::ZERO;
    if record_digest(
        &key,
        &scope_key(&record.scope)?,
        "workflow",
        1,
        &encode(&initial)?,
        None,
        None,
    )? != digest
    {
        return Err(invariant(
            "original owner changed its complete immutable creation preimage",
        ));
    }
    Ok(())
}
