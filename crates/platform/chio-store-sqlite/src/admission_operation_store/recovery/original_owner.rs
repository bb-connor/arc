//! Immutable origin claims retain one current continuation per original operation.
//! Unsupported ownership records refuse before serving and pricing.
use super::*;
use crate::admission_operation_store::setup::VerifiedUnusedSetupGeneration;
use crate::serving_owner::NativeSourceTransactionOrigin;

#[cfg(test)]
#[path = "original_owner/predecessor_absence_tests.rs"]
mod predecessor_absence_tests;

fn safe(value: u64) -> Result<SafeInteger, AdmissionOperationStoreError> {
    SafeInteger::new(value).map_err(|_| invariant("original owner ordinal exhausted"))
}

/// The workflow must retain its exact pristine immutable creation preimage.
fn verify_pristine_creation(
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
    initial.revision = safe(1)?;
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

/// The immutable origin claim is the single original-owner authority. A
/// claim owns at most one current generation; its current-owner head decides
/// which generation that is. Historical bound generations are not current.
pub(in crate::admission_operation_store) fn original_owner_is_current(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let Some(origin) = record.origin.as_ref() else {
        return Ok(false);
    };
    require_predecessor_original_owner_absence(tx)?;
    let (claim, _) = origins::load_immutable_claim(tx, origin)?;
    verify_pristine_creation(tx, record)?;
    super::storage::successor_binding::verify_current_owner(tx, record, &claim)
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

/// Retained successor-ownership prototype catalog, rows or indexes must stay
/// absent from the supported store in every physical location.
pub(in crate::admission_operation_store) fn require_predecessor_original_owner_absence(
    tx: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let present: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name IN ('admission_operation_recovery_original_owner','admission_operation_recovery_original_transfer','admission_operation_recovery_original_tombstone','admission_operation_recovery_unused_setup_generation'))",
        [],
        |row| row.get(0),
    )
    .map_err(sqlite_error)?;
    if present {
        return Err(invariant(
            "predecessor contains successor original ownership catalog",
        ));
    }
    for (table, query) in [
        ("admission_operation_recovery_records", "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-original-*' OR record_key GLOB 'unused-setup-generation:*')"),
        ("admission_operation_recovery_events", "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key GLOB 'recovery-original-*' OR record_key GLOB 'unused-setup-generation:*')"),
        ("authority_global_commits", "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind='recovery' AND (projection_key GLOB 'recovery-original-*' OR projection_key GLOB 'unused-setup-generation:*'))"),
    ] {
        let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)", [table], |row| row.get(0)).map_err(sqlite_error)?;
        if exists && tx.query_row(query, [], |row| row.get::<_,bool>(0)).map_err(sqlite_error)? {
            return Err(invariant("predecessor contains successor original ownership data"));
        }
    }
    Ok(())
}

/// Startup catalog verification: the supported format retains no successor
/// ownership prototype, so its retained presence in any location refuses.
pub(in crate::admission_operation_store) fn verify_original_owner_inventory(
    tx: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let stamp: Option<i32> = tx
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key=?1",
            [ADMISSION_OPERATION_SCHEMA_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if stamp.is_some_and(|version| {
        version <= 40 || version == ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION
    }) {
        return require_predecessor_original_owner_absence(tx);
    }
    Err(invariant(
        "original owner inventory requires its exact supported catalog",
    ))
}

/// Retire an unused setup generation through the normal cancellation writer.
/// The transaction-bound witness proves no admission or Process debt, and the
/// authenticated purpose allocation proves no native debt. Closing admission
/// spends exactly one Control purpose, retires its live allocation and
/// permits a distinct successor.
pub(in crate::admission_operation_store) fn retire_unused_setup_generation_with_origin<'owner>(
    tx: &Transaction<'_>,
    owner: &'owner SqliteServingOwner,
    proof: VerifiedUnusedSetupGeneration<'_, '_>,
    cut: &NativeSourceTransactionOrigin<'owner>,
) -> Result<(), AdmissionOperationStoreError> {
    cut.verify(tx).map_err(map_owner_error)?;
    if !cut.matches_owner(owner) {
        return Err(invariant(
            "setup retirement changed its actual source owner",
        ));
    }
    proof.verify(tx)?;
    let mut record = proof.record().clone();
    require_current_original_owner(tx, &record)?;
    let quota = super::workflow_reservations::unused_setup_quota(tx, &record)?;
    record.admission_closed = true;
    record.control = WorkflowControlV1::Cancelled;
    save_workflow(tx, owner, &mut record, WorkflowWriteClass::Control)?;
    quota.require_one_control_charge(tx)?;
    let closed = workflow_tx(tx, &record.scope, &record.workflow_id)?;
    if !closed.admission_closed
        || closed.control != WorkflowControlV1::Cancelled
        || closed.admission.is_some()
        || closed.captured
        || closed.native_link.is_some()
        || closed.process_reservation.is_some()
        || closed.effect != EffectObservationV1::NeverAdmitted
        || !super::active_workflows::retirement_committed(tx, &closed.scope, &closed.workflow_id)?
    {
        return Err(invariant(
            "setup retirement lost its closed effect-free custody",
        ));
    }
    Ok(())
}

/// Retire an unused materialized setup generation after its genuine unused
/// Process reservation closure is authenticated. The unprobed selection was
/// genuinely rotated away - its native flow source moved past the retained
/// snapshot, its pinned profile or serving writer changed, or its initial
/// qualification window expired - so no probe can ever qualify through it,
/// and its reserved logical call was never finalized or dispatched. The
/// physical closure permanently forbids every Process participant writer
/// for this reservation while preserving the original charge. The
/// authenticated live role is rechecked inside this owning writer, then
/// closing admission retires the live allocation through the normal
/// cancellation writer, which permits a distinct successor.
pub(in crate::admission_operation_store) fn retire_unused_materialized_setup_generation_with_origin<
    'owner,
>(
    tx: &Transaction<'_>,
    owner: &'owner SqliteServingOwner,
    closure: &dyn RecoveryUnusedReservationClosurePort,
    record: &RecoveryWorkflowRecordV1,
    fence: &StoreMutationFence,
    cut: &NativeSourceTransactionOrigin<'owner>,
) -> Result<(), AdmissionOperationStoreError> {
    cut.verify(tx).map_err(map_owner_error)?;
    if !cut.matches_owner(owner) {
        return Err(invariant(
            "unused setup retirement changed its actual source owner",
        ));
    }
    require_current_original_owner(tx, record)?;
    // Undispatched effect-free custody: the unprobed selection never
    // captured, linked a native operation, admitted an effect or retained a
    // hold or finality. Its materialized action and reservation stay
    // immutable historical custody.
    if record.control != WorkflowControlV1::Active
        || record.captured
        || record.native_link.is_some()
        || record.effect != EffectObservationV1::NeverAdmitted
        || record.historical_hold.is_some()
        || auxiliary_historical_hold(tx, record)?.is_some()
        || record.provider_finality.is_some()
    {
        return Err(invariant(
            "unused setup retirement requires undispatched effect-free custody",
        ));
    }
    let reservation: RecoveryProcessReservationV1 = chio_core_types::recovery::decode_contract(
        record
            .process_reservation
            .as_ref()
            .ok_or_else(|| invariant("unused setup retirement lost its reserved process call"))?
            .as_str()
            .as_bytes(),
    )
    .map_err(|_| invariant("unused setup retirement lost its reserved process call"))?;
    // The physical closure commits its immutable row before this writer
    // seals the cancelled admission, and the live role is rechecked here
    // through the actual Process runtime and its journal.
    let role = closure
        .close_unused_recovery_reservation(&reservation)
        .map_err(|_| invariant("unused recovery reservation closure refused"))?;
    role.verify_for(&reservation, fence.store_uuid.as_str())
        .map_err(|_| invariant("unused recovery reservation closure is not authenticated"))?;
    let mut closed = record.clone();
    // The permanent Process closure row and immutable journal events retain
    // the historical reservation and admission custody; the live record
    // keeps only its sealed closed state.
    closed.admission = None;
    closed.process_reservation = None;
    closed.admission_closed = true;
    closed.control = WorkflowControlV1::Cancelled;
    save_workflow(tx, owner, &mut closed, WorkflowWriteClass::Control)?;
    let persisted = workflow_tx(tx, &record.scope, &record.workflow_id)?;
    if !persisted.admission_closed
        || persisted.control != WorkflowControlV1::Cancelled
        || persisted.admission.is_some()
        || persisted.process_reservation.is_some()
        || persisted.captured
        || persisted.native_link.is_some()
        || persisted.effect != EffectObservationV1::NeverAdmitted
        || !super::active_workflows::retirement_committed(
            tx,
            &persisted.scope,
            &persisted.workflow_id,
        )?
    {
        return Err(invariant(
            "unused setup retirement lost its closed effect-free custody",
        ));
    }
    Ok(())
}
