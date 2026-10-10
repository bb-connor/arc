//! Immutable origin claims bind each original operation to one workflow.
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
/// consumed claim is permanent; a different prospective owner conflicts.
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

/// Closes an unprobed setup selection only through the complete successor
/// owner contract, which is not integrated at the supported catalog. Setup
/// pinning replacement reaches this boundary through
/// setup::service::retire_for_replacement; its caller retains the proof, cut
/// and serving-owner checks, and ordinary selection replacement must not
/// bypass consumed-origin fencing.
pub(in crate::admission_operation_store) fn retire_unused_setup_generation_with_origin<'owner>(
    _tx: &Transaction<'_>,
    _owner: &'owner SqliteServingOwner,
    _proof: VerifiedUnusedSetupGeneration<'_, '_>,
    _now: u64,
    _cut: &NativeSourceTransactionOrigin<'owner>,
) -> Result<ProtectedMutationDelta, AdmissionOperationStoreError> {
    Err(invariant(
        "original owner requires the complete successor format",
    ))
}
