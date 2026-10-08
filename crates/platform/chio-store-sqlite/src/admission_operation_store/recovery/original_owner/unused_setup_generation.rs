//! A qualified unused setup closes only its exact retained native identity.
use super::*;
use crate::admission_operation_store::setup::{
    UnusedSetupReplacementReason, VerifiedUnusedSetupGeneration,
};

pub(in crate::admission_operation_store) const UNUSED_SETUP_GENERATION_SQL: &str =
    "CREATE INDEX admission_operation_recovery_unused_setup_generation ON admission_operation_recovery_records(record_key) WHERE kind='command' AND record_key GLOB 'unused-setup-generation:*';";

#[derive(Eq, PartialEq, Serialize, Deserialize)]
enum ClosureReason {
    ProfileChanged,
    InitialWindowExpired,
    WriterChanged,
    StaleSource,
}

impl From<UnusedSetupReplacementReason> for ClosureReason {
    fn from(value: UnusedSetupReplacementReason) -> Self {
        match value {
            UnusedSetupReplacementReason::ProfileChanged => Self::ProfileChanged,
            UnusedSetupReplacementReason::InitialWindowExpired => Self::InitialWindowExpired,
            UnusedSetupReplacementReason::WriterChanged => Self::WriterChanged,
            UnusedSetupReplacementReason::StaleSource => Self::StaleSource,
        }
    }
}

#[derive(Eq, PartialEq, Serialize, Deserialize)]
enum ClosureSchema {
    #[serde(rename = "chio.recovery.unused-setup-generation.v1")]
    V1,
}

#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnusedClosure {
    schema: ClosureSchema,
    scope: RecoveryScopeV1,
    workflow_id: WorkflowId,
    selected_creation: CanonicalPayloadDigest,
    reason: ClosureReason,
    sealed_at_unix_ms: SafeInteger,
    selection_key: String,
    selection: SourceVersion,
    original_head: SourceVersion,
    workflow_before: SourceVersion,
    quota_before: SourceVersion,
    allocation_before: SourceVersion,
    workflow_after: SourceVersion,
    quota_after: SourceVersion,
    allocation_after: SourceVersion,
    continuation: no_future_admission::ContinuationClosure,
}

fn key(
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "unused-setup-generation:{}",
        sha256_hex(&encode(&(
            RecoveryDigestDomain::ParticipantOwner.name(),
            "unused_setup_generation",
            scope,
            workflow,
        ))?)
    ))
}

pub(in crate::admission_operation_store) fn retire_unused_setup_generation_with_origin<'owner>(
    tx: &Transaction<'_>,
    owner: &'owner SqliteServingOwner,
    proof: VerifiedUnusedSetupGeneration<'_, '_>,
    now: u64,
    cut: &NativeSourceTransactionOrigin<'owner>,
) -> Result<ProtectedMutationDelta, AdmissionOperationStoreError> {
    require_format(tx)?;
    proof.verify(tx)?;
    cut.verify(tx).map_err(map_owner_error)?;
    if !cut.matches_owner(owner)
        || proof.record().scope.authority_domain.as_str() != owner.fence.store_uuid
    {
        return Err(invariant(
            "unused setup closure changed its actual serving owner",
        ));
    }
    require_current_original_owner(tx, proof.record())?;
    super::super::active_workflows::require_live_allocation(tx, proof.record())?;
    historical_holds::require_unheld(tx, proof.record())?;
    let closure_key = key(&proof.record().scope, &proof.record().workflow_id)?;
    if raw_checked(tx, &closure_key)?.is_some() {
        return Err(invariant("unused setup generation was already sealed"));
    }
    let continuation = no_future_admission::verify_unused_native_custody(tx, proof.record(), now)?;
    let mut record = proof.record().clone();
    let mut closure = UnusedClosure {
        schema: ClosureSchema::V1,
        scope: record.scope.clone(),
        workflow_id: record.workflow_id.clone(),
        selected_creation: proof.selected_creation_digest(),
        reason: proof.replacement_reason()?.into(),
        sealed_at_unix_ms: safe(now)?,
        selection_key: proof.selection_source().record_key().to_owned(),
        selection: SourceVersion::capture(proof.selection_source())?,
        original_head: history::load_head(
            tx,
            record
                .origin
                .as_ref()
                .ok_or_else(|| invariant("unused setup lost its original"))?,
        )?
        .1,
        workflow_before: SourceVersion::capture(proof.workflow_source())?,
        quota_before: SourceVersion::capture(&source_reference(
            tx,
            &quota_key(&record.scope, &record.workflow_id)?,
        )?)?,
        allocation_before: SourceVersion::capture(&source_reference(
            tx,
            &allocation_key(&record.scope, &record.workflow_id)?,
        )?)?,
        workflow_after: SourceVersion::capture(proof.workflow_source())?,
        quota_after: SourceVersion::capture(&source_reference(
            tx,
            &quota_key(&record.scope, &record.workflow_id)?,
        )?)?,
        allocation_after: SourceVersion::capture(&source_reference(
            tx,
            &allocation_key(&record.scope, &record.workflow_id)?,
        )?)?,
        continuation,
    };
    super::super::super::resources::check_intake_committing(tx)?;
    let before = global_sequence(tx)?;
    record.control = WorkflowControlV1::Cancelled;
    record.admission_closed = true;
    save_workflow(tx, owner, &mut record, WorkflowWriteClass::Control)?;
    let native = no_future_admission::authenticate_closed(tx, owner, cut, &record, now)?;
    super::super::active_workflows::retire_no_future_native_admission(tx, owner, &native)?;
    closure.workflow_after = SourceVersion::capture(&source_reference(
        tx,
        &workflow_key(&record.scope, &record.workflow_id)?,
    )?)?;
    closure.quota_after = SourceVersion::capture(&source_reference(
        tx,
        &quota_key(&record.scope, &record.workflow_id)?,
    )?)?;
    closure.allocation_after = SourceVersion::capture(&source_reference(
        tx,
        &allocation_key(&record.scope, &record.workflow_id)?,
    )?)?;
    persist(tx, owner, cut, &closure_key, &record.scope, &closure)?;
    verify(tx, &record, &closure)?;
    let delta = actual_delta_since(tx, before)?;
    if delta.mutations() != 6 {
        return Err(invariant(
            "unused setup closure changed its fixed owning footprint",
        ));
    }
    Ok(delta)
}

fn verify(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
    closure: &UnusedClosure,
) -> Result<(), AdmissionOperationStoreError> {
    let origin = record
        .origin
        .as_ref()
        .ok_or_else(|| invariant("unused setup history lost native provenance"))?;
    if closure.scope != record.scope
        || closure.workflow_id != record.workflow_id
        || record.control != WorkflowControlV1::Cancelled
        || !record.admission_closed
        || closure.selected_creation
            != CanonicalPayloadDigest::from_bytes(hash(
                RecoveryDigestDomain::SetupCreation,
                &(&record.creation_seed, origin),
            )?)
        || closure.workflow_before.version.get().checked_add(1)
            != Some(closure.workflow_after.version.get())
        || closure.allocation_before.version.get() != 1
        || closure.allocation_after.version.get() != 2
    {
        return Err(invariant(
            "unused setup history changed its exact sealed generation",
        ));
    }
    closure.selection.historical(tx, &closure.selection_key)?;
    history::verify_historical_owner(tx, record, &closure.original_head)?;
    let workflow_key = workflow_key(&record.scope, &record.workflow_id)?;
    closure.workflow_before.historical(tx, &workflow_key)?;
    closure.workflow_after.current(tx, &workflow_key)?;
    let mut prior = record.clone();
    prior.control = WorkflowControlV1::Active;
    prior.admission_closed = false;
    prior.revision = closure.workflow_before.version;
    let header: (Option<String>, Option<String>) = tx.query_row(
        "SELECT native_namespace,native_request FROM admission_operation_recovery_records WHERE record_key=?1",
        [&workflow_key], |row| Ok((row.get(0)?,row.get(1)?)),
    ).map_err(sqlite_error)?;
    if record_digest(
        &workflow_key,
        &scope_key(&record.scope)?,
        "workflow",
        prior.revision.get(),
        &encode(&prior)?,
        header.0.as_deref(),
        header.1.as_deref(),
    )? != hex(closure.workflow_before.digest.as_bytes())
    {
        return Err(invariant(
            "unused setup closure changed fields outside control and admission closure",
        ));
    }
    let quota_key = quota_key(&record.scope, &record.workflow_id)?;
    closure.quota_before.historical(tx, &quota_key)?;
    closure.quota_after.current(tx, &quota_key)?;
    super::super::workflow_reservations::verify_unused_setup_control_quota(
        tx,
        record,
        closure.quota_before.version.get(),
        &closure.quota_before.digest,
    )?;
    let allocation_key = allocation_key(&record.scope, &record.workflow_id)?;
    closure.allocation_before.historical(tx, &allocation_key)?;
    closure.allocation_after.current(tx, &allocation_key)?;
    super::super::active_workflows::require_no_future_retired_allocation(tx, record)?;
    if no_future_admission::verify_unused_native_custody(
        tx,
        record,
        closure.sealed_at_unix_ms.get(),
    )? != closure.continuation
    {
        return Err(invariant(
            "unused setup history lost independent native absence custody",
        ));
    }
    Ok(())
}

pub(super) fn retired(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let key = key(&record.scope, &record.workflow_id)?;
    if raw_checked(tx, &key)?.is_none() {
        return Ok(false);
    }
    let (closure, _): (UnusedClosure, _) = checked_body(tx, &key, &record.scope, true)?;
    verify(tx, record, &closure)?;
    Ok(true)
}

pub(in crate::admission_operation_store) fn verify_unused_setup_generation_inventory(
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
    if stamp.is_some_and(|version| version <= 40) {
        return require_predecessor_original_owner_absence(tx);
    }
    require_format(tx)?;
    let mut query = tx.prepare(
        "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'unused-setup-generation:*'
         UNION SELECT record_key FROM admission_operation_recovery_events WHERE record_key GLOB 'unused-setup-generation:*'
         UNION SELECT projection_key FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key GLOB 'unused-setup-generation:*' ORDER BY 1",
    ).map_err(sqlite_error)?;
    for key_value in query
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
    {
        let key_value = key_value.map_err(sqlite_error)?;
        let row = raw_checked(tx, &key_value)?
            .ok_or_else(|| invariant("unused setup inventory lost its physical closure"))?;
        let closure: UnusedClosure = decode(&row.payload)?;
        if key_value != key(&closure.scope, &closure.workflow_id)? {
            return Err(invariant("unused setup inventory changed its key"));
        }
        let record = workflow_tx(tx, &closure.scope, &closure.workflow_id)?;
        if !retired(tx, &record)? {
            return Err(invariant(
                "unused setup inventory lost its qualified closure",
            ));
        }
    }
    Ok(())
}
