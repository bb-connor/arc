//! A verified original denial has one durable continuation owner.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginClaim {
    pub(super) scope: RecoveryScopeV1,
    pub(super) workflow_id: WorkflowId,
    pub(super) continuation_id: ContinuationId,
    pub(super) origin: RecoveryOriginV1,
}

pub(super) fn claim_key(origin: &RecoveryOriginV1) -> Result<String, AdmissionOperationStoreError> {
    // The native operation is exclusive across every tenant/process scope in
    // this authority. A different creation key cannot mint another owner.
    Ok(format!(
        "recovery-origin:{}",
        hex(&hash(
            chio_core_types::recovery::RecoveryDigestDomain::OriginClaim,
            origin.operation.operation_id()
        )?)
    ))
}

pub(super) fn load_claim_by_key(
    tx: &Connection,
    key: &str,
) -> Result<(OriginClaim, ProtectedSourceReference), AdmissionOperationStoreError> {
    let row =
        raw_checked(tx, key)?.ok_or_else(|| invariant("recovery original claim disappeared"))?;
    let source = source_reference(tx, key)?;
    let claim: OriginClaim = decode(&row.payload)?;
    let ordinary: bool = tx.query_row(
        "SELECT native_namespace IS NULL AND native_request IS NULL FROM admission_operation_recovery_records WHERE record_key=?1",
        [key], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if row.kind != "command"
        || row.version != 1
        || row.payload.len() > 4096
        || row.scope != scope_key(&claim.scope)?
        || key != claim_key(&claim.origin)?
        || !ordinary
        || source.version() != 1
    {
        return Err(invariant("recovery original immutable claim changed"));
    }
    Ok((claim, source))
}

pub(super) fn load_immutable_claim(
    tx: &Connection,
    origin: &RecoveryOriginV1,
) -> Result<(OriginClaim, ProtectedSourceReference), AdmissionOperationStoreError> {
    let (claim, source) = load_claim_by_key(tx, &claim_key(origin)?)?;
    if claim.origin != *origin {
        return Err(invariant(
            "recovery original claim changed native provenance",
        ));
    }
    Ok((claim, source))
}

fn require_linked_history(tx: &Transaction<'_>) -> Result<(), AdmissionOperationStoreError> {
    // Canonical origin presence is indexed. Authenticate the selected legacy
    // projection before refusing; no positive cache can hide later legacy rows.
    let key: Option<String> = tx
        .query_row(
            "SELECT record_key FROM admission_operation_recovery_records
         WHERE kind='workflow' AND coalesce(json_type(payload,'$.origin'),'null')='null'
         ORDER BY record_key LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if let Some(key) = key {
        verify_history_workflow(tx, &key)?;
        return Err(invariant(
            "unlinked recovery history requires a separate migration",
        ));
    }
    Ok(())
}

fn verify_history_workflow(tx: &Connection, key: &str) -> Result<(), AdmissionOperationStoreError> {
    let row = raw(tx, key)?.ok_or_else(|| invariant("recovery workflow history is absent"))?;
    let record: RecoveryWorkflowRecordV1 = decode(&row.payload)?;
    if row.kind != "workflow"
        || key != workflow_key(&record.scope, &record.workflow_id)?
        || row.scope != scope_key(&record.scope)?
        || record.revision.get() != row.version
    {
        return Err(invariant("recovery workflow history owner changed"));
    }
    if let Some(origin) = &record.origin {
        let version: Option<i32> = tx
            .query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key=?1",
                [ADMISSION_OPERATION_SCHEMA_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if version == Some(41) {
            return verify_original_owner_membership(tx, &record);
        }
        let retained = raw(tx, &claim_key(origin)?)?
            .ok_or_else(|| invariant("recovery history lost its original claim"))?;
        let claim: OriginClaim = decode(&retained.payload)?;
        if retained.kind != "command"
            || retained.version != 1
            || retained.scope != scope_key(&record.scope)?
            || claim.scope != record.scope
            || claim.workflow_id != record.workflow_id
            || claim.continuation_id != record.continuation_id
            || claim.origin != *origin
        {
            return Err(invariant("recovery history original owner changed"));
        }
    }
    Ok(())
}

/// Pure startup verification streams cold evidence; it never allocates capacity.
pub(super) fn verify_history(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let mut query = tx.prepare(
        "SELECT record_key FROM admission_operation_recovery_records WHERE kind='workflow' ORDER BY record_key",
    ).map_err(sqlite_error)?;
    for key in query
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
    {
        verify_history_workflow(tx, &key.map_err(sqlite_error)?)?;
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn resolve(
    tx: &Transaction<'_>,
    seed: &ToolCallRequest,
    profile: &RecoveryDeploymentV1,
    now: u64,
) -> Result<RecoveryOriginV1, RecoveryCommandPortError> {
    super::original_resolution::resolve_native_original(tx, seed, profile, now)
}

pub(super) fn claim(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), RecoveryCommandPortError> {
    let origin = record
        .origin
        .as_ref()
        .ok_or_else(|| invariant("recovery original evidence is absent"))?;
    let key = claim_key(origin)?;
    let claim = OriginClaim {
        scope: record.scope.clone(),
        workflow_id: record.workflow_id.clone(),
        continuation_id: record.continuation_id.clone(),
        origin: origin.clone(),
    };
    if let Some(existing) = raw(tx, &key)? {
        let retained: OriginClaim = decode(&existing.payload)?;
        return if existing.version == 1 && retained == claim {
            Ok(())
        } else {
            Err(RecoveryCommandPortError::Conflict)
        };
    }
    require_linked_history(tx)?;
    save(
        tx,
        owner,
        &key,
        &scope_key(&record.scope)?,
        "command",
        &encode(&claim)?,
        None,
    )?;
    Ok(())
}

pub(super) fn verify(
    tx: &Transaction<'_>,
    record: &RecoveryWorkflowRecordV1,
    profile: &RecoveryDeploymentV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let origin = record
        .origin
        .as_ref()
        .ok_or_else(|| invariant("recovery original evidence is absent"))?;
    let seed: ToolCallRequest =
        chio_core_types::recovery::decode_contract(record.creation_seed.as_str().as_bytes())
            .map_err(|_| invariant("recovery original seed refused"))?;
    super::original_resolution::revalidate(tx, &seed, profile, now, origin)?;
    if record
        .action
        .as_ref()
        .is_some_and(|action| action.origin.as_ref() != Some(origin))
    {
        return Err(invariant("recovery original binding changed"));
    }
    // Fresh validators also receive an owning producer's prospective clone
    // before its next mutation. Authorize the authenticated physical owner,
    // then bind the clone's immutable creation identity to that source.
    let physical = workflow_tx(tx, &record.scope, &record.workflow_id)?;
    if physical.scope != record.scope
        || physical.workflow_id != record.workflow_id
        || physical.step_id != record.step_id
        || physical.continuation_id != record.continuation_id
        || physical.created_by != record.created_by
        || physical.creation_seed != record.creation_seed
        || physical.origin != record.origin
        || physical.deployment_digest != record.deployment_digest
        || physical.effect_cardinality != record.effect_cardinality
    {
        return Err(invariant(
            "recovery prospective progress changed its immutable original owner",
        ));
    }
    require_current_original_owner(tx, &physical)
}
