//! One auxiliary release slot preserves the exact captured physical workflow.
use super::*;
use crate::admission_operation_store::recovery::terminal_custody::{
    release_key, require_current_terminal_format, verify_release, CapturedWorkflowReleaseV1,
    MAX_TERMINAL_CUSTODY_BYTES,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkflowReleaseAllocation {
    pub(super) record_digest: ProjectionDigest,
}

impl WorkflowReleaseAllocation {
    fn load(
        &self,
        tx: &Connection,
        scope: &RecoveryScopeV1,
        workflow: &WorkflowId,
    ) -> Result<CapturedWorkflowReleaseV1, AdmissionOperationStoreError> {
        let key = release_key(scope, workflow)?;
        let row = raw_checked(tx, &key)?
            .ok_or_else(|| invariant("captured release allocation lost its record"))?;
        let source = source_reference(tx, &key)?;
        let native_none: bool = tx
            .query_row(
                "SELECT native_namespace IS NULL AND native_request IS NULL
                 FROM admission_operation_recovery_records WHERE record_key=?1",
                [&key],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if row.kind != "command"
            || row.version != 1
            || row.scope != scope_key(scope)?
            || row.payload.len() > MAX_TERMINAL_CUSTODY_BYTES
            || !native_none
            || source.digest() != &self.record_digest
        {
            return Err(invariant("captured release allocation changed"));
        }
        let release = decode(&row.payload)?;
        verify_release(tx, scope, workflow, &release)?;
        Ok(release)
    }

    pub(super) fn verify(
        &self,
        tx: &Connection,
        scope: &RecoveryScopeV1,
        workflow: &WorkflowId,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.load(tx, scope, workflow).map(|_| ())
    }
}

pub(super) fn require_absent_release(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<(), AdmissionOperationStoreError> {
    if raw_checked(tx, &release_key(scope, workflow)?)?.is_some() {
        return Err(invariant("captured release record lost its quota owner"));
    }
    Ok(())
}

/// Auxiliary reads require the unchanged physical record, not a derived view.
pub(in crate::admission_operation_store) fn auxiliary_captured_release(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<Option<CapturedWorkflowReleaseV1>, AdmissionOperationStoreError> {
    let quota = workflow_quota(tx, &record.scope, &record.workflow_id)?;
    let Some(allocation) = quota.native_release else {
        return Ok(None);
    };
    let key = workflow_key(&record.scope, &record.workflow_id)?;
    let physical =
        raw_checked(tx, &key)?.ok_or_else(|| invariant("captured release workflow disappeared"))?;
    source_reference(tx, &key)?;
    if physical.payload != encode(record)? {
        return Err(invariant("captured release requires the physical workflow"));
    }
    allocation
        .load(tx, &record.scope, &record.workflow_id)
        .map(Some)
}

/// The owning release verifier supplies exact native and physical custody.
/// This slot changes metadata once and spends no physical workflow allowance.
pub(in crate::admission_operation_store) fn save_auxiliary_captured_release(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &RecoveryWorkflowRecordV1,
    release: &CapturedWorkflowReleaseV1,
) -> Result<bool, AdmissionOperationStoreError> {
    require_current_terminal_format(tx)?;
    verify_release(tx, &record.scope, &record.workflow_id, release)?;
    let workflow_key = workflow_key(&record.scope, &record.workflow_id)?;
    let physical = raw_checked(tx, &workflow_key)?
        .ok_or_else(|| invariant("captured release workflow disappeared"))?;
    source_reference(tx, &workflow_key)?;
    if physical.payload != encode(record)? {
        return Err(invariant(
            "captured release requires unchanged physical custody",
        ));
    }
    let mut quota = workflow_quota(tx, &record.scope, &record.workflow_id)?;
    if quota.native_terminal.is_none() {
        return Err(invariant(
            "captured release requires its terminal allocation",
        ));
    }
    if let Some(existing) = &quota.native_release {
        if encode(&existing.load(tx, &record.scope, &record.workflow_id)?)? != encode(release)? {
            return Err(invariant("captured release custody is immutable"));
        }
        return Ok(false);
    }
    let key = release_key(&record.scope, &record.workflow_id)?;
    require_absent_release(tx, &record.scope, &record.workflow_id)?;
    let payload = encode(release)?;
    if payload.len() > MAX_TERMINAL_CUSTODY_BYTES {
        return Err(invariant("captured release metadata envelope exhausted"));
    }
    persist_record(
        tx,
        owner,
        &key,
        &scope_key(&record.scope)?,
        "command",
        &payload,
        None,
    )?;
    let source = source_reference(tx, &key)?;
    let allocation = WorkflowReleaseAllocation {
        record_digest: *source.digest(),
    };
    allocation.verify(tx, &record.scope, &record.workflow_id)?;
    quota.native_release = Some(allocation);
    save_quota(tx, owner, &quota)?;
    Ok(true)
}
