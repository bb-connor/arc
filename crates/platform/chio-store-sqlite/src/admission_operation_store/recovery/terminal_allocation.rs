//! One auxiliary terminal slot preserves the exact captured physical workflow.
use super::*;
use crate::admission_operation_store::recovery::terminal_custody::{
    require_current_terminal_format, terminal_key, verify_terminal, CapturedWorkflowTerminalV1,
    MAX_TERMINAL_CUSTODY_BYTES,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkflowTerminalAllocation {
    pub(super) record_digest: ProjectionDigest,
}

impl WorkflowTerminalAllocation {
    fn load(
        &self,
        tx: &Connection,
        scope: &RecoveryScopeV1,
        workflow: &WorkflowId,
    ) -> Result<CapturedWorkflowTerminalV1, AdmissionOperationStoreError> {
        let key = terminal_key(scope, workflow)?;
        let row = raw_checked(tx, &key)?
            .ok_or_else(|| invariant("captured terminal allocation lost its record"))?;
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
            return Err(invariant("captured terminal allocation changed"));
        }
        let terminal = decode(&row.payload)?;
        verify_terminal(tx, scope, workflow, &terminal)?;
        Ok(terminal)
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

pub(super) fn require_absent_terminal(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<(), AdmissionOperationStoreError> {
    if raw_checked(tx, &terminal_key(scope, workflow)?)?.is_some() {
        return Err(invariant("captured terminal record lost its quota owner"));
    }
    Ok(())
}

/// Auxiliary reads require the unchanged physical record, not a derived view.
pub(in crate::admission_operation_store) fn auxiliary_captured_terminal(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<Option<CapturedWorkflowTerminalV1>, AdmissionOperationStoreError> {
    let quota = workflow_quota(tx, &record.scope, &record.workflow_id)?;
    let Some(allocation) = quota.native_terminal else {
        return Ok(None);
    };
    let key = workflow_key(&record.scope, &record.workflow_id)?;
    let physical = raw_checked(tx, &key)?
        .ok_or_else(|| invariant("captured terminal workflow disappeared"))?;
    source_reference(tx, &key)?;
    if physical.payload != encode(record)? {
        return Err(invariant(
            "captured terminal requires the physical workflow",
        ));
    }
    allocation
        .load(tx, &record.scope, &record.workflow_id)
        .map(Some)
}

/// The owning terminal verifier supplies exact native and physical custody.
/// This slot changes metadata once and spends no physical workflow allowance.
pub(in crate::admission_operation_store) fn save_auxiliary_captured_terminal(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &RecoveryWorkflowRecordV1,
    terminal: &CapturedWorkflowTerminalV1,
) -> Result<bool, AdmissionOperationStoreError> {
    require_current_terminal_format(tx)?;
    verify_terminal(tx, &record.scope, &record.workflow_id, terminal)?;
    let workflow_key = workflow_key(&record.scope, &record.workflow_id)?;
    let physical = raw_checked(tx, &workflow_key)?
        .ok_or_else(|| invariant("captured terminal workflow disappeared"))?;
    source_reference(tx, &workflow_key)?;
    if physical.payload != encode(record)? {
        return Err(invariant(
            "captured terminal requires unchanged physical custody",
        ));
    }
    let mut quota = workflow_quota(tx, &record.scope, &record.workflow_id)?;
    if let Some(existing) = &quota.native_terminal {
        if encode(&existing.load(tx, &record.scope, &record.workflow_id)?)? != encode(terminal)? {
            return Err(invariant("captured terminal custody is immutable"));
        }
        return super::super::active_workflows::retire_captured_terminal(
            tx, owner, record, terminal,
        );
    }
    let key = terminal_key(&record.scope, &record.workflow_id)?;
    require_absent_terminal(tx, &record.scope, &record.workflow_id)?;
    let payload = encode(terminal)?;
    if payload.len() > MAX_TERMINAL_CUSTODY_BYTES {
        return Err(invariant("captured terminal metadata envelope exhausted"));
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
    let allocation = WorkflowTerminalAllocation {
        record_digest: *source.digest(),
    };
    allocation.verify(tx, &record.scope, &record.workflow_id)?;
    quota.native_terminal = Some(allocation);
    save_quota(tx, owner, &quota)?;
    super::super::active_workflows::retire_captured_terminal(tx, owner, record, terminal)?;
    Ok(true)
}
