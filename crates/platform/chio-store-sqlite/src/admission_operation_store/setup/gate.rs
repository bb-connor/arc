//! Owning gates compare retained readiness with the actual native transaction.
use super::*;

pub(in crate::admission_operation_store) fn require_ready(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    if let Some(value) = load(tx, scope)? {
        if value.probe.scope != *scope {
            return Err(refused("unqualified scope"));
        }
        ready(tx, &value, fence)?;
    } else if protected::deployment_tx(tx, scope)?.setup_policy.is_some()
        || context::tenant_required(tx, scope)?
    {
        return Err(AdmissionOperationStoreError::RecoveryMediationRequired);
    }
    Ok(())
}
pub(in crate::admission_operation_store) fn require_command(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    fence: &StoreMutationFence,
    command: &RecoveryCommandV1,
) -> Result<(), AdmissionOperationStoreError> {
    let scope = actor.scope();
    let body = &command.command;
    if matches!(
        body,
        RecoveryCommandBodyV1::InspectWorkflow { .. }
            | RecoveryCommandBodyV1::CancelWorkflow { .. }
            | RecoveryCommandBodyV1::ReportDecision { .. }
    ) {
        return Ok(());
    }
    let Some(value) = load(tx, scope)? else {
        if protected::deployment_tx(tx, scope)?.setup_policy.is_some()
            || context::tenant_required(tx, scope)?
        {
            return Err(AdmissionOperationStoreError::RecoveryMediationRequired);
        }
        return Ok(());
    };
    if let RecoveryCommandBodyV1::ResumeWorkflow { workflow_id, .. } = body {
        let record = protected::workflow_tx(tx, scope, workflow_id)?;
        if let Some(id) = &record.native_link {
            let operation =
                load_by_operation_id_tx(tx, &AdmissionOperationId::from_persisted(id.as_str())?)?
                    .ok_or_else(|| refused("lost original operation"))?;
            if record.captured && operation.operation.state() == AdmissionOperationState::Completed
            {
                return Ok(());
            }
        }
    }
    if ready(tx, &value, fence).is_ok() && value.probe.scope == *scope {
        return Ok(());
    }
    current(tx, &value)?;
    pending_window(&value, fence, schema::observe_authority_time(tx)?)?;
    let id = match body {
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key,
            request_seed,
            ..
        } => {
            let id = WorkflowId::new(&format!(
                "workflow:{}",
                sha256_hex(&protected::encode(&(scope, creation_key))?)
            ))
            .map_err(refused)?;
            let seed: ToolCallRequest =
                chio_core::recovery::decode_contract(request_seed.as_str().as_bytes())
                    .map_err(refused)?;
            let recovery = protected::deployment_tx(tx, scope)?;
            let origin = super::super::recovery::origins::resolve(
                tx,
                &seed,
                &recovery,
                schema::observe_authority_time(tx)?,
            )
            .map_err(original_custody_error)?;
            if CanonicalPayloadDigest::from_bytes(digest(
                RecoveryDigestDomain::SetupCreation,
                &(request_seed, &origin),
            )?) != value.creation
            {
                return Err(AdmissionOperationStoreError::RecoveryMediationRequired);
            }
            id
        }
        RecoveryCommandBodyV1::SelectOffer { workflow_id, .. }
        | RecoveryCommandBodyV1::SubmitApproval { workflow_id, .. }
        | RecoveryCommandBodyV1::ResumeWorkflow { workflow_id, .. } => workflow_id.clone(),
        _ => return Ok(()),
    };
    if value.probe.scope != *scope || id != value.probe.benign_workflow {
        return Err(AdmissionOperationStoreError::RecoveryMediationRequired);
    }
    if matches!(body, RecoveryCommandBodyV1::ResumeWorkflow { .. }) {
        let record = protected::workflow_tx(tx, scope, &id)?;
        if actor.principal() != &record.created_by
            || !value.command_bound
            || protected::encode(command)? != protected::encode(&value.command)?
        {
            return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
        }
    }
    Ok(())
}
pub(in crate::admission_operation_store) fn require_capture(
    tx: &Connection,
    owner: &SqliteServingOwner,
    operation: &AdmissionOperationV1,
    context: &SecurityInvocationContext,
    native: &chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1,
    now: u64,
) -> Result<Option<u64>, AdmissionOperationStoreError> {
    let Some(scope) = context::capture_scope(tx, owner, context, native)? else {
        return Ok(None);
    };
    let Some(value) = load(tx, &scope)? else {
        return Err(AdmissionOperationStoreError::RecoveryMediationRequired);
    };
    current(tx, &value)?;
    let deployment = protected::deployment_tx(tx, &value.probe.scope)?;
    // Physical capture observes a joined flow generation, while the selected
    // process identity intentionally does not carry that transient generation.
    if native != &deployment.native_authority
        || context.as_v1().tenant_id() != deployment.security_context.as_v1().tenant_id()
        || context.as_v1().session_id() != deployment.security_context.as_v1().session_id()
        || context.as_v1().principal_id() != deployment.security_context.as_v1().principal_id()
        || context.as_v1().lineage_root_id()
            != deployment.security_context.as_v1().lineage_root_id()
        || context.as_v1().isolation_epoch_id()
            != deployment.security_context.as_v1().isolation_epoch_id()
        || context.as_v1().context_generation()
            != deployment.security_context.as_v1().context_generation()
    {
        return Err(refused("capture scope"));
    }
    if ready(tx, &value, &owner.fence).is_ok() {
        return Ok(None);
    }
    let valid_until = pending_window(&value, &owner.fence, now)?;
    let record = super::recovery::native::located(tx, operation.binding())?
        .ok_or_else(|| refused("unselected setup capture"))?;
    if record.scope != value.probe.scope
        || record.workflow_id != value.probe.benign_workflow
        || creation(&record)? != value.creation
        || record.captured
    {
        return Err(refused("unselected setup capture"));
    }
    Ok(Some(valid_until))
}

// Readiness may be re-attested from authenticated completion, but a pending
// self-test can acquire its first effect only in the selected writer's window.
fn pending_window(
    value: &Selection,
    fence: &StoreMutationFence,
    now: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    let valid_until = value.probe.expires_at_unix_ms.get();
    if now >= valid_until || fence_digest(fence)? != value.previous_fence {
        return Err(AdmissionOperationStoreError::RecoveryMediationRequired);
    }
    Ok(valid_until)
}
