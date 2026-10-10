//! Authenticated workflow previews coarsen genuine absence and hidden state.
use super::*;
use chio_security_types::flow::InformationLabel;

/// Read only authenticated custody. A lost retained workflow remains an
/// invariant failure from workflow_tx; only genuine absence is coarsened.
pub(in crate::admission_operation_store) fn workflow_preview_tx(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &RecoveryDeploymentV1,
    id: &WorkflowId,
) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
    let record = workflow_tx(tx, actor.scope(), id).map_err(|error| match error {
        AdmissionOperationStoreError::NotFound => {
            AdmissionOperationStoreError::RecoveryAuthorityDenied
        }
        error => error,
    })?;
    verify_preview(actor, profile, &record)?;
    let clearance = profile
        .actors
        .as_slice()
        .iter()
        .find(|assignment| assignment.principal == *actor.principal())
        .ok_or(AdmissionOperationStoreError::RecoveryAuthorityDenied)?;
    let (current, _) = crate::security_state::observe_native_flow_state(
        tx,
        profile.native_authority.security_authority_id().as_str(),
        &recovery_flow_key(&profile.security_context),
    )
    .map_err(|_| invariant("recovery current preview source unavailable"))?;
    let current = current.ok_or_else(|| invariant("recovery current preview source absent"))?;
    let mut source = record
        .action
        .as_ref()
        .map(|action| action.authorization_requirements.source_label.clone())
        .unwrap_or_else(InformationLabel::bottom);
    // Current inherited taint cannot erase the action's original source, and
    // a rotated live scope cannot erase its retained framed restriction.
    for snapshot in std::iter::once(&current).chain(record.original_flow.iter()) {
        source = source
            .join_restrictions(&snapshot.principal_label)
            .and_then(|source| source.join_restrictions(&snapshot.lineage_label))
            .and_then(|source| source.join_restrictions(&snapshot.session_label))
            .map_err(|_| invariant("recovery preview source labels refused"))?;
    }
    if matches!(source, InformationLabel::Top) || !source.flows_to(&clearance.preview_clearance) {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    Ok(record)
}
