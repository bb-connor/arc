//! Accept source-generation changes only from this original call's proven
//! preflight/input journals. Equal label bytes alone are not sufficient.
use super::*;
use chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1;
use chio_security_types::ports::FlowStateSnapshot;
use chio_security_types::InformationLabel;

pub(in crate::admission_operation_store) fn prove_recovery_source_history(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    operation: &AdmissionOperationId,
    original: &FlowStateSnapshot,
    current: &FlowStateSnapshot,
    source: &InformationLabel,
) -> Result<bool, AdmissionOperationStoreError> {
    let initialized = records::load_metadata(tx, binding.security_authority_id().as_str())?
        .ok_or_else(|| invalid("recovery source initialization is absent"))?;
    if initialized.admission_binding()? != *binding {
        return Err(invalid("recovery source authority changed"));
    }
    let mut expected = original.clone();
    if let Some(preflight) = nonce_preflight::load_operation(tx, operation)? {
        preflight.validate(tx)?;
        if preflight.authority != initialized.authority
            || preflight.initialization != initialized.digest
            || preflight.context.as_v1().flow_state_generation()
                != Some(expected.context_generation)
            || preflight.result.key != expected.key
            || preflight.request.principal_join != *source
            || preflight.request.lineage_join != *source
            || preflight.request.session_join != *source
        {
            return Ok(false);
        }
        expected = preflight.result;
    }
    if let Some(dispatch) = history::load_for_operation(tx, operation)? {
        dispatch.validate(tx)?;
        if dispatch.authority != initialized.authority
            || dispatch.initialization != initialized.digest
            || dispatch.input.is_none()
            || dispatch.context.as_v1().flow_state_generation() != Some(expected.context_generation)
            || dispatch.result.key != expected.key
            || dispatch.request.principal_join != *source
            || dispatch.request.lineage_join != *source
            || dispatch.request.session_join != *source
        {
            return Ok(false);
        }
        expected = dispatch.result;
    }
    Ok(expected == *current)
}

/// First input proves the actual framed snapshot or this operation's exact
/// authenticated nonce-preflight changes. It never fabricates input history.
pub(in crate::admission_operation_store) fn prove_semantic_before_input_source_history(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    operation: &AdmissionOperationId,
    original: &FlowStateSnapshot,
    current: &FlowStateSnapshot,
) -> Result<bool, AdmissionOperationStoreError> {
    prove_semantic_owned_source_history(tx, binding, operation, original, current, false)
}

/// Capture retains mandatory owned input history, independently of the nonce
/// preflight delta. Both journals bind exact immutable predecessor images.
pub(in crate::admission_operation_store) fn prove_semantic_source_history(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    operation: &AdmissionOperationId,
    original: &FlowStateSnapshot,
    current: &FlowStateSnapshot,
) -> Result<bool, AdmissionOperationStoreError> {
    prove_semantic_owned_source_history(tx, binding, operation, original, current, true)
}

fn prove_semantic_owned_source_history(
    tx: &Connection,
    binding: &NativeSecurityAuthorityBindingV1,
    operation: &AdmissionOperationId,
    original: &FlowStateSnapshot,
    current: &FlowStateSnapshot,
    input_required: bool,
) -> Result<bool, AdmissionOperationStoreError> {
    let initialized = records::load_metadata(tx, binding.security_authority_id().as_str())?
        .ok_or_else(|| invalid("semantic source initialization is absent"))?;
    if initialized.admission_binding()? != *binding {
        return Err(invalid("semantic source authority changed"));
    }
    let mut expected = original.clone();
    if let Some(preflight) = nonce_preflight::load_operation(tx, operation)? {
        preflight.validate(tx)?;
        let retained_operation = AdmissionOperationV1::from_persisted(preflight.operation.clone())?;
        if retained_operation.binding().operation_id() != operation
            || preflight.authority != initialized.authority
            || preflight.initialization != initialized.digest
            || preflight.context.as_v1().flow_state_generation()
                != Some(expected.context_generation)
            || preflight.result.key != expected.key
        {
            return Ok(false);
        }
        let before =
            crate::security_state::NativeRowChange::predecessor_snapshot_for_native_flow_join(
                &preflight.request,
                &preflight.result,
                preflight.changes.as_slice(),
            )
            .map_err(invalid)?;
        if before != expected {
            return Ok(false);
        }
        expected = preflight.result;
    }
    let dispatch = history::load_for_operation(tx, operation)?;
    if input_required {
        let dispatch = dispatch.ok_or_else(|| invalid("semantic capture lacks input history"))?;
        dispatch.validate(tx)?;
        let retained_operation = AdmissionOperationV1::from_persisted(dispatch.operation.clone())?;
        if retained_operation.binding().operation_id() != operation
            || dispatch.authority != initialized.authority
            || dispatch.initialization != initialized.digest
            || dispatch.input.is_none()
            || dispatch.context.as_v1().flow_state_generation() != Some(expected.context_generation)
            || dispatch.result.key != expected.key
        {
            return Ok(false);
        }
        let before =
            crate::security_state::NativeRowChange::predecessor_snapshot_for_native_flow_join(
                &dispatch.request,
                &dispatch.result,
                dispatch.changes.as_slice(),
            )
            .map_err(invalid)?;
        if before != expected {
            return Ok(false);
        }
        expected = dispatch.result;
    } else if dispatch.is_some() {
        // The physical input owner answers exact input replay before this fresh
        // first-input verifier. Existing history cannot mint another first join.
        return Ok(false);
    }
    Ok(expected == *current)
}
