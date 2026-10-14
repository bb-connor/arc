//! A selected denial joins the signed native witness to exact physical custody.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionCompensationStatus, AdmissionOperationKind, AdmissionProjectionContext,
    AdmissionReceiptMetadataV1, AdmissionReceiptSchema, AdmissionTerminalReplay,
    ADMISSION_RECEIPT_METADATA_KEY,
};

// Read only the context of an already authenticated, canonical native terminal
// projection. Its proof and incident were independently verified by the owning
// projection loader, and are never decoded into a live execution authority.
#[derive(Deserialize)]
struct RetainedCompensationContext {
    context: AdmissionProjectionContext,
}

pub(super) fn verify_denied_counterpart(
    tx: &Transaction<'_>,
    value: &Selection,
    profile: &RecoveryDeploymentV1,
    request: &ToolCallRequest,
    receipt: &ChioReceipt,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let record = protected::workflow_tx(tx, &value.probe.scope, &value.probe.benign_workflow)?;
    let benign = record
        .native_link
        .as_ref()
        .ok_or_else(|| refused("benign custody absent"))?;
    let benign =
        load_by_operation_id_tx(tx, &AdmissionOperationId::from_persisted(benign.as_str())?)?
            .ok_or_else(|| refused("benign native custody absent"))?;
    if !record.captured || benign.operation.state() != AdmissionOperationState::Completed {
        return Err(refused("benign native completion absent"));
    }
    let mut expected = record.seed;
    expected.request_id = value.probe.denied_command.as_str().to_owned();
    expected.declassification_grant = None;
    expected.execution_nonce = None;
    if protected::encode(request)? != protected::encode(&expected)?
        || receipt.kernel_key != value.receipt_key
        || !receipt.is_denied()
        || !receipt.verify_signature().map_err(refused)?
        || !receipt.action.verify_hash().map_err(refused)?
        || receipt.action.parameters != request.arguments
        || receipt.capability_id != expected.capability.id
        || receipt.tool_server != expected.server_id
        || receipt.tool_name != expected.tool_name
        || !receipt.evidence.iter().any(|guard| {
            guard.guard_name == "native-flow-resolver"
                && !guard.verdict
                && guard.details.as_deref() == Some("policy_flow_violation")
        })
    {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    let metadata = receipt
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|object| object.get(ADMISSION_RECEIPT_METADATA_KEY))
        .ok_or(AdmissionOperationStoreError::RecoveryAuthorityDenied)?;
    let metadata: AdmissionReceiptMetadataV1 =
        chio_core::recovery::decode_contract(&protected::encode(metadata)?)
            .map_err(|_| AdmissionOperationStoreError::RecoveryAuthorityDenied)?;
    let stored = load_by_operation_id_tx(tx, &metadata.operation_id)?
        .ok_or_else(|| refused("denied native operation absent"))?;
    stored.verify_decision_time(now)?;
    let operation = &stored.operation;
    if metadata.schema != AdmissionReceiptSchema::V1
        || operation.binding().kind() != AdmissionOperationKind::ToolDispatch
        || operation.state() != AdmissionOperationState::CompensatedBeforeDispatch
        || operation.dispatch_commit().is_some()
        || !matches!(
            operation.terminal_replay(),
            Some(AdmissionTerminalReplay::Incident { .. })
        )
        || operation.binding().operation_id() == benign.operation.binding().operation_id()
        || operation.binding().request_namespace_digest()
            != benign.operation.binding().request_namespace_digest()
        || operation.binding().request_id().as_str() != expected.request_id
        || metadata.request_id != *operation.binding().request_id()
        || metadata.request_namespace_digest != *operation.binding().request_namespace_digest()
        || metadata.request_binding_hash != *operation.binding().request_binding_hash()
        || metadata.projected_operation_version != operation.version()
        || metadata.projected_state != operation.state()
        || metadata.projected_dispatch_state != operation.dispatch_state()
        || metadata.retained_dispatch_commit.is_some()
        || metadata.compensation_status != AdmissionCompensationStatus::CompensatedBeforeDispatch
        || metadata.tool_outcome_id.is_some()
        || metadata.tool_outcome_version.is_some()
        || receipt.action.parameter_hash != operation.binding().action_parameter_hash().as_str()
        || receipt.policy_hash != operation.binding().policy_hash().as_str()
    {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    let retained = super::super::retained_request::load_retained_request_tx(tx, operation)?
        .ok_or_else(|| refused("denied original request custody absent"))?;
    retained.validate_request_material(request)?;
    retained.validate_native_security_context(&profile.security_context)?;
    retained.validate_native_security_authority(&profile.native_authority)?;
    super::super::projection::verify_stored_terminal_projection(tx, &stored)?;
    let raw: Vec<u8> = tx.query_row(
        "SELECT projection_json FROM admission_operation_terminal_projections WHERE operation_id=?1",
        [operation.binding().operation_id().as_str()], |row| row.get(0),
    ).map_err(sqlite_error)?;
    let historical: RetainedCompensationContext = serde_json::from_slice(&raw).map_err(refused)?;
    let context = historical.context;
    context.validate()?;
    if context.operation_id != *operation.binding().operation_id()
        || context.request_id != *operation.binding().request_id()
        || context.expected_operation_version.checked_add(1) != Some(operation.version())
        || metadata.trusted_time_unix_ms != context.trusted_time_unix_ms
        || metadata.coordinator_lease_id != context.coordinator_lease_id
        || metadata.coordinator_lease_epoch != context.coordinator_lease_epoch
        || metadata.store_fence != context.store_fence
        || metadata.trusted_time_unix_ms != stored.updated_at_unix_ms
        || receipt.timestamp != context.trusted_time_unix_ms / 1_000
        || fence_digest(&context.store_fence)? != value.previous_fence
    {
        return Err(refused("denied terminal context refused"));
    }
    Ok(())
}
