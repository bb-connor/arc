use super::*;
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
};
use chio_kernel::admission_operation::{
    AdmissionCompensationStatus, AdmissionDispatchState, AdmissionReceiptMetadataV1,
    AdmissionReceiptSchema, VerifiedAdmissionReceipt, ADMISSION_RECEIPT_METADATA_KEY,
    LOCAL_SYSTEM_TENANT_ID,
};

pub(crate) fn refusal_receipt(
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    state: AdmissionOperationState,
    signer: &Keypair,
    parameters: &serde_json::Value,
) -> Result<VerifiedAdmissionReceipt, Box<dyn Error>> {
    let compensation = match state {
        AdmissionOperationState::CompensatedBeforeDispatch => {
            AdmissionCompensationStatus::CompensatedBeforeDispatch
        }
        AdmissionOperationState::OutcomeUnknownAfterDispatch => {
            AdmissionCompensationStatus::NotCompensated
        }
        _ => return Err("unsupported refusal terminal".into()),
    };
    let metadata = AdmissionReceiptMetadataV1 {
        schema: AdmissionReceiptSchema::V1,
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.binding().request_id().clone(),
        request_namespace_digest: operation.binding().request_namespace_digest().clone(),
        request_binding_hash: operation.binding().request_binding_hash().clone(),
        projected_operation_version: operation.version() + 1,
        projected_state: state,
        projected_dispatch_state: AdmissionDispatchState::Terminal,
        trusted_time_unix_ms: context.trusted_time_unix_ms,
        coordinator_lease_id: context.coordinator_lease_id.clone(),
        coordinator_lease_epoch: context.coordinator_lease_epoch,
        store_fence: context.store_fence.clone(),
        retained_dispatch_commit: operation.dispatch_commit().cloned(),
        compensation_status: compensation,
        tool_outcome_id: None,
        tool_outcome_version: None,
    };
    let decision = Decision::Deny {
        reason: "operation refused".to_owned(),
        guard: "kernel".to_owned(),
    };
    let content = AdmissionDigest::try_new("content", sha256_hex(b"null"))?;
    let tenant = operation.to_persisted().binding.authenticated_tenant_id;
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "terminal-refusal".to_owned(),
            timestamp: context.trusted_time_unix_ms / 1_000,
            capability_id: operation.binding().capability_id().as_str().to_owned(),
            tool_server: "server".to_owned(),
            tool_name: "tool".to_owned(),
            action: ToolCallAction::from_parameters(parameters.clone())?,
            decision: Some(decision.clone()),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: content.as_str().to_owned(),
            policy_hash: operation.binding().policy_hash().as_str().to_owned(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({ADMISSION_RECEIPT_METADATA_KEY: metadata})),
            trust_level: Default::default(),
            tenant_id: (tenant.as_str() != LOCAL_SYSTEM_TENANT_ID)
                .then(|| tenant.as_str().to_owned()),
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
        },
        signer,
    )?;
    Ok(VerifiedAdmissionReceipt::from_kernel_verified_for_test(
        receipt,
        &signer.public_key(),
        &decision,
        "server",
        "tool",
        operation.binding().action_parameter_hash(),
        &content,
        operation,
        context,
        state,
        compensation,
        None,
    )?)
}
