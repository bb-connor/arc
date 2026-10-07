//! Observe real ordinary monetary operations without retaining or issuing authority.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationId, AdmissionOperationV1, AdmissionRecoveryError,
    AdmissionRecoveryFailureKind, AdmissionReplayKey, LOCAL_SYSTEM_TENANT_ID,
};

pub(super) fn from_signed_response(
    operations: &chio_store_sqlite::SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    request: &ToolCallRequest,
    response: &ToolCallResponse,
) -> Result<AdmissionOperationV1, Box<dyn Error>> {
    assert!(response.receipt.verify_signature()?);
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.receipt.capability_id, request.capability.id);
    let value = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get(ADMISSION_RECEIPT_METADATA_KEY))
        .cloned()
        .ok_or("original signed admission metadata")?;
    let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(value)?;
    assert_eq!(metadata.store_fence, *fence);
    let replay_key = AdmissionReplayKey {
        request_namespace_digest: metadata.request_namespace_digest.clone(),
        request_id: metadata.request_id.clone(),
    };
    let operation = operations
        .load_by_replay_key(&replay_key)?
        .ok_or("original authoritative replay key")?;
    assert_eq!(operation.binding().operation_id(), &metadata.operation_id);
    assert_eq!(operation.replay_key(), replay_key);
    assert_eq!(
        operation.binding().request_binding_hash(),
        &metadata.request_binding_hash
    );
    assert_eq!(operation.version(), metadata.projected_operation_version);
    assert_eq!(operation.state(), metadata.projected_state);
    verify_original_binding(operations, fence, request, &operation)?;
    Ok(operation)
}

pub(super) fn from_retained_payment_response(
    operations: &chio_store_sqlite::SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    request: &ToolCallRequest,
    response: &ToolCallResponse,
    reference: &str,
) -> Result<AdmissionOperationV1, Box<dyn Error>> {
    assert!(response.receipt.verify_signature()?);
    assert_eq!(response.receipt.kernel_key, request.capability.issuer);
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.receipt.capability_id, request.capability.id);
    assert_eq!(response.receipt.tool_server, request.server_id);
    assert_eq!(response.receipt.tool_name, request.tool_name);
    let operation = from_rail_reference(operations, fence, request, reference)?;
    let journal = operations
        .load_payment_journal(operation.binding().operation_id().as_str(), fence)?
        .ok_or("original retained authorization journal")?;
    let authorization_id = journal
        .authorization_id
        .as_deref()
        .ok_or("original retained authorization ID")?;
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or("original signed retained-payment metadata")?;
    assert_eq!(
        metadata
            .get("receipt_context")
            .and_then(|context| context.get("request_id"))
            .and_then(serde_json::Value::as_str),
        Some(request.request_id.as_str())
    );
    let financial = metadata
        .get("financial")
        .ok_or("original signed financial reference")?;
    assert_eq!(
        financial
            .get("payment_reference")
            .and_then(serde_json::Value::as_str),
        Some(authorization_id)
    );
    assert_eq!(
        financial
            .get("payment_authorization_retained")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    Ok(operation)
}

pub(super) fn from_rail_reference(
    operations: &chio_store_sqlite::SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    request: &ToolCallRequest,
    reference: &str,
) -> Result<AdmissionOperationV1, Box<dyn Error>> {
    // This checked reference is actual adapter-call data, never authority.
    let operation_id = AdmissionOperationId::from_persisted(reference)?;
    let operation = operations
        .load_by_operation_id(&operation_id)?
        .ok_or("original authoritative rail operation")?;
    assert_eq!(operation.binding().operation_id(), &operation_id);
    verify_original_binding(operations, fence, request, &operation)?;
    Ok(operation)
}

fn verify_original_binding(
    operations: &chio_store_sqlite::SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    request: &ToolCallRequest,
    operation: &AdmissionOperationV1,
) -> Result<(), Box<dyn Error>> {
    operation.validate()?;
    let binding = operation.binding();
    assert_eq!(binding.request_id().as_str(), request.request_id);
    assert_eq!(binding.capability_id().as_str(), request.capability.id);
    assert_eq!(
        binding.coordinator_authority_id().as_str(),
        fence.store_uuid
    );
    assert_eq!(
        binding.to_persisted().authenticated_tenant_id.as_str(),
        LOCAL_SYSTEM_TENANT_ID
    );
    let journal = operations
        .load_payment_journal(binding.operation_id().as_str(), fence)?
        .ok_or("original fenced payment journal")?;
    assert_eq!(journal.operation_id, binding.operation_id().as_str());
    assert_eq!(journal.request_id, request.request_id);
    assert_eq!(journal.capability_id, request.capability.id);
    assert_eq!(
        journal.request_namespace_digest,
        binding.request_namespace_digest().as_str()
    );
    Ok(())
}

pub(super) fn assert_interrupted_payment(
    error: &KernelError,
    expected_message: &str,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(error.report().code, "CHIO-KERNEL-DURABLE-ADMISSION");
    let KernelError::AdmissionRecovery(retained) = error else {
        return Err("expected the original typed payment recovery error".into());
    };
    let source = error.source().ok_or("original recovery cause")?;
    let cause = source
        .downcast_ref::<Box<AdmissionRecoveryError>>()
        .ok_or("original boxed recovery error type")?;
    assert!(std::ptr::eq(cause, retained));
    assert!(matches!(
        cause.as_ref(),
        AdmissionRecoveryError::Payment {
            kind: AdmissionRecoveryFailureKind::ParticipantUnavailable,
            source: PaymentError::Unavailable(detail),
        } if detail == expected_message
    ));
    let AdmissionRecoveryError::Payment {
        source: original, ..
    } = cause.as_ref()
    else {
        return Err("expected the original payment participant cause".into());
    };
    let native_source = source.source().ok_or("original payment error layer")?;
    let payment = native_source
        .downcast_ref::<PaymentError>()
        .ok_or("original native payment error type")?;
    assert!(std::ptr::eq(payment, original));
    assert!(matches!(payment,
        PaymentError::Unavailable(detail) if detail == expected_message));
    assert!(native_source.source().is_none());
    Ok(())
}
