use super::*;
use crate::admission_operation::{
    AdmissionCompensationStatus, AdmissionReceiptMetadataV1, ADMISSION_RECEIPT_METADATA_KEY,
};

pub(super) fn url_elicitation_after_dispatch() -> chio_core::receipt::decision::Decision {
    chio_core::receipt::decision::Decision::Cancelled {
        reason: "tool server returned URL elicitation after dispatch; outcome is unknown".into(),
    }
}

pub(super) fn unknown_after(step: &str, code: &str) -> chio_core::receipt::decision::Decision {
    chio_core::receipt::decision::Decision::Deny {
        reason: format!("dispatch outcome is unknown after {step}: {code}"),
        guard: "kernel".into(),
    }
}

pub(super) fn assert_original_unknown_incident(
    store: &TestAdmissionOperationStore,
    request: &ToolCallRequest,
    decision: &chio_core::receipt::decision::Decision,
) -> AdmissionOperationV1 {
    let operation = store.operation();
    operation
        .validate()
        .expect("authoritative unknown outcome is well bound");
    assert_eq!(
        operation.state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert_eq!(
        operation.binding().request_id().as_str(),
        request.request_id
    );
    assert_eq!(
        operation.binding().capability_id().as_str(),
        request.capability.id
    );
    let receipt = store
        .state
        .lock()
        .expect("admission state")
        .receipt
        .clone()
        .expect("the original saga persists its terminal refusal");
    assert_eq!(receipt.tool_server, request.server_id);
    assert_eq!(receipt.tool_name, request.tool_name);
    assert_eq!(receipt.action.parameters, request.arguments);
    assert_eq!(receipt.decision.as_ref(), Some(decision));
    assert_unknown_receipt(&receipt, &operation);
    operation
}

fn assert_unknown_receipt(
    receipt: &ChioReceipt,
    operation: &AdmissionOperationV1,
) -> AdmissionReceiptMetadataV1 {
    let Some(AdmissionTerminalReplay::Receipt {
        receipt_id,
        projection_digest,
    }) = operation.terminal_replay()
    else {
        panic!("the original saga must own the unknown-outcome receipt");
    };
    assert_eq!(receipt.id, receipt_id.as_str());
    assert_eq!(projection_digest.as_str().len(), 64);
    assert!(receipt.verify_integrity_embedded_key().expect("valid receipt signature"));
    assert_eq!(
        receipt.capability_id,
        operation.binding().capability_id().as_str()
    );
    assert_eq!(
        receipt.policy_hash,
        operation.binding().policy_hash().as_str()
    );
    assert_eq!(
        receipt.action.parameter_hash,
        operation.binding().action_parameter_hash().as_str()
    );
    assert!(receipt.action.verify_hash().expect("valid action digest"));
    assert_eq!(receipt.content_hash, sha256_hex(b"null"));
    let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
        receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get(ADMISSION_RECEIPT_METADATA_KEY))
            .cloned()
            .expect("signed admission metadata"),
    )
    .expect("typed signed admission metadata");
    assert_eq!(&metadata.operation_id, operation.binding().operation_id());
    assert_eq!(&metadata.request_id, operation.binding().request_id());
    assert_eq!(
        &metadata.request_namespace_digest,
        operation.binding().request_namespace_digest()
    );
    assert_eq!(
        &metadata.request_binding_hash,
        operation.binding().request_binding_hash()
    );
    assert_eq!(metadata.projected_operation_version, operation.version());
    assert_eq!(metadata.projected_state, operation.state());
    assert_eq!(
        metadata.projected_dispatch_state,
        operation.dispatch_state()
    );
    assert_eq!(
        metadata.retained_dispatch_commit.as_ref(),
        operation.dispatch_commit()
    );
    assert!(metadata.retained_dispatch_commit.is_some());
    assert_eq!(
        metadata.compensation_status,
        AdmissionCompensationStatus::NotCompensated
    );
    assert_eq!(metadata.tool_outcome_id, None);
    assert_eq!(metadata.tool_outcome_version, None);
    assert!(metadata.trusted_time_unix_ms > 0);
    assert_eq!(receipt.timestamp, metadata.trusted_time_unix_ms / 1_000);
    metadata
}

pub(super) fn assert_unknown_replay(
    result: Result<ToolCallResponse, KernelError>,
    operation: &AdmissionOperationV1,
    store: &TestAdmissionOperationStore,
) -> AdmissionReceiptMetadataV1 {
    let response = result.expect("retained unknown outcome replays its original refusal");
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.request_id,
        operation.binding().request_id().as_str()
    );
    assert_eq!(response.output, None);
    assert!(response.execution_nonce.is_none());
    let receipt = store
        .state
        .lock()
        .expect("admission state")
        .receipt
        .clone()
        .expect("persisted original terminal receipt");
    assert_same_receipt(&response.receipt, &receipt);
    let Some(
        chio_core::receipt::decision::Decision::Deny { reason, .. }
        | chio_core::receipt::decision::Decision::Cancelled { reason },
    ) = &receipt.decision
    else {
        panic!("the original receipt must refuse output");
    };
    assert_eq!(response.reason.as_deref(), Some(reason.as_str()));
    assert_unknown_receipt(&response.receipt, operation)
}
