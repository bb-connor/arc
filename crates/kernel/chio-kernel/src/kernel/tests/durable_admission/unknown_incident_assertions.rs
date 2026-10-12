use super::*;

pub(super) fn assert_original_unknown_incident(
    store: &TestAdmissionOperationStore,
    request: &ToolCallRequest,
) -> AdmissionOperationV1 {
    let operation = store.operation();
    operation
        .validate()
        .expect("authoritative original incident is well bound");
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
    assert!(
        operation.dispatch_commit().is_some(),
        "incident must retain its original dispatch binding"
    );
    let Some(AdmissionTerminalReplay::Incident {
        incident_id,
        projection_digest,
    }) = operation.terminal_replay()
    else {
        panic!("the original saga must own the unknown-outcome incident");
    };
    assert!(!incident_id.as_str().is_empty());
    assert_eq!(projection_digest.as_str().len(), 64);
    assert!(
        store
            .state
            .lock()
            .expect("admission state")
            .receipt
            .is_none(),
        "an incident must not invent a completed receipt"
    );
    operation
}

/// A retained incident may be observed but cannot mint another terminal receipt.
pub(super) fn assert_unknown_replay(
    result: Result<ToolCallResponse, KernelError>,
    operation: &AdmissionOperationV1,
) -> crate::admission_operation::AdmissionReceiptMetadataV1 {
    let error = result.expect_err("retained incident must not mint another receipt");
    let KernelError::DurableAdmissionRetained(metadata) = error else {
        panic!("expected the original retained incident, got {error:?}");
    };
    let expected =
        crate::admission_operation::AdmissionReceiptMetadataV1::retained_unknown_dispatch(
            operation,
            metadata.trusted_time_unix_ms,
        )
        .expect("valid retained incident projection");
    assert_eq!(*metadata, expected);
    *metadata
}
