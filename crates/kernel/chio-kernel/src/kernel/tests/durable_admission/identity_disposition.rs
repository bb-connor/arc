use super::*;

fn assert_disposition(response: &ToolCallResponse, expected: &str) {
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.verify_signature().unwrap());
    assert_eq!(
        response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.pointer("/chio_runtime/identity_disposition"))
            .and_then(serde_json::Value::as_str),
        Some(expected),
    );
}

#[test]
fn unconfirmed_begin_retains_identity_without_dispatch() {
    let (kernel, request, store, invocations) = durable_admission_fixture("identity-begin-unknown");
    store.lose_next_begin_ack.store(true, Ordering::SeqCst);
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("injected begin acknowledgement loss")));
    assert_eq!(store.operation().state(), AdmissionOperationState::Prepared);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_disposition(&response, "retained");
}

#[test]
fn conflicting_begin_preserves_the_live_owner_without_a_terminal_receipt() {
    let (kernel, mut request, store, invocations) =
        durable_admission_fixture("identity-begin-conflict");
    let matching = [MatchingGrant {
        index: 0,
        grant: &request.capability.scope.grants[0],
        specificity: (0, 0, 0),
    }];
    let admission = kernel
        .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
        .unwrap()
        .unwrap();
    let original = store.operation();
    assert_eq!(
        original.state(),
        AdmissionOperationState::BrokerAttemptRegistered
    );
    request.arguments["value"] = serde_json::json!("changed");
    let error = kernel.evaluate_tool_call_blocking(&request).unwrap_err();
    assert!(error
        .to_string()
        .contains("request id conflicts with retained operation"));
    assert_eq!(admission.operation(), &original);
    assert_eq!(store.operation(), original);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn unconfirmed_broker_registration_retains_identity_without_dispatch() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("identity-broker-unknown");
    store.lose_next_command_ack.store(true, Ordering::SeqCst);
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("injected command acknowledgement loss")));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::BrokerAttemptRegistered
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_disposition(&response, "retained");
}
