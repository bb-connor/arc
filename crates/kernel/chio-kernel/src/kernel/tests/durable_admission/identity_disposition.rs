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
fn conflicting_begin_keeps_the_original_identity_terminal() {
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
    drop(admission);
    request.arguments["value"] = serde_json::json!("changed");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("request id conflicts with retained operation")));
    assert_eq!(store.operation(), original);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_disposition(&response, "terminal");
}
