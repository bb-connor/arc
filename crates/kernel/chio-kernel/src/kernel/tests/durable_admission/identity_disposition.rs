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

#[test]
fn early_refusal_reuses_only_an_unoccupied_request_identity() {
    for occupied in [false, true] {
        let (kernel, mut request, store, invocations) =
            durable_admission_fixture("early-refusal-identity");
        let admission = if occupied {
            let matching = [MatchingGrant {
                index: 0,
                grant: &request.capability.scope.grants[0],
                specificity: (0, 0, 0),
            }];
            kernel
                .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
                .unwrap()
        } else {
            None
        };
        let original = admission
            .as_ref()
            .map(|admission| admission.operation().clone());
        let receipts = kernel.receipt_log().len();
        request.server_id = "unavailable-server".into();
        let result = kernel.evaluate_tool_call_blocking(&request);
        if let Some(original) = original {
            let error = result.expect_err("occupied identity cannot be advertised as reusable");
            assert!(
                matches!(
                    error,
                    KernelError::DurableAdmission(_) | KernelError::OperationConflict { .. }
                ),
                "{error:?}"
            );
            assert_eq!(store.operation(), original);
            assert_eq!(kernel.receipt_log().len(), receipts);
        } else {
            assert_disposition(&result.expect("unoccupied early refusal"), "reusable");
            assert!(!store.has_operation());
        }
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn unavailable_replay_lookup_cannot_attest_reusable_identity() {
    let (kernel, mut request, store, invocations) =
        durable_admission_fixture("early-refusal-unavailable-identity");
    request.server_id = "unavailable-server".into();
    store.fail_next_replay_read.store(true, Ordering::SeqCst);
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("failed identity read must not attest absence");
    assert!(
        error.to_string().contains("injected replay lookup failure"),
        "{error:?}"
    );
    assert!(!store.has_operation());
    assert!(kernel.receipt_log().is_empty());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn capture_boundary_retains_only_an_unknown_submitted_commit() {
    for nested in [false, true] {
        for unknown in [false, true] {
            let mut grant = make_grant("durable-server", "mutate");
            grant.max_invocations = Some(1);
            let (kernel, request, store, invocations) =
                durable_admission_fixture_with_grants("capture-boundary-disposition", vec![grant]);
            store
                .capture_pending_failure
                .store(if unknown { 2 } else { 1 }, Ordering::SeqCst);
            let result = if nested {
                let session = kernel
                    .open_session(request.agent_id.clone(), Vec::new())
                    .unwrap();
                kernel.activate_session(&session).unwrap();
                let parent = make_operation_context(&session, "capture-parent", &request.agent_id);
                kernel
                    .begin_session_request(&parent, OperationKind::ToolCall, true)
                    .unwrap();
                kernel.evaluate_tool_call_with_nested_flow_client(
                    &parent,
                    &request,
                    &mut NoopNestedFlowClient,
                    None,
                )
            } else {
                kernel.evaluate_tool_call_blocking(&request)
            };
            let expected_state = if unknown {
                let response = result.expect("unconfirmed capture response");
                assert_disposition(&response, "retained");
                AdmissionOperationState::CapturePending
            } else {
                let error =
                    result.expect_err("definite capture refusal cannot attest an unknown commit");
                assert!(
                    error
                        .to_string()
                        .contains("injected capture pre-write refusal"),
                    "{error:?}"
                );
                assert!(kernel.receipt_log().is_empty());
                AdmissionOperationState::ReadyToDispatch
            };
            let operation = store.operation();
            assert_eq!(operation.state(), expected_state);
            let hold = store
                .budget_store()
                .get_budget_hold(operation.budget_hold_id().unwrap().as_str())
                .unwrap()
                .unwrap();
            assert_eq!(
                hold.disposition,
                crate::budget_store::BudgetHoldDispositionView::Open
            );
            assert_eq!(invocations.load(Ordering::SeqCst), 0);
        }
    }
}
