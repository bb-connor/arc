use super::*;

#[test]
fn chio_runtime_admission_releases_reservations_on_pre_dispatch_budget_denial(
) -> Result<(), Box<dyn std::error::Error>> {
    let SiblingSumMonetaryFixture {
        mut kernel,
        child_a,
        child_b,
        child_a_kp,
        child_b_kp,
        path: _path,
    } = make_sibling_sum_monetary_fixture("chio-runtime-pre-dispatch-release");

    let allow_response = kernel.evaluate_tool_call_blocking(&ToolCallRequest {
        request_id: "req-chio-runtime-pre-dispatch-budget-allow".to_string(),
        capability: child_a,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: child_a_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    })?;
    assert_eq!(
        allow_response.verdict,
        Verdict::Allow,
        "unexpected deny reason: {:?}",
        allow_response.reason
    );

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-pre-dispatch-budget-deny",
        admission_id: "adm-pre-dispatch-budget-deny",
        lease_id: "lease-pre-dispatch-budget-deny",
        continuation_id: Some("continuation-pre-dispatch-budget-deny"),
    }));

    let deny_response = kernel.evaluate_tool_call_blocking(&ToolCallRequest {
        request_id: "req-chio-runtime-pre-dispatch-budget-deny".to_string(),
        capability: child_b,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: child_b_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    })?;

    assert_eq!(deny_response.verdict, Verdict::Deny);
    assert!(deny_response.reason.as_deref().is_some_and(|reason| {
        reason.contains("sibling-sum") || reason.contains("sibling sum")
    }));
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "runtime reservations must be released before tool dispatch starts"
    );
    let metadata = deny_response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["admission_id"],
        "adm-pre-dispatch-budget-deny"
    );
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-pre-dispatch-budget-deny"
    );
    assert_eq!(
        metadata["chio_runtime"]["reserved_treaty_continuation_id"],
        "continuation-pre-dispatch-budget-deny"
    );
    Ok(())
}

#[test]
fn chio_runtime_release_failure_does_not_mask_pre_dispatch_budget_denial(
) -> Result<(), Box<dyn std::error::Error>> {
    let SiblingSumMonetaryFixture {
        mut kernel,
        child_a,
        child_b,
        child_a_kp,
        child_b_kp,
        path: _path,
    } = make_sibling_sum_monetary_fixture("chio-runtime-release-failure");

    let allow_response = kernel.evaluate_tool_call_blocking(&ToolCallRequest {
        request_id: "req-chio-runtime-release-failure-budget-allow".to_string(),
        capability: child_a,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: child_a_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    })?;
    assert_eq!(
        allow_response.verdict,
        Verdict::Allow,
        "unexpected deny reason: {:?}",
        allow_response.reason
    );

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(FailingReleaseRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-release-failure-budget-deny",
        admission_id: "adm-release-failure-budget-deny",
        lease_id: "lease-release-failure-budget-deny",
    }));

    let deny_response = kernel.evaluate_tool_call_blocking(&ToolCallRequest {
        request_id: "req-chio-runtime-release-failure-budget-deny".to_string(),
        capability: child_b,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: child_b_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    })?;

    assert_eq!(deny_response.verdict, Verdict::Deny);
    assert!(deny_response.reason.as_deref().is_some_and(|reason| {
        reason.contains("sibling-sum") || reason.contains("sibling sum")
    }));
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "runtime release must be attempted before the denial receipt is returned"
    );
    let metadata = deny_response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["admission_id"],
        "adm-release-failure-budget-deny"
    );
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-release-failure-budget-deny"
    );
    assert_eq!(metadata["chio_runtime"]["reservation_release_failed"], true);
    assert_eq!(metadata["chio_runtime"]["reservation_retained"], true);
    assert!(metadata["chio_runtime"]
        .get("reservation_release_failure_reason")
        .is_none());
    Ok(())
}

#[test]
fn chio_runtime_release_failure_surfaces_cleanup_failure_on_pending_approval() {
    let (mut kernel, mut request, _store, invocations) =
        durable_admission_fixture("req-chio-runtime-release-failure-pending");
    let approver_a = CoreKeypair::generate();
    let approver_b = CoreKeypair::generate();
    let requirement = ThresholdApprovalRequirement::new(
        kernel.config.policy_hash.clone(),
        2,
        vec![
            ThresholdApproverIdentity {
                identifier: "approver-a".to_owned(),
                public_key: approver_a.public_key(),
            },
            ThresholdApproverIdentity {
                identifier: "approver-b".to_owned(),
                public_key: approver_b.public_key(),
            },
        ],
        "cumulative-approval-directory-v1".to_owned(),
        300,
    )
    .expect("threshold requirement");
    kernel.set_threshold_approval_requirement_resolver(StdArc::new(FixedThresholdRequirement(
        requirement,
    )));
    let mut body = request.capability.body();
    body.scope.grants[0]
        .constraints
        .push(Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 100,
                currency: "USD".to_owned(),
            },
            approval_budget_id: "budget-pending-release".to_owned(),
            approval_budget_epoch: 7,
            cumulative_approval_root_binding: None,
        });
    request.capability = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("cumulative capability must sign");
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "cumulative-approval-release-intent".to_owned(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "authorize a bounded ledger mutation".to_owned(),
        max_amount: Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_owned(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    });

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(FailingReleaseRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-release-failure-pending",
        admission_id: "adm-release-failure-pending",
        lease_id: "lease-release-failure-pending",
    }));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("pending-approval evaluation");

    // The runtime lease was reserved before the budget check parked the call for
    // cumulative approval, and its release could not be confirmed. A retained
    // lease cannot be parked for approval, so the outcome fails closed instead
    // of returning a bare pending verdict.
    assert_ne!(
        response.verdict,
        Verdict::PendingApproval,
        "a stuck runtime lease must not surface as a bare pending approval"
    );
    assert_eq!(
        response.verdict,
        Verdict::Deny,
        "unexpected verdict: {:?}",
        response.reason
    );
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "runtime release must be attempted before surfacing the cleanup failure"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .expect("cleanup-failure metadata present");
    assert_eq!(metadata["chio_runtime"]["reservation_release_failed"], true);
    assert_eq!(metadata["chio_runtime"]["reservation_retained"], true);
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-release-failure-pending"
    );
}

#[test]
fn nested_runtime_release_failure_denies_pending_approval() {
    let request_id = "req-chio-runtime-nested-release-failure-pending";
    let (mut kernel, mut request, _store, invocations) = durable_admission_fixture(request_id);
    let approver_a = CoreKeypair::generate();
    let approver_b = CoreKeypair::generate();
    let requirement = ThresholdApprovalRequirement::new(
        kernel.config.policy_hash.clone(),
        2,
        vec![
            ThresholdApproverIdentity {
                identifier: "approver-a".to_owned(),
                public_key: approver_a.public_key(),
            },
            ThresholdApproverIdentity {
                identifier: "approver-b".to_owned(),
                public_key: approver_b.public_key(),
            },
        ],
        "cumulative-approval-directory-v1".to_owned(),
        300,
    )
    .expect("threshold requirement");
    kernel.set_threshold_approval_requirement_resolver(StdArc::new(FixedThresholdRequirement(
        requirement,
    )));
    let mut body = request.capability.body();
    body.scope.grants[0]
        .constraints
        .push(Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 100,
                currency: "USD".to_owned(),
            },
            approval_budget_id: "budget-nested-pending-release".to_owned(),
            approval_budget_epoch: 7,
            cumulative_approval_root_binding: None,
        });
    request.capability = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("cumulative capability must sign");
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "cumulative-approval-nested-release-intent".to_owned(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "authorize a bounded ledger mutation".to_owned(),
        max_amount: Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_owned(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    });

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(FailingReleaseRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: request_id,
        admission_id: "adm-nested-release-failure-pending",
        lease_id: "lease-nested-release-failure-pending",
    }));

    let session_id = kernel
        .open_session(request.agent_id.clone(), vec![request.capability.clone()])
        .expect("nested session should open");
    kernel
        .activate_session(&session_id)
        .expect("nested session should activate");
    let context = make_operation_context(&session_id, request_id, &request.agent_id);
    let operation = ToolCallOperation {
        capability: request.capability,
        server_id: request.server_id,
        tool_name: request.tool_name,
        arguments: request.arguments,
        governed_intent: request.governed_intent,
        approval_token: request.approval_token,
        approval_tokens: request.approval_tokens,
        threshold_approval_proposal: request.threshold_approval_proposal,
        supplemental_authorization: request.supplemental_authorization,
        execution_nonce: None,
        model_metadata: request.model_metadata,
        extra_metadata: None,
    };
    let mut client = NoopNestedFlowClient;
    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .expect("nested pending-approval evaluation");

    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .expect("cleanup-failure metadata present");
    assert_eq!(metadata["chio_runtime"]["reservation_release_failed"], true);
    assert_eq!(metadata["chio_runtime"]["reservation_retained"], true);
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-nested-release-failure-pending"
    );
}

#[test]
fn exhausted_grant_receipt_retains_failed_runtime_release_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new(
        "runtime-release-srv",
        vec!["read"],
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(FailingReleaseRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-exhausted-runtime-release-failure",
        admission_id: "adm-exhausted-runtime-release-failure",
        lease_id: "lease-exhausted-runtime-release-failure",
    }));

    let mut grant = make_grant("runtime-release-srv", "read");
    grant.max_invocations = Some(0);
    let agent = make_keypair();
    let capability = make_capability(&kernel, &agent, make_scope(vec![grant]), 300);
    let response = kernel.evaluate_tool_call_blocking(&make_request_with_arguments(
        "req-exhausted-runtime-release-failure",
        &capability,
        "read",
        "runtime-release-srv",
        serde_json::json!({}),
    ))?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("budget exhausted")));
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-exhausted-runtime-release-failure"
    );
    assert_eq!(metadata["chio_runtime"]["reservation_release_failed"], true);
    assert_eq!(metadata["chio_runtime"]["reservation_retained"], true);
    Ok(())
}

#[test]
fn drop_guard_reverse_failure_records_cleanup_fault() {
    let mut kernel = make_kernel(make_config());
    kernel.set_budget_store(Box::new(ReverseFailingBudgetStore::new()));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-drop-reverse-failure",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    authorize_fabricated_drop_hold(&kernel, &cap.id).unwrap();
    let mutation = PreExecutionBudgetMutation::Charge(make_fabricated_drop_charge());

    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: None,
            pre_invocation_guard_evidence: Vec::new(),
            verified_payee_binding: None,
        },
        false,
    ));

    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "drop guard must emit exactly one cancellation receipt"
    );
    let receipt = receipt_log.get(0).unwrap();
    assert!(
        receipt.is_cancelled(),
        "drop guard receipt must be a cancellation"
    );
    let metadata = receipt
        .metadata
        .as_ref()
        .expect("cancellation receipt must carry metadata");
    assert_eq!(
        metadata["chio_runtime"]["pre_dispatch_cleanup_failed"], true,
        "reverse failure must be visible as a pre-dispatch cleanup fault"
    );
    assert!(
        metadata["chio_runtime"]["pre_dispatch_cleanup_faults"]
            .as_array()
            .is_some_and(|faults| faults.iter().any(|fault| {
                fault["step"] == "monetary_unwind"
                    && fault["hold_ids"]
                        .as_array()
                        .is_some_and(|ids| ids.iter().any(|id| id == "hold-drop-guard-tests"))
            })),
        "cleanup fault receipt must identify the failed monetary hold"
    );
}

#[test]
fn drop_pre_dispatch_releases_reservations_no_receipt() -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-pre-dispatch-dropped",
        admission_id: "adm-pre-dispatch-dropped",
        lease_id: "lease-pre-dispatch-dropped",
        continuation_id: None,
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-pre-dispatch-dropped",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    let metadata = serde_json::json!({
        "chio_runtime": {
            "admission_id": "adm-pre-dispatch-dropped",
            "accepted": true,
            "reserved_destructive_lease_id": "lease-pre-dispatch-dropped",
            "failure_code": null
        }
    });

    // No mark_dispatch_started(): this models a future dropped (or a panic
    // unwinding) after admission but before the tool-server dispatch await
    // was entered. No side effect is possible, so the unwind is total.
    let mutation = PreExecutionBudgetMutation::None;
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: Some(metadata),
            pre_invocation_guard_evidence: Vec::new(),
            verified_payee_binding: None,
        },
        true,
    ));

    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "a pre-dispatch drop must safe-release runtime-admission reservations"
    );
    assert_eq!(
        kernel.receipt_log().len(),
        0,
        "a pre-dispatch drop is the receipt-free fully-unwound exit"
    );
    Ok(())
}

#[test]
fn drop_pre_dispatch_monetary_unwinds_without_receipt() -> Result<(), Box<dyn std::error::Error>> {
    // A MONETARY future dropped before dispatch takes the pre-dispatch branch: the
    // hold is reversed, reservations released, and no receipt is recorded.
    let mut kernel = make_kernel(make_config());
    let payment = TrackingPaymentAdapter::new();
    kernel.set_payment_adapter(Box::new(payment.clone()));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-monetary-pre-dispatch-drop",
        admission_id: "adm-monetary-pre-dispatch-drop",
        lease_id: "lease-monetary-pre-dispatch-drop",
        continuation_id: None,
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-monetary-pre-dispatch-drop",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    let metadata = serde_json::json!({
        "chio_runtime": {
            "admission_id": "adm-monetary-pre-dispatch-drop",
            "accepted": true,
            "reserved_destructive_lease_id": "lease-monetary-pre-dispatch-drop",
            "failure_code": null
        }
    });
    // Model the real admission behind the fabricated charge so the monetary
    // reversal is a genuine, clean unwind (an un-reversible fabricated hold would
    // otherwise record a fault receipt).
    authorize_fabricated_drop_hold(&kernel, &cap.id)?;
    let mutation = PreExecutionBudgetMutation::Charge(make_fabricated_drop_charge());
    let authorization = PaymentAuthorization {
        authorization_id: "auth-monetary-pre-dispatch-drop".to_string(),
        state: PaymentAuthorizationState::Held,
        metadata: serde_json::json!({ "adapter": "tracking" }),
    };

    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        Some(&authorization),
        PostAdmissionReceiptContext {
            extra_metadata: Some(metadata),
            pre_invocation_guard_evidence: Vec::new(),
            verified_payee_binding: None,
        },
        true,
    ));

    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the unsettled monetary authorization must be released on a pre-dispatch drop"
    );
    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "runtime reservations must be released on a pre-dispatch drop"
    );
    assert_eq!(
        kernel.receipt_log().len(),
        0,
        "a monetary pre-dispatch drop is receipt-free: hold reversed, reservations released"
    );
    Ok(())
}

#[test]
fn drop_pre_dispatch_reverses_invocation_budget() -> Result<(), Box<dyn std::error::Error>> {
    // A non-monetary grant with `max_invocations` increments an invocation counter
    // at admission. A future dropped BEFORE dispatch must reverse that increment so
    // a never-dispatched call does not permanently consume the slot.
    let kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-pre-dispatch-invocation",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    // Model admission consuming the single invocation slot for grant 0.
    let admitted =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        admitted,
        "admission must consume the single invocation slot"
    );

    let mutation = PreExecutionBudgetMutation::Invocation { grant_index: 0 };
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: None,
            pre_invocation_guard_evidence: Vec::new(),
            verified_payee_binding: None,
        },
        true,
    ));

    // The slot must be free again: a retry increment succeeds.
    let retry =
        kernel.with_budget_store(|store| Ok(store.try_increment(&cap.id, 0, Some(1))?))?;
    assert!(
        retry,
        "a pre-dispatch drop must reverse the invocation increment so the slot is reusable"
    );
    assert_eq!(
        kernel.receipt_log().len(),
        0,
        "a clean invocation reversal on a pre-dispatch drop is receipt-free"
    );
    Ok(())
}

#[test]
fn drop_pre_dispatch_releases_admitted_child_budget() -> Result<(), Box<dyn std::error::Error>> {
    // A delegated capability admitted its share of the parent budget at admission.
    // A future dropped BEFORE dispatch must release that share or the child's claim
    // is permanently recorded.
    let SiblingSumMonetaryFixture {
        kernel,
        child_a,
        child_b,
        path: _path,
        ..
    } = make_sibling_sum_monetary_fixture("chio-runtime-pre-dispatch-child-budget");

    // Admit child_a's share. In the fixture (parent share 5000 bps, each child
    // 4000 bps) child_a alone fits but child_a + child_b does not.
    kernel
        .admit_capability_budget(&child_a)
        .map_err(std::io::Error::other)?;

    let request = make_request_with_arguments(
        "req-chio-runtime-pre-dispatch-child-budget",
        &child_a,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );
    let mutation = PreExecutionBudgetMutation::None;
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &child_a,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: None,
            pre_invocation_guard_evidence: Vec::new(),
            verified_payee_binding: None,
        },
        // Genuinely-new admission (child_a inserted above): the drop MUST
        // release it, so child_b can admit. Verifies no under-release leak.
        true,
    ));

    // child_a's share must have been released: child_b can now admit within
    // the parent budget.
    let readmit = kernel.admit_capability_budget(&child_b);
    assert!(
        readmit.is_ok(),
        "a pre-dispatch drop must release child_a's admitted share so child_b admits: {readmit:?}"
    );
    assert_eq!(
        kernel.receipt_log().len(),
        0,
        "a clean child-budget release on a pre-dispatch drop is receipt-free"
    );
    Ok(())
}

#[test]
fn drop_pre_dispatch_overlapping_readmit_keeps_sibling_denied(
) -> Result<(), Box<dyn std::error::Error>> {
    // Refcount model: two OVERLAPPING evaluations hold the SAME delegated child
    // edge. An EARLIER evaluation admits child_a (lease 1). A SECOND overlapping
    // evaluation idempotently re-admits the same child_a (lease 2) and is then
    // DROPPED before dispatch. The drop releases only the SECOND evaluation's lease
    // (holders 2 -> 1); it must NOT free the edge the first evaluation still holds,
    // so an oversubscribing sibling child_b stays DENIED. A non-refcounted release
    // would free child_a's only edge and wrongly admit child_b.
    let SiblingSumMonetaryFixture {
        kernel,
        child_a,
        child_b,
        path: _path,
        ..
    } = make_sibling_sum_monetary_fixture("chio-runtime-pre-dispatch-overlapping-readmit");

    // Earlier evaluation: fresh admission of child_a (4000 of 5000 bps).
    let first = kernel
        .admit_capability_budget(&child_a)
        .map_err(std::io::Error::other)?;
    assert!(first, "the first admission of child_a must acquire a lease");

    // Second overlapping evaluation: the idempotent re-admit takes a second
    // lease on the same edge (holders 2).
    let second = kernel
        .admit_capability_budget(&child_a)
        .map_err(std::io::Error::other)?;
    assert!(
        second,
        "an idempotent re-admit of child_a must also acquire a lease (holders 2)"
    );

    let request = make_request_with_arguments(
        "req-chio-runtime-pre-dispatch-overlapping-readmit",
        &child_a,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );
    let mutation = PreExecutionBudgetMutation::None;
    // The second evaluation's future is dropped before dispatch. It acquired a
    // lease, so the refcounted release drops ONE holder (holders 2 -> 1) and
    // leaves the edge intact.
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &child_a,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: None,
            pre_invocation_guard_evidence: Vec::new(),
            verified_payee_binding: None,
        },
        true,
    ));

    // child_a's share is still held by the first evaluation (holders 1), so an
    // oversubscribing sibling child_b (4000 + 4000 > 5000 bps) stays DENIED.
    let sibling = kernel.admit_capability_budget(&child_b);
    assert!(
        sibling.is_err(),
        "the second evaluation's drop must release only its own lease, leaving \
         child_a's share held by the first evaluation, so child_b stays denied: {sibling:?}"
    );
    assert_eq!(
        kernel.receipt_log().len(),
        0,
        "a pre-dispatch drop whose refcounted release does not free the edge is receipt-free"
    );
    Ok(())
}

#[test]
fn drop_pre_dispatch_records_receipt_on_cleanup_fault() -> Result<(), Box<dyn std::error::Error>> {
    // When a pre-dispatch cleanup step FAILS, the drop must record a signed receipt
    // documenting the fault so a stuck hold/reservation lands on the append-only
    // log rather than being silently burned.
    let mut kernel = make_kernel(make_config());
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(FailingReleaseRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-pre-dispatch-cleanup-fault",
        admission_id: "adm-pre-dispatch-cleanup-fault",
        lease_id: "lease-pre-dispatch-cleanup-fault",
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-pre-dispatch-cleanup-fault",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    let metadata = serde_json::json!({
        "chio_runtime": {
            "admission_id": "adm-pre-dispatch-cleanup-fault",
            "accepted": true,
            "reserved_destructive_lease_id": "lease-pre-dispatch-cleanup-fault",
            "failure_code": null
        }
    });

    let mutation = PreExecutionBudgetMutation::None;
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: Some(metadata),
            pre_invocation_guard_evidence: Vec::new(),
            verified_payee_binding: None,
        },
        true,
    ));

    assert_eq!(
        releases.load(Ordering::SeqCst),
        1,
        "the failing runtime-admission release must be attempted"
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "a failed pre-dispatch cleanup must record exactly one signed fault receipt"
    );
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("pre-dispatch cleanup fault receipt missing"))?;
    assert!(receipt.is_cancelled());
    let receipt_metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("fault receipt metadata missing"))?;
    assert_eq!(
        receipt_metadata["chio_runtime"]["pre_dispatch_cleanup_failed"],
        true
    );
    // The reserved lease id must survive alongside the fault annotation so an
    // operator can locate the possibly-stuck reservation.
    assert_eq!(
        receipt_metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-pre-dispatch-cleanup-fault"
    );
    let faults = receipt_metadata["chio_runtime"]["pre_dispatch_cleanup_faults"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("fault list missing"))?;
    assert!(
        faults
            .iter()
            .any(|fault| fault["step"] == "runtime_admission_release"),
        "the fault list must name the failing runtime-admission release step: {faults:?}"
    );
    Ok(())
}

#[test]
fn drop_pre_dispatch_cleanup_fault_receipt_includes_monetary_hold_id(
) -> Result<(), Box<dyn std::error::Error>> {
    // When a pre-dispatch drop hits a monetary cleanup failure, the fault entry
    // must name the budget hold id it was unwinding so an operator can locate the
    // possibly-stuck hold from the fault receipt alone. The fabricated charge has no
    // matching open hold in the store, so the monetary reversal fails and records a
    // fault.
    let kernel = make_kernel(make_config());

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-monetary-cleanup-fault-hold-id",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    // Charge WITHOUT authorizing the matching hold: the monetary reversal fails
    // and records a monetary_unwind fault (no mark_dispatch_started, so this is
    // the pre-dispatch drop branch).
    let mutation = PreExecutionBudgetMutation::Charge(make_fabricated_drop_charge());
    drop(PostAdmissionDropGuard::new(
        &kernel,
        &request,
        &cap,
        Some(0),
        &mutation,
        None,
        PostAdmissionReceiptContext {
            extra_metadata: None,
            pre_invocation_guard_evidence: Vec::new(),
            verified_payee_binding: None,
        },
        true,
    ));

    let receipt_log = kernel.receipt_log();
    assert_eq!(
        receipt_log.len(),
        1,
        "a failed monetary pre-dispatch cleanup must record exactly one fault receipt"
    );
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("monetary cleanup fault receipt missing"))?;
    let receipt_metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("fault receipt metadata missing"))?;
    let faults = receipt_metadata["chio_runtime"]["pre_dispatch_cleanup_faults"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("fault list missing"))?;
    let monetary_fault = faults
        .iter()
        .find(|fault| fault["step"] == "monetary_unwind")
        .ok_or_else(|| std::io::Error::other("monetary_unwind fault entry missing"))?;
    let hold_ids = monetary_fault["hold_ids"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("monetary_unwind fault must carry hold_ids"))?;
    assert!(
        hold_ids.iter().any(|id| id == "hold-drop-guard-tests"),
        "the monetary_unwind fault must name the budget hold id: {hold_ids:?}"
    );
    Ok(())
}
