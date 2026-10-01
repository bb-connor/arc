use super::*;

fn no_charge_mustprepay_dispatch(nested: bool, unsafe_financial_dispatch: bool) -> TestResult {
    let mut grant = make_no_ceiling_mustprepay_grant();
    grant.server_id = "durable-server".to_owned();
    grant.tool_name = "mutate".to_owned();
    grant.max_invocations = Some(1);
    let (mut kernel, mut request, store, invocations) =
        durable_admission_fixture_with_grants("no-charge-mustprepay-dispatch", vec![grant]);
    // The general fixture explicitly enables development-only financial dispatch.
    // Restore the production default, then opt in only for the compatibility case.
    kernel.unsafe_ephemeral_financial_dispatch = false;
    if unsafe_financial_dispatch {
        kernel.enable_unsafe_ephemeral_financial_dispatch_for_development();
    }
    kernel
        .set_governed_approval_replay_store(Box::new(InMemoryGovernedApprovalReplayStore::new(8)));
    let intent = make_mustprepay_intent(
        "no-charge-mustprepay-intent",
        "durable-server",
        "mutate",
        100,
        "USD",
    );
    request.approval_token = Some(make_governed_approval_token(
        &kernel.config.keypair,
        &request.capability.subject,
        &intent,
        &request.request_id,
    ));
    request.governed_intent = Some(intent);
    let authorizations = Arc::new(Mutex::new(Vec::new()));
    let settlements = Arc::new(Mutex::new(Vec::new()));
    let settlement_references = Arc::new(Mutex::new(Vec::new()));
    // The adapter records a real authorization before losing its acknowledgement.
    // Strict mode must stop before this point. Unsafe mode must retain the actual
    // request reference, since the durable tool operation has no payment journal.
    kernel.set_payment_adapter(Box::new(LostPaymentAcknowledgement {
        adapter: QualifiedDurablePaymentAdapter {
            authorization_references: authorizations.clone(),
            settlement_actions: settlements.clone(),
            settlement_references: settlement_references.clone(),
        },
        boundary: FailureBoundary::AuthorizationAcknowledgement,
    }));

    let response = if nested {
        let session = kernel.open_session("mustprepay-parent".to_owned(), Vec::new())?;
        kernel.activate_session(&session)?;
        let parent =
            make_operation_context(&session, "mustprepay-parent-request", "mustprepay-parent");
        kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
        kernel.evaluate_tool_call_with_nested_flow_client(
            &parent,
            &request,
            &mut NoopNestedFlowClient,
            None,
        )?
    } else {
        kernel.evaluate_tool_call_blocking(&request)?
    };
    assert_eq!(response.verdict, Verdict::Deny, "{response:?}");
    assert!(response.receipt.verify_signature()?);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert!(settlements
        .lock()
        .map_err(|_| "settlement lock")?
        .is_empty());
    assert!(settlement_references
        .lock()
        .map_err(|_| "settlement reference lock")?
        .is_empty());
    assert!(store.payment_journal().is_none());
    let operation = store.operation();
    assert!(!operation.binding().participant_requirements().payment);
    assert_ne!(
        operation.binding().operation_id().as_str(),
        request.request_id
    );
    assert!(store
        .state
        .lock()
        .map_err(|_| "admission lock")?
        .raw_outcome
        .is_none());
    let attempted = authorizations.lock().map_err(|_| "authorization lock")?;
    if unsafe_financial_dispatch {
        assert_eq!(attempted.as_slice(), [request.request_id.as_str()]);
        let metadata = response
            .receipt
            .metadata
            .as_ref()
            .ok_or("denial metadata")?;
        assert_eq!(
            metadata["financial"]["payment_authorization_ambiguous"],
            true
        );
        assert_eq!(
            metadata["financial"]["payment_attempt_reference"].as_str(),
            attempted.first().map(String::as_str)
        );
    } else {
        assert_eq!(
            response.reason.as_deref(),
            Some("financial tool dispatch requires durable admission coverage")
        );
        assert!(attempted.is_empty());
        assert_eq!(
            operation.state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        let hold = store
            .budget_store()
            .get_budget_hold(operation.budget_hold_id().ok_or("hold ID")?.as_str())?
            .ok_or("original invocation hold")?;
        assert_eq!(hold.capability_id, request.capability.id);
        assert_eq!(hold.authorized_exposure_units, 0);
        assert_eq!(hold.remaining_exposure_units, 0);
        assert_eq!(
            hold.disposition,
            crate::budget_store::BudgetHoldDispositionView::Reversed
        );
        let quota = store
            .budget_store()
            .get_invocation_quota_usage(&crate::budget_store::BudgetQuotaKey::grant(
                &request.capability.id,
                0,
            ))?
            .ok_or("original invocation quota")?;
        assert_eq!(
            (quota.reserved_invocations, quota.captured_invocations),
            (0, 0)
        );
    }
    Ok(())
}

#[test]
fn no_charge_mustprepay_requires_a_durable_payment_participant_before_authorization() -> TestResult
{
    for nested in [false, true] {
        no_charge_mustprepay_dispatch(nested, false)?;
    }
    Ok(())
}

#[test]
fn explicit_unsafe_no_charge_mustprepay_records_the_actual_request_reference() -> TestResult {
    for nested in [false, true] {
        no_charge_mustprepay_dispatch(nested, true)?;
    }
    Ok(())
}
