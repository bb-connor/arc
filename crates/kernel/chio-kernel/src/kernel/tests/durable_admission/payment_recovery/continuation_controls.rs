//! Regression controls for an inherited prepaid bug and bounded retained recovery.
use super::*;

fn optional_nonce(kernel: &mut ChioKernel) {
    let config = crate::execution_nonce::ExecutionNonceConfig::default();
    let capacity = config.nonce_store_capacity;
    kernel.set_execution_nonce_store(
        config,
        Box::new(crate::execution_nonce::InMemoryExecutionNonceStore::new(
            capacity,
        )),
    );
}

#[test]
fn review_continuation_prepaid_quote_five_closes_exposure_ten_without_capture() -> TestResult {
    let grant = make_governed_monetary_grant("durable-server", "mutate", 10, 100, "USD", 4);
    let (mut kernel, mut request, store, invocations) =
        durable_admission_fixture_with_grants("review-normal-prepay-five", vec![grant]);
    let calls = Arc::new(RailCalls::default());
    kernel.set_payment_adapter(Box::new(RecoveryRail {
        prepaid: true,
        calls: calls.clone(),
    }));
    let mut intent = make_mustprepay_intent(
        "review-normal-prepay-five",
        "durable-server",
        "mutate",
        5,
        "USD",
    );
    // Approve the exposure ceiling, while the exact fixed quote is five.
    intent.max_amount = Some(MonetaryAmount {
        units: 10,
        currency: "USD".into(),
    });
    bind_test_tool_approval(
        &mut kernel,
        &request.capability,
        &request.arguments,
        &request.request_id,
        &mut intent,
    );
    request.approval_token = Some(make_governed_approval_token(
        &kernel.config.keypair,
        &request.capability.subject,
        &intent,
        &request.request_id,
    ));
    request.governed_intent = Some(intent);
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    let journal = store.payment_journal().ok_or("original prepaid journal")?;
    assert_eq!(journal.amount_units, 10);
    assert_eq!(journal.authorized_amount_units, Some(5));
    assert_eq!(journal.settle_action, None);
    let financial = &response
        .receipt
        .metadata
        .as_ref()
        .ok_or("financial metadata")?["financial"];
    assert_eq!(financial["cost_charged"], 5);
    assert_eq!(
        financial["cost_breakdown"]["payment"]["budget_exposure_units"],
        10
    );
    assert_eq!(
        calls
            .authorizations
            .lock()
            .map_err(|_| "authorization lock")?
            .len(),
        1
    );
    assert!(calls
        .captures
        .lock()
        .map_err(|_| "capture lock")?
        .is_empty());
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(
        canonical_json_bytes(&replay.receipt)?,
        canonical_json_bytes(&response.receipt)?
    );
    assert_eq!(
        calls
            .authorizations
            .lock()
            .map_err(|_| "authorization lock")?
            .len(),
        1
    );
    assert!(calls
        .captures
        .lock()
        .map_err(|_| "capture lock")?
        .is_empty());
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn review_target_retained_finalization_does_not_mint_fresh_execution_nonce() -> TestResult {
    let (mut kernel, request, store, invocations, calls) =
        payment_fixture("review-retained-payment-nonce", false);
    calls.capture_pending.store(true, Ordering::SeqCst);
    let first = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        first.is_err(),
        "original valid call must reach pending settlement: {first:?}"
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )?;
    let mut original = kernel
        .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())?
        .ok_or("checked original finalizing admission")?;
    // Startup enters this same historical finalizer without the fresh-admission
    // nonce route. The original validated return did not contain a nonce.
    optional_nonce(&mut kernel);
    let returned = kernel
        .recover_durable_tool_admission(&mut original, &request)?
        .ok_or("retained return")?;
    assert_eq!(returned.verdict, Verdict::Allow, "{returned:?}");
    assert!(
        returned.execution_nonce.is_none(),
        "historical finalization must not mint fresh execution authority"
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        calls
            .authorizations
            .lock()
            .map_err(|_| "authorization lock")?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn review_target_fresh_live_optional_nonce_still_mints() -> TestResult {
    // Optional issuance is supported by the ordinary live profile; durable
    // fresh admission explicitly requires the strict preflight profile.
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new(
        "fresh-nonce-server",
        vec!["echo"],
    )));
    optional_nonce(&mut kernel);
    let agent = Keypair::generate();
    let capability = kernel.issue_capability(
        &agent.public_key(),
        make_scope(vec![make_grant("fresh-nonce-server", "echo")]),
        300,
    )?;
    let request = make_request_with_arguments(
        "review-fresh-live-nonce",
        &capability,
        "echo",
        "fresh-nonce-server",
        serde_json::json!({"message": "fresh"}),
    );
    let returned = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(returned.verdict, Verdict::Allow, "{returned:?}");
    assert!(returned.execution_nonce.is_some());
    Ok(())
}

// Original baseline: hosts can call only the full sweep. After introducing the
// bounded public seam, the same observable count/cursor assertions use that seam.
fn due_tick(kernel: &ChioKernel, candidate_limit: usize) -> Result<usize, KernelError> {
    kernel.reconcile_recoverable_admissions_batch(candidate_limit)
}

#[test]
fn review_continuation_due_tick_visits_one_physical_page_then_resumes_cursor() -> TestResult {
    let (kernel, _, store, _) = durable_admission_fixture("review-bounded-due-tick");
    let cursor = crate::admission_operation::AdmissionOperationId::from_persisted("a".repeat(64))?;
    store.script_recovery_pages(vec![Ok(Some(cursor.clone())), Ok(None)]);
    assert_eq!(due_tick(&kernel, 16)?, 0);
    assert_eq!(store.recovery_page_trace(), vec![(16, None)]);
    assert_eq!(due_tick(&kernel, 16)?, 0);
    assert_eq!(
        store.recovery_page_trace(),
        vec![(16, None), (16, Some(cursor))]
    );
    assert_eq!(due_tick(&kernel, 16)?, 0);
    assert_eq!(store.recovery_page_trace().last(), Some(&(16, None)));
    Ok(())
}

#[test]
fn review_continuation_due_tick_rejects_invalid_count_before_store_work() -> TestResult {
    let (kernel, _, store, _) = durable_admission_fixture("review-bounded-due-tick-invalid");
    for invalid in [0, 257] {
        assert!(due_tick(&kernel, invalid).is_err());
    }
    assert!(store.recovery_page_trace().is_empty());
    Ok(())
}

#[test]
fn review_continuation_due_tick_preserves_typed_fence_failure_and_retry_cursor() -> TestResult {
    let (kernel, _, store, _) = durable_admission_fixture("review-bounded-due-tick-fence");
    store.script_recovery_pages(vec![Err(AdmissionOperationStoreError::Fenced), Ok(None)]);
    let error = due_tick(&kernel, 16).err().ok_or("global fenced refusal")?;
    assert!(matches!(error, KernelError::AdmissionRecovery(failure)
        if matches!(failure.as_ref(), crate::admission_operation::AdmissionRecoveryError::Port(
            crate::admission_operation::AdmissionRecoveryPortError::Local(AdmissionOperationStoreError::Fenced)))));
    assert_eq!(due_tick(&kernel, 16)?, 0);
    assert!(store
        .recovery_page_trace()
        .iter()
        .all(|(_, after)| after.is_none()));
    Ok(())
}
