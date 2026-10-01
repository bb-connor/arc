// Real-clock expiry at capture and historical replay after issuance expires.
use super::*;

#[test]
fn native_nonce_expiry_at_final_commit_rolls_back_capture_without_reversing_taint() -> TestResult {
    let mut fixture = super::super::super::super::public_fixture()?;
    let legacy = configure(&mut fixture, false)?;
    let original_id = issue(&mut fixture)?;
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        super::super::super::super::registry(false, InformationLabel::bottom())?,
        Arc::new(CountingEmptyClassifier::new()),
        Arc::new(Clock::default()),
        flow_config(),
    )?);
    fixture
        .kernel
        .set_security_pre_dispatch_hook(resolver.clone());
    let store = fixture.authority.admission_operation_store();
    store.inject_native_capture_nonce_expiry_for_test()?;
    let successes = Arc::new(AtomicUsize::new(0));
    fixture
        .kernel
        .install_native_capture_checkpoint_hook(Arc::new({
            let successes = successes.clone();
            move |authority| {
                resolver
                    .prepare_dispatch(authority.prepare_egress()?)
                    .and_then(|prepared| prepared.capture_invocation(authority))
                    .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
                successes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }));
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    store.clear_native_capture_nonce_expiry_for_test()?;
    assert_eq!(successes.load(Ordering::SeqCst), 0);
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(
        response.reason.as_deref().is_some_and(|reason| reason
            .contains("native capture rejected after nonce expiry cutpoint:")
            && reason.contains("native capture execution nonce expired before commit")),
        "{:?}",
        response.reason
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(legacy.load(Ordering::SeqCst), 0);
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_retained_tool_request(&original_id, &fence, now_ms()?)?
        .ok_or("original expired capture")?;
    assert_eq!(operation.state(), AdmissionOperationState::CapturePending);
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert!(operation.execution_nonce_id().is_some());
    assert!(store
        .load_native_dispatch_capture(&original_id, &fence, now_ms()?)?
        .is_none());
    assert!(store
        .load_native_security_input_join(&original_id, &fence, now_ms()?)?
        .ok_or("original taint")?
        .1
        .is_some());
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("held quota")?;
    assert_eq!(
        (usage.reserved_invocations, usage.captured_invocations),
        (1, 0)
    );
    Ok(())
}

#[test]
fn native_nonce_completed_receipt_replay_survives_expiry_without_new_authority() -> TestResult {
    let mut fixture = super::super::super::super::public_fixture()?;
    let legacy = configure(&mut fixture, false)?;
    issue(&mut fixture)?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert!(response.output.is_some());
    let expiry = u64::try_from(
        fixture
            .request
            .execution_nonce
            .as_ref()
            .ok_or("issued nonce")?
            .expires_at(),
    )?
    .checked_mul(1000)
    .ok_or("nonce expiry overflow")?;
    if let Some(remaining) = expiry
        .checked_sub(now_ms()?)
        .filter(|remaining| *remaining > 0)
    {
        assert!(remaining < 60_000);
        std::thread::sleep(std::time::Duration::from_millis(remaining));
    }
    assert!(now_ms()? >= expiry);
    let replay = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(
        chio_core::canonical_json_bytes(&response.receipt)?,
        chio_core::canonical_json_bytes(&replay.receipt)?
    );
    assert!(replay.receipt.verify_signature()?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(legacy.load(Ordering::SeqCst), 0);
    Ok(())
}
