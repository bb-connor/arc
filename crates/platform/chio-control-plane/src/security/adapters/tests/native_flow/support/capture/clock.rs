//! Explicit deadline advancement exercises the real resolver and capture path.
use super::*;

#[test]
fn native_capture_policy_deadline_is_exclusive_with_shared_clock() -> TestResult {
    for elapsed_ms in [9_999, 10_000] {
        let mut fixture = Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?;
        let resolver = Arc::new(NativeFlowResolver::new(
            fixture.binding.clone(),
            super::super::super::registry(false, InformationLabel::bottom())?,
            Arc::new(CountingEmptyClassifier::new()),
            fixture.clock.clone(),
            flow_config(),
        )?);
        fixture
            .kernel
            .set_security_pre_dispatch_hook(resolver.clone());
        let clock = fixture.clock.clone();
        let captures = Arc::new(AtomicUsize::new(0));
        fixture
            .kernel
            .install_native_capture_checkpoint_hook(Arc::new({
                let captures = captures.clone();
                move |authority| {
                    let prepared = resolver
                        .prepare_dispatch(authority.prepare_egress()?)
                        .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
                    clock
                        .advance_to(FIXTURE_EPOCH_MS + elapsed_ms)
                        .map_err(|error| KernelError::Internal(error.to_string()))?;
                    match prepared.capture_invocation(authority) {
                        Ok(_) => {
                            captures.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        }
                        Err(error) => {
                            assert_eq!(elapsed_ms, 10_000);
                            assert!(matches!(error, NativeFlowError::ClockChanged), "{error:?}");
                            Err(KernelError::GuardDenied(error.to_string()))
                        }
                    }
                }
            }));
        let response = fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?;
        let captured = elapsed_ms < 10_000;
        // The checkpoint deliberately stops before tool execution, even after
        // successful capture. Physical custody proves which side of expiry won.
        assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
        if captured {
            assert!(
                response
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("native capture checkpoint complete")),
                "{:?}",
                response.reason
            );
        }
        assert_eq!(captures.load(Ordering::SeqCst), usize::from(captured));
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        let quota = fixture
            .authority
            .budget_store()
            .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
            .ok_or("original quota")?;
        assert_eq!(quota.captured_invocations, u32::from(captured));
        assert!(response.receipt.verify_signature()?);
    }
    Ok(())
}
