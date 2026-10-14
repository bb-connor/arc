// Ordinary (no declassification) native egress stamps the trusted physical commit event.
use super::*;

#[test]
fn native_ordinary_egress_event_is_stamped_after_queued_valid_work() -> TestResult {
    let mut fixture = Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?;
    let mut config = flow_config();
    config.fence_ttl_ms = 60_000;
    let resolver = Arc::new(
        NativeFlowResolver::new(
            fixture.binding.clone(),
            super::super::super::registry(false, InformationLabel::bottom())?,
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(Clock::default()),
            config,
        )?
        .with_captured_lifecycle(),
    );
    resolver.install_captured_on_kernel(&mut fixture.kernel)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let prepared_at = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let owner_thread = std::thread::current().id();
    let _observer = fixture
        .kernel
        .observe_native_egress_commit_for_test(Arc::new({
            let calls = calls.clone();
            let prepared_at = prepared_at.clone();
            move |time| {
                if std::thread::current().id() != owner_thread {
                    return;
                }
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    prepared_at.store(time, Ordering::SeqCst);
                    // The native lease and fence stay valid far longer than this
                    // real scheduling delay; only the pre-writer event clock is old.
                    std::thread::sleep(std::time::Duration::from_millis(6_050));
                }
            }
        }))?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert!(
        calls.load(Ordering::SeqCst) > 0,
        "the prepared event was not observed"
    );
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("queued ordinary original absent")?;
    let (_, history) = store
        .load_native_security_egress(operation.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("queued ordinary egress absent")?;
    let commitment = history
        .ok_or("queued ordinary history absent")?
        .commitment
        .ok_or("queued ordinary commitment absent")?;
    assert!(commitment.declassification.is_none());
    assert!(
        commitment.commitment.committed_at_unix_ms > prepared_at.load(Ordering::SeqCst) + 5_000,
    );
    assert!(operation.dispatch_commit().is_some());
    Ok(())
}
