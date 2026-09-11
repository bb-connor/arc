//! The actual admission/budget path reaches custody, then still denies dispatch.
use super::*;
use chio_kernel::admission_operation::NativeSecurityEgressHistoryV1;
use std::sync::Mutex;

#[test]
fn actual_kernel_egress_custody_commits_sqlite_history_without_dispatch_activation() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let mut runtime = fixture.open()?;
    let selected = initialize(&fixture, &runtime, "kernel-egress-source")?;
    let request = fixture.request(&runtime, "actual-native-egress")?;
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("native-tenant")?,
        SessionId::new("native-session")?,
        PrincipalId::new(request.agent_id.clone())?,
        IsolationEpochId::new("native-epoch")?,
        LineageId::new(request.capability.id.clone())?,
        1,
    ));
    assert_eq!(context.as_v1().flow_state_generation(), None);
    let probe = Arc::new(NativeAdmissionProbe {
        store: runtime.authority.admission_operation_store(),
        fence: runtime.authority.mutation_fence(),
        selected,
        context: context.clone(),
        calls: AtomicUsize::new(0),
        preparation_calls: AtomicUsize::new(0),
        dispatch_calls: AtomicUsize::new(0),
        mode: PreparationMode::Normal,
    });
    let result: Arc<Mutex<Option<Result<NativeSecurityEgressHistoryV1, String>>>> =
        Arc::new(Mutex::new(None));
    let checkpoint_calls = Arc::new(AtomicUsize::new(0));
    let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("unique kernel")?;
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(probe.clone());
    kernel.install_native_egress_checkpoint_hook(Arc::new({
        let result = result.clone();
        let calls = checkpoint_calls.clone();
        move |kernel, operation, request, context| {
            calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(operation.state(), AdmissionOperationState::CapturePending);
            assert!(operation.dispatch_commit().is_none());
            let run = || -> TestResult<NativeSecurityEgressHistoryV1> {
                let prepared = kernel.prepare_native_security_egress(
                    operation.binding().operation_id(),
                    request,
                    context,
                )?;
                assert!(prepared.observation().stored_context_generation().is_some());
                let acquired = prepared.acquire(now_ms()? + 60_000)?;
                let first = acquired.history().acquisition.clone();
                let committed = acquired.commit()?;
                assert_eq!(committed.acquisition, first);
                assert_eq!(
                    committed
                        .commitment
                        .as_ref()
                        .ok_or("commitment")?
                        .acquisition_digest,
                    first.event_digest
                );
                Ok(committed)
            };
            let outcome = run().map_err(|error| error.to_string());
            // The test reader below reports a poisoned lock as a failure.
            if let Ok(mut slot) = result.lock() {
                *slot = Some(outcome);
            }
        }
    }));
    let response = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context)?;
    assert_eq!(checkpoint_calls.load(Ordering::SeqCst), 1);
    let history = result
        .lock()
        .map_err(|_| "checkpoint poisoned")?
        .take()
        .ok_or("checkpoint did not run")??;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("native security dispatch lifecycle is unsupported")
    );
    assert!(response.output.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(probe.preparation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(probe.dispatch_calls.load(Ordering::SeqCst), 0);
    assert_eq!(grant_quota(&runtime, &request)?, (0, 0));
    let store = runtime.authority.admission_operation_store();
    let (operation, readback) = store
        .load_native_security_egress(
            &history.operation_id,
            &runtime.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("durable operation")?;
    assert!(operation.dispatch_commit().is_none());
    assert_eq!(readback.as_ref(), Some(&history));
    // Committed custody is not permission to reacquire from terminal admission.
    assert!(runtime
        .kernel
        .prepare_native_security_egress(&history.operation_id, &request, &context)
        .is_err());
    Ok(())
}
