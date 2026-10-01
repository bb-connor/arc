use super::*;
use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantPhase;
use chio_kernel::admission_operation::AdmissionOperationState;
use chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore};
use chio_kernel::{BudgetStore, KernelError, ToolServerConnection};

struct UncertainTool {
    invocations: Arc<AtomicU64>,
    park: bool,
}

#[async_trait::async_trait]
impl ToolServerConnection for UncertainTool {
    fn server_id(&self) -> &str {
        "vendor-ledger"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["close_account".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        if self.park {
            std::future::pending::<()>().await;
        }
        Err(KernelError::Internal(
            "injected uncertain tool outcome".into(),
        ))
    }
}

#[test]
fn combined_owned_nonce_preflight_releases_three_resources_before_fresh_dispatch_claim(
) -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    let fixture = CombinedFixture::new()?;
    let mut kernel = fixture.kernel(fixture.hook()?)?;
    let config = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 64,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&config)),
    );
    let preflight = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(preflight.verdict, Verdict::Allow, "{preflight:#?}");
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 0);
    let history = faults::history(&fixture.inner)?;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].intent.resources().len(), 3);
    assert_eq!(
        history[0].intent.phase(),
        RuntimeParticipantPhase::NoncePreflight
    );
    assert_eq!(
        history[0].disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch
    );
    let (issued, _) = fixture.history(&history[0].reference)?;
    assert!(issued.execution_nonce_issuance_digest().is_some());
    assert!(issued.dispatch_commit().is_none());
    let mut execution = fixture.inner.request.clone();
    execution.execution_nonce = Some(*preflight.execution_nonce.ok_or("combined issued nonce")?);
    let dispatched = kernel
        .evaluate_tool_call_blocking_with_metadata(&execution, Some(swarm_route_metadata()))?;
    assert_eq!(dispatched.verdict, Verdict::Allow, "{dispatched:#?}");
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
    let (operation, after) = fixture.history(&history[0].reference)?;
    assert!(operation.dispatch_commit().is_some());
    assert_eq!(after.len(), 2);
    assert_eq!(after[0], history[0]);
    assert_eq!(after[1].intent.resources(), history[0].intent.resources());
    assert_eq!(after[1].intent.phase(), RuntimeParticipantPhase::Dispatch);
    assert_ne!(after[1].reference, history[0].reference);
    assert_eq!(
        after[1].disposition,
        RuntimeParticipantDisposition::RetainedAfterDispatchCommit
    );
    let replay = kernel
        .evaluate_tool_call_blocking_with_metadata(&execution, Some(swarm_route_metadata()))?;
    assert_eq!(replay.verdict, Verdict::Allow, "{replay:#?}");
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.history(&history[0].reference)?, (operation, after));
    Ok(())
}

#[test]
fn combined_owned_predispatch_drop_releases_all_resources_and_budget() -> TestResult {
    use std::future::Future;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    let fixture = CombinedFixture::new()?;
    let polls = Arc::new(AtomicU64::new(0));
    let kernel = fixture.kernel(faults::FaultHook::new(
        fixture.hook()?,
        fixture.inner._directory.path().join("runtime.sqlite3"),
        faults::Fault::Park(polls.clone()),
    ))?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut invocation = Box::pin(kernel.evaluate_tool_call_with_metadata(
                &fixture.inner.request,
                Some(swarm_route_metadata()),
            ));
            std::future::poll_fn(|cx| {
                let result = invocation.as_mut().poll(cx);
                assert!(
                    result.is_pending(),
                    "combined parked call finished: {result:?}"
                );
                if polls.load(Ordering::SeqCst) > 0 {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
            drop(invocation);
        });
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 0);
    let history = faults::history(&fixture.inner)?;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].intent.resources().len(), 3);
    assert_eq!(
        history[0].disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch
    );
    let (operation, _) = fixture.history(&history[0].reference)?;
    assert!(operation.dispatch_commit().is_none());
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
    Ok(())
}

#[test]
fn combined_owned_tool_error_and_postdispatch_drop_retain_every_claim_and_captured_budget(
) -> TestResult {
    use std::future::Future;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    for park in [false, true] {
        let fixture = CombinedFixture::new()?;
        let mut kernel = fixture.kernel(fixture.hook()?)?;
        kernel.register_tool_server(Box::new(UncertainTool {
            invocations: fixture.inner.invocations.clone(),
            park,
        }));
        if park {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    let mut invocation = Box::pin(kernel.evaluate_tool_call_with_metadata(
                        &fixture.inner.request,
                        Some(swarm_route_metadata()),
                    ));
                    std::future::poll_fn(|cx| {
                        let result = invocation.as_mut().poll(cx);
                        assert!(
                            result.is_pending(),
                            "combined parked tool finished: {result:?}"
                        );
                        if fixture.inner.invocations.load(Ordering::SeqCst) > 0 {
                            std::task::Poll::Ready(())
                        } else {
                            std::task::Poll::Pending
                        }
                    })
                    .await;
                    drop(invocation);
                });
        } else {
            let response = kernel.evaluate_tool_call_blocking_with_metadata(
                &fixture.inner.request,
                Some(swarm_route_metadata()),
            )?;
            assert_eq!(response.verdict, Verdict::Deny, "{response:#?}");
            assert!(response.receipt.verify_signature()?);
        }
        assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
        let history = faults::history(&fixture.inner)?;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].intent.resources().len(), 3);
        assert_eq!(
            history[0].disposition,
            RuntimeParticipantDisposition::RetainedAfterDispatchCommit
        );
        let (operation, _) = fixture.history(&history[0].reference)?;
        assert!(operation.dispatch_commit().is_some());
        assert_ne!(
            operation.state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        let usage = fixture
            .inner
            .authority
            .budget_store()
            .get_usage(&fixture.inner.request.capability.id, 0)?
            .ok_or("captured combined budget")?;
        assert_eq!(usage.invocation_count, 1);
        let raw =
            rusqlite::Connection::open(fixture.inner._directory.path().join("authority.sqlite3"))?;
        let released: i64 = raw.query_row(
            "SELECT count(*) FROM runtime_replay_claim_releases",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            released, 0,
            "post-dispatch cleanup cannot release replay custody"
        );
        drop(raw);
        let old_fence = fixture.inner.authority.mutation_fence();
        drop(kernel);
        let fixture = fixture.reopen()?;
        assert!(fixture
            .inner
            .authority
            .admission_operation_store()
            .load_runtime_participant_history(history[0].reference.operation_id(), &old_fence, NOW,)
            .is_err());
        let kernel = fixture.kernel(fixture.hook()?)?;
        kernel.reconcile_recoverable_admissions()?;
        let retry = kernel.evaluate_tool_call_blocking_with_metadata(
            &fixture.inner.request,
            Some(swarm_route_metadata()),
        );
        assert!(
            !retry
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Allow),
            "uncertain execution cannot acquire a fresh Allow: {retry:#?}"
        );
        assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.history(&history[0].reference)?.1, history);
        let usage = fixture
            .inner
            .authority
            .budget_store()
            .get_usage(&fixture.inner.request.capability.id, 0)?
            .ok_or("retained combined budget")?;
        assert_eq!(usage.invocation_count, 1);
    }
    Ok(())
}
