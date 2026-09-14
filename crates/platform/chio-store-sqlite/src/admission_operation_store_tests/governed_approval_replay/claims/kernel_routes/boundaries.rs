use super::*;

struct BoundaryServer {
    source: Arc<Source>,
    calls: Arc<AtomicUsize>,
    started: Arc<tokio::sync::Notify>,
    park_after_dispatch: Option<bool>,
}

#[async_trait::async_trait]
impl ToolServerConnection for BoundaryServer {
    fn server_id(&self) -> &str {
        "approval-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["tool".into()]
    }
    async fn prepare_delivery(
        &self,
        _: &chio_kernel::ToolDispatchContext,
    ) -> Result<(), KernelError> {
        match self.park_after_dispatch {
            None => self.source.state.lock().expect("state").panic_on = Some("verify"),
            Some(false) => {
                self.started.notify_one();
                std::future::pending::<()>().await;
            }
            Some(true) => {}
        }
        Ok(())
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.park_after_dispatch == Some(true) {
            self.started.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(serde_json::json!({"ok": true}))
    }
}

#[test]
fn source_failure_after_readiness_denies_and_releases_without_source_reverification(
) -> AnchoredTestResult {
    let mut route = Route::new()?;
    route.kernel.register_tool_server(Box::new(BoundaryServer {
        source: route.source.clone(),
        calls: route.calls.clone(),
        started: Arc::default(),
        park_after_dispatch: None,
    }));
    let request = route.request("source-after-readiness", &[1])?;
    let response = route.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("source verification")),
        "{:?}",
        response.reason
    );
    let (operation, history) = route.history(&request)?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].disposition,
        GovernedApprovalClaimDisposition::ReleasedBeforeDispatch
    );
    assert_eq!(route.calls.load(Ordering::SeqCst), 0);
    assert_eq!(route.legacy.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn dropped_evaluation_releases_only_before_the_durable_effect_boundary() -> AnchoredTestResult
{
    for after_dispatch in [false, true] {
        let mut route = Route::new()?;
        let started = Arc::new(tokio::sync::Notify::new());
        route.kernel.register_tool_server(Box::new(BoundaryServer {
            source: route.source.clone(),
            calls: route.calls.clone(),
            started: started.clone(),
            park_after_dispatch: Some(after_dispatch),
        }));
        let request = route.request("cancel-owned-approval", &[1])?;
        let mut evaluation = Box::pin(route.kernel.evaluate_tool_call(&request));
        tokio::select! {
            _ = started.notified() => {},
            result = &mut evaluation => panic!("evaluation completed before cancellation: {result:?}"),
            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => panic!("evaluation never reached its boundary"),
        }
        drop(evaluation);
        let (operation, history) = route.history(&request)?;
        assert_eq!(history.len(), 1);
        assert_eq!(
            history[0].disposition,
            if after_dispatch {
                GovernedApprovalClaimDisposition::RetainedAfterDispatchCommit
            } else {
                GovernedApprovalClaimDisposition::ReleasedBeforeDispatch
            }
        );
        assert_eq!(
            operation.state(),
            if after_dispatch {
                AdmissionOperationState::OutcomeUnknownAfterDispatch
            } else {
                AdmissionOperationState::CompensatedBeforeDispatch
            }
        );
        assert_eq!(
            route.calls.load(Ordering::SeqCst),
            usize::from(after_dispatch)
        );
        assert_eq!(route.legacy.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
