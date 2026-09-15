use super::*;

struct BoundaryServer {
    calls: Arc<AtomicUsize>,
    started: Arc<tokio::sync::Notify>,
    resume: Option<Arc<tokio::sync::Notify>>,
    after_dispatch: bool,
}
#[async_trait::async_trait]
impl ToolServerConnection for BoundaryServer {
    fn server_id(&self) -> &str {
        "dpop-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["tool".into()]
    }
    async fn prepare_delivery(
        &self,
        _: &chio_kernel::ToolDispatchContext,
    ) -> Result<(), KernelError> {
        if !self.after_dispatch {
            self.started.notify_one();
            if let Some(resume) = &self.resume {
                resume.notified().await;
            } else {
                std::future::pending::<()>().await;
            }
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
        if self.after_dispatch {
            self.started.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(serde_json::json!({"ok": true}))
    }
}

#[tokio::test]
async fn cancellation_releases_dpop_only_before_the_durable_dispatch_boundary() -> AnchoredTestResult
{
    for after_dispatch in [false, true] {
        let mut route = Route::new()?;
        let started = Arc::new(tokio::sync::Notify::new());
        route.kernel.register_tool_server(Box::new(BoundaryServer {
            calls: route.calls.clone(),
            started: started.clone(),
            resume: None,
            after_dispatch,
        }));
        let request = route.request("cancel-dpop", &[1])?;
        let mut evaluation = Box::pin(route.kernel.evaluate_tool_call(&request));
        tokio::select! {
            _ = started.notified() => {},
            result = &mut evaluation => panic!("evaluation completed before cancellation: {result:?}"),
            _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("evaluation did not reach the boundary"),
        }
        drop(evaluation);
        let (operation, history) = route.history(&request)?;
        assert_eq!(history.len(), 1);
        assert_eq!(
            history[0].disposition,
            if after_dispatch {
                DpopReplayClaimDisposition::RetainedAfterDispatchCommit
            } else {
                DpopReplayClaimDisposition::ReleasedBeforeDispatch
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
    }
    Ok(())
}

#[tokio::test]
async fn dpop_expiring_after_readiness_is_denied_and_released_before_capture() -> AnchoredTestResult
{
    let mut route = Route::new()?;
    let started = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    route.kernel.register_tool_server(Box::new(BoundaryServer {
        calls: route.calls.clone(),
        started: started.clone(),
        resume: Some(resume.clone()),
        after_dispatch: false,
    }));
    let request = route.request("expire-after-readiness", &[1])?;
    let expires = request
        .dpop_proof
        .as_ref()
        .ok_or("proof absent")?
        .body
        .issued_at
        + route.domain.proof_ttl_secs()
        + 1;
    let mut evaluation = Box::pin(route.kernel.evaluate_tool_call(&request));
    tokio::select! {
        _ = started.notified() => {},
        result = &mut evaluation => panic!("evaluation completed before readiness: {result:?}"),
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("evaluation did not reach readiness"),
    }
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expires, std::iter::empty());
    resume.notify_one();
    let response = evaluation.await?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("expired")),
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
        DpopReplayClaimDisposition::ReleasedBeforeDispatch
    );
    assert_eq!(route.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
