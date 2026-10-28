use super::*;

struct BoundaryServer {
    calls: Arc<AtomicUsize>,
    started: Arc<tokio::sync::Notify>,
    park_after_dispatch: bool,
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
        if !self.park_after_dispatch {
            self.started.notify_one();
            std::future::pending::<()>().await;
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
        if self.park_after_dispatch {
            self.started.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(serde_json::json!({"ok": true}))
    }
}

#[tokio::test]
async fn dropped_evaluation_releases_only_before_the_durable_effect_boundary() -> AnchoredTestResult
{
    for after_dispatch in [false, true] {
        let mut route = Route::new()?;
        let started = Arc::new(tokio::sync::Notify::new());
        route.kernel.register_tool_server(Box::new(BoundaryServer {
            calls: route.calls.clone(),
            started: started.clone(),
            park_after_dispatch: after_dispatch,
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
        if after_dispatch {
            assert_eq!(
                operation.state(),
                AdmissionOperationState::DispatchCommitted
            );
            route = route.restarted()?;
            assert_eq!(route.kernel.reconcile_durable_admission_startup()?, 1);
            assert_eq!(
                route.history(&request)?.0.state(),
                AdmissionOperationState::OutcomeUnknownAfterDispatch
            );
        } else {
            assert_eq!(
                operation.state(),
                AdmissionOperationState::CompensatedBeforeDispatch
            );
        }
        assert_eq!(
            route.calls.load(Ordering::SeqCst),
            usize::from(after_dispatch)
        );
        assert_eq!(route.legacy.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
