//! A failed approval-set reservation still unwinds runtime custody.

use super::threshold_crypto_floor::{Fixture, TestResult};
use super::*;
use std::sync::atomic::AtomicU64;

struct ReservingRuntimeHook {
    releases: Arc<AtomicU64>,
}

impl RuntimeAdmissionHook for ReservingRuntimeHook {
    fn name(&self) -> &str {
        "approval-reservation-cleanup"
    }

    fn evaluate(
        &self,
        _: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "admission_id": "approval-cleanup-admission",
                "accepted": true,
                "reserved_destructive_lease_id": "approval-cleanup-lease",
                "failure_code": null
            }
        }))))
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        assert_eq!(
            metadata["chio_runtime"]["reserved_destructive_lease_id"],
            "approval-cleanup-lease"
        );
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct TransferServer(Arc<AtomicU64>);

#[async_trait::async_trait]
impl ToolServerConnection for TransferServer {
    fn server_id(&self) -> &str {
        "threshold-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["transfer".into()]
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"transferred": true}))
    }
}

#[test]
fn failed_approval_reservation_releases_runtime_custody_when_the_budget_reverse_fails() -> TestResult
{
    for nested in [false, true] {
        let mut grant = make_grant("threshold-server", "transfer");
        grant.max_invocations = Some(4);
        let mut fixture = Fixture::with_grant(false, false, grant)?;
        let releases = Arc::new(AtomicU64::new(0));
        let invocations = Arc::new(AtomicU64::new(0));
        fixture
            .kernel
            .set_budget_store(Box::new(ReverseFailingBudgetStore::new()));
        fixture
            .kernel
            .set_runtime_admission_hook(Arc::new(ReservingRuntimeHook {
                releases: releases.clone(),
            }));
        fixture
            .kernel
            .register_tool_server(Box::new(TransferServer(invocations.clone())));
        let kernel = &fixture.kernel;
        let request = &fixture.request;
        let response = if nested {
            let session = kernel.open_session(request.agent_id.clone(), Vec::new())?;
            kernel.activate_session(&session)?;
            let parent =
                make_operation_context(&session, "approval-cleanup-parent", &request.agent_id);
            kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
            kernel.evaluate_tool_call_with_nested_flow_client(
                &parent,
                request,
                &mut NoopNestedFlowClient,
                None,
            )
        } else {
            kernel.evaluate_tool_call_blocking(request)
        };
        assert_eq!(releases.load(Ordering::SeqCst), 1, "{response:?}");
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        let response = response?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.receipt.verify_signature()?);
        let reason = response.reason.as_deref().ok_or("denial reason")?;
        assert!(
            reason.contains("threshold approval requires a durable admission operation")
                && reason.contains("pre-dispatch cleanup could not be confirmed"),
            "{reason}"
        );
        let metadata = response
            .receipt
            .metadata
            .as_ref()
            .ok_or("denial metadata")?;
        assert_eq!(
            metadata["budget_authority"]["pre_dispatch_cleanup_unconfirmed"],
            true
        );
        assert_eq!(
            metadata["chio_runtime"]["reserved_destructive_lease_id"],
            "approval-cleanup-lease"
        );
    }
    Ok(())
}
