use super::*;
use crate::tests::{
    kernel_for_server, metrics_test_guard, test_manifest, test_server, text_message,
};
use chio_kernel::KernelError;
use chio_test_support::prelude::*;

const PRIVATE_DETAIL: &str = "/srv/chio/tenant-7/private-key.json Bearer secret-token";

struct DetailGuard;

impl chio_kernel::Guard for DetailGuard {
    fn name(&self) -> &str {
        "detail-guard"
    }

    fn evidence_declaration(&self) -> chio_kernel::GuardEvidenceDeclaration {
        chio_kernel::GuardEvidenceDeclaration::SAFE
    }

    fn evaluate(
        &self,
        _ctx: &chio_kernel::GuardContext,
    ) -> Result<chio_kernel::GuardDecision, KernelError> {
        Err(KernelError::GuardDenied(PRIVATE_DETAIL.to_string()))
    }
}

/// The task response a client sees, with the signed receipt removed.
fn client_fields_without_receipt(response: &TaskResponse) -> String {
    let mut client = serde_json::to_value(response).test_unwrap();
    if let Some(receipt) = client.pointer_mut("/metadata/chio/receipt") {
        *receipt = Value::Null;
    }
    client.to_string()
}

#[test]
fn guard_denial_projects_only_its_family_code_and_text() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let (mut kernel, execution) = kernel_for_server(test_server());
    kernel.add_guard(Box::new(DetailGuard));
    let response = edge
        .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
        .test_unwrap();

    assert_eq!(response.status, TaskStatus::Failed);
    assert_eq!(
        response.status_message.as_deref(),
        Some("Request denied by policy guard")
    );
    let chio = &response.metadata.as_ref().test_unwrap()["chio"];
    assert_eq!(chio["decision"], "deny");
    assert_eq!(chio["denialCode"], "guard_denied");
    assert_eq!(chio["reason"], "Request denied by policy guard");
    assert!(
        chio["receipt"].to_string().contains(PRIVATE_DETAIL),
        "receipt lost the denial detail: {}",
        chio["receipt"]
    );
    let client = client_fields_without_receipt(&response);
    assert!(
        !client.contains(PRIVATE_DETAIL),
        "denial detail reached a client field: {client}"
    );
}

struct IncompleteToolServer;

#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for IncompleteToolServer {
    fn server_id(&self) -> &str {
        "test-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Err(KernelError::RequestIncomplete(PRIVATE_DETAIL.to_string()))
    }
}

#[test]
fn incomplete_denial_projects_the_generic_code_without_its_reason() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let (kernel, execution) = kernel_for_server(IncompleteToolServer);
    let response = edge
        .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
        .test_unwrap();

    assert_eq!(response.status, TaskStatus::Failed);
    assert_eq!(response.status_message.as_deref(), Some("Request denied"));
    let chio = &response.metadata.as_ref().test_unwrap()["chio"];
    assert_eq!(chio["denialCode"], "denied");
    assert_eq!(chio["reason"], "Request denied");
    assert!(
        chio["receipt"].to_string().contains(PRIVATE_DETAIL),
        "receipt lost the incomplete reason: {}",
        chio["receipt"]
    );
    let client = client_fields_without_receipt(&response);
    assert!(
        !client.contains(PRIVATE_DETAIL),
        "incomplete reason reached a client field: {client}"
    );
}

#[test]
fn pending_approval_status_message_is_the_fixed_approval_text() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let (kernel, execution) = kernel_for_server(test_server());
    let response = edge
        .project_pending_approval_for_test(
            "echo",
            &text_message("hello"),
            &kernel,
            &execution,
            PRIVATE_DETAIL,
        )
        .test_unwrap();

    assert_eq!(response.status, TaskStatus::Working);
    assert_eq!(
        response.status_message.as_deref(),
        Some("Approval required")
    );
}
