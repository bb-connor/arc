use super::*;

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

/// The invocation result a client sees, with the signed receipt removed.
fn client_fields_without_receipt(result: &AcpInvocationResult) -> String {
    let mut client = serde_json::to_value(result).test_unwrap();
    if let Some(receipt) = client.pointer_mut("/metadata/chio/receipt") {
        *receipt = Value::Null;
    }
    client.to_string()
}

#[test]
fn guard_denial_projects_only_its_family_code_and_text() {
    let _metrics_guard = metrics_test_guard();
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let (mut kernel, execution) =
        kernel_execution(Box::new(test_server()), "test-srv", "read_file");
    kernel.add_guard(Box::new(DetailGuard));
    let result = edge
        .invoke("read_file", json!({}), &kernel, &execution)
        .test_unwrap();

    assert!(!result.success);
    assert_eq!(
        result.error.as_deref(),
        Some("Request denied by policy guard")
    );
    let chio = &result.metadata.as_ref().test_unwrap()["chio"];
    assert_eq!(chio["decision"], "deny");
    assert_eq!(chio["denialCode"], "guard_denied");
    assert_eq!(chio["reason"], "Request denied by policy guard");
    assert!(
        chio["receipt"].to_string().contains(PRIVATE_DETAIL),
        "receipt lost the denial detail: {}",
        chio["receipt"]
    );
    let client = client_fields_without_receipt(&result);
    assert!(
        !client.contains(PRIVATE_DETAIL),
        "denial detail reached a client field: {client}"
    );
}
