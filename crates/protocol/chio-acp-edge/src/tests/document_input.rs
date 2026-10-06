use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct ArgumentEchoServer {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ToolServerConnection for ArgumentEchoServer {
    fn server_id(&self) -> &str {
        "test-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["read_file".into()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(arguments)
    }
}

#[test]
fn unsigned_tool_arguments_accept_producer_decimal_spellings() {
    for (number, expected) in [
        ("0.50", 0.5),
        ("1e-05", 0.00001),
        ("1e+16", 1e16),
        ("18446744073709551616", 18446744073709551616.0),
    ] {
        let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let (kernel, execution) = kernel_execution(
            Box::new(ArgumentEchoServer {
                calls: calls.clone(),
            }),
            "test-srv",
            "read_file",
        );
        let bytes = format!(
            r#"{{"jsonrpc":"2.0","id":18446744073709551615,"method":"tool/invoke","params":{{"capabilityId":"read_file","arguments":{{"score":{number}}}}}}}"#
        );
        let response = edge
            .handle_jsonrpc(bytes.as_bytes(), &kernel, &execution)
            .test_unwrap();
        assert_eq!(response["id"].as_u64(), Some(u64::MAX));
        assert!(response.local_error().is_none(), "{response:?}");
        assert_eq!(response["result"]["success"], true);
        assert_eq!(response["result"]["data"]["score"].as_f64(), Some(expected));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(kernel.receipt_log().receipts().len(), 1);
    }
}

#[test]
fn peer_authority_fields_cannot_replace_the_typed_execution_context() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let (kernel, mut execution) = kernel_execution(
        Box::new(ArgumentEchoServer {
            calls: calls.clone(),
        }),
        "test-srv",
        "read_file",
    );
    let peer_capability = serde_json::to_string(&execution.capability).test_unwrap();
    execution.agent_id = "unbound-caller".into();
    for number in ["0.50", "1e-05", "9007199254740993", "18446744073709551616"] {
        let bytes = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tool/invoke","params":{{"capabilityId":"read_file","capabilityToken":{peer_capability},"executionNonce":{{"issued_at":{number}}},"arguments":{{"score":{number}}}}}}}"#
        );
        let response = edge
            .handle_jsonrpc(bytes.as_bytes(), &kernel, &execution)
            .test_unwrap();
        assert!(response.local_error().is_some() || response["result"]["success"] == false);
        assert_ne!(response["result"]["success"], true);
    }
    assert!(kernel.receipt_log().receipts().iter().all(|receipt| {
        receipt.decision != Some(chio_core::receipt::decision::Decision::Allow)
    }));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn peer_authority_duplicate_rejects_before_kernel_authorization() {
    let edge = new_test_edge(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let (kernel, execution) = kernel_execution(Box::new(test_server()), "test-srv", "read_file");
    let bytes = br#"{"jsonrpc":"2.0","id":1,"method":"tool/invoke","params":{"capabilityId":"read_file","capabilityToken":{"issued_at":1,"issued_at":2},"arguments":{"score":0.50}}}"#;
    assert!(matches!(
        edge.handle_jsonrpc(bytes, &kernel, &execution),
        Err(AcpEdgeError::UntrustedInput(_))
    ));
    assert!(kernel.receipt_log().receipts().is_empty());
}
