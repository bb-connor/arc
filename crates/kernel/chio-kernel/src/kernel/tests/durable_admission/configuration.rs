use super::*;

#[test]
fn durable_admission_runtime_defaults_closed_and_off_requires_explicit_unsafe_ephemeral_mode() {
    use crate::admission_operation::{AdmissionOperationError, DurableAdmissionMode};

    let mut kernel = make_kernel(make_config());
    assert_eq!(
        kernel.durable_admission_mode(),
        DurableAdmissionMode::SideEffecting
    );
    assert_eq!(
        kernel.configure_durable_admission(DurableAdmissionMode::Off, false),
        Err(AdmissionOperationError::UnsafeDurableAdmissionOff)
    );
    kernel
        .configure_durable_admission(DurableAdmissionMode::Monetary, false)
        .expect("monetary qualification mode");
    assert_eq!(
        kernel.durable_admission_mode(),
        DurableAdmissionMode::Monetary
    );
    kernel
        .configure_durable_admission(DurableAdmissionMode::Off, true)
        .expect("explicit unsafe ephemeral mode");
    assert_eq!(kernel.durable_admission_mode(), DurableAdmissionMode::Off);

    let mut durable_config = make_config();
    durable_config.allow_ephemeral_receipt_log = false;
    let mut durable_kernel = make_kernel(durable_config);
    assert_eq!(
        durable_kernel.configure_durable_admission(DurableAdmissionMode::Off, true),
        Err(AdmissionOperationError::UnsafeDurableAdmissionOff)
    );
}

#[test]
fn financial_dispatch_without_durable_admission_is_refused(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::admission_operation::DurableAdmissionMode;

    for nested in [false, true] {
        let mut kernel =
            ChioKernel::new_with_clock(make_monetary_config(), chio_test_support::clock::clock());
        kernel.configure_durable_admission(DurableAdmissionMode::Off, true)?;
        let invocations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        kernel.register_tool_server(Box::new(CountingMonetaryServer {
            id: "ephemeral-cost-srv".to_string(),
            invocations: invocations.clone(),
        }));
        let agent = make_keypair();
        let grant = make_monetary_grant("ephemeral-cost-srv", "compute", 100, 1000, "USD");
        let capability = make_capability(&kernel, &agent, make_scope(vec![grant]), 300);
        let request = make_request(
            "ephemeral-financial-dispatch",
            &capability,
            "compute",
            "ephemeral-cost-srv",
        );
        let response = if nested {
            let session = kernel.open_session("ephemeral-financial-parent".into(), Vec::new())?;
            kernel.activate_session(&session)?;
            let parent = make_operation_context(
                &session,
                "ephemeral-financial-parent-request",
                "ephemeral-financial-parent",
            );
            kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
            kernel.evaluate_tool_call_with_nested_flow_client(
                &parent,
                &request,
                &mut NoopNestedFlowClient,
                None,
            )?
        } else {
            kernel.evaluate_tool_call_blocking(&request)?
        };
        assert_eq!(response.verdict, Verdict::Deny, "{response:?}");
        assert_eq!(
            response.reason.as_deref(),
            Some("financial tool dispatch requires durable admission coverage")
        );
        assert_eq!(
            invocations.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "nested={nested}"
        );
    }
    Ok(())
}

#[test]
fn side_effecting_mode_exempts_only_explicitly_read_only_tools() {
    struct ReadOnlyServer;

    #[async_trait::async_trait]
    impl ToolServerConnection for ReadOnlyServer {
        fn server_id(&self) -> &str {
            "read-only-server"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["lookup".to_owned()]
        }

        fn tool_is_read_only(&self, tool_name: &str) -> bool {
            tool_name == "lookup"
        }

        async fn invoke(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            Ok(serde_json::json!({"found": true}))
        }
    }

    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(ReadOnlyServer));
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("read-only-server", "lookup")]),
        300,
    );
    let request = make_request(
        "durable-read-only-classification",
        &capability,
        "lookup",
        "read-only-server",
    );
    let matching = resolve_required_matching_grants(
        &capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("matching read-only grant");

    assert!(kernel
        .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
        .expect("read-only classification")
        .is_none());
}

#[test]
fn finding_memory_lineage_requires_a_durable_terminal_projection() {
    let mut kernel = make_kernel(make_config());
    kernel
        .configure_durable_admission(crate::admission_operation::DurableAdmissionMode::Off, true)
        .expect("unsafe ephemeral mode for the regression");
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("memory-server", "write")]),
        300,
    );
    let mut request = make_request(
        "finding-memory-durable",
        &capability,
        "write",
        "memory-server",
    );
    request.arguments[crate::memory_provenance::FINDING_DELIVERY_RECEIPT_ID_ARGUMENT] =
        serde_json::json!("delivery-receipt");
    let matching = resolve_required_matching_grants(
        &capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("matching Finding memory grant");

    let error =
        match kernel.begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
        {
            Ok(_) => panic!("Finding memory lineage used an ephemeral terminal"),
            Err(error) => error,
        };
    assert!(error
        .to_string()
        .contains("no qualified admission operation store"));
}
