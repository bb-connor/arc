use super::*;

#[test]
fn chio_runtime_admission_hook_denies_before_tool_dispatch_and_records_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(DenyingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-deny",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("chio runtime admission denied")
    );
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["admission_id"], "adm-denied");
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "test_runtime_deny"
    );
    Ok(())
}

#[test]
fn chio_governed_request_without_runtime_hook_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-chio-runtime-no-hook",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "intent:chio:no-hook".to_string(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "verify Chio admission fails closed without a hook".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            "chioAdmission": {
                "admissionId": "adm-no-hook",
                "bundleSha256": "a".repeat(64)
            }
        })),
        body: Default::default(),
    });

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
    Ok(())
}

#[test]
fn chio_treaty_request_without_runtime_hook_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-chio-treaty-no-hook",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "intent:chio:treaty-no-hook".to_string(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "verify Chio treaty context fails closed without a hook".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            "chioTreaty": {
                "treatyScopeId": "treaty-buyer-vendor",
                "treatyScopeSha256": "b".repeat(64),
                "ladderIntersectionId": "intersection-live-1",
                "ladderIntersectionSha256": "c".repeat(64),
                "actionClassId": "workflow.destructive.vendor_call"
            }
        })),
        body: Default::default(),
    });

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_hook_denies_federated_call_before_dispatch_or_cosign(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.chio-buyer";
    let tool_host_kernel_id = "kernel.chio-vendor";

    let mut kernel = make_kernel(make_config());
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);
    let path = unique_receipt_db_path("chio-runtime-deny-no-cosign");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path)?))?;

    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let trust = KernelTrustExchange::new(tool_host_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_kp.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())?;
    let peer = handshake_and_pin(&trust, origin_kernel_id, &origin_kp, now);
    let mut kernel = kernel.with_federation_peers(vec![peer]);

    let cosigner_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_federation_cosigner(std::sync::Arc::new(CountingRejectingCosigner {
        calls: std::sync::Arc::clone(&cosigner_calls),
    }));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(DenyingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-chio-runtime-deny",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("chio runtime admission denied")
    );
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        cosigner_calls.load(Ordering::SeqCst),
        0,
        "runtime admission denial must not request federation cosign"
    );
    assert!(
        response.receipt.verify_signature()?,
        "deny response receipt signature must verify"
    );
    assert!(response.receipt.is_denied());
    assert_eq!(kernel.receipt_log().len(), 1);
    assert_eq!(kernel.receipt_log().receipts()[0].id, response.receipt.id);
    Ok(())
}

#[test]
fn federated_origin_without_runtime_hook_or_context_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.chio-buyer";
    let tool_host_kernel_id = "kernel.chio-vendor";

    let mut kernel = make_kernel(make_config());
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);
    let path = unique_receipt_db_path("federated-no-hook-no-context");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path)?))?;

    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let trust = KernelTrustExchange::new(tool_host_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_kp.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())?;
    let peer = handshake_and_pin(&trust, origin_kernel_id, &origin_kp, now);
    let kernel = kernel.with_federation_peers(vec![peer]);

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-federated-no-hook-no-context",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "missing_chio_treaty_context"
    );
    Ok(())
}

#[test]
fn chio_swarm_request_without_runtime_hook_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-chio-swarm-no-hook",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "intent:chio:swarm-no-hook".to_string(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "verify swarm authority fails closed without a runtime hook".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            "chioSwarm": {
                "taskGraph": {
                    "id": "swarm-task-graph-runtime",
                    "sha256": "a".repeat(64)
                },
                "continuationToken": {
                    "id": "swarm-continuation-runtime",
                    "sha256": "b".repeat(64)
                }
            }
        })),
        body: Default::default(),
    });

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
    Ok(())
}

#[test]
fn session_tool_call_preserves_chio_swarm_runtime_context() -> Result<(), Box<dyn std::error::Error>>
{
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-swarm-session-no-hook",
        &agent_kp.public_key().to_hex(),
    );
    let operation = SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability: cap,
        server_id: "srv-chio-runtime".to_string(),
        tool_name: "destructive_update".to_string(),
        arguments: serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent:chio:swarm-session-no-hook".to_string(),
            server_id: "srv-chio-runtime".to_string(),
            tool_name: "destructive_update".to_string(),
            purpose: "verify session swarm authority fails closed without a runtime hook"
                .to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({
                "chioSwarm": {
                    "taskGraph": {
                        "id": "swarm-task-graph-runtime",
                        "sha256": "a".repeat(64)
                    },
                    "continuationToken": {
                        "id": "swarm-continuation-runtime",
                        "sha256": "b".repeat(64)
                    }
                }
            })),
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
    }));

    let response = session_tool_call(kernel.evaluate_session_operation(&context, &operation)?)
        .ok_or_else(|| std::io::Error::other("tool call response missing"))?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_hook_allows_dispatch_and_records_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(AllowingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-allow",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let output = tool_call_value_output(response.output)
        .ok_or_else(|| std::io::Error::other("tool output missing"))?;
    assert_eq!(output["tool"], "destructive_update");
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("allow metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["admission_id"], "adm-allowed");
    assert_eq!(metadata["chio_runtime"]["accepted"], true);
    assert_eq!(metadata["chio_runtime"]["observe_only"], true);
    Ok(())
}

#[test]
fn chio_runtime_admission_hook_receives_route_metadata_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        MetadataInspectingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-route-metadata",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    let metadata = serde_json::json!({
        "route": {
            "bridge": "mcp",
            "protocolTarget": "mcp://provider-a"
        }
    });

    let response = kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(metadata))?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn chio_runtime_admission_hook_receives_nested_flow_route_metadata_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        MetadataInspectingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-runtime-nested-route-metadata",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability: cap,
        server_id: "srv-chio-runtime".to_string(),
        tool_name: "destructive_update".to_string(),
        arguments: serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: Some(serde_json::json!({
            "route": {
                "bridge": "mcp",
                "protocolTarget": "mcp://provider-a"
            }
        })),
    };
    let mut client = NoopNestedFlowClient;

    let response = kernel.evaluate_tool_call_operation_with_nested_flow_client(
        &context,
        &operation,
        &mut client,
    )?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| "allow metadata missing".to_string())?;
    assert_eq!(metadata["route"]["bridge"], "mcp");
    assert_eq!(metadata["route"]["protocolTarget"], "mcp://provider-a");
    assert_eq!(
        metadata["chio_runtime"]["admission_id"],
        "adm-route-metadata"
    );
    Ok(())
}

#[test]
fn chio_runtime_live_parent_and_vendor_calls_expose_package_valid_receipts(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-live",
        vec!["parent_decision", "vendor_quote"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        LiveReceiptAllowingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![
            make_grant("srv-chio-live", "parent_decision"),
            make_grant("srv-chio-live", "vendor_quote"),
        ]),
        300,
    );
    let parent_request = make_request_with_arguments(
        "req-chio-live-parent",
        &cap,
        "parent_decision",
        "srv-chio-live",
        serde_json::json!({"workflow": "chio-7.8", "step": "parent"}),
    );
    let vendor_request = make_request_with_arguments(
        "req-chio-live-vendor-a",
        &cap,
        "vendor_quote",
        "srv-chio-live",
        serde_json::json!({"workflow": "chio-7.8", "step": "vendor-a"}),
    );

    let parent_response = kernel.evaluate_tool_call_blocking(&parent_request)?;
    let vendor_response = kernel.evaluate_tool_call_blocking(&vendor_request)?;

    assert_eq!(admission_calls.load(Ordering::SeqCst), 2);
    assert_eq!(invocations.load(Ordering::SeqCst), 2);
    assert_package_valid_allow_receipt(&parent_response, &parent_request)?;
    assert_package_valid_allow_receipt(&vendor_response, &vendor_request)?;

    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 2);
    assert_eq!(receipt_log.receipts()[0].id, parent_response.receipt.id);
    assert_eq!(receipt_log.receipts()[1].id, vendor_response.receipt.id);
    assert_ne!(parent_response.receipt.id, vendor_response.receipt.id);
    Ok(())
}
