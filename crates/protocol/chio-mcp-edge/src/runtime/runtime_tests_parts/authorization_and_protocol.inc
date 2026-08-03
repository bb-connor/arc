#[test]
fn bridge_mcp_kernel_request_preserves_complete_authorization_context() {
    let (kernel, issuer) = make_kernel();
    let subject = Keypair::generate();
    let capability = issue_aggregate_family_capability(&kernel, &issuer, &subject);
    let aggregate_budget = capability
        .aggregate_invocation_budget
        .clone()
        .expect("aggregate family budget");
    assert!(aggregate_budget.root_binding.is_some());
    let governed_intent = active_response_intent(&subject);
    let request_id = "mcp-bridge-preservation";
    let (approval_tokens, proposal, supplemental) =
        adapter_authorization_artifacts(&subject, request_id);
    let bridge_request = BridgeMcpToolCallRequest {
        request_id: request_id.to_string(),
        capability: capability.clone(),
        server_id: "srv".to_string(),
        tool_name: "read_file".to_string(),
        arguments: json!({"path":"/tmp/preserve"}),
        agent_id: subject.public_key().to_hex(),
        execution_nonce: None,
        governed_intent: Some(governed_intent.clone()),
        approval_token: None,
        approval_tokens: approval_tokens.clone(),
        threshold_approval_proposal: Some(proposal.clone()),
        model_metadata: None,
        supplemental_authorization: Some(supplemental.clone()),
        route_selection_metadata: None,
        peer_supports_chio_tool_streaming: false,
    };

    let kernel_request = bridge_request.to_tool_call_request().unwrap();

    assert_eq!(
        serde_json::to_value(&kernel_request.capability).unwrap(),
        serde_json::to_value(&capability).unwrap()
    );
    assert_eq!(
        kernel_request.capability.aggregate_invocation_budget,
        Some(aggregate_budget)
    );
    assert_eq!(kernel_request.governed_intent, Some(governed_intent));
    assert_eq!(kernel_request.approval_tokens, approval_tokens);
    assert_eq!(kernel_request.threshold_approval_proposal, Some(proposal));
    assert_eq!(
        kernel_request.supplemental_authorization,
        Some(supplemental)
    );
}

#[test]
fn tools_call_meta_preserves_complete_authorization_context() {
    let mut edge = make_edge(10);
    initialize_edge_with_protocol_features(&mut edge, &threshold_and_broker_protocol_features());
    let subject = Keypair::generate();
    let request_id = "mcp-session-preservation";
    let (approval_tokens, proposal, supplemental) =
        adapter_authorization_artifacts(&subject, request_id);
    let params = json!({
        "name": "read_file",
        "arguments": {"path":"/tmp/preserve"},
        "_meta": {
            "approvalTokens": serde_json::to_value(&approval_tokens).unwrap(),
            "thresholdApprovalProposal": serde_json::to_value(&proposal).unwrap(),
            "supplementalAuthorization": serde_json::to_value(&supplemental).unwrap()
        }
    });

    let (_, _, operation) = edge
        .prepare_tool_call_request(&json!(73), &params)
        .expect("authenticated Chio extensions should parse");

    assert_eq!(operation.approval_tokens, approval_tokens);
    assert_eq!(operation.threshold_approval_proposal, Some(proposal));
    assert_eq!(operation.supplemental_authorization, Some(supplemental));
}

#[test]
fn tools_call_meta_accepts_singular_legacy_approval_without_threshold_negotiation() {
    let mut edge = make_edge(10);
    initialize_edge(&mut edge);
    let subject = Keypair::generate();
    let approval = legacy_approval_token(&subject, "mcp-legacy-singular");
    let params = json!({
        "name": "read_file",
        "arguments": {"path":"/tmp/legacy-singular"},
        "_meta": {
            "approvalToken": serde_json::to_value(&approval).unwrap()
        }
    });

    let (_, _, operation) = edge
        .prepare_tool_call_request(&json!(75), &params)
        .expect("legacy singular approval must pass compatibility negotiation");

    assert_eq!(operation.approval_token, Some(approval));
    assert!(operation.approval_tokens.is_empty());
    assert!(operation.threshold_approval_proposal.is_none());
}

#[test]
fn mcp_unnegotiated_authorization_extensions_deny_before_receipt_or_dispatch() {
    let mut edge = make_edge(10);
    initialize_edge(&mut edge);
    let subject = Keypair::generate();
    let request_id = "mcp-session-unnegotiated";
    let (approval_tokens, proposal, supplemental) =
        adapter_authorization_artifacts(&subject, request_id);
    let singular_approval = approval_tokens[0].clone();
    let receipt_count_before = edge.kernel.receipt_log().len();

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 74,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path":"/tmp/unnegotiated"},
                "_meta": {
                    "approvalTokens": approval_tokens,
                    "thresholdApprovalProposal": proposal,
                    "supplementalAuthorization": supplemental
                }
            }
        }))
        .expect("unnegotiated request must return a JSON-RPC error");

    assert_eq!(response["error"]["code"], JSONRPC_INVALID_PARAMS);
    assert!(response["error"]["message"]
        .as_str()
        .is_some_and(|message| message.contains(THRESHOLD_GOVERNED_APPROVALS)));
    assert_eq!(edge.kernel.receipt_log().len(), receipt_count_before);

    let singular_response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 75,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path":"/tmp/unnegotiated-singular"},
                "_meta": {
                    "approvalToken": singular_approval
                }
            }
        }))
        .expect("singular unnegotiated approval must return a JSON-RPC error");
    assert_eq!(singular_response["error"]["code"], JSONRPC_INVALID_PARAMS);
    assert!(singular_response["error"]["message"]
        .as_str()
        .is_some_and(|message| message.contains(THRESHOLD_GOVERNED_APPROVALS)));
    assert_eq!(edge.kernel.receipt_log().len(), receipt_count_before);
}

#[test]
fn execute_bridge_mcp_tool_call_preserves_model_metadata() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capability = issue_model_constrained_capability(&kernel, &agent);

    let bridge = execute_bridge_mcp_tool_call(
        &kernel,
        BridgeMcpToolCallRequest {
            request_id: "mcp-model-1".to_string(),
            capability,
            server_id: "srv".to_string(),
            tool_name: "read_file".to_string(),
            arguments: json!({"path":"/tmp/demo.txt"}),
            agent_id: agent.public_key().to_hex(),
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: Some(ModelMetadata {
                model_id: "gpt-5".to_string(),
                safety_tier: Some(ModelSafetyTier::High),
                provider: Some("openai".to_string()),
                provenance_class: ProvenanceEvidenceClass::Asserted,
            }),
            supplemental_authorization: None,
            route_selection_metadata: None,
            peer_supports_chio_tool_streaming: false,
        },
    )
    .unwrap();

    assert!(matches!(bridge.response.verdict, Verdict::Allow));
}

#[test]
fn pending_approval_receipt_write_uses_pending_outcome_label() {
    let _metrics_guard = metrics_test_guard();
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capability = issue_capabilities(&kernel, &agent).remove(0);
    let bridge = execute_bridge_mcp_tool_call(
        &kernel,
        BridgeMcpToolCallRequest {
            request_id: "mcp-pending-seed".to_string(),
            capability,
            server_id: "srv".to_string(),
            tool_name: "read_file".to_string(),
            arguments: json!({"path":"/tmp/demo.txt"}),
            agent_id: agent.public_key().to_hex(),
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            supplemental_authorization: None,
            route_selection_metadata: None,
            peer_supports_chio_tool_streaming: false,
        },
    )
    .unwrap();
    let before_pending = crate::receipt_write_total(crate::RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL);

    let mut response = bridge.response;
    response.verdict = Verdict::PendingApproval;
    response.reason = Some("approval required".to_string());
    response.output = None;
    response.terminal_state = OperationTerminalState::Incomplete {
        reason: "approval required".to_string(),
    };
    let projected =
        BridgeMcpToolCall::from_kernel_response(response, "mcp-pending-1", false).unwrap();

    assert!(matches!(
        projected.response.verdict,
        Verdict::PendingApproval
    ));
    assert_eq!(projected.mcp_result["isError"], true);
    assert!(
        crate::receipt_write_total(crate::RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL) > before_pending
    );
    assert_eq!(
        crate::metrics::receipt_write_outcome_for_verdict(Verdict::PendingApproval),
        crate::RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL
    );
    assert!(
        crate::render_mcp_edge_metrics_prometheus(chio_kernel::ReceiptWriterLiveness::Healthy)
            .contains("outcome=\"pending_approval\"")
    );
}

#[test]
fn tools_call_jsonrpc_path_records_receipt_write_allow() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = make_edge_with_config(10, false);
    initialize_edge(&mut edge);
    let before_allow = crate::receipt_write_total(crate::RECEIPT_WRITE_OUTCOME_ALLOW);

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/demo.txt" }
            }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], false);
    assert!(
        crate::receipt_write_total(crate::RECEIPT_WRITE_OUTCOME_ALLOW) > before_allow,
        "MCP JSON-RPC allow path must advance receipt write metrics"
    );
}

#[test]
fn tools_call_jsonrpc_preserves_governed_swarm_context() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = make_edge_with_config(10, false);
    initialize_edge(&mut edge);
    let before_deny = crate::receipt_write_total(crate::RECEIPT_WRITE_OUTCOME_DENY);

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/demo.txt" },
                "_meta": {
                    "governedIntent": {
                        "schema": "chio.governed-transaction-intent.v2",
                        "kind": "tool_invocation",
                        "body": {
                            "id": "intent:chio:mcp-swarm-no-hook",
                            "server_id": "srv",
                            "tool_name": "read_file",
                            "purpose": "verify MCP swarm authority fails closed without a runtime hook",
                            "context": {
                                "chioSwarm": {
                                    "taskGraph": {
                                        "id": "swarm-task-graph-runtime",
                                        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                    },
                                    "continuationToken": {
                                        "id": "swarm-continuation-runtime",
                                        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], true, "{response}");
    assert!(
        crate::receipt_write_total(crate::RECEIPT_WRITE_OUTCOME_DENY) > before_deny,
        "MCP JSON-RPC governed swarm path must deny before tool execution"
    );
}

#[test]
fn tools_call_jsonrpc_passes_route_selection_metadata_to_runtime_admission() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = make_edge_with_route_selection_admission(10);
    initialize_edge(&mut edge);

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/demo.txt" },
                "_meta": {
                    "routeSelection": {
                        "selectedRouteId": "mcp:task-child-a",
                        "selectedTargetProtocol": "mcp"
                    }
                }
            }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], false);
}

#[test]
fn tools_call_jsonrpc_path_records_receipt_write_deny() {
    let _metrics_guard = metrics_test_guard();
    let (kernel, _) = make_kernel();
    let caller = Keypair::generate();
    let capability_subject = Keypair::generate();
    let capabilities = issue_capabilities(&kernel, &capability_subject);
    let mut edge = ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig::default(),
        kernel,
        caller.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();
    initialize_edge(&mut edge);
    let before_deny = crate::receipt_write_total(crate::RECEIPT_WRITE_OUTCOME_DENY);

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/demo.txt" }
            }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], true);
    assert!(
        crate::receipt_write_total(crate::RECEIPT_WRITE_OUTCOME_DENY) > before_deny,
        "MCP JSON-RPC deny path must advance receipt write metrics"
    );
}

#[test]
fn tools_call_jsonrpc_path_skips_receipt_write_error_for_url_elicitation() {
    let _metrics_guard = metrics_test_guard();
    assert_kernel_error_not_counted_as_receipt_write(&url_required_kernel_error());
    let mut edge = make_url_required_edge();
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "elicitation": {
                    "url": {}
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "authorize",
                "arguments": {}
            }
        }))
        .unwrap();

    assert_eq!(response["error"]["code"], JSONRPC_URL_ELICITATION_REQUIRED);
}

#[test]
fn tool_call_error_outcome_records_receipt_write_error_for_kernel_error() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = make_edge(10);
    initialize_edge(&mut edge);
    let (session_id, _context, _operation) = edge
        .prepare_tool_call_request(
            &json!(2),
            &json!({
                "name": "read_file",
                "arguments": { "path": "/tmp/demo.txt" }
            }),
        )
        .unwrap();
    let before_error = crate::receipt_write_total(crate::RECEIPT_WRITE_OUTCOME_ERROR);

    let outcome = edge.tool_call_error_outcome(
        &session_id,
        KernelError::Internal("receipt sink unavailable".to_string()),
        None,
    );

    assert!(
        matches!(
            outcome,
            ToolCallEdgeOutcome::Result(result) if result["isError"] == true
        ),
        "kernel infrastructure errors should return an MCP tool error result"
    );
    assert!(
        crate::receipt_write_total(crate::RECEIPT_WRITE_OUTCOME_ERROR) > before_error,
        "MCP KernelError path must advance receipt write error metrics"
    );
}

#[test]
fn kernel_error_records_receipt_write_error_outcome() {
    let _metrics_guard = metrics_test_guard();
    let (kernel, _) = make_web3_required_kernel();
    let agent = Keypair::generate();
    let capability = issue_capabilities(&kernel, &agent).remove(0);
    let before_error = crate::receipt_write_total(crate::RECEIPT_WRITE_OUTCOME_ERROR);

    let error = execute_bridge_mcp_tool_call(
        &kernel,
        BridgeMcpToolCallRequest {
            request_id: "mcp-error-1".to_string(),
            capability,
            server_id: "srv".to_string(),
            tool_name: "read_file".to_string(),
            arguments: json!({"path":"/tmp/demo.txt"}),
            agent_id: agent.public_key().to_hex(),
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            supplemental_authorization: None,
            route_selection_metadata: None,
            peer_supports_chio_tool_streaming: false,
        },
    )
    .unwrap_err();

    assert!(matches!(
        error,
        AdapterError::KernelRuntime(message)
            if message.contains("web3 evidence prerequisites unavailable")
    ));
    assert!(
        crate::receipt_write_total(crate::RECEIPT_WRITE_OUTCOME_ERROR) > before_error,
        "mcp kernel error path must advance receipt write error"
    );
}

#[test]
fn execute_bridge_mcp_tool_call_blocking_skips_receipt_write_error_for_request_cancelled() {
    let _metrics_guard = metrics_test_guard();
    assert_kernel_error_not_counted_as_receipt_write(&cancelled_kernel_error());
    let (kernel, request) = make_kernel_error_bridge_fixture(
        Box::new(CancelledServer),
        "cancel-srv",
        "cancel",
        "mcp-cancelled-blocking",
    );
    // execute_bridge_mcp_tool_call drives the kernel's sync tool-dispatch
    // bridge, which requires a multi-thread runtime (the documented host
    // requirement); a current-thread runtime cannot drive the async tool server.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let bridge =
        runtime.block_on(async { execute_bridge_mcp_tool_call(&kernel, request).unwrap() });

    assert!(matches!(
        bridge.response.terminal_state,
        OperationTerminalState::Cancelled { reason }
            if reason == "cancelled by direct bridge test"
    ));
}

#[test]
fn execute_bridge_mcp_tool_call_blocking_skips_receipt_write_error_for_url_elicitation() {
    let _metrics_guard = metrics_test_guard();
    assert_kernel_error_not_counted_as_receipt_write(&url_required_kernel_error());
    let (kernel, request) = make_kernel_error_bridge_fixture(
        Box::new(UrlRequiredServer),
        "url-srv",
        "authorize",
        "mcp-url-required-blocking",
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let error =
        runtime.block_on(async { execute_bridge_mcp_tool_call(&kernel, request).unwrap_err() });

    assert!(matches!(
        error,
        AdapterError::KernelRuntime(message) if message.contains("URL elicitation")
    ));
}

#[test]
fn execute_bridge_mcp_tool_call_async_skips_receipt_write_error_for_request_cancelled() {
    let _metrics_guard = metrics_test_guard();
    assert_kernel_error_not_counted_as_receipt_write(&cancelled_kernel_error());
    let (kernel, request) = make_kernel_error_bridge_fixture(
        Box::new(CancelledServer),
        "cancel-srv",
        "cancel",
        "mcp-cancelled-async",
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let bridge = runtime
        .block_on(execute_bridge_mcp_tool_call_async(&kernel, request))
        .unwrap();

    assert!(matches!(
        bridge.response.terminal_state,
        OperationTerminalState::Cancelled { reason }
            if reason == "cancelled by direct bridge test"
    ));
}

#[test]
fn execute_bridge_mcp_tool_call_async_skips_receipt_write_error_for_url_elicitation() {
    let _metrics_guard = metrics_test_guard();
    assert_kernel_error_not_counted_as_receipt_write(&url_required_kernel_error());
    let (kernel, request) = make_kernel_error_bridge_fixture(
        Box::new(UrlRequiredServer),
        "url-srv",
        "authorize",
        "mcp-url-required-async",
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let error = runtime
        .block_on(execute_bridge_mcp_tool_call_async(&kernel, request))
        .unwrap_err();

    assert!(matches!(
        error,
        AdapterError::KernelRuntime(message) if message.contains("URL elicitation")
    ));
}

#[tokio::test]
async fn execute_bridge_mcp_tool_call_async_preserves_model_metadata() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capability = issue_model_constrained_capability(&kernel, &agent);

    let bridge = execute_bridge_mcp_tool_call_async(
        &kernel,
        BridgeMcpToolCallRequest {
            request_id: "mcp-model-async-1".to_string(),
            capability,
            server_id: "srv".to_string(),
            tool_name: "read_file".to_string(),
            arguments: json!({"path":"/tmp/demo.txt"}),
            agent_id: agent.public_key().to_hex(),
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: Some(ModelMetadata {
                model_id: "gpt-5".to_string(),
                safety_tier: Some(ModelSafetyTier::High),
                provider: Some("openai".to_string()),
                provenance_class: ProvenanceEvidenceClass::Asserted,
            }),
            supplemental_authorization: None,
            route_selection_metadata: None,
            peer_supports_chio_tool_streaming: false,
        },
    )
    .await
    .unwrap();

    assert!(matches!(bridge.response.verdict, Verdict::Allow));
}

#[test]
fn tools_call_uses_meta_model_metadata_and_records_asserted_provenance() {
    let mut edge = make_model_constrained_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let denied = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/demo.txt" }
            }
        }))
        .unwrap();
    assert_eq!(denied["result"]["isError"], true);

    let allowed = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/demo.txt" },
                "_meta": {
                    "modelMetadata": {
                        "model_id": "gpt-5",
                        "safety_tier": "high",
                        "provider": "openai",
                        "provenance_class": "verified"
                    }
                }
            }
        }))
        .unwrap();
    assert_eq!(allowed["result"]["isError"], false);

    let receipt_log = edge.kernel.receipt_log();
    let receipts = receipt_log.receipts();
    let receipt = receipts.last().expect("tool call receipt");
    let metadata = receipt.metadata.as_ref().expect("receipt metadata");
    assert_eq!(metadata["model_metadata"]["model_id"], "gpt-5");
    assert_eq!(metadata["model_metadata"]["provenance_class"], "asserted");
}

fn make_streaming_edge(page_size: usize) -> ChioMcpEdge {
    let (kernel, _) = make_streaming_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_streaming_capabilities(&kernel, &agent);
    ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig {
            server_name: "Chio MCP Edge".to_string(),
            server_version: "0.1.0".to_string(),
            page_size,
            tools_list_changed: false,
            completion_enabled: None,
            resources_subscribe: false,
            resources_list_changed: false,
            prompts_list_changed: false,
            logging_enabled: false,
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest(), streaming_manifest()],
    )
    .unwrap()
}

fn make_url_required_edge() -> ChioMcpEdge {
    let keypair = Keypair::generate();
    let config = KernelConfig {
        keypair: keypair.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "edge-policy".to_string(),
        allow_sampling: true,
        allow_sampling_tool_use: false,
        allow_elicitation: true,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(UrlRequiredServer));
    let agent = Keypair::generate();
    let capabilities = vec![kernel
        .issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "url-srv".to_string(),
                    tool_name: "authorize".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            300,
        )
        .unwrap()];

    ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![ToolManifest {
            schema: chio_manifest::TOOL_MANIFEST_SCHEMA.into(),
            server_id: "url-srv".into(),
            name: "URL Required Server".into(),
            description: Some("url required test".into()),
            version: "0.1.0".into(),
            tools: vec![ToolDefinition {
                name: "authorize".into(),
                description: "Requires URL elicitation".into(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                },
                latency_hint: Some(LatencyHint::Moderate),
                flow: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: Keypair::from_seed(&[9u8; 32]).public_key().to_hex(),
        }],
    )
    .unwrap()
}

fn make_event_edge(server: Arc<AsyncEventServer>) -> ChioMcpEdge {
    let keypair = Keypair::generate();
    let config = KernelConfig {
        keypair: keypair.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "edge-policy".to_string(),
        allow_sampling: true,
        allow_sampling_tool_use: false,
        allow_elicitation: true,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(AsyncEventServerConnection(server)));
    kernel.register_resource_provider(Box::new(DocsResourceProvider));
    kernel.register_prompt_provider(Box::new(ExamplePromptProvider));
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_operations(
        &kernel,
        &agent,
        vec![Operation::Read, Operation::Subscribe],
    );

    ChioMcpEdge::new_from_unverified_internal(
        McpEdgeConfig {
            tools_list_changed: true,
            resources_subscribe: true,
            resources_list_changed: true,
            prompts_list_changed: true,
            ..McpEdgeConfig::default()
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap()
}

fn ready_session_id(edge: &ChioMcpEdge) -> SessionId {
    match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        other => panic!("expected ready session, got {other:?}"),
    }
}

fn register_pending_url_elicitation(
    edge: &mut ChioMcpEdge,
    elicitation_id: &str,
    related_task_id: Option<&str>,
) {
    let session_id = ready_session_id(edge);
    edge.kernel
        .register_session_pending_url_elicitation(
            &session_id,
            elicitation_id.to_string(),
            related_task_id.map(ToString::to_string),
        )
        .unwrap();
}

#[test]
fn initialize_then_initialized_enters_ready_state() {
    let mut edge = make_edge(10);

    let initialize = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap();

    assert_eq!(
        initialize["result"]["protocolVersion"],
        MCP_PROTOCOL_VERSION
    );
    assert_eq!(
        initialize["result"]["capabilities"]["tools"]["listChanged"],
        false
    );
    assert_eq!(
        initialize["result"]["capabilities"]["resources"]["subscribe"],
        false
    );
    assert_eq!(
        initialize["result"]["capabilities"]["prompts"]["listChanged"],
        false
    );
    assert_eq!(
        initialize["result"]["capabilities"]["completions"],
        json!({})
    );
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"][CHIO_TOOL_STREAMING_CAPABILITY_KEY]
            ["toolCallChunkNotifications"],
        true
    );
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"][CHIO_PROTOCOL_CAPABILITY_KEY]
            ["supportedProtocolVersions"],
        json!([MCP_PROTOCOL_VERSION])
    );
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"][CHIO_PROTOCOL_CAPABILITY_KEY]
            ["selectedProtocolVersion"],
        MCP_PROTOCOL_VERSION
    );
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"][CHIO_PROTOCOL_CAPABILITY_KEY]
            ["compatibility"],
        "exact_match"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"][CHIO_PROTOCOL_CAPABILITY_KEY]
            ["downgradeBehavior"],
        "reject"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"][CHIO_PROTOCOL_CAPABILITY_KEY]
            ["requestIdentity"]["stableRequestIdMetaField"],
        "chioRequestId"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"][CHIO_PROTOCOL_CAPABILITY_KEY]
            ["requestIdentity"]["requestBoundArtifactsRequireStableId"],
        true
    );
    assert_eq!(
        initialize["result"]["capabilities"]["tasks"]["list"],
        json!({})
    );
    assert_eq!(
        initialize["result"]["capabilities"]["tasks"]["cancel"],
        json!({})
    );
    assert_eq!(
        initialize["result"]["capabilities"]["tasks"]["requests"]["tools"]["call"],
        json!({})
    );
    assert!(initialize["result"]["capabilities"]
        .get("logging")
        .is_none());

    let initialized = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
    assert!(initialized.is_none());
    assert!(matches!(edge.state, EdgeState::Ready { .. }));
}

#[test]
fn external_request_identity_is_unique_without_a_caller_stable_id() {
    let first = build_operation_context(
        &json!(41),
        SessionId::new("stable-session-a"),
        "agent",
        "tools/call",
        &json!({}),
    )
    .unwrap();
    let replay = build_operation_context(
        &json!(41),
        SessionId::new("stable-session-a"),
        "agent",
        "tools/call",
        &json!({}),
    )
    .unwrap();
    let other_session = build_operation_context(
        &json!(41),
        SessionId::new("stable-session-b"),
        "agent",
        "tools/call",
        &json!({}),
    )
    .unwrap();
    let other_request = build_operation_context(
        &json!(42),
        SessionId::new("stable-session-a"),
        "agent",
        "tools/call",
        &json!({}),
    )
    .unwrap();

    assert_ne!(first.request_id, replay.request_id);
    assert_ne!(first.request_id, other_session.request_id);
    assert_ne!(first.request_id, other_request.request_id);
    assert!(first.request_id.as_str().starts_with("mcp-edge-req-"));
}

#[test]
fn caller_supplied_request_identity_is_stable_across_sessions() {
    let first = build_operation_context(
        &json!(41),
        SessionId::new("caller-session-a"),
        "agent",
        "tools/call",
        &json!({
            "_meta": {
                "chioRequestId": "caller-stable-request"
            }
        }),
    )
    .expect("caller request ID should build");
    let replay = build_operation_context(
        &json!(99),
        SessionId::new("caller-session-b"),
        "agent",
        "tools/call",
        &json!({
            "_meta": {
                "chioRequestId": "caller-stable-request",
                "progressToken": "retry"
            }
        }),
    )
    .expect("caller request ID replay should build");

    assert_eq!(first.request_id.as_str(), "caller-stable-request");
    assert_eq!(first.request_id, replay.request_id);
}

#[test]
fn caller_supplied_request_identity_rejects_invalid_values() {
    for invalid in [
        Value::Null,
        json!(""),
        json!(" padded"),
        json!("control\ncharacter"),
        json!("x".repeat(2_049)),
    ] {
        let error = build_operation_context(
            &json!(41),
            SessionId::new("caller-session"),
            "agent",
            "tools/call",
            &json!({
                "_meta": {
                    "chioRequestId": invalid
                }
            }),
        )
        .expect_err("invalid caller request ID must be rejected");
        assert_eq!(error["error"]["code"], JSONRPC_INVALID_PARAMS);
    }
}

#[test]
fn request_bound_artifacts_require_a_caller_supplied_request_identity() {
    let mut edge = make_edge(10);
    initialize_edge_with_protocol_features(&mut edge, &threshold_and_broker_protocol_features());
    let params = json!({
        "name": "read_file",
        "arguments": { "path": "/tmp/demo.txt" },
        "_meta": {
            "supplementalAuthorization": {
                "reference": "opaque",
                "artifact": [1]
            }
        }
    });
    let error = edge
        .prepare_tool_call_request(&json!(2), &params)
        .expect_err("request-bound artifacts must require a stable request ID");
    assert_eq!(error["error"]["code"], JSONRPC_INVALID_PARAMS);
    assert!(error["error"]["message"]
        .as_str()
        .is_some_and(|message| message.contains("_meta.chioRequestId")));

    let mut stable_params = params;
    stable_params["_meta"]["chioRequestId"] = json!("mcp-stable-authorization-request");
    let (_session_id, context, operation) = edge
        .prepare_tool_call_request(&json!(2), &stable_params)
        .expect("stable request ID path should accept request-bound artifacts");
    assert_eq!(
        context.request_id.as_str(),
        "mcp-stable-authorization-request"
    );
    assert!(operation.supplemental_authorization.is_some());
}

#[test]
fn configured_kernel_session_id_is_identical_on_fresh_initialize_and_restore() {
    let authoritative_session_id = SessionId::new(format!(
        "sess-{}",
        Keypair::generate().public_key().to_hex()
    ));
    let mut fresh_edge = make_edge(10);
    fresh_edge
        .set_initial_session_id(authoritative_session_id.clone())
        .unwrap();
    initialize_edge(&mut fresh_edge);
    assert_eq!(ready_session_id(&fresh_edge), authoritative_session_id);

    let mut restored_edge = make_edge(10);
    restored_edge
        .restore_ready_session(
            authoritative_session_id.clone(),
            PeerCapabilities::default(),
        )
        .unwrap();
    assert_eq!(ready_session_id(&restored_edge), authoritative_session_id);
}

#[test]
fn malformed_initialized_notification_does_not_enter_ready_state() {
    let mut edge = make_edge(10);

    let initialize = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap();
    assert_eq!(
        initialize["result"]["protocolVersion"],
        MCP_PROTOCOL_VERSION
    );
    assert!(matches!(
        edge.state,
        EdgeState::WaitingForInitialized { .. }
    ));

    let initialized = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": []
    }));
    assert!(initialized.is_none());
    assert!(matches!(
        edge.state,
        EdgeState::WaitingForInitialized { .. }
    ));

    let tools_list = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }))
        .unwrap();
    assert_eq!(tools_list["error"]["code"], JSONRPC_SERVER_NOT_INITIALIZED);
}

#[test]
fn initialize_unsupported_protocol_version_rejected() {
    let mut edge = make_edge(10);

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-01-01"
            }
        }))
        .unwrap();

    assert_eq!(response["error"]["code"], JSONRPC_INVALID_REQUEST);
    assert_eq!(response["error"]["message"], "unsupported protocolVersion");
    assert_eq!(
        response["error"]["data"]["chioError"]["code"],
        CHIO_ERROR_PROTOCOL_VERSION_UNSUPPORTED
    );
    assert_eq!(
        response["error"]["data"]["chioError"]["name"],
        "protocol_version_unsupported"
    );
    assert_eq!(
        response["error"]["data"]["chioError"]["category"],
        "protocol"
    );
    assert_eq!(response["error"]["data"]["chioError"]["transient"], false);
    assert_eq!(
        response["error"]["data"]["chioError"]["retry"]["strategy"],
        "do_not_retry_until_version_change"
    );
    assert_eq!(
        response["error"]["data"]["requestedProtocolVersion"],
        "2024-01-01"
    );
    assert_eq!(
        response["error"]["data"]["supportedProtocolVersions"],
        json!([MCP_PROTOCOL_VERSION])
    );
    assert!(matches!(edge.state, EdgeState::Uninitialized));
}

#[test]
fn initialize_rejects_non_object_params_without_opening_session() {
    let mut edge = make_edge(10);
    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": []
        }))
        .unwrap();

    assert_eq!(response["error"]["code"], JSONRPC_INVALID_PARAMS);
    assert_eq!(
        response["error"]["message"],
        "initialize params must be an object"
    );
    assert!(matches!(edge.state, EdgeState::Uninitialized));
}

#[test]
fn tools_list_is_paginated() {
    let mut edge = make_edge(2);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let first_page = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }))
        .unwrap();
    assert_eq!(first_page["result"]["tools"].as_array().unwrap().len(), 2);
    assert!(first_page["result"]["nextCursor"].is_null());
    assert!(
        first_page["result"]["tools"][0]["annotations"]["readOnlyHint"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        first_page["result"]["tools"][0]["execution"]["taskSupport"],
        "optional"
    );
    assert_eq!(
        first_page["result"]["tools"][1]["outputSchema"]["type"],
        "object"
    );

    let second_page = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": { "cursor": "2" }
        }))
        .unwrap();
    assert_eq!(second_page["result"]["tools"].as_array().unwrap().len(), 0);
    assert!(second_page["result"]["nextCursor"].is_null());
}

#[test]
fn tools_list_rejects_non_object_params() {
    let mut edge = make_edge(10);
    initialize_edge(&mut edge);

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": []
        }))
        .unwrap();

    assert_eq!(response["error"]["code"], JSONRPC_INVALID_PARAMS);
    assert_eq!(
        response["error"]["message"],
        "tools/list params must be an object"
    );
}

#[test]
fn tools_call_requires_initialized_session() {
    let mut edge = make_edge(10);
    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "read_file", "arguments": { "path": "/tmp/x" } }
        }))
        .unwrap();

    assert_eq!(response["error"]["code"], JSONRPC_SERVER_NOT_INITIALIZED);
}

#[test]
fn parse_peer_capabilities_treats_empty_elicitation_as_form_support() {
    let capabilities = parse_peer_capabilities(&json!({
        "capabilities": {
            "elicitation": {},
        }
    }));

    assert!(capabilities.supports_elicitation);
    assert!(capabilities.elicitation_form);
    assert!(!capabilities.elicitation_url);

    let capabilities = parse_peer_capabilities(&json!({
        "capabilities": {
            "elicitation": {
                "form": {},
                "url": {}
            }
        }
    }));

    assert!(capabilities.supports_elicitation);
    assert!(capabilities.elicitation_form);
    assert!(capabilities.elicitation_url);
}

#[test]
fn parse_peer_capabilities_honors_object_valued_sampling_subcapabilities() {
    let capabilities = parse_peer_capabilities(&json!({
        "capabilities": {
            "sampling": {
                "context": {},
                "tools": {}
            }
        }
    }));

    assert!(capabilities.supports_sampling);
    assert!(capabilities.sampling_context);
    assert!(capabilities.sampling_tools);

    let malformed = parse_peer_capabilities(&json!({
        "capabilities": {
            "sampling": {
                "includeContext": true,
                "tools": true
            }
        }
    }));

    assert!(malformed.supports_sampling);
    assert!(!malformed.sampling_context);
    assert!(!malformed.sampling_tools);
}

#[test]
fn parse_peer_capabilities_tracks_resource_subscription_support_when_present() {
    let capabilities = parse_peer_capabilities(&json!({
        "capabilities": {
            "resources": {
                "subscribe": true
            }
        }
    }));

    assert!(capabilities.supports_subscriptions);

    let capabilities = parse_peer_capabilities(&json!({
        "capabilities": {
            "resources": {
                "subscribe": false
            }
        }
    }));

    assert!(!capabilities.supports_subscriptions);
}

#[test]
fn wrapped_elicitation_completion_notifications_only_emit_for_known_ids() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "elicitation": {
                    "form": {},
                    "url": {}
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    register_pending_url_elicitation(&mut edge, "elicit-123", Some("task-7"));

    edge.handle_upstream_transport_notification(json!({
        "jsonrpc": "2.0",
        "method": "notifications/elicitation/complete",
        "params": {
            "elicitationId": "elicit-123"
        }
    }));
    edge.handle_upstream_transport_notification(json!({
        "jsonrpc": "2.0",
        "method": "notifications/elicitation/complete",
        "params": {
            "elicitationId": "unknown-id"
        }
    }));

    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(
        notifications[0]["method"],
        "notifications/elicitation/complete"
    );
    assert_eq!(notifications[0]["params"]["elicitationId"], "elicit-123");
    assert_eq!(
        notifications[0]["params"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        "task-7"
    );
}

#[test]
fn direct_tool_server_url_required_errors_are_brokered_as_jsonrpc_errors() {
    let mut edge = make_url_required_edge();
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "elicitation": {
                    "url": {}
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "authorize",
                "arguments": {}
            }
        }))
        .unwrap();

    assert_eq!(response["error"]["code"], JSONRPC_URL_ELICITATION_REQUIRED);
    assert_eq!(response["error"]["data"]["elicitations"][0]["mode"], "url");
    assert_eq!(
        response["error"]["data"]["elicitations"][0]["elicitationId"],
        "elicit-auth"
    );

    edge.notify_elicitation_completed("elicit-auth");
    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(
        notifications[0]["method"],
        "notifications/elicitation/complete"
    );
    assert_eq!(notifications[0]["params"]["elicitationId"], "elicit-auth");
}

#[test]
fn direct_tool_server_events_are_forwarded_through_the_edge() {
    let server = Arc::new(AsyncEventServer::default());
    let mut edge = make_event_edge(Arc::clone(&server));
    edge.set_session_auth_context(SessionAuthContext::in_process_anonymous());
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "elicitation": {
                    "url": {}
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
    let subscribe = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/subscribe",
            "params": {
                "uri": "repo://docs/architecture"
            }
        }))
        .unwrap();
    assert!(subscribe.get("result").is_some());

    register_pending_url_elicitation(&mut edge, "elicit-async", None);
    server.push_event(ToolServerEvent::ElicitationCompleted {
        elicitation_id: "elicit-async".to_string(),
    });
    server.push_event(ToolServerEvent::ResourceUpdated {
        uri: "repo://docs/architecture".to_string(),
    });
    server.push_event(ToolServerEvent::ResourcesListChanged);
    server.push_event(ToolServerEvent::ToolsListChanged);
    server.push_event(ToolServerEvent::PromptsListChanged);

    let notifications = edge.drain_runtime_notifications().unwrap();
    let methods = notifications
        .iter()
        .map(|notification| notification["method"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert!(methods.contains(&"notifications/elicitation/complete"));
    assert!(methods.contains(&"notifications/resources/updated"));
    assert!(methods.contains(&"notifications/resources/list_changed"));
    assert!(methods.contains(&"notifications/tools/list_changed"));
    assert!(methods.contains(&"notifications/prompts/list_changed"));
}

#[test]
fn in_process_runtime_drain_flushes_late_async_events_without_request_bridge() {
    let server = Arc::new(AsyncEventServer::default());
    let mut edge = make_event_edge(Arc::clone(&server));
    edge.set_session_auth_context(SessionAuthContext::in_process_anonymous());
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "elicitation": {
                    "url": {}
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
    register_pending_url_elicitation(&mut edge, "elicit-late", Some("task-7"));

    server.push_event(ToolServerEvent::ElicitationCompleted {
        elicitation_id: "elicit-late".to_string(),
    });

    let notifications = edge.drain_runtime_notifications().unwrap();

    assert_eq!(notifications.len(), 1);
    assert_eq!(
        notifications[0]["method"],
        "notifications/elicitation/complete"
    );
    assert_eq!(notifications[0]["params"]["elicitationId"], "elicit-late");
    assert_eq!(
        notifications[0]["params"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        "task-7"
    );
    assert!(edge.drain_runtime_notifications().unwrap().is_empty());
}

#[test]
fn in_process_runtime_drain_completes_task_after_tools_call_returns_task() {
    let mut edge = make_edge(10);
    edge.set_session_auth_context(SessionAuthContext::in_process_anonymous());
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let create = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {},
                "task": {}
            }
        }))
        .unwrap();
    let task_id = create["result"]["task"]["taskId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(create["result"]["task"]["status"], "working");

    let notifications = edge.drain_runtime_notifications().unwrap();
    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0]["method"], "notifications/tasks/status");
    assert_eq!(notifications[0]["params"]["taskId"], task_id);
    assert_eq!(notifications[0]["params"]["status"], "completed");

    let get_completed = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/get",
            "params": { "taskId": task_id.clone() }
        }))
        .unwrap();
    assert_eq!(get_completed["result"]["status"], "completed");

    let result = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tasks/result",
            "params": { "taskId": task_id.clone() }
        }))
        .unwrap();
    assert_eq!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        task_id
    );
    assert_eq!(result["result"]["structuredContent"]["temperature"], 22.5);
    assert!(edge.drain_runtime_notifications().unwrap().is_empty());
}
