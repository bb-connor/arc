use crate::config::A2aEdgeConfig;
use crate::edge::{validate_execution_context, ChioA2aEdge};
use crate::error::A2aEdgeError;
use crate::metrics::{
    receipt_write_total, RECEIPT_WRITE_OUTCOME_ERROR, RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
};
use crate::tests::{
    assert_receipt_write_prometheus_sample_at_least, capability_for_tool, kernel_for_server,
    manifest_public_key, metrics_test_guard, test_kernel_config, test_manifest, test_server,
    text_message, threshold_artifacts, FailingToolServer,
};
use crate::types::{A2aKernelExecutionContext, TaskStatus};
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
};
use chio_core::crypto::Keypair;
use chio_cross_protocol::capability_bridge::CrossProtocolCapabilityRef;
use chio_cross_protocol::discovery::DiscoveryProtocol;
use chio_kernel::ChioKernel;
use chio_manifest::{ToolDefinition, ToolManifest};
use chio_test_support::prelude::*;
use serde_json::json;

// ---- SendMessage tests ----

#[test]
fn send_message_completes_successfully() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let (kernel, execution) = kernel_for_server(test_server());
    let request = text_message("hello");
    let response = edge
        .handle_send_message("echo", &request, &kernel, &execution)
        .test_unwrap();
    assert_eq!(response.status, TaskStatus::Completed);
    assert!(response.message.is_some());
    assert_eq!(
        response
            .metadata
            .as_ref()
            .and_then(|metadata| { metadata["chio"]["authorityPath"].as_str() }),
        Some("cross_protocol_orchestrator")
    );
}

#[test]
fn send_message_returns_task_id() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let (kernel, execution) = kernel_for_server(test_server());
    let request = text_message("test");
    let r1 = edge
        .handle_send_message("echo", &request, &kernel, &execution)
        .test_unwrap();
    let r2 = edge
        .handle_send_message("echo", &request, &kernel, &execution)
        .test_unwrap();
    assert_ne!(r1.id, r2.id);
    assert!(r1.id.starts_with("a2a-task-"));
}

#[test]
fn send_message_unknown_skill_errors() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let (kernel, execution) = kernel_for_server(test_server());
    let request = text_message("test");
    let err = edge
        .handle_send_message("nonexistent", &request, &kernel, &execution)
        .test_expect_err("unknown A2A skill must fail");
    assert!(matches!(err, A2aEdgeError::ToolNotFound(_)));
}

#[test]
fn send_message_server_failure_returns_failed_task() {
    let (kernel, execution) = kernel_for_server(FailingToolServer);
    // Need a manifest for the failing server
    let manifest = ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "fail-srv".to_string(),
        name: "Fail".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "fail_tool".to_string(),
            description: "Fails".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: chio_manifest::ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: false,
                requires_approval: false,
            },
            latency_hint: None,
            flow: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: manifest_public_key(9),
    };
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![manifest]).test_unwrap();
    let request = text_message("test");
    let response = edge
        .handle_send_message("fail_tool", &request, &kernel, &execution)
        .test_unwrap();
    assert_eq!(response.status, TaskStatus::Failed);
    assert!(response.status_message.is_some());
    assert_eq!(
        response
            .metadata
            .as_ref()
            .and_then(|metadata| { metadata["chio"]["authorityPath"].as_str() }),
        Some("cross_protocol_orchestrator")
    );
}

#[test]
fn send_message_with_kernel_emits_signed_receipt_metadata() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };

    let response = edge
        .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
        .test_unwrap();
    assert_eq!(response.status, TaskStatus::Completed);
    let metadata = response
        .metadata
        .test_expect("kernel path should attach metadata");
    assert!(metadata["chio"]["receiptId"].as_str().is_some());
    assert_eq!(
        metadata["chio"]["authorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );
    assert_eq!(
        metadata["chio"]["bridge"]["sourceProtocol"].as_str(),
        Some("a2a")
    );
    assert_eq!(
        metadata["chio"]["bridge"]["targetProtocol"].as_str(),
        Some("native")
    );
    assert_eq!(
        metadata["chio"]["lifecycle"]["messageSend"].as_str(),
        Some("blocking_terminal_task")
    );
    assert_eq!(
        metadata["chio"]["lifecycle"]["messageStream"].as_str(),
        Some("deferred_task_poll")
    );
    assert_eq!(
        metadata["chio"]["runtimeLifecycle"]["surface"].as_str(),
        Some("a2a_authoritative")
    );
    assert_eq!(
        metadata["chio"]["receipt"]["capability_id"].as_str(),
        Some("cap-test-srv-echo")
    );
}

#[test]
fn send_message_rejects_blank_execution_agent_id_before_dispatch() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
        agent_id: "\t".to_string(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };

    let error = edge
        .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
        .test_expect_err("blank A2A execution agent_id must fail");

    assert_eq!(
        error.to_string(),
        "invalid request: A2A execution agent_id must not be empty"
    );
}

#[test]
fn send_message_rejects_supplemental_authorization_without_stable_request_id() {
    let mut edge = ChioA2aEdge::new(
        A2aEdgeConfig {
            peer_capabilities: chio_mcp_edge::authorization::authorization_capabilities(),
            ..A2aEdgeConfig::default()
        },
        vec![test_manifest()],
    )
    .test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: Some(
            chio_core::capability::supplemental_authorization::OpaqueSupplementalAuthorization {
                signed_extension: "opaque-extension".to_string(),
            },
        ),
        model_metadata: None,
    };

    let error = edge
        .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
        .test_expect_err("supplemental authorization must require a stable request id");

    assert_eq!(
        error.to_string(),
        "invalid request: A2A request-bound authorization artifacts and execution nonces \
         require handle_send_message_with_request_id or handle_stream_message_with_request_id"
    );
}

#[test]
fn send_message_rejects_singular_approval_token_without_stable_request_id() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

    let subject = Keypair::generate();
    let (approvals, _proposal) = threshold_artifacts(&subject, "a2a-singular-auth");
    let approval_token = approvals
        .into_iter()
        .next()
        .test_expect("threshold artifacts must yield at least one approval token");
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: Some(approval_token.clone()),
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };

    let error = edge
        .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
        .test_expect_err("a singular approval token must require a stable request id");

    assert_eq!(
        error.to_string(),
        "invalid request: A2A request-bound authorization artifacts and execution nonces \
         require handle_send_message_with_request_id or handle_stream_message_with_request_id"
    );
}

#[test]
fn send_message_with_request_id_accepts_request_bound_artifacts() {
    let mut edge = ChioA2aEdge::new(
        A2aEdgeConfig {
            peer_capabilities: chio_mcp_edge::authorization::authorization_capabilities(),
            ..A2aEdgeConfig::default()
        },
        vec![test_manifest()],
    )
    .test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: Some(
            chio_core::capability::supplemental_authorization::OpaqueSupplementalAuthorization {
                signed_extension: "opaque-extension".to_string(),
            },
        ),
        model_metadata: None,
    };

    edge.handle_send_message_with_request_id(
        "caller-chosen-request",
        "echo",
        &text_message("hello"),
        &kernel,
        &execution,
    )
    .test_expect("stable request id path must accept request-bound artifacts");
}

#[test]
fn execution_context_rejects_oversized_threshold_approval_set() {
    let subject = Keypair::generate();
    let approver = Keypair::generate();
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "approval-oversize".to_string(),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: "a".repeat(64),
            request_id: "a2a-request".to_string(),
            threshold_proposal_hash: Some("b".repeat(64)),
            issued_at: 1,
            expires_at: 2,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )
    .test_unwrap();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&Keypair::generate(), &subject, "test-srv", "echo"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: vec![
            token;
            chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
                + 1
        ],
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };

    let error = validate_execution_context(&execution, &Default::default())
        .test_expect_err("oversized A2A threshold approval set must fail");

    assert_eq!(
        error.to_string(),
        format!(
            "invalid request: A2A threshold approval set exceeds {} tokens",
            chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
        )
    );
}

#[test]
fn execution_context_rejects_control_character_agent_id() {
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&Keypair::generate(), &subject, "test-srv", "echo"),
        agent_id: format!("{}{}suffix", subject.public_key().to_hex(), '\u{7}'),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };

    let error = validate_execution_context(&execution, &Default::default())
        .test_expect_err("control character A2A execution agent_id must fail");

    assert_eq!(
        error.to_string(),
        "invalid request: A2A execution agent_id must not include control characters"
    );
}

#[test]
fn send_message_with_kernel_denial_still_returns_receipt_metadata() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };

    let response = edge
        .handle_send_message("write", &text_message("blocked"), &kernel, &execution)
        .test_unwrap();
    assert_eq!(response.status, TaskStatus::Failed);
    let metadata = response
        .metadata
        .test_expect("deny path should attach metadata");
    assert_eq!(
        metadata["chio"]["authorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );
    assert_eq!(metadata["chio"]["decision"].as_str(), Some("deny"));
    assert!(metadata["chio"]["receipt"]["id"].as_str().is_some());
}

#[test]
fn pending_approval_is_not_reported_as_completed() {
    let _metrics_guard = metrics_test_guard();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

    let subject = Keypair::generate();
    let request = text_message("blocked pending approval");
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let before_pending = receipt_write_total(RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL);
    let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

    let response = edge
        .project_pending_approval_for_test(
            "echo",
            &request,
            &kernel,
            &A2aKernelExecutionContext {
                capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
                agent_id: subject.public_key().to_hex(),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                model_metadata: None,
            },
            "approval required",
        )
        .test_unwrap();
    let metadata = response
        .metadata
        .test_expect("pending approval should attach metadata");

    assert_eq!(response.status, TaskStatus::Working);
    assert!(!response.status.is_terminal());
    assert_eq!(
        response.status_message.as_deref(),
        Some("approval required")
    );
    assert!(response.message.is_none());
    assert_eq!(
        metadata["chio"]["decision"].as_str(),
        Some("pending_approval")
    );
    let pending_total = receipt_write_total(RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL);
    assert!(pending_total > before_pending);
    assert_receipt_write_prometheus_sample_at_least(
        RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
        pending_total,
    );
    assert_eq!(
        receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR),
        before_error
    );
}

#[test]
fn send_message_kernel_error_records_receipt_write_error_outcome() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let mut config = test_kernel_config();
    config.require_web3_evidence = true;
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };
    let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

    let error = edge
        .handle_send_message("echo", &text_message("boom"), &kernel, &execution)
        .test_expect_err("A2A web3 evidence prerequisite failure must reject");

    assert!(error
        .to_string()
        .contains("web3 evidence prerequisites unavailable"));
    assert!(
        receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR) > before_error,
        "a2a orchestrator error path must advance receipt write error"
    );
}

#[test]
fn pre_kernel_bridge_error_does_not_record_receipt_write_error_outcome() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));

    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "test-srv", "echo"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };
    let capability_ref = CrossProtocolCapabilityRef {
        chio_capability_id: "wrong-capability".to_string(),
        origin_protocol: DiscoveryProtocol::A2a,
        protocol_context: Some(json!({ "targetSkillId": "echo" })),
        parent_capability_hash: "wrong-parent-hash".to_string(),
    };
    let mut request = text_message("boom");
    request.metadata = Some(json!({
        "chio": {
            "capabilityRef": serde_json::to_value(capability_ref).test_unwrap()
        }
    }));
    let before_error = receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR);

    let error = edge
        .handle_send_message("echo", &request, &kernel, &execution)
        .test_expect_err("A2A capability reference mismatch must reject");

    assert!(error.to_string().contains("capability reference mismatch"));
    assert_eq!(
        receipt_write_total(RECEIPT_WRITE_OUTCOME_ERROR),
        before_error,
        "pre-kernel A2A bridge errors must not advance receipt write error"
    );
}

#[test]
fn send_message_kernel_failure_still_returns_receipt_metadata() {
    let manifest = ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "fail-srv".to_string(),
        name: "Fail".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "fail_tool".to_string(),
            description: "Fails".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: chio_manifest::ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: false,
                requires_approval: false,
            },
            latency_hint: None,
            flow: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: manifest_public_key(10),
    };
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![manifest]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(FailingToolServer));

    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject, "fail-srv", "fail_tool"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };

    let response = edge
        .handle_send_message("fail_tool", &text_message("boom"), &kernel, &execution)
        .test_unwrap();
    assert_eq!(response.status, TaskStatus::Failed);
    let metadata = response
        .metadata
        .test_expect("kernel failure should attach metadata");
    assert_eq!(
        metadata["chio"]["authorityPath"].as_str(),
        Some("cross_protocol_orchestrator")
    );
    assert!(metadata["chio"]["receipt"]["id"].as_str().is_some());
    assert_eq!(metadata["chio"]["decision"].as_str(), Some("deny"));
}
