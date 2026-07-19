#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::capability_bridge::*;
use crate::discovery::*;
use crate::error::*;
use crate::execution::*;
use crate::lifecycle::*;
use crate::negotiation::{validate_execution_feature_negotiation, TrustedPeerNegotiation};
use crate::orchestrator::*;
use crate::routing::*;
use crate::semantic_hints::*;
use crate::validation::{schema_extension, validate_execution_request_boundary};

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use chio_core::capability::{
    aggregate_budget::{AggregateInvocationBudget, AggregateInvocationScope},
    features::{
        CapabilityNegotiation, AGGREGATE_INVOCATION_BUDGET, GOVERNED_ACTIVE_RESPONSE_PLAN,
        SUPPLEMENTAL_BROKER_EXECUTION_QUOTA, THRESHOLD_GOVERNED_APPROVALS,
    },
    governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        GovernedResponseEffect, GovernedResponsePlanIntentBody, GovernedTransactionIntent,
        CHIO_RESPONSE_PLAN_SCHEMA,
    },
    scope::{ChioScope, Constraint, ModelMetadata, ModelSafetyTier, Operation, ToolGrant},
    threshold_approval::{ThresholdApprovalProposal, ThresholdApprovalProposalBody},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_core::message::OpaqueSupplementalAuthorization;
use chio_kernel::{
    ActiveResponseExecutionEvidence, ActiveResponseExecutionRequest,
    ActiveResponseExecutorAuthority, ActiveResponseExecutorAuthorityIdentity,
    ActiveResponseExecutorError, ActiveResponseFindingAuthority,
    ActiveResponseFindingAuthorityError, ActiveResponsePolicyResolutionError,
    AuthoritativeCorrelatedFindingEvidence, CapabilityIssuanceAdmissionAuthority, ChioKernel,
    GovernedSecurityRuntimePublication, KernelConfig, KernelError, NestedFlowBridge,
    PostInvocationPipeline, SecurityDispatchOutcomeHandle, SecurityInvocationContext,
    SecurityInvocationContextV1, SecurityPreDispatchContext, SecurityPreDispatchHook,
    ToolServerConnection, Verdict as KernelVerdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_manifest::{
    sign_manifest, BridgeSecurityMetadata, LatencyHint, RuntimeToolTopology, ToolDefinition,
    ToolFlowDeclaration, ToolManifest, VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use chio_security_types::ports::{
    IsolationEpochId, IssuanceFreezeAdmissionQuery, LineageId, OpaqueReceiptRef, PortResult,
    SessionId, TenantId,
};
use chio_security_types::PrincipalId;
use chio_store_sqlite::{
    SqliteAdmissionOperationStore, SqliteApprovalStore, SqliteBudgetStore, SqliteReceiptStore,
};
use serde_json::{json, Value};
use std::sync::Arc;

struct MockBridge;

struct ReadyFlowFindingAuthority;

impl ActiveResponseFindingAuthority for ReadyFlowFindingAuthority {
    fn ensure_ready(&self) -> Result<(), ActiveResponseFindingAuthorityError> {
        Ok(())
    }

    fn load_correlated_finding(
        &self,
        _evidence_id: &OpaqueReceiptRef,
    ) -> Result<Option<AuthoritativeCorrelatedFindingEvidence>, ActiveResponseFindingAuthorityError>
    {
        Ok(None)
    }
}

struct ReadyFlowExecutor;

impl ActiveResponseExecutorAuthority for ReadyFlowExecutor {
    fn identity(&self) -> ActiveResponseExecutorAuthorityIdentity {
        ActiveResponseExecutorAuthorityIdentity::new(
            Keypair::from_seed(&[71_u8; 32]).public_key(),
            1,
        )
        .unwrap()
    }

    fn ensure_ready(&self) -> Result<(), ActiveResponseExecutorError> {
        Ok(())
    }

    fn execute_active_response(
        &self,
        _request: &ActiveResponseExecutionRequest,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        Err(ActiveResponseExecutorError::NotReady(
            "cross-protocol flow test does not execute active responses".to_string(),
        ))
    }
}

struct AllowFlowIssuance;

impl CapabilityIssuanceAdmissionAuthority for AllowFlowIssuance {
    fn ensure_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn authorize(&self, _query: &IssuanceFreezeAdmissionQuery) -> PortResult<()> {
        Ok(())
    }
}

struct AllowFlowPreDispatch;

impl SecurityPreDispatchHook for AllowFlowPreDispatch {
    fn name(&self) -> &str {
        "cross-protocol-flow-pre-dispatch"
    }

    fn commit(
        &self,
        _context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

impl CapabilityBridge for MockBridge {
    fn source_protocol(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::A2a
    }

    fn extract_capability_ref(
        &self,
        request: &Value,
    ) -> Result<Option<CrossProtocolCapabilityRef>, BridgeError> {
        request
            .pointer("/metadata/chio/capabilityRef")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| BridgeError::InvalidRequest(error.to_string()))
    }

    fn inject_capability_ref(
        &self,
        envelope: &mut Value,
        cap_ref: &CrossProtocolCapabilityRef,
    ) -> Result<(), BridgeError> {
        let Some(object) = envelope.as_object_mut() else {
            return Err(BridgeError::InvalidRequest(
                "request envelope must be a JSON object".to_string(),
            ));
        };
        let metadata = object
            .entry("metadata".to_string())
            .or_insert_with(|| json!({}));
        let Some(metadata_obj) = metadata.as_object_mut() else {
            return Err(BridgeError::InvalidRequest(
                "metadata must be a JSON object".to_string(),
            ));
        };
        let chio = metadata_obj
            .entry("chio".to_string())
            .or_insert_with(|| json!({}));
        let Some(chio_obj) = chio.as_object_mut() else {
            return Err(BridgeError::InvalidRequest(
                "metadata.chio must be a JSON object".to_string(),
            ));
        };
        chio_obj.insert(
            "capabilityRef".to_string(),
            serde_json::to_value(cap_ref)
                .map_err(|error| BridgeError::InvalidRequest(error.to_string()))?,
        );
        Ok(())
    }

    fn protocol_context(&self, request: &Value) -> Result<Option<Value>, BridgeError> {
        Ok(request
            .pointer("/metadata/chio/targetSkillId")
            .and_then(Value::as_str)
            .map(|skill| json!({ "targetSkillId": skill })))
    }
}

struct MockToolServer;

struct CountingNativeToolServer {
    dispatches: std::sync::Arc<AtomicUsize>,
}

struct MockMcpExecutor;

struct CountingMcpExecutor<'a> {
    dispatches: &'a AtomicUsize,
}

impl TargetProtocolExecutor for CountingMcpExecutor<'_> {
    fn target_protocol(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::Mcp
    }

    fn execute(
        &self,
        _request: CrossProtocolTargetRequest<'_>,
    ) -> Result<CrossProtocolTargetExecution, BridgeError> {
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        Err(BridgeError::InvalidRequest(
            "counting executor must not receive a forged sidecar".to_string(),
        ))
    }
}

impl TargetProtocolExecutor for MockMcpExecutor {
    fn target_protocol(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::Mcp
    }

    fn execute(
        &self,
        request: CrossProtocolTargetRequest<'_>,
    ) -> Result<CrossProtocolTargetExecution, BridgeError> {
        let route_metadata = route_selection_metadata(request.route_selection)?;
        let response = request
            .kernel
            .evaluate_tool_call_blocking_with_manifest_security(
                &request.execution.to_tool_call_request(),
                request.manifest_registry,
                &request.execution.bridge_security,
                Some(route_metadata),
            )
            .map_err(BridgeError::Kernel)?;
        let receipt_id = response.receipt.id.clone();

        Ok(CrossProtocolTargetExecution {
            response,
            protocol_result: Some(json!({
                "content": [{"type": "text", "text": "projected"}],
                "structuredContent": {"mode": "mcp"},
                "isError": false
            })),
            protocol_notifications: vec![json!({"jsonrpc": "2.0", "method": "notifications/test"})],
            route_hops: vec![
                TargetExecutionHop {
                    protocol: DiscoveryProtocol::Mcp,
                    request_id: format!("{}:mcp", request.execution.kernel_request_id),
                    receipt_id: None,
                },
                TargetExecutionHop {
                    protocol: DiscoveryProtocol::Native,
                    request_id: request.execution.kernel_request_id.clone(),
                    receipt_id: Some(receipt_id),
                },
            ],
        })
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingNativeToolServer {
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
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"result": "should-not-dispatch"}))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for MockToolServer {
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
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(json!({"result":"ok"}))
    }
}

fn unix_now() -> u64 {
    current_unix_timestamp()
}

fn test_kernel() -> (Keypair, ChioKernel) {
    let keypair = Keypair::generate();
    let config = KernelConfig {
        ca_public_keys: vec![keypair.public_key()],
        keypair: keypair.clone(),
        max_delegation_depth: 8,
        policy_hash: "policy-cross-protocol-test".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(MockToolServer));
    (keypair, kernel)
}

fn install_test_flow_runtime(kernel: &mut ChioKernel) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let receipt_store =
        Arc::new(SqliteReceiptStore::open(directory.path().join("receipts.sqlite3")).unwrap());
    kernel.set_receipt_store_handle(receipt_store).unwrap();
    kernel
        .set_active_response_submission_authority(Keypair::from_seed(&[72_u8; 32]).public_key())
        .unwrap();

    let active_response_requirement_resolver = Arc::new(
        |_request: &chio_kernel::ActiveResponsePolicyRequest, _policy_hash: &str| {
            Err(ActiveResponsePolicyResolutionError::Unavailable(
                "cross-protocol flow test does not resolve active responses".to_string(),
            ))
        },
    );
    let threshold_approval_requirement_resolver = Arc::new(
        |_request: &chio_core::capability::threshold_approval::ThresholdApprovalRequest,
         _policy_hash: &str| {
            Err(
                chio_core::capability::threshold_approval::ThresholdApprovalResolutionError::Unavailable(
                    "cross-protocol flow test does not resolve threshold approvals".to_string(),
                ),
            )
        },
    );
    let admission_operation_store = Arc::new(
        SqliteAdmissionOperationStore::open(directory.path().join("admission-operations.sqlite3"))
            .unwrap(),
    );
    let approval_store =
        Arc::new(SqliteApprovalStore::open(directory.path().join("approvals.sqlite3")).unwrap());
    let budget_store =
        Arc::new(SqliteBudgetStore::open(directory.path().join("budgets.sqlite3")).unwrap());

    kernel
        .publish_governed_security_runtime(GovernedSecurityRuntimePublication {
            active_response_requirement_resolver,
            threshold_approval_requirement_resolver,
            admission_operation_store,
            approval_store,
            budget_store,
            finding_authority: Arc::new(ReadyFlowFindingAuthority),
            executor_authority: Arc::new(ReadyFlowExecutor),
            capability_issuance_admission_authority: Arc::new(AllowFlowIssuance),
            threshold_policy_authorities: vec![Keypair::from_seed(&[73_u8; 32]).public_key()],
            guards: Vec::new(),
            pre_dispatch_hook: Arc::new(AllowFlowPreDispatch),
            post_invocation_pipeline: PostInvocationPipeline::new(),
        })
        .unwrap();
    directory
}

fn capability_for_tool(
    issuer: &Keypair,
    subject: &Keypair,
    server_id: &str,
    tool_name: &str,
) -> CapabilityToken {
    capability_for_tool_with_constraints(issuer, subject, server_id, tool_name, vec![])
}

fn capability_for_tool_with_constraints(
    issuer: &Keypair,
    subject: &Keypair,
    server_id: &str,
    tool_name: &str,
    constraints: Vec<Constraint>,
) -> CapabilityToken {
    let now = unix_now();
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: format!("cap-{server_id}-{tool_name}"),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: server_id.to_string(),
                    tool_name: tool_name.to_string(),
                    operations: vec![Operation::Invoke],
                    constraints,
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: now.saturating_sub(30),
            expires_at: now + 300,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .unwrap()
}

fn adapter_authorization_artifacts(
    subject: &Keypair,
    request_id: &str,
) -> (
    Vec<GovernedApprovalToken>,
    ThresholdApprovalProposal,
    OpaqueSupplementalAuthorization,
) {
    let authority = Keypair::from_seed(&[91; 32]);
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody::new(
            "proposal-cross-protocol-preservation",
            request_id,
            "11".repeat(32),
            subject.public_key(),
            "22".repeat(32),
            "33".repeat(32),
            1,
            "44".repeat(32),
            1_000,
            300,
            1_500,
            1_400,
        )
        .unwrap(),
        &authority,
    )
    .unwrap();
    let proposal_hash = proposal.proposal_hash().unwrap();
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "approval-cross-protocol-preservation".to_string(),
            approver: authority.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: "11".repeat(32),
            threshold_proposal_hash: Some(proposal_hash),
            request_id: request_id.to_string(),
            issued_at: 1_000,
            expires_at: 1_300,
            decision: GovernedApprovalDecision::Approved,
        },
        &authority,
    )
    .unwrap();
    let supplemental = OpaqueSupplementalAuthorization::new(
        "supplemental-cross-protocol-preservation",
        vec![0x43, 0x48, 0x49, 0x4f],
    )
    .unwrap();
    (vec![token], proposal, supplemental)
}

fn legacy_approval_token(subject: &Keypair, request_id: &str) -> GovernedApprovalToken {
    let approver = Keypair::from_seed(&[92; 32]);
    GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("legacy-approval-{request_id}"),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: "11".repeat(32),
            threshold_proposal_hash: None,
            request_id: request_id.to_string(),
            issued_at: 1_000,
            expires_at: 1_300,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )
    .unwrap()
}

fn complete_protocol_extension_features() -> CapabilityNegotiation {
    let mut features = CapabilityNegotiation::t1_default();
    for feature in [
        AGGREGATE_INVOCATION_BUDGET,
        THRESHOLD_GOVERNED_APPROVALS,
        GOVERNED_ACTIVE_RESPONSE_PLAN,
        SUPPLEMENTAL_BROKER_EXECUTION_QUOTA,
    ] {
        features.features.insert(feature.to_string(), true);
    }
    features
}

#[test]
fn singular_legacy_approval_does_not_require_threshold_feature_negotiation() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = capability_for_tool(&issuer, &subject, "test-srv", "echo");
    let approval = legacy_approval_token(&subject, "legacy-negotiation-request");

    validate_execution_feature_negotiation(
        &TrustedPeerNegotiation::default(),
        &capability,
        None,
        Some(&approval),
        &[],
        None,
        None,
    )
    .expect("the compatibility singular approval field must remain a v1 capability");
}

fn active_response_intent(subject: &Keypair) -> GovernedTransactionIntent {
    let canonical_plan_body = json!({"action":"suspend_session"});
    let plan_body_hash =
        GovernedResponsePlanIntentBody::compute_plan_body_hash(&canonical_plan_body).unwrap();
    GovernedTransactionIntent::active_response_plan(
        GovernedResponsePlanIntentBody::new(
            CHIO_RESPONSE_PLAN_SCHEMA,
            "plan-cross-protocol-negotiation",
            "operator-capability-cross-protocol",
            "55".repeat(32),
            2_000,
            subject.public_key(),
            canonical_plan_body,
            plan_body_hash.clone(),
            json!({"sessionId":"session-cross-protocol"}),
            vec![GovernedResponseEffect::SuspendSession],
            1_900,
            json!({"responsePlanHash":plan_body_hash}),
        )
        .unwrap(),
    )
}

#[test]
fn cross_protocol_kernel_request_preserves_complete_authorization_context() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let kernel_request_id = "kernel-cross-protocol-preservation";
    let (approval_tokens, proposal, supplemental) =
        adapter_authorization_artifacts(&subject, kernel_request_id);
    let mut request = CrossProtocolExecutionRequest {
        origin_request_id: "origin-cross-protocol-preservation".to_string(),
        kernel_request_id: kernel_request_id.to_string(),
        target_protocol: DiscoveryProtocol::Native,
        target_server_id: "test-srv".to_string(),
        target_tool_name: "echo".to_string(),
        agent_id: subject.public_key().to_hex(),
        arguments: json!({"message":"preserve authorization"}),
        capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
        source_envelope: json!({"message":{"role":"user"}}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: approval_tokens.clone(),
        threshold_approval_proposal: Some(proposal.clone()),
        model_metadata: None,
        supplemental_authorization: Some(supplemental.clone()),
        authenticated_session_id: None,
        security_context: None,
        bridge_security: explicit_local_bridge_security("test-srv", "echo"),
    };
    request.capability.aggregate_invocation_budget = Some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 3,
        root_binding: None,
    });
    request.governed_intent = Some(active_response_intent(&subject));
    let features = complete_protocol_extension_features();
    let negotiation =
        TrustedPeerNegotiation::from_advertised_intersection(&features, &features).unwrap();

    validate_execution_feature_negotiation(
        &negotiation,
        &request.capability,
        request.governed_intent.as_ref(),
        request.approval_token.as_ref(),
        &request.approval_tokens,
        request.threshold_approval_proposal.as_ref(),
        request.supplemental_authorization.as_ref(),
    )
    .unwrap();
    for required_feature in [
        AGGREGATE_INVOCATION_BUDGET,
        THRESHOLD_GOVERNED_APPROVALS,
        GOVERNED_ACTIVE_RESPONSE_PLAN,
        SUPPLEMENTAL_BROKER_EXECUTION_QUOTA,
    ] {
        let mut peer_features = features.clone();
        peer_features.features.remove(required_feature);
        let missing =
            TrustedPeerNegotiation::from_advertised_intersection(&features, &peer_features)
                .unwrap();
        let error = validate_execution_feature_negotiation(
            &missing,
            &request.capability,
            request.governed_intent.as_ref(),
            request.approval_token.as_ref(),
            &request.approval_tokens,
            request.threshold_approval_proposal.as_ref(),
            request.supplemental_authorization.as_ref(),
        )
        .unwrap_err();
        assert!(error.contains(required_feature));
    }

    let kernel_request = request.to_tool_call_request();

    assert_eq!(
        kernel_request.capability.aggregate_invocation_budget,
        request.capability.aggregate_invocation_budget
    );
    assert_eq!(kernel_request.governed_intent, request.governed_intent);
    assert_eq!(kernel_request.approval_tokens, approval_tokens);
    assert_eq!(kernel_request.threshold_approval_proposal, Some(proposal));
    assert_eq!(
        kernel_request.supplemental_authorization,
        Some(supplemental)
    );
}

#[test]
fn native_cross_protocol_unnegotiated_extensions_deny_before_dispatch_or_receipt_mutation() {
    let dispatches = std::sync::Arc::new(AtomicUsize::new(0));
    let keypair = Keypair::generate();
    let config = KernelConfig {
        ca_public_keys: vec![keypair.public_key()],
        keypair: keypair.clone(),
        max_delegation_depth: 8,
        policy_hash: "policy-cross-protocol-negotiation".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(CountingNativeToolServer {
        dispatches: std::sync::Arc::clone(&dispatches),
    }));
    let registry = explicit_local_manifest_registry("test-srv", "echo");
    let subject = Keypair::generate();
    let request_id = "native-cross-protocol-unnegotiated";
    let (approval_tokens, proposal, supplemental) =
        adapter_authorization_artifacts(&subject, request_id);
    let request = CrossProtocolExecutionRequest {
        origin_request_id: "native-unnegotiated-origin".to_string(),
        kernel_request_id: request_id.to_string(),
        target_protocol: DiscoveryProtocol::Native,
        target_server_id: "test-srv".to_string(),
        target_tool_name: "echo".to_string(),
        agent_id: subject.public_key().to_hex(),
        arguments: json!({"message":"deny before dispatch"}),
        capability: capability_for_tool(&keypair, &subject, "test-srv", "echo"),
        source_envelope: json!({"message":{"role":"user"}}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens,
        threshold_approval_proposal: Some(proposal),
        model_metadata: None,
        supplemental_authorization: Some(supplemental),
        authenticated_session_id: None,
        security_context: None,
        bridge_security: explicit_local_bridge_security("test-srv", "echo"),
    };
    let mut singular_request = request.clone();
    singular_request.kernel_request_id = "native-cross-protocol-unnegotiated-singular".to_string();
    singular_request.approval_token = singular_request.approval_tokens.first().cloned();
    singular_request.approval_tokens.clear();
    singular_request.threshold_approval_proposal = None;
    singular_request.supplemental_authorization = None;
    let receipt_count_before = kernel.receipt_log().len();

    let error = CrossProtocolOrchestrator::new(&kernel, &registry)
        .execute(&MockBridge, request)
        .unwrap_err();

    assert!(error.to_string().contains(THRESHOLD_GOVERNED_APPROVALS));
    assert_eq!(dispatches.load(Ordering::SeqCst), 0);
    assert_eq!(kernel.receipt_log().len(), receipt_count_before);

    let singular_error = CrossProtocolOrchestrator::new(&kernel, &registry)
        .execute(&MockBridge, singular_request)
        .unwrap_err();
    assert!(singular_error
        .to_string()
        .contains(THRESHOLD_GOVERNED_APPROVALS));
    assert_eq!(dispatches.load(Ordering::SeqCst), 0);
    assert_eq!(kernel.receipt_log().len(), receipt_count_before);
}

#[test]
fn attenuate_scope_for_tool_narrows_wildcard_parent_grants() {
    let parent = ChioScope {
        grants: vec![ToolGrant {
            server_id: "*".to_string(),
            tool_name: "*".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::MaxLength(1024)],
            max_invocations: Some(3),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(true),
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };

    let child = attenuate_scope_for_tool(&parent, "test-srv", "echo");

    assert_eq!(child.grants.len(), 1);
    assert_eq!(child.grants[0].server_id, "test-srv");
    assert_eq!(child.grants[0].tool_name, "echo");
    assert_eq!(child.grants[0].operations, vec![Operation::Invoke]);
    assert_eq!(
        child.grants[0].constraints,
        vec![Constraint::MaxLength(1024)]
    );
    assert_eq!(child.grants[0].max_invocations, Some(3));
    assert_eq!(child.grants[0].dpop_required, Some(true));
}

#[test]
fn parent_capability_hash_commits_to_signed_token_not_id_only() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let first = capability_for_tool(&issuer, &subject, "test-srv", "echo");
    let mut second = capability_for_tool(&issuer, &subject, "test-srv", "echo");
    second.expires_at = second.expires_at.saturating_add(1);

    assert_eq!(first.id, second.id);
    assert_ne!(
        parent_capability_hash(&first).unwrap(),
        parent_capability_hash(&second).unwrap()
    );
}

#[test]
fn capability_envelope_serializes_without_parent_capability_token() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = capability_for_tool(&issuer, &subject, "test-srv", "echo");
    let capability_ref =
        CrossProtocolCapabilityRef::from_capability(&capability, DiscoveryProtocol::A2a, None)
            .unwrap();
    let envelope = CrossProtocolCapabilityEnvelope {
        schema: CROSS_PROTOCOL_CAPABILITY_ENVELOPE_SCHEMA.to_string(),
        capability_ref,
        target_protocol: DiscoveryProtocol::Native,
        attenuated_scope: capability.scope.clone(),
        bridged_at: 1,
        bridge_id: "bridge-no-token".to_string(),
    };

    let serialized = serde_json::to_value(envelope).unwrap();
    assert!(serialized.get("capability").is_none());
    assert_eq!(
        serialized["capabilityRef"]["chioCapabilityId"].as_str(),
        Some("cap-test-srv-echo")
    );
    assert!(serialized["capabilityRef"]["parentCapabilityHash"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
}

include!("tests/execution_boundary.rs");

#[test]
fn target_protocol_defaults_to_native() {
    let tool = semantic_tool(
        "echo",
        Some(LatencyHint::Instant),
        json!({"type": "object"}),
        None,
    );
    assert_eq!(
        target_protocol_for_tool(&tool).unwrap(),
        DiscoveryProtocol::Native
    );
}

#[test]
fn target_protocol_can_be_registry_derived() {
    let tool = semantic_tool(
        "echo",
        Some(LatencyHint::Instant),
        json!({"type": "object"}),
        None,
    );
    let registry = TargetProtocolRegistry::new(DiscoveryProtocol::OpenAi);
    assert_eq!(
        target_protocol_for_tool_with_registry(&tool, &registry).unwrap(),
        DiscoveryProtocol::OpenAi
    );
}

#[test]
fn target_protocol_reads_schema_extension() {
    let tool = semantic_tool(
        "echo",
        Some(LatencyHint::Instant),
        json!({
            "type": "object",
            "x-chio-target-protocol": "mcp"
        }),
        None,
    );
    assert_eq!(
        target_protocol_for_tool(&tool).unwrap(),
        DiscoveryProtocol::Mcp
    );
}

#[test]
fn target_protocol_rejects_unknown_extension_value() {
    let tool = semantic_tool(
        "echo",
        Some(LatencyHint::Instant),
        json!({
            "type": "object",
            "x-chio-target-protocol": "smtp"
        }),
        None,
    );
    assert!(target_protocol_for_tool(&tool).is_err());
}

#[test]
fn target_protocol_rejects_non_string_extension_value() {
    let tool = semantic_tool(
        "echo",
        Some(LatencyHint::Instant),
        json!({
            "type": "object",
            "x-chio-target-protocol": 42
        }),
        None,
    );
    let err = target_protocol_for_tool(&tool).unwrap_err();

    assert!(err.contains("x-chio-target-protocol must be a string"));
}

#[test]
fn orchestrator_rejects_empty_origin_request_id_before_signed_lineage() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = explicit_local_manifest_registry("test-srv", "echo");
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);

    let err = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: " ".to_string(),
                kernel_request_id: "a2a-empty-origin-kernel-1".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                authenticated_session_id: None,
                security_context: None,
                model_metadata: None,
                bridge_security: explicit_local_bridge_security("test-srv", "echo"),
            },
        )
        .unwrap_err();

    assert_eq!(
        err.to_string(),
        "invalid request envelope: origin_request_id must be a non-empty string"
    );
}

#[test]
fn orchestrator_rejects_padded_or_control_execution_identity_before_signed_lineage() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = explicit_local_manifest_registry("test-srv", "echo");
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);
    let capability = capability_for_tool(&issuer, &subject, "test-srv", "echo");
    let agent_id = subject.public_key().to_hex();

    let cases = [
        ("origin_request_id", " a2a-padded-origin "),
        ("kernel_request_id", "kernel\ncontrol"),
        ("target_server_id", " test-srv "),
        ("target_tool_name", "echo\rcontrol"),
        ("agent_id", " agent-padded "),
    ];

    for (field_name, malformed_value) in cases {
        let mut request = CrossProtocolExecutionRequest {
            origin_request_id: "a2a-valid-origin".to_string(),
            kernel_request_id: "a2a-valid-kernel".to_string(),
            target_protocol: DiscoveryProtocol::Native,
            target_server_id: "test-srv".to_string(),
            target_tool_name: "echo".to_string(),
            agent_id: agent_id.clone(),
            arguments: json!({"message":"hello"}),
            capability: capability.clone(),
            source_envelope: json!({
                "message": {"role":"user"},
                "metadata": { "chio": { "targetSkillId": "echo" } }
            }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            authenticated_session_id: None,
            security_context: None,
            model_metadata: None,
            bridge_security: explicit_local_bridge_security("test-srv", "echo"),
        };

        match field_name {
            "origin_request_id" => request.origin_request_id = malformed_value.to_string(),
            "kernel_request_id" => request.kernel_request_id = malformed_value.to_string(),
            "target_server_id" => request.target_server_id = malformed_value.to_string(),
            "target_tool_name" => request.target_tool_name = malformed_value.to_string(),
            "agent_id" => request.agent_id = malformed_value.to_string(),
            _ => unreachable!("test case uses only request identity fields"),
        }

        let err = orchestrator.execute(&MockBridge, request).unwrap_err();

        assert_eq!(
                err.to_string(),
                format!(
                    "invalid request envelope: {field_name} must be unpadded and contain no control characters"
                )
            );
    }
}

#[test]
fn orchestrator_rejects_forged_capability_ref_parent_hash() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = explicit_local_manifest_registry("test-srv", "echo");
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);
    let capability = capability_for_tool(&issuer, &subject, "test-srv", "echo");

    let err = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-forged-cap-ref".to_string(),
                kernel_request_id: "a2a-forged-cap-ref-kernel-1".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability,
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": {
                        "chio": {
                            "targetSkillId": "echo",
                            "capabilityRef": {
                                "chioCapabilityId": "cap-test-srv-echo",
                                "originProtocol": "a2a",
                                "protocolContext": {"targetSkillId": "echo"},
                                "parentCapabilityHash": "forged-parent-hash"
                            }
                        }
                    }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                authenticated_session_id: None,
                security_context: None,
                model_metadata: None,
                bridge_security: explicit_local_bridge_security("test-srv", "echo"),
            },
        )
        .unwrap_err();

    assert_eq!(
            err.to_string(),
            "invalid request envelope: capabilityRef parentCapabilityHash does not match active capability lineage"
        );
}

#[test]
fn orchestrator_rejects_capability_ref_origin_protocol_drift() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = explicit_local_manifest_registry("test-srv", "echo");
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);
    let capability = capability_for_tool(&issuer, &subject, "test-srv", "echo");
    let parent_hash = parent_capability_hash(&capability).unwrap();

    let err = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-drifted-cap-ref".to_string(),
                kernel_request_id: "a2a-drifted-cap-ref-kernel-1".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability,
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": {
                        "chio": {
                            "targetSkillId": "echo",
                            "capabilityRef": {
                                "chioCapabilityId": "cap-test-srv-echo",
                                "originProtocol": "acp",
                                "protocolContext": {"targetSkillId": "echo"},
                                "parentCapabilityHash": parent_hash
                            }
                        }
                    }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                authenticated_session_id: None,
                security_context: None,
                model_metadata: None,
                bridge_security: explicit_local_bridge_security("test-srv", "echo"),
            },
        )
        .unwrap_err();

    assert_eq!(
            err.to_string(),
            "invalid request envelope: capabilityRef originProtocol acp does not match source protocol a2a"
        );
}

#[test]
fn orchestrator_executes_and_preserves_bridge_lineage() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = explicit_local_manifest_registry("test-srv", "echo");
    let expected_sidecar = registry.bridge_security("test-srv", "echo").unwrap();
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);

    let result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-task-1".to_string(),
                kernel_request_id: "a2a-a2a-task-1".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                authenticated_session_id: None,
                security_context: None,
                model_metadata: None,
                bridge_security: expected_sidecar.clone(),
            },
        )
        .unwrap();

    assert_eq!(result.source_protocol, DiscoveryProtocol::A2a);
    assert_eq!(result.target_protocol, DiscoveryProtocol::Native);
    assert_eq!(
        result.capability_ref.chio_capability_id,
        "cap-test-srv-echo"
    );
    assert_eq!(
        result.projected_request["metadata"]["chio"]["capabilityRef"]["chioCapabilityId"].as_str(),
        Some("cap-test-srv-echo")
    );
    assert_eq!(result.trace.hops.len(), 2);
    assert!(result.trace.hops[1].receipt_id.is_some());

    let metadata = result.metadata();
    assert_eq!(
        metadata["chio"]["authorityPath"].as_str(),
        Some(CROSS_PROTOCOL_AUTHORITY_PATH)
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
        metadata["chio"]["bridge"]["terminalProtocol"].as_str(),
        Some("native")
    );
    let routed_sidecar = metadata
        .pointer("/chio/receipt/metadata/chio_manifest_security_v1")
        .expect("routed receipt must retain the complete admitted sidecar");
    assert_eq!(
        chio_core::canonical_json_bytes(routed_sidecar).unwrap(),
        chio_core::canonical_json_bytes(&serde_json::to_value(expected_sidecar).unwrap()).unwrap()
    );
    assert_eq!(routed_sidecar["effective_egress"].as_bool(), Some(false));
    assert!(routed_sidecar["flow"].is_null());
    assert_eq!(
        metadata["chio"]["routeSelection"]["decision"].as_str(),
        Some("select")
    );
    assert_eq!(
        metadata["chio"]["routeSelection"]["selectedTargetProtocol"].as_str(),
        Some("native")
    );
    assert!(metadata["chio"]["bridge"]["capabilityEnvelope"]
        .get("capability")
        .is_none());
    assert_eq!(
        metadata["chio"]["bridge"]["capabilityEnvelope"]["capabilityRef"]["chioCapabilityId"]
            .as_str(),
        Some("cap-test-srv-echo")
    );
}

#[test]
fn orchestrator_fail_closes_with_empty_attenuation_on_out_of_scope_target() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = explicit_local_manifest_registry("test-srv", "write");
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);

    let result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-task-2".to_string(),
                kernel_request_id: "a2a-a2a-task-2".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "write".to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"nope"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "write" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                authenticated_session_id: None,
                security_context: None,
                model_metadata: None,
                bridge_security: explicit_local_bridge_security("test-srv", "write"),
            },
        )
        .unwrap();

    assert!(result
        .capability_envelope
        .attenuated_scope
        .grants
        .is_empty());
    assert!(matches!(result.response.verdict, KernelVerdict::Deny));
    assert_eq!(result.metadata()["chio"]["decision"].as_str(), Some("deny"));
    assert_eq!(
        result.metadata()["chio"]["routeSelection"]["decision"].as_str(),
        Some("select")
    );
}

#[test]
fn pending_approval_metadata_is_not_labeled_allow() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = explicit_local_manifest_registry("test-srv", "echo");
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);

    let mut result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-task-pending".to_string(),
                kernel_request_id: "a2a-a2a-task-pending".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                authenticated_session_id: None,
                security_context: None,
                model_metadata: None,
                bridge_security: explicit_local_bridge_security("test-srv", "echo"),
            },
        )
        .unwrap();
    result.response.verdict = KernelVerdict::PendingApproval;
    result.response.reason = Some("approval required".to_string());

    let metadata = result.metadata();
    assert_eq!(
        metadata["chio"]["decision"].as_str(),
        Some("pending_approval")
    );
    assert_eq!(
        metadata["chio"]["reason"].as_str(),
        Some("approval required")
    );
}

#[test]
fn orchestrator_dispatches_to_registered_target_executor() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let executor = MockMcpExecutor;
    let registry = explicit_local_manifest_registry("test-srv", "echo");
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry).with_executor(&executor);

    let result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-task-mcp".to_string(),
                kernel_request_id: "a2a-mcp-1".to_string(),
                target_protocol: DiscoveryProtocol::Mcp,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                authenticated_session_id: None,
                security_context: None,
                model_metadata: None,
                bridge_security: explicit_local_bridge_security("test-srv", "echo"),
            },
        )
        .unwrap();

    assert_eq!(result.target_protocol, DiscoveryProtocol::Mcp);
    assert_eq!(
        result
            .protocol_result
            .as_ref()
            .and_then(|value| value["isError"].as_bool()),
        Some(false)
    );
    assert_eq!(result.protocol_notifications.len(), 1);
    assert_eq!(
        result.metadata()["chio"]["targetExecution"]["projectedResult"],
        Value::Bool(true)
    );
    assert_eq!(result.trace.hops.len(), 3);
    assert_eq!(result.trace.hops[1].protocol, DiscoveryProtocol::Mcp);
    assert_eq!(result.trace.hops[2].protocol, DiscoveryProtocol::Native);
    assert_eq!(
        result.metadata()["chio"]["bridge"]["route"]["multiHop"],
        Value::Bool(true)
    );
    assert_eq!(
        result.metadata()["chio"]["routeSelection"]["selectedTargetProtocol"].as_str(),
        Some("mcp")
    );
}

#[test]
fn orchestrator_capability_envelope_uses_selected_native_fallback_target() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let executor = MockMcpExecutor;
    let registry = explicit_local_manifest_registry("test-srv", "echo");
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry)
        .with_executor(&executor)
        .with_protocol_availability(
            DiscoveryProtocol::Mcp,
            RouteAvailabilityStatus::unavailable("mcp route unavailable"),
        );

    let result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-task-mcp-fallback".to_string(),
                kernel_request_id: "a2a-mcp-fallback-1".to_string(),
                target_protocol: DiscoveryProtocol::Mcp,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: Some(governed_intent_with_control_plane(json!({
                    "allowNativeFallback": true
                }))),
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                authenticated_session_id: None,
                security_context: None,
                model_metadata: None,
                bridge_security: explicit_local_bridge_security("test-srv", "echo"),
            },
        )
        .unwrap();

    assert_eq!(result.target_protocol, DiscoveryProtocol::Native);
    assert_eq!(result.terminal_protocol, DiscoveryProtocol::Native);
    assert_eq!(
        result.capability_envelope.target_protocol,
        DiscoveryProtocol::Native
    );
    assert_eq!(
        result.metadata()["chio"]["bridge"]["capabilityEnvelope"]["targetProtocol"].as_str(),
        Some("native")
    );
    assert_eq!(
        result.metadata()["chio"]["routeSelection"]["selectedTargetProtocol"].as_str(),
        Some("native")
    );
    assert_eq!(result.trace.hops.len(), 2);
    assert_eq!(result.trace.hops[1].protocol, DiscoveryProtocol::Native);
}

#[test]
fn orchestrator_preserves_model_metadata_for_model_constrained_grant() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = explicit_local_manifest_registry("test-srv", "echo");
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);

    let result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-model-1".to_string(),
                kernel_request_id: "a2a-model-kernel-1".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool_with_constraints(
                    &issuer,
                    &subject,
                    "test-srv",
                    "echo",
                    vec![Constraint::ModelConstraint {
                        allowed_model_ids: vec!["gpt-5".to_string()],
                        min_safety_tier: Some(ModelSafetyTier::High),
                    }],
                ),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                authenticated_session_id: None,
                security_context: None,
                model_metadata: Some(ModelMetadata {
                    model_id: "gpt-5".to_string(),
                    safety_tier: Some(ModelSafetyTier::High),
                    provider: Some("openai".to_string()),
                    provenance_class:
                        chio_core::capability::governance::ProvenanceEvidenceClass::Asserted,
                }),
                bridge_security: explicit_local_bridge_security("test-srv", "echo"),
            },
        )
        .unwrap();

    assert!(matches!(result.response.verdict, KernelVerdict::Allow));
}

#[test]
fn orchestrator_denies_unregistered_non_native_target_with_signed_route_selection() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let registry = explicit_egress_manifest_registry("test-srv", "echo");
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry);
    let expected_sidecar = registry.bridge_security("test-srv", "echo").unwrap();

    let result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-task-mcp-missing".to_string(),
                kernel_request_id: "a2a-mcp-missing-1".to_string(),
                target_protocol: DiscoveryProtocol::Mcp,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                authenticated_session_id: None,
                security_context: None,
                model_metadata: None,
                bridge_security: expected_sidecar.clone(),
            },
        )
        .unwrap();

    assert!(matches!(result.response.verdict, KernelVerdict::Deny));
    assert_eq!(
        result.metadata()["chio"]["routeSelection"]["decision"].as_str(),
        Some("deny")
    );
    assert_eq!(
        result.metadata()["chio"]["routeSelection"]["selectedTargetProtocol"].as_str(),
        None
    );
    let deny_sidecar = result
        .metadata()
        .pointer("/chio/receipt/metadata/chio_manifest_security_v1")
        .cloned()
        .expect("planned deny receipt must retain the complete admitted sidecar");
    assert_eq!(
        chio_core::canonical_json_bytes(&deny_sidecar).unwrap(),
        chio_core::canonical_json_bytes(&serde_json::to_value(expected_sidecar).unwrap()).unwrap()
    );
}

#[test]
fn orchestrator_dispatches_to_registered_openai_target_executor() {
    let (issuer, kernel) = test_kernel();
    let subject = Keypair::generate();
    let executor = OpenAiTargetExecutor;
    let registry = explicit_local_manifest_registry("test-srv", "echo");
    let orchestrator = CrossProtocolOrchestrator::new(&kernel, &registry).with_executor(&executor);

    let result = orchestrator
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "a2a-openai-1".to_string(),
                kernel_request_id: "a2a-openai-kernel-1".to_string(),
                target_protocol: DiscoveryProtocol::OpenAi,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message":"hello"}),
                capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
                source_envelope: json!({
                    "message": {"role":"user"},
                    "metadata": { "chio": { "targetSkillId": "echo" } }
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                authenticated_session_id: None,
                security_context: None,
                model_metadata: None,
                bridge_security: explicit_local_bridge_security("test-srv", "echo"),
            },
        )
        .unwrap();

    assert_eq!(result.target_protocol, DiscoveryProtocol::OpenAi);
    assert_eq!(result.terminal_protocol, DiscoveryProtocol::Native);
    assert_eq!(
        result
            .protocol_result
            .as_ref()
            .and_then(|value| value["type"].as_str()),
        Some("function_call_output")
    );
    assert_eq!(
        result
            .protocol_result
            .as_ref()
            .and_then(|value| value["receipt_ref"].as_str()),
        Some(result.response.receipt.id.as_str())
    );
    assert_eq!(result.trace.hops.len(), 3);
    assert_eq!(result.trace.hops[1].protocol, DiscoveryProtocol::OpenAi);
    assert_eq!(result.trace.hops[2].protocol, DiscoveryProtocol::Native);
    assert_eq!(
        result.metadata()["chio"]["routeSelection"]["selectedTargetProtocol"].as_str(),
        Some("open_ai")
    );
}

#[test]
fn direct_openai_target_rejects_invalid_signed_schema_arguments_without_effects_and_recovers() {
    let dispatches = std::sync::Arc::new(AtomicUsize::new(0));
    let issuer = Keypair::generate();
    let config = KernelConfig {
        ca_public_keys: vec![issuer.public_key()],
        keypair: issuer.clone(),
        max_delegation_depth: 8,
        policy_hash: "policy-openai-target-schema".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(CountingNativeToolServer {
        dispatches: std::sync::Arc::clone(&dispatches),
    }));
    let registry = admitted_manifest_registry_with_schema(
        "test-srv",
        "echo",
        None,
        RuntimeToolTopology::local(),
        json!({
            "type": "object",
            "properties": {
                "message": {"type": "string", "minLength": 1, "maxLength": 4}
            },
            "required": ["message"],
            "additionalProperties": false
        }),
    );
    let subject = Keypair::generate();
    let capability = capability_for_tool(&issuer, &subject, "test-srv", "echo");
    let capability_ref =
        CrossProtocolCapabilityRef::from_capability(&capability, DiscoveryProtocol::A2a, None)
            .unwrap();
    let capability_envelope = CrossProtocolCapabilityEnvelope {
        schema: CROSS_PROTOCOL_CAPABILITY_ENVELOPE_SCHEMA.to_string(),
        capability_ref: capability_ref.clone(),
        target_protocol: DiscoveryProtocol::OpenAi,
        attenuated_scope: capability.scope.clone(),
        bridged_at: 1,
        bridge_id: "bridge-openai-schema".to_string(),
    };
    let route_id = "a2a-openai-native".to_string();
    let route_selection = RouteSelectionEvidence {
        route_selection_id: "route-openai-schema".to_string(),
        decision: RouteSelectionDecision::Select,
        source_protocol: DiscoveryProtocol::A2a,
        requested_target_protocol: DiscoveryProtocol::OpenAi,
        selected_route_id: Some(route_id.clone()),
        selected_target_protocol: Some(DiscoveryProtocol::OpenAi),
        selected_protocols: vec![DiscoveryProtocol::A2a, DiscoveryProtocol::OpenAi],
        reason: None,
        governed_intent_id: None,
        candidates: vec![RouteCandidateEvidence {
            route_id,
            target_protocol: DiscoveryProtocol::OpenAi,
            selected_protocols: vec![DiscoveryProtocol::A2a, DiscoveryProtocol::OpenAi],
            available: true,
            availability_reason: None,
        }],
    };
    let projected_request = json!({"type": "function_call"});
    let mut execution = CrossProtocolExecutionRequest {
        origin_request_id: "openai-schema-invalid".to_string(),
        kernel_request_id: "openai-schema-invalid-kernel".to_string(),
        target_protocol: DiscoveryProtocol::OpenAi,
        target_server_id: "test-srv".to_string(),
        target_tool_name: "echo".to_string(),
        agent_id: subject.public_key().to_hex(),
        arguments: json!({"message": "abcde"}),
        capability,
        source_envelope: json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        authenticated_session_id: None,
        security_context: None,
        bridge_security: registry.bridge_security("test-srv", "echo").unwrap(),
    };
    let executor = OpenAiTargetExecutor;
    let receipt_count_before = kernel.receipt_log().len();

    let invalid = executor.execute(CrossProtocolTargetRequest {
        kernel: &kernel,
        manifest_registry: &registry,
        execution: &execution,
        source_protocol: DiscoveryProtocol::A2a,
        bridge_id: "bridge-openai-schema",
        capability_ref: &capability_ref,
        capability_envelope: &capability_envelope,
        route_selection: &route_selection,
        projected_request: &projected_request,
    });
    let error = match invalid {
        Err(error) => error,
        Ok(_) => panic!("invalid arguments must be rejected"),
    };

    assert!(matches!(
        error,
        BridgeError::InvalidRequest(reason)
            if reason.contains("signed manifest input schema")
    ));
    assert_eq!(dispatches.load(Ordering::SeqCst), 0);
    assert_eq!(kernel.receipt_log().len(), receipt_count_before);

    execution.origin_request_id = "openai-schema-valid".to_string();
    execution.kernel_request_id = "openai-schema-valid-kernel".to_string();
    execution.arguments = json!({"message": "chio"});
    let valid = executor
        .execute(CrossProtocolTargetRequest {
            kernel: &kernel,
            manifest_registry: &registry,
            execution: &execution,
            source_protocol: DiscoveryProtocol::A2a,
            bridge_id: "bridge-openai-schema",
            capability_ref: &capability_ref,
            capability_envelope: &capability_envelope,
            route_selection: &route_selection,
            projected_request: &projected_request,
        })
        .unwrap();

    assert_eq!(valid.response.verdict, KernelVerdict::Allow);
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(kernel.receipt_log().len(), receipt_count_before + 1);
}

fn governed_intent_with_control_plane(control_plane: Value) -> GovernedTransactionIntent {
    GovernedTransactionIntent::tool_invocation(
        chio_core::capability::governance::GovernedToolInvocationIntentBody {
            id: "intent-1".to_string(),
            server_id: "test-srv".to_string(),
            tool_name: "echo".to_string(),
            purpose: "test route planning".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(json!({ "chioControlPlane": control_plane })),
        },
    )
}

include!("tests/routing_and_metadata.rs");
