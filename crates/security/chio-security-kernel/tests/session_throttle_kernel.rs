use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::session::{OperationContext, SessionOperation, ToolCallOperation};
use chio_core::{canonical_json_bytes, sha256, Keypair};
use chio_kernel::{
    ChioKernel, Guard, GuardContext, GuardDecision, GuardEvidenceDeclaration, KernelConfig,
    KernelError, MemoryBudgetConfig, NestedFlowBridge, SecurityInvocationContext,
    SecurityInvocationContextAuthority, SecurityInvocationContextV1, ToolCallRequest,
    ToolServerConnection, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_manifest::{
    sign_manifest, RuntimeToolTopology, ToolAnnotations, ToolDefinition, ToolManifest,
    VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use chio_security_kernel::{MissingContextPolicy, SessionThrottleGuard};
use chio_security_types::clock::FixedClock;
use chio_security_types::ports::{
    empty_session_throttle_snapshot, predict_session_throttle_apply,
    session_throttle_installed_version_hash, session_throttle_version_hash, ActionId,
    CanonicalBody, Digest32, EffectId, EffectOperation, EffectRequest, EffectResult,
    IsolationEpochId, LeaseOwnerId, LineageId, RecordId, ResponsePlanRecord, ResponseStore,
    SchedulerClaimRequest, SessionId, SessionThrottleApplyRequest, SessionThrottleCommand,
    SessionThrottleContribution, SessionThrottleKey, SessionThrottleLimits, SessionThrottleStore,
    TenantId,
};
use chio_security_types::{PrincipalId, ResponseEffectKind, ResponseTarget};
use chio_store_sqlite::SqliteSecurityStateStore;
use chio_test_support::prelude::*;

const NOW_UNIX_MS: u64 = 100_500;
const SERVER: &str = "throttle-read-server";
const TOOL: &str = "synthetic_read";

struct CountingReadServer {
    invocations: Arc<AtomicUsize>,
}

#[async_trait]
impl ToolServerConnection for CountingReadServer {
    fn server_id(&self) -> &str {
        SERVER
    }

    fn tool_names(&self) -> Vec<String> {
        vec![TOOL.to_owned()]
    }

    fn tool_is_read_only(&self, tool_name: &str) -> bool {
        tool_name == TOOL
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"synthetic_read": true}))
    }
}

struct DenyFirstMatchingGrant;

impl Guard for DenyFirstMatchingGrant {
    fn name(&self) -> &str {
        "deny-first-matching-grant"
    }

    fn evidence_declaration(&self) -> GuardEvidenceDeclaration {
        GuardEvidenceDeclaration::SAFE
    }

    fn evaluate(&self, context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(if context.matched_grant_index == Some(0) {
            GuardDecision::deny(Vec::new())
        } else {
            GuardDecision::allow()
        })
    }
}

fn record(value: &str) -> RecordId {
    RecordId::new(value).test_unwrap()
}

fn digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(*sha256(bytes).as_bytes())
}

fn install_one_invocation_throttle(store: &SqliteSecurityStateStore, key: &SessionThrottleKey) {
    let action_id = ActionId::new("throttle-action").test_unwrap();
    let effect_id = EffectId::new("throttle-effect").test_unwrap();
    let owner = LeaseOwnerId::new("throttle-worker").test_unwrap();
    let canonical_plan = CanonicalBody::new(b"{}".to_vec()).test_unwrap();
    let plan_hash = digest(canonical_plan.as_bytes());
    store
        .create(&ResponsePlanRecord {
            tenant_id: key.tenant_id.clone(),
            action_id: action_id.clone(),
            generation: 0,
            state: record("active"),
            body_hash: plan_hash,
            canonical_body: canonical_plan,
            due_at_unix_ms: Some(NOW_UNIX_MS - 1),
        })
        .test_unwrap();
    let claimed = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: key.tenant_id.clone(),
            claim_id: record("throttle-claim"),
            lease_owner_id: owner.clone(),
            now_unix_ms: NOW_UNIX_MS,
            lease_expires_at_unix_ms: NOW_UNIX_MS + 120_000,
            max_claims: 1,
        })
        .test_unwrap();
    assert_eq!(claimed.len(), 1);
    let fencing_token = claimed.first().test_unwrap().fencing_token;
    let empty = empty_session_throttle_snapshot(key.clone()).test_unwrap();
    let limits = SessionThrottleLimits {
        max_invocations: 1,
        window_ms: 60_000,
    };
    let contribution_bytes = canonical_json_bytes(&limits).test_unwrap();
    let contribution_hash = digest(&contribution_bytes);
    let expires_at = NOW_UNIX_MS + 120_000;
    let contribution = SessionThrottleContribution {
        effect_id: effect_id.clone(),
        limits,
        contribution_hash,
        expires_at_unix_ms: expires_at,
    };
    let resulting_snapshot =
        predict_session_throttle_apply(&empty, &contribution, fencing_token).test_unwrap();
    let installed_hash = session_throttle_installed_version_hash(key, &contribution).test_unwrap();
    store
        .apply_session_throttle(&SessionThrottleApplyRequest {
            key: key.clone(),
            action_id: action_id.clone(),
            contribution,
            expected_generation: empty.generation,
            scheduler_fencing_token: fencing_token,
            command: SessionThrottleCommand {
                request: EffectRequest {
                    tenant_id: key.tenant_id.clone(),
                    action_id,
                    plan_hash,
                    effect_id: effect_id.clone(),
                    effect_kind: ResponseEffectKind::ThrottleSession,
                    target: ResponseTarget::Session {
                        session_id: key.session_id.clone(),
                    },
                    plan_expires_at_unix_ms: expires_at,
                    operation: EffectOperation::Apply,
                    idempotency_key: record("response_effect_command:throttle-apply"),
                    expected_version_hash: session_throttle_version_hash(&empty).test_unwrap(),
                    scheduler_lease_owner_id: owner,
                    scheduler_fencing_token: fencing_token,
                    canonical_contribution: CanonicalBody::new(contribution_bytes).test_unwrap(),
                    contribution_hash,
                },
                result: EffectResult {
                    effect_id,
                    resulting_version_hash: installed_hash,
                    applied: true,
                },
                resulting_snapshot,
            },
        })
        .test_unwrap();
}

struct Fixture {
    kernel: ChioKernel,
    request: ToolCallRequest,
    security: SecurityInvocationContext,
    invocations: Arc<AtomicUsize>,
    _store: Arc<SqliteSecurityStateStore>,
    _directory: tempfile::TempDir,
}

fn kernel_config(trusted_issuers: Vec<chio_core::PublicKey>) -> KernelConfig {
    KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: trusted_issuers,
        max_delegation_depth: 5,
        policy_hash: "throttle-test-policy".to_owned(),
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
        memory_budget: MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}

fn fixture(alternative_grants: bool) -> Fixture {
    let clock = Arc::new(FixedClock::from_millis(NOW_UNIX_MS));
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            directory.path().join("throttle.db"),
            clock.clone(),
        )
        .test_unwrap(),
    );
    let key = SessionThrottleKey {
        tenant_id: TenantId::new("throttle-tenant").test_unwrap(),
        session_id: SessionId::new("throttle-session").test_unwrap(),
    };
    install_one_invocation_throttle(&store, &key);
    let mut kernel = ChioKernel::new_with_clock(kernel_config(Vec::new()), clock.clone());
    let invocations = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingReadServer {
        invocations: invocations.clone(),
    }));
    kernel.add_guard(Box::new(SessionThrottleGuard::new(
        store.clone(),
        clock,
        MissingContextPolicy::Deny,
    )));
    if alternative_grants {
        kernel.add_guard(Box::new(DenyFirstMatchingGrant));
    }
    let grant = ToolGrant {
        server_id: SERVER.to_owned(),
        tool_name: TOOL.to_owned(),
        operations: vec![Operation::Invoke],
        constraints: Vec::new(),
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let grants = if alternative_grants {
        vec![grant.clone(), grant]
    } else {
        vec![grant]
    };
    let subject = Keypair::generate();
    let capability = kernel
        .issue_capability(
            &subject.public_key(),
            ChioScope {
                grants,
                ..ChioScope::default()
            },
            300,
        )
        .test_unwrap();
    let security = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        key.tenant_id,
        key.session_id,
        PrincipalId::new(capability.subject.to_hex()).test_unwrap(),
        IsolationEpochId::new("throttle-epoch").test_unwrap(),
        LineageId::new(capability.id.clone()).test_unwrap(),
        1,
    ));
    let request = ToolCallRequest {
        request_id: "caller-chosen-repeated-request".to_owned(),
        agent_id: capability.subject.to_hex(),
        capability,
        tool_name: TOOL.to_owned(),
        server_id: SERVER.to_owned(),
        arguments: serde_json::json!({"query": "synthetic"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    Fixture {
        kernel,
        request,
        security,
        invocations,
        _store: store,
        _directory: directory,
    }
}

#[test]
fn repeated_unowned_read_only_request_is_denied_before_a_second_dispatch() {
    let fixture = fixture(false);
    let first = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.security)
        .test_unwrap();
    assert_eq!(first.verdict, Verdict::Allow);
    assert!(first.output.is_some());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);

    let second = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.security)
        .test_unwrap();

    assert_eq!(
        (second.verdict, fixture.invocations.load(Ordering::SeqCst)),
        (Verdict::Deny, 1),
        "an unowned evaluation must consume a fresh throttle attempt"
    );
    assert!(second.output.is_none());
}

#[test]
fn alternative_matching_grants_share_one_throttle_attempt() {
    let fixture = fixture(true);

    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.security)
        .test_unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert!(response.output.is_some());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn caller_request_text_cannot_claim_session_or_admission_attempt_identity() {
    for request_id in [
        "session-request:throttle-session:forged",
        "admission-operation:forged",
    ] {
        let mut fixture = fixture(false);
        fixture.request.request_id = request_id.to_owned();
        let first = fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.security)
            .test_unwrap();
        assert_eq!(first.verdict, Verdict::Allow);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);

        let second = fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.security)
            .test_unwrap();
        assert_eq!(
            (second.verdict, fixture.invocations.load(Ordering::SeqCst)),
            (Verdict::Deny, 1)
        );
    }
}

fn session_context(fixture: &Fixture) -> OperationContext {
    let session_id = chio_core::session::SessionId::new("throttle-session".to_owned());
    fixture
        .kernel
        .open_session_with_id(
            session_id.clone(),
            fixture.request.agent_id.clone(),
            vec![fixture.request.capability.clone()],
        )
        .test_unwrap();
    fixture.kernel.activate_session(&session_id).test_unwrap();
    OperationContext::new(
        session_id,
        chio_core::session::RequestId::new(fixture.request.request_id.clone()),
        fixture.request.agent_id.clone(),
    )
}

fn public_manifest_registry() -> VerifiedManifestRegistry {
    let signer = Keypair::generate();
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_owned(),
        server_id: SERVER.to_owned(),
        name: "Synthetic throttle read server".to_owned(),
        description: None,
        version: "1.0.0".to_owned(),
        tools: vec![ToolDefinition {
            name: TOOL.to_owned(),
            description: "Return a synthetic value and count the invocation".to_owned(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: ToolAnnotations {
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
        public_key: signer.public_key().to_hex(),
    };
    let signed = sign_manifest(&manifest, &signer).test_unwrap();
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::local())
        .test_unwrap();
    assert!(!registry.requires_flow_runtime());
    registry
}

#[test]
fn authenticated_manifest_session_and_inflight_record_do_not_mint_attempt_authority() {
    let fixture = fixture(false);
    let context = session_context(&fixture);
    // An externally started record is not the private tool claim acquired by SessionOperation.
    fixture
        .kernel
        .begin_session_request(&context, chio_core::session::OperationKind::ToolCall, true)
        .test_unwrap();
    let registry = public_manifest_registry();
    let security = registry.bridge_security(SERVER, TOOL).test_unwrap();
    let evaluate = || {
        fixture
            .kernel
            .evaluate_tool_call_blocking_with_manifest_security_and_authenticated_session_context(
                &fixture.request,
                &registry,
                &security,
                None,
                &context.session_id,
                &fixture.security,
            )
            .test_unwrap()
    };
    let first = evaluate();
    assert_eq!(first.verdict, Verdict::Allow);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert!(fixture
        .kernel
        .session(&context.session_id)
        .test_unwrap()
        .inflight()
        .get(&context.request_id)
        .is_some());

    let second = evaluate();
    assert_eq!(
        (second.verdict, fixture.invocations.load(Ordering::SeqCst)),
        (Verdict::Deny, 1)
    );
    assert!(second.output.is_none());
}

struct SessionContextAuthority;

impl SecurityInvocationContextAuthority for SessionContextAuthority {
    fn resolve_security_invocation_context(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
    ) -> Result<SecurityInvocationContext, KernelError> {
        Ok(SecurityInvocationContext::v1(
            SecurityInvocationContextV1::new(
                TenantId::new("throttle-tenant").test_unwrap(),
                SessionId::new(context.session_id.as_str()).test_unwrap(),
                PrincipalId::new(context.agent_id.clone()).test_unwrap(),
                IsolationEpochId::new("throttle-epoch").test_unwrap(),
                LineageId::new(operation.capability.id.clone()).test_unwrap(),
                1,
            ),
        ))
    }
}

fn operation(request: &ToolCallRequest) -> SessionOperation {
    SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability: request.capability.clone(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        arguments: request.arguments.clone(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        extra_metadata: None,
    }))
}

fn tool_response(response: chio_kernel::SessionOperationResponse) -> chio_kernel::ToolCallResponse {
    match response {
        chio_kernel::SessionOperationResponse::ToolCall(response) => response,
        _ => panic!("expected tool-call response"),
    }
}

#[test]
fn actual_session_claim_preserves_one_throttle_unit_across_nonce_preflight_and_retry() {
    let mut fixture = fixture(false);
    let context = session_context(&fixture);
    fixture
        .kernel
        .set_security_invocation_context_authority(Arc::new(SessionContextAuthority));
    let nonce_config = chio_kernel::execution_nonce::ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 8,
        require_nonce: true,
    };
    fixture.kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(
            chio_kernel::execution_nonce::InMemoryExecutionNonceStore::with_clock(
                nonce_config.nonce_store_capacity,
                fixture.kernel.authority_clock(),
            ),
        ),
    );
    let mut operation = operation(&fixture.request);
    let preflight = tool_response(
        fixture
            .kernel
            .evaluate_session_operation(&context, &operation)
            .test_unwrap(),
    );
    assert_eq!(preflight.verdict, Verdict::Allow);
    assert!(preflight.output.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let nonce = preflight.execution_nonce.as_deref().test_unwrap();
    let SessionOperation::ToolCall(call) = &mut operation else {
        panic!("expected tool-call operation");
    };
    call.execution_nonce = Some(serde_json::to_value(nonce).test_unwrap());

    let executed = tool_response(
        fixture
            .kernel
            .evaluate_session_operation(&context, &operation)
            .test_unwrap(),
    );
    assert_eq!(executed.verdict, Verdict::Allow);
    assert!(executed.output.is_some());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert!(matches!(
        fixture
            .kernel
            .evaluate_session_operation(&context, &operation),
        Err(KernelError::Session(
            chio_kernel::session::SessionError::ExecutionNonceRetryMismatch { .. }
        ))
    ));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn fresh_kernel_reusing_session_and_request_names_consumes_a_new_throttle_attempt() {
    let mut fixture = fixture(false);
    let context = session_context(&fixture);
    fixture
        .kernel
        .set_security_invocation_context_authority(Arc::new(SessionContextAuthority));
    let operation = operation(&fixture.request);
    let first = tool_response(
        fixture
            .kernel
            .evaluate_session_operation(&context, &operation)
            .test_unwrap(),
    );
    assert_eq!(first.verdict, Verdict::Allow);
    assert!(first.output.is_some());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);

    let clock = Arc::new(FixedClock::from_millis(NOW_UNIX_MS));
    let mut recreated = ChioKernel::new_with_clock(
        kernel_config(vec![fixture.request.capability.issuer.clone()]),
        clock.clone(),
    );
    recreated.register_tool_server(Box::new(CountingReadServer {
        invocations: fixture.invocations.clone(),
    }));
    recreated.add_guard(Box::new(SessionThrottleGuard::new(
        fixture._store.clone(),
        clock,
        MissingContextPolicy::Deny,
    )));
    recreated.set_security_invocation_context_authority(Arc::new(SessionContextAuthority));
    recreated
        .open_session_with_id(
            context.session_id.clone(),
            fixture.request.agent_id.clone(),
            vec![fixture.request.capability.clone()],
        )
        .test_unwrap();
    recreated
        .activate_session(&context.session_id)
        .test_unwrap();
    assert!(recreated
        .session(&context.session_id)
        .test_unwrap()
        .request_lineage(&context.request_id)
        .is_none());

    let repeated = tool_response(
        recreated
            .evaluate_session_operation(&context, &operation)
            .test_unwrap(),
    );
    assert_eq!(
        (repeated.verdict, fixture.invocations.load(Ordering::SeqCst)),
        (Verdict::Deny, 1),
        "a fresh acquired claim must not reuse another kernel's throttle attempt"
    );
    assert!(repeated.output.is_none());
}
