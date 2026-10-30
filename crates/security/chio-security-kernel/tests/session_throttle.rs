use std::sync::{Arc, Mutex};

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::Keypair;
use chio_kernel::{
    ChioKernel, Guard, GuardContext, GuardDecision, GuardEvidenceDeclaration, KernelConfig,
    KernelError, MemoryBudgetConfig, NestedFlowBridge, SecurityInvocationContext,
    SecurityInvocationContextV1, ToolCallRequest, ToolCallResponse, ToolServerConnection, Verdict,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_security_kernel::{Clock, MissingContextPolicy, SessionThrottleGuard};
use chio_security_types::ports::{
    empty_session_throttle_snapshot, predict_session_throttle_apply, session_throttle_version_hash,
    Digest32, EffectExecutionStatus, EffectResultQuery, IsolationEpochId, LineageId, PortError,
    PortResult, SessionId, SessionThrottleApplyRequest, SessionThrottleConsumeRequest,
    SessionThrottleContribution, SessionThrottleDecision, SessionThrottleKey,
    SessionThrottleLimits, SessionThrottleRemoveRequest, SessionThrottleSnapshot,
    SessionThrottleStore, SessionThrottleWindowUsage, SessionThrottleWindowUsages, TenantId,
};
use chio_security_types::PrincipalId;

#[derive(Clone, Copy)]
enum Behavior {
    Allow,
    Deny,
    Fail,
    Tamper,
}

struct FixedClock(u64);

impl chio_security_types::clock::Clock for FixedClock {
    fn read(
        &self,
    ) -> core::result::Result<
        chio_security_types::clock::ClockReading,
        chio_security_types::clock::ClockError,
    > {
        let value = self.0;
        chio_security_types::clock::Clock::read(
            &chio_security_types::clock::FixedClock::from_millis(value),
        )
    }
}

struct FakeThrottles {
    snapshot: SessionThrottleSnapshot,
    behavior: Behavior,
    invocations: Mutex<Vec<SessionThrottleConsumeRequest>>,
}

impl FakeThrottles {
    fn new(behavior: Behavior) -> Self {
        let key = throttle_key();
        let empty = empty_session_throttle_snapshot(key.clone())
            .unwrap_or_else(|error| panic!("empty throttle snapshot: {error}"));
        let contribution = SessionThrottleContribution {
            effect_id: chio_security_types::ports::EffectId::new("effect-throttle")
                .unwrap_or_else(|error| panic!("effect id: {error}")),
            limits: SessionThrottleLimits {
                window_ms: 1_000,
                max_invocations: 1,
            },
            contribution_hash: Digest32::new([7_u8; 32]),
            expires_at_unix_ms: u64::MAX,
        };
        let snapshot = predict_session_throttle_apply(&empty, &contribution, 1)
            .unwrap_or_else(|error| panic!("throttle snapshot: {error}"));
        Self {
            snapshot,
            behavior,
            invocations: Mutex::new(Vec::new()),
        }
    }

    fn invocations(&self) -> Vec<SessionThrottleConsumeRequest> {
        self.invocations
            .lock()
            .unwrap_or_else(|error| panic!("invocations poisoned: {error}"))
            .clone()
    }
}

impl SessionThrottleStore for FakeThrottles {
    fn ensure_session_throttles_ready(&self) -> PortResult<()> {
        match self.behavior {
            Behavior::Fail => Err(PortError::unavailable()),
            Behavior::Allow | Behavior::Deny | Behavior::Tamper => Ok(()),
        }
    }

    fn apply_session_throttle(
        &self,
        _request: &SessionThrottleApplyRequest,
    ) -> PortResult<SessionThrottleSnapshot> {
        Err(PortError::unavailable())
    }

    fn remove_session_throttle(
        &self,
        _request: &SessionThrottleRemoveRequest,
    ) -> PortResult<SessionThrottleSnapshot> {
        Err(PortError::unavailable())
    }

    fn load_session_throttles(
        &self,
        key: &SessionThrottleKey,
    ) -> PortResult<Option<SessionThrottleSnapshot>> {
        if matches!(self.behavior, Behavior::Fail) {
            return Err(PortError::unavailable());
        }
        if key != &self.snapshot.key {
            return Err(PortError::integrity_failure());
        }
        Ok(Some(self.snapshot.clone()))
    }

    fn consume_session_invocation(
        &self,
        request: &SessionThrottleConsumeRequest,
    ) -> PortResult<SessionThrottleDecision> {
        if matches!(self.behavior, Behavior::Fail) {
            return Err(PortError::unavailable());
        }
        if request.key != self.snapshot.key {
            return Err(PortError::integrity_failure());
        }
        self.invocations
            .lock()
            .unwrap_or_else(|error| panic!("invocations poisoned: {error}"))
            .push(request.clone());
        let contribution = &self.snapshot.contributions.as_slice()[0];
        let identity = chio_security_types::ports::session_throttle_window_identity(
            &request.key,
            &contribution.effect_id,
            contribution.limits,
            request.observed_at_unix_ms,
        )?;
        let denied = matches!(self.behavior, Behavior::Deny);
        let usage = SessionThrottleWindowUsage {
            effect_id: contribution.effect_id.clone(),
            identity,
            consumed_before: if denied { 1 } else { 0 },
            consumed_after: 1,
            max_invocations: 1,
            replayed: false,
        };
        Ok(SessionThrottleDecision {
            key: request.key.clone(),
            allowed: !denied,
            generation: self.snapshot.generation,
            current_version_hash: if matches!(self.behavior, Behavior::Tamper) {
                Digest32::new([99_u8; 32])
            } else {
                session_throttle_version_hash(&self.snapshot)?
            },
            windows: SessionThrottleWindowUsages::new(vec![usage])
                .map_err(|_| PortError::integrity_failure())?,
        })
    }

    fn load_session_throttle_result(
        &self,
        _query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        Err(PortError::unavailable())
    }
}

fn throttle_key() -> SessionThrottleKey {
    SessionThrottleKey {
        tenant_id: TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant id: {error}")),
        session_id: SessionId::new("session-a")
            .unwrap_or_else(|error| panic!("session id: {error}")),
    }
}

fn scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "server-a".to_string(),
            tool_name: "tool-a".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn request() -> ToolCallRequest {
    let keypair = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "capability-a".to_string(),
            issuer: keypair.public_key(),
            subject: keypair.public_key(),
            scope: scope(),
            issued_at: 1,
            expires_at: 60,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &keypair,
    )
    .unwrap_or_else(|error| panic!("sign capability: {error}"));
    ToolCallRequest {
        request_id: "request-a".to_string(),
        agent_id: capability.subject.to_hex(),
        capability,
        tool_name: "tool-a".to_string(),
        server_id: "server-a".to_string(),
        arguments: serde_json::json!({"value": "input"}),
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
    }
}

fn security_context(request: &ToolCallRequest) -> SecurityInvocationContext {
    SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        throttle_key().tenant_id,
        throttle_key().session_id,
        PrincipalId::new(request.agent_id.clone())
            .unwrap_or_else(|error| panic!("principal id: {error}")),
        IsolationEpochId::new("epoch-a").unwrap_or_else(|error| panic!("isolation epoch: {error}")),
        LineageId::new(request.capability.id.clone())
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        1,
    ))
}

struct SharedGuard {
    guard: Arc<SessionThrottleGuard>,
    attempts: Arc<Mutex<Vec<String>>>,
}

impl Guard for SharedGuard {
    fn name(&self) -> &str {
        self.guard.name()
    }

    fn evidence_declaration(&self) -> GuardEvidenceDeclaration {
        GuardEvidenceDeclaration::SAFE
    }

    fn evaluate(&self, context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        if let Some(attempt) = context.invocation_attempt_id() {
            self.attempts
                .lock()
                .unwrap_or_else(|_| panic!("attempt mutex poisoned"))
                .push(attempt.to_owned());
        }
        self.guard.evaluate(context)
    }
}

struct ReadServer;

#[async_trait::async_trait]
impl ToolServerConnection for ReadServer {
    fn server_id(&self) -> &str {
        "server-a"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["tool-a".to_owned()]
    }

    fn tool_is_read_only(&self, tool_name: &str) -> bool {
        tool_name == "tool-a"
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({"ok": true}))
    }
}

fn evaluate(
    guard: &Arc<SessionThrottleGuard>,
    request: &ToolCallRequest,
    security: Option<&SecurityInvocationContext>,
) -> Verdict {
    respond_recording_attempts(guard, request, security, &Arc::default()).verdict
}

fn respond_recording_attempts(
    guard: &Arc<SessionThrottleGuard>,
    request: &ToolCallRequest,
    security: Option<&SecurityInvocationContext>,
    attempts: &Arc<Mutex<Vec<String>>>,
) -> ToolCallResponse {
    let mut kernel = ChioKernel::new_with_clock(
        KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![request.capability.issuer.clone()],
            max_delegation_depth: 5,
            policy_hash: "throttle-guard-test-policy".to_owned(),
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
        },
        Arc::new(chio_security_types::clock::FixedClock::from_millis(10_500)),
    );
    kernel.register_tool_server(Box::new(ReadServer));
    kernel.add_guard(Box::new(SharedGuard {
        guard: guard.clone(),
        attempts: attempts.clone(),
    }));
    let result = if let Some(security) = security {
        kernel.evaluate_tool_call_blocking_with_security_context(request, security)
    } else {
        kernel.evaluate_tool_call_blocking(request)
    };
    result.unwrap_or_else(|error| panic!("evaluate throttle guard: {error}"))
}

#[test]
fn exact_decisions_allow_with_distinct_kernel_attempts() {
    let store = Arc::new(FakeThrottles::new(Behavior::Allow));
    let throttle_store: Arc<dyn SessionThrottleStore> = store.clone();
    let guard = Arc::new(SessionThrottleGuard::new(
        throttle_store,
        Arc::new(FixedClock(10_500)),
        MissingContextPolicy::Deny,
    ));
    let request = request();
    let security = security_context(&request);
    assert_eq!(evaluate(&guard, &request, Some(&security)), Verdict::Allow);
    assert_eq!(evaluate(&guard, &request, Some(&security)), Verdict::Allow);
    let invocations = store.invocations();
    assert_eq!(invocations.len(), 2);
    assert_eq!(invocations[0].key, throttle_key());
    assert_ne!(invocations[0].invocation_id, invocations[1].invocation_id);
    assert!(invocations[0]
        .invocation_id
        .as_str()
        .starts_with("session_throttle_invocation:"));
}

fn expected_invocation_id(
    domain: &[u8],
    schema_version: u8,
    request: &ToolCallRequest,
    attempt: &str,
) -> String {
    let commitment = serde_json::json!({
        "schema_version": schema_version,
        "tenant_id": "tenant-a",
        "session_id": "session-a",
        "request_id": request.request_id,
        "invocation_attempt_id": attempt,
        "capability_id": request.capability.id,
        "server_id": request.server_id,
        "tool_name": request.tool_name,
        "arguments": request.arguments,
    });
    let canonical = chio_core::canonical_json_bytes(&commitment)
        .unwrap_or_else(|error| panic!("canonical commitment: {error}"));
    let mut preimage = domain.to_vec();
    preimage.extend_from_slice(&canonical);
    format!(
        "session_throttle_invocation:{}",
        chio_core::sha256(&preimage).to_hex()
    )
}

#[test]
fn invocation_id_commits_to_the_v1_domain_and_schema_only() {
    let store = Arc::new(FakeThrottles::new(Behavior::Allow));
    let throttle_store: Arc<dyn SessionThrottleStore> = store.clone();
    let guard = Arc::new(SessionThrottleGuard::new(
        throttle_store,
        Arc::new(FixedClock(10_500)),
        MissingContextPolicy::Deny,
    ));
    let request = request();
    let security = security_context(&request);
    let attempts = Arc::default();
    assert_eq!(
        respond_recording_attempts(&guard, &request, Some(&security), &attempts).verdict,
        Verdict::Allow
    );
    let attempts = attempts
        .lock()
        .unwrap_or_else(|_| panic!("attempt mutex poisoned"))
        .clone();
    assert_eq!(attempts.len(), 1);
    let invocations = store.invocations();
    assert_eq!(invocations.len(), 1);
    let produced = invocations[0].invocation_id.as_str();
    assert_eq!(
        produced,
        expected_invocation_id(
            b"chio.session-throttle-invocation.v1\0",
            1,
            &request,
            &attempts[0]
        )
    );
    for (domain, schema_version) in [
        (&b"chio.session-throttle-invocation.v2\0"[..], 2),
        (&b"chio.session-throttle-invocation.v1\0"[..], 2),
        (&b"chio.session-throttle-invocation.v2\0"[..], 1),
    ] {
        assert_ne!(
            produced,
            expected_invocation_id(domain, schema_version, &request, &attempts[0])
        );
    }
}

#[test]
fn reconstructed_guard_preserves_the_session_and_uses_a_new_attempt() {
    let store = Arc::new(FakeThrottles::new(Behavior::Allow));
    let request = request();
    let security = security_context(&request);
    {
        let throttle_store: Arc<dyn SessionThrottleStore> = store.clone();
        let guard = Arc::new(SessionThrottleGuard::new(
            throttle_store,
            Arc::new(FixedClock(10_500)),
            MissingContextPolicy::Deny,
        ));
        assert_eq!(evaluate(&guard, &request, Some(&security)), Verdict::Allow);
    }
    let throttle_store: Arc<dyn SessionThrottleStore> = store.clone();
    let restored_guard = Arc::new(SessionThrottleGuard::new(
        throttle_store,
        Arc::new(FixedClock(10_500)),
        MissingContextPolicy::Deny,
    ));
    assert_eq!(
        evaluate(&restored_guard, &request, Some(&security)),
        Verdict::Allow
    );

    let invocations = store.invocations();
    assert_eq!(invocations.len(), 2);
    assert_eq!(invocations[0].key, invocations[1].key);
    assert_eq!(invocations[0].key.session_id.as_str(), "session-a");
    assert_ne!(invocations[0].invocation_id, invocations[1].invocation_id);
}

#[test]
fn exhausted_outage_and_tampered_decisions_all_deny() {
    let request = request();
    let security = security_context(&request);
    for behavior in [Behavior::Deny, Behavior::Fail, Behavior::Tamper] {
        let store: Arc<dyn SessionThrottleStore> = Arc::new(FakeThrottles::new(behavior));
        let guard = Arc::new(SessionThrottleGuard::new(
            store,
            Arc::new(FixedClock(10_500)),
            MissingContextPolicy::Deny,
        ));
        assert_eq!(evaluate(&guard, &request, Some(&security)), Verdict::Deny);
    }
}

#[test]
fn missing_authoritative_session_cannot_bypass_enforcement() {
    let store = Arc::new(FakeThrottles::new(Behavior::Allow));
    let throttle_store: Arc<dyn SessionThrottleStore> = store.clone();
    let guard = Arc::new(SessionThrottleGuard::new(
        throttle_store,
        Arc::new(FixedClock(10_500)),
        MissingContextPolicy::Deny,
    ));
    let request = request();
    assert_eq!(evaluate(&guard, &request, None), Verdict::Deny);
    assert!(store.invocations().is_empty());
}

#[test]
fn zero_or_failed_clock_denies_before_consumption() {
    struct FailingClock;
    impl chio_security_types::clock::Clock for FailingClock {
        fn read(
            &self,
        ) -> core::result::Result<
            chio_security_types::clock::ClockReading,
            chio_security_types::clock::ClockError,
        > {
            let value: PortResult<u64> = Err(PortError::unavailable());
            let value = value.map_err(|_| chio_security_types::clock::ClockError::Unavailable)?;
            chio_security_types::clock::Clock::read(
                &chio_security_types::clock::FixedClock::from_millis(value),
            )
        }
    }

    let request = request();
    let security = security_context(&request);
    for clock in [
        Arc::new(FixedClock(0)) as Arc<dyn Clock>,
        Arc::new(FailingClock) as Arc<dyn Clock>,
    ] {
        let store = Arc::new(FakeThrottles::new(Behavior::Allow));
        let throttle_store: Arc<dyn SessionThrottleStore> = store.clone();
        let guard = Arc::new(SessionThrottleGuard::new(
            throttle_store,
            clock,
            MissingContextPolicy::Deny,
        ));
        assert_eq!(evaluate(&guard, &request, Some(&security)), Verdict::Deny);
        assert!(store.invocations().is_empty());
    }
}

#[test]
fn standalone_security_context_cannot_mint_a_kernel_attempt() {
    let store = Arc::new(FakeThrottles::new(Behavior::Allow));
    let guard = SessionThrottleGuard::new(
        store.clone(),
        Arc::new(FixedClock(10_500)),
        MissingContextPolicy::Deny,
    );
    let request = request();
    let security = security_context(&request);
    let context = GuardContext::new(&request, &request.capability.scope)
        .with_security_context(Some(&security));

    assert!(context.invocation_attempt_id().is_none());
    assert_eq!(
        guard
            .evaluate(&context)
            .unwrap_or_else(|error| panic!("guard: {error}"))
            .verdict,
        Verdict::Deny
    );
    assert!(store.invocations().is_empty());
}

const MARKER: &str = "chio-throttle-deny-marker-4e19";

/// Deny evidence becomes the signed deny reason, so no path quotes request
/// text. The guard has no `Err` path; a store outage takes its failure path.
#[test]
fn deny_reason_carries_no_request_text() {
    let mut request = request();
    request.request_id = format!("request-{MARKER}");
    request.arguments = serde_json::json!({ MARKER: MARKER, "value": MARKER });
    let security = security_context(&request);
    for behavior in [
        Behavior::Allow,
        Behavior::Deny,
        Behavior::Fail,
        Behavior::Tamper,
    ] {
        for security in [Some(&security), None] {
            let store: Arc<dyn SessionThrottleStore> = Arc::new(FakeThrottles::new(behavior));
            let guard = Arc::new(SessionThrottleGuard::new(
                store,
                Arc::new(FixedClock(10_500)),
                MissingContextPolicy::Deny,
            ));
            assert_eq!(guard.evidence_declaration(), GuardEvidenceDeclaration::SAFE);
            let response = respond_recording_attempts(&guard, &request, security, &Arc::default());
            let reason = response.reason.unwrap_or_default();
            assert!(!reason.contains(MARKER), "{reason}");
            let details: Vec<_> = response
                .receipt
                .evidence
                .iter()
                .filter(|evidence| evidence.guard_name == "chio-session-throttle")
                .filter_map(|evidence| evidence.details.as_deref())
                .collect();
            for detail in &details {
                assert!(!detail.contains(MARKER), "{detail}");
            }
            if matches!(behavior, Behavior::Fail) && security.is_some() {
                assert_eq!(response.verdict, Verdict::Deny);
                assert_eq!(details, ["session throttle consumption failed"]);
            }
        }
    }
}
