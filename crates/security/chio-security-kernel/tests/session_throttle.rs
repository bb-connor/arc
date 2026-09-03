use std::sync::{Arc, Mutex};

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::Keypair;
use chio_kernel::{
    Guard, GuardContext, SecurityInvocationContext, SecurityInvocationContextV1, ToolCallRequest,
    Verdict,
};
use chio_security_kernel::{MissingContextPolicy, SecurityClock, SessionThrottleGuard};
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

impl SecurityClock for FixedClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        Ok(self.0)
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
            expires_at: u64::MAX,
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

fn security_context() -> SecurityInvocationContext {
    SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        throttle_key().tenant_id,
        throttle_key().session_id,
        PrincipalId::new("principal-a").unwrap_or_else(|error| panic!("principal id: {error}")),
        IsolationEpochId::new("epoch-a").unwrap_or_else(|error| panic!("isolation epoch: {error}")),
        LineageId::new("lineage-a").unwrap_or_else(|error| panic!("lineage id: {error}")),
        1,
    ))
}

fn evaluate(
    guard: &SessionThrottleGuard,
    request: &ToolCallRequest,
    security: Option<&SecurityInvocationContext>,
) -> Verdict {
    let context =
        GuardContext::new(request, &request.capability.scope).with_security_context(security);
    guard
        .evaluate(&context)
        .unwrap_or_else(|error| panic!("evaluate throttle guard: {error}"))
        .verdict
}

#[test]
fn exact_decision_allows_and_invocation_identity_is_deterministic() {
    let store = Arc::new(FakeThrottles::new(Behavior::Allow));
    let throttle_store: Arc<dyn SessionThrottleStore> = store.clone();
    let guard = SessionThrottleGuard::new(
        throttle_store,
        Arc::new(FixedClock(10_500)),
        MissingContextPolicy::Deny,
    );
    let request = request();
    let security = security_context();
    assert_eq!(evaluate(&guard, &request, Some(&security)), Verdict::Allow);
    assert_eq!(evaluate(&guard, &request, Some(&security)), Verdict::Allow);
    let invocations = store.invocations();
    assert_eq!(invocations.len(), 2);
    assert_eq!(invocations[0].key, throttle_key());
    assert_eq!(invocations[0].invocation_id, invocations[1].invocation_id);
    assert!(invocations[0]
        .invocation_id
        .as_str()
        .starts_with("session_throttle_invocation:"));
}

#[test]
fn reconstructed_guard_preserves_session_throttle_identity() {
    let store = Arc::new(FakeThrottles::new(Behavior::Allow));
    let request = request();
    let security = security_context();
    {
        let throttle_store: Arc<dyn SessionThrottleStore> = store.clone();
        let guard = SessionThrottleGuard::new(
            throttle_store,
            Arc::new(FixedClock(10_500)),
            MissingContextPolicy::Deny,
        );
        assert_eq!(evaluate(&guard, &request, Some(&security)), Verdict::Allow);
    }
    let throttle_store: Arc<dyn SessionThrottleStore> = store.clone();
    let restored_guard = SessionThrottleGuard::new(
        throttle_store,
        Arc::new(FixedClock(10_500)),
        MissingContextPolicy::Deny,
    );
    assert_eq!(
        evaluate(&restored_guard, &request, Some(&security)),
        Verdict::Allow
    );

    let invocations = store.invocations();
    assert_eq!(invocations.len(), 2);
    assert_eq!(invocations[0].key, invocations[1].key);
    assert_eq!(invocations[0].key.session_id.as_str(), "session-a");
}

#[test]
fn exhausted_outage_and_tampered_decisions_all_deny() {
    let request = request();
    let security = security_context();
    for behavior in [Behavior::Deny, Behavior::Fail, Behavior::Tamper] {
        let store: Arc<dyn SessionThrottleStore> = Arc::new(FakeThrottles::new(behavior));
        let guard = SessionThrottleGuard::new(
            store,
            Arc::new(FixedClock(10_500)),
            MissingContextPolicy::Deny,
        );
        assert_eq!(evaluate(&guard, &request, Some(&security)), Verdict::Deny);
    }
}

#[test]
fn missing_authoritative_session_cannot_bypass_enforcement() {
    let store = Arc::new(FakeThrottles::new(Behavior::Allow));
    let throttle_store: Arc<dyn SessionThrottleStore> = store.clone();
    let guard = SessionThrottleGuard::new(
        throttle_store,
        Arc::new(FixedClock(10_500)),
        MissingContextPolicy::Deny,
    );
    let request = request();
    assert_eq!(evaluate(&guard, &request, None), Verdict::Deny);
    assert!(store.invocations().is_empty());
}

#[test]
fn zero_or_failed_clock_denies_before_consumption() {
    struct FailingClock;
    impl SecurityClock for FailingClock {
        fn now_unix_ms(&self) -> PortResult<u64> {
            Err(PortError::unavailable())
        }
    }

    let request = request();
    let security = security_context();
    for clock in [
        Arc::new(FixedClock(0)) as Arc<dyn SecurityClock>,
        Arc::new(FailingClock) as Arc<dyn SecurityClock>,
    ] {
        let store = Arc::new(FakeThrottles::new(Behavior::Allow));
        let throttle_store: Arc<dyn SessionThrottleStore> = store.clone();
        let guard = SessionThrottleGuard::new(throttle_store, clock, MissingContextPolicy::Deny);
        assert_eq!(evaluate(&guard, &request, Some(&security)), Verdict::Deny);
        assert!(store.invocations().is_empty());
    }
}
