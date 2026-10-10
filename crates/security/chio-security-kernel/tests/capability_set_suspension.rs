use std::sync::{Arc, Mutex};

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::Keypair;
use chio_kernel::{
    Guard, GuardContext, SecurityInvocationContext, SecurityInvocationContextV1, ToolCallRequest,
    Verdict,
};
use chio_security_kernel::{CapabilitySetSuspensionGuard, MissingContextPolicy};
use chio_security_types::ports::{
    ActionId, CapabilitySetSuspensionApplyRequest, CapabilitySetSuspensionMatch,
    CapabilitySetSuspensionMatches, CapabilitySetSuspensionRemoveRequest,
    CapabilitySetSuspensionSnapshot, CapabilitySetSuspensionStore, CapabilitySuspensionDecision,
    CapabilitySuspensionQuery, Digest32, EffectExecutionStatus, EffectId, EffectResultQuery,
    IsolationEpochId, LineageId, PortError, PortResult, SessionId, TenantId,
};
use chio_security_types::PrincipalId;

#[derive(Clone, Copy)]
enum Behavior {
    Allow,
    Deny,
    Fail,
    Tamper,
}

struct FakeSuspensions {
    behavior: Behavior,
    queries: Mutex<Vec<CapabilitySuspensionQuery>>,
}

impl FakeSuspensions {
    fn new(behavior: Behavior) -> Self {
        Self {
            behavior,
            queries: Mutex::new(Vec::new()),
        }
    }

    fn queries(&self) -> Vec<CapabilitySuspensionQuery> {
        self.queries
            .lock()
            .unwrap_or_else(|error| panic!("queries poisoned: {error}"))
            .clone()
    }
}

impl CapabilitySetSuspensionStore for FakeSuspensions {
    fn ensure_capability_set_suspensions_ready(&self) -> PortResult<()> {
        Err(PortError::unavailable())
    }

    fn apply_capability_set_suspension(
        &self,
        _request: &CapabilitySetSuspensionApplyRequest,
    ) -> PortResult<CapabilitySetSuspensionSnapshot> {
        Err(PortError::unavailable())
    }

    fn remove_capability_set_suspension(
        &self,
        _request: &CapabilitySetSuspensionRemoveRequest,
    ) -> PortResult<CapabilitySetSuspensionSnapshot> {
        Err(PortError::unavailable())
    }

    fn load_capability_set_suspensions(
        &self,
        _key: &chio_security_types::ports::CapabilitySetSuspensionKey,
    ) -> PortResult<Option<CapabilitySetSuspensionSnapshot>> {
        Err(PortError::unavailable())
    }

    fn evaluate_capability_suspension(
        &self,
        query: &CapabilitySuspensionQuery,
    ) -> PortResult<CapabilitySuspensionDecision> {
        if matches!(self.behavior, Behavior::Fail) {
            return Err(PortError::unavailable());
        }
        self.queries
            .lock()
            .unwrap_or_else(|error| panic!("queries poisoned: {error}"))
            .push(query.clone());
        let denied = matches!(self.behavior, Behavior::Deny | Behavior::Tamper);
        let active_matches = if denied {
            CapabilitySetSuspensionMatches::new(vec![CapabilitySetSuspensionMatch {
                affected_set_hash: Digest32::new([1_u8; 32]),
                action_id: ActionId::new("action-a")
                    .unwrap_or_else(|error| panic!("action id: {error}")),
                effect_id: EffectId::new("effect-a")
                    .unwrap_or_else(|error| panic!("effect id: {error}")),
                contribution_hash: Digest32::new([2_u8; 32]),
                expires_at_unix_ms: u64::MAX,
            }])
            .unwrap_or_else(|error| panic!("active matches: {error}"))
        } else {
            CapabilitySetSuspensionMatches::new(Vec::new())
                .unwrap_or_else(|error| panic!("active matches: {error}"))
        };
        Ok(CapabilitySuspensionDecision {
            tenant_id: if matches!(self.behavior, Behavior::Tamper) {
                TenantId::new("tenant-wrong").unwrap_or_else(|error| panic!("tenant id: {error}"))
            } else {
                query.tenant_id.clone()
            },
            capability_id: query.capability_id.clone(),
            denied,
            active_matches,
        })
    }

    fn load_capability_set_suspension_result(
        &self,
        _query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        Err(PortError::unavailable())
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
        TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant id: {error}")),
        SessionId::new("session-a").unwrap_or_else(|error| panic!("session id: {error}")),
        PrincipalId::new("principal-a").unwrap_or_else(|error| panic!("principal id: {error}")),
        IsolationEpochId::new("epoch-a").unwrap_or_else(|error| panic!("epoch id: {error}")),
        LineageId::new("lineage-a").unwrap_or_else(|error| panic!("lineage id: {error}")),
        1,
    ))
}

fn evaluate(
    guard: &CapabilitySetSuspensionGuard,
    request: &ToolCallRequest,
    security: Option<&SecurityInvocationContext>,
) -> Verdict {
    let context =
        GuardContext::new(request, &request.capability.scope).with_security_context(security);
    guard
        .evaluate(&context)
        .unwrap_or_else(|error| panic!("evaluate capability suspension guard: {error}"))
        .verdict
}

#[test]
fn exact_capability_and_tenant_are_queried_before_dispatch() {
    let store = Arc::new(FakeSuspensions::new(Behavior::Allow));
    let suspension_store: Arc<dyn CapabilitySetSuspensionStore> = store.clone();
    let guard = CapabilitySetSuspensionGuard::new(suspension_store, MissingContextPolicy::Deny);
    let request = request();
    let security = security_context();
    assert_eq!(evaluate(&guard, &request, Some(&security)), Verdict::Allow);
    let queries = store.queries();
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].tenant_id.as_str(), "tenant-a");
    assert_eq!(queries[0].capability_id.as_str(), "capability-a");
}

#[test]
fn suspension_outage_and_tampered_decision_all_deny() {
    let request = request();
    let security = security_context();
    for behavior in [Behavior::Deny, Behavior::Fail, Behavior::Tamper] {
        let store: Arc<dyn CapabilitySetSuspensionStore> = Arc::new(FakeSuspensions::new(behavior));
        let guard = CapabilitySetSuspensionGuard::new(store, MissingContextPolicy::Deny);
        assert_eq!(evaluate(&guard, &request, Some(&security)), Verdict::Deny);
    }
}

#[test]
fn missing_authoritative_context_denies_without_store_access() {
    let store = Arc::new(FakeSuspensions::new(Behavior::Allow));
    let suspension_store: Arc<dyn CapabilitySetSuspensionStore> = store.clone();
    let guard = CapabilitySetSuspensionGuard::new(suspension_store, MissingContextPolicy::Deny);
    assert_eq!(evaluate(&guard, &request(), None), Verdict::Deny);
    assert!(store.queries().is_empty());
}
