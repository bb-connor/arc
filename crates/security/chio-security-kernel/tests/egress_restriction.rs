use std::sync::Arc;

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::Keypair;
use chio_kernel::{
    Guard, GuardContext, SecurityInvocationContext, SecurityInvocationContextV1, ToolCallRequest,
    Verdict,
};
use chio_security_kernel::{EgressRestrictionGuard, MissingContextPolicy};
use chio_security_types::ports::{
    DestinationId, EffectExecutionStatus, EffectId, EffectResultQuery, EgressDestinationQuery,
    EgressRestrictionApplyRequest, EgressRestrictionDecision, EgressRestrictionEffectIds,
    EgressRestrictionRemoveRequest, EgressRestrictionSessionKey, EgressRestrictionSnapshot,
    EgressRestrictionStore, IsolationEpochId, LineageId, PortError, PortResult, SessionId,
    TenantId,
};
use chio_security_types::PrincipalId;

#[derive(Clone, Copy)]
enum StoreBehavior {
    Allow,
    Deny,
    Fail,
    CorruptAllowWithEffects,
}

struct FixedEgressStore {
    behavior: StoreBehavior,
}

impl EgressRestrictionStore for FixedEgressStore {
    fn ensure_egress_restrictions_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn apply_egress_restriction(
        &self,
        _: &EgressRestrictionApplyRequest,
    ) -> PortResult<EgressRestrictionSnapshot> {
        Err(PortError::unavailable())
    }

    fn remove_egress_restriction(
        &self,
        _: &EgressRestrictionRemoveRequest,
    ) -> PortResult<EgressRestrictionSnapshot> {
        Err(PortError::unavailable())
    }

    fn load_egress_restrictions(
        &self,
        _: &EgressRestrictionSessionKey,
    ) -> PortResult<Option<EgressRestrictionSnapshot>> {
        Err(PortError::unavailable())
    }

    fn evaluate_destination(
        &self,
        query: &EgressDestinationQuery,
    ) -> PortResult<EgressRestrictionDecision> {
        assert_eq!(query.key.tenant_id.as_str(), "tenant-authoritative");
        assert_eq!(query.key.session_id.as_str(), "session-authoritative");
        assert_eq!(query.destination_id.as_str(), "server-a");
        match self.behavior {
            StoreBehavior::Fail => Err(PortError::unavailable()),
            StoreBehavior::Allow => Ok(decision(query, false, Vec::new())),
            StoreBehavior::Deny => Ok(decision(
                query,
                true,
                vec![EffectId::new("effect-a").unwrap_or_else(|error| panic!("effect id: {error}"))],
            )),
            StoreBehavior::CorruptAllowWithEffects => Ok(decision(
                query,
                false,
                vec![EffectId::new("effect-a").unwrap_or_else(|error| panic!("effect id: {error}"))],
            )),
        }
    }

    fn load_egress_restriction_result(
        &self,
        _: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        Err(PortError::unavailable())
    }
}

fn decision(
    query: &EgressDestinationQuery,
    denied: bool,
    effects: Vec<EffectId>,
) -> EgressRestrictionDecision {
    EgressRestrictionDecision {
        key: query.key.clone(),
        destination_id: query.destination_id.clone(),
        denied,
        active_effect_ids: EgressRestrictionEffectIds::new(effects)
            .unwrap_or_else(|error| panic!("effect ids: {error}")),
        generation: 4,
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
    .unwrap_or_else(|error| panic!("capability: {error}"));
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

fn context() -> SecurityInvocationContext {
    SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("tenant-authoritative").unwrap_or_else(|error| panic!("tenant: {error}")),
        SessionId::new("session-authoritative").unwrap_or_else(|error| panic!("session: {error}")),
        PrincipalId::new("principal-a").unwrap_or_else(|error| panic!("principal: {error}")),
        IsolationEpochId::new("epoch-a").unwrap_or_else(|error| panic!("isolation epoch: {error}")),
        LineageId::new("lineage-a").unwrap_or_else(|error| panic!("lineage: {error}")),
        7,
    ))
}

fn evaluate(behavior: StoreBehavior, security: Option<&SecurityInvocationContext>) -> Verdict {
    let request = request();
    let scope = request.capability.scope.clone();
    let guard = EgressRestrictionGuard::new(
        Arc::new(FixedEgressStore { behavior }),
        MissingContextPolicy::Deny,
    );
    guard
        .evaluate(&GuardContext::new(&request, &scope).with_security_context(security))
        .unwrap_or_else(|error| panic!("guard evaluation: {error}"))
        .verdict
}

#[test]
fn exact_matching_destination_is_denied_and_nonmatching_is_allowed() {
    let security = context();
    assert_eq!(
        evaluate(StoreBehavior::Deny, Some(&security)),
        Verdict::Deny
    );
    assert_eq!(
        evaluate(StoreBehavior::Allow, Some(&security)),
        Verdict::Allow
    );
}

#[test]
fn store_failure_and_corrupt_decision_fail_closed() {
    let security = context();
    assert_eq!(
        evaluate(StoreBehavior::Fail, Some(&security)),
        Verdict::Deny
    );
    assert_eq!(
        evaluate(StoreBehavior::CorruptAllowWithEffects, Some(&security)),
        Verdict::Deny
    );
}

#[test]
fn enforce_mode_denies_missing_authoritative_session_context() {
    assert_eq!(evaluate(StoreBehavior::Allow, None), Verdict::Deny);
}

#[test]
fn destination_identifier_conversion_failure_denies() {
    let security = context();
    let mut request = request();
    request.server_id = " server-a".to_string();
    let scope = request.capability.scope.clone();
    let guard = EgressRestrictionGuard::new(
        Arc::new(FixedEgressStore {
            behavior: StoreBehavior::Allow,
        }),
        MissingContextPolicy::Deny,
    );
    let verdict = guard
        .evaluate(&GuardContext::new(&request, &scope).with_security_context(Some(&security)))
        .unwrap_or_else(|error| panic!("guard evaluation: {error}"))
        .verdict;
    assert_eq!(verdict, Verdict::Deny);
}

#[test]
fn typed_destination_is_the_request_server_identifier() {
    let destination =
        DestinationId::new("server-a").unwrap_or_else(|error| panic!("destination: {error}"));
    assert_eq!(destination.as_str(), request().server_id);
}
