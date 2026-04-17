use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use arc_core_types::capability::{ArcScope, CapabilityToken, Operation, ToolGrant};
use arc_core_types::crypto::{Keypair, PublicKey};
use arc_core_types::receipt::GuardEvidence;
use arc_cross_protocol::{
    plan_authoritative_route, route_selection_metadata, DiscoveryProtocol, TargetProtocolRegistry,
};
use arc_kernel::{
    ArcKernel, Guard, GuardContext, KernelConfig, KernelError, ToolCallRequest,
    ToolServerConnection, Verdict as KernelVerdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    http_status_metadata_decision, http_status_metadata_final, ArcHttpRequest, CallerIdentity,
    HttpMethod, HttpReceipt, HttpReceiptBody, Verdict, ARC_KERNEL_RECEIPT_ID_KEY,
};

const HTTP_AUTHORITY_SERVER_ID: &str = "arc_http_authority";
const HTTP_AUTHORITY_TOOL_NAME: &str = "authorize_http_request";
const HTTP_AUTHORITY_TTL_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpAuthorityPolicy {
    SessionAllow,
    DenyByDefault,
}

#[derive(Clone)]
pub struct HttpAuthority {
    keypair: Arc<Keypair>,
    policy_hash: String,
    kernel: Arc<ArcKernel>,
    kernel_subject: PublicKey,
    kernel_agent_id: String,
}

impl std::fmt::Debug for HttpAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAuthority")
            .field("policy_hash", &self.policy_hash)
            .field("kernel_agent_id", &self.kernel_agent_id)
            .finish_non_exhaustive()
    }
}

pub struct HttpAuthorityInput<'a> {
    pub request_id: String,
    pub method: HttpMethod,
    pub route_pattern: String,
    pub path: &'a str,
    pub query: &'a HashMap<String, String>,
    pub caller: CallerIdentity,
    pub body_hash: Option<String>,
    pub body_length: u64,
    pub session_id: Option<String>,
    pub capability_id_hint: Option<&'a str>,
    pub presented_capability: Option<&'a str>,
    pub policy: HttpAuthorityPolicy,
}

#[derive(Debug, Clone)]
pub struct PreparedHttpEvaluation {
    pub verdict: Verdict,
    pub evidence: Vec<GuardEvidence>,
    pub request_id: String,
    pub route_pattern: String,
    pub http_method: HttpMethod,
    pub caller_identity_hash: String,
    pub content_hash: String,
    pub session_id: Option<String>,
    pub capability_id: Option<String>,
    pub kernel_receipt_id: String,
    pub route_selection_metadata: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct HttpAuthorityEvaluation {
    pub verdict: Verdict,
    pub receipt: HttpReceipt,
    pub evidence: Vec<GuardEvidence>,
}

#[derive(Debug, Error)]
pub enum HttpAuthorityError {
    #[error("failed to hash caller identity: {0}")]
    CallerIdentity(String),

    #[error("failed to compute content hash: {0}")]
    ContentHash(String),

    #[error("kernel-backed authorization failed: {0}")]
    Kernel(String),

    #[error("kernel-backed authorization requires approval")]
    PendingApproval {
        approval_id: Option<String>,
        kernel_receipt_id: String,
    },

    #[error("failed to sign receipt: {0}")]
    ReceiptSign(String),
}

#[derive(Debug, Clone)]
struct PresentedCapabilityState {
    capability_id: Option<String>,
    invalid_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HttpKernelAuthorizationRequest {
    request_id: String,
    method: HttpMethod,
    route_pattern: String,
    path: String,
    content_hash: String,
    caller_identity_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    policy: HttpAuthorityPolicy,
    capability: HttpKernelCapabilityState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HttpKernelCapabilityState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invalid_reason: Option<String>,
}

struct HttpAuthorizationServer;

impl ToolServerConnection for HttpAuthorizationServer {
    fn server_id(&self) -> &str {
        HTTP_AUTHORITY_SERVER_ID
    }

    fn tool_names(&self) -> Vec<String> {
        vec![HTTP_AUTHORITY_TOOL_NAME.to_string()]
    }

    fn invoke(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn arc_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        if tool_name != HTTP_AUTHORITY_TOOL_NAME {
            return Err(KernelError::Internal(format!(
                "unsupported HTTP authority tool: {tool_name}"
            )));
        }
        Ok(serde_json::json!({ "authorized": true }))
    }
}

struct HttpProjectionGuard;

impl Guard for HttpProjectionGuard {
    fn name(&self) -> &str {
        "http_projection_policy"
    }

    fn evaluate(&self, ctx: &GuardContext<'_>) -> Result<KernelVerdict, KernelError> {
        let projected: HttpKernelAuthorizationRequest =
            serde_json::from_value(ctx.request.arguments.clone()).map_err(|error| {
                KernelError::Internal(format!(
                    "failed to decode projected HTTP authorization request: {error}"
                ))
            })?;

        if let Some(reason) = projected.capability.invalid_reason {
            return Err(KernelError::GuardDenied(reason));
        }

        match projected.policy {
            HttpAuthorityPolicy::SessionAllow => Ok(KernelVerdict::Allow),
            HttpAuthorityPolicy::DenyByDefault => {
                if projected.capability.id.is_some() {
                    Ok(KernelVerdict::Allow)
                } else {
                    Err(KernelError::GuardDenied(
                        "side-effect route requires a capability token".to_string(),
                    ))
                }
            }
        }
    }
}

impl HttpAuthority {
    #[must_use]
    pub fn new(keypair: Keypair, policy_hash: String) -> Self {
        let keypair = Arc::new(keypair);
        let kernel_subject = Keypair::generate().public_key();
        let kernel_agent_id = kernel_subject.to_hex();

        let mut kernel = ArcKernel::new(KernelConfig {
            keypair: keypair.as_ref().clone(),
            ca_public_keys: vec![keypair.public_key()],
            max_delegation_depth: 8,
            policy_hash: policy_hash.clone(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.register_tool_server(Box::new(HttpAuthorizationServer));
        kernel.add_guard(Box::new(HttpProjectionGuard));

        Self {
            keypair,
            policy_hash,
            kernel: Arc::new(kernel),
            kernel_subject,
            kernel_agent_id,
        }
    }

    pub fn evaluate(
        &self,
        input: HttpAuthorityInput<'_>,
    ) -> Result<HttpAuthorityEvaluation, HttpAuthorityError> {
        let prepared = self.prepare(input)?;
        let receipt = self.sign_decision_receipt(&prepared)?;
        Ok(HttpAuthorityEvaluation {
            verdict: prepared.verdict.clone(),
            receipt,
            evidence: prepared.evidence.clone(),
        })
    }

    pub fn prepare(
        &self,
        input: HttpAuthorityInput<'_>,
    ) -> Result<PreparedHttpEvaluation, HttpAuthorityError> {
        let presented_capability =
            validate_presented_capability(input.capability_id_hint, input.presented_capability);
        let caller_identity_hash = input
            .caller
            .identity_hash()
            .map_err(|e| HttpAuthorityError::CallerIdentity(e.to_string()))?;

        let arc_request = ArcHttpRequest {
            request_id: input.request_id.clone(),
            method: input.method,
            route_pattern: input.route_pattern.clone(),
            path: input.path.to_string(),
            query: input.query.clone(),
            headers: HashMap::new(),
            caller: input.caller,
            body_hash: input.body_hash,
            body_length: input.body_length,
            session_id: input.session_id.clone(),
            capability_id: presented_capability.capability_id.clone(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        let content_hash = arc_request
            .content_hash()
            .map_err(|e| HttpAuthorityError::ContentHash(e.to_string()))?;

        let kernel_response = self.authorize_via_kernel(
            &input.request_id,
            input.method,
            &input.route_pattern,
            input.path,
            &content_hash,
            &caller_identity_hash,
            input.session_id.as_deref(),
            input.policy,
            &presented_capability,
        )?;

        let verdict = projected_verdict(input.policy, &presented_capability);
        let expected_allowed = verdict.is_allowed();
        match (kernel_response.verdict, expected_allowed) {
            (KernelVerdict::Allow, true) | (KernelVerdict::Deny, false) => {}
            (KernelVerdict::Allow, false) => {
                return Err(HttpAuthorityError::Kernel(
                    "kernel allowed an HTTP projection that should have been denied".to_string(),
                ));
            }
            (KernelVerdict::Deny, true) => {
                let reason = kernel_response
                    .reason
                    .unwrap_or_else(|| "kernel denied an allowed HTTP projection".to_string());
                return Err(HttpAuthorityError::Kernel(reason));
            }
            (KernelVerdict::PendingApproval, _) => {
                return Err(HttpAuthorityError::PendingApproval {
                    approval_id: pending_approval_id(
                        kernel_response.receipt.metadata.as_ref(),
                        kernel_response.reason.as_deref(),
                    ),
                    kernel_receipt_id: kernel_response.receipt.id,
                });
            }
        }

        let evidence = projected_evidence(input.policy, &presented_capability);

        Ok(PreparedHttpEvaluation {
            verdict,
            evidence,
            request_id: input.request_id,
            route_pattern: input.route_pattern,
            http_method: input.method,
            caller_identity_hash,
            content_hash,
            session_id: input.session_id,
            capability_id: presented_capability.capability_id,
            kernel_receipt_id: kernel_response.receipt.id,
            route_selection_metadata: metadata_value(
                kernel_response.receipt.metadata.as_ref(),
                "route_selection",
            )
            .cloned(),
        })
    }

    pub fn sign_decision_receipt(
        &self,
        prepared: &PreparedHttpEvaluation,
    ) -> Result<HttpReceipt, HttpAuthorityError> {
        self.sign_receipt(
            prepared,
            decision_status(&prepared.verdict),
            decision_metadata(
                Some(&prepared.kernel_receipt_id),
                prepared.route_selection_metadata.as_ref(),
            ),
        )
    }

    pub fn finalize_receipt(
        &self,
        prepared: &PreparedHttpEvaluation,
        response_status: u16,
        decision_receipt_id: Option<&str>,
    ) -> Result<HttpReceipt, HttpAuthorityError> {
        self.sign_receipt(
            prepared,
            response_status,
            final_metadata(
                decision_receipt_id,
                Some(&prepared.kernel_receipt_id),
                prepared.route_selection_metadata.as_ref(),
            ),
        )
    }

    pub fn finalize_decision_receipt(
        &self,
        decision_receipt: &HttpReceipt,
        response_status: u16,
    ) -> Result<HttpReceipt, HttpAuthorityError> {
        let mut body = decision_receipt.body();
        let decision_receipt_id = body.id.clone();
        let kernel_receipt_id = metadata_string(body.metadata.as_ref(), ARC_KERNEL_RECEIPT_ID_KEY)
            .map(ToOwned::to_owned);
        let route_selection = metadata_value(body.metadata.as_ref(), "route_selection").cloned();
        body.id = uuid::Uuid::now_v7().to_string();
        body.response_status = response_status;
        body.timestamp = chrono::Utc::now().timestamp() as u64;
        body.metadata = final_metadata(
            Some(&decision_receipt_id),
            kernel_receipt_id.as_deref(),
            route_selection.as_ref(),
        );
        HttpReceipt::sign(body, self.keypair.as_ref())
            .map_err(|e| HttpAuthorityError::ReceiptSign(e.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_via_kernel(
        &self,
        request_id: &str,
        method: HttpMethod,
        route_pattern: &str,
        path: &str,
        content_hash: &str,
        caller_identity_hash: &str,
        session_id: Option<&str>,
        policy: HttpAuthorityPolicy,
        presented_capability: &PresentedCapabilityState,
    ) -> Result<arc_kernel::ToolCallResponse, HttpAuthorityError> {
        let capability = self
            .kernel
            .issue_capability(
                &self.kernel_subject,
                kernel_scope(),
                HTTP_AUTHORITY_TTL_SECS,
            )
            .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))?;

        let projected = HttpKernelAuthorizationRequest {
            request_id: request_id.to_string(),
            method,
            route_pattern: route_pattern.to_string(),
            path: path.to_string(),
            content_hash: content_hash.to_string(),
            caller_identity_hash: caller_identity_hash.to_string(),
            session_id: session_id.map(ToOwned::to_owned),
            policy,
            capability: HttpKernelCapabilityState {
                id: presented_capability.capability_id.clone(),
                invalid_reason: presented_capability.invalid_reason.clone(),
            },
        };

        let request = ToolCallRequest {
            request_id: request_id.to_string(),
            capability,
            tool_name: HTTP_AUTHORITY_TOOL_NAME.to_string(),
            server_id: HTTP_AUTHORITY_SERVER_ID.to_string(),
            agent_id: self.kernel_agent_id.clone(),
            arguments: serde_json::to_value(projected)
                .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))?,
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let route_plan = plan_authoritative_route(
            request_id,
            DiscoveryProtocol::Http,
            DiscoveryProtocol::Native,
            None,
            &TargetProtocolRegistry::new(DiscoveryProtocol::Native),
            &BTreeMap::new(),
        )
        .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))?;
        let route_metadata = route_selection_metadata(&route_plan.evidence)
            .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))?;

        self.kernel
            .evaluate_tool_call_blocking_with_metadata(&request, Some(route_metadata))
            .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))
    }

    fn sign_receipt(
        &self,
        prepared: &PreparedHttpEvaluation,
        response_status: u16,
        metadata: Option<Value>,
    ) -> Result<HttpReceipt, HttpAuthorityError> {
        let body = HttpReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            request_id: prepared.request_id.clone(),
            route_pattern: prepared.route_pattern.clone(),
            method: prepared.http_method,
            caller_identity_hash: prepared.caller_identity_hash.clone(),
            session_id: prepared.session_id.clone(),
            verdict: prepared.verdict.clone(),
            evidence: prepared.evidence.clone(),
            response_status,
            timestamp: chrono::Utc::now().timestamp() as u64,
            content_hash: prepared.content_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            capability_id: prepared.capability_id.clone(),
            metadata,
            kernel_key: self.keypair.public_key(),
        };

        HttpReceipt::sign(body, self.keypair.as_ref())
            .map_err(|e| HttpAuthorityError::ReceiptSign(e.to_string()))
    }
}

fn kernel_scope() -> ArcScope {
    ArcScope {
        grants: vec![ToolGrant {
            server_id: HTTP_AUTHORITY_SERVER_ID.to_string(),
            tool_name: HTTP_AUTHORITY_TOOL_NAME.to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: Some(1),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    }
}

fn decision_status(verdict: &Verdict) -> u16 {
    match verdict {
        Verdict::Allow => 200,
        Verdict::Deny { http_status, .. } => *http_status,
        Verdict::Cancel { .. } | Verdict::Incomplete { .. } => 500,
    }
}

fn validate_presented_capability(
    capability_id_hint: Option<&str>,
    presented_capability: Option<&str>,
) -> PresentedCapabilityState {
    let Some(raw_capability) = presented_capability else {
        return PresentedCapabilityState {
            capability_id: None,
            invalid_reason: None,
        };
    };

    match validate_capability_token(raw_capability) {
        Ok(token) => {
            if let Some(hint) = capability_id_hint {
                if hint != token.id {
                    return PresentedCapabilityState {
                        capability_id: None,
                        invalid_reason: Some(
                            "capability_id does not match the presented capability token"
                                .to_string(),
                        ),
                    };
                }
            }
            PresentedCapabilityState {
                capability_id: Some(token.id),
                invalid_reason: None,
            }
        }
        Err(reason) => PresentedCapabilityState {
            capability_id: None,
            invalid_reason: Some(reason),
        },
    }
}

fn projected_verdict(
    policy: HttpAuthorityPolicy,
    presented_capability: &PresentedCapabilityState,
) -> Verdict {
    if let Some(reason) = &presented_capability.invalid_reason {
        return Verdict::deny(reason, "CapabilityGuard");
    }

    match policy {
        HttpAuthorityPolicy::SessionAllow => Verdict::Allow,
        HttpAuthorityPolicy::DenyByDefault => match &presented_capability.capability_id {
            Some(_) => Verdict::Allow,
            None => Verdict::deny(
                "side-effect route requires a capability token",
                "CapabilityGuard",
            ),
        },
    }
}

fn projected_evidence(
    policy: HttpAuthorityPolicy,
    presented_capability: &PresentedCapabilityState,
) -> Vec<GuardEvidence> {
    if let Some(reason) = &presented_capability.invalid_reason {
        return vec![GuardEvidence {
            guard_name: "CapabilityGuard".to_string(),
            verdict: false,
            details: Some(reason.clone()),
        }];
    }

    match policy {
        HttpAuthorityPolicy::SessionAllow => vec![GuardEvidence {
            guard_name: "DefaultPolicyGuard".to_string(),
            verdict: true,
            details: Some("safe method, session-scoped allow".to_string()),
        }],
        HttpAuthorityPolicy::DenyByDefault => match &presented_capability.capability_id {
            Some(_) => vec![GuardEvidence {
                guard_name: "CapabilityGuard".to_string(),
                verdict: true,
                details: Some("valid capability token presented".to_string()),
            }],
            None => vec![GuardEvidence {
                guard_name: "CapabilityGuard".to_string(),
                verdict: false,
                details: Some("side-effect route requires a valid capability token".to_string()),
            }],
        },
    }
}

fn validate_capability_token(raw: &str) -> Result<CapabilityToken, String> {
    let token: CapabilityToken =
        serde_json::from_str(raw).map_err(|e| format!("invalid capability token: {e}"))?;
    let signature_valid = token
        .verify_signature()
        .map_err(|e| format!("capability signature verification failed: {e}"))?;
    if !signature_valid {
        return Err("capability signature verification failed".to_string());
    }
    token
        .validate_time(chrono::Utc::now().timestamp() as u64)
        .map_err(|e| format!("invalid capability token: {e}"))?;
    Ok(token)
}

fn decision_metadata(
    kernel_receipt_id: Option<&str>,
    route_selection: Option<&Value>,
) -> Option<Value> {
    let mut metadata = http_status_metadata_decision();
    insert_metadata_string(&mut metadata, ARC_KERNEL_RECEIPT_ID_KEY, kernel_receipt_id);
    insert_metadata_value(&mut metadata, "route_selection", route_selection);
    Some(metadata)
}

fn final_metadata(
    decision_receipt_id: Option<&str>,
    kernel_receipt_id: Option<&str>,
    route_selection: Option<&Value>,
) -> Option<Value> {
    let mut metadata = http_status_metadata_final(decision_receipt_id);
    insert_metadata_string(&mut metadata, ARC_KERNEL_RECEIPT_ID_KEY, kernel_receipt_id);
    insert_metadata_value(&mut metadata, "route_selection", route_selection);
    Some(metadata)
}

fn insert_metadata_string(metadata: &mut Value, key: &str, value: Option<&str>) {
    let Some(value) = value else {
        return;
    };
    if let Value::Object(map) = metadata {
        map.insert(key.to_string(), Value::String(value.to_string()));
    } else {
        let mut map = Map::new();
        map.insert(key.to_string(), Value::String(value.to_string()));
        *metadata = Value::Object(map);
    }
}

fn insert_metadata_value(metadata: &mut Value, key: &str, value: Option<&Value>) {
    let Some(value) = value else {
        return;
    };
    if let Value::Object(map) = metadata {
        map.insert(key.to_string(), value.clone());
    } else {
        let mut map = Map::new();
        map.insert(key.to_string(), value.clone());
        *metadata = Value::Object(map);
    }
}

fn metadata_string<'a>(metadata: Option<&'a Value>, key: &str) -> Option<&'a str> {
    metadata
        .and_then(Value::as_object)
        .and_then(|map| map.get(key))
        .and_then(Value::as_str)
}

fn metadata_value<'a>(metadata: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    metadata
        .and_then(Value::as_object)
        .and_then(|map| map.get(key))
}

fn pending_approval_id(metadata: Option<&Value>, reason: Option<&str>) -> Option<String> {
    metadata_string(metadata, "approval_id")
        .or_else(|| {
            metadata_value(metadata, "pending_approval")
                .and_then(Value::as_object)
                .and_then(|pending| pending.get("approval_id"))
                .and_then(Value::as_str)
        })
        .map(ToOwned::to_owned)
        .or_else(|| extract_approval_id(reason))
}

fn extract_approval_id(reason: Option<&str>) -> Option<String> {
    let reason = reason?;
    for marker in ["/approvals/", "approval_id=", "approval_id:"] {
        if let Some(start) = reason.find(marker) {
            let suffix = reason[start + marker.len()..].trim_start();
            let approval_id = suffix
                .split(|character: char| {
                    character == '/'
                        || character == ','
                        || character == ';'
                        || character.is_whitespace()
                })
                .next()?;
            if !approval_id.is_empty() {
                return Some(approval_id.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        http_status_scope, AuthMethod, ARC_DECISION_RECEIPT_ID_KEY, ARC_HTTP_STATUS_SCOPE_DECISION,
        ARC_HTTP_STATUS_SCOPE_FINAL,
    };
    use arc_core_types::capability::{ArcScope, CapabilityTokenBody};

    fn valid_capability_token_json(id: &str) -> String {
        let issuer = Keypair::generate();
        let now = chrono::Utc::now().timestamp() as u64;
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: issuer.public_key(),
                scope: ArcScope::default(),
                issued_at: now.saturating_sub(60),
                expires_at: now + 3600,
                delegation_chain: Vec::new(),
            },
            &issuer,
        )
        .unwrap();
        serde_json::to_string(&token).unwrap()
    }

    fn caller() -> CallerIdentity {
        CallerIdentity {
            subject: "tester".to_string(),
            auth_method: AuthMethod::Anonymous,
            verified: false,
            tenant: None,
            agent_id: None,
        }
    }

    fn authority() -> HttpAuthority {
        HttpAuthority::new(Keypair::generate(), "policy-hash".to_string())
    }

    #[test]
    fn safe_policy_allows_without_capability() {
        let query = HashMap::new();
        let result = authority()
            .evaluate(HttpAuthorityInput {
                request_id: "req-1".to_string(),
                method: HttpMethod::Get,
                route_pattern: "/pets".to_string(),
                path: "/pets",
                query: &query,
                caller: caller(),
                body_hash: None,
                body_length: 0,
                session_id: None,
                capability_id_hint: None,
                presented_capability: None,
                policy: HttpAuthorityPolicy::SessionAllow,
            })
            .unwrap();

        assert!(result.verdict.is_allowed());
        assert_eq!(
            http_status_scope(result.receipt.metadata.as_ref()),
            Some(ARC_HTTP_STATUS_SCOPE_DECISION)
        );
        assert!(
            metadata_string(result.receipt.metadata.as_ref(), ARC_KERNEL_RECEIPT_ID_KEY).is_some()
        );
        assert_eq!(
            metadata_value(result.receipt.metadata.as_ref(), "route_selection")
                .and_then(|value| value.get("selectedTargetProtocol"))
                .and_then(Value::as_str),
            Some("native")
        );
    }

    #[test]
    fn deny_by_default_requires_capability() {
        let query = HashMap::new();
        let result = authority()
            .evaluate(HttpAuthorityInput {
                request_id: "req-2".to_string(),
                method: HttpMethod::Post,
                route_pattern: "/pets".to_string(),
                path: "/pets",
                query: &query,
                caller: caller(),
                body_hash: Some("abc".to_string()),
                body_length: 3,
                session_id: None,
                capability_id_hint: None,
                presented_capability: None,
                policy: HttpAuthorityPolicy::DenyByDefault,
            })
            .unwrap();

        assert!(result.verdict.is_denied());
        assert_eq!(result.receipt.response_status, 403);
    }

    #[test]
    fn invalid_presented_capability_denies_even_safe_route() {
        let query = HashMap::new();
        let result = authority()
            .evaluate(HttpAuthorityInput {
                request_id: "req-invalid".to_string(),
                method: HttpMethod::Get,
                route_pattern: "/pets".to_string(),
                path: "/pets",
                query: &query,
                caller: caller(),
                body_hash: None,
                body_length: 0,
                session_id: None,
                capability_id_hint: None,
                presented_capability: Some("{not-json"),
                policy: HttpAuthorityPolicy::SessionAllow,
            })
            .unwrap();

        assert!(result.verdict.is_denied());
        assert_eq!(result.receipt.evidence.len(), 1);
        assert_eq!(result.receipt.evidence[0].guard_name, "CapabilityGuard");
    }

    #[test]
    fn valid_capability_allows_deny_by_default() {
        let query = HashMap::new();
        let capability = valid_capability_token_json("cap-123");
        let result = authority()
            .evaluate(HttpAuthorityInput {
                request_id: "req-3".to_string(),
                method: HttpMethod::Patch,
                route_pattern: "/pets/{petId}".to_string(),
                path: "/pets/42",
                query: &query,
                caller: caller(),
                body_hash: Some("def".to_string()),
                body_length: 3,
                session_id: Some("session-1".to_string()),
                capability_id_hint: None,
                presented_capability: Some(&capability),
                policy: HttpAuthorityPolicy::DenyByDefault,
            })
            .unwrap();

        assert!(result.verdict.is_allowed());
        assert_eq!(result.receipt.capability_id.as_deref(), Some("cap-123"));
        assert_eq!(result.receipt.session_id.as_deref(), Some("session-1"));
        assert!(
            metadata_string(result.receipt.metadata.as_ref(), ARC_KERNEL_RECEIPT_ID_KEY).is_some()
        );
    }

    #[test]
    fn capability_hint_mismatch_becomes_denial() {
        let query = HashMap::new();
        let capability = valid_capability_token_json("cap-123");
        let result = authority()
            .evaluate(HttpAuthorityInput {
                request_id: "req-4".to_string(),
                method: HttpMethod::Put,
                route_pattern: "/pets/42".to_string(),
                path: "/pets/42",
                query: &query,
                caller: caller(),
                body_hash: None,
                body_length: 0,
                session_id: None,
                capability_id_hint: Some("cap-other"),
                presented_capability: Some(&capability),
                policy: HttpAuthorityPolicy::DenyByDefault,
            })
            .unwrap();

        assert!(result.verdict.is_denied());
        assert!(result.receipt.capability_id.is_none());
    }

    #[test]
    fn finalized_receipt_links_decision_receipt_and_kernel_receipt() {
        let query = HashMap::new();
        let shared = authority();
        let decision = shared
            .evaluate(HttpAuthorityInput {
                request_id: "req-5".to_string(),
                method: HttpMethod::Get,
                route_pattern: "/pets".to_string(),
                path: "/pets",
                query: &query,
                caller: caller(),
                body_hash: None,
                body_length: 0,
                session_id: None,
                capability_id_hint: None,
                presented_capability: None,
                policy: HttpAuthorityPolicy::SessionAllow,
            })
            .unwrap()
            .receipt;
        let kernel_receipt_id =
            metadata_string(decision.metadata.as_ref(), ARC_KERNEL_RECEIPT_ID_KEY)
                .map(ToOwned::to_owned)
                .unwrap();
        let final_receipt = shared.finalize_decision_receipt(&decision, 204).unwrap();

        assert_ne!(final_receipt.id, decision.id);
        assert_eq!(final_receipt.response_status, 204);
        assert_eq!(
            http_status_scope(final_receipt.metadata.as_ref()),
            Some(ARC_HTTP_STATUS_SCOPE_FINAL)
        );
        assert_eq!(
            final_receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get(ARC_DECISION_RECEIPT_ID_KEY))
                .and_then(serde_json::Value::as_str),
            Some(decision.id.as_str())
        );
        assert_eq!(
            metadata_string(final_receipt.metadata.as_ref(), ARC_KERNEL_RECEIPT_ID_KEY),
            Some(kernel_receipt_id.as_str())
        );
        assert_eq!(
            metadata_value(final_receipt.metadata.as_ref(), "route_selection")
                .and_then(|value| value.get("selectedTargetProtocol"))
                .and_then(Value::as_str),
            Some("native")
        );
    }

    #[test]
    fn extract_approval_id_parses_resume_path() {
        assert_eq!(
            extract_approval_id(Some(
                "kernel returned PendingApproval; resume via /approvals/ap-123/respond"
            ))
            .as_deref(),
            Some("ap-123")
        );
        assert_eq!(
            extract_approval_id(Some("kernel returned PendingApproval; approval_id=ap-456"))
                .as_deref(),
            Some("ap-456")
        );
        assert_eq!(
            extract_approval_id(Some("kernel returned PendingApproval; approval_id: ap-789"))
                .as_deref(),
            Some("ap-789")
        );
        assert!(extract_approval_id(Some("kernel returned PendingApproval")).is_none());
    }

    #[test]
    fn pending_approval_id_reads_nested_metadata() {
        let metadata = serde_json::json!({
            "pending_approval": {
                "approval_id": "ap-structured"
            }
        });
        assert_eq!(
            pending_approval_id(Some(&metadata), Some("kernel returned PendingApproval"))
                .as_deref(),
            Some("ap-structured")
        );
    }
}
