//! Provider-fabric verdict shim.
//!
//! Wires the provider-agnostic [`chio_tool_call_fabric`] crate into the kernel
//! via a thin conversion layer. Lifts a [`ToolInvocation`] into a kernel
//! [`ToolCallRequest`] (when paired with the surrounding capability context)
//! and lowers a kernel [`ToolCallResponse`] into a fabric [`VerdictResult`].
//! The shim is a single conversion point so the fabric vocabulary never leaks
//! into the kernel's internals.

use chio_core::canonical::canonical_json_bytes;
use chio_core::session::OperationTerminalState;
use chio_tool_call_fabric::{
    DenyReason, ProviderId, ReceiptId, ToolInvocation, ToolInvocationValidationError, VerdictResult,
};

use crate::runtime::{ToolCallRequest, ToolCallResponse, Verdict};
use crate::{AgentId, ServerId};
use chio_core::capability::token::CapabilityToken;

/// Errors surfaced while admitting fabric types into the kernel's MCP path.
///
/// This enum covers structural lifting, canonical-JSON translation, and the
/// registry-bound manifest checks that must complete before kernel execution.
/// The underlying MCP pipeline retains its own [`crate::KernelError`] surface.
#[derive(Debug, thiserror::Error)]
pub enum ProviderVerdictError {
    /// The lifted invocation failed the fabric's structural validation.
    #[error("invalid provider invocation: {0}")]
    InvalidInvocation(#[source] ToolInvocationValidationError),

    /// Provider projection without a registry-admitted manifest sidecar is
    /// discovery-only and cannot enter kernel execution.
    #[error("provider invocation is missing registry-admitted bridge security")]
    MissingBridgeSecurity,

    /// The execution target must be the same server admitted by the signed
    /// manifest sidecar.
    #[error(
        "provider invocation targets server {target}, but bridge security admits server {admitted}"
    )]
    BridgeServerMismatch { target: String, admitted: String },

    /// The complete sidecar must equal the value reconstructed from the live
    /// signed-manifest registry.
    #[error("provider bridge security does not match the live registry: {0}")]
    BridgeSecurityMismatch(String),

    /// Registry sidecar metadata could not be represented in the kernel's
    /// reserved metadata envelope.
    #[error("provider bridge security could not be lowered into kernel metadata: {0}")]
    InvalidBridgeSecurityMetadata(String),

    /// The fabric arguments payload was not valid JSON. Fabric promises
    /// canonical-JSON bytes (RFC 8785); a parse failure here is a contract
    /// violation by the upstream adapter.
    #[error("fabric arguments payload is not valid JSON: {0}")]
    InvalidArguments(#[source] serde_json::Error),

    /// The decoded arguments must satisfy the exact registry-admitted input
    /// schema, either manifest-signed or pinned for a provider-native tool.
    #[error("provider arguments do not satisfy the registry-admitted input schema: {0}")]
    ManifestArguments(String),
}

fn lower_provider_invocation(
    invocation: &ToolInvocation,
    capability: CapabilityToken,
    agent_id: AgentId,
    server_id: ServerId,
    registry: &chio_manifest::VerifiedManifestRegistry,
) -> Result<(ToolCallRequest, serde_json::Value), ProviderVerdictError> {
    invocation
        .validate()
        .map_err(ProviderVerdictError::InvalidInvocation)?;
    let bridge_security = invocation
        .bridge_security
        .as_ref()
        .ok_or(ProviderVerdictError::MissingBridgeSecurity)?;
    let admitted_server = bridge_security
        .server_id()
        .ok_or(ProviderVerdictError::MissingBridgeSecurity)?;
    if admitted_server != server_id.as_str() {
        return Err(ProviderVerdictError::BridgeServerMismatch {
            target: server_id,
            admitted: admitted_server.to_string(),
        });
    }
    registry
        .validate_bridge_security(&server_id, &invocation.tool_name, bridge_security)
        .map_err(|error| ProviderVerdictError::BridgeSecurityMismatch(error.to_string()))?;
    let metadata = bridge_security
        .merge_into_kernel_metadata(None)
        .map_err(|error| ProviderVerdictError::InvalidBridgeSecurityMetadata(error.to_string()))?;

    let arguments = if invocation.arguments.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&invocation.arguments)
            .map_err(ProviderVerdictError::InvalidArguments)?
    };
    registry
        .validate_invocation_arguments(
            &server_id,
            &invocation.tool_name,
            bridge_security,
            &arguments,
        )
        .map_err(|error| ProviderVerdictError::ManifestArguments(error.to_string()))?;

    Ok((
        ToolCallRequest {
            request_id: invocation.provenance.request_id.clone(),
            capability,
            tool_name: invocation.tool_name.clone(),
            server_id: admitted_server.to_string(),
            agent_id,
            arguments,
            supplemental_authorization: None,
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        },
        metadata,
    ))
}

/// Build a [`ToolCallRequest`] from a fabric [`ToolInvocation`] plus the
/// surrounding kernel context (capability token, calling agent, target tool
/// server). Execution admission requires a registry-bound bridge sidecar with
/// exact tool and server identity. All policy decisions remain with
/// `evaluate_tool_call*`; this helper only validates and translates the wire
/// shape.
///
/// `request_id` defaults to `invocation.provenance.request_id` so the
/// upstream provider's request id flows into the kernel verdict and into the
/// resulting receipt without a second round of bookkeeping.
#[cfg(test)]
fn build_tool_call_request(
    invocation: &ToolInvocation,
    capability: CapabilityToken,
    agent_id: AgentId,
    server_id: ServerId,
    registry: &chio_manifest::VerifiedManifestRegistry,
) -> Result<ToolCallRequest, ProviderVerdictError> {
    lower_provider_invocation(invocation, capability, agent_id, server_id, registry)
        .map(|(request, _metadata)| request)
}

/// Lower a kernel [`ToolCallResponse`] into a fabric [`VerdictResult`].
///
/// The mapping is structural and lossless within the fabric's vocabulary:
///
/// - `Verdict::Allow` -> `VerdictResult::Allow { redactions: [], receipt_id }`
/// - `Verdict::Deny` (and the non-allow terminal variants) ->
///   `VerdictResult::Deny { reason, receipt_id }`
/// - `Verdict::PendingApproval` -> `VerdictResult::Deny { reason, receipt_id }`
///   so callers fail-closed if they ignore the approval channel. The fabric
///   verdict vocabulary has no pending state, so an approval-gated outcome
///   maps to a denial here.
///
/// Redactions are emitted as an empty list: the fabric verdict does not
/// carry data-guard redaction detail.
#[must_use]
pub fn verdict_result_from_response(
    invocation: &ToolInvocation,
    response: &ToolCallResponse,
) -> VerdictResult {
    let receipt_id = ReceiptId(response.receipt.id.clone());
    match response.verdict {
        Verdict::Allow if matches!(response.terminal_state, OperationTerminalState::Completed) => {
            VerdictResult::Allow {
                redactions: Vec::new(),
                receipt_id,
            }
        }
        Verdict::Allow => VerdictResult::Deny {
            reason: DenyReason::PolicyDeny {
                rule_id: "kernel.execution_nonce_preflight".to_string(),
            },
            receipt_id,
        },
        Verdict::Deny => VerdictResult::Deny {
            reason: classify_deny_reason(invocation, response),
            receipt_id,
        },
        Verdict::PendingApproval => VerdictResult::Deny {
            reason: DenyReason::PolicyDeny {
                rule_id: "kernel.pending_approval".to_string(),
            },
            receipt_id,
        },
    }
}

/// Pick a [`DenyReason`] variant from the kernel response.
///
/// The kernel's deny pathway encodes its rationale as a free-form
/// [`ToolCallResponse::reason`] string. We surface this as
/// [`DenyReason::PolicyDeny`] with the kernel's reason as the `rule_id`,
/// preserving information for auditors without inventing a richer mapping.
/// Specialized variants (`CapabilityExpired`, `BudgetExceeded`, etc.) would
/// require kernel-side classification; this shim maps every deny to the
/// single [`DenyReason::PolicyDeny`] form.
fn classify_deny_reason(_invocation: &ToolInvocation, response: &ToolCallResponse) -> DenyReason {
    let detail = response
        .reason
        .clone()
        .unwrap_or_else(|| "kernel.deny".to_string());
    DenyReason::PolicyDeny { rule_id: detail }
}

/// Stable canonical-JSON byte form of a [`ToolInvocation`].
///
/// Adapters frequently need a stable hash of the invocation for telemetry
/// and replay correlation. The kernel exposes its canonical-JSON helper
/// already; this is a typed wrapper so callers do not import the helper
/// directly. The wrapped helper returns the workspace's own
/// [`chio_core::error::Error`]; callers that already work in that error
/// space can map straight through `?`.
pub fn canonical_invocation_bytes(
    invocation: &ToolInvocation,
) -> chio_core::error::Result<Vec<u8>> {
    canonical_json_bytes(invocation)
}

/// Marker constant tying the shim to the fabric crate version it was built
/// against. Used by the workspace's drift checks to flag when the fabric
/// trait surface evolves without the kernel shim being revisited.
pub const FABRIC_SHIM_PROVIDER_LANES: &[ProviderId] = &[
    ProviderId::OpenAi,
    ProviderId::Anthropic,
    ProviderId::Bedrock,
];

impl crate::ChioKernel {
    /// Compute a fabric [`VerdictResult`] for a provider-native tool
    /// invocation by routing through the existing MCP verdict path.
    ///
    /// The shim builds a [`ToolCallRequest`] from the supplied invocation
    /// plus the surrounding capability context, calls
    /// [`crate::ChioKernel::evaluate_tool_call_blocking`], and lowers the
    /// kernel response into a fabric verdict via
    /// [`verdict_result_from_response`].
    ///
    /// The kernel-side fabric integration point. Adapters call this method
    /// with an invocation already lifted from the upstream wire format and a
    /// capability token resolved from their authentication path.
    pub fn verdict_for_provider_invocation(
        &self,
        invocation: &ToolInvocation,
        capability: CapabilityToken,
        agent_id: AgentId,
        server_id: ServerId,
        registry: &chio_manifest::VerifiedManifestRegistry,
    ) -> Result<VerdictResult, crate::KernelError> {
        self.verdict_for_provider_invocation_inner(
            invocation, capability, agent_id, server_id, registry, None,
        )
    }

    /// Compute a provider-fabric verdict with authoritative identity and
    /// isolation state supplied by the trusted provider host.
    pub fn verdict_for_provider_invocation_with_security_context(
        &self,
        invocation: &ToolInvocation,
        capability: CapabilityToken,
        agent_id: AgentId,
        server_id: ServerId,
        registry: &chio_manifest::VerifiedManifestRegistry,
        security_context: &crate::SecurityInvocationContext,
    ) -> Result<VerdictResult, crate::KernelError> {
        self.verdict_for_provider_invocation_inner(
            invocation,
            capability,
            agent_id,
            server_id,
            registry,
            Some(security_context),
        )
    }

    fn verdict_for_provider_invocation_inner(
        &self,
        invocation: &ToolInvocation,
        capability: CapabilityToken,
        agent_id: AgentId,
        server_id: ServerId,
        registry: &chio_manifest::VerifiedManifestRegistry,
        security_context: Option<&crate::SecurityInvocationContext>,
    ) -> Result<VerdictResult, crate::KernelError> {
        let (request, metadata) =
            lower_provider_invocation(invocation, capability, agent_id, server_id, registry)
                .map_err(|e| {
                    crate::KernelError::Internal(format!(
                        "provider invocation could not enter kernel execution: {e}"
                    ))
                })?;
        let bridge_security = invocation.bridge_security.as_ref().ok_or_else(|| {
            crate::KernelError::InvalidReceiptMetadata(
                "provider invocation is missing bridge security".to_string(),
            )
        })?;
        let response = match security_context {
            Some(security_context) => self
                .evaluate_tool_call_blocking_with_manifest_security_and_security_context(
                    &request,
                    registry,
                    bridge_security,
                    None,
                    security_context,
                )?,
            None => self.evaluate_tool_call_blocking_with_manifest_security(
                &request,
                registry,
                bridge_security,
                None,
            )?,
        };
        debug_assert_eq!(
            response
                .receipt
                .metadata
                .as_ref()
                .and_then(|value| value.get("chio_manifest_security_v1")),
            metadata.get("chio_manifest_security_v1")
        );
        Ok(verdict_result_from_response(invocation, &response))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core::capability::scope::ChioScope;
    use chio_core::capability::token::CapabilityTokenBody;
    use chio_core::receipt::{body::ChioReceipt, decision::Decision, decision::ToolCallAction};
    use chio_core::session::OperationTerminalState;
    use chio_manifest::{
        sign_manifest, BridgeSecurityMetadata, RuntimeToolTopology, ToolAnnotations,
        ToolDefinition, ToolFlowDeclaration, ToolManifest, VerifiedManifestRegistry,
        TOOL_MANIFEST_SCHEMA,
    };
    use chio_tool_call_fabric::{Principal, ProvenanceStamp};
    use std::time::{Duration, SystemTime};

    fn sample_invocation() -> ToolInvocation {
        ToolInvocation {
            provider: ProviderId::OpenAi,
            tool_name: "search_web".to_string(),
            arguments: br#"{"query":"chio"}"#.to_vec(),
            provenance: ProvenanceStamp {
                provider: ProviderId::OpenAi,
                request_id: "call_abc123".to_string(),
                api_version: "responses.2026-04-25".to_string(),
                principal: Principal::OpenAiOrg {
                    org_id: "org_123".to_string(),
                },
                received_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            },
            bridge_security: None,
        }
    }

    fn sample_capability() -> CapabilityToken {
        let issuer = chio_core::crypto::Keypair::generate();
        let subject = chio_core::crypto::Keypair::generate();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-provider-test".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 1_700_000_000,
                expires_at: 1_700_000_300,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &issuer,
        )
        .unwrap()
    }

    fn registry_bound_invocation() -> (ToolInvocation, VerifiedManifestRegistry) {
        let signer = chio_core::crypto::Keypair::generate();
        let manifest = ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "srv-test".to_string(),
            name: "Provider test server".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "search_web".to_string(),
                description: "Search the web".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "minLength": 1, "maxLength": 8}
                    },
                    "required": ["query"],
                    "additionalProperties": false
                }),
                output_schema: None,
                pricing: None,
                annotations: ToolAnnotations::default(),
                latency_hint: None,
                flow: Some(ToolFlowDeclaration::public_egress()),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: signer.public_key().to_hex(),
        };
        let signed = sign_manifest(&manifest, &signer).unwrap();
        let mut registry = VerifiedManifestRegistry::default();
        registry
            .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
            .unwrap();

        let mut invocation = sample_invocation();
        invocation.bridge_security = registry.bridge_security("srv-test", "search_web");
        (invocation, registry)
    }

    fn local_registry_bound_invocation() -> (ToolInvocation, VerifiedManifestRegistry) {
        let signer = chio_core::crypto::Keypair::generate();
        let manifest = ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "srv-test".to_string(),
            name: "Local provider test server".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "search_web".to_string(),
                description: "Search the web".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "minLength": 1, "maxLength": 8}
                    },
                    "required": ["query"],
                    "additionalProperties": false
                }),
                output_schema: None,
                pricing: None,
                annotations: ToolAnnotations::default(),
                latency_hint: None,
                flow: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: signer.public_key().to_hex(),
        };
        let signed = sign_manifest(&manifest, &signer).unwrap();
        let mut registry = VerifiedManifestRegistry::default();
        registry
            .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::local())
            .unwrap();

        let mut invocation = sample_invocation();
        invocation.bridge_security = registry.bridge_security("srv-test", "search_web");
        (invocation, registry)
    }

    fn registry_bound_server_tool_invocation() -> (ToolInvocation, VerifiedManifestRegistry) {
        let signer = chio_core::crypto::Keypair::generate();
        let manifest = ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "srv-test".to_string(),
            name: "Provider server-tool test".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "search_web".to_string(),
                description: "Search the web".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: ToolAnnotations::default(),
                latency_hint: None,
                flow: Some(ToolFlowDeclaration::public_egress()),
            }],
            server_tools: vec![chio_manifest::ServerTool::Bash],
            required_permissions: None,
            public_key: signer.public_key().to_hex(),
        };
        let signed = sign_manifest(&manifest, &signer).unwrap();
        let policies = [
            (
                "search_web".to_string(),
                chio_manifest::AuthoritativeToolPolicy::public_only(),
            ),
            (
                "bash".to_string(),
                chio_manifest::AuthoritativeToolPolicy::public_only(),
            ),
        ]
        .into_iter()
        .collect();
        let topologies = [
            ("search_web".to_string(), RuntimeToolTopology::remote()),
            ("bash".to_string(), RuntimeToolTopology::remote()),
        ]
        .into_iter()
        .collect();
        let mut registry = VerifiedManifestRegistry::default();
        registry
            .register(signed, &signer.public_key(), &policies, &topologies)
            .unwrap();

        let mut invocation = sample_invocation();
        invocation.provider = ProviderId::Anthropic;
        invocation.tool_name = "bash_20241022".to_string();
        invocation.arguments =
            chio_core::canonical::canonical_json_bytes(&serde_json::json!({"command": "pwd"}))
                .unwrap();
        invocation.bridge_security =
            registry.bridge_security_for_server_tool("srv-test", "bash_20241022");
        invocation.provenance.provider = ProviderId::Anthropic;
        invocation.provenance.api_version = "messages.2024-10-22".to_string();
        invocation.provenance.principal = Principal::AnthropicWorkspace {
            workspace_id: "wks_provider_test".to_string(),
        };
        (invocation, registry)
    }

    struct CountingProviderServer {
        invocations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl crate::ToolServerConnection for CountingProviderServer {
        fn server_id(&self) -> &str {
            "srv-test"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["search_web".to_string()]
        }

        async fn invoke(
            &self,
            _tool_name: &str,
            arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn crate::NestedFlowBridge>,
        ) -> Result<serde_json::Value, crate::KernelError> {
            self.invocations
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(serde_json::json!({"echo": arguments}))
        }
    }

    fn provider_capability(
        authority: &chio_core::crypto::Keypair,
        subject: &chio_core::crypto::Keypair,
    ) -> CapabilityToken {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-provider-live-schema".to_string(),
                issuer: authority.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![chio_core::capability::scope::ToolGrant {
                        server_id: "srv-test".to_string(),
                        tool_name: "search_web".to_string(),
                        operations: vec![chio_core::capability::scope::Operation::Invoke],
                        constraints: Vec::new(),
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: Vec::new(),
                    prompt_grants: Vec::new(),
                },
                issued_at: now.saturating_sub(60),
                expires_at: now.saturating_add(300),
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            authority,
        )
        .unwrap()
    }

    fn synthetic_receipt(id: &str, decision: Decision) -> ChioReceipt {
        // Build a minimal signed receipt for the conversion tests. These
        // tests only exercise the structural mapping from kernel verdict
        // to fabric verdict; signature verification is covered by the
        // kernel's own receipt tests.
        let kp = chio_core::crypto::Keypair::generate();
        let body = chio_core::receipt::body::ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-test".to_string(),
            tool_server: "srv-test".to_string(),
            tool_name: "search_web".to_string(),
            action: ToolCallAction {
                parameters: serde_json::json!({"query": "chio"}),
                parameter_hash: "0".repeat(64),
            },
            decision: Some(decision),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "0".repeat(64),
            policy_hash: "0".repeat(64),
            evidence: Vec::new(),
            metadata: None,
            trust_level: Default::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
            bbs_projection_version: None,
        };
        ChioReceipt::sign(body, &kp).unwrap()
    }

    fn allow_response() -> ToolCallResponse {
        ToolCallResponse {
            request_id: "call_abc123".to_string(),
            verdict: Verdict::Allow,
            output: None,
            reason: None,
            terminal_state: OperationTerminalState::Completed,
            receipt: synthetic_receipt("rcpt_allow", Decision::Allow),
            execution_nonce: None,
        }
    }

    fn deny_response(reason: &str) -> ToolCallResponse {
        let dec = Decision::Deny {
            reason: reason.to_string(),
            guard: "policy.deny".to_string(),
        };
        ToolCallResponse {
            request_id: "call_abc123".to_string(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Completed,
            receipt: synthetic_receipt("rcpt_deny", dec),
            execution_nonce: None,
        }
    }

    fn pending_response() -> ToolCallResponse {
        ToolCallResponse {
            request_id: "call_abc123".to_string(),
            verdict: Verdict::PendingApproval,
            output: None,
            reason: Some("approval pending".to_string()),
            terminal_state: OperationTerminalState::Incomplete {
                reason: "approval pending".to_string(),
            },
            receipt: synthetic_receipt("rcpt_pending", Decision::Allow),
            execution_nonce: None,
        }
    }

    fn nonce_preflight_response() -> ToolCallResponse {
        ToolCallResponse {
            request_id: "call_abc123".to_string(),
            verdict: Verdict::Allow,
            output: None,
            reason: None,
            terminal_state: OperationTerminalState::Incomplete {
                reason: "execution nonce preflight requires retry with presented nonce".to_string(),
            },
            receipt: synthetic_receipt("rcpt_preflight", Decision::Allow),
            execution_nonce: None,
        }
    }

    #[test]
    fn provider_verdict_allow_maps_to_fabric_allow() {
        let inv = sample_invocation();
        let resp = allow_response();
        let v = verdict_result_from_response(&inv, &resp);
        match v {
            VerdictResult::Allow {
                redactions,
                receipt_id,
            } => {
                assert!(redactions.is_empty());
                assert_eq!(receipt_id, ReceiptId(resp.receipt.id.clone()));
            }
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn provider_verdict_deny_carries_kernel_reason_as_rule_id() {
        let inv = sample_invocation();
        let resp = deny_response("budget exhausted");
        let v = verdict_result_from_response(&inv, &resp);
        match v {
            VerdictResult::Deny { reason, receipt_id } => {
                assert_eq!(receipt_id, ReceiptId(resp.receipt.id.clone()));
                match reason {
                    DenyReason::PolicyDeny { rule_id } => {
                        assert_eq!(rule_id, "budget exhausted");
                    }
                    other => panic!("expected policy_deny, got {other:?}"),
                }
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn provider_verdict_deny_falls_back_to_default_rule_id_when_reason_missing() {
        let inv = sample_invocation();
        let mut resp = deny_response("unused");
        resp.reason = None;
        let v = verdict_result_from_response(&inv, &resp);
        let VerdictResult::Deny { reason, .. } = v else {
            panic!("expected deny");
        };
        let DenyReason::PolicyDeny { rule_id } = reason else {
            panic!("expected policy_deny");
        };
        assert_eq!(rule_id, "kernel.deny");
    }

    #[test]
    fn provider_verdict_pending_approval_fails_closed() {
        let inv = sample_invocation();
        let resp = pending_response();
        let v = verdict_result_from_response(&inv, &resp);
        match v {
            VerdictResult::Deny { reason, .. } => match reason {
                DenyReason::PolicyDeny { rule_id } => {
                    assert_eq!(rule_id, "kernel.pending_approval");
                }
                other => panic!("expected policy_deny for pending, got {other:?}"),
            },
            other => panic!("expected deny for pending approval, got {other:?}"),
        }
    }

    #[test]
    fn provider_verdict_nonce_preflight_fails_closed() {
        let inv = sample_invocation();
        let resp = nonce_preflight_response();
        let v = verdict_result_from_response(&inv, &resp);
        match v {
            VerdictResult::Deny { reason, receipt_id } => {
                assert_eq!(receipt_id, ReceiptId(resp.receipt.id.clone()));
                match reason {
                    DenyReason::PolicyDeny { rule_id } => {
                        assert_eq!(rule_id, "kernel.execution_nonce_preflight");
                    }
                    other => panic!("expected policy_deny for nonce preflight, got {other:?}"),
                }
            }
            other => panic!("expected deny for nonce preflight, got {other:?}"),
        }
    }

    #[test]
    fn provider_verdict_receipt_id_round_trips() {
        let inv = sample_invocation();
        let resp = allow_response();
        let v = verdict_result_from_response(&inv, &resp);
        let json = serde_json::to_string(&v).unwrap();
        let back: VerdictResult = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn provider_verdict_canonical_invocation_bytes_are_stable() {
        let inv = sample_invocation();
        let a = canonical_invocation_bytes(&inv).unwrap();
        let b = canonical_invocation_bytes(&inv).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn provider_execution_preserves_registry_admitted_flow_metadata() {
        let (invocation, registry) = registry_bound_invocation();
        let expected_sidecar =
            serde_json::to_value(invocation.bridge_security.as_ref().unwrap()).unwrap();
        let (request, metadata) = lower_provider_invocation(
            &invocation,
            sample_capability(),
            "agent-test".to_string(),
            "srv-test".to_string(),
            &registry,
        )
        .unwrap();

        assert_eq!(request.tool_name, "search_web");
        assert_eq!(request.server_id, "srv-test");
        assert_eq!(metadata["chio_manifest_security_v1"], expected_sidecar);
        assert_eq!(
            metadata["chio_manifest_security_v1"]["flow"],
            serde_json::to_value(ToolFlowDeclaration::public_egress()).unwrap()
        );
    }

    #[test]
    fn provider_lowering_rejects_arguments_outside_signed_manifest_schema() {
        let (mut invocation, registry) = registry_bound_invocation();
        invocation.arguments =
            chio_core::canonical::canonical_json_bytes(&serde_json::json!({"query": 7})).unwrap();

        let error = lower_provider_invocation(
            &invocation,
            sample_capability(),
            "agent-test".to_string(),
            "srv-test".to_string(),
            &registry,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ProviderVerdictError::ManifestArguments(reason)
                if reason.contains("signed manifest input schema")
        ));
    }

    #[test]
    fn provider_lowering_uses_trusted_schema_for_admitted_server_tool_family() {
        let (mut invocation, registry) = registry_bound_server_tool_invocation();
        let (request, _) = lower_provider_invocation(
            &invocation,
            sample_capability(),
            "agent-test".to_string(),
            "srv-test".to_string(),
            &registry,
        )
        .unwrap();
        assert_eq!(request.tool_name, "bash_20241022");
        assert_eq!(request.arguments, serde_json::json!({"command": "pwd"}));

        invocation.tool_name = "bash_20250124".to_string();
        invocation.arguments =
            chio_core::canonical::canonical_json_bytes(&serde_json::json!({"command": 7})).unwrap();
        let error = lower_provider_invocation(
            &invocation,
            sample_capability(),
            "agent-test".to_string(),
            "srv-test".to_string(),
            &registry,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ProviderVerdictError::ManifestArguments(reason)
                if reason.contains("trusted server-tool input schema")
        ));
    }

    #[test]
    fn provider_entrypoint_rejects_invalid_arguments_without_effects_and_recovers() {
        let (mut invocation, registry) = local_registry_bound_invocation();
        let authority = chio_core::crypto::Keypair::generate();
        let subject = chio_core::crypto::Keypair::generate();
        let capability = provider_capability(&authority, &subject);
        let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut kernel = crate::ChioKernel::new(crate::KernelConfig {
            keypair: chio_core::crypto::Keypair::generate(),
            ca_public_keys: vec![authority.public_key()],
            max_delegation_depth: 5,
            policy_hash: "provider-schema-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: crate::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: crate::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: crate::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: crate::MemoryBudgetConfig::defaults(),
            deadlines: crate::HotPathDeadlineConfig::default(),
            dispatch_intent_journal: crate::DispatchIntentJournalMode::Off,
        });
        kernel.register_tool_server(Box::new(CountingProviderServer {
            invocations: std::sync::Arc::clone(&invocations),
        }));
        invocation.arguments =
            chio_core::canonical::canonical_json_bytes(&serde_json::json!({"query": 7})).unwrap();
        let receipt_count_before = kernel.receipt_log().len();

        let error = kernel
            .verdict_for_provider_invocation(
                &invocation,
                capability.clone(),
                subject.public_key().to_hex(),
                "srv-test".to_string(),
                &registry,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            crate::KernelError::Internal(reason)
                if reason.contains("signed manifest input schema")
        ));
        assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(kernel.receipt_log().len(), receipt_count_before);

        invocation.arguments =
            chio_core::canonical::canonical_json_bytes(&serde_json::json!({"query": "chio"}))
                .unwrap();
        let verdict = kernel
            .verdict_for_provider_invocation(
                &invocation,
                capability,
                subject.public_key().to_hex(),
                "srv-test".to_string(),
                &registry,
            )
            .unwrap();

        assert!(matches!(verdict, VerdictResult::Allow { .. }));
        assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(kernel.receipt_log().len(), receipt_count_before + 1);
    }

    #[test]
    fn provider_entrypoint_rejects_security_context_for_another_principal() {
        let signer = chio_core::crypto::Keypair::generate();
        let manifest = ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "srv-test".to_string(),
            name: "Provider binding test server".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "search_web".to_string(),
                description: "Search the web".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: ToolAnnotations::default(),
                latency_hint: None,
                flow: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: signer.public_key().to_hex(),
        };
        let signed = sign_manifest(&manifest, &signer).unwrap();
        let mut registry = VerifiedManifestRegistry::default();
        registry
            .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
            .unwrap();
        let mut invocation = sample_invocation();
        invocation.bridge_security = registry.bridge_security("srv-test", "search_web");
        let capability = sample_capability();
        let security_context =
            crate::SecurityInvocationContext::v1(crate::SecurityInvocationContextV1::new(
                chio_security_types::ports::TenantId::new("tenant-provider-binding").unwrap(),
                chio_security_types::ports::SessionId::new("session-provider-binding").unwrap(),
                chio_security_types::PrincipalId::new("different-provider-agent").unwrap(),
                chio_security_types::ports::IsolationEpochId::new("epoch-provider-binding")
                    .unwrap(),
                chio_security_types::ports::LineageId::new(capability.id.clone()).unwrap(),
                1,
            ));
        let kernel = crate::ChioKernel::new(crate::KernelConfig {
            keypair: chio_core::crypto::Keypair::generate(),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 5,
            policy_hash: "provider-binding-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: crate::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: crate::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: crate::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: crate::MemoryBudgetConfig::defaults(),
            deadlines: crate::HotPathDeadlineConfig::default(),
            dispatch_intent_journal: crate::DispatchIntentJournalMode::Off,
        });

        let error = kernel
            .verdict_for_provider_invocation_with_security_context(
                &invocation,
                capability,
                "provider-agent".to_string(),
                "srv-test".to_string(),
                &registry,
                &security_context,
            )
            .unwrap_err();

        assert!(
            matches!(
                &error,
                crate::KernelError::GuardDenied(reason)
                    if reason == "authoritative security context principal does not match the request agent"
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn provider_execution_rejects_projection_without_security_sidecar() {
        let (_, registry) = registry_bound_invocation();
        let error = build_tool_call_request(
            &sample_invocation(),
            sample_capability(),
            "agent-test".to_string(),
            "srv-test".to_string(),
            &registry,
        )
        .unwrap_err();
        assert!(matches!(error, ProviderVerdictError::MissingBridgeSecurity));
    }

    #[test]
    fn provider_execution_rejects_unadmitted_security_sidecar() {
        let (_, registry) = registry_bound_invocation();
        let mut invocation = sample_invocation();
        invocation.bridge_security = Some(BridgeSecurityMetadata::from_flow(Some(
            ToolFlowDeclaration::public_egress(),
        )));
        let error = build_tool_call_request(
            &invocation,
            sample_capability(),
            "agent-test".to_string(),
            "srv-test".to_string(),
            &registry,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ProviderVerdictError::InvalidInvocation(
                ToolInvocationValidationError::UnadmittedBridgeSecurity
            )
        ));
    }

    #[test]
    fn provider_execution_rejects_structural_coordinates_with_forged_digest() {
        let (mut invocation, registry) = registry_bound_invocation();
        let mut forged = serde_json::to_value(
            invocation
                .bridge_security
                .as_ref()
                .unwrap_or_else(|| panic!("bridge security")),
        )
        .unwrap_or_else(|error| panic!("serialize sidecar: {error}"));
        forged["manifest_digest"] = serde_json::json!("00".repeat(32));
        invocation.bridge_security = Some(
            serde_json::from_value(forged)
                .unwrap_or_else(|error| panic!("decode forged sidecar: {error}")),
        );
        let error = build_tool_call_request(
            &invocation,
            sample_capability(),
            "agent-test".to_string(),
            "srv-test".to_string(),
            &registry,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ProviderVerdictError::BridgeSecurityMismatch(_)
        ));
    }

    #[test]
    fn provider_execution_rejects_manifest_server_mismatch() {
        let (invocation, registry) = registry_bound_invocation();
        let error = build_tool_call_request(
            &invocation,
            sample_capability(),
            "agent-test".to_string(),
            "srv-other".to_string(),
            &registry,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ProviderVerdictError::BridgeServerMismatch { .. }
        ));
    }

    #[test]
    fn provider_execution_rejects_manifest_tool_mismatch() {
        let (mut invocation, registry) = registry_bound_invocation();
        invocation.tool_name = "search_private".to_string();
        let error = build_tool_call_request(
            &invocation,
            sample_capability(),
            "agent-test".to_string(),
            "srv-test".to_string(),
            &registry,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ProviderVerdictError::InvalidInvocation(
                ToolInvocationValidationError::BridgeToolMismatch { .. }
            )
        ));
    }

    #[test]
    fn provider_verdict_known_provider_lanes_are_three() {
        // Sanity check that the provider-id constant tracks the fabric.
        assert_eq!(FABRIC_SHIM_PROVIDER_LANES.len(), 3);
    }
}
