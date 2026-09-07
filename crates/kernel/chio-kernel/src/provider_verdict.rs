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

/// Errors surfaced when admitting fabric types into the kernel's MCP path.
///
/// The shim validates the invocation against the live verified-manifest
/// registry before constructing a [`ToolCallRequest`]. The underlying kernel
/// pipeline still owns its own [`crate::KernelError`] surface.
#[derive(Debug, thiserror::Error)]
pub enum ProviderVerdictError {
    /// The lifted invocation failed the fabric's structural validation.
    #[error("invalid provider invocation: {0}")]
    InvalidInvocation(#[source] ToolInvocationValidationError),
    /// Projection without a registry-admitted sidecar cannot execute.
    #[error("provider invocation is missing registry-admitted bridge security")]
    MissingBridgeSecurity,
    /// The execution target must equal the server admitted by the sidecar.
    #[error(
        "provider invocation targets server {target}, but bridge security admits server {admitted}"
    )]
    BridgeServerMismatch { target: String, admitted: String },
    /// The complete sidecar must equal the live registry value.
    #[error("provider bridge security does not match the live registry: {0}")]
    BridgeSecurityMismatch(String),
    /// The fabric arguments payload was not valid JSON. Fabric promises
    /// canonical-JSON bytes (RFC 8785); a parse failure here is a contract
    /// violation by the upstream adapter.
    #[error("fabric arguments payload is not valid JSON: {0}")]
    InvalidArguments(#[source] serde_json::Error),
    /// Decoded arguments must satisfy the registry-admitted schema.
    #[error("provider arguments do not satisfy the registry-admitted input schema: {0}")]
    ManifestArguments(String),
}

/// Build a [`ToolCallRequest`] from a fabric [`ToolInvocation`] plus the
/// surrounding kernel context (capability token, calling agent, target tool
/// server). The helper validates the fabric shape, the complete registry-bound
/// security sidecar, and the signed input schema. Runtime policy decisions
/// remain with the kernel evaluation path.
///
/// `request_id` defaults to `invocation.provenance.request_id` so the
/// upstream provider's request id flows into the kernel verdict and into the
/// resulting receipt without a second round of bookkeeping.
pub fn build_tool_call_request(
    invocation: &ToolInvocation,
    capability: CapabilityToken,
    agent_id: AgentId,
    server_id: ServerId,
    registry: &chio_manifest::VerifiedManifestRegistry,
) -> Result<ToolCallRequest, ProviderVerdictError> {
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
    if admitted_server != server_id {
        return Err(ProviderVerdictError::BridgeServerMismatch {
            target: server_id,
            admitted: admitted_server.to_string(),
        });
    }
    registry
        .validate_bridge_security(&server_id, &invocation.tool_name, bridge_security)
        .map_err(|error| ProviderVerdictError::BridgeSecurityMismatch(error.to_string()))?;
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

    Ok(ToolCallRequest {
        request_id: invocation.provenance.request_id.clone(),
        capability,
        tool_name: invocation.tool_name.clone(),
        server_id,
        agent_id,
        arguments,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    })
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
    /// invocation through the registry-bound manifest-security path.
    ///
    /// The shim builds a [`ToolCallRequest`] from the supplied invocation
    /// plus the surrounding capability context, validates it against the live
    /// verified-manifest registry, evaluates it with manifest security, and
    /// lowers the kernel response into a fabric verdict via
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

    /// Compute a provider verdict with trusted identity and isolation state.
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
        let request =
            build_tool_call_request(invocation, capability, agent_id, server_id, registry)
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
        ToolDefinition, ToolManifest, VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
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
        let signer = chio_core::crypto::Keypair::from_seed(&[76; 32]);
        let manifest = ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "srv-test".to_string(),
            name: "Provider verdict test".to_string(),
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
    fn provider_lowering_accepts_only_exact_registry_binding_and_schema() {
        let (invocation, registry) = registry_bound_invocation();

        let request = build_tool_call_request(
            &invocation,
            sample_capability(),
            "agent-test".to_string(),
            "srv-test".to_string(),
            &registry,
        )
        .unwrap();

        assert_eq!(request.server_id, "srv-test");
        assert_eq!(request.tool_name, "search_web");
        assert_eq!(request.arguments, serde_json::json!({"query": "chio"}));
    }

    #[test]
    fn provider_lowering_rejects_missing_or_forged_security_sidecars() {
        let (mut invocation, registry) = registry_bound_invocation();
        invocation.bridge_security = None;
        let missing = build_tool_call_request(
            &invocation,
            sample_capability(),
            "agent-test".to_string(),
            "srv-test".to_string(),
            &registry,
        )
        .expect_err("projection-only invocation must not execute");
        assert!(matches!(
            missing,
            ProviderVerdictError::MissingBridgeSecurity
        ));

        let (mut invocation, registry) = registry_bound_invocation();
        let mut forged = serde_json::to_value(
            invocation
                .bridge_security
                .as_ref()
                .expect("bound invocation has security metadata"),
        )
        .unwrap();
        forged["manifest_digest"] = serde_json::json!("00".repeat(32));
        invocation.bridge_security =
            Some(serde_json::from_value::<BridgeSecurityMetadata>(forged).unwrap());
        let error = build_tool_call_request(
            &invocation,
            sample_capability(),
            "agent-test".to_string(),
            "srv-test".to_string(),
            &registry,
        )
        .expect_err("forged registry digest must fail closed");
        assert!(matches!(
            error,
            ProviderVerdictError::BridgeSecurityMismatch(_)
        ));
    }

    #[test]
    fn provider_lowering_rejects_server_and_schema_drift() {
        let (invocation, registry) = registry_bound_invocation();
        let server_error = build_tool_call_request(
            &invocation,
            sample_capability(),
            "agent-test".to_string(),
            "other-server".to_string(),
            &registry,
        )
        .expect_err("execution target must equal the admitted server");
        assert!(matches!(
            server_error,
            ProviderVerdictError::BridgeServerMismatch { .. }
        ));

        let (mut invocation, registry) = registry_bound_invocation();
        invocation.arguments = chio_core::canonical::canonical_json_bytes(&serde_json::json!({
            "query": "query-is-too-long"
        }))
        .unwrap();
        let schema_error = build_tool_call_request(
            &invocation,
            sample_capability(),
            "agent-test".to_string(),
            "srv-test".to_string(),
            &registry,
        )
        .expect_err("arguments outside the signed schema must fail closed");
        assert!(matches!(
            schema_error,
            ProviderVerdictError::ManifestArguments(_)
        ));
    }

    #[test]
    fn provider_verdict_known_provider_lanes_are_three() {
        // Sanity check that the provider-id constant tracks the fabric.
        assert_eq!(FABRIC_SHIM_PROVIDER_LANES.len(), 3);
    }
}
