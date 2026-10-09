use crate::conversion::ensure_chio_metadata;
use crate::error::{record_receipt_write_bridge_error, A2aEdgeError};
use chio_cross_protocol::capability_bridge::{CapabilityBridge, CrossProtocolCapabilityRef};
use chio_cross_protocol::discovery::{
    target_protocol_for_tool_with_registry, DiscoveryProtocol, TargetProtocolRegistry,
};
use chio_cross_protocol::error::BridgeError;
use chio_cross_protocol::execution::{CrossProtocolExecutionRequest, OpenAiTargetExecutor};
use chio_cross_protocol::lifecycle::{runtime_lifecycle_contract, RuntimeLifecycleSurface};
use chio_cross_protocol::orchestrator::{CrossProtocolOrchestrator, OrchestratedToolCall};
use chio_cross_protocol::semantic_hints::{semantic_hints_for_tool, BridgeFidelity};
use chio_kernel::ChioKernel;
use chio_manifest::{
    BridgeSecurityMetadata, ToolDefinition, ToolManifest, VerifiedManifestRegistry,
};
use chio_mcp_edge::McpTargetExecutor;
use serde_json::{json, Value};

// Cross-protocol capability bridge, skill candidate construction, fidelity
// evaluation, and the authoritative target registry / orchestration path.

struct A2aCapabilityBridge;

static MCP_TARGET_EXECUTOR: McpTargetExecutor = McpTargetExecutor {
    peer_supports_chio_tool_streaming: false,
};
static OPENAI_TARGET_EXECUTOR: OpenAiTargetExecutor = OpenAiTargetExecutor;
pub(super) const MAX_DEFERRED_A2A_TASKS: usize = 1024;
pub(super) const DEFERRED_A2A_TASK_TTL_MILLIS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone)]
pub(super) struct SkillBinding {
    pub(super) target_protocol: DiscoveryProtocol,
    pub(super) server_id: String,
    pub(super) tool_name: String,
    pub(super) security: BridgeSecurityMetadata,
}

#[derive(Debug, Clone)]
pub(super) struct SkillCandidate {
    pub(super) published_id: String,
    pub(super) lookup_alias: Option<String>,
    pub(super) display_name: String,
    pub(super) description: String,
    pub(super) tags: Vec<String>,
    pub(super) fidelity: BridgeFidelity,
    pub(super) binding: Option<SkillBinding>,
}

impl CapabilityBridge for A2aCapabilityBridge {
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
            .map_err(|error| {
                BridgeError::UntrustedInput(chio_core::canonical::UntrustedJsonError::Decode(error))
            })
    }

    fn inject_capability_ref(
        &self,
        envelope: &mut Value,
        cap_ref: &CrossProtocolCapabilityRef,
    ) -> Result<(), BridgeError> {
        let chio_metadata = ensure_chio_metadata(envelope)?;
        chio_metadata.insert(
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
            .map(|skill_id| json!({ "targetSkillId": skill_id })))
    }
}

/// Evaluate how faithfully a Chio tool maps to A2A semantics.
fn evaluate_bridge_fidelity(
    tool: &ToolDefinition,
    target_protocol: DiscoveryProtocol,
) -> BridgeFidelity {
    let registry = authoritative_target_registry();
    let hints = semantic_hints_for_tool(tool);
    let lifecycle = runtime_lifecycle_contract(RuntimeLifecycleSurface::A2aAuthoritative);
    if !hints.publish {
        return BridgeFidelity::Unsupported {
            reason: "publication disabled by x-chio-publish=false".to_string(),
        };
    }
    if !registry.supports_target_protocol(target_protocol) {
        return BridgeFidelity::Unsupported {
            reason: format!(
                "A2A authoritative execution does not yet have a registered `{target_protocol}` target executor"
            ),
        };
    }
    if hints.approval_required {
        return BridgeFidelity::Unsupported {
            reason: "requires interactive approval semantics that the current A2A edge cannot truthfully project".to_string(),
        };
    }
    let mut caveats = Vec::new();
    if !tool.annotations.read_only {
        caveats.push(
            "A2A publication cannot project protocol-native permission prompts; callers must rely on Chio capability enforcement".to_string(),
        );
    }
    if hints.streams_output {
        caveats.push(format!(
            "stream-capable tools execute through `{}` deferred tasks; output is surfaced on follow-up `{}` rather than incremental transport updates",
            lifecycle.stream_entrypoint, lifecycle.follow_up_entrypoint
        ));
        caveats.push(
            "stream chunks are collated into the terminal task payload instead of pushed as incremental A2A events".to_string(),
        );
    }
    if hints.partial_output {
        caveats.push(
            "partial output is preserved only in the terminal task payload, not incremental updates"
                .to_string(),
        );
    }
    if hints.supports_cancellation {
        caveats.push(format!(
            "cancellation is available only for deferred `{}` tasks; blocking `{}` remains terminal",
            lifecycle.stream_entrypoint, lifecycle.blocking_entrypoint
        ));
    }

    if caveats.is_empty() {
        BridgeFidelity::Lossless
    } else {
        BridgeFidelity::Adapted { caveats }
    }
}

pub(super) fn build_skill_candidate(
    manifest: &ToolManifest,
    tool: &ToolDefinition,
    requires_qualification: bool,
    security: BridgeSecurityMetadata,
) -> Result<SkillCandidate, A2aEdgeError> {
    let target_protocol =
        target_protocol_for_tool_with_registry(tool, &authoritative_target_registry())
            .map_err(A2aEdgeError::InvalidRequest)?;
    let fidelity = evaluate_bridge_fidelity(tool, target_protocol);
    let (published_id, lookup_alias, display_name, mut tags, description) =
        if requires_qualification {
            (
            format!("{}::{}", manifest.server_id, tool.name),
            Some(tool.name.clone()),
            format!("{} ({})", tool.name, manifest.server_id),
            vec!["chio:collision-qualified".to_string()],
            format!(
                "{} Published under a server-qualified skill id because this tool name collides across manifests.",
                tool.description
            ),
        )
        } else {
            (
                tool.name.clone(),
                None,
                tool.name.clone(),
                vec![],
                tool.description.clone(),
            )
        };

    if !fidelity.published_by_default() {
        tags.push("chio:publication-gated".to_string());
    }
    if target_protocol != DiscoveryProtocol::Native {
        tags.push(format!("chio:target-protocol:{target_protocol}"));
    }

    Ok(SkillCandidate {
        binding: fidelity.published_by_default().then(|| SkillBinding {
            target_protocol,
            server_id: manifest.server_id.clone(),
            tool_name: tool.name.clone(),
            security,
        }),
        published_id,
        lookup_alias,
        display_name,
        description,
        tags,
        fidelity,
    })
}

pub(super) fn execute_orchestrated_a2a_request(
    peer: &chio_core::capability::features::CapabilityNegotiation,
    kernel: &ChioKernel,
    manifest_registry: &VerifiedManifestRegistry,
    request: CrossProtocolExecutionRequest,
) -> Result<OrchestratedToolCall, A2aEdgeError> {
    let registry = authoritative_target_registry();
    if !registry.supports_target_protocol(request.target_protocol) {
        return Err(A2aEdgeError::InvalidRequest(format!(
            "A2A authoritative execution does not have a registered `{}` target executor",
            request.target_protocol
        )));
    }

    match CrossProtocolOrchestrator::new(kernel, manifest_registry)
        .with_peer_capabilities(peer)?
        .with_registry(registry)
        .execute(&A2aCapabilityBridge, request)
    {
        Ok(orchestrated) => Ok(orchestrated),
        Err(error) => {
            record_receipt_write_bridge_error(&error);
            Err(error.into())
        }
    }
}

fn authoritative_target_registry() -> TargetProtocolRegistry<'static> {
    TargetProtocolRegistry::new(DiscoveryProtocol::Native)
        .with_executor(&MCP_TARGET_EXECUTOR)
        .with_executor(&OPENAI_TARGET_EXECUTOR)
}
