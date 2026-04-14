//! # arc-acp-edge
//!
//! Edge crate that exposes ARC kernel-governed tools as ACP (Agent Client
//! Protocol) capabilities. This allows ACP-compatible editors and IDEs to
//! access ARC-governed tools.
//!
//! Responsibilities:
//!
//! 1. Map ARC tool definitions to ACP capability advertisements.
//! 2. Intercept ACP `session/request_permission` calls.
//! 3. Route tool invocations through the ARC kernel guard pipeline.
//! 4. Evaluate `BridgeFidelity` per tool.
//!
//! NOTE: Full integration with signed ACP receipts requires Phase 324
//! (ACP Kernel Integration). This crate provides the type foundation
//! and basic routing logic.

use std::collections::BTreeMap;

use arc_kernel::ToolServerConnection;
use arc_manifest::{ToolDefinition, ToolManifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Errors produced by the ACP edge.
#[derive(Debug, thiserror::Error)]
pub enum AcpEdgeError {
    /// A tool was not found.
    #[error("tool not found: {0}")]
    ToolNotFound(String),

    /// The request was malformed.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Access was denied.
    #[error("access denied: {0}")]
    AccessDenied(String),

    /// The kernel reported an error.
    #[error("kernel error: {0}")]
    Kernel(String),

    /// Manifest error.
    #[error("manifest error: {0}")]
    Manifest(#[from] arc_manifest::ManifestError),
}

/// Fidelity assessment for how well an ARC tool maps to ACP semantics.
///
/// ACP has a narrow tool model (fs read/write, terminal commands, browser
/// actions) so many ARC tools will be `Degraded` or `Partial`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeFidelity {
    /// Tool maps perfectly to an ACP primitive.
    Full,
    /// Tool maps with minor semantic loss.
    Partial,
    /// Tool maps with significant loss.
    Degraded,
}

/// An ACP capability advertisement derived from an ARC tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcpCapability {
    /// Capability identifier (matches the ARC tool name).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of the capability.
    pub description: String,
    /// The ACP category this maps to (e.g., "tool", "fs", "terminal").
    pub category: AcpCategory,
    /// Whether the capability requires explicit permission.
    pub requires_permission: bool,
    /// Fidelity assessment for this mapping.
    pub bridge_fidelity: BridgeFidelity,
}

/// ACP capability categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcpCategory {
    /// General tool invocation.
    Tool,
    /// Filesystem operations.
    Filesystem,
    /// Terminal/command execution.
    Terminal,
    /// Browser-based operations.
    Browser,
}

/// Configuration for the ACP edge.
#[derive(Debug, Clone)]
pub struct AcpEdgeConfig {
    /// Whether to require explicit permission for all tools.
    pub require_permission: bool,
    /// Default ACP category for unmapped tools.
    pub default_category: AcpCategory,
}

impl Default for AcpEdgeConfig {
    fn default() -> Self {
        Self {
            require_permission: true,
            default_category: AcpCategory::Tool,
        }
    }
}

/// An ACP permission request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequest {
    /// The capability ID being requested.
    pub capability_id: String,
    /// Arguments for the invocation.
    pub arguments: Value,
}

/// An ACP permission decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDecision {
    /// Permission granted.
    Allow,
    /// Permission denied.
    Deny,
}

/// Result of an ACP tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcpInvocationResult {
    /// Whether the invocation succeeded.
    pub success: bool,
    /// The result data.
    pub data: Value,
    /// Optional error message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The ACP edge server.
///
/// Maps ARC tools to ACP capabilities and routes invocations through
/// the kernel guard pipeline.
pub struct ArcAcpEdge {
    #[allow(dead_code)]
    config: AcpEdgeConfig,
    capabilities: Vec<AcpCapability>,
    /// Maps capability ID to (server_id, tool_name).
    capability_bindings: BTreeMap<String, (String, String)>,
}

impl ArcAcpEdge {
    /// Create a new ACP edge from ARC tool manifests.
    pub fn new(config: AcpEdgeConfig, manifests: Vec<ToolManifest>) -> Result<Self, AcpEdgeError> {
        let mut capabilities = Vec::new();
        let mut capability_bindings = BTreeMap::new();

        for manifest in &manifests {
            for tool in &manifest.tools {
                let cap_id = tool.name.clone();
                if capability_bindings.contains_key(&cap_id) {
                    continue;
                }

                let category = infer_acp_category(tool, config.default_category);
                let fidelity = evaluate_bridge_fidelity(tool, category);

                capabilities.push(AcpCapability {
                    id: cap_id.clone(),
                    name: cap_id.clone(),
                    description: tool.description.clone(),
                    category,
                    requires_permission: config.require_permission || tool.has_side_effects,
                    bridge_fidelity: fidelity,
                });

                capability_bindings.insert(cap_id, (manifest.server_id.clone(), tool.name.clone()));
            }
        }

        Ok(Self {
            config,
            capabilities,
            capability_bindings,
        })
    }

    /// List all capabilities.
    pub fn capabilities(&self) -> &[AcpCapability] {
        &self.capabilities
    }

    /// Get a capability by ID.
    pub fn capability(&self, id: &str) -> Option<&AcpCapability> {
        self.capabilities.iter().find(|c| c.id == id)
    }

    /// List all capability IDs.
    pub fn capability_ids(&self) -> Vec<String> {
        self.capabilities.iter().map(|c| c.id.clone()).collect()
    }

    /// Evaluate a permission request.
    ///
    /// In the full implementation, this would check the kernel's capability
    /// tokens. For now, it uses the configuration's require_permission flag.
    pub fn evaluate_permission(&self, request: &PermissionRequest) -> PermissionDecision {
        let Some(cap) = self.capability(&request.capability_id) else {
            return PermissionDecision::Deny;
        };

        // Fail-closed: if permission is required and not explicitly granted,
        // deny by default.
        if cap.requires_permission {
            PermissionDecision::Deny
        } else {
            PermissionDecision::Allow
        }
    }

    /// Invoke a capability through the tool server.
    pub fn invoke(
        &self,
        capability_id: &str,
        arguments: Value,
        server: &dyn ToolServerConnection,
    ) -> Result<AcpInvocationResult, AcpEdgeError> {
        let (_server_id, tool_name) = self
            .capability_bindings
            .get(capability_id)
            .ok_or_else(|| AcpEdgeError::ToolNotFound(capability_id.to_string()))?;

        match server.invoke(tool_name, arguments, None) {
            Ok(result) => Ok(AcpInvocationResult {
                success: true,
                data: result,
                error: None,
            }),
            Err(error) => Ok(AcpInvocationResult {
                success: false,
                data: Value::Null,
                error: Some(error.to_string()),
            }),
        }
    }

    /// Handle a JSON-RPC ACP request.
    pub fn handle_jsonrpc(&self, message: Value, server: &dyn ToolServerConnection) -> Value {
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        match method {
            "session/list_capabilities" => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "capabilities": serde_json::to_value(&self.capabilities)
                            .unwrap_or(Value::Null)
                    }
                })
            }
            "session/request_permission" => {
                let cap_id = params
                    .get("capabilityId")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let request = PermissionRequest {
                    capability_id: cap_id.to_string(),
                    arguments: params
                        .get("arguments")
                        .cloned()
                        .unwrap_or_else(|| json!({})),
                };
                let decision = self.evaluate_permission(&request);
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "decision": serde_json::to_value(decision)
                            .unwrap_or(Value::Null)
                    }
                })
            }
            "tool/invoke" => {
                let cap_id = params
                    .get("capabilityId")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                match self.invoke(cap_id, arguments, server) {
                    Ok(result) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": serde_json::to_value(&result)
                            .unwrap_or(Value::Null)
                    }),
                    Err(error) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32603,
                            "message": error.to_string()
                        }
                    }),
                }
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": "method not found"
                }
            }),
        }
    }
}

/// Infer the ACP category for an ARC tool based on its name and properties.
fn infer_acp_category(tool: &ToolDefinition, default: AcpCategory) -> AcpCategory {
    let name_lower = tool.name.to_lowercase();
    if name_lower.contains("read_file")
        || name_lower.contains("write_file")
        || name_lower.contains("list_dir")
        || name_lower.starts_with("fs_")
    {
        AcpCategory::Filesystem
    } else if name_lower.contains("terminal")
        || name_lower.contains("exec")
        || name_lower.contains("shell")
        || name_lower.contains("command")
    {
        AcpCategory::Terminal
    } else if name_lower.contains("browser")
        || name_lower.contains("navigate")
        || name_lower.contains("screenshot")
    {
        AcpCategory::Browser
    } else {
        default
    }
}

/// Evaluate bridge fidelity for an ARC tool to ACP mapping.
fn evaluate_bridge_fidelity(tool: &ToolDefinition, category: AcpCategory) -> BridgeFidelity {
    match category {
        // Filesystem and terminal tools map well to ACP primitives
        AcpCategory::Filesystem | AcpCategory::Terminal => BridgeFidelity::Full,
        AcpCategory::Browser => BridgeFidelity::Partial,
        AcpCategory::Tool => {
            if tool.has_side_effects {
                BridgeFidelity::Degraded
            } else {
                BridgeFidelity::Partial
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use arc_kernel::{KernelError, NestedFlowBridge};

    struct MockToolServer {
        server_id: String,
        tools: Vec<String>,
        response: Value,
    }

    impl ToolServerConnection for MockToolServer {
        fn server_id(&self) -> &str {
            &self.server_id
        }

        fn tool_names(&self) -> Vec<String> {
            self.tools.clone()
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Ok(self.response.clone())
        }
    }

    struct FailingToolServer;

    impl ToolServerConnection for FailingToolServer {
        fn server_id(&self) -> &str {
            "fail-srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["fail_tool".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Err(KernelError::ToolServerError("simulated failure".into()))
        }
    }

    fn test_manifest() -> ToolManifest {
        ToolManifest {
            schema: "arc.manifest.v1".to_string(),
            server_id: "test-srv".to_string(),
            name: "Test Server".to_string(),
            description: Some("Test".to_string()),
            version: "1.0.0".to_string(),
            tools: vec![
                ToolDefinition {
                    name: "read_file".to_string(),
                    description: "Read a file".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: false,
                    latency_hint: None,
                },
                ToolDefinition {
                    name: "write_file".to_string(),
                    description: "Write a file".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: true,
                    latency_hint: None,
                },
                ToolDefinition {
                    name: "exec_command".to_string(),
                    description: "Execute a shell command".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: true,
                    latency_hint: None,
                },
                ToolDefinition {
                    name: "search".to_string(),
                    description: "Search documents".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: false,
                    latency_hint: None,
                },
            ],
            required_permissions: None,
            public_key: "aabbccdd".to_string(),
        }
    }

    fn test_server() -> MockToolServer {
        MockToolServer {
            server_id: "test-srv".to_string(),
            tools: vec![
                "read_file".to_string(),
                "write_file".to_string(),
                "exec_command".to_string(),
                "search".to_string(),
            ],
            response: json!({"result": "ok"}),
        }
    }

    // ---- Capability generation tests ----

    #[test]
    fn edge_generates_capabilities_from_manifest() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        assert_eq!(edge.capabilities().len(), 4);
    }

    #[test]
    fn edge_capability_ids_match_tool_names() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let ids = edge.capability_ids();
        assert!(ids.contains(&"read_file".to_string()));
        assert!(ids.contains(&"write_file".to_string()));
        assert!(ids.contains(&"exec_command".to_string()));
        assert!(ids.contains(&"search".to_string()));
    }

    #[test]
    fn edge_capability_lookup() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("read_file").unwrap();
        assert_eq!(cap.description, "Read a file");
    }

    #[test]
    fn edge_unknown_capability_returns_none() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        assert!(edge.capability("nonexistent").is_none());
    }

    // ---- Category inference tests ----

    #[test]
    fn read_file_gets_filesystem_category() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("read_file").unwrap();
        assert_eq!(cap.category, AcpCategory::Filesystem);
    }

    #[test]
    fn write_file_gets_filesystem_category() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("write_file").unwrap();
        assert_eq!(cap.category, AcpCategory::Filesystem);
    }

    #[test]
    fn exec_command_gets_terminal_category() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("exec_command").unwrap();
        assert_eq!(cap.category, AcpCategory::Terminal);
    }

    #[test]
    fn search_gets_default_tool_category() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("search").unwrap();
        assert_eq!(cap.category, AcpCategory::Tool);
    }

    // ---- BridgeFidelity tests ----

    #[test]
    fn filesystem_tools_have_full_fidelity() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("read_file").unwrap();
        assert_eq!(cap.bridge_fidelity, BridgeFidelity::Full);
    }

    #[test]
    fn terminal_tools_have_full_fidelity() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("exec_command").unwrap();
        assert_eq!(cap.bridge_fidelity, BridgeFidelity::Full);
    }

    #[test]
    fn generic_readonly_tool_has_partial_fidelity() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("search").unwrap();
        assert_eq!(cap.bridge_fidelity, BridgeFidelity::Partial);
    }

    // ---- Permission tests ----

    #[test]
    fn side_effect_tools_require_permission() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let cap = edge.capability("write_file").unwrap();
        assert!(cap.requires_permission);
    }

    #[test]
    fn permission_denied_by_default_for_required_caps() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let request = PermissionRequest {
            capability_id: "write_file".to_string(),
            arguments: json!({}),
        };
        assert_eq!(edge.evaluate_permission(&request), PermissionDecision::Deny);
    }

    #[test]
    fn permission_denied_for_unknown_capability() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let request = PermissionRequest {
            capability_id: "nonexistent".to_string(),
            arguments: json!({}),
        };
        assert_eq!(edge.evaluate_permission(&request), PermissionDecision::Deny);
    }

    #[test]
    fn permission_not_required_when_config_disabled() {
        let config = AcpEdgeConfig {
            require_permission: false,
            default_category: AcpCategory::Tool,
        };
        let edge = ArcAcpEdge::new(config, vec![test_manifest()]).unwrap();
        // read_file has no side effects and require_permission is false
        let cap = edge.capability("read_file").unwrap();
        assert!(!cap.requires_permission);
    }

    // ---- Invocation tests ----

    #[test]
    fn invoke_succeeds() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let result = edge
            .invoke("read_file", json!({"path": "/tmp"}), &server)
            .unwrap();
        assert!(result.success);
        assert_eq!(result.data["result"], "ok");
    }

    #[test]
    fn invoke_unknown_tool_errors() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let err = edge.invoke("nonexistent", json!({}), &server).unwrap_err();
        assert!(matches!(err, AcpEdgeError::ToolNotFound(_)));
    }

    #[test]
    fn invoke_server_failure_returns_unsuccessful() {
        let manifest = ToolManifest {
            schema: "arc.manifest.v1".to_string(),
            server_id: "fail-srv".to_string(),
            name: "Fail".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "fail_tool".to_string(),
                description: "Fails".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            required_permissions: None,
            public_key: "aabb".to_string(),
        };
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![manifest]).unwrap();
        let server = FailingToolServer;
        let result = edge.invoke("fail_tool", json!({}), &server).unwrap();
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    // ---- JSON-RPC handler tests ----

    #[test]
    fn jsonrpc_list_capabilities() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "session/list_capabilities",
                "params": {}
            }),
            &server,
        );
        let caps = response["result"]["capabilities"].as_array().unwrap();
        assert_eq!(caps.len(), 4);
    }

    #[test]
    fn jsonrpc_request_permission() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "session/request_permission",
                "params": {
                    "capabilityId": "read_file",
                    "arguments": {"path": "/tmp"}
                }
            }),
            &server,
        );
        assert!(response.get("result").is_some());
    }

    #[test]
    fn jsonrpc_tool_invoke() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tool/invoke",
                "params": {
                    "capabilityId": "search",
                    "arguments": {"query": "test"}
                }
            }),
            &server,
        );
        assert!(response["result"]["success"].as_bool().unwrap_or(false));
    }

    #[test]
    fn jsonrpc_unknown_method() {
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "unknown/method",
                "params": {}
            }),
            &server,
        );
        assert_eq!(response["error"]["code"], -32601);
    }

    // ---- Deduplication tests ----

    #[test]
    fn duplicate_tools_across_manifests_deduplicated() {
        let m1 = test_manifest();
        let m2 = test_manifest();
        let edge = ArcAcpEdge::new(AcpEdgeConfig::default(), vec![m1, m2]).unwrap();
        assert_eq!(edge.capabilities().len(), 4);
    }

    // ---- Error display tests ----

    #[test]
    fn error_display_tool_not_found() {
        let err = AcpEdgeError::ToolNotFound("x".into());
        assert!(format!("{err}").contains("x"));
    }

    #[test]
    fn error_display_access_denied() {
        let err = AcpEdgeError::AccessDenied("no cap".into());
        assert!(format!("{err}").contains("no cap"));
    }

    #[test]
    fn error_display_kernel() {
        let err = AcpEdgeError::Kernel("internal".into());
        assert!(format!("{err}").contains("internal"));
    }

    // ---- Serde tests ----

    #[test]
    fn bridge_fidelity_serializes() {
        assert_eq!(serde_json::to_value(BridgeFidelity::Full).unwrap(), "full");
        assert_eq!(
            serde_json::to_value(BridgeFidelity::Partial).unwrap(),
            "partial"
        );
        assert_eq!(
            serde_json::to_value(BridgeFidelity::Degraded).unwrap(),
            "degraded"
        );
    }

    #[test]
    fn acp_category_serializes() {
        assert_eq!(serde_json::to_value(AcpCategory::Tool).unwrap(), "tool");
        assert_eq!(
            serde_json::to_value(AcpCategory::Filesystem).unwrap(),
            "filesystem"
        );
        assert_eq!(
            serde_json::to_value(AcpCategory::Terminal).unwrap(),
            "terminal"
        );
        assert_eq!(
            serde_json::to_value(AcpCategory::Browser).unwrap(),
            "browser"
        );
    }

    #[test]
    fn permission_decision_serializes() {
        assert_eq!(
            serde_json::to_value(PermissionDecision::Allow).unwrap(),
            "allow"
        );
        assert_eq!(
            serde_json::to_value(PermissionDecision::Deny).unwrap(),
            "deny"
        );
    }

    // ---- Default config tests ----

    #[test]
    fn default_config_requires_permission() {
        let config = AcpEdgeConfig::default();
        assert!(config.require_permission);
        assert_eq!(config.default_category, AcpCategory::Tool);
    }
}
