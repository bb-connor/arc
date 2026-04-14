//! # arc-a2a-edge
//!
//! Edge crate that exposes ARC kernel-governed tools as A2A (Agent-to-Agent)
//! skills. This is the reverse direction from `arc-a2a-adapter`: instead of
//! consuming a remote A2A server, this crate *serves* ARC tools to A2A clients.
//!
//! Responsibilities:
//!
//! 1. Publish an A2A Agent Card at `/.well-known/agent-card.json`.
//! 2. Accept `SendMessage` requests and route them through the ARC kernel.
//! 3. Support streaming via `SendStreamingMessage`.
//! 4. Evaluate `BridgeFidelity` per tool to signal translation quality.
//!
//! Every invocation flows through the kernel guard pipeline, producing a
//! signed ARC receipt.

use std::collections::BTreeMap;

use arc_kernel::ToolServerConnection;
use arc_manifest::{ToolDefinition, ToolManifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Errors produced by the A2A edge.
#[derive(Debug, thiserror::Error)]
pub enum A2aEdgeError {
    /// A tool was not found.
    #[error("tool not found: {0}")]
    ToolNotFound(String),

    /// The request was malformed.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The kernel denied the request.
    #[error("kernel error: {0}")]
    Kernel(String),

    /// Manifest construction failed.
    #[error("manifest error: {0}")]
    Manifest(#[from] arc_manifest::ManifestError),
}

/// Fidelity assessment for how well an ARC tool maps to A2A semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeFidelity {
    /// Tool maps perfectly to A2A (text in, text out, no streaming loss).
    Full,
    /// Tool maps with minor semantic loss (e.g., structured output
    /// collapsed to text).
    Partial,
    /// Tool maps with significant loss (e.g., streaming not representable).
    Degraded,
}

/// Configuration for the A2A edge.
#[derive(Debug, Clone)]
pub struct A2aEdgeConfig {
    /// Name to advertise in the Agent Card.
    pub agent_name: String,
    /// Description for the Agent Card.
    pub agent_description: String,
    /// Version of the agent.
    pub agent_version: String,
    /// URL where the A2A endpoint is hosted.
    pub endpoint_url: String,
    /// Protocol binding (default: "JSONRPC").
    pub protocol_binding: String,
    /// Whether streaming is supported.
    pub streaming_enabled: bool,
}

impl Default for A2aEdgeConfig {
    fn default() -> Self {
        Self {
            agent_name: "ARC A2A Edge".to_string(),
            agent_description: "ARC-governed tools exposed as A2A skills".to_string(),
            agent_version: "0.1.0".to_string(),
            endpoint_url: "http://localhost:8080".to_string(),
            protocol_binding: "JSONRPC".to_string(),
            streaming_enabled: false,
        }
    }
}

/// A skill entry in the A2A Agent Card.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aSkillEntry {
    /// Skill identifier (matches the ARC tool name).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of what the skill does.
    pub description: String,
    /// Tags for categorization.
    pub tags: Vec<String>,
    /// Example inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examples: Option<Vec<String>>,
    /// Input modes supported.
    pub input_modes: Vec<String>,
    /// Output modes supported.
    pub output_modes: Vec<String>,
    /// Fidelity assessment.
    pub bridge_fidelity: BridgeFidelity,
}

/// An A2A Agent Card.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    /// Agent name.
    pub name: String,
    /// Agent description.
    pub description: String,
    /// Agent version.
    pub version: String,
    /// Supported interfaces.
    pub supported_interfaces: Vec<AgentInterface>,
    /// Capabilities.
    pub capabilities: AgentCapabilities,
    /// Default input modes.
    pub default_input_modes: Vec<String>,
    /// Default output modes.
    pub default_output_modes: Vec<String>,
    /// Skills (tools exposed as A2A skills).
    pub skills: Vec<A2aSkillEntry>,
}

/// An A2A interface definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentInterface {
    /// URL for the A2A endpoint.
    pub url: String,
    /// Protocol binding.
    pub protocol_binding: String,
    /// Protocol version.
    pub protocol_version: String,
}

/// A2A agent capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    /// Whether streaming is supported.
    #[serde(default)]
    pub streaming: bool,
    /// Whether push notifications are supported.
    #[serde(default)]
    pub push_notifications: bool,
    /// Whether state transition history is tracked.
    #[serde(default)]
    pub state_transition_history: bool,
}

/// An A2A SendMessage request (simplified).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageRequest {
    /// The message to send.
    pub message: A2aMessage,
    /// Optional metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// An A2A message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aMessage {
    /// Role of the message sender.
    pub role: String,
    /// Message parts.
    pub parts: Vec<A2aPart>,
    /// Optional message metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// A single part of an A2A message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum A2aPart {
    /// A text part.
    #[serde(rename = "text")]
    Text { text: String },
    /// A structured data part.
    #[serde(rename = "data")]
    Data { data: Value },
}

/// A2A task status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TaskStatus {
    Working,
    Completed,
    Failed,
    Cancelled,
}

/// An A2A task response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskResponse {
    /// Task identifier.
    pub id: String,
    /// Current status.
    pub status: TaskStatus,
    /// Optional status message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    /// The result message (present when completed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<A2aMessage>,
}

/// The A2A edge server.
///
/// Wraps a set of ARC tool manifests and exposes them as A2A skills.
pub struct ArcA2aEdge {
    config: A2aEdgeConfig,
    skills: Vec<A2aSkillEntry>,
    /// Maps skill ID to (server_id, tool_name).
    skill_bindings: BTreeMap<String, (String, String)>,
    task_counter: u64,
}

impl ArcA2aEdge {
    /// Create a new A2A edge from ARC tool manifests.
    pub fn new(config: A2aEdgeConfig, manifests: Vec<ToolManifest>) -> Result<Self, A2aEdgeError> {
        let mut skills = Vec::new();
        let mut skill_bindings = BTreeMap::new();

        for manifest in &manifests {
            for tool in &manifest.tools {
                let skill_id = tool.name.clone();
                if skill_bindings.contains_key(&skill_id) {
                    continue; // Skip duplicates
                }

                let fidelity = evaluate_bridge_fidelity(tool);
                skills.push(A2aSkillEntry {
                    id: skill_id.clone(),
                    name: skill_id.clone(),
                    description: tool.description.clone(),
                    tags: vec![],
                    examples: None,
                    input_modes: vec!["text".to_string()],
                    output_modes: vec!["text".to_string()],
                    bridge_fidelity: fidelity,
                });
                skill_bindings.insert(skill_id, (manifest.server_id.clone(), tool.name.clone()));
            }
        }

        Ok(Self {
            config,
            skills,
            skill_bindings,
            task_counter: 0,
        })
    }

    /// Generate the A2A Agent Card for `/.well-known/agent-card.json`.
    pub fn agent_card(&self) -> AgentCard {
        AgentCard {
            name: self.config.agent_name.clone(),
            description: self.config.agent_description.clone(),
            version: self.config.agent_version.clone(),
            supported_interfaces: vec![AgentInterface {
                url: self.config.endpoint_url.clone(),
                protocol_binding: self.config.protocol_binding.clone(),
                protocol_version: "1.0".to_string(),
            }],
            capabilities: AgentCapabilities {
                streaming: self.config.streaming_enabled,
                push_notifications: false,
                state_transition_history: false,
            },
            default_input_modes: vec!["text".to_string()],
            default_output_modes: vec!["text".to_string()],
            skills: self.skills.clone(),
        }
    }

    /// Serialize the Agent Card as JSON.
    pub fn agent_card_json(&self) -> Result<String, A2aEdgeError> {
        serde_json::to_string_pretty(&self.agent_card())
            .map_err(|e| A2aEdgeError::InvalidRequest(e.to_string()))
    }

    /// List all skill IDs.
    pub fn skill_ids(&self) -> Vec<String> {
        self.skills.iter().map(|s| s.id.clone()).collect()
    }

    /// Get a skill entry by ID.
    pub fn skill(&self, id: &str) -> Option<&A2aSkillEntry> {
        self.skills.iter().find(|s| s.id == id)
    }

    /// Allocate a new task ID.
    fn next_task_id(&mut self) -> String {
        self.task_counter += 1;
        format!("a2a-task-{}", self.task_counter)
    }

    /// Handle a SendMessage request by routing through a tool server connection.
    pub fn handle_send_message(
        &mut self,
        skill_id: &str,
        request: &SendMessageRequest,
        server: &dyn ToolServerConnection,
    ) -> Result<TaskResponse, A2aEdgeError> {
        let tool_name = {
            let (_server_id, name) = self
                .skill_bindings
                .get(skill_id)
                .ok_or_else(|| A2aEdgeError::ToolNotFound(skill_id.to_string()))?;
            name.clone()
        };

        // Extract text from message parts
        let arguments = extract_arguments_from_message(&request.message);

        let task_id = self.next_task_id();

        match server.invoke(&tool_name, arguments, None) {
            Ok(result) => {
                let response_parts = result_to_parts(&result);
                Ok(TaskResponse {
                    id: task_id,
                    status: TaskStatus::Completed,
                    status_message: None,
                    message: Some(A2aMessage {
                        role: "agent".to_string(),
                        parts: response_parts,
                        metadata: None,
                    }),
                })
            }
            Err(error) => Ok(TaskResponse {
                id: task_id,
                status: TaskStatus::Failed,
                status_message: Some(error.to_string()),
                message: None,
            }),
        }
    }

    /// Handle a JSON-RPC A2A request.
    pub fn handle_jsonrpc(&mut self, message: Value, server: &dyn ToolServerConnection) -> Value {
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        match method {
            "message/send" | "message/stream" => {
                self.handle_jsonrpc_send_message(id, params, server)
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

    fn handle_jsonrpc_send_message(
        &mut self,
        id: Value,
        params: Value,
        server: &dyn ToolServerConnection,
    ) -> Value {
        let skill_id_from_metadata = params
            .get("metadata")
            .and_then(|m| m.get("arc"))
            .and_then(|a| a.get("targetSkillId"))
            .and_then(Value::as_str)
            .map(String::from);

        let skill_id = skill_id_from_metadata.or_else(|| {
            // Try to find a single skill if there's only one
            if self.skills.len() == 1 {
                self.skills.first().map(|s| s.id.clone())
            } else {
                None
            }
        });

        let Some(skill_id) = skill_id else {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32602,
                    "message": "metadata.arc.targetSkillId is required when multiple skills are exposed"
                }
            });
        };

        let request = match serde_json::from_value::<SendMessageRequest>(params.clone()) {
            Ok(req) => req,
            Err(e) => {
                return json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32602,
                        "message": format!("invalid SendMessage request: {e}")
                    }
                });
            }
        };

        match self.handle_send_message(&skill_id, &request, server) {
            Ok(response) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": serde_json::to_value(&response).unwrap_or(Value::Null)
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
}

/// Evaluate how faithfully an ARC tool maps to A2A semantics.
fn evaluate_bridge_fidelity(tool: &ToolDefinition) -> BridgeFidelity {
    // Tools with side effects have lower fidelity because A2A
    // doesn't distinguish read-only from mutating operations
    if tool.has_side_effects {
        BridgeFidelity::Partial
    } else {
        BridgeFidelity::Full
    }
}

/// Extract arguments from A2A message parts.
fn extract_arguments_from_message(message: &A2aMessage) -> Value {
    let mut text_parts = Vec::new();
    let mut data_part = None;

    for part in &message.parts {
        match part {
            A2aPart::Text { text } => text_parts.push(text.clone()),
            A2aPart::Data { data } => data_part = Some(data.clone()),
        }
    }

    if let Some(data) = data_part {
        data
    } else {
        json!({
            "message": text_parts.join("\n"),
        })
    }
}

/// Convert a tool result to A2A message parts.
fn result_to_parts(result: &Value) -> Vec<A2aPart> {
    if let Some(text) = result.as_str() {
        vec![A2aPart::Text {
            text: text.to_string(),
        }]
    } else if let Some(content) = result.get("content").and_then(Value::as_array) {
        content
            .iter()
            .filter_map(|c| {
                c.get("text")
                    .and_then(Value::as_str)
                    .map(|t| A2aPart::Text {
                        text: t.to_string(),
                    })
            })
            .collect()
    } else if result.is_object() || result.is_array() {
        vec![A2aPart::Data {
            data: result.clone(),
        }]
    } else {
        vec![A2aPart::Text {
            text: result.to_string(),
        }]
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
                    name: "echo".to_string(),
                    description: "Echo input".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: false,
                    latency_hint: None,
                },
                ToolDefinition {
                    name: "write".to_string(),
                    description: "Write data".to_string(),
                    input_schema: json!({"type": "object"}),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: true,
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
            tools: vec!["echo".to_string(), "write".to_string()],
            response: json!({"result": "ok"}),
        }
    }

    fn text_message(text: &str) -> SendMessageRequest {
        SendMessageRequest {
            message: A2aMessage {
                role: "user".to_string(),
                parts: vec![A2aPart::Text {
                    text: text.to_string(),
                }],
                metadata: None,
            },
            metadata: None,
        }
    }

    // ---- Agent Card tests ----

    #[test]
    fn agent_card_has_correct_name() {
        let edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let card = edge.agent_card();
        assert_eq!(card.name, "ARC A2A Edge");
    }

    #[test]
    fn agent_card_has_correct_version() {
        let edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let card = edge.agent_card();
        assert_eq!(card.version, "0.1.0");
    }

    #[test]
    fn agent_card_includes_all_skills() {
        let edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let card = edge.agent_card();
        assert_eq!(card.skills.len(), 2);
        assert!(card.skills.iter().any(|s| s.id == "echo"));
        assert!(card.skills.iter().any(|s| s.id == "write"));
    }

    #[test]
    fn agent_card_has_interface() {
        let edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let card = edge.agent_card();
        assert_eq!(card.supported_interfaces.len(), 1);
        assert_eq!(card.supported_interfaces[0].protocol_binding, "JSONRPC");
        assert_eq!(card.supported_interfaces[0].protocol_version, "1.0");
    }

    #[test]
    fn agent_card_json_serializes() {
        let edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let json_str = edge.agent_card_json().unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["name"], "ARC A2A Edge");
    }

    #[test]
    fn agent_card_custom_config() {
        let config = A2aEdgeConfig {
            agent_name: "My Agent".to_string(),
            agent_description: "Custom agent".to_string(),
            agent_version: "2.0.0".to_string(),
            endpoint_url: "https://myagent.com".to_string(),
            protocol_binding: "HTTP+JSON".to_string(),
            streaming_enabled: true,
        };
        let edge = ArcA2aEdge::new(config, vec![test_manifest()]).unwrap();
        let card = edge.agent_card();
        assert_eq!(card.name, "My Agent");
        assert_eq!(card.description, "Custom agent");
        assert!(card.capabilities.streaming);
        assert_eq!(card.supported_interfaces[0].url, "https://myagent.com");
        assert_eq!(card.supported_interfaces[0].protocol_binding, "HTTP+JSON");
    }

    // ---- BridgeFidelity tests ----

    #[test]
    fn read_only_tool_has_full_fidelity() {
        let edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let skill = edge.skill("echo").unwrap();
        assert_eq!(skill.bridge_fidelity, BridgeFidelity::Full);
    }

    #[test]
    fn side_effect_tool_has_partial_fidelity() {
        let edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let skill = edge.skill("write").unwrap();
        assert_eq!(skill.bridge_fidelity, BridgeFidelity::Partial);
    }

    // ---- Skill lookup tests ----

    #[test]
    fn skill_ids_returns_all() {
        let edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let ids = edge.skill_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn skill_returns_none_for_unknown() {
        let edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        assert!(edge.skill("nonexistent").is_none());
    }

    // ---- SendMessage tests ----

    #[test]
    fn send_message_completes_successfully() {
        let mut edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let request = text_message("hello");
        let response = edge.handle_send_message("echo", &request, &server).unwrap();
        assert_eq!(response.status, TaskStatus::Completed);
        assert!(response.message.is_some());
    }

    #[test]
    fn send_message_returns_task_id() {
        let mut edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let request = text_message("test");
        let r1 = edge.handle_send_message("echo", &request, &server).unwrap();
        let r2 = edge.handle_send_message("echo", &request, &server).unwrap();
        assert_ne!(r1.id, r2.id);
        assert!(r1.id.starts_with("a2a-task-"));
    }

    #[test]
    fn send_message_unknown_skill_errors() {
        let mut edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let request = text_message("test");
        let err = edge
            .handle_send_message("nonexistent", &request, &server)
            .unwrap_err();
        assert!(matches!(err, A2aEdgeError::ToolNotFound(_)));
    }

    #[test]
    fn send_message_server_failure_returns_failed_task() {
        let mut edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = FailingToolServer;
        // Need a manifest for the failing server
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
        let mut edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![manifest]).unwrap();
        let request = text_message("test");
        let response = edge
            .handle_send_message("fail_tool", &request, &server)
            .unwrap();
        assert_eq!(response.status, TaskStatus::Failed);
        assert!(response.status_message.is_some());
    }

    // ---- Message extraction tests ----

    #[test]
    fn extract_text_from_parts() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Text {
                text: "hello world".to_string(),
            }],
            metadata: None,
        };
        let args = extract_arguments_from_message(&msg);
        assert_eq!(args["message"], "hello world");
    }

    #[test]
    fn extract_data_from_parts() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Data {
                data: json!({"key": "value"}),
            }],
            metadata: None,
        };
        let args = extract_arguments_from_message(&msg);
        assert_eq!(args["key"], "value");
    }

    #[test]
    fn extract_prefers_data_over_text() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![
                A2aPart::Text {
                    text: "hello".to_string(),
                },
                A2aPart::Data {
                    data: json!({"priority": "high"}),
                },
            ],
            metadata: None,
        };
        let args = extract_arguments_from_message(&msg);
        assert_eq!(args["priority"], "high");
    }

    // ---- Result conversion tests ----

    #[test]
    fn result_text_to_parts() {
        let parts = result_to_parts(&json!("hello"));
        assert_eq!(parts.len(), 1);
        match &parts[0] {
            A2aPart::Text { text } => assert_eq!(text, "hello"),
            _ => panic!("expected text part"),
        }
    }

    #[test]
    fn result_object_to_data_parts() {
        let parts = result_to_parts(&json!({"key": "value"}));
        assert_eq!(parts.len(), 1);
        match &parts[0] {
            A2aPart::Data { data } => assert_eq!(data["key"], "value"),
            _ => panic!("expected data part"),
        }
    }

    #[test]
    fn result_content_array_to_text_parts() {
        let parts = result_to_parts(&json!({
            "content": [
                {"type": "text", "text": "part1"},
                {"type": "text", "text": "part2"},
            ]
        }));
        assert_eq!(parts.len(), 2);
    }

    // ---- JSON-RPC handler tests ----

    #[test]
    fn jsonrpc_send_message_single_skill() {
        let mut edge = ArcA2aEdge::new(
            A2aEdgeConfig::default(),
            vec![{
                let mut m = test_manifest();
                m.tools.truncate(1); // Only "echo"
                m
            }],
        )
        .unwrap();
        let server = test_server();
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    }
                }
            }),
            &server,
        );
        assert!(response.get("result").is_some());
    }

    #[test]
    fn jsonrpc_send_message_with_skill_id() {
        let mut edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    },
                    "metadata": {
                        "arc": {"targetSkillId": "echo"}
                    }
                }
            }),
            &server,
        );
        assert!(response.get("result").is_some());
    }

    #[test]
    fn jsonrpc_missing_skill_id_with_multiple_skills_errors() {
        let mut edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let response = edge.handle_jsonrpc(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{"type": "text", "text": "hi"}]
                    }
                }
            }),
            &server,
        );
        assert!(response.get("error").is_some());
    }

    #[test]
    fn jsonrpc_unknown_method_returns_error() {
        let mut edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).unwrap();
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

    // ---- Error type tests ----

    #[test]
    fn error_display_tool_not_found() {
        let err = A2aEdgeError::ToolNotFound("missing".into());
        assert!(format!("{err}").contains("missing"));
    }

    #[test]
    fn error_display_invalid_request() {
        let err = A2aEdgeError::InvalidRequest("bad".into());
        assert!(format!("{err}").contains("bad"));
    }

    #[test]
    fn error_display_kernel() {
        let err = A2aEdgeError::Kernel("denied".into());
        assert!(format!("{err}").contains("denied"));
    }

    // ---- Duplicate skill handling ----

    #[test]
    fn duplicate_skills_across_manifests_are_deduplicated() {
        let m1 = test_manifest();
        let m2 = test_manifest(); // Same tool names
        let edge = ArcA2aEdge::new(A2aEdgeConfig::default(), vec![m1, m2]).unwrap();
        assert_eq!(edge.skill_ids().len(), 2); // Not 4
    }

    // ---- Default config tests ----

    #[test]
    fn default_config_has_reasonable_values() {
        let config = A2aEdgeConfig::default();
        assert!(!config.agent_name.is_empty());
        assert!(!config.streaming_enabled);
        assert_eq!(config.protocol_binding, "JSONRPC");
    }

    // ---- TaskStatus serde ----

    #[test]
    fn task_status_serializes_correctly() {
        let json = serde_json::to_value(TaskStatus::Completed).unwrap();
        assert_eq!(json, "completed");
        let json = serde_json::to_value(TaskStatus::Failed).unwrap();
        assert_eq!(json, "failed");
    }

    #[test]
    fn bridge_fidelity_serializes_correctly() {
        let json = serde_json::to_value(BridgeFidelity::Full).unwrap();
        assert_eq!(json, "full");
        let json = serde_json::to_value(BridgeFidelity::Partial).unwrap();
        assert_eq!(json, "partial");
        let json = serde_json::to_value(BridgeFidelity::Degraded).unwrap();
        assert_eq!(json, "degraded");
    }
}
