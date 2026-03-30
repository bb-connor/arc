//! # arc-mcp-adapter
//!
//! Compatibility adapter that wraps an existing MCP (Model Context Protocol)
//! server and exposes it as a ARC tool server. This allows incremental
//! migration: existing MCP tools continue to work, but gain the security
//! properties of ARC (capability tokens, guard evaluation, signed receipts).
//!
//! The adapter:
//!
//! 1. Reads the MCP server's tool list (via `tools/list`) and generates a
//!    ARC `ToolManifest`.
//! 2. Translates incoming ARC `ToolCallRequest` messages into MCP
//!    `tools/call` requests.
//! 3. Translates MCP responses back into ARC `ToolCallResponse` format.
//!
//! The MCP server itself runs in a sandboxed subprocess. The adapter sits
//! between the ARC kernel and the MCP server, providing the security
//! boundary that MCP lacks.

use std::sync::{Arc, Mutex};

use arc_core::session::CreateElicitationOperation;
use arc_core::{
    CompletionResult, PromptDefinition, PromptResult, ResourceContent, ResourceDefinition,
    ResourceTemplateDefinition, ServerId,
};
use arc_kernel::{
    KernelError, NestedFlowBridge, PromptProvider, ResourceProvider, ToolServerConnection,
};
use arc_manifest::{ToolDefinition, ToolManifest};
use tracing::warn;

pub mod edge {
    pub use arc_mcp_edge::{ArcMcpEdge, McpEdgeConfig, McpExposedTool};
}
pub mod native;
pub mod transport;

pub use arc_mcp_edge::{
    AdapterError, ArcMcpEdge, McpEdgeConfig, McpExposedTool, McpServerCapabilities, McpToolInfo,
    McpToolResult, McpTransport,
};
#[allow(deprecated)]
pub use native::{
    NativeArcService, NativeArcServiceBuilder, NativePactService, NativePactServiceBuilder,
    NativePrompt, NativeResource, NativeTool,
};
pub use transport::StdioMcpTransport;

/// Configuration for the MCP adapter.
#[derive(Clone)]
pub struct McpAdapterConfig {
    /// Server ID to assign to the wrapped MCP server.
    pub server_id: ServerId,

    /// Human-readable name for the adapted server.
    pub server_name: String,

    /// Version string for the adapted server.
    pub server_version: String,

    /// Hex-encoded Ed25519 public key for the manifest.
    pub public_key: String,
}

/// Adapter that wraps an MCP server as a ARC tool server.
///
/// Usage:
///
/// ```ignore
/// let transport = StdioMcpTransport::spawn("npx", &["-y", "some-mcp-server"]);
/// let config = McpAdapterConfig { /* ... */ };
/// let adapter = McpAdapter::new(config, Box::new(transport));
/// let manifest = adapter.generate_manifest()?;
/// let result = adapter.invoke("read_file", json!({"path": "/tmp/test.txt"}))?;
/// ```
#[derive(Clone)]
pub struct McpAdapter {
    config: McpAdapterConfig,
    transport: Arc<dyn McpTransport>,
}

/// A ARC tool-server connection backed by a wrapped MCP server.
#[derive(Clone)]
pub struct AdaptedMcpServer {
    adapter: McpAdapter,
    manifest: ToolManifest,
}

pub struct AdaptedMcpResourceProvider {
    adapter: McpAdapter,
}

pub struct AdaptedMcpPromptProvider {
    adapter: McpAdapter,
}

/// Transport wrapper that serializes upstream MCP calls through one shared gate.
///
/// This is useful when multiple ARC sessions need to share a single wrapped
/// MCP transport without tripping the transport's single-active-request guard.
pub struct SerializedMcpTransport {
    inner: Arc<dyn McpTransport>,
    request_gate: Mutex<()>,
}

impl SerializedMcpTransport {
    pub fn from_arc(inner: Arc<dyn McpTransport>) -> Self {
        Self {
            inner,
            request_gate: Mutex::new(()),
        }
    }

    fn with_request_gate<T>(
        &self,
        action: impl FnOnce(&dyn McpTransport) -> Result<T, AdapterError>,
    ) -> Result<T, AdapterError> {
        let _guard = self.request_gate.lock().map_err(|error| {
            AdapterError::ConnectionFailed(format!("shared MCP transport gate poisoned: {error}"))
        })?;
        action(self.inner.as_ref())
    }
}

impl McpTransport for SerializedMcpTransport {
    fn capabilities(&self) -> McpServerCapabilities {
        self.inner.capabilities()
    }

    fn list_tools(&self) -> Result<Vec<McpToolInfo>, AdapterError> {
        self.with_request_gate(|inner| inner.list_tools())
    }

    fn call_tool(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<McpToolResult, AdapterError> {
        self.with_request_gate(|inner| inner.call_tool(tool_name, arguments))
    }

    fn call_tool_with_nested_flow(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<McpToolResult, AdapterError> {
        self.with_request_gate(|inner| {
            inner.call_tool_with_nested_flow(tool_name, arguments, nested_flow_bridge)
        })
    }

    fn list_resources(&self) -> Result<Vec<ResourceDefinition>, AdapterError> {
        self.with_request_gate(|inner| inner.list_resources())
    }

    fn list_resource_templates(&self) -> Result<Vec<ResourceTemplateDefinition>, AdapterError> {
        self.with_request_gate(|inner| inner.list_resource_templates())
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, AdapterError> {
        self.with_request_gate(|inner| inner.read_resource(uri))
    }

    fn list_prompts(&self) -> Result<Vec<PromptDefinition>, AdapterError> {
        self.with_request_gate(|inner| inner.list_prompts())
    }

    fn get_prompt(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, AdapterError> {
        self.with_request_gate(|inner| inner.get_prompt(name, arguments))
    }

    fn complete_prompt_argument(
        &self,
        name: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        self.with_request_gate(|inner| {
            inner.complete_prompt_argument(name, argument_name, value, context)
        })
    }

    fn complete_resource_argument(
        &self,
        uri: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        self.with_request_gate(|inner| {
            inner.complete_resource_argument(uri, argument_name, value, context)
        })
    }

    fn drain_notifications(&self) -> Vec<serde_json::Value> {
        self.inner.drain_notifications()
    }
}

impl McpAdapter {
    pub fn new(config: McpAdapterConfig, transport: Box<dyn McpTransport>) -> Self {
        Self {
            config,
            transport: Arc::from(transport),
        }
    }

    /// Create an adapter that spawns an MCP server as a subprocess.
    ///
    /// This is a convenience constructor that creates a [`StdioMcpTransport`]
    /// and wraps it in an `McpAdapter`. The MCP server is spawned immediately
    /// and the `initialize` handshake is performed before this returns.
    pub fn from_command(
        command: &str,
        args: &[&str],
        config: McpAdapterConfig,
    ) -> Result<Self, AdapterError> {
        let transport = StdioMcpTransport::spawn(command, args)?;
        Ok(Self::new(config, Box::new(transport)))
    }

    /// Query the MCP server for its tool list and generate a ARC manifest.
    ///
    /// Each MCP tool becomes a `ToolDefinition` in the manifest. Since MCP
    /// tools provide no side-effect metadata, all adapted tools are marked
    /// `has_side_effects: true` (fail-closed).
    pub fn generate_manifest(&self) -> Result<ToolManifest, AdapterError> {
        let mcp_tools = self.transport.list_tools()?;

        let tools: Vec<ToolDefinition> = mcp_tools
            .into_iter()
            .map(|t| ToolDefinition {
                name: t.name,
                description: t.description.unwrap_or_default(),
                input_schema: t.input_schema,
                output_schema: t.output_schema,
                pricing: None,
                has_side_effects: infer_has_side_effects(t.annotations.as_ref()),
                latency_hint: None,
            })
            .collect();

        let manifest = ToolManifest {
            schema: "arc.manifest.v1".into(),
            server_id: self.config.server_id.clone(),
            name: self.config.server_name.clone(),
            description: Some("MCP server adapted to ARC protocol".into()),
            version: self.config.server_version.clone(),
            tools,
            required_permissions: None,
            public_key: self.config.public_key.clone(),
        };

        arc_manifest::validate_manifest(&manifest)?;
        Ok(manifest)
    }

    pub fn capabilities(&self) -> McpServerCapabilities {
        self.transport.capabilities()
    }

    /// Invoke a tool on the wrapped MCP server.
    ///
    /// This translates the ARC-style call into an MCP `tools/call` request
    /// and converts the response back.
    pub fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, AdapterError> {
        self.invoke_with_nested_flow(tool_name, arguments, None)
    }

    pub fn invoke_with_nested_flow(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, AdapterError> {
        let result =
            self.transport
                .call_tool_with_nested_flow(tool_name, arguments, nested_flow_bridge)?;

        let mut output = serde_json::Map::new();
        output.insert(
            "content".to_string(),
            serde_json::Value::Array(result.content),
        );
        if let Some(structured_content) = result.structured_content {
            output.insert("structuredContent".to_string(), structured_content);
        }
        if let Some(is_error) = result.is_error {
            output.insert("isError".to_string(), serde_json::Value::Bool(is_error));
        }

        Ok(serde_json::Value::Object(output))
    }

    pub fn list_resources(&self) -> Result<Vec<ResourceDefinition>, AdapterError> {
        self.transport.list_resources()
    }

    pub fn list_resource_templates(&self) -> Result<Vec<ResourceTemplateDefinition>, AdapterError> {
        self.transport.list_resource_templates()
    }

    pub fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, AdapterError> {
        self.transport.read_resource(uri)
    }

    pub fn list_prompts(&self) -> Result<Vec<PromptDefinition>, AdapterError> {
        self.transport.list_prompts()
    }

    pub fn get_prompt(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, AdapterError> {
        self.transport.get_prompt(name, arguments)
    }

    pub fn complete_prompt_argument(
        &self,
        name: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        self.transport
            .complete_prompt_argument(name, argument_name, value, context)
    }

    pub fn complete_resource_argument(
        &self,
        uri: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        self.transport
            .complete_resource_argument(uri, argument_name, value, context)
    }
}

impl AdaptedMcpServer {
    pub fn new(adapter: McpAdapter) -> Result<Self, AdapterError> {
        let manifest = adapter.generate_manifest()?;
        Ok(Self { adapter, manifest })
    }

    pub fn from_command(
        command: &str,
        args: &[&str],
        config: McpAdapterConfig,
    ) -> Result<Self, AdapterError> {
        Self::new(McpAdapter::from_command(command, args, config)?)
    }

    pub fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }

    pub fn manifest_clone(&self) -> ToolManifest {
        self.manifest.clone()
    }

    pub fn upstream_capabilities(&self) -> McpServerCapabilities {
        self.adapter.capabilities()
    }

    pub fn notification_source(&self) -> Arc<dyn McpTransport> {
        self.adapter.transport.clone()
    }

    pub fn resource_provider(&self) -> Option<AdaptedMcpResourceProvider> {
        self.upstream_capabilities()
            .resources_supported
            .then(|| AdaptedMcpResourceProvider {
                adapter: self.adapter.clone(),
            })
    }

    pub fn prompt_provider(&self) -> Option<AdaptedMcpPromptProvider> {
        self.upstream_capabilities()
            .prompts_supported
            .then(|| AdaptedMcpPromptProvider {
                adapter: self.adapter.clone(),
            })
    }
}

impl ToolServerConnection for AdaptedMcpServer {
    fn server_id(&self) -> &str {
        &self.manifest.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.manifest
            .tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect()
    }

    fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.adapter
            .invoke_with_nested_flow(tool_name, arguments, nested_flow_bridge)
            .map_err(map_tool_invocation_error)
    }
}

impl ResourceProvider for AdaptedMcpResourceProvider {
    fn list_resources(&self) -> Vec<ResourceDefinition> {
        self.adapter.list_resources().unwrap_or_else(|error| {
            warn!(error = %error, "wrapped MCP resources/list failed");
            vec![]
        })
    }

    fn list_resource_templates(&self) -> Vec<ResourceTemplateDefinition> {
        self.adapter
            .list_resource_templates()
            .unwrap_or_else(|error| {
                warn!(error = %error, "wrapped MCP resources/templates/list failed");
                vec![]
            })
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
        self.adapter
            .read_resource(uri)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))
    }

    fn complete_resource_argument(
        &self,
        uri: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        self.adapter
            .complete_resource_argument(uri, argument_name, value, context)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))
    }
}

impl PromptProvider for AdaptedMcpPromptProvider {
    fn list_prompts(&self) -> Vec<PromptDefinition> {
        self.adapter.list_prompts().unwrap_or_else(|error| {
            warn!(error = %error, "wrapped MCP prompts/list failed");
            vec![]
        })
    }

    fn get_prompt(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, KernelError> {
        self.adapter
            .get_prompt(name, arguments)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))
    }

    fn complete_prompt_argument(
        &self,
        name: &str,
        argument_name: &str,
        value: &str,
        context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        self.adapter
            .complete_prompt_argument(name, argument_name, value, context)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))
    }
}

fn map_tool_invocation_error(error: AdapterError) -> KernelError {
    match error {
        AdapterError::RequestCancelled { request_id, reason } => {
            KernelError::RequestCancelled { request_id, reason }
        }
        AdapterError::McpError {
            code: -32042,
            message,
            data,
        } => match parse_url_elicitation_required_error(message, data) {
            Ok(error) => error,
            Err(message) => KernelError::ToolServerError(message),
        },
        AdapterError::ConnectionFailed(message) | AdapterError::ParseError(message) => {
            KernelError::RequestIncomplete(message)
        }
        other => KernelError::ToolServerError(other.to_string()),
    }
}

fn parse_url_elicitation_required_error(
    message: String,
    data: Option<serde_json::Value>,
) -> Result<KernelError, String> {
    let data = data
        .ok_or_else(|| "upstream MCP URL-required error is missing structured data".to_string())?;
    let elicitations = data.get("elicitations").cloned().ok_or_else(|| {
        "upstream MCP URL-required error is missing data.elicitations".to_string()
    })?;
    let elicitations: Vec<CreateElicitationOperation> = serde_json::from_value(elicitations)
        .map_err(|error| format!("failed to parse upstream URL-required elicitations: {error}"))?;
    if elicitations.is_empty() {
        return Err(
            "upstream MCP URL-required error must include at least one elicitation".to_string(),
        );
    }
    if elicitations
        .iter()
        .any(|elicitation| !matches!(elicitation, CreateElicitationOperation::Url { .. }))
    {
        return Err(
            "upstream MCP URL-required error must include only URL-mode elicitations".to_string(),
        );
    }

    Ok(KernelError::UrlElicitationsRequired {
        message,
        elicitations,
    })
}

fn infer_has_side_effects(annotations: Option<&serde_json::Value>) -> bool {
    annotations
        .and_then(|value| value.get("readOnlyHint"))
        .and_then(serde_json::Value::as_bool)
        .map(|read_only| !read_only)
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_core::session::CreateElicitationOperation;
    use arc_kernel::KernelError;

    #[derive(Clone)]
    enum MockCallBehavior {
        Success(McpToolResult),
        UrlRequired {
            message: String,
            data: serde_json::Value,
        },
    }

    struct MockTransport {
        tools: Vec<McpToolInfo>,
        call_behavior: MockCallBehavior,
    }

    impl McpTransport for MockTransport {
        fn list_tools(&self) -> Result<Vec<McpToolInfo>, AdapterError> {
            Ok(self.tools.clone())
        }

        fn call_tool(
            &self,
            tool_name: &str,
            _arguments: serde_json::Value,
        ) -> Result<McpToolResult, AdapterError> {
            let _ = tool_name;
            match &self.call_behavior {
                MockCallBehavior::Success(result) => Ok(result.clone()),
                MockCallBehavior::UrlRequired { message, data } => Err(AdapterError::McpError {
                    code: -32042,
                    message: message.clone(),
                    data: Some(data.clone()),
                }),
            }
        }
    }

    #[test]
    fn generate_manifest_from_mcp() {
        let transport = MockTransport {
            tools: vec![McpToolInfo {
                name: "read_file".into(),
                title: Some("Read File".into()),
                description: Some("Read a file".into()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: Some(serde_json::json!({"type": "string"})),
                annotations: Some(serde_json::json!({"readOnlyHint": true})),
                execution: None,
            }],
            call_behavior: MockCallBehavior::Success(McpToolResult {
                content: vec![serde_json::json!({
                    "type": "text",
                    "text": "called read_file",
                })],
                structured_content: None,
                is_error: Some(false),
            }),
        };

        let config = McpAdapterConfig {
            server_id: "mcp-fs".into(),
            server_name: "Filesystem MCP".into(),
            server_version: "1.0.0".into(),
            public_key: "aabbccdd".into(),
        };

        let adapter = McpAdapter::new(config, Box::new(transport));
        let manifest = adapter
            .generate_manifest()
            .unwrap_or_else(|e| panic!("manifest: {e}"));

        assert_eq!(manifest.tools.len(), 1);
        assert_eq!(manifest.tools[0].name, "read_file");
        assert_eq!(
            manifest.tools[0].output_schema,
            Some(serde_json::json!({"type": "string"}))
        );
        assert!(!manifest.tools[0].has_side_effects);
    }

    #[test]
    fn invoke_tool_via_adapter() {
        let transport = MockTransport {
            tools: vec![],
            call_behavior: MockCallBehavior::Success(McpToolResult {
                content: vec![serde_json::json!({
                    "type": "text",
                    "text": "called some_tool",
                })],
                structured_content: None,
                is_error: Some(false),
            }),
        };
        let config = McpAdapterConfig {
            server_id: "mcp-test".into(),
            server_name: "Test".into(),
            server_version: "0.1.0".into(),
            public_key: "aabbccdd".into(),
        };

        let adapter = McpAdapter::new(config, Box::new(transport));
        let result = adapter
            .invoke("some_tool", serde_json::json!({}))
            .unwrap_or_else(|e| panic!("invoke: {e}"));

        let content = result["content"]
            .as_array()
            .unwrap_or_else(|| panic!("expected content array"));
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["text"], "called some_tool");
    }

    #[test]
    fn adapted_server_exposes_manifest_tool_names() {
        let transport = MockTransport {
            tools: vec![
                McpToolInfo {
                    name: "read_file".into(),
                    title: None,
                    description: Some("Read a file".into()),
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: None,
                    annotations: None,
                    execution: None,
                },
                McpToolInfo {
                    name: "write_file".into(),
                    title: None,
                    description: Some("Write a file".into()),
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: None,
                    annotations: None,
                    execution: None,
                },
            ],
            call_behavior: MockCallBehavior::Success(McpToolResult {
                content: vec![serde_json::json!({
                    "type": "text",
                    "text": "called read_file",
                })],
                structured_content: None,
                is_error: Some(false),
            }),
        };

        let config = McpAdapterConfig {
            server_id: "mcp-test".into(),
            server_name: "Test".into(),
            server_version: "0.1.0".into(),
            public_key: "aabbccdd".into(),
        };

        let adapted = AdaptedMcpServer::new(McpAdapter::new(config, Box::new(transport)))
            .unwrap_or_else(|e| panic!("adapted server: {e}"));

        assert_eq!(adapted.server_id(), "mcp-test");
        assert_eq!(
            adapted.tool_names(),
            vec!["read_file".to_string(), "write_file".to_string()]
        );
    }

    #[test]
    fn adapted_server_maps_url_required_errors_into_kernel_errors() {
        let transport = MockTransport {
            tools: vec![McpToolInfo {
                name: "authorize".into(),
                title: None,
                description: Some("Requires URL elicitation".into()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                annotations: None,
                execution: None,
            }],
            call_behavior: MockCallBehavior::UrlRequired {
                message: "URL elicitation is required for this operation".to_string(),
                data: serde_json::json!({
                    "elicitations": [{
                        "mode": "url",
                        "message": "Complete authorization in your browser",
                        "url": "https://example.com/authorize",
                        "elicitationId": "elicit-auth"
                    }]
                }),
            },
        };

        let config = McpAdapterConfig {
            server_id: "mcp-auth".into(),
            server_name: "Auth".into(),
            server_version: "0.1.0".into(),
            public_key: "aabbccdd".into(),
        };

        let adapted = AdaptedMcpServer::new(McpAdapter::new(config, Box::new(transport)))
            .unwrap_or_else(|e| panic!("adapted server: {e}"));
        let error = adapted
            .invoke("authorize", serde_json::json!({}), None)
            .expect_err("invoke should surface URL-required error");

        match error {
            KernelError::UrlElicitationsRequired {
                message,
                elicitations,
            } => {
                assert_eq!(message, "URL elicitation is required for this operation");
                assert_eq!(elicitations.len(), 1);
                assert!(matches!(
                    &elicitations[0],
                    CreateElicitationOperation::Url { elicitation_id, .. }
                    if elicitation_id == "elicit-auth"
                ));
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}
