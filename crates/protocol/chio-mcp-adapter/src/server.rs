use std::sync::Arc;

use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use chio_manifest::ToolManifest;

use crate::adapter::{McpAdapter, McpAdapterConfig};
use crate::edge::{AdapterError, McpServerCapabilities, McpTransport};
use crate::errors::map_tool_invocation_error;
use crate::prompts::AdaptedMcpPromptProvider;
use crate::resources::AdaptedMcpResourceProvider;

/// A Chio tool-server connection backed by a wrapped MCP server.
#[derive(Clone)]
pub struct AdaptedMcpServer {
    pub(crate) adapter: McpAdapter,
    pub(crate) manifest: ToolManifest,
}

impl AdaptedMcpServer {
    /// Build a discovery-only adapter server.
    ///
    /// Production runtimes that use manifest security metadata must call
    /// [`Self::new_with_manifest_registry`] so the retained manifest comes
    /// from a verified publisher signature.
    pub fn new(adapter: McpAdapter) -> Result<Self, AdapterError> {
        let manifest = adapter.generate_manifest()?;
        Ok(Self { adapter, manifest })
    }

    /// Build an adapter server after matching fresh MCP discovery against the
    /// exact publisher-signed manifest admitted by `registry`.
    pub fn new_with_manifest_registry(
        adapter: McpAdapter,
        registry: &chio_manifest::VerifiedManifestRegistry,
    ) -> Result<Self, AdapterError> {
        let discovered = adapter.generate_manifest()?;
        let admitted = registry
            .verified_manifest(&discovered.server_id)
            .ok_or_else(|| AdapterError::SecurityMetadataUnavailable {
                server_id: discovered.server_id.clone(),
                tool_name: "*".to_string(),
            })?;
        crate::verify_discovered_manifest_surface(&discovered, &admitted.manifest)?;
        Ok(Self {
            adapter,
            manifest: admitted.manifest.clone(),
        })
    }

    pub fn from_command(
        command: &str,
        args: &[&str],
        config: McpAdapterConfig,
    ) -> Result<Self, AdapterError> {
        Self::new(McpAdapter::from_command(command, args, config)?)
    }

    /// Spawn an MCP server, discover its live surface, and retain only the
    /// publisher-signed manifest admitted by `registry`.
    pub fn from_command_with_manifest_registry(
        command: &str,
        args: &[&str],
        config: McpAdapterConfig,
        registry: &chio_manifest::VerifiedManifestRegistry,
    ) -> Result<Self, AdapterError> {
        Self::new_with_manifest_registry(McpAdapter::from_command(command, args, config)?, registry)
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
            .then(|| AdaptedMcpResourceProvider::new(self.adapter.clone()))
    }

    pub fn prompt_provider(&self) -> Option<AdaptedMcpPromptProvider> {
        self.upstream_capabilities()
            .prompts_supported
            .then(|| AdaptedMcpPromptProvider::new(self.adapter.clone()))
    }
}

#[async_trait::async_trait]
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

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        if !self
            .manifest
            .tools
            .iter()
            .any(|tool| tool.name == tool_name)
        {
            return Err(KernelError::ToolNotRegistered(tool_name.to_string()));
        }

        self.adapter
            .invoke_with_nested_flow(tool_name, arguments, nested_flow_bridge)
            .map_err(map_tool_invocation_error)
    }
}
