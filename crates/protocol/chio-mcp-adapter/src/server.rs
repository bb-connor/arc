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
    pub fn new(adapter: McpAdapter) -> Result<Self, AdapterError> {
        let manifest = match adapter.generate_manifest() {
            Ok(manifest) => manifest,
            Err(error) => {
                return Err(crate::adapter::merge_shutdown_error(
                    error,
                    adapter.shutdown(),
                ));
            }
        };
        Ok(Self { adapter, manifest })
    }

    pub fn from_command(
        command: &str,
        args: &[&str],
        config: McpAdapterConfig,
        launch: crate::transport::NativeMcpLaunch,
    ) -> Result<Self, AdapterError> {
        Self::new(McpAdapter::from_command(command, args, config, launch)?)
    }

    /// Construct a server whose native subprocess cannot fall back from cage
    /// enforcement to the legacy direct launcher.
    pub fn from_cage_required_command(
        command: &str,
        args: &[&str],
        config: McpAdapterConfig,
        launch: crate::transport::CageRequiredLaunch,
    ) -> Result<Self, AdapterError> {
        Self::new(McpAdapter::from_cage_required_command(
            command, args, config, launch,
        )?)
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

    #[must_use]
    pub fn native_enforcement_evidence(&self) -> Option<&chio_cage::FullyEnforcedEvidence> {
        self.adapter.native_enforcement_evidence()
    }

    pub fn notification_source(&self) -> Arc<dyn McpTransport> {
        self.adapter.transport.clone()
    }

    /// Shut down the upstream transport and persist terminal security evidence.
    pub fn shutdown(&self) -> Result<(), AdapterError> {
        self.adapter.shutdown()
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
