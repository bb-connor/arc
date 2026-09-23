//! One original broker dispatch through the production confined stdio adapter.
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chio_kernel::{
    KernelError, NestedFlowBridge, ToolDispatchContext, ToolInvocationContext, ToolInvocationCost,
    ToolServerConnection,
};
use chio_manifest::{NativeSyscallProfile, VerifiedManifestRegistry};
use chio_mcp_adapter::adapter::McpAdapterConfig;
use chio_mcp_adapter::server::AdaptedMcpServer;
use chio_mcp_adapter::transport::{NativeMcpLaunch, NativeMcpLaunchFactory};

use crate::kernel_admission::BrokerMcpToolConnection;

/// A single-use confined connection for one original kernel dispatch.
///
/// Construct and register this connection for the lifetime of one invocation,
/// inside `BrokerMcpConnection`. Preparation launches the tool only after the
/// host has authenticated its exact prepared broker descriptor. Discovery must
/// match the signed manifest before the kernel commits dispatch. Completion,
/// failure, or dropping the invocation owner shuts down the caged child through
/// the adapter's durable terminal-receipt path. Reuse requires a new connection
/// and fresh kernel admission; this object never reconnects or retries.
pub struct NativeBrokerMcpTool {
    command: String,
    args: Vec<String>,
    config: McpAdapterConfig,
    tool_name: String,
    registry: Arc<VerifiedManifestRegistry>,
    factory: Arc<dyn NativeMcpLaunchFactory>,
    preparation_started: AtomicBool,
    prepared: Mutex<Option<PreparedDelivery>>,
}

struct PreparedDelivery {
    context: ToolDispatchContext,
    server: AdaptedMcpServer,
}

impl Drop for PreparedDelivery {
    fn drop(&mut self) {
        // This path also owns cancellation before the kernel commits dispatch.
        // Failure to persist termination never grants another execution.
        let _ = self.server.shutdown();
    }
}

impl NativeBrokerMcpTool {
    pub fn new(
        command: String,
        args: Vec<String>,
        server_id: &str,
        registry: Arc<VerifiedManifestRegistry>,
        factory: Arc<dyn NativeMcpLaunchFactory>,
    ) -> Result<Self, KernelError> {
        if !Path::new(&command).is_absolute() {
            return Err(refused());
        }
        let authorization = registry
            .authorize_cage_manifest(server_id)
            .map_err(|_| refused())?;
        let manifest = &authorization.signed_manifest().manifest;
        if manifest.tools.len() != 1
            || manifest
                .required_permissions
                .as_ref()
                .is_none_or(|permissions| {
                    permissions.native_syscall_profile != NativeSyscallProfile::BrokeredNativeV1
                })
        {
            return Err(refused());
        }
        let config = McpAdapterConfig {
            server_id: manifest.server_id.clone(),
            server_name: manifest.name.clone(),
            server_version: manifest.version.clone(),
            public_key: manifest.public_key.clone(),
        };
        let tool_name = manifest.tools[0].name.clone();
        Ok(Self {
            command,
            args,
            config,
            tool_name,
            registry,
            factory,
            preparation_started: AtomicBool::new(false),
            prepared: Mutex::new(None),
        })
    }
}

#[async_trait::async_trait]
impl BrokerMcpToolConnection for NativeBrokerMcpTool {
    async fn prepare_broker_delivery(
        &self,
        context: &ToolDispatchContext,
        stream: UnixStream,
    ) -> Result<(), KernelError> {
        // Readiness precedes final authorization. The kernel binds the caller
        // capability when it creates the invocation context after preparation.
        if self
            .preparation_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(refused());
        }
        let command = self.command.clone();
        let args = self.args.clone();
        let config = self.config.clone();
        let registry = self.registry.clone();
        let factory = self.factory.clone();
        let context = context.clone();
        let prepare = move || -> Result<PreparedDelivery, KernelError> {
            let witness = stream.try_clone().map_err(|_| refused())?;
            let args: Vec<_> = args.iter().map(String::as_str).collect();
            let launch = factory
                .prepare_broker_launch(&command, &args, &config.server_id, registry.clone(), stream)
                .map_err(|_| refused())?;
            // Matching peer credentials alone would also accept a fresh
            // connection to this daemon. Require the same open socket.
            launch
                .verify_prepared_broker_stream(&witness)
                .map_err(|_| refused())?;
            let server = AdaptedMcpServer::from_command_with_manifest_registry(
                &command,
                &args,
                config,
                registry.as_ref(),
                NativeMcpLaunch::CageRequired(Box::new(launch)),
            )
            .map_err(|error| {
                #[cfg(test)]
                eprintln!("confined MCP adapter preparation failed: {error}");
                let _ = error;
                refused()
            })?;
            let prepared = PreparedDelivery { context, server };
            if prepared.server.native_enforcement_evidence().is_none()
                || prepared.server.native_enforcement_receipt().is_none()
            {
                return Err(refused());
            }
            Ok(prepared)
        };
        let prepared = if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::spawn_blocking(prepare)
                .await
                .map_err(|_| refused())??
        } else {
            prepare()?
        };
        let mut slot = self.prepared.lock().map_err(|_| refused())?;
        *slot = Some(prepared);
        Ok(())
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for NativeBrokerMcpTool {
    fn server_id(&self) -> &str {
        &self.config.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![self.tool_name.clone()]
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(refused())
    }

    async fn prepare_delivery(&self, _: &ToolDispatchContext) -> Result<(), KernelError> {
        Err(refused())
    }

    async fn invoke_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invoke_with_cost_and_context(context, arguments, bridge)
            .await
            .map(|(value, _)| value)
    }

    async fn invoke_with_cost_and_context(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let dispatch = context.dispatch().ok_or_else(refused)?;
        let prepared = {
            let mut slot = self.prepared.lock().map_err(|_| refused())?;
            let original = slot.as_ref().ok_or_else(refused)?;
            if original.context.request_id() != dispatch.request_id()
                || original.context.attempt() != dispatch.attempt()
                || original
                    .context
                    .caller_capability_sha256()
                    .is_some_and(|digest| digest != context.capability_hash())
                || context.server_id() != self.server_id()
                || context.tool_name() != self.tool_name
                || dispatch.caller_capability_sha256() != Some(context.capability_hash())
            {
                return Err(refused());
            }
            slot.take().ok_or_else(refused)?
        };
        let outcome = prepared
            .server
            .invoke_with_cost_and_context(context, arguments, bridge)
            .await;
        prepared.server.shutdown().map_err(|_| refused())?;
        outcome
    }
}

fn refused() -> KernelError {
    KernelError::ToolServerError("confined broker MCP delivery refused".to_string())
}
