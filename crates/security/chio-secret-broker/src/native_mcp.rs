//! One original broker dispatch through the production confined stdio adapter.
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chio_kernel::{
    BlockingToolServerConnection, KernelError, NestedFlowBridge, ToolDispatchContext,
    ToolInvocationContext, ToolInvocationCost, ToolServerConnection,
};
use chio_manifest::{NativeSyscallProfile, VerifiedManifestRegistry};
use chio_mcp_adapter::adapter::{McpAdapter, McpAdapterConfig};
use chio_mcp_adapter::server::AdaptedMcpServer;
use chio_mcp_adapter::transport::{NativeMcpLaunch, NativeMcpLaunchFactory, StdioRequestTimeouts};

use crate::kernel_admission::{
    BrokerKernelConnection, BrokerMcpConnection, BrokerMcpToolConnection,
};

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
    timeouts: StdioRequestTimeouts,
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
            timeouts: StdioRequestTimeouts::default(),
            preparation_started: AtomicBool::new(false),
            prepared: Mutex::new(None),
        })
    }

    pub fn with_request_timeouts(mut self, timeouts: StdioRequestTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    pub(crate) fn fresh(&self) -> Self {
        Self {
            command: self.command.clone(),
            args: self.args.clone(),
            config: self.config.clone(),
            tool_name: self.tool_name.clone(),
            registry: self.registry.clone(),
            factory: self.factory.clone(),
            timeouts: self.timeouts,
            preparation_started: AtomicBool::new(false),
            prepared: Mutex::new(None),
        }
    }
}

/// A process host's persistent route to invocation-owned confined children.
/// Every readiness operation authenticates a fresh original broker dispatch;
/// children and prepared descriptors are never shared, reconnected or retried.
pub struct NativeBrokerMcpRouter {
    authority: Arc<BrokerKernelConnection>,
    template: NativeBrokerMcpTool,
}

impl NativeBrokerMcpRouter {
    pub fn new(
        authority: Arc<BrokerKernelConnection>,
        template: NativeBrokerMcpTool,
    ) -> Result<Self, KernelError> {
        if template.preparation_started.load(Ordering::Acquire)
            || template.server_id() != authority.server_id()
            || template.tool_names() != authority.tool_names()
        {
            return Err(refused());
        }
        Ok(Self {
            authority,
            template,
        })
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for NativeBrokerMcpRouter {
    fn server_id(&self) -> &str {
        self.template.server_id()
    }
    fn tool_names(&self) -> Vec<String> {
        self.template.tool_names()
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

    async fn prepare_invocation_connection(
        &self,
        context: &ToolDispatchContext,
    ) -> Result<Option<Arc<dyn ToolServerConnection>>, KernelError> {
        let connection = Arc::new(
            BrokerMcpConnection::new(self.authority.clone(), Arc::new(self.template.fresh()))
                .map_err(|_| refused())?,
        );
        connection.prepare_delivery(context).await?;
        Ok(Some(connection))
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
        let timeouts = self.timeouts;
        let context = context.clone();
        let prepare = move || -> Result<PreparedDelivery, KernelError> {
            let witness = stream.try_clone().map_err(|_| refused())?;
            let args: Vec<_> = args.iter().map(String::as_str).collect();
            let launch = factory
                .prepare_broker_launch(&command, &args, &config.server_id, registry.clone(), stream)
                .map_err(|_| refused_at("launch policy"))?;
            // Matching peer credentials alone would also accept a fresh
            // connection to this daemon. Require the same open socket.
            launch
                .verify_prepared_broker_stream(&witness)
                .map_err(|_| refused_at("prepared socket identity"))?;
            let adapter = McpAdapter::from_command_with_timeouts(
                &command,
                &args,
                config,
                NativeMcpLaunch::CageRequired(Box::new(launch)),
                timeouts,
            )
            .map_err(|error| {
                tracing::error!(error = %error, "confined broker MCP preparation failed");
                refused_at("MCP handshake")
            })?;
            let server = AdaptedMcpServer::new_with_manifest_registry(adapter, registry.as_ref())
                .map_err(|_| refused_at("manifest discovery"))?;
            let prepared = PreparedDelivery { context, server };
            if prepared.server.native_enforcement_evidence().is_none()
                || prepared.server.native_enforcement_receipt().is_none()
            {
                return Err(refused_at("enforcement evidence"));
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

    fn prepared_native_launch_receipt(
        &self,
    ) -> Option<chio_core_types::receipt::body::ChioReceipt> {
        self.prepared
            .lock()
            .ok()?
            .as_ref()?
            .server
            .native_enforcement_receipt()
            .cloned()
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

fn refused_at(stage: &'static str) -> KernelError {
    // Report only a fixed stage to the caller, never tool output or arguments.
    KernelError::ToolServerError(format!("confined broker MCP delivery refused at {stage}"))
}
