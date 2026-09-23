//! Original broker admission around an independently configured MCP transport.
use super::{kernel_error, rejected, BrokerKernelConnection};
use crate::protocol::BrokerExecuteResponse;
use crate::Result;
use chio_kernel::{
    BlockingToolServerConnection, KernelError, NestedFlowBridge, ToolDispatchContext,
    ToolInvocationContext, ToolInvocationCost, ToolServerConnection,
};
use serde::Deserialize;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

/// A selected confined transport accepts a prepared broker descriptor from
/// the privileged host. Implementations must retain that exact descriptor for
/// this dispatch and must not reconnect or substitute another broker.
#[async_trait::async_trait]
pub trait BrokerMcpToolConnection: ToolServerConnection {
    async fn prepare_broker_delivery(
        &self,
        context: &ToolDispatchContext,
        stream: UnixStream,
    ) -> std::result::Result<(), KernelError>;
}

/// A single broker tool returns the signed broker response as MCP structured
/// content with no additional content or error payload. The selected transport
/// owns cage readiness and confinement. This wrapper preserves original kernel
/// custody; installing it alone does not establish that a tool is confined.
/// Streaming is unsupported because completion requires the complete signature.
pub struct BrokerMcpConnection {
    authority: Arc<BrokerKernelConnection>,
    tool: Arc<dyn BrokerMcpToolConnection>,
}

impl BrokerMcpConnection {
    pub fn new(
        authority: Arc<BrokerKernelConnection>,
        tool: Arc<dyn BrokerMcpToolConnection>,
    ) -> Result<Self> {
        if tool.server_id() != authority.server_id()
            || tool.tool_names() != authority.tool_names()
            || !tool.measures_realized_cost()
        {
            return Err(rejected());
        }
        Ok(Self { authority, tool })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompletedMcpResult {
    content: Vec<serde_json::Value>,
    structured_content: BrokerExecuteResponse,
    is_error: bool,
}

#[async_trait::async_trait]
impl ToolServerConnection for BrokerMcpConnection {
    fn server_id(&self) -> &str {
        self.authority.server_id()
    }

    fn tool_names(&self) -> Vec<String> {
        self.authority.tool_names()
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<serde_json::Value, KernelError> {
        Err(KernelError::GuardDenied(
            "broker MCP delivery requires kernel caller context".into(),
        ))
    }

    async fn prepare_delivery(
        &self,
        context: &ToolDispatchContext,
    ) -> std::result::Result<(), KernelError> {
        let authority = self.authority.clone();
        let original = context.clone();
        let stream = blocking(move || {
            authority
                .prepare_connection(&original)
                .map_err(kernel_error)
        })
        .await?;
        self.tool.prepare_broker_delivery(context, stream).await
    }

    async fn invoke_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<serde_json::Value, KernelError> {
        self.invoke_with_cost_and_context(context, arguments, bridge)
            .await
            .map(|(value, _)| value)
    }

    async fn invoke_with_cost_and_context(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let authority = self.authority.clone();
        let caller = context.clone();
        let original_arguments = arguments.clone();
        let delivery = blocking(move || {
            authority
                .validate_delivery(&caller, &original_arguments)
                .map_err(kernel_error)
        })
        .await?;
        let (value, cost) = self
            .tool
            .invoke_with_cost_and_context(context, arguments, bridge)
            .await?;
        let result: CompletedMcpResult =
            serde_json::from_value(value).map_err(|_| kernel_error(rejected()))?;
        if result.is_error || !result.content.is_empty() {
            return Err(kernel_error(rejected()));
        }
        delivery
            .verify_response(
                self.authority.participant.as_ref(),
                &result.structured_content,
                super::trusted_now_ms().map_err(kernel_error)?,
            )
            .map_err(kernel_error)?;
        let response = serde_json::to_value(result.structured_content)
            .map_err(|_| kernel_error(rejected()))?;
        Ok((response, cost))
    }
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> std::result::Result<T, KernelError> + Send + 'static,
) -> std::result::Result<T, KernelError> {
    if tokio::runtime::Handle::try_current().is_err() {
        return work();
    }
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| KernelError::ToolServerError("broker authority task did not return".into()))?
}
