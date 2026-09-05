use super::{
    NestedFlowBridge, ToolInvocationContext, ToolInvocationCost, ToolServerEvent,
    ToolServerStreamResult,
};
use crate::KernelError;

/// Trait representing a connection to a tool server.
///
/// The kernel holds one `ToolServerConnection` per registered server. In
/// production this is an mTLS connection over UDS or TCP. For testing,
/// an in-process implementation can be used.
#[async_trait::async_trait]
pub trait ToolServerConnection: Send + Sync {
    /// Receive kernel-selected caller binding for native stateful operations.
    /// Existing connectors retain their invocation behavior by default.
    async fn invoke_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invoke(context.tool_name(), arguments, nested_flow_bridge)
            .await
    }

    /// Cost-reporting counterpart preserving existing connector cost overrides.
    async fn invoke_with_cost_and_context(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        self.invoke_with_cost(context.tool_name(), arguments, nested_flow_bridge)
            .await
    }

    /// Streaming counterpart preserving existing connector stream overrides.
    async fn invoke_stream_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        self.invoke_stream(context.tool_name(), arguments, nested_flow_bridge)
            .await
    }

    /// The server's unique identifier.
    fn server_id(&self) -> &str;

    /// List the tool names available on this server.
    fn tool_names(&self) -> Vec<String>;

    /// Return whether the registered tool is explicitly declared read-only.
    ///
    /// The conservative default keeps unannotated tools side-effecting for
    /// durable admission. Implementations should return `true` only from
    /// authenticated manifest metadata owned by the registered connection.
    fn tool_is_read_only(&self, _tool_name: &str) -> bool {
        false
    }

    /// Invoke a tool on this server. The kernel has already validated the
    /// capability and run guards before calling this.
    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError>;

    /// Invoke a tool and optionally report the actual cost of the invocation.
    ///
    /// Tool servers that track monetary costs should override this method.
    /// The default implementation delegates to `invoke` and returns `None`
    /// cost, meaning the kernel will charge `max_cost_per_invocation` as
    /// the worst-case debit.
    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self
            .invoke(tool_name, arguments, nested_flow_bridge)
            .await?;
        Ok((value, None))
    }

    /// Whether this server measures the realized cost of an invocation it
    /// dispatches.
    ///
    /// The default is `true`: a server that returns `None` cost from
    /// `invoke_with_cost` is asserting that the realized cost equals the
    /// authorized ceiling, and the kernel reconciles and settles that as a
    /// completed spend.
    ///
    /// A server that returns `false` does not execute the target tool and
    /// cannot measure a realized cost (for example a pre-execution
    /// authorization gate that dispatches a pass-through while the real tool
    /// runs elsewhere). For such a server the kernel reverses the
    /// pre-execution hold and signs a provisional, unreconciled receipt
    /// instead of a settled authoritative spend, since no cost was realized on
    /// this path. Real reconciliation happens at the execution site.
    fn measures_realized_cost(&self) -> bool {
        true
    }

    /// Invoke a tool that can emit multiple streamed chunks before its final terminal state.
    ///
    /// Servers that do not support streaming can ignore this and rely on `invoke`.
    async fn invoke_stream(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        let _ = (tool_name, arguments, nested_flow_bridge);
        Ok(None)
    }

    /// Drain asynchronous events emitted after a tool invocation has already returned.
    ///
    /// Native tool servers can use this to surface late URL-elicitation completions and
    /// catalog/resource notifications without depending on a still-live request-local bridge.
    async fn drain_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
        Ok(vec![])
    }
}
