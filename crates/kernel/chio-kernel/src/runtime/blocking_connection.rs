use std::sync::Arc;

use super::{NestedFlowBridge, ToolDispatchContext, ToolInvocationCost, ToolServerConnection};
use crate::KernelError;

/// Synchronous transport port adapted onto the kernel's asynchronous tool
/// server boundary. Calls use `spawn_blocking` when a Tokio runtime is active
/// and execute directly when driven by the kernel's no-runtime sync bridge.
/// This is intended for bounded local IPC clients whose wire APIs are
/// deliberately blocking.
pub trait BlockingToolServerConnection: Send + Sync {
    fn server_id(&self) -> &str;

    fn tool_names(&self) -> Vec<String>;

    fn invoke_blocking(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError>;

    fn prepare_delivery_blocking(&self, context: &ToolDispatchContext) -> Result<(), KernelError> {
        let _ = context;
        Ok(())
    }

    fn invoke_blocking_in_context(
        &self,
        context: &ToolDispatchContext,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        let _ = context;
        self.invoke_blocking(tool_name, arguments)
    }
}

pub struct BlockingToolServerAdapter {
    server_id: String,
    inner: Arc<dyn BlockingToolServerConnection>,
}

impl BlockingToolServerAdapter {
    pub fn new(inner: Arc<dyn BlockingToolServerConnection>) -> Result<Self, KernelError> {
        let server_id = inner.server_id().to_string();
        if server_id.is_empty() || inner.tool_names().is_empty() {
            return Err(KernelError::ToolServerError(
                "blocking tool server identity or tool set is empty".to_string(),
            ));
        }
        Ok(Self { server_id, inner })
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for BlockingToolServerAdapter {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.inner.tool_names()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return self.inner.invoke_blocking(tool_name, arguments);
        }
        let inner = Arc::clone(&self.inner);
        let tool_name = tool_name.to_string();
        tokio::task::spawn_blocking(move || inner.invoke_blocking(&tool_name, arguments))
            .await
            .map_err(|error| {
                KernelError::ToolServerError(format!(
                    "blocking tool server task failed before returning: {error}"
                ))
            })?
    }

    async fn prepare_delivery(&self, context: &ToolDispatchContext) -> Result<(), KernelError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return self.inner.prepare_delivery_blocking(context);
        }
        let inner = Arc::clone(&self.inner);
        let context = context.clone();
        tokio::task::spawn_blocking(move || inner.prepare_delivery_blocking(&context))
            .await
            .map_err(|error| {
                KernelError::ToolServerError(format!(
                    "blocking tool server task failed before returning: {error}"
                ))
            })?
    }

    async fn invoke_in_context(
        &self,
        context: &ToolDispatchContext,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return self
                .inner
                .invoke_blocking_in_context(context, tool_name, arguments);
        }
        let inner = Arc::clone(&self.inner);
        let context = context.clone();
        let tool_name = tool_name.to_string();
        tokio::task::spawn_blocking(move || {
            inner.invoke_blocking_in_context(&context, &tool_name, arguments)
        })
        .await
        .map_err(|error| {
            KernelError::ToolServerError(format!(
                "blocking tool server task failed before returning: {error}"
            ))
        })?
    }

    async fn invoke_with_cost_in_context(
        &self,
        context: &ToolDispatchContext,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        self.invoke_in_context(context, tool_name, arguments, bridge)
            .await
            .map(|value| (value, None))
    }
}
