use std::sync::Arc;

use super::{
    NestedFlowBridge, ToolDispatchContext, ToolInvocationContext, ToolInvocationCost,
    ToolServerConnection,
};
use crate::KernelError;
use std::cell::Cell;
use std::time::Duration;

#[cfg(test)]
#[path = "blocking_connection/cancellation_tests.rs"]
mod cancellation_tests;

#[derive(Clone, Copy)]
struct BlockingToolDispatch {
    deadline: Option<tokio::time::Instant>,
    budget: Duration,
}

thread_local! {
    // Scheduling context for one call on an already-offloaded physical worker.
    // This supplies no policy, custody or execution authority.
    static BLOCKING_TOOL_DISPATCH: Cell<Option<BlockingToolDispatch>> = const { Cell::new(None) };
}

struct RestoreBlockingToolDispatch(Option<BlockingToolDispatch>);

impl Drop for RestoreBlockingToolDispatch {
    fn drop(&mut self) {
        BLOCKING_TOOL_DISPATCH.with(|current| current.set(self.0));
    }
}

pub(crate) fn with_blocking_tool_dispatch<T>(
    deadline: Option<tokio::time::Instant>,
    budget: Duration,
    dispatch: impl FnOnce() -> T,
) -> T {
    let previous = BLOCKING_TOOL_DISPATCH
        .with(|current| current.replace(Some(BlockingToolDispatch { deadline, budget })));
    let _restore = RestoreBlockingToolDispatch(previous);
    dispatch()
}

/// One typed refusal for every dispatch path and the adapter's expired worker.
pub(crate) fn blocking_dispatch_deadline_exceeded(budget: Duration) -> KernelError {
    KernelError::HotPathDeadlineExceeded {
        stage: crate::HotPathStage::Dispatch,
        budget_ms: u64::try_from(budget.as_millis()).unwrap_or(u64::MAX),
    }
}

fn run_inline() -> Result<bool, KernelError> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Ok(true);
    }
    let Some(dispatch) = BLOCKING_TOOL_DISPATCH.with(Cell::take) else {
        return Ok(false);
    };
    // Timeout polls its inner future first, so reject expired work before
    // entering a synchronous callback even when the timer is already ready.
    if dispatch
        .deadline
        .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
    {
        return Err(blocking_dispatch_deadline_exceeded(dispatch.budget));
    }
    Ok(true)
}

async fn run_blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, KernelError> + Send + 'static,
) -> Result<T, KernelError> {
    let task = tokio::task::spawn_blocking(work);
    let _abort_on_drop = super::AbortOnDrop(task.abort_handle());
    task.await.map_err(|error| {
        KernelError::ToolServerError(format!(
            "blocking tool server task failed before returning: {error}"
        ))
    })?
}

/// Synchronous transport port adapted onto the kernel's asynchronous tool
/// server boundary. The first call on the kernel's existing blocking dispatch
/// worker executes directly. Other calls use `spawn_blocking` when a Tokio
/// runtime is active, and the no-runtime sync bridge also executes directly.
/// Dropping an awaiting call aborts work still queued; already-started
/// synchronous work continues with its original outcome semantics.
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

    /// Preserve the kernel-created caller binding for native IPC adapters.
    /// Existing transports continue receiving their original dispatch identity.
    fn invoke_blocking_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        match context.dispatch() {
            Some(dispatch) => {
                self.invoke_blocking_in_context(dispatch, context.tool_name(), arguments)
            }
            None => self.invoke_blocking(context.tool_name(), arguments),
        }
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

    async fn invoke_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        if run_inline()? {
            return self.inner.invoke_blocking_with_context(context, arguments);
        }
        let inner = Arc::clone(&self.inner);
        let context = context.clone();
        run_blocking(move || inner.invoke_blocking_with_context(&context, arguments)).await
    }

    async fn invoke_with_cost_and_context(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        self.invoke_with_context(context, arguments, nested_flow_bridge)
            .await
            .map(|value| (value, None))
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        if run_inline()? {
            return self.inner.invoke_blocking(tool_name, arguments);
        }
        let inner = Arc::clone(&self.inner);
        let tool_name = tool_name.to_string();
        run_blocking(move || inner.invoke_blocking(&tool_name, arguments)).await
    }

    async fn prepare_delivery(&self, context: &ToolDispatchContext) -> Result<(), KernelError> {
        if run_inline()? {
            return self.inner.prepare_delivery_blocking(context);
        }
        let inner = Arc::clone(&self.inner);
        let context = context.clone();
        run_blocking(move || inner.prepare_delivery_blocking(&context)).await
    }

    async fn invoke_in_context(
        &self,
        context: &ToolDispatchContext,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        if run_inline()? {
            return self
                .inner
                .invoke_blocking_in_context(context, tool_name, arguments);
        }
        let inner = Arc::clone(&self.inner);
        let context = context.clone();
        let tool_name = tool_name.to_string();
        run_blocking(move || inner.invoke_blocking_in_context(&context, &tool_name, arguments))
            .await
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
