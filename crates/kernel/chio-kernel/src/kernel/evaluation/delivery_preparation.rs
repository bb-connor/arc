//! Transport readiness belongs before final authorization and effect commitment.

use super::*;

impl ChioKernel {
    /// Wait while the caller's pre-dispatch drop guard still owns cleanup.
    /// Preparation may yield, but cannot invoke the tool. Its success requires
    /// full authorization revalidation with a freshly sampled clock before
    /// any payment authorization, pool claim or durable dispatch commitment.
    pub(super) async fn wait_for_tool_dispatch_readiness(
        &self,
        request: &ToolCallRequest,
        server: Option<&Arc<dyn ToolServerConnection>>,
        context: Option<&ToolDispatchContext>,
    ) -> Result<bool, KernelError> {
        let runtime_waited = self
            .wait_for_runtime_admission_dispatch_readiness(request)
            .await?;
        let Some(context) = context else {
            return Ok(runtime_waited);
        };
        let server = server.ok_or_else(|| {
            KernelError::Internal("delivery preparation has no resolved tool server".to_owned())
        })?;
        server.prepare_delivery(context).await.map_err(|error| {
            KernelError::ToolServerError(format!("tool server could not prepare delivery: {error}"))
        })?;
        // Even an immediately ready preparation is an external callback. Do
        // not infer that authorization remained unchanged because it did not
        // visibly yield to this executor.
        Ok(true)
    }
}
