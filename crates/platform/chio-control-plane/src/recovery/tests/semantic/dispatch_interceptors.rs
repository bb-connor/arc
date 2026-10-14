//! Test-only interception around actual prepared native connector ownership.
use super::*;

pub(super) struct SaturatedSemanticConnector {
    pub(super) inner: PinnedSemanticConnector,
    pub(super) _occupied: tokio::sync::OwnedSemaphorePermit,
}

pub(super) struct ExpiringHeldSemanticConnector {
    pub(super) inner: Arc<dyn ToolServerConnection>,
    pub(super) path: std::path::PathBuf,
}
impl ExpiringHeldSemanticConnector {
    async fn wait_for_captured_expiry(
        &self,
        context: &ToolInvocationContext,
    ) -> Result<(), KernelError> {
        let dispatch = context
            .dispatch()
            .ok_or_else(|| KernelError::Internal("expiry fixture lacks native dispatch".into()))?;
        let record = {
            let connection = rusqlite::Connection::open(self.path.join("admission.db"))
                .map_err(|_| KernelError::Internal("expiry fixture unavailable".into()))?;
            let payload: Vec<u8> = connection
                .query_row(
                    "SELECT payload FROM admission_operation_recovery_records WHERE record_key=?1",
                    [format!("semantic-capture:{}", dispatch.operation_id())],
                    |row| row.get(0),
                )
                .map_err(|_| KernelError::Internal("expiry fixture capture absent".into()))?;
            serde_json::from_slice::<
                chio_store_sqlite::admission_operation_store::NativeSemanticCaptureRecordV1,
            >(&payload)
            .map_err(|_| KernelError::Internal("expiry fixture capture malformed".into()))?
        };
        if record.operation_id.as_str() != dispatch.operation_id()
            || !record
                .invocation
                .prerequisites
                .as_slice()
                .iter()
                .any(|proof| {
                    proof.body().kind == SemanticPrerequisiteKindV1::HeldReservation
                        && proof.body().lease.is_some()
                        && proof.body().valid_until_unix_ms == record.valid_until_unix_ms
                })
        {
            return Err(KernelError::Internal(
                "expiry fixture lost held capture".into(),
            ));
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let now =
                now_ms().map_err(|_| KernelError::Internal("expiry clock unavailable".into()))?;
            if now >= record.valid_until_unix_ms.get() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(KernelError::Internal(
                    "expiry clock failed to advance".into(),
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(
                (record.valid_until_unix_ms.get() - now).min(50_000),
            ))
            .await;
        }
        std::fs::write(self.path.join("held-capture-expired"), b"verified")
            .map_err(|_| KernelError::Internal("expiry fixture evidence unavailable".into()))?;
        Ok(())
    }
}
#[async_trait::async_trait]
impl ToolServerConnection for ExpiringHeldSemanticConnector {
    fn server_id(&self) -> &str {
        self.inner.server_id()
    }
    fn tool_names(&self) -> Vec<String> {
        self.inner.tool_names()
    }
    fn tool_is_read_only(&self, name: &str) -> bool {
        self.inner.tool_is_read_only(name)
    }
    async fn prepare_invocation_connection(
        &self,
        context: &chio_kernel::ToolDispatchContext,
    ) -> Result<Option<Arc<dyn ToolServerConnection>>, KernelError> {
        Ok(self
            .inner
            .prepare_invocation_connection(context)
            .await?
            .map(|inner| {
                Arc::new(Self {
                    inner,
                    path: self.path.clone(),
                }) as Arc<dyn ToolServerConnection>
            }))
    }
    async fn invoke(
        &self,
        tool: &str,
        arguments: Value,
        nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.inner.invoke(tool, arguments, nested).await
    }
    async fn invoke_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.wait_for_captured_expiry(context).await?;
        self.inner
            .invoke_with_context(context, arguments, nested)
            .await
    }
    async fn invoke_with_cost_and_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(Value, Option<chio_kernel::ToolInvocationCost>), KernelError> {
        self.wait_for_captured_expiry(context).await?;
        self.inner
            .invoke_with_cost_and_context(context, arguments, nested)
            .await
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for SaturatedSemanticConnector {
    fn server_id(&self) -> &str {
        self.inner.server_id()
    }
    fn tool_names(&self) -> Vec<String> {
        self.inner.tool_names()
    }
    fn tool_is_read_only(&self, name: &str) -> bool {
        self.inner.tool_is_read_only(name)
    }
    async fn prepare_invocation_connection(
        &self,
        context: &chio_kernel::ToolDispatchContext,
    ) -> Result<Option<Arc<dyn ToolServerConnection>>, KernelError> {
        self.inner.prepare_invocation_connection(context).await
    }
    async fn invoke(
        &self,
        tool: &str,
        arguments: Value,
        nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.inner.invoke(tool, arguments, nested).await
    }
    async fn invoke_with_context(
        &self,
        context: &chio_kernel::ToolInvocationContext,
        arguments: Value,
        nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.inner
            .invoke_with_context(context, arguments, nested)
            .await
    }
    async fn invoke_with_cost_and_context(
        &self,
        context: &chio_kernel::ToolInvocationContext,
        arguments: Value,
        nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(Value, Option<chio_kernel::ToolInvocationCost>), KernelError> {
        self.inner
            .invoke_with_cost_and_context(context, arguments, nested)
            .await
    }
}
