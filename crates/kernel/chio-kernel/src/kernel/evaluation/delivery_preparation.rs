//! Transport readiness belongs before final authorization and effect commitment.

use super::*;

pub(super) struct PreparedToolDelivery {
    pub waited: bool,
    pub connection: Option<Arc<dyn ToolServerConnection>>,
}

impl PreparedToolDelivery {
    /// Keep the prepared child owned through post-readiness denials and dispatch.
    /// Cancellation drops the same owner without a separate cleanup registry.
    pub fn retain(
        result: Result<Self, KernelError>,
        metadata: &mut Option<serde_json::Value>,
    ) -> (Result<bool, KernelError>, Option<Self>) {
        let mut owner = None;
        let readiness = result.and_then(|prepared| {
            prepared.bind_launch_receipt(metadata)?;
            let waited = prepared.waited;
            owner = Some(prepared);
            Ok(waited)
        });
        (readiness, owner)
    }

    pub fn bind_launch_receipt(
        &self,
        metadata: &mut Option<serde_json::Value>,
    ) -> Result<(), KernelError> {
        let Some(receipt) = self
            .connection
            .as_ref()
            .and_then(|server| server.prepared_native_launch_receipt())
        else {
            return Ok(());
        };
        let bytes = chio_core::canonical_json_bytes(&receipt)
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        let reference = serde_json::json!({
            "receipt_id": receipt.id,
            "receipt_sha256": chio_core::sha256_hex(&bytes),
        });
        let metadata = metadata.get_or_insert_with(|| serde_json::json!({}));
        let object = metadata
            .as_object_mut()
            .ok_or_else(|| KernelError::Internal("delivery metadata must be an object".into()))?;
        if object
            .get("native_launch")
            .is_some_and(|existing| existing != &reference)
        {
            return Err(KernelError::ToolServerError(
                "prepared tool launch differs from host attribution".into(),
            ));
        }
        object.insert("native_launch".into(), reference);
        Ok(())
    }
}

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
    ) -> Result<PreparedToolDelivery, KernelError> {
        let runtime_waited = self
            .wait_for_runtime_admission_dispatch_readiness(request)
            .await?;
        let Some(context) = context else {
            return Ok(PreparedToolDelivery {
                waited: runtime_waited,
                connection: None,
            });
        };
        let server = server.ok_or_else(|| {
            KernelError::Internal("delivery preparation has no resolved tool server".to_owned())
        })?;
        let connection = server
            .prepare_invocation_connection(context)
            .await
            .map_err(|error| {
                KernelError::ToolServerError(format!(
                    "tool server could not prepare delivery: {error}"
                ))
            })?;
        if let Some(prepared) = &connection {
            if prepared.server_id() != server.server_id()
                || prepared.tool_names() != server.tool_names()
                || prepared.measures_realized_cost() != server.measures_realized_cost()
                || prepared.tool_is_read_only(&request.tool_name)
                    != server.tool_is_read_only(&request.tool_name)
            {
                return Err(KernelError::ToolServerError(
                    "prepared connection changed the admitted tool identity".into(),
                ));
            }
        }
        // Even an immediately ready preparation is an external callback. Do
        // not infer that authorization remained unchanged because it did not
        // visibly yield to this executor.
        Ok(PreparedToolDelivery {
            waited: true,
            connection,
        })
    }
}
