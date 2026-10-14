//! One workload slot belongs to the exact invocation before native capture.
use super::*;
use chio_kernel::ToolDispatchContext;
use std::sync::Mutex;

struct PreparedSubmission {
    connector: PinnedSupportIssueConnector,
    dispatch: ToolDispatchContext,
    permit: Mutex<Option<OwnedSemaphorePermit>>,
}

pub(super) fn prepare(
    connector: &PinnedSupportIssueConnector,
    dispatch: &ToolDispatchContext,
) -> Result<Arc<dyn ToolServerConnection>, KernelError> {
    // Local readiness only. No provider request, native capture or dispatch
    // permission is created by reserving this bounded owned slot.
    let permit = connector
        .capacity
        .clone()
        .try_acquire_owned()
        .map_err(|_| refused())?;
    Ok(Arc::new(PreparedSubmission {
        connector: connector.clone(),
        dispatch: dispatch.clone(),
        permit: Mutex::new(Some(permit)),
    }))
}

impl PreparedSubmission {
    async fn submit_once(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        let dispatch = context.dispatch().ok_or_else(refused)?;
        if context.server_id() != self.connector.server
            || context.tool_name() != self.connector.tool
            || nested.is_some()
            || dispatch.caller_capability_sha256() != Some(context.capability_hash())
            || dispatch.request_id() != context.request_id()
            || dispatch.request_id() != self.dispatch.request_id()
            || dispatch.attempt() != self.dispatch.attempt()
            || self
                .dispatch
                .caller_capability_sha256()
                .is_some_and(|expected| dispatch.caller_capability_sha256() != Some(expected))
        {
            return Err(refused());
        }
        let wire = chio_core_types::canonical_json_bytes(&arguments).map_err(|_| refused())?;
        let _: chio_security_types::recovery::RecoverySupportIssueInputV1 =
            decode_contract(&wire).map_err(|_| refused())?;
        // No lock crosses await. Taking the original permit is affine; a
        // prepared connection cannot submit a second time or reacquire a slot.
        let permit = self
            .permit
            .lock()
            .map_err(|_| refused())?
            .take()
            .ok_or_else(refused)?;
        let request =
            self.connector
                .submit_request(dispatch.operation_id(), dispatch.attempt_id(), wire)?;
        // One request only. Operation correlation does not establish provider
        // deduplication. A network or delivery failure remains ambiguous.
        let response = self.connector.dispatch(request).await?;
        let created: IssueCreated = decode_contract(response.body()).map_err(|_| refused())?;
        let result = serde_json::to_value(created).map_err(|_| refused());
        drop(permit);
        result
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for PreparedSubmission {
    fn recovery_effect_contract(&self) -> Option<RecoveryEffectContractV1> {
        Some(self.connector.contract.clone())
    }
    fn server_id(&self) -> &str {
        &self.connector.server
    }
    fn tool_names(&self) -> Vec<String> {
        vec![self.connector.tool.clone()]
    }
    async fn prepare_invocation_connection(
        &self,
        _: &ToolDispatchContext,
    ) -> Result<Option<Arc<dyn ToolServerConnection>>, KernelError> {
        Err(refused())
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Err(refused())
    }
    async fn invoke_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.submit_once(context, arguments, nested).await
    }
    async fn invoke_with_cost_and_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(Value, Option<ToolInvocationCost>), KernelError> {
        Ok((self.submit_once(context, arguments, nested).await?, None))
    }
}
