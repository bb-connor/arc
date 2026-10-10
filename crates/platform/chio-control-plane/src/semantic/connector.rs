use super::transport::canonical_endpoint;
use super::*;
use chio_kernel::{
    NestedFlowBridge, ToolDispatchContext, ToolInvocationContext, ToolInvocationCost,
    ToolServerConnection,
};
use chio_semantic_contracts::{project_semantic_fields, VerificationBudget};
use serde_json::Value;

#[cfg(test)]
pub(crate) fn submission_for_transport_test(
    request: SemanticTransportRequestV1,
) -> CapturedSemanticSubmissionV1 {
    CapturedSemanticSubmissionV1::new(request)
}

#[cfg(test)]
pub(crate) fn hold_submission_capacity_for_test(
    connector: &PinnedSemanticConnector,
) -> Result<tokio::sync::OwnedSemaphorePermit, KernelError> {
    let permits =
        u32::try_from(connector.inner.capacity.available_permits()).map_err(|_| refused())?;
    if permits == 0 {
        return Err(refused());
    }
    connector
        .inner
        .capacity
        .clone()
        .try_acquire_many_owned(permits)
        .map_err(|_| refused())
}

/// A single native submission, constructed only after the protected dispatch
/// check. Wire data and cloned request descriptions cannot construct this owner.
/// It is Send for the supervised kernel task and deliberately not Sync.
/// ```compile_fail
/// use chio_control_plane::semantic::CapturedSemanticSubmissionV1;
/// fn requires_sync<T: Sync>() {}
/// requires_sync::<CapturedSemanticSubmissionV1>();
/// ```
/// ```compile_fail
/// use chio_control_plane::semantic::CapturedSemanticSubmissionV1;
/// fn duplicate(value: CapturedSemanticSubmissionV1) { let _ = value.clone(); }
/// ```
/// ```compile_fail
/// use chio_control_plane::semantic::CapturedSemanticSubmissionV1;
/// fn parse() -> Result<CapturedSemanticSubmissionV1, serde_json::Error> { serde_json::from_str("{}") }
/// ```
pub struct CapturedSemanticSubmissionV1 {
    request: SemanticTransportRequestV1,
    _exclusive: core::marker::PhantomData<core::cell::Cell<()>>,
}
impl CapturedSemanticSubmissionV1 {
    fn new(request: SemanticTransportRequestV1) -> Self {
        Self {
            request,
            _exclusive: core::marker::PhantomData,
        }
    }
    pub fn request(&self) -> &SemanticTransportRequestV1 {
        &self.request
    }
    pub fn into_request(self) -> SemanticTransportRequestV1 {
        self.request
    }
}
impl std::fmt::Debug for CapturedSemanticSubmissionV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CapturedSemanticSubmissionV1([redacted])")
    }
}

pub struct PinnedSemanticConnector {
    inner: Arc<PinnedSemanticConnection>,
}
struct PinnedSemanticConnection {
    route: SemanticRouteV1,
    contract: SemanticOperationContractV1,
    store: Arc<SqliteAdmissionOperationStore>,
    transport: Arc<dyn SemanticTransport>,
    capacity: Arc<tokio::sync::Semaphore>,
}

/// A private one-use slot stays owned from reversible readiness through the
/// blocking capture check and the physical provider request.
struct PreparedSemanticConnector {
    inner: Arc<PinnedSemanticConnection>,
    dispatch: ToolDispatchContext,
    slot: std::sync::Mutex<Option<tokio::sync::OwnedSemaphorePermit>>,
}
impl std::fmt::Debug for PinnedSemanticConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinnedSemanticConnector([redacted])")
    }
}
impl PinnedSemanticConnector {
    pub fn new(
        route: SemanticRouteV1,
        contract: SemanticOperationContractV1,
        store: Arc<SqliteAdmissionOperationStore>,
        transport: Arc<dyn SemanticTransport>,
    ) -> Result<Self, KernelError> {
        chio_semantic_contracts::validate_semantic_channels(
            contract.channels.as_slice(),
            &mut VerificationBudget::new(4096).map_err(|_| refused())?,
        )
        .map_err(|_| refused())?;
        if route.operation != contract.operation
            || route.implementation != contract.implementation
            || route.input_schema != contract.input_schema
            || route.output_schema != contract.output_schema
        {
            return Err(refused());
        }
        for destination in route.destinations.as_slice() {
            canonical_endpoint(destination.endpoint.as_str())?;
            if destination.require_provider_precondition
                && contract.kind != SemanticOperationKindV1::FieldProjection
                && transport.precondition_guarantee()
                    != ProviderPreconditionGuaranteeV1::AtomicIfMatch
            {
                return Err(refused());
            }
        }
        Ok(Self {
            inner: Arc::new(PinnedSemanticConnection {
                route,
                contract,
                store,
                transport,
                capacity: Arc::new(tokio::sync::Semaphore::new(8)),
            }),
        })
    }
}
impl PinnedSemanticConnection {
    async fn invoke_native(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        nested: Option<&mut dyn NestedFlowBridge>,
        slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<Value, KernelError> {
        if nested.is_some()
            || context.server_id() != self.route.server.as_str()
            || context.tool_name() != self.route.tool.as_str()
        {
            return Err(refused());
        }
        let dispatch = context.dispatch().ok_or_else(refused)?;
        if dispatch.request_id() != context.request_id()
            || dispatch.caller_capability_sha256() != Some(context.capability_hash())
        {
            return Err(refused());
        }
        let store = self.store.clone();
        let operation = dispatch.operation_id().to_owned();
        let request_id = dispatch.request_id().to_owned();
        let capability = dispatch
            .caller_capability_sha256()
            .ok_or_else(refused)?
            .to_owned();
        let (captured, _slot) = tokio::task::spawn_blocking(move || {
            store
                .semantic_dispatch_capture(&operation, &request_id, &capability)
                .map(|captured| (captured, slot))
                .map_err(|_| refused())
        })
        .await
        .map_err(|_| refused())??;
        if captured.route != self.route
            || captured.contract != self.contract
            || serde_json::to_value(&captured.invocation).map_err(|_| refused())? != arguments
        {
            return Err(refused());
        }
        let output = if self.contract.kind == SemanticOperationKindV1::FieldProjection {
            project_semantic_fields(
                &captured.invocation.payload,
                self.contract.projection_fields.as_slice(),
                &mut VerificationBudget::new(4096).map_err(|_| refused())?,
            )
            .map_err(|_| refused())?
        } else {
            let destination = self
                .route
                .destinations
                .as_slice()
                .iter()
                .find(|dest| dest.destination == captured.invocation.action.destination)
                .ok_or_else(refused)?
                .clone();
            self.transport
                .submit(CapturedSemanticSubmissionV1::new(
                    SemanticTransportRequestV1 {
                        kind: self.contract.kind,
                        destination,
                        provider_version: captured
                            .invocation
                            .audience
                            .body()
                            .provider_version
                            .clone(),
                        operation: captured.operation_id,
                        attempt: SemanticProviderAttemptId::new(dispatch.attempt_id())
                            .map_err(|_| refused())?,
                        payload: captured.invocation.payload,
                    },
                ))
                .await
                .map_err(|_| refused())?
        };
        let bytes = chio_core_types::canonical_json_bytes(&output).map_err(|_| refused())?;
        if bytes.len() > MAX_RECOVERY_WIRE_BYTES {
            return Err(refused());
        }
        serde_json::to_value(output).map_err(|_| refused())
    }
}
#[async_trait::async_trait]
impl ToolServerConnection for PinnedSemanticConnector {
    fn server_id(&self) -> &str {
        self.inner.route.server.as_str()
    }
    fn tool_names(&self) -> Vec<String> {
        vec![self.inner.route.tool.as_str().into()]
    }
    fn tool_is_read_only(&self, tool: &str) -> bool {
        tool == self.inner.route.tool.as_str()
            && self.inner.contract.kind != SemanticOperationKindV1::IssueWrite
    }
    async fn prepare_invocation_connection(
        &self,
        context: &ToolDispatchContext,
    ) -> Result<Option<Arc<dyn ToolServerConnection>>, KernelError> {
        let slot = self
            .inner
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| refused())?;
        Ok(Some(Arc::new(PreparedSemanticConnector {
            inner: self.inner.clone(),
            dispatch: context.clone(),
            slot: std::sync::Mutex::new(Some(slot)),
        })))
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
        _: &ToolInvocationContext,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Err(refused())
    }
    async fn invoke_with_cost_and_context(
        &self,
        _: &ToolInvocationContext,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(Value, Option<ToolInvocationCost>), KernelError> {
        Err(refused())
    }
}

impl PreparedSemanticConnector {
    fn consume_slot(
        &self,
        context: &ToolInvocationContext,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, KernelError> {
        let dispatch = context.dispatch().ok_or_else(refused)?;
        // The kernel adds the caller capability hash after readiness. The
        // immutable request and entire provider attempt must remain identical.
        if dispatch.request_id() != self.dispatch.request_id()
            || dispatch.attempt() != self.dispatch.attempt()
            || context.request_id() != dispatch.request_id()
            || context.server_id() != self.inner.route.server.as_str()
            || context.tool_name() != self.inner.route.tool.as_str()
            || dispatch.caller_capability_sha256() != Some(context.capability_hash())
        {
            return Err(refused());
        }
        self.slot
            .lock()
            .map_err(|_| refused())?
            .take()
            .ok_or_else(refused)
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for PreparedSemanticConnector {
    fn server_id(&self) -> &str {
        self.inner.route.server.as_str()
    }
    fn tool_names(&self) -> Vec<String> {
        vec![self.inner.route.tool.as_str().into()]
    }
    fn tool_is_read_only(&self, tool: &str) -> bool {
        tool == self.inner.route.tool.as_str()
            && self.inner.contract.kind != SemanticOperationKindV1::IssueWrite
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
        let slot = self.consume_slot(context)?;
        self.inner
            .invoke_native(context, arguments, nested, slot)
            .await
    }
    async fn invoke_with_cost_and_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(Value, Option<ToolInvocationCost>), KernelError> {
        Ok((
            self.invoke_with_context(context, arguments, nested).await?,
            None,
        ))
    }
}
