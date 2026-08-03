use super::receipts::record_receipt_write_error;
use super::receipts::record_receipt_write_kernel_error;
use super::*;

// Raw bridge execution is test-only. Production execution must enter through
// a registry-bound MCP session or the registry-bound cross-protocol executor.
/// Test request for projecting a Chio tool invocation through MCP session semantics.
#[derive(Debug, Clone)]
#[cfg(test)]
pub(super) struct BridgeMcpToolCallRequest {
    pub(super) request_id: String,
    pub(super) capability: CapabilityToken,
    pub(super) server_id: String,
    pub(super) tool_name: String,
    pub(super) arguments: Value,
    pub(super) agent_id: String,
    pub(super) execution_nonce: Option<SignedExecutionNonce>,
    pub(super) governed_intent: Option<GovernedTransactionIntent>,
    pub(super) approval_token: Option<GovernedApprovalToken>,
    pub(super) approval_tokens: Vec<GovernedApprovalToken>,
    pub(super) threshold_approval_proposal: Option<ThresholdApprovalProposal>,
    pub(super) model_metadata: Option<ModelMetadata>,
    pub(super) supplemental_authorization: Option<OpaqueSupplementalAuthorization>,
    pub(super) route_selection_metadata: Option<Value>,
    pub(super) peer_supports_chio_tool_streaming: bool,
}

#[cfg(test)]
impl BridgeMcpToolCallRequest {
    pub(super) fn to_tool_call_request(&self) -> Result<ToolCallRequest, AdapterError> {
        let request = ToolCallRequest {
            request_id: self.request_id.clone(),
            capability: self.capability.clone(),
            tool_name: self.tool_name.clone(),
            server_id: self.server_id.clone(),
            agent_id: self.agent_id.clone(),
            arguments: self.arguments.clone(),
            dpop_proof: None,
            execution_nonce: self.execution_nonce.clone(),
            governed_intent: self.governed_intent.clone(),
            approval_token: self.approval_token.clone(),
            approval_tokens: self.approval_tokens.clone(),
            threshold_approval_proposal: self.threshold_approval_proposal.clone(),
            model_metadata: self.model_metadata.clone(),
            supplemental_authorization: self.supplemental_authorization.clone(),
            federated_origin_kernel_id: None,
            declassification_grant: None,
        };
        request.validate().map_err(|error| {
            AdapterError::ParseError(format!("invalid MCP authorization context: {error}"))
        })?;
        Ok(request)
    }
}

/// MCP projection of an already evaluated kernel tool-call response.
///
/// Raw bridge request execution is deliberately unavailable to production
/// callers. Tool execution must enter through a registry-bound path.
///
/// ```compile_fail
/// use chio_mcp_edge::BridgeMcpToolCallRequest;
/// ```
///
/// ```compile_fail
/// use chio_mcp_edge::execute_bridge_mcp_tool_call;
/// ```
///
/// ```compile_fail
/// use chio_mcp_edge::execute_bridge_mcp_tool_call_async;
/// ```
#[derive(Debug)]
pub struct BridgeMcpToolCall {
    pub response: ToolCallResponse,
    pub mcp_result: Value,
    pub notifications: Vec<Value>,
}

impl BridgeMcpToolCall {
    /// Project a kernel tool-call response through the MCP bridge result surface.
    ///
    /// This is the production projection used by bridge execution and by
    /// hosts that already hold a kernel response, including PendingApproval.
    pub fn from_kernel_response(
        response: ToolCallResponse,
        request_id: &str,
        peer_supports_chio_tool_streaming: bool,
    ) -> Result<Self, AdapterError> {
        bridge_mcp_tool_call_from_response(
            response,
            request_id,
            peer_supports_chio_tool_streaming,
            true,
        )
    }
}

/// Default non-native protocol executor for MCP target projections.
#[derive(Debug, Default, Clone, Copy)]
pub struct McpTargetExecutor {
    pub peer_supports_chio_tool_streaming: bool,
}

impl TargetProtocolExecutor for McpTargetExecutor {
    fn target_protocol(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::Mcp
    }

    fn execute(
        &self,
        request: CrossProtocolTargetRequest<'_>,
    ) -> Result<CrossProtocolTargetExecution, BridgeError> {
        request
            .manifest_registry
            .validate_invocation_arguments(
                &request.execution.target_server_id,
                &request.execution.target_tool_name,
                &request.execution.bridge_security,
                &request.execution.arguments,
            )
            .map_err(|error| BridgeError::InvalidRequest(error.to_string()))?;
        let route_metadata = metadata_with_source_receipt_context(
            route_selection_metadata(request.route_selection)?,
            &request.execution.source_envelope,
        )?;
        let kernel_request = request.execution.to_tool_call_request();
        let evaluation = match (
            request.execution.security_context.as_ref(),
            request.execution.authenticated_session_id.as_ref(),
        ) {
            (Some(security_context), Some(authenticated_session_id)) => request
                .kernel
                .evaluate_tool_call_blocking_with_manifest_security_and_authenticated_session_context(
                    &kernel_request,
                    request.manifest_registry,
                    &request.execution.bridge_security,
                    Some(route_metadata),
                    authenticated_session_id,
                    security_context,
                ),
            (Some(security_context), None) => request
                .kernel
                .evaluate_tool_call_blocking_with_manifest_security_and_security_context(
                    &kernel_request,
                    request.manifest_registry,
                    &request.execution.bridge_security,
                    Some(route_metadata),
                    security_context,
                ),
            (None, _) => request
                .kernel
                .evaluate_tool_call_blocking_with_manifest_security(
                    &kernel_request,
                    request.manifest_registry,
                    &request.execution.bridge_security,
                    Some(route_metadata),
                ),
        };
        let response = match evaluation {
            Ok(response) => response,
            Err(error) => {
                record_receipt_write_kernel_error(&error);
                return Err(BridgeError::Kernel(error));
            }
        };
        let bridge = bridge_mcp_tool_call_from_response(
            response,
            &request.execution.kernel_request_id,
            self.peer_supports_chio_tool_streaming,
            false,
        )
        .map_err(|error| BridgeError::InvalidRequest(error.to_string()))?;
        let receipt_id = bridge.response.receipt.id.clone();

        Ok(CrossProtocolTargetExecution {
            response: bridge.response,
            protocol_result: Some(bridge.mcp_result),
            protocol_notifications: bridge.notifications,
            route_hops: vec![
                TargetExecutionHop {
                    protocol: DiscoveryProtocol::Mcp,
                    request_id: format!("{}:mcp", request.execution.kernel_request_id),
                    receipt_id: None,
                },
                TargetExecutionHop {
                    protocol: DiscoveryProtocol::Native,
                    request_id: request.execution.kernel_request_id.clone(),
                    receipt_id: Some(receipt_id),
                },
            ],
        })
    }
}

#[cfg(test)]
pub(super) async fn execute_bridge_mcp_tool_call_async(
    kernel: &ChioKernel,
    request: BridgeMcpToolCallRequest,
) -> Result<BridgeMcpToolCall, AdapterError> {
    let request_id = request.request_id.clone();
    let route_selection_metadata = request.route_selection_metadata.clone();
    let peer_supports_chio_tool_streaming = request.peer_supports_chio_tool_streaming;
    let kernel_request = request.to_tool_call_request()?;
    let response = match kernel
        .evaluate_tool_call_with_metadata(&kernel_request, route_selection_metadata)
        .await
    {
        Ok(response) => response,
        Err(error) => return Err(bridge_kernel_error(error)),
    };

    BridgeMcpToolCall::from_kernel_response(
        response,
        &request_id,
        peer_supports_chio_tool_streaming,
    )
}

#[cfg(test)]
pub(super) fn execute_bridge_mcp_tool_call(
    kernel: &ChioKernel,
    request: BridgeMcpToolCallRequest,
) -> Result<BridgeMcpToolCall, AdapterError> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| {
                handle.block_on(execute_bridge_mcp_tool_call_async(kernel, request))
            })
        }
        Ok(_) => {
            let kernel_request = request.to_tool_call_request()?;
            let response = match kernel.evaluate_tool_call_blocking_with_metadata(
                &kernel_request,
                request.route_selection_metadata.clone(),
            ) {
                Ok(response) => response,
                Err(error) => return Err(bridge_kernel_error(error)),
            };
            BridgeMcpToolCall::from_kernel_response(
                response,
                &request.request_id,
                request.peer_supports_chio_tool_streaming,
            )
        }
        Err(_) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| AdapterError::KernelRuntime(error.to_string()))?;
            runtime.block_on(execute_bridge_mcp_tool_call_async(kernel, request))
        }
    }
}

#[cfg(test)]
fn bridge_kernel_error(error: chio_kernel::KernelError) -> AdapterError {
    record_receipt_write_kernel_error(&error);
    match error {
        chio_kernel::KernelError::UrlElicitationsRequired {
            message,
            elicitations,
        } => AdapterError::McpError {
            code: JSONRPC_URL_ELICITATION_REQUIRED,
            message,
            data: Some(json!({ "elicitations": elicitations })),
        },
        other => AdapterError::KernelRuntime(other.to_string()),
    }
}

fn bridge_mcp_tool_call_from_response(
    response: ToolCallResponse,
    request_id: &str,
    peer_supports_chio_tool_streaming: bool,
    record_receipt_write: bool,
) -> Result<BridgeMcpToolCall, AdapterError> {
    let mut notifications = Vec::new();
    let mcp_result = kernel_response_to_tool_result(KernelResponseToToolResultArgs {
        pending_notifications: &mut notifications,
        request_id: &json!(request_id),
        output: response.output.clone(),
        reason: response.reason.clone(),
        verdict: response.verdict,
        terminal_state: &response.terminal_state,
        execution_nonce: response.execution_nonce.as_deref(),
        peer_supports_chio_tool_streaming,
        related_task_id: None,
    });

    if record_receipt_write {
        // Emit `chio_receipt_write_total` at the MCP receipt-sink
        // boundary. PendingApproval is normal HITL flow, so it must not feed
        // infrastructure error burn-rate numerators.
        crate::metrics::record_receipt_write_verdict(response.verdict);
    }

    Ok(BridgeMcpToolCall {
        response,
        mcp_result,
        notifications,
    })
}

pub(super) struct ToolCallRequestContext<'a> {
    pub(super) id: &'a Value,
    pub(super) session_id: &'a SessionId,
    pub(super) context: &'a OperationContext,
    pub(super) operation: &'a ToolCallOperation,
    pub(super) related_task_id: Option<&'a str>,
}

pub(super) struct KernelToolResultArgs<'a> {
    pub(super) client_request_id: &'a Value,
    pub(super) session_id: &'a SessionId,
    pub(super) output: Option<ToolCallOutput>,
    pub(super) reason: Option<String>,
    pub(super) verdict: Verdict,
    pub(super) terminal_state: &'a OperationTerminalState,
    pub(super) execution_nonce: Option<Box<SignedExecutionNonce>>,
    pub(super) related_task_id: Option<&'a str>,
}

impl ChioMcpEdge {
    fn resolve_security_invocation_context(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
    ) -> Result<Option<SecurityInvocationContext>, chio_kernel::KernelError> {
        match self.security_context_authority.as_ref() {
            Some(authority) => authority
                .resolve_security_invocation_context(context, operation)
                .map(Some),
            None if self.kernel.security_pre_dispatch_policy()
                == SecurityPreDispatchPolicy::Enforce =>
            {
                Err(chio_kernel::KernelError::GuardDenied(
                    "enforced MCP dispatch has no security invocation context authority"
                        .to_string(),
                ))
            }
            None => Ok(None),
        }
    }

    fn manifest_execution_binding(
        &self,
        operation: &ToolCallOperation,
    ) -> Result<
        Option<(
            Arc<chio_manifest::VerifiedManifestRegistry>,
            chio_manifest::BridgeSecurityMetadata,
        )>,
        chio_kernel::KernelError,
    > {
        let Some(registry) = self.manifest_registry.as_ref() else {
            return Ok(None);
        };
        let security = registry
            .bridge_security(&operation.server_id, &operation.tool_name)
            .ok_or_else(|| {
                chio_kernel::KernelError::InvalidReceiptMetadata(format!(
                    "verified manifest registry has no bridge security for {}/{}",
                    operation.server_id, operation.tool_name
                ))
            })?;
        Ok(Some((Arc::clone(registry), security)))
    }

    pub(super) fn prepare_tool_call_request(
        &mut self,
        id: &Value,
        params: &Value,
    ) -> Result<(SessionId, OperationContext, ToolCallOperation), Value> {
        let session_id = match &self.state {
            EdgeState::Ready { session_id } => session_id.clone(),
            _ => {
                return Err(jsonrpc_error(
                    id.clone(),
                    JSONRPC_SERVER_NOT_INITIALIZED,
                    "tools/call requires initialize followed by notifications/initialized",
                ))
            }
        };

        let tool_name = match params.get("name").and_then(Value::as_str) {
            Some(name) => name,
            None => {
                return Err(jsonrpc_error(
                    id.clone(),
                    JSONRPC_INVALID_PARAMS,
                    "tools/call requires a tool name",
                ))
            }
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let model_metadata = parse_request_model_metadata(id, params)?;
        let execution_nonce = parse_request_execution_nonce(id, params)?;
        let governed_intent = parse_request_governed_intent(id, params)?;
        let supplemental_authorization = parse_request_supplemental_authorization(id, params)?;
        let (approval_token, approval_tokens, threshold_approval_proposal) =
            parse_request_approval_artifacts(id, params)?;
        if parse_request_stable_request_id(id, params)?.is_none()
            && (approval_token.is_some()
                || !approval_tokens.is_empty()
                || threshold_approval_proposal.is_some()
                || supplemental_authorization.is_some())
        {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "MCP approval artifacts and supplemental authorization require \
                 _meta.chioRequestId",
            ));
        }
        let extra_metadata = parse_request_extra_metadata(id, params)?;

        let Some(&tool_index) = self.tool_index.get(tool_name) else {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "unknown tool",
            ));
        };
        let binding = self.tools[tool_index].clone();
        if !arguments.is_object() {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "tool arguments must be a JSON object",
            ));
        }
        if !binding.input_validator.is_valid(&arguments) {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "tool arguments do not match the admitted input schema",
            ));
        }

        let capability = match select_capability_for_request(
            &self.capabilities,
            &binding.tool_name,
            &binding.server_id,
            &arguments,
            model_metadata.as_ref(),
        ) {
            Some(capability) => capability,
            None => {
                self.emit_log(
                    LogLevel::Warning,
                    "chio.mcp.tools",
                    json!({
                        "event": "tool_denied",
                        "tool": binding.tool_name,
                        "server": binding.server_id,
                    }),
                );
                return Err(jsonrpc_result(
                    id.clone(),
                    tool_error_result("tool is not authorized by the active capability set"),
                ));
            }
        };

        let nonce_bound_request_id = execution_nonce
            .as_ref()
            .map(|nonce| nonce.nonce.bound_to.request_id.as_str());
        let context = build_operation_context_for_retry(
            id,
            session_id.clone(),
            &self.agent_id,
            "tools/call",
            params,
            nonce_bound_request_id,
        )?;
        let execution_nonce = execution_nonce
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| {
                jsonrpc_error(
                    id.clone(),
                    JSONRPC_INVALID_REQUEST,
                    &format!("failed to serialize execution nonce: {error}"),
                )
            })?;
        let operation = ToolCallOperation {
            capability,
            server_id: binding.server_id,
            tool_name: binding.tool_name,
            arguments,
            supplemental_authorization,
            governed_intent,
            approval_token,
            approval_tokens,
            threshold_approval_proposal,
            execution_nonce,
            model_metadata,
            extra_metadata,
            declassification_grant: None,
        };
        operation.validate().map_err(|error| {
            jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                &format!("invalid MCP authorization context: {error}"),
            )
        })?;
        validate_execution_feature_negotiation(
            &self.trusted_peer_negotiation,
            &operation.capability,
            operation.governed_intent.as_ref(),
            operation.approval_token.as_ref(),
            &operation.approval_tokens,
            operation.threshold_approval_proposal.as_ref(),
            operation.supplemental_authorization.as_ref(),
        )
        .map_err(|error| {
            jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                &format!("MCP authorization context is not negotiated: {error}"),
            )
        })?;

        Ok((session_id, context, operation))
    }

    pub(super) fn evaluate_tool_call_operation(
        &mut self,
        id: &Value,
        session_id: &SessionId,
        context: &OperationContext,
        operation: &ToolCallOperation,
        related_task_id: Option<&str>,
    ) -> ToolCallEdgeOutcome {
        let security_context = match self.resolve_security_invocation_context(context, operation) {
            Ok(context) => context,
            Err(error) => return self.tool_call_error_outcome(session_id, error, related_task_id),
        };
        let manifest_binding = match self.manifest_execution_binding(operation) {
            Ok(binding) => binding,
            Err(error) => return self.tool_call_error_outcome(session_id, error, related_task_id),
        };
        let operation = SessionOperation::ToolCall(Box::new(operation.clone()));
        let evaluation = match (manifest_binding, security_context.as_ref()) {
            (Some((registry, security)), Some(security_context)) => self
                .kernel
                .evaluate_session_operation_with_manifest_security_and_security_context(
                    context,
                    &operation,
                    registry.as_ref(),
                    &security,
                    security_context,
                ),
            (Some((registry, security)), None) => self
                .kernel
                .evaluate_session_operation_with_manifest_security(
                    context,
                    &operation,
                    registry.as_ref(),
                    &security,
                ),
            (None, Some(security_context)) => self
                .kernel
                .evaluate_session_operation_with_security_context(
                    context,
                    &operation,
                    security_context,
                ),
            (None, None) => self.kernel.evaluate_session_operation(context, &operation),
        };
        match evaluation {
            Ok(SessionOperationResponse::ToolCall(response)) => self
                .tool_result_for_kernel_response(KernelToolResultArgs {
                    client_request_id: id,
                    session_id,
                    output: response.output,
                    reason: response.reason,
                    verdict: response.verdict,
                    terminal_state: &response.terminal_state,
                    execution_nonce: response.execution_nonce,
                    related_task_id,
                }),
            Ok(
                SessionOperationResponse::RootList { .. }
                | SessionOperationResponse::ResourceList { .. }
                | SessionOperationResponse::ResourceRead { .. }
                | SessionOperationResponse::ResourceReadDenied { .. }
                | SessionOperationResponse::ResourceTemplateList { .. }
                | SessionOperationResponse::PromptList { .. }
                | SessionOperationResponse::PromptGet { .. }
                | SessionOperationResponse::Completion { .. }
                | SessionOperationResponse::CapabilityList { .. }
                | SessionOperationResponse::Heartbeat,
            ) => ToolCallEdgeOutcome::JsonRpcError {
                code: JSONRPC_INTERNAL_ERROR,
                message: "unexpected kernel response type".to_string(),
                data: None,
            },
            Err(error) => {
                self.emit_log_with_related_task(
                    LogLevel::Error,
                    "chio.mcp.tools",
                    json!({
                        "event": "tool_failed",
                        "error": error.to_string(),
                    }),
                    related_task_id,
                );
                self.tool_call_error_outcome(session_id, error, related_task_id)
            }
        }
    }

    pub(super) fn evaluate_tool_call_operation_with_transport<
        R: BufRead + Send,
        W: Write + Send,
    >(
        &mut self,
        request: ToolCallRequestContext<'_>,
        reader: &mut R,
        writer: &mut W,
    ) -> ToolCallEdgeOutcome {
        let ToolCallRequestContext {
            id,
            session_id,
            context,
            operation,
            related_task_id,
        } = request;
        let security_context = match self.resolve_security_invocation_context(context, operation) {
            Ok(context) => context,
            Err(error) => return self.tool_call_error_outcome(session_id, error, related_task_id),
        };
        let manifest_binding = match self.manifest_execution_binding(operation) {
            Ok(binding) => binding,
            Err(error) => return self.tool_call_error_outcome(session_id, error, related_task_id),
        };
        let mut parent_progress_step = 0;
        let mut accepted_url_elicitations = Vec::new();
        let mut nested_flow_client = EdgeNestedFlowClient {
            request_counter: &mut self.client_request_counter,
            parent_progress_step: &mut parent_progress_step,
            parent_client_request_id: id,
            parent_kernel_request_id: &context.request_id,
            pending_notifications: &mut self.pending_notifications,
            deferred_client_messages: &mut self.deferred_client_messages,
            accepted_url_elicitations: &mut accepted_url_elicitations,
            logging_enabled: self.config.logging_enabled,
            minimum_log_level: self.minimum_log_level,
            related_task_id,
            reader,
            writer,
        };

        let evaluation = match (manifest_binding, security_context.as_ref()) {
            (Some((registry, security)), Some(security_context)) => self
                .kernel
                .evaluate_tool_call_operation_with_nested_flow_client_and_manifest_security_and_security_context(
                    context,
                    operation,
                    &mut nested_flow_client,
                    registry.as_ref(),
                    &security,
                    security_context,
                ),
            (Some((registry, security)), None) => self
                .kernel
                .evaluate_tool_call_operation_with_nested_flow_client_and_manifest_security(
                    context,
                    operation,
                    &mut nested_flow_client,
                    registry.as_ref(),
                    &security,
                ),
            (None, Some(security_context)) => self
                .kernel
                .evaluate_tool_call_operation_with_nested_flow_client_and_security_context(
                    context,
                    operation,
                    &mut nested_flow_client,
                    security_context,
                ),
            (None, None) => self
                .kernel
                .evaluate_tool_call_operation_with_nested_flow_client(
                    context,
                    operation,
                    &mut nested_flow_client,
                ),
        };
        let outcome = match evaluation {
            Ok(response) => self.tool_result_for_kernel_response(KernelToolResultArgs {
                client_request_id: id,
                session_id,
                output: response.output,
                reason: response.reason,
                verdict: response.verdict,
                terminal_state: &response.terminal_state,
                execution_nonce: response.execution_nonce,
                related_task_id,
            }),
            Err(error) => {
                self.emit_log_with_related_task(
                    LogLevel::Error,
                    "chio.mcp.tools",
                    json!({
                        "event": "tool_failed",
                        "error": error.to_string(),
                    }),
                    related_task_id,
                );
                self.tool_call_error_outcome(session_id, error, related_task_id)
            }
        };
        self.persist_accepted_url_elicitations(session_id, accepted_url_elicitations);
        outcome
    }

    pub(super) fn evaluate_tool_call_operation_with_transport_channel<W: Write>(
        &mut self,
        request: ToolCallRequestContext<'_>,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> ToolCallEdgeOutcome {
        let ToolCallRequestContext {
            id,
            session_id,
            context,
            operation,
            related_task_id,
        } = request;
        let security_context = match self.resolve_security_invocation_context(context, operation) {
            Ok(context) => context,
            Err(error) => return self.tool_call_error_outcome(session_id, error, related_task_id),
        };
        let manifest_binding = match self.manifest_execution_binding(operation) {
            Ok(binding) => binding,
            Err(error) => return self.tool_call_error_outcome(session_id, error, related_task_id),
        };
        let mut parent_progress_step = 0;
        let mut accepted_url_elicitations = Vec::new();
        let mut nested_flow_client = QueuedEdgeNestedFlowClient {
            request_counter: &mut self.client_request_counter,
            parent_progress_step: &mut parent_progress_step,
            parent_client_request_id: id,
            parent_kernel_request_id: &context.request_id,
            pending_notifications: &mut self.pending_notifications,
            deferred_client_messages: &mut self.deferred_client_messages,
            accepted_url_elicitations: &mut accepted_url_elicitations,
            logging_enabled: self.config.logging_enabled,
            minimum_log_level: self.minimum_log_level,
            related_task_id,
            client_rx,
            cancel_rx,
            writer,
        };

        let evaluation = match (manifest_binding, security_context.as_ref()) {
            (Some((registry, security)), Some(security_context)) => self
                .kernel
                .evaluate_tool_call_operation_with_nested_flow_client_and_manifest_security_and_security_context(
                    context,
                    operation,
                    &mut nested_flow_client,
                    registry.as_ref(),
                    &security,
                    security_context,
                ),
            (Some((registry, security)), None) => self
                .kernel
                .evaluate_tool_call_operation_with_nested_flow_client_and_manifest_security(
                    context,
                    operation,
                    &mut nested_flow_client,
                    registry.as_ref(),
                    &security,
                ),
            (None, Some(security_context)) => self
                .kernel
                .evaluate_tool_call_operation_with_nested_flow_client_and_security_context(
                    context,
                    operation,
                    &mut nested_flow_client,
                    security_context,
                ),
            (None, None) => self
                .kernel
                .evaluate_tool_call_operation_with_nested_flow_client(
                    context,
                    operation,
                    &mut nested_flow_client,
                ),
        };
        let outcome = match evaluation {
            Ok(response) => self.tool_result_for_kernel_response(KernelToolResultArgs {
                client_request_id: id,
                session_id,
                output: response.output,
                reason: response.reason,
                verdict: response.verdict,
                terminal_state: &response.terminal_state,
                execution_nonce: response.execution_nonce,
                related_task_id,
            }),
            Err(error) => {
                self.emit_log_with_related_task(
                    LogLevel::Error,
                    "chio.mcp.tools",
                    json!({
                        "event": "tool_failed",
                        "error": error.to_string(),
                    }),
                    related_task_id,
                );
                self.tool_call_error_outcome(session_id, error, related_task_id)
            }
        };
        self.persist_accepted_url_elicitations(session_id, accepted_url_elicitations);
        outcome
    }
    pub(super) fn handle_tools_call(&mut self, id: Value, params: Value) -> Value {
        let (session_id, context, operation) = match self.prepare_tool_call_request(&id, &params) {
            Ok(parts) => parts,
            Err(response) => return response,
        };
        let requested_task = match parse_requested_task(&id, &params) {
            Ok(requested_task) => requested_task,
            Err(response) => return response,
        };
        if let Some(requested_task) = requested_task {
            return self.create_tool_call_task(
                id,
                session_id,
                context,
                operation,
                requested_task,
                true,
            );
        }

        tool_call_outcome_to_jsonrpc(
            id.clone(),
            self.evaluate_tool_call_operation(&id, &session_id, &context, &operation, None),
        )
    }

    // Reader/writer transport variant dispatched from `handle_request_with_transport`.
    pub(super) fn handle_tools_call_with_transport<R: BufRead + Send, W: Write + Send>(
        &mut self,
        id: Value,
        params: Value,
        reader: &mut R,
        writer: &mut W,
    ) -> Value {
        let (session_id, context, operation) = match self.prepare_tool_call_request(&id, &params) {
            Ok(parts) => parts,
            Err(response) => return response,
        };
        let requested_task = match parse_requested_task(&id, &params) {
            Ok(requested_task) => requested_task,
            Err(response) => return response,
        };
        if let Some(requested_task) = requested_task {
            return self.create_tool_call_task(
                id,
                session_id,
                context,
                operation,
                requested_task,
                false,
            );
        }

        tool_call_outcome_to_jsonrpc(
            id.clone(),
            self.evaluate_tool_call_operation_with_transport(
                ToolCallRequestContext {
                    id: &id,
                    session_id: &session_id,
                    context: &context,
                    operation: &operation,
                    related_task_id: None,
                },
                reader,
                writer,
            ),
        )
    }

    pub(super) fn handle_tools_call_with_transport_channel<W: Write>(
        &mut self,
        id: Value,
        params: Value,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Value {
        let (session_id, context, operation) = match self.prepare_tool_call_request(&id, &params) {
            Ok(parts) => parts,
            Err(response) => return response,
        };
        let requested_task = match parse_requested_task(&id, &params) {
            Ok(requested_task) => requested_task,
            Err(response) => return response,
        };
        if let Some(requested_task) = requested_task {
            return self.create_tool_call_task(
                id,
                session_id,
                context,
                operation,
                requested_task,
                true,
            );
        }

        tool_call_outcome_to_jsonrpc(
            id.clone(),
            self.evaluate_tool_call_operation_with_transport_channel(
                ToolCallRequestContext {
                    id: &id,
                    session_id: &session_id,
                    context: &context,
                    operation: &operation,
                    related_task_id: None,
                },
                client_rx,
                cancel_rx,
                writer,
            ),
        )
    }
    pub(super) fn tool_result_for_kernel_response(
        &mut self,
        args: KernelToolResultArgs<'_>,
    ) -> ToolCallEdgeOutcome {
        let KernelToolResultArgs {
            client_request_id,
            session_id,
            output,
            reason,
            verdict,
            terminal_state,
            execution_nonce,
            related_task_id,
        } = args;
        let peer_supports_chio_tool_streaming = self.peer_supports_chio_tool_streaming(session_id);
        crate::metrics::record_receipt_write_verdict(verdict);
        let result = kernel_response_to_tool_result(KernelResponseToToolResultArgs {
            pending_notifications: &mut self.pending_notifications,
            request_id: client_request_id,
            output,
            reason,
            verdict,
            terminal_state,
            execution_nonce: execution_nonce.as_deref(),
            peer_supports_chio_tool_streaming,
            related_task_id,
        });

        if let Some(reason) = cancellation_reason_from_tool_result(&result) {
            return ToolCallEdgeOutcome::Cancelled { reason };
        }

        match terminal_state {
            OperationTerminalState::Cancelled { reason } => ToolCallEdgeOutcome::Cancelled {
                reason: reason.clone(),
            },
            _ => ToolCallEdgeOutcome::Result(result),
        }
    }

    pub(super) fn tool_call_error_outcome(
        &mut self,
        session_id: &SessionId,
        error: chio_kernel::KernelError,
        related_task_id: Option<&str>,
    ) -> ToolCallEdgeOutcome {
        match error {
            chio_kernel::KernelError::RequestCancelled { reason, .. } => {
                ToolCallEdgeOutcome::Cancelled { reason }
            }
            chio_kernel::KernelError::UrlElicitationsRequired {
                message,
                elicitations,
            } => {
                if let Err(register_error) = self.kernel.register_session_required_url_elicitations(
                    session_id,
                    &elicitations,
                    related_task_id,
                ) {
                    self.emit_log_with_related_task(
                        LogLevel::Warning,
                        "chio.mcp.elicitation",
                        json!({
                            "event": "session_elicitation_registration_failed",
                            "error": register_error.to_string(),
                        }),
                        related_task_id,
                    );
                }
                ToolCallEdgeOutcome::JsonRpcError {
                    code: JSONRPC_URL_ELICITATION_REQUIRED,
                    message,
                    data: Some(json!({ "elicitations": elicitations })),
                }
            }
            other => {
                record_receipt_write_error();
                ToolCallEdgeOutcome::Result(tool_error_result(&other.to_string()))
            }
        }
    }

    pub(super) fn persist_accepted_url_elicitations(
        &mut self,
        session_id: &SessionId,
        accepted_url_elicitations: Vec<AcceptedUrlElicitation>,
    ) {
        for accepted in accepted_url_elicitations {
            if let Err(error) = self.kernel.register_session_pending_url_elicitation(
                session_id,
                accepted.elicitation_id,
                accepted.related_task_id,
            ) {
                self.emit_log(
                    LogLevel::Warning,
                    "chio.mcp.elicitation",
                    json!({
                        "event": "session_elicitation_registration_failed",
                        "error": error.to_string(),
                    }),
                );
            }
        }
    }
}
