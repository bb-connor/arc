// JSON-RPC request-boundary parsing for the ACP edge.

#[derive(Debug)]
struct AcpJsonRpcEnvelope {
    id: Option<Value>,
    method: String,
    params: Value,
}

const ACP_JSONRPC_KNOWN_METHODS: &[&str] = &[
    "session/list_capabilities",
    "session/request_permission",
    "tool/invoke",
    "tool/stream",
    "tool/cancel",
    "tool/resume",
];

impl ChioAcpEdge {
    fn jsonrpc_serialized_response(
        id: Value,
        result: serde_json::Result<Value>,
    ) -> AcpJsonRpcResponse {
        match result {
            Ok(value) => {
                AcpJsonRpcResponse::response(json!({"jsonrpc": "2.0", "id": id, "result": value}))
            }
            Err(error) => Self::jsonrpc_error_response(id, error.into()),
        }
    }

    fn jsonrpc_error_response(id: Value, error: AcpEdgeError) -> AcpJsonRpcResponse {
        let code = if matches!(error, AcpEdgeError::UnknownMethod) {
            -32601
        } else if matches!(
            error,
            AcpEdgeError::InvalidRequest(
                AcpRequestError::InvalidId
                    | AcpRequestError::InvalidVersion
                    | AcpRequestError::MissingMethod
            )
        ) {
            -32600
        } else if matches!(
            error,
            AcpEdgeError::InvalidRequest(_) | AcpEdgeError::UntrustedInput(_)
        ) {
            -32602
        } else {
            -32603
        };
        let message = error.to_string();
        AcpJsonRpcResponse::with_error(
            json!({"jsonrpc":"2.0", "id":id, "error":{"code":code,"message":message}}),
            error,
        )
    }

    fn parse_jsonrpc_envelope(message: &Value) -> Result<AcpJsonRpcEnvelope, AcpEdgeError> {
        let id = message.get("id").cloned();
        if id
            .as_ref()
            .is_some_and(|id| !id.is_string() && !id.is_number() && !id.is_null())
        {
            return Err(AcpRequestError::InvalidId.into());
        }
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(AcpRequestError::InvalidVersion.into());
        }
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .ok_or(AcpRequestError::MissingMethod)?;
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        Ok(AcpJsonRpcEnvelope {
            id,
            method: method.to_owned(),
            params,
        })
    }

    fn ensure_jsonrpc_params_object_for_known_method(
        _id: &Value,
        method: &str,
        params: &Value,
        known_methods: &[&str],
    ) -> Result<(), AcpEdgeError> {
        if !known_methods.contains(&method) || params.is_object() {
            Ok(())
        } else {
            Err(AcpRequestError::ParamsObjectRequired.into())
        }
    }

    fn jsonrpc_permission_request(params: &Value) -> Result<PermissionRequest, AcpEdgeError> {
        Ok(PermissionRequest {
            capability_id: Self::jsonrpc_capability_id(params, "session/request_permission")?,
            arguments: Self::jsonrpc_arguments(params),
        })
    }

    fn jsonrpc_invocation_params(
        params: &Value,
        operation: &str,
    ) -> Result<(String, Value), AcpEdgeError> {
        Ok((
            Self::jsonrpc_capability_id(params, operation)?,
            Self::jsonrpc_arguments(params),
        ))
    }

    fn jsonrpc_task_id_params(params: &Value, _operation: &str) -> Result<String, AcpEdgeError> {
        Ok(request_error::validate_field(AcpField::TaskId, params.get("taskId"))?.to_owned())
    }

    fn jsonrpc_capability_id(params: &Value, _operation: &str) -> Result<String, AcpEdgeError> {
        Ok(
            request_error::validate_field(AcpField::CapabilityId, params.get("capabilityId"))?
                .to_owned(),
        )
    }

    fn jsonrpc_arguments(params: &Value) -> Value {
        params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}))
    }
}

const MAX_ACP_REQUEST_BYTES: usize = 8 * 1024 * 1024;
impl ChioAcpEdge {
    /// Validate bounded original bytes before projecting a request.
    pub fn handle_jsonrpc(
        &self,
        bytes: &[u8],
        kernel: &ChioKernel,
        execution: &AcpKernelExecutionContext,
    ) -> Result<AcpJsonRpcResponse, AcpEdgeError> {
        let message =
            chio_core::canonical::UntrustedJsonText::from_wire(bytes, MAX_ACP_REQUEST_BYTES)?
                .decode_signed()?;
        Ok(self.handle_jsonrpc_value(message, kernel, execution))
    }
}
