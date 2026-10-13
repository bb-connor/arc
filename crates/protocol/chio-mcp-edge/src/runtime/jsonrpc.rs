use super::errors::JsonRpcProtocolErrorArgs;
use super::*;

fn chio_protocol_error_payload(
    code: i64,
    name: &str,
    transient: bool,
    retry_strategy: &str,
    guidance: &str,
) -> Value {
    json!({
        "code": code,
        "name": name,
        "category": "protocol",
        "transient": transient,
        "retry": {
            "strategy": retry_strategy,
            "guidance": guidance,
        }
    })
}

pub(super) fn jsonrpc_protocol_error(args: JsonRpcProtocolErrorArgs<'_>) -> Value {
    let JsonRpcProtocolErrorArgs {
        id,
        jsonrpc_code,
        message,
        chio_code,
        name,
        retry_strategy,
        guidance,
        context,
    } = args;
    let mut data = serde_json::Map::new();
    data.insert(
        "chioError".to_string(),
        chio_protocol_error_payload(chio_code, name, false, retry_strategy, guidance),
    );
    if let Some(context) = context.and_then(|value| value.as_object().cloned()) {
        for (key, value) in context {
            data.insert(key, value);
        }
    }
    jsonrpc_error_with_data(id, jsonrpc_code, message, Some(Value::Object(data)))
}

/// MCP 2025-11-25 lifecycle: when the requested revision is not served, the
/// server answers with one it does serve and the client decides whether to
/// continue. Only a malformed request is refused.
pub(super) fn negotiate_protocol_version(
    id: &Value,
    params: &Value,
) -> Result<&'static str, Value> {
    match params.get("protocolVersion") {
        None | Some(Value::String(_)) => Ok(MCP_PROTOCOL_VERSION),
        Some(_) => Err(jsonrpc_protocol_error(JsonRpcProtocolErrorArgs {
            id: id.clone(),
            jsonrpc_code: JSONRPC_INVALID_REQUEST,
            message: "initialize.params.protocolVersion must be a string",
            chio_code: CHIO_ERROR_INVALID_REQUEST_SHAPE,
            name: "invalid_request_shape",
            retry_strategy: "do_not_retry",
            guidance: "correct the initialize request shape before retrying",
            context: Some(json!({
                "parameter": "protocolVersion"
            })),
        })),
    }
}
