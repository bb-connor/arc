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

/// Result of hosted MCP protocol version negotiation.
pub(super) struct NegotiatedProtocolVersion {
    /// The revision the edge will speak for this session. Echoed in
    /// `result.protocolVersion`.
    pub(super) selected: &'static str,
    /// What the client asked for, when it asked for anything. Reported back
    /// under `chioProtocol` so a downgrade is observable instead of silent.
    pub(super) requested: Option<String>,
}

/// Negotiate the MCP protocol version for a hosted `initialize`.
///
/// The MCP lifecycle rule has been the same since 2024-11-05: if the server
/// supports the version the client requested it MUST respond with that same
/// version; otherwise it MUST respond with a version it does support, and the
/// client decides whether to continue or disconnect. Answering a version
/// mismatch with a JSON-RPC error is not one of the permitted outcomes, and in
/// practice it locked out nearly every deployed client, because
/// `@modelcontextprotocol/sdk` negotiated `2025-06-18` up to and including
/// 1.29.x while the edge accepted only `2025-11-25`.
///
/// The only remaining error is a structurally invalid request: a
/// `protocolVersion` that is present but not a string.
pub(super) fn negotiate_protocol_version(
    id: &Value,
    params: &Value,
) -> Result<NegotiatedProtocolVersion, Value> {
    let Some(requested) = params.get("protocolVersion") else {
        return Ok(NegotiatedProtocolVersion {
            selected: MCP_PROTOCOL_VERSION,
            requested: None,
        });
    };
    let Some(requested) = requested.as_str() else {
        return Err(jsonrpc_protocol_error(JsonRpcProtocolErrorArgs {
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
        }));
    };
    let selected = SUPPORTED_MCP_PROTOCOL_VERSIONS
        .iter()
        .copied()
        .find(|supported| *supported == requested)
        .unwrap_or(MCP_PROTOCOL_VERSION);
    Ok(NegotiatedProtocolVersion {
        selected,
        requested: Some(requested.to_string()),
    })
}
