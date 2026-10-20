//! Streamable HTTP for MCP 2026-07-28: one self-contained POST per request,
//! with no protocol session in either direction.
//!
//! Each request runs in an ephemeral session built by the same factory as an
//! `initialize` session (auth snapshot, policy, kernel, receipts). The
//! ephemeral session is never published to the ledger, persisted or resumed.

use super::*;
use base64::Engine as _;
use chio_mcp_adapter::edge::stateless::{
    requested_protocol_version, unsupported_protocol_version_data, JSONRPC_HEADER_MISMATCH,
    JSONRPC_UNSUPPORTED_PROTOCOL_VERSION, STATELESS_PROTOCOL_VERSIONS,
};

const MCP_METHOD_HEADER: &str = "mcp-method";
const MCP_NAME_HEADER: &str = "mcp-name";
const BASE64_SENTINEL_PREFIX: &str = "=?base64?";
const BASE64_SENTINEL_SUFFIX: &str = "?=";
const JSONRPC_INVALID_REQUEST: i64 = -32600;
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;

/// Whether a POST asks for the stateless revision, by body or by header.
pub(super) fn is_stateless_post(headers: &HeaderMap, message: &Value) -> bool {
    requested_protocol_version(message).is_some()
        || header_str(headers, MCP_PROTOCOL_VERSION_HEADER)
            .is_some_and(|version| STATELESS_PROTOCOL_VERSIONS.contains(&version))
}

pub(super) async fn handle_post(
    state: RemoteAppState,
    auth_context: SessionAuthContext,
    headers: &HeaderMap,
    names_session: bool,
    message: Value,
) -> Response {
    let error_id = message.get("id").cloned().unwrap_or(Value::Null);
    if names_session {
        return header_mismatch(
            error_id,
            "MCP-Session-Id is not part of a stateless protocol revision",
        );
    }
    if let Err(response) = validate_request_headers(headers, &message, &error_id) {
        return response;
    }
    let Some(request_id) = message.get("id").cloned() else {
        // No client notification has a meaning without a session to carry it.
        return response_with_mode(
            StatusCode::ACCEPTED.into_response(),
            "stateless_notification",
        );
    };

    let session = match state.factory.spawn_session(auth_context) {
        Ok(session) => session,
        Err(error) => return spawn_session_error(error),
    };
    let response = dispatch(&session, message, &request_id).await;
    session.worker_serving_closed.send_replace(true);
    if let Err(error) = session.shutdown_upstream_transport() {
        warn!(session_id = %session.session_id, error = %error,
            "stateless MCP request upstream shutdown failed");
    }
    let status = match response
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_i64)
    {
        Some(
            JSONRPC_INVALID_REQUEST
            | JSONRPC_HEADER_MISMATCH
            | JSONRPC_UNSUPPORTED_PROTOCOL_VERSION,
        ) => StatusCode::BAD_REQUEST,
        Some(JSONRPC_METHOD_NOT_FOUND) => StatusCode::NOT_FOUND,
        _ => StatusCode::OK,
    };
    response_with_mode((status, Json(response)).into_response(), "stateless_json")
}

/// Send one request to its ephemeral session and wait for the terminal
/// response. Every failure after enqueue reports an uncertain effect.
async fn dispatch(session: &Arc<RemoteSession>, message: Value, request_id: &Value) -> Value {
    let uncertain = |reason: &str| {
        json!({"jsonrpc": "2.0", "id": request_id,
            "error": {"code": -32603, "message": format!("{reason}; effect is uncertain")}})
    };
    let mut event_rx = session.subscribe();
    if let Err(error) = session.send(message) {
        warn!(session_id = %session.session_id, error = %error,
            "stateless MCP request was not enqueued");
        return json!({"jsonrpc": "2.0", "id": request_id,
            "error": {"code": -32603, "message": "stateless MCP request was not enqueued"}});
    }
    let mut response_deadline = Box::pin(session.response_deadline());
    loop {
        let received = tokio::select! {
            biased;
            received = session_worker::receive(session, &mut event_rx) => received,
            () = response_deadline.as_mut() => {
                return uncertain("request response deadline exceeded");
            }
        };
        match received {
            Ok(event) if is_terminal_response_for_request(&event.message, request_id) => {
                return event.message;
            }
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => {
                return uncertain("session response was lost");
            }
            Err(broadcast::error::RecvError::Closed) => {
                return uncertain("session worker stopped");
            }
        }
    }
}

/// Mirrored headers must agree with the body (2026-07-28 Streamable HTTP,
/// Server Validation), and the body must name a served revision.
fn validate_request_headers(
    headers: &HeaderMap,
    message: &Value,
    error_id: &Value,
) -> Result<(), Response> {
    let mismatch = |detail: &str| header_mismatch(error_id.clone(), detail);
    let Some(header_version) = header_str(headers, MCP_PROTOCOL_VERSION_HEADER) else {
        return Err(mismatch(
            "MCP-Protocol-Version header is missing or malformed",
        ));
    };
    let Some(requested) = requested_protocol_version(message) else {
        return Err(mismatch(
            "MCP-Protocol-Version header names a stateless revision the body does not carry",
        ));
    };
    if requested.as_str() != Some(header_version) {
        return Err(mismatch(
            "MCP-Protocol-Version header does not match the body protocol version",
        ));
    }
    if !STATELESS_PROTOCOL_VERSIONS.contains(&header_version) {
        return Err(unsupported_protocol_version(error_id.clone(), requested));
    }

    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return Err(jsonrpc_http_error(
            StatusCode::BAD_REQUEST,
            JSONRPC_INVALID_REQUEST,
            "a stateless POST must carry a JSON-RPC request or notification",
        ));
    };
    if header_str(headers, MCP_METHOD_HEADER) != Some(method) {
        return Err(mismatch(
            "Mcp-Method header is missing or does not match the body method",
        ));
    }

    let name_field = match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        _ => None,
    };
    if let Some(field) = name_field {
        let body_name = message
            .get("params")
            .and_then(|params| params.get(field))
            .and_then(Value::as_str);
        let header_name = header_str(headers, MCP_NAME_HEADER).and_then(decode_header_value);
        if body_name.is_none() || header_name.as_deref() != body_name {
            return Err(mismatch(
                "Mcp-Name header is missing or does not match the body",
            ));
        }
    }
    Ok(())
}

fn header_str<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    headers
        .get(HeaderName::from_static(name))
        .and_then(|value| value.to_str().ok())
}

/// Decode the `=?base64?...?=` sentinel; any other value is taken literally.
fn decode_header_value(value: &str) -> Option<String> {
    let Some(encoded) = value
        .strip_prefix(BASE64_SENTINEL_PREFIX)
        .and_then(|rest| rest.strip_suffix(BASE64_SENTINEL_SUFFIX))
    else {
        return Some(value.to_string());
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn header_mismatch(id: Value, detail: &str) -> Response {
    let body = json!({"jsonrpc": "2.0", "id": id,
        "error": {"code": JSONRPC_HEADER_MISMATCH, "message": format!("Header mismatch: {detail}")}});
    response_with_mode(
        (StatusCode::BAD_REQUEST, Json(body)).into_response(),
        "stateless_refusal",
    )
}

fn unsupported_protocol_version(id: Value, requested: &Value) -> Response {
    let body = json!({"jsonrpc": "2.0", "id": id, "error": {
        "code": JSONRPC_UNSUPPORTED_PROTOCOL_VERSION,
        "message": "Unsupported protocol version",
        "data": unsupported_protocol_version_data(requested),
    }});
    response_with_mode(
        (StatusCode::BAD_REQUEST, Json(body)).into_response(),
        "stateless_refusal",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_values_decode_the_base64_sentinel_only() {
        assert_eq!(decode_header_value("echo").as_deref(), Some("echo"));
        assert_eq!(
            decode_header_value("=?base64?SGVsbG8sIOS4lueVjA==?=").as_deref(),
            Some("Hello, \u{4e16}\u{754c}")
        );
        assert_eq!(decode_header_value("=?base64?not base64?="), None);
    }
}
