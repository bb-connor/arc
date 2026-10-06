//! Shared bounded HTTP body ownership before MCP decoding.

use super::*;

pub(super) async fn read_limited_mcp_post_body(
    request: Request,
) -> Result<(HeaderMap, axum::body::Bytes), Response> {
    let headers = request.headers().clone();
    validate_mcp_post_content_length(&headers)?;
    match axum::body::to_bytes(request.into_body(), MCP_MAX_POST_BODY_BYTES).await {
        Ok(body) => Ok((headers, body)),
        Err(error) if error.to_string().contains("length limit") => Err(jsonrpc_http_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            -32600,
            &format!("request body exceeds {MCP_MAX_POST_BODY_BYTES}-byte limit"),
        )),
        Err(error) => Err(jsonrpc_http_error(
            StatusCode::BAD_REQUEST,
            -32700,
            &format!("failed to read request body: {error}"),
        )),
    }
}

pub(super) fn validate_mcp_post_content_length(headers: &HeaderMap) -> Result<(), Response> {
    let Some(value) = headers.get(axum::http::header::CONTENT_LENGTH) else {
        return Ok(());
    };
    let length = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            jsonrpc_http_error(StatusCode::BAD_REQUEST, -32600, "invalid Content-Length")
        })?;
    if length > MCP_MAX_POST_BODY_BYTES as u64 {
        return Err(jsonrpc_http_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            -32600,
            &format!("request body exceeds {MCP_MAX_POST_BODY_BYTES}-byte limit"),
        ));
    }
    Ok(())
}
