use super::*;

pub(super) fn pkce_s256(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

pub(super) fn generate_authorization_code() -> String {
    let entropy = Keypair::generate().public_key().to_hex();
    format!("code-{}", sha256_hex(entropy.as_bytes()))
}

pub(super) fn sign_jwt(keypair: &Keypair, claims: &serde_json::Value) -> Result<String, Response> {
    let encode = |value: &Value| {
        canonical_json_bytes(value)
            .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
            .map_err(|error| {
                crate::input::with_source(
                    oauth_token_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "token canonicalization failed",
                    ),
                    error,
                )
            })
    };
    let header =
        encode(&json!({"alg": "EdDSA", "typ": "JWT", "kid": jwk_key_id(&keypair.public_key())}))?;
    let payload = encode(claims)?;
    let signing_input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(keypair.sign(signing_input.as_bytes()).to_bytes());
    Ok(format!("{signing_input}.{signature}"))
}

pub(super) fn jwk_key_id(public_key: &PublicKey) -> String {
    let hex = public_key.to_hex();
    format!("chio-{}", &hex[..hex.len().min(16)])
}

pub(super) fn redirect_oauth_error(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
) -> Response {
    let mut redirect = match Url::parse(redirect_uri) {
        Ok(url) => url,
        Err(_) => return oauth_token_error(StatusCode::BAD_REQUEST, error, description),
    };
    {
        let mut pairs = redirect.query_pairs_mut();
        pairs.append_pair("error", error);
        pairs.append_pair("error_description", description);
        if let Some(state) = state {
            pairs.append_pair("state", state);
        }
    }
    Redirect::to(redirect.as_str()).into_response()
}

pub(super) fn oauth_token_error(status: StatusCode, error: &str, description: &str) -> Response {
    let mut response = (
        status,
        Json(json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

pub(super) fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
pub(super) fn unix_now() -> u64 {
    RemoteClock::default().seconds().expect("test clock")
}
#[cfg(test)]
pub(super) fn session_now_millis() -> u64 {
    RemoteClock::default().millis().expect("test clock")
}

pub(super) fn read_session_lifecycle_policy() -> SessionLifecyclePolicy {
    SessionLifecyclePolicy {
        idle_expiry_millis: read_env_u64(
            SESSION_IDLE_EXPIRY_ENV,
            DEFAULT_SESSION_IDLE_EXPIRY_MILLIS,
        ),
        drain_grace_millis: read_env_u64(
            SESSION_DRAIN_GRACE_ENV,
            DEFAULT_SESSION_DRAIN_GRACE_MILLIS,
        ),
        reaper_interval_millis: read_env_u64(
            SESSION_REAPER_INTERVAL_ENV,
            DEFAULT_SESSION_REAPER_INTERVAL_MILLIS,
        ),
        tombstone_retention_millis: read_env_u64(
            SESSION_TOMBSTONE_RETENTION_ENV,
            DEFAULT_SESSION_TOMBSTONE_RETENTION_MILLIS,
        ),
    }
}

pub(super) fn read_env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

pub(super) fn terminal_session_response(state: RemoteSessionState) -> Response {
    match state {
        RemoteSessionState::Initializing => {
            plain_http_error(StatusCode::CONFLICT, "MCP session is still initializing")
        }
        RemoteSessionState::Ready => plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "active session was resolved as terminal",
        ),
        RemoteSessionState::Draining => plain_http_error(
            StatusCode::CONFLICT,
            "MCP session is draining and must not be resumed",
        ),
        RemoteSessionState::Deleted => plain_http_error(
            StatusCode::GONE,
            "MCP session was deleted and must be re-initialized",
        ),
        RemoteSessionState::Expired => plain_http_error(
            StatusCode::GONE,
            "MCP session expired and must be re-initialized",
        ),
        RemoteSessionState::Closed => plain_http_error(
            StatusCode::GONE,
            "MCP session was shut down and must be re-initialized",
        ),
    }
}

pub(super) fn plain_http_error(status: StatusCode, message: &str) -> Response {
    (status, message.to_string()).into_response()
}

pub(super) fn jsonrpc_http_error(status: StatusCode, code: i64, message: &str) -> Response {
    let mut response = (
        status,
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message,
            }
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}
