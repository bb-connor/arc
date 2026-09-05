//! Shared operator/tool-server credential gate. Peer location is not authority.

use super::*;
use subtle::ConstantTimeEq;

pub(crate) async fn require_sidecar_control_middleware(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if let Err(response) =
        require_sidecar_control_request(&request, state.sidecar_control_token.as_deref())
    {
        return response;
    }
    next.run(request).await
}

/// Require a configured credential even for local callers. Untrusted agents may
/// share the listener's loopback interface or network namespace.
#[allow(clippy::result_large_err)]
pub(crate) fn require_sidecar_control_request(
    request: &Request<Body>,
    expected_bearer_token: Option<&str>,
) -> Result<(), Response> {
    let authorized = expected_bearer_token
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .is_some_and(|token| sidecar_control_bearer_token_matches(request, token));
    if authorized {
        Ok(())
    } else {
        // Never log presented credentials or disclose the configured value.
        warn!("rejecting sidecar control request without valid control credentials");
        Err(sidecar_control_forbidden_response())
    }
}

pub(crate) fn sidecar_control_bearer_token_matches(
    request: &Request<Body>,
    expected_bearer_token: &str,
) -> bool {
    let mut authorization = request.headers().get_all(AUTHORIZATION).iter();
    let Some(header) = authorization.next() else {
        return false;
    };
    // Different HTTP components can select different values. Do not choose an
    // authority from an ambiguous header set, even if both values are identical.
    if authorization.next().is_some() || expected_bearer_token.is_empty() {
        return false;
    }
    header
        .to_str()
        .ok()
        .and_then(|value| {
            let (scheme, token) = value.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then_some(token)
        })
        // Compare the complete credential, never prefixes or trimmed input.
        .is_some_and(|token| {
            token
                .as_bytes()
                .ct_eq(expected_bearer_token.as_bytes())
                .into()
        })
}

fn sidecar_control_forbidden_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "error": "chio_control_forbidden",
            "message": "sidecar control endpoints require a configured control token and valid bearer credentials",
        })),
    )
        .into_response()
}
