//! Shared operator/tool-server credential gate. Peer location is not authority.

use super::*;
use subtle::ConstantTimeEq;

const MAX_CONTROL_TOKEN_BYTES: usize = 512;
const MAX_CONTROL_HEADER_SCAN_BYTES: usize = 64 * 1024;

/// Borrowed configuration, validated before it can drive credential comparison.
/// No Debug implementation: the inner bytes are a live operator credential.
struct ControlCredential<'a>(&'a str);

#[derive(Debug, thiserror::Error)]
#[error("sidecar control token must be a bearer token of at most 512 bytes")]
pub(crate) struct InvalidControlCredential;

impl<'a> ControlCredential<'a> {
    fn from_config(configured: Option<&'a str>) -> Result<Option<Self>, InvalidControlCredential> {
        let Some(token) = configured.map(str::trim).filter(|token| !token.is_empty()) else {
            return Ok(None);
        };
        // RFC 6750 section 2.1 b64token: nonempty alphabet, optional trailing '='.
        // The size limit is a local work bound, not a claim about token entropy.
        let unpadded = token.trim_end_matches('=');
        if token.len() > MAX_CONTROL_TOKEN_BYTES
            || unpadded.is_empty()
            || !unpadded.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
            })
        {
            return Err(InvalidControlCredential);
        }
        Ok(Some(Self(token)))
    }
}

pub(crate) fn validate_sidecar_control_token(
    configured: Option<&str>,
) -> Result<(), InvalidControlCredential> {
    ControlCredential::from_config(configured).map(|_| ())
}

#[derive(Debug)]
pub(crate) enum ProxyControlCredentialError {
    InvalidConfiguration,
    HeaderBudgetExceeded,
    ReservedCredential,
}

impl IntoResponse for ProxyControlCredentialError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::InvalidConfiguration => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "chio_control_configuration_invalid",
                "sidecar control credential configuration is invalid",
            ),
            Self::HeaderBudgetExceeded => (
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "chio_proxy_headers_too_large",
                "proxy header fields exceed the control credential scan budget",
            ),
            Self::ReservedCredential => (
                StatusCode::FORBIDDEN,
                "chio_control_credential_wrong_route",
                "sidecar control credentials cannot be sent to upstream proxy routes",
            ),
        };
        (
            status,
            axum::Json(serde_json::json!({ "error": code, "message": message })),
        )
            .into_response()
    }
}

/// Reject reserved control bytes before caller projection, body reads, admission
/// or egress. Scan original values, not a lossy single-value or UTF-8 map.
pub(crate) fn check_proxy_control_credential(
    headers: &axum::http::HeaderMap,
    configured: Option<&str>,
) -> Result<(), ProxyControlCredentialError> {
    let Some(credential) = ControlCredential::from_config(configured)
        .map_err(|_| ProxyControlCredentialError::InvalidConfiguration)?
    else {
        return Ok(());
    };
    // Check the complete budget before comparing secret bytes. Duplicate field
    // names count once per value, so both iteration count and comparison work
    // are bounded. There is no request-sized allocation in this check.
    let mut header_bytes = 0_usize;
    for (name, value) in headers {
        header_bytes = header_bytes
            .saturating_add(name.as_str().len())
            .saturating_add(value.len());
        if header_bytes > MAX_CONTROL_HEADER_SCAN_BYTES {
            return Err(ProxyControlCredentialError::HeaderBudgetExceeded);
        }
    }
    let secret = credential.0.as_bytes();
    let mut contained = subtle::Choice::from(0);
    for value in headers.values() {
        for candidate in value.as_bytes().windows(secret.len()) {
            // Constant-time complete comparisons, without a prefix-dependent
            // search or early return at the first match. Work depends on public
            // field lengths and configured token length, not matching prefixes.
            contained |= candidate.ct_eq(secret);
        }
    }
    if bool::from(contained) {
        Err(ProxyControlCredentialError::ReservedCredential)
    } else {
        Ok(())
    }
}

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
    let Ok(Some(expected)) = ControlCredential::from_config(Some(expected_bearer_token)) else {
        return false;
    };
    let mut authorization = request.headers().get_all(AUTHORIZATION).iter();
    let Some(header) = authorization.next() else {
        return false;
    };
    // Different HTTP components can select different values. Do not choose an
    // authority from an ambiguous header set, even if both values are identical.
    if authorization.next().is_some() {
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
        .is_some_and(|token| token.as_bytes().ct_eq(expected.0.as_bytes()).into())
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
