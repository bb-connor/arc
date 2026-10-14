use super::*;

/// Every refusal here answers the client directly and never redirects: the
/// redirect URI is trusted only once it matches a registration exactly.
pub(super) fn validate_authorization_request(
    clock: &RemoteClock,
    request: &AuthorizationRequest,
    clients: &HashMap<String, HashSet<String>>,
    supported_scopes: &[String],
    expected_resource: &str,
) -> Result<String, Response> {
    if request.response_type != "code" {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            OAuthError::UnsupportedResponseType,
            "response_type must be code",
        ));
    }
    let redirect_uris = clients.get(&request.client_id).ok_or_else(|| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidRequest,
            "unknown client_id",
        )
    })?;
    if !redirect_uris.contains(&request.redirect_uri) {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidRequest,
            "redirect_uri is not registered for client_id",
        ));
    }
    let resource = request.resource.clone().ok_or_else(|| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidTarget,
            "missing resource parameter",
        )
    })?;
    if resource != expected_resource {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidTarget,
            "resource parameter must match the advertised protected resource",
        ));
    }
    let code_challenge = request.code_challenge.as_deref().ok_or_else(|| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidRequest,
            "missing code_challenge",
        )
    })?;
    if code_challenge.is_empty() {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidRequest,
            "empty code_challenge",
        ));
    }
    if request.code_challenge_method.as_deref() != Some("S256") {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidRequest,
            "code_challenge_method must be S256",
        ));
    }
    let _ = parse_request_time_authorization_details(request.authorization_details.as_deref())?;
    let _ =
        parse_request_time_transaction_context(clock, request.chio_transaction_context.as_deref())?;
    let _ = resolve_requested_scopes(request.scope.as_deref(), supported_scopes)?;
    Ok(resource)
}

pub(super) fn resolve_requested_scopes(
    requested_scope: Option<&str>,
    supported_scopes: &[String],
) -> Result<Vec<String>, Response> {
    let requested = requested_scope
        .unwrap_or_default()
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if supported_scopes.is_empty() {
        return Ok(requested);
    }
    let scopes = if requested.is_empty() {
        supported_scopes.to_vec()
    } else {
        requested
    };
    if scopes
        .iter()
        .all(|scope| supported_scopes.iter().any(|supported| supported == scope))
    {
        Ok(scopes)
    } else {
        Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidScope,
            "requested scope is not supported",
        ))
    }
}

pub(super) fn resolve_exchange_scopes(
    requested_scope: Option<&str>,
    subject_scopes: &[String],
    supported_scopes: &[String],
) -> Result<Vec<String>, Response> {
    let requested = resolve_requested_scopes(requested_scope, supported_scopes)?;
    let scopes = if requested.is_empty() {
        subject_scopes.to_vec()
    } else {
        requested
    };
    if scopes
        .iter()
        .all(|scope| subject_scopes.iter().any(|granted| granted == scope))
    {
        Ok(scopes)
    } else {
        Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidScope,
            "requested exchange scope exceeds subject token scope",
        ))
    }
}
