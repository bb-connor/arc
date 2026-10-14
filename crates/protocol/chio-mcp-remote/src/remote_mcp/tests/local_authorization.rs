use super::clock_custody::{reading, TestClock};
use super::*;

fn redirect_query(response: Response) -> Vec<(String, String)> {
    let location = response
        .headers()
        .get(axum::http::header::LOCATION)
        .expect("redirect has location")
        .to_str()
        .expect("location is valid header text")
        .to_string();
    Url::parse(&location)
        .expect("parse redirect location")
        .query_pairs()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

fn query_value<'a>(query: &'a [(String, String)], name: &str) -> Option<&'a str> {
    query
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

#[test]
fn local_authorization_server_denial_redirects_access_denied_without_code() {
    let server = test_local_authorization_server();
    let form = test_authorization_approval_form(&server, &test_authorization_request(), "deny");
    let denied = server
        .approve_authorization(form)
        .expect_err("denial answers with an error redirect");
    assert_eq!(denied.status(), StatusCode::SEE_OTHER);
    let query = redirect_query(denied);
    assert_eq!(query_value(&query, "error"), Some("access_denied"));
    assert_eq!(query_value(&query, "state"), Some("state-1"));
    assert_eq!(query_value(&query, "code"), None);
}

#[test]
fn local_authorization_server_redirect_carries_iss() {
    let server = test_local_authorization_server();
    let request = test_authorization_request();
    let approved = server
        .approve_authorization(test_authorization_approval_form(
            &server, &request, "approve",
        ))
        .expect("approval redirects with a code")
        .into_response();
    let denied = server
        .approve_authorization(test_authorization_approval_form(&server, &request, "deny"))
        .expect_err("denial redirects with an error");
    for response in [approved, denied] {
        let issuers = redirect_query(response)
            .into_iter()
            .filter(|(name, _)| name == "iss")
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        assert_eq!(issuers, vec![server.issuer.clone()]);
    }

    let directory = std::env::temp_dir().join(format!(
        "chio-local-authorization-{}-{}",
        std::process::id(),
        &Keypair::generate().public_key().to_hex()[..16]
    ));
    std::fs::create_dir_all(&directory).expect("create authorization server directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("secure authorization server directory");
    }
    let mut config = test_remote_config();
    config.auth_token = None;
    config.auth_server_seed_path = Some(directory.join("auth-server.seed"));
    config.admin_token = Some("admin-token".to_string());
    let metadata = build_authorization_server_metadata(
        &config,
        "127.0.0.1:8080".parse().expect("listen address"),
        None,
    )
    .expect("authorization server metadata")
    .expect("local authorization server publishes metadata");
    assert_eq!(
        metadata.document["authorization_response_iss_parameter_supported"],
        Value::Bool(true)
    );
}

fn oauth_refusal(response: Response) -> (StatusCode, OAuthError, String) {
    let cause = response
        .extensions()
        .get::<Arc<OAuthRejection>>()
        .expect("local OAuth cause")
        .clone();
    (
        response.status(),
        cause.kind,
        cause.local_detail().to_string(),
    )
}

fn page_refusal(
    server: &LocalAuthorizationServer,
    request: &AuthorizationRequest,
) -> (StatusCode, OAuthError, String) {
    let response = server
        .authorization_page(request)
        .expect_err("authorization request must be refused");
    assert!(response
        .headers()
        .get(axum::http::header::LOCATION)
        .is_none());
    oauth_refusal(response)
}

fn approved_code(server: &LocalAuthorizationServer) -> String {
    let mut request = test_authorization_request();
    request.code_challenge = Some(pkce_s256("verifier"));
    let form = test_authorization_approval_form(server, &request, "approve");
    authorization_code_from_redirect(server.approve_authorization(form).expect("approval"))
}

fn code_exchange(code: &str, overrides: Value) -> TokenRequestForm {
    let mut form = json!({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://client.example/callback",
        "client_id": "client-abc",
        "code_verifier": "verifier",
    });
    for (key, value) in overrides.as_object().expect("override object") {
        form[key] = value.clone();
    }
    serde_json::from_value(form).expect("token form")
}

fn exchange(server: &LocalAuthorizationServer, form: TokenRequestForm) -> Result<Value, Response> {
    server.exchange_authorization_code((&HeaderMap::new()).into(), form)
}

fn jwt_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("JWT payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("decode JWT payload"))
        .expect("JWT claims")
}

#[test]
fn local_authorization_server_rejects_missing_or_plain_code_challenge() {
    let server = test_local_authorization_server();
    let mut missing = test_authorization_request();
    missing.code_challenge = None;
    let mut empty = test_authorization_request();
    empty.code_challenge = Some(String::new());
    let mut plain = test_authorization_request();
    plain.code_challenge_method = Some("plain".to_string());
    let mut absent_method = test_authorization_request();
    absent_method.code_challenge_method = None;
    for (request, detail) in [
        (missing, "missing code_challenge"),
        (empty, "empty code_challenge"),
        (plain, "code_challenge_method must be S256"),
        (absent_method, "code_challenge_method must be S256"),
    ] {
        assert_eq!(
            page_refusal(&server, &request),
            (
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidRequest,
                detail.to_string()
            )
        );
    }

    let directory = std::env::temp_dir().join(format!(
        "chio-local-authorization-pkce-{}-{}",
        std::process::id(),
        &Keypair::generate().public_key().to_hex()[..16]
    ));
    std::fs::create_dir_all(&directory).expect("create authorization server directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("secure authorization server directory");
    }
    let mut config = test_remote_config();
    config.auth_token = None;
    config.auth_server_seed_path = Some(directory.join("auth-server.seed"));
    let metadata = build_authorization_server_metadata(
        &config,
        "127.0.0.1:8080".parse().expect("listen address"),
        None,
    )
    .expect("authorization server metadata")
    .expect("local authorization server publishes metadata");
    assert_eq!(
        metadata.document["code_challenge_methods_supported"],
        json!(["S256"])
    );
}

#[test]
fn local_authorization_server_rejects_missing_resource() {
    let server = test_local_authorization_server();
    let mut request = test_authorization_request();
    request.resource = None;
    assert_eq!(
        page_refusal(&server, &request),
        (
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidTarget,
            "missing resource parameter".to_string()
        )
    );
}

#[test]
fn local_authorization_server_rejects_token_resource_mismatch() {
    let server = test_local_authorization_server();
    let code = approved_code(&server);
    let refused = exchange(
        &server,
        code_exchange(&code, json!({"resource": "https://other.example/mcp"})),
    )
    .expect_err("a foreign resource must be refused");
    assert_eq!(
        oauth_refusal(refused),
        (
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidTarget,
            "resource parameter mismatch".to_string()
        )
    );
    assert!(exchange(
        &server,
        code_exchange(&code, json!({"resource": "https://edge.example/mcp"}))
    )
    .is_ok());
}

#[test]
fn local_authorization_server_codes_are_single_use_expiring_and_bound() {
    let server = test_local_authorization_server();
    let code = approved_code(&server);
    for (overrides, detail) in [
        (
            json!({"client_id": "client-other"}),
            "client_id or redirect_uri mismatch",
        ),
        (
            json!({"redirect_uri": "https://client.example/other"}),
            "client_id or redirect_uri mismatch",
        ),
        (
            json!({"code_verifier": "wrong"}),
            "PKCE verification failed",
        ),
    ] {
        assert_eq!(
            oauth_refusal(exchange(&server, code_exchange(&code, overrides)).expect_err("refused")),
            (
                StatusCode::BAD_REQUEST,
                OAuthError::InvalidGrant,
                detail.to_string()
            )
        );
    }
    assert!(exchange(&server, code_exchange(&code, json!({}))).is_ok());
    assert_eq!(
        oauth_refusal(
            exchange(&server, code_exchange(&code, json!({}))).expect_err("replay refused")
        ),
        (
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidGrant,
            "unknown authorization code".to_string()
        )
    );

    let source = Arc::new(TestClock(StdMutex::new(reading(1_000_000, 0))));
    let mut server = test_local_authorization_server();
    server.clock = RemoteClock::new(source.clone());
    let code = approved_code(&server);
    *source.0.lock().expect("test clock") =
        reading(1_000_000, server.code_ttl_secs * 1_000_000_000);
    assert_eq!(
        oauth_refusal(
            exchange(&server, code_exchange(&code, json!({}))).expect_err("expired code")
        ),
        (
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidGrant,
            "authorization code expired".to_string()
        )
    );
}

#[test]
fn local_authorization_server_access_token_lifetime_is_bounded() {
    let server = test_local_authorization_server();
    let code = approved_code(&server);
    let response = exchange(&server, code_exchange(&code, json!({}))).expect("token response");
    assert_eq!(response["expires_in"], json!(server.access_token_ttl_secs));
    let claims = jwt_claims(response["access_token"].as_str().expect("access token"));
    let issued_at = claims["iat"].as_u64().expect("iat");
    assert_eq!(
        claims["exp"].as_u64(),
        Some(issued_at + server.access_token_ttl_secs)
    );
}

#[test]
fn local_authorization_server_rejects_unsupported_and_widened_scopes() {
    let mut server = test_local_authorization_server();
    server.supported_scopes = vec!["mcp:invoke".to_string(), "tools.read".to_string()];
    let mut request = test_authorization_request();
    request.scope = Some("mcp:invoke admin".to_string());
    assert_eq!(
        page_refusal(&server, &request),
        (
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidScope,
            "requested scope is not supported".to_string()
        )
    );

    let code = approved_code(&server);
    let subject_token = exchange(&server, code_exchange(&code, json!({}))).expect("token response")
        ["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    let widened: TokenRequestForm = serde_json::from_value(json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": subject_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "scope": "mcp:invoke tools.read",
    }))
    .expect("token exchange form");
    assert_eq!(
        oauth_refusal(
            server
                .exchange_subject_token((&HeaderMap::new()).into(), widened)
                .expect_err("widened scope refused")
        ),
        (
            StatusCode::BAD_REQUEST,
            OAuthError::InvalidScope,
            "requested exchange scope exceeds subject token scope".to_string()
        )
    );
}
