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
