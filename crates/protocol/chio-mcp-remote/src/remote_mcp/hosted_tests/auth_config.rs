#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::support::{
    base_remote_config, create_private_test_directory, local_oauth_test_client,
    reserve_listen_addr, unique_test_dir,
};
use crate::RemoteServeHttpConfig;

fn local_oauth_config() -> RemoteServeHttpConfig {
    let dir = unique_test_dir();
    create_private_test_directory(&dir);
    let listen = reserve_listen_addr();
    let mut config = base_remote_config(&dir, listen);
    let public_base_url = format!("http://{listen}");
    config.auth_server_seed_path = Some(dir.join("auth-server.seed"));
    config.auth_jwt_audience = Some(format!("{public_base_url}/mcp"));
    config.admin_token = Some("admin-token".to_string());
    config.public_base_url = Some(public_base_url);
    config.auth_scopes = vec!["mcp:invoke".to_string()];
    config.auth_clients = vec![local_oauth_test_client()];
    config
}

fn cli_refusal(message: &str) -> String {
    format!(
        "urn:chio:error:cli:other [cli:error]: {message} (Preserve the original message and migrate the call site to a specific registry code when touched.)"
    )
}

fn startup_refusal(config: RemoteServeHttpConfig) -> String {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("HTTP test runtime")
        .block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                crate::serve_http_async(config),
            )
            .await
        })
        .expect("edge must refuse to start instead of serving")
        .expect_err("edge must refuse to start")
        .to_string()
}

#[test]
fn public_base_url_rejects_non_https_non_loopback_scheme() {
    for public_base_url in [
        "http://edge.example",
        "http://10.0.0.7:8080",
        "http://0.0.0.0:8080",
        "ftp://edge.example",
    ] {
        let mut config = local_oauth_config();
        config.public_base_url = Some(public_base_url.to_string());
        assert_eq!(
            startup_refusal(config),
            cli_refusal(&format!(
                "--public-base-url must use https unless its host is loopback: {public_base_url}"
            ))
        );
    }
}

#[test]
fn remote_auth_config_rejects_offline_access_scope() {
    let mut config = local_oauth_config();
    config.auth_scopes = vec!["mcp:invoke".to_string(), "offline_access".to_string()];
    assert_eq!(
        startup_refusal(config),
        cli_refusal("--auth-scope must not include offline_access")
    );
}

#[test]
fn local_authorization_server_refuses_invalid_client_registrations() {
    let registration = |client_id: &str, redirect_uri: &str| crate::OAuthClientRegistration {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        token_endpoint_auth: crate::TokenEndpointAuth::None,
    };
    let cases = [
        (
            vec![],
            "--auth-server-seed-file requires at least one --auth-client".to_string(),
        ),
        (
            vec![registration(" ", "https://client.example/callback")],
            "--auth-client client_id must be non-empty with no surrounding whitespace: ` `"
                .to_string(),
        ),
        (
            vec![registration("app", "/callback")],
            "--auth-client redirect_uri is not an absolute URL: `/callback`".to_string(),
        ),
        (
            vec![registration("app", "https://client.example")],
            "--auth-client redirect_uri is not in canonical form: `https://client.example`"
                .to_string(),
        ),
        (
            vec![registration("app", "https://client.example/callback#done")],
            "--auth-client redirect_uri must not carry a fragment: `https://client.example/callback#done`"
                .to_string(),
        ),
        (
            vec![registration("app", "https://client.example/*")],
            "--auth-client redirect_uri must not contain a wildcard: `https://client.example/*`"
                .to_string(),
        ),
        (
            vec![registration("app", "http://client.example/callback")],
            "--auth-client redirect_uri must use https or http on a loopback host: `http://client.example/callback`"
                .to_string(),
        ),
        (
            vec![
                registration("app", "https://client.example/callback"),
                registration("app", "https://client.example/callback"),
            ],
            "--auth-client redirect_uri is registered twice for this client: `https://client.example/callback`"
                .to_string(),
        ),
    ];
    for (clients, expected) in cases {
        let mut config = local_oauth_config();
        config.auth_clients = clients;
        assert_eq!(startup_refusal(config), cli_refusal(&expected));
    }

    let mut config = local_oauth_config();
    config.auth_server_seed_path = None;
    config.auth_jwt_public_key = Some(chio_core::crypto::Keypair::generate().public_key().to_hex());
    config.auth_jwt_issuer = Some("https://issuer.example".to_string());
    assert_eq!(
        startup_refusal(config),
        cli_refusal("--auth-client requires --auth-server-seed-file")
    );
}

#[test]
fn oauth_edge_without_authorization_server_refuses_to_start() {
    let mut config = local_oauth_config();
    config.auth_server_seed_path = None;
    config.auth_clients = Vec::new();
    config.auth_jwt_public_key = Some(chio_core::crypto::Keypair::generate().public_key().to_hex());
    config.auth_jwt_issuer = None;
    config.auth_servers = Vec::new();
    assert_eq!(
        startup_refusal(config),
        cli_refusal(
            "bearer-authenticated remote MCP edge requires --auth-server or --auth-jwt-issuer so protected-resource metadata can advertise an authorization server"
        )
    );
}
