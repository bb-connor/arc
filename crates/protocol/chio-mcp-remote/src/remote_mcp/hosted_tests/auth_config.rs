#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::support::{
    base_remote_config, create_private_test_directory, reserve_listen_addr, unique_test_dir,
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
    config
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
            format!(
                "--public-base-url must use https unless its host is loopback: {public_base_url}"
            )
        );
    }
}

#[test]
fn remote_auth_config_rejects_offline_access_scope() {
    let mut config = local_oauth_config();
    config.auth_scopes = vec!["mcp:invoke".to_string(), "offline_access".to_string()];
    assert_eq!(
        startup_refusal(config),
        "--auth-scope must not include offline_access"
    );
}
