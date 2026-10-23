//! Session construction reads the enterprise provider registry for the resume
//! binding; a refused read answers the fixed 503 refusal and never the cause,
//! which names the registry path.

use super::enterprise_provider_freshness::{
    authenticate, jwt_verifier, signed_token, write_oversized_registry, write_registry, ISSUER,
};
use super::*;
use axum::body::Body;

struct Fixture {
    directory: tempfile::TempDir,
    registry_path: PathBuf,
    config: RemoteServeHttpConfig,
}

impl Fixture {
    fn with_enabled_provider() -> Self {
        let directory = chio_test_support::private_tempdir().unwrap();
        let registry_path = directory.path().join("enterprise-providers.json");
        write_registry(&registry_path, true);
        let mut config = test_remote_config();
        config.policy_path = directory.path().join("policy.yaml");
        std::fs::write(
            &config.policy_path,
            "capabilities:\n  default:\n    tools: []\n",
        )
        .unwrap();
        config.wrapped_args.clear();
        config.test_transport = Some(Arc::new(TestSessionTransport));
        config.enterprise_providers_file = Some(registry_path.clone());
        config.session_db_path = Some(directory.path().join("sessions.sqlite3"));
        config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(directory.path()));
        configure_signed_manifest(&mut config, directory.path());
        Self {
            directory,
            registry_path,
            config,
        }
    }

    fn static_bearer_state(&self) -> RemoteAppState {
        let config = self.config.clone();
        RemoteAppState {
            sessions: Arc::new(
                RemoteSessionLedger::new(
                    config.clock.clone(),
                    config.lifecycle_policy().unwrap(),
                    None,
                    None,
                )
                .unwrap(),
            ),
            factory: Arc::new(RemoteSessionFactory::new(config.clone()).unwrap()),
            auth_mode: Arc::new(RemoteAuthMode::StaticBearer {
                token: "remote-auth-token".into(),
            }),
            enterprise_provider_registry: enterprise_provider_registry_file(
                config.enterprise_providers_file.as_deref(),
                "remote_mcp",
            )
            .unwrap(),
            admin_token: None,
            protected_resource_metadata: None,
            authorization_server_metadata: None,
            local_auth_server: None,
        }
    }

    async fn assert_refusal_body(&self, response: Response, expected: &str) {
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(body, expected);
        let directory = self.directory.path().to_string_lossy();
        assert!(
            !body.contains(&*directory),
            "refusal body disclosed the registry path"
        );
    }
}

fn initialize_request() -> Request {
    let message = json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-11-25","capabilities":{},
            "clientInfo":{"name":"registry-spawn","version":"1"}}});
    Request::builder()
        .method("POST")
        .uri(MCP_ENDPOINT_PATH)
        .header(AUTHORIZATION, "Bearer remote-auth-token")
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&message).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn static_bearer_initialize_refuses_an_unreadable_registry_without_its_path() {
    let fixture = Fixture::with_enabled_provider();
    let state = fixture.static_bearer_state();
    std::fs::remove_file(&fixture.registry_path).unwrap();
    let response = handle_post(State(state.clone()), initialize_request()).await;
    fixture
        .assert_refusal_body(
            response,
            "urn:chio:error:transport:provider-registry-unreadable",
        )
        .await;
    assert!(state.sessions.active.lock().await.is_empty());
}

#[tokio::test]
async fn static_bearer_initialize_refuses_an_oversized_registry_without_its_path() {
    let fixture = Fixture::with_enabled_provider();
    let state = fixture.static_bearer_state();
    write_oversized_registry(&fixture.registry_path);
    let response = handle_post(State(state.clone()), initialize_request()).await;
    fixture
        .assert_refusal_body(
            response,
            "urn:chio:error:transport:provider-registry-oversized",
        )
        .await;
    assert!(state.sessions.active.lock().await.is_empty());
}

#[tokio::test]
async fn a_registry_corrupted_between_admission_and_spawn_refuses_the_session() {
    let fixture = Fixture::with_enabled_provider();
    let keypair = Keypair::generate();
    let mut config = fixture.config.clone();
    config.auth_token = None;
    config.auth_jwt_public_key = Some(keypair.public_key().to_hex());
    config.auth_jwt_issuer = Some(ISSUER.to_string());
    config.auth_jwt_audience = Some("chio-mcp".to_string());
    let verifier = jwt_verifier(&config);
    let factory = RemoteSessionFactory::new(config).unwrap();
    let admitted = authenticate(&verifier, &signed_token(&keypair)).unwrap();

    std::fs::write(&fixture.registry_path, b"{\"version\":").unwrap();
    let Err(error) = factory.spawn_session(admitted) else {
        panic!("a session spawned under a corrupted provider registry");
    };
    assert_eq!(error.to_string(), "urn:chio:error:cli:json");
    assert!(matches!(
        EnterpriseProviderRegistryRefusal::find(&error),
        Some(EnterpriseProviderRegistryRefusal::Invalid(_))
    ));
    fixture
        .assert_refusal_body(
            spawn_session_error(error),
            "urn:chio:error:transport:provider-registry-invalid",
        )
        .await;
}
