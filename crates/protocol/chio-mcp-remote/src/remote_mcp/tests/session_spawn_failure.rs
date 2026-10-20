//! A session construction failure other than a provider registry refusal
//! answers the fixed 500 URN on both the initialize and the stateless POST.
//! The cause can name local paths and store detail, so it stays in the log.

use super::*;
use axum::body::Body;

const SPAWN_FAILED: &str = "urn:chio:error:transport:session-spawn-failed";
const STATELESS: &str = "2026-07-28";

struct Upstream(Option<String>);

impl McpTransport for Upstream {
    fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, AdapterError> {
        if let Some(cause) = &self.0 {
            return Err(AdapterError::ConnectionFailed(cause.clone()));
        }
        Ok(vec![chio_mcp_adapter::edge::McpToolInfo {
            name: "read".into(),
            title: None,
            description: Some("Read".into()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            annotations: Some(json!({"readOnlyHint": true, "destructiveHint": false})),
            execution: None,
        }])
    }

    fn call_tool(
        &self,
        tool_name: &str,
        arguments: Value,
    ) -> Result<chio_mcp_adapter::edge::McpToolResult, AdapterError> {
        TestSessionTransport.call_tool(tool_name, arguments)
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    policy_path: PathBuf,
    factory: Arc<RemoteSessionFactory>,
}

impl Fixture {
    fn new(configure: impl FnOnce(&FsPath, &mut RemoteServeHttpConfig)) -> Self {
        let directory = chio_test_support::private_tempdir().unwrap();
        let mut config = test_remote_config();
        config.policy_path = directory.path().join("policy.yaml");
        std::fs::write(
            &config.policy_path,
            "capabilities:\n  default:\n    tools: []\n",
        )
        .unwrap();
        config.wrapped_args.clear();
        config.test_transport = Some(Arc::new(Upstream(None)));
        config.session_db_path = Some(directory.path().join("sessions.sqlite3"));
        config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(directory.path()));
        configure_signed_manifest(&mut config, directory.path());
        configure(directory.path(), &mut config);
        let factory = Arc::new(RemoteSessionFactory::new(config.clone()).unwrap());
        Self {
            directory,
            policy_path: config.policy_path,
            factory,
        }
    }

    fn path_text(&self) -> String {
        self.directory.path().to_string_lossy().into_owned()
    }

    fn spawn_cause(&self) -> String {
        let Err(error) =
            self.factory
                .spawn_session(SessionAuthContext::streamable_http_static_bearer(
                    "agent", "token", None,
                ))
        else {
            panic!("the session spawned despite the injected failure");
        };
        assert!(EnterpriseProviderRegistryRefusal::find(&error).is_none());
        error.to_string()
    }

    fn state(&self) -> RemoteAppState {
        RemoteAppState {
            sessions: Arc::new(
                RemoteSessionLedger::new(
                    self.factory.config.clock.clone(),
                    self.factory.config.lifecycle_policy().unwrap(),
                    None,
                    None,
                )
                .unwrap(),
            ),
            factory: Arc::clone(&self.factory),
            auth_mode: Arc::new(RemoteAuthMode::StaticBearer {
                token: "remote-auth-token".into(),
            }),
            enterprise_provider_registry: None,
            admin_token: None,
            protected_resource_metadata: None,
            authorization_server_metadata: None,
            local_auth_server: None,
        }
    }

    async fn assert_fixed_failure(&self) {
        for request in [initialize_request(), stateless_request()] {
            let state = self.state();
            let response = handle_post(State(state.clone()), request).await;
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            let body = String::from_utf8_lossy(&body);
            assert_eq!(body, SPAWN_FAILED);
            assert!(!body.contains(&self.path_text()));
            assert!(state.sessions.active.lock().await.is_empty());
        }
    }
}

fn post(message: Value, headers: &[(&str, &str)]) -> Request {
    let mut builder = Request::builder()
        .method("POST")
        .uri(MCP_ENDPOINT_PATH)
        .header(AUTHORIZATION, "Bearer remote-auth-token")
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(Body::from(serde_json::to_vec(&message).unwrap()))
        .unwrap()
}

fn initialize_request() -> Request {
    post(
        json!({"jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"spawn-failure","version":"1"}}}),
        &[],
    )
}

fn stateless_request() -> Request {
    post(
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion": STATELESS,
            "io.modelcontextprotocol/clientInfo": {"name":"spawn-failure","version":"1"},
            "io.modelcontextprotocol/clientCapabilities": {}}}}),
        &[
            ("MCP-Protocol-Version", STATELESS),
            ("Mcp-Method", "tools/list"),
        ],
    )
}

#[test]
fn the_spawn_failed_urn_is_registered_for_this_crate() {
    let spec = chio_errors::lookup_error_code(SPAWN_FAILED).unwrap();
    assert_eq!(spec.domain, chio_errors::Domain::Transport);
    assert_eq!(spec.severity, chio_errors::Severity::Error);
    assert_eq!(spec.string_code, "CHIO-TRANSPORT-SESSION-SPAWN-FAILED");
    assert!(spec.consumed_by.contains(&"chio-mcp-remote"));
}

#[tokio::test]
async fn a_missing_policy_file_answers_the_fixed_urn_without_its_cause() {
    let fixture = Fixture::new(|_, _| {});
    std::fs::remove_file(&fixture.policy_path).unwrap();
    assert_eq!(
        fixture.spawn_cause(),
        "failed to read policy file: No such file or directory (os error 2)"
    );
    fixture.assert_fixed_failure().await;
}

#[tokio::test]
async fn an_invalid_policy_answers_the_fixed_urn_without_its_cause() {
    let fixture = Fixture::new(|_, _| {});
    std::fs::write(&fixture.policy_path, "capabilities: [\n").unwrap();
    assert_eq!(
        fixture.spawn_cause(),
        "failed to parse policy YAML: capabilities: invalid type: sequence, expected struct CapabilityPolicyConfig at line 1 column 15"
    );
    fixture.assert_fixed_failure().await;
}

#[tokio::test]
async fn an_unreachable_upstream_answers_the_fixed_urn_without_its_path() {
    let fixture = Fixture::new(|directory, config| {
        config.test_transport = Some(Arc::new(Upstream(Some(format!(
            "cannot launch {}/upstream-server",
            directory.display()
        )))));
    });
    assert!(fixture.spawn_cause().contains(&fixture.path_text()));
    fixture.assert_fixed_failure().await;
}

#[tokio::test]
async fn an_unopenable_receipt_store_answers_the_fixed_urn_without_its_path() {
    let fixture = Fixture::new(|directory, config| {
        let store = directory.join("receipts.sqlite3");
        std::fs::create_dir(&store).unwrap();
        config.receipt_db_path = Some(store);
    });
    assert_eq!(
        fixture.spawn_cause(),
        format!(
            "receipt store error: sqlite error: unable to open database file: {}/receipts.sqlite3",
            fixture.path_text()
        )
    );
    fixture.assert_fixed_failure().await;
}
