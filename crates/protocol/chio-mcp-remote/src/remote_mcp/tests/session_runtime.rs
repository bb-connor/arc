use super::*;

fn private_remote_admission_directory(label: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "chio-remote-admission-{label}-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create remote admission directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("secure remote admission directory");
    }
    directory
}

#[test]
fn remote_session_factory_holds_one_durable_admission_sidecar() {
    let directory = private_remote_admission_directory("owner");
    let policy_path = directory.join("policy.yaml");
    std::fs::write(&policy_path, "capabilities:\n  default:\n    tools: []\n")
        .expect("write remote admission policy");
    let session_database = directory.join("sessions.sqlite3");
    let mut config = test_remote_config();
    config.policy_path = policy_path;
    config.test_transport = Some(Arc::new(TestSessionTransport));
    config.session_db_path = Some(session_database.clone());
    config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(&directory));
    let _manifest_path = configure_signed_manifest(&mut config, &directory);

    let factory =
        RemoteSessionFactory::new(config.clone()).expect("claim remote durable admission owner");
    assert!(factory.durable_admission.is_some());
    assert_ne!(
        durable_admission_sidecar_path(&session_database).expect("derive remote admission sidecar"),
        session_database
    );
    assert!(RemoteSessionFactory::new(config.clone()).is_err());

    drop(factory);
    RemoteSessionFactory::new(config).expect("reclaim remote admission owner after shutdown");
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn remote_session_factory_requires_manifest_trust_inputs() {
    let directory = private_remote_admission_directory("manifest-trust");
    let policy_path = directory.join("policy.yaml");
    std::fs::write(&policy_path, "capabilities:\n  default:\n    tools: []\n")
        .expect("write remote admission policy");
    let mut config = test_remote_config();
    config.policy_path = policy_path;
    config.session_db_path = Some(directory.join("sessions.sqlite3"));

    let error = RemoteSessionFactory::new(config)
        .err()
        .expect("missing signed manifest must be rejected");
    assert!(error
        .to_string()
        .contains("requires an existing publisher-signed manifest file"));
    let _ = std::fs::remove_dir_all(directory);
}

struct CountingLaunchFactory(Arc<std::sync::atomic::AtomicUsize>);

impl chio_mcp_adapter::transport::NativeMcpLaunchFactory for CountingLaunchFactory {
    fn authorization_contract_digest(&self) -> Result<String, AdapterError> {
        chio_mcp_adapter::transport::NativeMcpLaunchFactory::authorization_contract_digest(
            &TestNativeLaunchFactory,
        )
    }

    fn prepare_launch(
        &self,
        command: &str,
        args: &[&str],
        expected_server_id: &str,
        registry: Arc<chio_manifest::VerifiedManifestRegistry>,
    ) -> Result<chio_mcp_adapter::transport::CageRequiredLaunch, AdapterError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        chio_mcp_adapter::transport::NativeMcpLaunchFactory::prepare_launch(
            &TestNativeLaunchFactory,
            command,
            args,
            expected_server_id,
            registry,
        )
    }
}

#[test]
fn remote_session_factory_rejects_flow_before_launch_authority_or_store_acquisition() {
    for flow in [
        None,
        Some(chio_manifest::ToolFlowDeclaration::public_egress()),
    ] {
        let requires_flow = flow.is_some();
        let directory = private_remote_admission_directory("flow-installation");
        let policy_path = directory.join("policy.yaml");
        std::fs::write(&policy_path, "capabilities:\n  default:\n    tools: []\n")
            .expect("write remote admission policy");
        let session_database = directory.join("sessions.sqlite3");
        let admission_database =
            durable_admission_sidecar_path(&session_database).expect("derive admission sidecar");
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut config = test_remote_config();
        config.policy_path = policy_path;
        config.session_db_path = Some(session_database.clone());
        config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(&directory));
        config.native_launch_factory = Arc::new(CountingLaunchFactory(Arc::clone(&calls)));
        configure_signed_manifest_with_flow(&mut config, &directory, flow);

        let result = RemoteSessionFactory::new(config);
        if requires_flow {
            let error = result
                .err()
                .expect("flow runtime is not installed by this factory");
            assert!(error.to_string().contains(
                "remote MCP session construction requires an active-defense host for flow-required manifests"
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(!session_database.exists());
            assert!(!admission_database.exists());
        } else {
            let error = result
                .err()
                .expect("native launch requires enforced authority");
            assert!(error
                .to_string()
                .contains("test factory refuses native launch"));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(!session_database.exists());
            assert!(!admission_database.exists());
        }
        std::fs::remove_dir_all(directory).expect("remove isolated remote factory fixture");
    }
}

#[test]
fn remote_session_factory_rejects_admission_sidecar_aliases() {
    let directory = private_remote_admission_directory("alias");
    let policy_path = directory.join("policy.yaml");
    std::fs::write(&policy_path, "capabilities:\n  default:\n    tools: []\n")
        .expect("write remote admission policy");
    let session_database = directory.join("sessions.sqlite3");
    let admission_database =
        durable_admission_sidecar_path(&session_database).expect("derive admission sidecar");
    let mut config = test_remote_config();
    config.policy_path = policy_path;
    config.session_db_path = Some(session_database);
    config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(&directory));
    config.receipt_db_path = Some(admission_database);
    let _manifest_path = configure_signed_manifest(&mut config, &directory);

    let error = RemoteSessionFactory::new(config)
        .err()
        .expect("admission sidecar alias must be rejected");
    assert!(error
        .to_string()
        .contains("durable admission database must not alias receipt database"));
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn inbound_authority_factory_binds_caller_key_and_rejects_unbound_proof_policy() {
    #[derive(Debug)]
    struct ReadTransport;

    impl McpTransport for ReadTransport {
        fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, AdapterError> {
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

    let directory = private_remote_admission_directory("sender-bootstrap");
    let mut config = test_remote_config();
    config.policy_path = directory.join("policy.yaml");
    std::fs::write(
        &config.policy_path,
        "hushspec: '0.1.0'\nrules:\n  tool_access:\n    default: block\n    allow: ['*']\n    dpop_required: true\n",
    )
    .unwrap();
    config.test_transport = Some(Arc::new(ReadTransport));
    config.session_db_path = Some(directory.join("sessions.sqlite3"));
    config.receipt_db_path = Some(directory.join("receipts.sqlite3"));
    config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(&directory));
    configure_signed_manifest(&mut config, &directory);
    let factory = RemoteSessionFactory::new(config.clone()).unwrap();
    let auth = SessionAuthContext::streamable_http_static_bearer("unbound", "token", None);
    let error = factory.spawn_session(auth).err().unwrap();
    assert!(
        error.to_string().contains("authenticated Chio sender key"),
        "{error:?}"
    );
    let sender = Keypair::generate();
    let auth = SessionAuthContext::streamable_http_oauth_bearer_with_claims(
        chio_core::OAuthBearerSessionAuthInput {
            principal: Some("verified-sender".into()),
            issuer: Some("https://issuer.example".into()),
            subject: Some("sender".into()),
            audience: None,
            scopes: vec![],
            federated_claims: OAuthBearerFederatedClaims {
                sender_public_key: Some(sender.public_key()),
                ..Default::default()
            },
            enterprise_identity: None,
            token_fingerprint: Some("fingerprint".into()),
            origin: None,
        },
    );
    let session = factory.spawn_session(auth.clone()).unwrap();
    assert_eq!(session.agent_id, sender.public_key().to_hex());
    assert!(!session.issued_capabilities.is_empty());
    for cap in &session.issued_capabilities {
        assert_eq!(cap.subject, sender.public_key());
        assert!(cap
            .scope
            .grants
            .iter()
            .all(|grant| grant.dpop_required == Some(true)));
    }
    assert_eq!(
        expected_resume_agent_id(&config, &auth).unwrap(),
        Some(session.agent_id.clone())
    );
    session.shutdown_upstream_transport().unwrap();
    drop(session);
    drop(factory);
    std::fs::remove_dir_all(directory).unwrap();
}
