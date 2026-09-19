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
fn mcp_rate_limiter_caps_session_window() {
    let limiter = McpRateLimiter::new();
    for _ in 0..MCP_RATE_LIMIT_MAX_REQUESTS {
        assert!(limiter.check("session:test".to_string(), 120).is_ok());
    }

    let retry_after = limiter
        .check("session:test".to_string(), 120)
        .expect_err("session should be rate limited after the window budget is exhausted");
    assert_eq!(retry_after, 60);
    assert!(limiter.check("session:test".to_string(), 180).is_ok());
}

#[test]
fn mcp_rate_limiter_caps_tracked_keys() {
    let limiter = McpRateLimiter::new();
    for idx in 0..MCP_RATE_LIMIT_MAX_KEYS {
        assert!(limiter.check(format!("session:{idx}"), 120).is_ok());
    }

    let retry_after = limiter
        .check("session:overflow".to_string(), 120)
        .expect_err("new rate-limit keys should be capped within a window");
    assert_eq!(retry_after, 60);
    assert!(limiter.check("session:0".to_string(), 120).is_ok());
}

#[test]
fn remote_session_factory_holds_one_durable_admission_sidecar() {
    let directory = private_remote_admission_directory("owner");
    let policy_path = directory.join("policy.yaml");
    std::fs::write(
        &policy_path,
        "capabilities:\n  default:\n    tools: []\n",
    )
    .expect("write remote admission policy");
    let session_database = directory.join("sessions.sqlite3");
    let mut config = test_remote_config();
    config.policy_path = policy_path;
    config.session_db_path = Some(session_database.clone());
    config.resume_hmac_keyring_path = Some(write_test_resume_hmac_keyring(&directory));
    let _manifest_path = configure_signed_manifest(&mut config, &directory);

    let factory =
        RemoteSessionFactory::new(config.clone()).expect("claim remote durable admission owner");
    assert!(factory.durable_admission.is_some());
    assert_ne!(
        durable_admission_sidecar_path(&session_database)
            .expect("derive remote admission sidecar"),
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
    std::fs::write(
        &policy_path,
        "capabilities:\n  default:\n    tools: []\n",
    )
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
    ) -> Result<chio_mcp_adapter::transport::NativeMcpLaunch, AdapterError> {
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
    for flow in [None, Some(chio_manifest::ToolFlowDeclaration::public_egress())] {
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
            let error = result.err().expect("flow runtime is not installed by this factory");
            assert!(error.to_string().contains(
                "remote MCP session construction requires an active-defense host for flow-required manifests"
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(!session_database.exists());
            assert!(!admission_database.exists());
        } else {
            let factory = result.expect("unconstrained manifest remains supported");
            assert!(calls.load(Ordering::SeqCst) > 0);
            assert!(factory.durable_admission.is_some());
            drop(factory);
        }
        std::fs::remove_dir_all(directory).expect("remove isolated remote factory fixture");
    }
}

#[test]
fn remote_session_factory_rejects_admission_sidecar_aliases() {
    let directory = private_remote_admission_directory("alias");
    let policy_path = directory.join("policy.yaml");
    std::fs::write(
        &policy_path,
        "capabilities:\n  default:\n    tools: []\n",
    )
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
