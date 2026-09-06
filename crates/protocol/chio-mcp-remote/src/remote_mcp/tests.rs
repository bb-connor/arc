#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_core::session::{SessionAuthMethod, SessionTransport};
    use rusqlite::params;
    use serde_json::json;
    use std::net::ToSocketAddrs as _;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

    #[path = "bearer_verifier.rs"]
    mod bearer_verifier;
    #[path = "session_runtime.rs"]
    mod session_runtime;

    #[derive(Clone)]
    struct TestNativeLaunchFactory;

    struct TestMigrationStore {
        state: chio_security_types::EnterpriseMigrationState,
    }

    impl chio_security_types::EnterpriseMigrationStateStore for TestMigrationStore {
        fn register(
            &self,
            _transition: &chio_security_types::EnterpriseMigrationTransition,
        ) -> chio_security_types::ports::PortResult<
            chio_security_types::EnterpriseMigrationRegisterOutcome,
        > {
            Err(chio_security_types::ports::PortError::unavailable())
        }

        fn load(
            &self,
            key: &chio_security_types::EnterpriseMigrationKey,
        ) -> chio_security_types::ports::PortResult<
            Option<chio_security_types::EnterpriseMigrationState>,
        > {
            Ok((key == &self.state.key).then(|| self.state.clone()))
        }

        fn compare_and_promote(
            &self,
            _transition: &chio_security_types::EnterpriseMigrationTransition,
        ) -> chio_security_types::ports::PortResult<
            chio_security_types::EnterpriseMigrationCasOutcome,
        > {
            Err(chio_security_types::ports::PortError::unavailable())
        }
    }

    impl chio_mcp_adapter::transport::NativeMcpLaunchFactory for TestNativeLaunchFactory {
        fn authorization_contract_digest(&self) -> Result<String, AdapterError> {
            Ok("21".repeat(32))
        }

        fn prepare_launch(
            &self,
            _command: &str,
            _args: &[&str],
            expected_server_id: &str,
            admitted_manifest_registry: Arc<chio_manifest::VerifiedManifestRegistry>,
        ) -> Result<chio_mcp_adapter::transport::NativeMcpLaunch, AdapterError> {
            let key = chio_security_types::EnterpriseMigrationKey {
                deployment_id: chio_security_types::ports::RecordId::new("test-deployment")
                    .map_err(|error| AdapterError::ConnectionFailed(error.to_string()))?,
                scope_kind: chio_security_types::EnterpriseMigrationScopeKind::ToolServer,
                scope_id: chio_security_types::ports::RecordId::new(expected_server_id)
                    .map_err(|error| AdapterError::ConnectionFailed(error.to_string()))?,
                control: chio_security_types::EnterpriseMigrationControl::CageEnforcement,
            };
            let posture = chio_security_types::ports::Digest32::new([0x21; 32]);
            let state = chio_security_types::EnterpriseMigrationState {
                schema_version: chio_security_types::ENTERPRISE_MIGRATION_STATE_SCHEMA_VERSION,
                key: key.clone(),
                stage: chio_security_types::EnterpriseMigrationStage::Shadow,
                generation: 1,
                transition_digest: chio_security_types::ports::Digest32::new([0x22; 32]),
                prior_head_digest: Some(chio_security_types::ports::Digest32::new([0x23; 32])),
                posture_digest: posture,
                evidence_digest: chio_security_types::ports::Digest32::new([0x24; 32]),
                authorization_digest: chio_security_types::ports::Digest32::new([0x25; 32]),
                intent_digest: chio_security_types::ports::Digest32::new([0x26; 32]),
                updated_at_unix_ms: 1,
                signer_public_key: "test-signer".to_string(),
            };
            let store: Arc<dyn chio_security_types::EnterpriseMigrationStateStore> =
                Arc::new(TestMigrationStore { state });
            let binding = chio_security_types::EnterpriseMigrationRuntimeBinding::load(
                &store,
                &key,
                chio_security_types::EnterpriseMigrationStage::Shadow,
                posture,
            )
            .map_err(|error| AdapterError::ConnectionFailed(error.to_string()))?;
            let authorization =
                chio_mcp_adapter::transport::LegacyNativeLaunchAuthorization::new(
                    expected_server_id,
                    binding,
                    admitted_manifest_registry,
                )?;
            Ok(chio_mcp_adapter::transport::NativeMcpLaunch::LegacyAuthorized(
                Box::new(authorization),
            ))
        }
    }

    fn test_native_launch_factory(
    ) -> Arc<dyn chio_mcp_adapter::transport::NativeMcpLaunchFactory> {
        Arc::new(TestNativeLaunchFactory)
    }

    #[test]
    fn mcp_rate_limit_key_ignores_unverified_client_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            MCP_SESSION_ID_HEADER,
            HeaderValue::from_static("session-secret"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer token-secret"),
        );

        let key = mcp_rate_limit_key("127.0.0.1:8080".parse().unwrap());
        assert_eq!(key, "ip:127.0.0.1");
        assert!(!key.contains("session-secret"));
        assert!(!key.contains("token-secret"));
    }

    #[test]
    fn mcp_session_id_header_classifies_missing_invalid_and_valid_values() {
        let mut headers = HeaderMap::new();
        assert_eq!(mcp_session_id_header(&headers), McpSessionIdHeader::Missing);

        headers.insert(MCP_SESSION_ID_HEADER, HeaderValue::from_static(""));
        assert_eq!(mcp_session_id_header(&headers), McpSessionIdHeader::Invalid);

        headers.insert(
            MCP_SESSION_ID_HEADER,
            HeaderValue::from_static(" session-123"),
        );
        assert_eq!(mcp_session_id_header(&headers), McpSessionIdHeader::Invalid);

        headers.insert(
            MCP_SESSION_ID_HEADER,
            HeaderValue::from_static("session-123 "),
        );
        assert_eq!(mcp_session_id_header(&headers), McpSessionIdHeader::Invalid);

        headers.insert(
            MCP_SESSION_ID_HEADER,
            HeaderValue::from_static("session-123"),
        );
        assert_eq!(
            mcp_session_id_header(&headers),
            McpSessionIdHeader::Valid("session-123".to_string())
        );
    }

    fn test_sender_dpop_runtime() -> (Arc<DpopNonceStore>, DpopConfig) {
        let config = DpopConfig::default();
        let store = Arc::new(DpopNonceStore::new(
            config.nonce_store_capacity,
            Duration::from_secs(config.proof_ttl_secs),
        ));
        (store, config)
    }

    fn test_kernel_config() -> chio_kernel::KernelConfig {
        chio_kernel::KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "test-policy-hash".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        }
    }

    fn empty_header_map() -> HeaderMap {
        HeaderMap::new()
    }

    fn test_remote_config() -> RemoteServeHttpConfig {
        RemoteServeHttpConfig {
            listen: "127.0.0.1:0".parse().expect("parse listen addr"),
            auth_token: Some("remote-auth-token".to_string()),
            auth_jwt_public_key: None,
            auth_jwt_discovery_url: None,
            auth_introspection_url: None,
            auth_introspection_client_id: None,
            auth_introspection_client_secret: None,
            auth_jwt_provider_profile: None,
            auth_server_seed_path: None,
            identity_federation_seed_path: None,
            enterprise_providers_file: None,
            auth_jwt_issuer: None,
            auth_jwt_audience: None,
            admin_token: Some("admin-token".to_string()),
            control_url: None,
            control_token: None,
            remote_authority_workload_token: None,
            control_authority_public_key: None,
            control_authority_trusted_public_keys: Vec::new(),
            public_base_url: None,
            auth_servers: vec![],
            auth_authorization_endpoint: None,
            auth_token_endpoint: None,
            auth_registration_endpoint: None,
            auth_jwks_uri: None,
            auth_scopes: vec!["mcp:invoke".to_string()],
            auth_subject: "operator".to_string(),
            auth_code_ttl_secs: 300,
            auth_access_token_ttl_secs: 600,
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            session_db_path: None,
            resume_hmac_keyring_path: None,
            policy_path: PathBuf::from("policy.yaml"),
            server_id: "srv".to_string(),
            server_name: "srv".to_string(),
            server_version: "0.1.0".to_string(),
            signed_manifest_path: None,
            manifest_public_key: None,
            native_launch_factory: test_native_launch_factory(),
            page_size: 50,
            tools_list_changed: false,
            shared_hosted_owner: false,
            wrapped_command: "/bin/true".to_string(),
            wrapped_args: vec!["mock.py".to_string()],
            egress_contract: None,

        }
    }

    #[test]
    fn remote_authority_configuration_requires_distinct_credentials_and_exact_pins() {
        let mut config = test_remote_config();
        config.control_url = Some("https://control.example".to_string());
        config.control_token = Some("service-token".to_string());

        let missing_workload =
            session_core_authority_mode::validate_remote_authority_config(&config)
                .expect_err("remote authority must require a workload credential");
        assert!(missing_workload
            .to_string()
            .contains("remote-authority-workload-token"));

        config.remote_authority_workload_token = Some("service-token".to_string());
        config.control_authority_public_key = Some(Keypair::generate().public_key());
        let aliased = session_core_authority_mode::validate_remote_authority_config(&config)
            .expect_err("remote authority credentials must be role-separated");
        assert!(aliased.to_string().contains("must be distinct"));

        config.remote_authority_workload_token = Some("workload-token".to_string());
        assert!(session_core_authority_mode::validate_remote_authority_config(&config).is_ok());
    }

    #[test]
    fn hosted_edge_requires_a_session_credential_and_a_distinct_control_token() {
        let mut config = test_remote_config();
        config.control_url = Some("https://control.example".to_string());
        config.control_token = Some("service-token".to_string());
        config.remote_authority_workload_token = Some("workload-token".to_string());
        config.control_authority_public_key = Some(Keypair::generate().public_key());
        assert!(session_core_authority_mode::validate_remote_authority_config(&config).is_ok());

        let mut control_as_admin = config.clone();
        control_as_admin.control_token = Some("admin-token".to_string());
        let error =
            session_core_authority_mode::validate_remote_authority_config(&control_as_admin)
                .expect_err("the control credential must not double as the admin credential");
        assert!(error
            .to_string()
            .contains("--control-token and --admin-token must be distinct"));

        let mut control_as_session = config.clone();
        control_as_session.control_token = Some("remote-auth-token".to_string());
        let error =
            session_core_authority_mode::validate_remote_authority_config(&control_as_session)
                .expect_err("the control credential must not double as the session credential");
        assert!(error
            .to_string()
            .contains("--control-token and --auth-token must be distinct"));

        let mut no_session_credential = config.clone();
        no_session_credential.auth_token = None;
        let error = session_core_authority_mode::validate_remote_authority_config(
            &no_session_credential,
        )
        .expect_err("a hosted edge needs a session credential");
        assert!(error.to_string().contains("requires a session credential"));

        no_session_credential.auth_jwt_public_key = Some("jwt-public-key".to_string());
        assert!(session_core_authority_mode::validate_remote_authority_config(
            &no_session_credential
        )
        .is_ok());
    }

    #[test]
    fn remote_authority_only_configuration_is_rejected_without_control_url() {
        let mut config = test_remote_config();
        config.remote_authority_workload_token = Some("workload-token".to_string());
        let error = session_core_authority_mode::validate_remote_authority_config(&config)
            .expect_err("remote authority settings must require a control URL");
        assert!(error.to_string().contains("require --control-url"));
    }

    fn configure_signed_manifest(
        config: &mut RemoteServeHttpConfig,
        directory: &std::path::Path,
    ) -> PathBuf {
        let signer = Keypair::generate();
        let public_key = signer.public_key().to_hex();
        let manifest = chio_manifest::ToolManifest {
            schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: config.server_id.clone(),
            name: config.server_name.clone(),
            description: Some("MCP server adapted to Chio protocol".to_string()),
            version: config.server_version.clone(),
            tools: vec![chio_manifest::ToolDefinition {
                name: "read".to_string(),
                description: "Read".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                    estimated_duration_ms: None,
                },
                latency_hint: None,
                flow: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: public_key.clone(),
        };
        let signed = chio_manifest::sign_manifest(&manifest, &signer)
            .expect("sign remote MCP test manifest");
        let path = directory.join("signed-manifest.json");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&signed).expect("serialize remote MCP test manifest"),
        )
        .expect("write remote MCP test manifest");
        config.signed_manifest_path = Some(path.clone());
        config.manifest_public_key = Some(public_key);
        path
    }

    fn write_test_resume_hmac_keyring(directory: &FsPath) -> PathBuf {
        let path = directory.join("resume-hmac-keyring.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema": REMOTE_SESSION_HMAC_KEYRING_SCHEMA,
                "current": {
                    "keyId": "factory-test",
                    "version": 1,
                    "keyBase64": URL_SAFE_NO_PAD.encode([29_u8; 32]),
                },
                "previous": [],
            }))
            .expect("serialize factory test resume HMAC keyring"),
        )
        .expect("write factory test resume HMAC keyring");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("secure factory test resume HMAC keyring");
        }
        path
    }

    fn test_local_authorization_server() -> LocalAuthorizationServer {
        let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
        LocalAuthorizationServer {
            signing_key: Keypair::generate(),
            issuer: "https://auth.example".to_string(),
            default_audience: "https://edge.example/mcp".to_string(),
            supported_scopes: vec!["mcp:invoke".to_string()],
            subject: "operator".to_string(),
            code_ttl_secs: 300,
            access_token_ttl_secs: 600,
            codes: Arc::new(StdMutex::new(HashMap::new())),
            sender_dpop_nonce_store,
            sender_dpop_config,
        }
    }

    fn test_authorization_approval_form() -> AuthorizationApprovalForm {
        AuthorizationApprovalForm {
            response_type: "code".to_string(),
            client_id: "client-abc".to_string(),
            redirect_uri: "https://client.example/callback".to_string(),
            state: Some("state-1".to_string()),
            scope: Some("mcp:invoke".to_string()),
            resource: Some("https://edge.example/mcp".to_string()),
            authorization_details: None,
            chio_transaction_context: None,
            code_challenge: "challenge".to_string(),
            code_challenge_method: "S256".to_string(),
            chio_sender_dpop_public_key: None,
            chio_sender_mtls_thumbprint_sha256: None,
            chio_sender_attestation_sha256: None,
            decision: "approve".to_string(),
        }
    }

    fn authorization_code_from_redirect(redirect: Redirect) -> String {
        let response = redirect.into_response();
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .expect("redirect has location")
            .to_str()
            .expect("location is valid header text");
        Url::parse(location)
            .expect("parse redirect location")
            .query_pairs()
            .find_map(|(key, value)| (key == "code").then(|| value.to_string()))
            .expect("redirect includes authorization code")
    }

    fn stored_authorization_code_expiry(
        server: &LocalAuthorizationServer,
        code: &str,
    ) -> u64 {
        let guard = server.codes.lock().expect("lock authorization codes");
        guard
            .get(code)
            .expect("authorization code stored")
            .expires_at
    }

    fn test_resume_hmac_keyring() -> Arc<RemoteSessionHmacKeyring> {
        Arc::new(RemoteSessionHmacKeyring {
            current: RemoteSessionHmacKey {
                key_id: "test-current".to_string(),
                version: 2,
                key: Zeroizing::new([41_u8; 32]),
                verify_until_millis: None,
            },
            previous: vec![RemoteSessionHmacKey {
                key_id: "test-previous".to_string(),
                version: 1,
                key: Zeroizing::new([17_u8; 32]),
                verify_until_millis: Some(session_now_millis().saturating_add(60_000)),
            }],
        })
    }

    fn sign_test_resume_record(
        mut record: RemoteSessionResumeRecord,
        keyring: &RemoteSessionHmacKeyring,
    ) -> RemoteSessionResumeRecord {
        record.resume_integrity = keyring.empty_tag_for_current();
        record.resume_integrity.tag =
            compute_resume_record_integrity_tag(&keyring.current, &record)
                .expect("sign test resume record");
        record
    }

    fn sample_resume_record_with_keyring(
        keyring: &RemoteSessionHmacKeyring,
    ) -> RemoteSessionResumeRecord {
        sign_test_resume_record(
            RemoteSessionResumeRecord {
                session_id: "session-valid".to_string(),
                agent_id: "agent-valid".to_string(),
                auth_context: SessionAuthContext::streamable_http_oauth_bearer(
                    Some("principal-valid".to_string()),
                    Some("https://issuer.example".to_string()),
                    Some("subject-valid".to_string()),
                    Some("audience-valid".to_string()),
                    vec!["mcp:invoke".to_string(), "mcp:read".to_string()],
                    Some("token-fingerprint".to_string()),
                    None,
                ),
                auth_mode_fingerprint: Some("auth-contract-v1".to_string()),
                policy_fingerprint: Some("policy-contract-v1".to_string()),
                runtime_contract_fingerprint: "runtime-contract-v1".to_string(),
                hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
                lifecycle: RemoteSessionLifecycleSnapshot {
                    state: RemoteSessionState::Ready,
                    created_at: 10,
                    last_seen_at: 11,
                    idle_expires_at: 12,
                    drain_deadline_at: None,
                },
                protocol_version: Some("2025-06-18".to_string()),
                peer_capabilities: PeerCapabilities::default(),
                initialize_params: json!({}),
                issued_capabilities: Vec::new(),
                resume_generation: 1,
                resume_integrity: keyring.empty_tag_for_current(),
            },
            keyring,
        )
    }

    fn sample_resume_record() -> RemoteSessionResumeRecord {
        let keyring = test_resume_hmac_keyring();
        sample_resume_record_with_keyring(&keyring)
    }

    #[cfg(target_os = "linux")]
    fn acquire_test_session_store(path: &FsPath) -> Arc<RemoteSessionStoreLifecycleLease> {
        Arc::new(
            RemoteSessionStoreLifecycleLease::acquire(path)
                .expect("acquire retained test session store"),
        )
    }

    #[cfg(target_os = "linux")]
    fn private_test_session_database(label: &str) -> (PathBuf, PathBuf) {
        let directory = std::env::temp_dir().join(format!(
            "chio-remote-session-store-{label}-{}-{}",
            std::process::id(),
            session_now_millis()
        ));
        std::fs::create_dir(&directory).expect("create private test session directory");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("secure private test session directory");
        let path = directory.join("sessions.sqlite3");
        (directory, path)
    }

    #[derive(Debug)]
    struct TestSessionTransport;

    impl McpTransport for TestSessionTransport {
        fn list_tools(
            &self,
        ) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, AdapterError> {
            Ok(Vec::new())
        }

        fn call_tool(
            &self,
            _tool_name: &str,
            _arguments: Value,
        ) -> Result<chio_mcp_adapter::edge::McpToolResult, AdapterError> {
            Err(AdapterError::ConnectionFailed(
                "test session transport does not dispatch tools".to_string(),
            ))
        }
    }

    #[test]
    fn shared_hosted_owner_notification_fanout_replays_to_all_live_taps() {
        let subscriber_a = Arc::new(StdMutex::new(VecDeque::<Value>::new()));
        let subscriber_b = Arc::new(StdMutex::new(VecDeque::<Value>::new()));
        let stats = SharedUpstreamNotificationStats::default();
        let subscribers: NotificationSubscriberList = Arc::new(StdMutex::new(vec![
            Arc::downgrade(&subscriber_a),
            Arc::downgrade(&subscriber_b),
        ]));

        fan_out_shared_upstream_notifications(
            &subscribers,
            &stats,
            vec![json!({
                "jsonrpc": "2.0",
                "method": "notifications/resources/list_changed"
            })],
        );

        let subscriber_a = subscriber_a.lock().expect("lock subscriber a");
        let subscriber_b = subscriber_b.lock().expect("lock subscriber b");
        assert_eq!(subscriber_a.len(), 1);
        assert_eq!(subscriber_b.len(), 1);
        assert_eq!(
            subscriber_a[0]["method"].as_str(),
            Some("notifications/resources/list_changed")
        );
        assert_eq!(subscriber_a.as_slices(), subscriber_b.as_slices());
        assert_eq!(stats.fanout_batches.load(Ordering::Relaxed), 1);
        assert_eq!(stats.fanout_notifications.load(Ordering::Relaxed), 1);
        assert_eq!(stats.fanout_targets.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn shared_hosted_owner_notification_fanout_tracks_pruned_dead_subscribers() {
        let stats = SharedUpstreamNotificationStats::default();
        let live = Arc::new(StdMutex::new(VecDeque::<Value>::new()));
        let dropped = Arc::new(StdMutex::new(VecDeque::<Value>::new()));
        let subscribers: NotificationSubscriberList = Arc::new(StdMutex::new(vec![
            Arc::downgrade(&live),
            Arc::downgrade(&dropped),
        ]));
        drop(dropped);

        fan_out_shared_upstream_notifications(
            &subscribers,
            &stats,
            vec![json!({
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed"
            })],
        );

        assert_eq!(stats.pruned_subscribers.load(Ordering::Relaxed), 1);
        assert_eq!(stats.fanout_targets.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn validate_resume_record_integrity_rejects_tampered_auth_context() {
        let keyring = test_resume_hmac_keyring();
        let mut record = sample_resume_record_with_keyring(&keyring);
        if let SessionAuthMethod::OAuthBearer { scopes, .. } = &mut record.auth_context.method {
            scopes.push("mcp:admin".to_string());
        } else {
            panic!("expected OAuth bearer auth context");
        }

        let error =
            validate_resume_record_integrity_with_keyring(&keyring, &record, session_now_millis())
                .expect_err("tampered auth context should fail integrity validation");
        assert!(error
            .to_string()
            .contains("failed resumable integrity validation"));
    }

    #[test]
    fn resume_hmac_keyring_is_required_and_parsed_strictly() {
        let mut config = test_remote_config();
        config.session_db_path = Some(PathBuf::from("/tmp/chio-test-session.sqlite3"));
        let missing = load_resume_hmac_keyring(&config)
            .expect_err("durable resume without a keyring must fail closed");
        assert!(missing.to_string().contains("--resume-hmac-keyring"));

        let path = std::env::temp_dir().join(format!(
            "chio-remote-resume-keyring-{}-{}.json",
            std::process::id(),
            session_now_millis()
        ));
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema": REMOTE_SESSION_HMAC_KEYRING_SCHEMA,
                "current": {
                    "keyId": "current",
                    "version": 2,
                    "keyBase64": URL_SAFE_NO_PAD.encode([9_u8; 32]),
                },
                "previous": [{
                    "keyId": "previous",
                    "version": 1,
                    "keyBase64": URL_SAFE_NO_PAD.encode([8_u8; 32]),
                    "verifyUntilMillis": session_now_millis().saturating_add(60_000),
                }],
            }))
            .expect("serialize test keyring"),
        )
        .expect("write test keyring");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("secure test keyring");
        }
        config.resume_hmac_keyring_path = Some(path.clone());
        let loaded = load_resume_hmac_keyring(&config)
            .expect("load strict keyring")
            .expect("configured keyring");
        assert_eq!(loaded.current.key_id, "current");
        assert_eq!(loaded.previous.len(), 1);
        std::fs::remove_file(path).expect("remove test keyring");
    }

    #[test]
    fn runtime_contract_fingerprint_binds_upstream_argument_file_contents() {
        let directory = std::env::temp_dir().join(format!(
            "chio-remote-runtime-contract-{}-{}",
            std::process::id(),
            session_now_millis()
        ));
        std::fs::create_dir(&directory).expect("create runtime contract test directory");
        let argument_path = directory.join("server.py");
        std::fs::write(&argument_path, b"print('first')\n")
            .expect("write first upstream argument content");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&argument_path, std::fs::Permissions::from_mode(0o600))
                .expect("secure upstream argument file");
        }

        let mut config = test_remote_config();
        config.wrapped_args = vec![argument_path.to_string_lossy().into_owned()];
        let manifest_path = configure_signed_manifest(&mut config, &directory);
        let manifest_public_key = config
            .manifest_public_key
            .as_deref()
            .expect("configured manifest key");
        let registry = chio_manifest::load_existing_verified_manifest_registry(
            &manifest_path,
            manifest_public_key,
            &config.server_id,
            chio_manifest::RuntimeToolTopology::local(),
        )
        .expect("load verified runtime contract manifest");
        let first = fingerprint_remote_runtime_contract(&config, &registry)
            .expect("fingerprint first runtime contract");

        config.control_url = Some("https://control.example".to_string());
        config.control_token = Some("service-token".to_string());
        config.remote_authority_workload_token = Some("workload-token".to_string());
        config.control_authority_public_key = Some(Keypair::generate().public_key());
        let authority_bound = fingerprint_remote_runtime_contract(&config, &registry)
            .expect("fingerprint authority-bound runtime contract");
        assert_ne!(first, authority_bound);

        std::fs::write(&argument_path, b"print('second revision')\n")
            .expect("write changed upstream argument content");
        let second = fingerprint_remote_runtime_contract(&config, &registry)
            .expect("fingerprint changed runtime contract");
        assert_ne!(first, second);

        std::fs::remove_dir_all(directory).expect("remove runtime contract test directory");
    }

    #[test]
    fn stored_capability_issuer_revalidation_rejects_untrusted_restart_issuer() {
        let old_authority = Keypair::generate();
        let subject = Keypair::generate().public_key();
        let stale_capability = CapabilityToken::sign(
            chio_core::capability::token::CapabilityTokenBody {
                id: "cap-stale-issuer".to_string(),
                issuer: old_authority.public_key(),
                subject,
                scope: chio_core::capability::scope::ChioScope::default(),
                issued_at: 1,
                expires_at: u64::MAX,
                delegation_chain: vec![],
                aggregate_invocation_budget: None,
            },
            &old_authority,
        )
        .expect("sign stale capability");

        let restarted_kernel = chio_kernel::ChioKernel::new(test_kernel_config());
        assert!(!stored_capability_issuers_are_trusted(
            &restarted_kernel,
            std::slice::from_ref(&stale_capability)
        ));

        let mut trusted_kernel = chio_kernel::ChioKernel::new(test_kernel_config());
        trusted_kernel.set_capability_authority(Box::new(
            chio_kernel::LocalCapabilityAuthority::new(old_authority),
        ));
        assert!(stored_capability_issuers_are_trusted(
            &trusted_kernel,
            &[stale_capability]
        ));
    }

    #[test]
    fn validate_restored_peer_capabilities_rejects_tampered_record() {
        let mut record = sample_resume_record();
        record.initialize_params = json!({
            "capabilities": {
                "tools": { "listChanged": true },
                "resources": { "subscribe": true, "listChanged": true },
                "prompts": { "listChanged": true }
            }
        });
        record.peer_capabilities = PeerCapabilities::default();

        let error = validate_restored_peer_capabilities(&record)
            .expect_err("tampered peer capabilities should fail restore validation");
        assert!(error
            .to_string()
            .contains("failed peer capability re-validation"));
    }

    #[test]
    fn expected_resume_agent_id_is_revalidated_from_identity_federation_seed() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let seed_path = std::env::temp_dir().join(format!(
            "chio-identity-federation-resume-{}-{nonce}.seed",
            std::process::id()
        ));
        let mut config = test_remote_config();
        config.identity_federation_seed_path = Some(seed_path.clone());
        let auth_context = SessionAuthContext::streamable_http_oauth_bearer(
            Some("oidc:https://issuer.example#sub:user-123".to_string()),
            Some("https://issuer.example".to_string()),
            Some("user-123".to_string()),
            Some("audience-valid".to_string()),
            vec!["mcp:invoke".to_string()],
            Some("token-fingerprint".to_string()),
            None,
        );

        let expected = expected_resume_agent_id(&config, &auth_context)
            .expect("derive expected agent id")
            .expect("expected agent id");
        let foreign = derive_federated_agent_keypair(
            &seed_path,
            "oidc:https://issuer.example#sub:user-456",
        )
        .expect("derive foreign principal keypair")
        .public_key()
        .to_hex();

        assert_ne!(expected, foreign);
        let _ = std::fs::remove_file(seed_path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn session_store_rejects_concurrent_ownership() {
        let (directory, path) = private_test_session_database("ownership");
        let lease = acquire_test_session_store(&path);
        let error = RemoteSessionStoreLifecycleLease::acquire(&path)
            .expect_err("a second owner must be rejected");
        assert!(error.to_string().contains("already owned"));
        drop(lease);
        std::fs::remove_dir_all(directory).expect("remove test session directory");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn load_active_session_records_skips_malformed_rows() {
        let (directory, path) = private_test_session_database("active");
        let lease = acquire_test_session_store(&path);
        let keyring = test_resume_hmac_keyring();
        let valid_record = sample_resume_record_with_keyring(&keyring);
        persist_active_session_record(&path, &valid_record, &keyring)
            .expect("persist valid session row");

        let conn = open_session_state_db(&path).expect("open session state db");
        conn.execute(
            &format!(
                "INSERT OR REPLACE INTO {table} (session_id, updated_at, record_json)
                 VALUES (?1, ?2, ?3)",
                table = SESSION_ACTIVE_TABLE,
            ),
            params!["session-bad", session_now_millis() as i64, "{not json"],
        )
        .expect("insert malformed session row");
        drop(conn);

        let loaded =
            load_active_session_records(&path, &keyring).expect("load active session records");
        assert_eq!(loaded.records.len(), 1);
        assert_eq!(loaded.records[0].session_id, "session-valid");
        assert_eq!(loaded.invalid_session_ids, vec!["session-bad".to_string()]);

        drop(lease);
        std::fs::remove_dir_all(directory).expect("remove test session directory");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_transition_deletes_active_state_and_retains_replay_fence() {
        let (directory, path) = private_test_session_database("terminal-transition");
        let lease = acquire_test_session_store(&path);
        let keyring = test_resume_hmac_keyring();
        let active_record = sample_resume_record_with_keyring(&keyring);
        persist_active_session_record(&path, &active_record, &keyring)
            .expect("persist active session row");

        let mut lifecycle = active_record.lifecycle.clone();
        lifecycle.state = RemoteSessionState::Deleted;
        let terminal_record = RemoteSessionDiagnosticRecord {
            session_id: active_record.session_id.clone(),
            auth_context: active_record.auth_context.clone(),
            capabilities: Vec::new(),
            lifecycle,
            protocol_version: active_record.protocol_version.clone(),
            ownership: RemoteSessionOwnershipSnapshot::default(),
            terminal_at: 13,
        };
        let (tombstone, fence) =
            sign_terminal_session_records(&keyring, terminal_record, 2, 2)
                .expect("sign terminal transition");
        persist_terminal_session_transition(&path, &tombstone, &fence, &keyring)
            .expect("persist terminal transition");

        let active =
            load_active_session_records(&path, &keyring).expect("load active session records");
        assert!(active.records.is_empty());
        let terminal =
            load_terminal_session_records(&path, &keyring).expect("load terminal records");
        assert!(terminal.contains_key("session-valid"));

        let mut replay = sample_resume_record_with_keyring(&keyring);
        replay.resume_generation = 3;
        replay.resume_integrity = keyring.empty_tag_for_current();
        replay.resume_integrity.tag =
            compute_resume_record_integrity_tag(&keyring.current, &replay)
                .expect("sign replay attempt");
        let replay_error = persist_active_session_record(&path, &replay, &keyring)
            .expect_err("terminal fence must permanently block active replay");
        assert!(replay_error.to_string().contains("retained terminal state"));

        drop(lease);
        std::fs::remove_dir_all(directory).expect("remove test session directory");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn malformed_terminal_state_blocks_active_replay_fail_closed() {
        let (directory, path) = private_test_session_database("malformed-terminal");
        let lease = acquire_test_session_store(&path);
        let keyring = test_resume_hmac_keyring();
        let active_record = sample_resume_record_with_keyring(&keyring);
        persist_active_session_record(&path, &active_record, &keyring)
            .expect("persist active session row");

        let conn = open_session_state_db(&path).expect("open session state db");
        conn.execute(
            &format!(
                "INSERT INTO {table} (session_id, terminal_at, record_json)
                 VALUES (?1, ?2, ?3)",
                table = SESSION_TOMBSTONE_TABLE,
            ),
            params!["session-valid", 13_i64, "{not json"],
        )
        .expect("insert malformed terminal row");
        drop(conn);

        let loaded =
            load_active_session_records(&path, &keyring).expect("load active session records");
        assert!(loaded.records.is_empty());
        assert_eq!(
            loaded.invalid_session_ids,
            vec!["session-valid".to_string()]
        );

        drop(lease);
        std::fs::remove_dir_all(directory).expect("remove test session directory");
    }

    #[test]
    fn restored_ready_session_preserves_lifecycle_and_requires_store_lease() {
        let (input_tx, _input_rx) = mpsc::channel::<Value>();
        let (event_tx, _) = broadcast::channel::<RemoteSessionEvent>(8);
        let retained_notification_events =
            Arc::new(StdMutex::new(VecDeque::<RetainedRemoteSessionEvent>::new()));
        let next_event_id = Arc::new(AtomicU64::new(0));
        let lifecycle_policy = SessionLifecyclePolicy {
            idle_expiry_millis: 5_000,
            drain_grace_millis: 1_000,
            reaper_interval_millis: 100,
            tombstone_retention_millis: 10_000,
        };
        let session = RemoteSession::new(RemoteSessionInit {
            session_id: "session-restore".to_string(),
            agent_id: "agent-restore".to_string(),
            capabilities: Vec::new(),
            issued_capabilities: Vec::new(),
            auth_context: SessionAuthContext::streamable_http_static_bearer(
                "agent-restore",
                "restore-token",
                None,
            ),
            auth_mode_fingerprint: "auth-contract-v1".to_string(),
            policy_fingerprint: "policy-contract-v1".to_string(),
            runtime_contract_fingerprint: "runtime-contract-v1".to_string(),
            hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
            lifecycle_policy: lifecycle_policy.clone(),
            protocol_version: None,
            peer_capabilities: None,
            initialize_params: None,
            lifecycle_snapshot: Some(RemoteSessionLifecycleSnapshot {
                state: RemoteSessionState::Ready,
                created_at: 11,
                last_seen_at: 12,
                idle_expires_at: 13,
                drain_deadline_at: Some(14),
            }),
            input_tx,
            event_tx,
            retained_notification_events,
            next_event_id,
            session_db_path: Some(PathBuf::from("unused-session-store.sqlite3")),
            session_store_lease: None,
            resume_hmac_keyring: Some(test_resume_hmac_keyring()),
            resume_generation: 0,
            upstream_transport: Arc::new(TestSessionTransport),
        });

        let lifecycle = session.lifecycle_snapshot();
        assert_eq!(lifecycle.state, RemoteSessionState::Ready);
        assert_eq!(lifecycle.created_at, 11);
        assert_eq!(lifecycle.last_seen_at, 12);
        assert_eq!(lifecycle.idle_expires_at, 13);
        assert_eq!(lifecycle.drain_deadline_at, None);

        let error = session
            .mark_ready(None, json!({}), PeerCapabilities::default())
            .expect_err("ready session persistence must require retained store ownership");
        assert!(
            error
                .to_string()
                .contains("no retained database ownership lease"),
            "unexpected persistence error: {error}"
        );
    }

    #[test]
    fn chio_oauth_discovery_profile_metadata_advertises_sender_constraints() {
        let metadata =
            build_chio_oauth_authorization_profile_metadata().expect("build Chio auth profile");
        let profile: ChioOAuthAuthorizationProfile =
            serde_json::from_value(metadata.clone()).expect("parse Chio auth profile");
        assert_eq!(profile.id, CHIO_OAUTH_AUTHORIZATION_PROFILE_ID);
        assert_eq!(profile.schema, CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA);
        assert_eq!(
            profile.sender_constraints.subject_binding,
            CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT
        );
        assert!(profile
            .sender_constraints
            .proof_types_supported
            .iter()
            .any(|proof| proof == CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP));
        assert!(profile
            .sender_constraints
            .proof_types_supported
            .iter()
            .any(|proof| proof == chio_kernel::operator_report::CHIO_OAUTH_SENDER_PROOF_CHIO_MTLS));
        assert!(profile
            .sender_constraints
            .proof_types_supported
            .iter()
            .any(|proof| proof
                == chio_kernel::operator_report::CHIO_OAUTH_SENDER_PROOF_CHIO_ATTESTATION));
        assert_eq!(
            profile
                .request_time_contract
                .authorization_details_parameter
                .as_str(),
            CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_PARAMETER
        );
        assert!(
            profile
                .resource_binding
                .request_resource_must_match_protected_resource
        );
        assert!(
            !profile
                .artifact_boundary
                .reviewer_evidence_runtime_admission_supported
        );
        assert_eq!(metadata["discoveryInformationalOnly"].as_bool(), Some(true));
    }

    #[test]
    fn chio_oauth_discovery_validation_rejects_profile_mismatch() {
        let protected_resource_metadata = ProtectedResourceMetadata {
            resource: "https://edge.example/mcp".to_string(),
            resource_metadata_url: "https://edge.example/.well-known/oauth-protected-resource/mcp"
                .to_string(),
            authorization_servers: vec!["https://edge.example/oauth".to_string()],
            scopes_supported: vec!["mcp:invoke".to_string()],
            chio_authorization_profile: build_chio_oauth_authorization_profile_metadata()
                .expect("build protected Chio auth profile"),
        };
        let authorization_server_metadata = AuthorizationServerMetadata {
            metadata_path: "/.well-known/oauth-authorization-server/oauth".to_string(),
            document: json!({
                "issuer": "https://edge.example/oauth",
                "chio_authorization_profile": {
                    "schema": CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA,
                    "id": "mismatched-profile",
                    "authoritativeSource": "governed_receipt_projection",
                    "authorizationDetailTypes": ["chio_governed_tool"],
                    "transactionContextFields": ["intentId", "intentHash"],
                    "senderConstraints": {
                        "schema": "chio.oauth.sender-constraint.v1",
                        "subjectBinding": CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT,
                        "proofTypesSupported": [CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP],
                        "proofRequiredWhen": "matchedGrant.dpopRequired == true",
                        "runtimeAssuranceBindingFields": ["runtimeAssuranceTier"],
                        "delegatedCallChainField": "callChain",
                        "unsupportedSenderShapesFailClosed": true
                    },
                    "unsupportedShapesFailClosed": true
                }
            }),
        };

        let error = validate_chio_oauth_discovery_metadata_pair(
            &protected_resource_metadata,
            &authorization_server_metadata,
        )
        .expect_err("mismatched discovery metadata should fail");
        assert!(
            error.to_string().contains("Chio authorization profile id"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn local_authorization_server_issues_unique_codes_for_same_second_approvals() {
        for _ in 0..8 {
            let server = test_local_authorization_server();
            let first = authorization_code_from_redirect(
                server
                    .approve_authorization(test_authorization_approval_form())
                    .expect("first approval succeeds"),
            );
            let first_expires_at = stored_authorization_code_expiry(&server, &first);
            let second = authorization_code_from_redirect(
                server
                    .approve_authorization(test_authorization_approval_form())
                    .expect("second approval succeeds"),
            );
            let second_expires_at = stored_authorization_code_expiry(&server, &second);

            if first_expires_at == second_expires_at {
                assert_ne!(first, second);
                return;
            }
        }

        panic!("test could not issue two authorization codes in the same second");
    }

    #[test]
    fn remote_session_auth_context_uses_static_bearer_fingerprint_and_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("http://localhost:3000"));

        let auth_context = build_static_bearer_session_auth_context(&headers, "test-token");
        assert_eq!(auth_context.transport, SessionTransport::StreamableHttp);
        assert_eq!(
            auth_context.origin.as_deref(),
            Some("http://localhost:3000")
        );
        assert!(auth_context.is_authenticated());

        match &auth_context.method {
            SessionAuthMethod::StaticBearer {
                principal,
                token_fingerprint,
            } => {
                assert_eq!(token_fingerprint, &sha256_hex(b"test-token"));
                assert!(principal.starts_with("static-bearer:"));
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn build_federated_principal_prefers_subject_over_client_id() {
        let principal = build_federated_principal(
            &JwtClaims {
                iss: Some("https://issuer.example/".to_string()),
                sub: Some("user-123".to_string()),
                aud: None,
                scope: None,
                scp: vec![],
                client_id: Some("client-abc".to_string()),
                jti: None,
                oid: None,
                azp: None,
                appid: None,
                tid: None,
                tenant_id: None,
                org_id: None,
                organization_id: None,
                groups: Vec::new(),
                roles: Vec::new(),
                resource: None,
                authorization_details: None,
                chio_transaction_context: None,
                cnf: None,
                exp: None,
                nbf: None,
            },
            None,
            None,
            JwtProviderProfile::Generic,
        )
        .unwrap();
        assert_eq!(principal, "oidc:https://issuer.example#sub:user-123");
    }

    #[test]
    fn build_federated_principal_azure_ad_prefers_oid_and_appid() {
        let principal = build_federated_principal(
            &JwtClaims {
                iss: Some("https://login.microsoftonline.com/example/v2.0".to_string()),
                sub: Some("subject-123".to_string()),
                aud: None,
                scope: None,
                scp: vec![],
                client_id: None,
                jti: None,
                oid: Some("object-456".to_string()),
                azp: None,
                appid: Some("app-789".to_string()),
                tid: None,
                tenant_id: None,
                org_id: None,
                organization_id: None,
                groups: Vec::new(),
                roles: Vec::new(),
                resource: None,
                authorization_details: None,
                chio_transaction_context: None,
                cnf: None,
                exp: None,
                nbf: None,
            },
            None,
            None,
            JwtProviderProfile::AzureAd,
        )
        .unwrap();
        assert_eq!(
            principal,
            "oidc:https://login.microsoftonline.com/example/v2.0#oid:object-456"
        );
    }

    #[test]
    fn build_federated_claims_normalizes_enterprise_identity_metadata() {
        let federated_claims = build_federated_claims(
            &JwtClaims {
                iss: Some("https://issuer.example".to_string()),
                sub: Some("user-123".to_string()),
                aud: None,
                scope: None,
                scp: vec![],
                client_id: None,
                jti: None,
                oid: Some("object-456".to_string()),
                azp: Some("client-azp".to_string()),
                appid: Some("client-app".to_string()),
                tid: Some("tenant-123".to_string()),
                tenant_id: Some("tenant-fallback".to_string()),
                org_id: Some("org-789".to_string()),
                organization_id: Some("org-fallback".to_string()),
                groups: vec![
                    " ops ".to_string(),
                    "eng".to_string(),
                    "eng".to_string(),
                    "".to_string(),
                ],
                roles: vec![" reviewer ".to_string(), "operator".to_string()],
                resource: None,
                authorization_details: None,
                chio_transaction_context: None,
                cnf: None,
                exp: None,
                nbf: None,
            },
            JwtProviderProfile::AzureAd,
        );
        assert_eq!(federated_claims.client_id.as_deref(), Some("client-azp"));
        assert_eq!(federated_claims.object_id.as_deref(), Some("object-456"));
        assert_eq!(federated_claims.tenant_id.as_deref(), Some("tenant-123"));
        assert_eq!(federated_claims.organization_id.as_deref(), Some("org-789"));
        assert_eq!(
            federated_claims.groups,
            vec!["eng".to_string(), "ops".to_string()]
        );
        assert_eq!(
            federated_claims.roles,
            vec!["operator".to_string(), "reviewer".to_string()]
        );
    }

    #[test]
    fn provider_profile_can_derive_standard_oidc_discovery_url_from_issuer() {
        let config = RemoteServeHttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            auth_token: None,
            auth_jwt_public_key: Some(Keypair::generate().public_key().to_hex()),
            auth_jwt_discovery_url: None,
            auth_introspection_url: None,
            auth_introspection_client_id: None,
            auth_introspection_client_secret: None,
            auth_jwt_provider_profile: Some(JwtProviderProfile::Okta),
            auth_server_seed_path: None,
            identity_federation_seed_path: None,
            enterprise_providers_file: None,
            auth_jwt_issuer: Some("https://id.example.com/oauth2/default".to_string()),
            auth_jwt_audience: None,
            admin_token: Some("admin-token".to_string()),
            control_url: None,
            control_token: None,
            remote_authority_workload_token: None,
            control_authority_public_key: None,
            control_authority_trusted_public_keys: Vec::new(),
            public_base_url: None,
            auth_servers: vec![],
            auth_authorization_endpoint: None,
            auth_token_endpoint: None,
            auth_registration_endpoint: None,
            auth_jwks_uri: None,
            auth_scopes: vec![],
            auth_subject: "operator".to_string(),
            auth_code_ttl_secs: 300,
            auth_access_token_ttl_secs: 600,
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            session_db_path: None,
            resume_hmac_keyring_path: None,
            policy_path: PathBuf::from("policy.yaml"),
            server_id: "srv".to_string(),
            server_name: "srv".to_string(),
            server_version: "0.1.0".to_string(),
            signed_manifest_path: None,
            manifest_public_key: None,
            native_launch_factory: test_native_launch_factory(),
            page_size: 50,
            tools_list_changed: false,
            shared_hosted_owner: false,
            wrapped_command: "python3".to_string(),
            wrapped_args: vec!["mock.py".to_string()],
            egress_contract: None,

        };

        let discovery_url = resolve_identity_provider_discovery_url(&config)
            .unwrap()
            .expect("discovery url");
        assert_eq!(
            discovery_url.as_str(),
            "https://id.example.com/oauth2/default/.well-known/openid-configuration"
        );
    }

    fn spawn_localhost_json_server(body: &'static str) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let bind_ip = ("localhost", 0)
            .to_socket_addrs()
            .expect("resolve localhost")
            .next()
            .map(|addr| addr.ip())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let listener = std::net::TcpListener::bind(std::net::SocketAddr::new(bind_ip, 0))
            .expect("bind localhost test server");
        let addr = listener.local_addr().expect("read local addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write JSON response");
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn oidc_fetch_uses_contract_backed_client_for_hostname_url() {
        let (addr, handle) = spawn_localhost_json_server("{\"ok\":true}");
        let url = Url::parse(&format!(
            "http://localhost:{}/.well-known/openid-configuration",
            addr.port()
        ))
        .expect("parse OIDC URL");
        let contract =
            HttpEgressContract::permissive_for_tests(&format!("localhost:{}", addr.port()));

        let json: Value =
            fetch_identity_provider_json(&url, "test OIDC discovery", Some(&contract))
                .await
                .expect("OIDC fetch uses contract-backed reqwest client");

        assert_eq!(json["ok"].as_bool(), Some(true));
        handle.join().expect("join localhost JSON server");
    }

    #[tokio::test]
    async fn oidc_fetch_rejects_special_use_address_contract() {
        let url = Url::parse("http://169.254.169.254/.well-known/openid-configuration")
            .expect("parse link-local OIDC URL");
        let contract = HttpEgressContract {
            tenant_egress_namespace: "chio-mcp-remote-oidc-test".to_string(),
            allowed_schemes: std::collections::BTreeSet::from(["http".to_string()]),
            allowed_authority_set: std::collections::BTreeSet::from([
                "169.254.169.254".to_string()
            ]),
            deny_loopback: true,
            deny_link_local: true,
            deny_ipv6_ula: true,
            max_redirect_chain: 0,
            max_response_bytes: 64 * 1024,
        };

        let error =
            fetch_identity_provider_json::<Value>(&url, "test OIDC discovery", Some(&contract))
                .await
                .expect_err("link-local OIDC URL should fail closed");
        let message = error.to_string();
        assert!(
            message.contains("HttpEgressContract") && message.contains("link-local"),
            "unexpected OIDC egress denial: {message}"
        );
    }

    #[test]
    fn identity_federation_derives_stable_keypair_per_principal() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seed_path = std::env::temp_dir().join(format!(
            "chio-identity-federation-seed-{}-{nonce}.seed",
            std::process::id()
        ));

        let first =
            derive_federated_agent_keypair(&seed_path, "oidc:https://issuer.example#sub:user-123")
                .unwrap();
        let second =
            derive_federated_agent_keypair(&seed_path, "oidc:https://issuer.example#sub:user-123")
                .unwrap();
        let other =
            derive_federated_agent_keypair(&seed_path, "oidc:https://issuer.example#sub:user-456")
                .unwrap();

        assert_eq!(first.public_key().to_hex(), second.public_key().to_hex());
        assert_ne!(first.public_key().to_hex(), other.public_key().to_hex());
    }

    #[test]
    fn jwt_remote_auth_requires_separate_admin_token() {
        let config = RemoteServeHttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            auth_token: None,
            auth_jwt_public_key: Some(Keypair::generate().public_key().to_hex()),
            auth_jwt_discovery_url: None,
            auth_introspection_url: None,
            auth_introspection_client_id: None,
            auth_introspection_client_secret: None,
            auth_jwt_provider_profile: None,
            auth_server_seed_path: None,
            identity_federation_seed_path: None,
            enterprise_providers_file: None,
            auth_jwt_issuer: None,
            auth_jwt_audience: None,
            admin_token: None,
            control_url: None,
            control_token: None,
            remote_authority_workload_token: None,
            control_authority_public_key: None,
            control_authority_trusted_public_keys: Vec::new(),
            public_base_url: None,
            auth_servers: vec![],
            auth_authorization_endpoint: None,
            auth_token_endpoint: None,
            auth_registration_endpoint: None,
            auth_jwks_uri: None,
            auth_scopes: vec![],
            auth_subject: "operator".to_string(),
            auth_code_ttl_secs: 300,
            auth_access_token_ttl_secs: 600,
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            session_db_path: None,
            resume_hmac_keyring_path: None,
            policy_path: PathBuf::from("policy.yaml"),
            server_id: "srv".to_string(),
            server_name: "srv".to_string(),
            server_version: "0.1.0".to_string(),
            signed_manifest_path: None,
            manifest_public_key: None,
            native_launch_factory: test_native_launch_factory(),
            page_size: 50,
            tools_list_changed: false,
            shared_hosted_owner: false,
            wrapped_command: "python3".to_string(),
            wrapped_args: vec!["mock.py".to_string()],
            egress_contract: None,

        };

        let error = build_remote_auth_state(&config, "127.0.0.1:0".parse().unwrap(), None, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("--admin-token"));
    }

    #[test]
    fn bearer_edge_requires_a_dedicated_admin_token() {
        let mut missing_admin = test_remote_config();
        missing_admin.admin_token = None;
        let error =
            build_remote_auth_state(&missing_admin, "127.0.0.1:0".parse().unwrap(), None, None)
                .unwrap_err()
                .to_string();
        assert!(error.contains("requires --admin-token"), "{error}");

        let mut session_as_admin = test_remote_config();
        session_as_admin.admin_token = session_as_admin.auth_token.clone();
        let error = build_remote_auth_state(
            &session_as_admin,
            "127.0.0.1:0".parse().unwrap(),
            None,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("--auth-token and --admin-token must be distinct"),
            "{error}"
        );
    }

    #[test]
    fn remote_auth_state_rejects_unusable_static_bearer_tokens() {
        for (field, value) in [
            ("--auth-token", ""),
            ("--auth-token", " remote-auth-token"),
            ("--auth-token", "remote-auth-token\n"),
            ("--admin-token", ""),
            ("--admin-token", " admin-token"),
            ("--admin-token", "admin-token\r"),
        ] {
            let mut config = test_remote_config();
            match field {
                "--auth-token" => config.auth_token = Some(value.to_string()),
                "--admin-token" => config.admin_token = Some(value.to_string()),
                other => panic!("unexpected field {other}"),
            }

            let error =
                build_remote_auth_state(&config, "127.0.0.1:0".parse().unwrap(), None, None)
                    .unwrap_err()
                    .to_string();

            assert!(error.contains(field), "error should name {field}: {error}");
            assert!(
                error.contains("must be non-empty, unpadded, and control-free"),
                "error should describe usable bearer requirements: {error}"
            );
        }
    }

    #[test]
    fn shared_upstream_notification_fanout_copies_notifications_and_prunes_dead_queues() {
        let subscribers = Arc::new(StdMutex::new(Vec::new()));
        let stats = SharedUpstreamNotificationStats::default();
        let queue_a = Arc::new(StdMutex::new(VecDeque::new()));
        let queue_b = Arc::new(StdMutex::new(VecDeque::new()));
        let dropped_queue = Arc::new(StdMutex::new(VecDeque::new()));
        if let Ok(mut guard) = subscribers.lock() {
            guard.push(Arc::downgrade(&queue_a));
            guard.push(Arc::downgrade(&queue_b));
            guard.push(Arc::downgrade(&dropped_queue));
        }
        drop(dropped_queue);

        fan_out_shared_upstream_notifications(
            &subscribers,
            &stats,
            vec![
                json!({"jsonrpc": "2.0", "method": "notifications/resources/list_changed"}),
                json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
            ],
        );

        let queue_a = queue_a.lock().unwrap();
        let queue_b = queue_b.lock().unwrap();
        assert_eq!(queue_a.len(), 2);
        assert_eq!(queue_b.len(), 2);
        assert_eq!(
            queue_a[0]["method"].as_str(),
            Some("notifications/resources/list_changed")
        );
        assert_eq!(
            queue_a[1]["method"].as_str(),
            Some("notifications/tools/list_changed")
        );
        assert_eq!(queue_a.as_slices(), queue_b.as_slices());
        drop(queue_a);
        drop(queue_b);

        let subscriber_count = subscribers.lock().unwrap().len();
        assert_eq!(subscriber_count, 2);
    }
}
